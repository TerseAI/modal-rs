use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::OnceCell;

use crate::app::App;
use crate::client::{Client, cp_call};
use crate::error::{Error, Result};
use crate::proto::client::{
    self as pb, GpuConfig, RegistryAuthType, generic_result::GenericStatus,
};
use crate::secret::{self, Secret};

/// A container image for Sandboxes. Built on Modal the first time it is used
/// and cached per value, so reuse one `Image` across Sandboxes.
#[derive(Clone, Debug)]
pub struct Image {
    tag: String,
    /// Parent image for the first layer, when extending a built image.
    base_image_id: Option<String>,
    registry: Option<(RegistryAuthType, Option<Secret>)>,
    layers: Vec<Layer>,
    built: Arc<OnceCell<String>>,
}

/// Options for one [`Image::dockerfile_commands_with`] layer.
#[derive(Clone, Debug, Default)]
pub struct ImageLayerParams {
    /// Environment variables available while the layer builds.
    pub env: HashMap<String, String>,
    /// Secrets available while the layer builds.
    pub secrets: Vec<Secret>,
    /// GPU to build the layer on, e.g. "A10G" or "H100:2".
    pub gpu: Option<String>,
    /// Ignore cached builds of this layer.
    pub force_build: bool,
}

#[derive(Clone, Debug, Default)]
struct Layer {
    commands: Vec<String>,
    params: ImageLayerParams,
}

impl Image {
    /// A public registry image, e.g. `python:3.12-slim`.
    pub fn from_registry(tag: impl Into<String>) -> Self {
        Self::registry(tag, None)
    }

    /// A private registry image; the Secret holds `REGISTRY_USERNAME` and
    /// `REGISTRY_PASSWORD`.
    pub fn from_private_registry(tag: impl Into<String>, secret: Secret) -> Self {
        Self::registry(tag, Some((RegistryAuthType::StaticCreds, Some(secret))))
    }

    /// An image in AWS ECR; the Secret holds AWS credentials.
    pub fn from_aws_ecr(tag: impl Into<String>, secret: Secret) -> Self {
        Self::registry(tag, Some((RegistryAuthType::Aws, Some(secret))))
    }

    /// An image in GCP Artifact Registry; the Secret holds a service account key.
    pub fn from_gcp_artifact_registry(tag: impl Into<String>, secret: Secret) -> Self {
        Self::registry(tag, Some((RegistryAuthType::Gcp, Some(secret))))
    }

    /// An image Modal has already built, e.g. from [`Image::image_id`] or a
    /// filesystem snapshot. No lookup is made.
    pub fn from_id(image_id: impl Into<String>) -> Self {
        Self {
            tag: String::new(),
            base_image_id: None,
            registry: None,
            layers: Vec::new(),
            built: Arc::new(OnceCell::new_with(Some(image_id.into()))),
        }
    }

    fn registry(
        tag: impl Into<String>,
        registry: Option<(RegistryAuthType, Option<Secret>)>,
    ) -> Self {
        Self {
            tag: tag.into(),
            base_image_id: None,
            registry,
            layers: vec![Layer::default()],
            built: Arc::new(OnceCell::new()),
        }
    }

    /// Adds a layer of Dockerfile commands (`RUN`, `ENV`, ...).
    pub fn dockerfile_commands<I, S>(&self, commands: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.dockerfile_commands_with(commands, ImageLayerParams::default())
    }

    pub fn dockerfile_commands_with<I, S>(&self, commands: I, params: ImageLayerParams) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let commands: Vec<String> = commands.into_iter().map(Into::into).collect();
        if commands.is_empty() {
            return self.clone();
        }
        let layer = Layer { commands, params };
        let (base_image_id, mut layers) = match self.built.get() {
            Some(id) => (Some(id.clone()), Vec::new()),
            None => (self.base_image_id.clone(), self.layers.clone()),
        };
        layers.push(layer);
        Self {
            tag: self.tag.clone(),
            base_image_id,
            registry: self.registry.clone(),
            layers,
            built: Arc::new(OnceCell::new()),
        }
    }

    /// The image ID, once built.
    pub fn image_id(&self) -> Option<&str> {
        self.built.get().map(String::as_str)
    }

    /// Builds the image in an App (if it isn't already) and returns its ID.
    pub async fn build(&self, client: &Client, app: &App) -> Result<String> {
        self.built
            .get_or_try_init(|| self.build_layers(client, app))
            .await
            .cloned()
    }

    async fn build_layers(&self, client: &Client, app: &App) -> Result<String> {
        for layer in &self.layers {
            validate_dockerfile_commands(&layer.commands)?;
        }
        let builder_version = client.image_builder_version(Some(&app.environment)).await?;
        let mut current_image_id = self.base_image_id.clone();

        for (i, layer) in self.layers.iter().enumerate() {
            let mut secrets = layer.params.secrets.clone();
            if !layer.params.env.is_empty() {
                secret::validate_env_var_names(&layer.params.env)?;
                secrets.push(Secret::from_map(layer.params.env.clone()));
            }
            let secret_ids = secret::resolve_ids(client, &secrets).await?;
            let gpu_config = layer
                .params
                .gpu
                .as_deref()
                .map(parse_gpu_config)
                .transpose()?;

            let (from, base_images) = match &current_image_id {
                Some(id) => (
                    "FROM base".to_string(),
                    vec![pb::BaseImage {
                        docker_tag: "base".into(),
                        image_id: id.clone(),
                    }],
                ),
                None => (format!("FROM {}", self.tag), Vec::new()),
            };
            let mut dockerfile_commands = vec![from];
            dockerfile_commands.extend(layer.commands.iter().cloned());

            let image_registry_config = match (&self.registry, i, &current_image_id) {
                (Some((auth_type, secret)), 0, None) => Some(pb::ImageRegistryConfig {
                    registry_auth_type: *auth_type as i32,
                    secret_id: match secret {
                        Some(secret) => secret.resolve(client).await?,
                        None => String::new(),
                    },
                }),
                _ => None,
            };

            let response = cp_call!(
                client,
                image_get_or_create,
                pb::ImageGetOrCreateRequest {
                    app_id: app.app_id.clone(),
                    image: Some(pb::Image {
                        dockerfile_commands,
                        image_registry_config,
                        secret_ids,
                        gpu_config,
                        base_images,
                        ..Default::default()
                    }),
                    builder_version: builder_version.clone(),
                    force_build: layer.params.force_build,
                    ..Default::default()
                }
            )
            .await?;

            let result = match response.result {
                Some(result) if result.status() != GenericStatus::Unspecified => result,
                _ => wait_for_build(client, &response.image_id).await?,
            };
            match result.status() {
                GenericStatus::Success => {}
                GenericStatus::Failure | GenericStatus::MemoryManagerEviction => {
                    return Err(Error::Remote(format!(
                        "image build for {} failed:\n{}",
                        response.image_id, result.exception
                    )));
                }
                GenericStatus::Terminated => {
                    return Err(Error::Remote(format!(
                        "image build for {} was terminated by an external shutdown; try again",
                        response.image_id
                    )));
                }
                GenericStatus::Timeout => {
                    return Err(Error::Remote(format!(
                        "image build for {} timed out",
                        response.image_id
                    )));
                }
                other => {
                    return Err(Error::Remote(format!(
                        "image build for {} ended with status {other:?}",
                        response.image_id
                    )));
                }
            }
            current_image_id = Some(response.image_id);
        }

        let image_id = current_image_id
            .ok_or_else(|| Error::Invalid("image has no layers to build".into()))?;
        tracing::debug!(image_id, "built Modal image");
        Ok(image_id)
    }
}

/// Follows an in-progress build until it reports a result. Each
/// `ImageJoinStreaming` call long-polls for up to 55s, so it is reopened from
/// the last entry until a result arrives.
async fn wait_for_build(client: &Client, image_id: &str) -> Result<pb::GenericResult> {
    let mut last_entry_id = String::new();
    loop {
        let request = client.stream_request(pb::ImageJoinStreamingRequest {
            image_id: image_id.to_string(),
            timeout: 55.0,
            last_entry_id: last_entry_id.clone(),
            ..Default::default()
        });
        let mut stream = client
            .stub()
            .image_join_streaming(request)
            .await?
            .into_inner();
        while let Some(item) = stream.message().await? {
            if !item.entry_id.is_empty() {
                last_entry_id = item.entry_id;
            }
            if let Some(result) = item.result
                && result.status() != GenericStatus::Unspecified
            {
                return Ok(result);
            }
        }
    }
}

fn validate_dockerfile_commands(commands: &[String]) -> Result<()> {
    for command in commands {
        let upper = command.trim().to_ascii_uppercase();
        if upper.starts_with("COPY ") && !upper.starts_with("COPY --FROM=") {
            return Err(Error::Invalid(
                "COPY commands that copy from the local context are not supported".into(),
            ));
        }
    }
    Ok(())
}

/// Parses `"A100"`, `"T4:2"` or `"A100-80GB:4"` into a GPU request.
pub(crate) fn parse_gpu_config(gpu: &str) -> Result<GpuConfig> {
    let (gpu_type, count) = match gpu.split_once(':') {
        Some((gpu_type, count)) => {
            let count = count
                .parse::<u32>()
                .ok()
                .filter(|c| *c >= 1)
                .ok_or_else(|| {
                    Error::Invalid(format!(
                        "invalid GPU count {count:?}: must be a positive integer"
                    ))
                })?;
            (gpu_type, count)
        }
        None => (gpu, 1),
    };
    Ok(GpuConfig {
        r#type: 0,
        count,
        gpu_type: gpu_type.to_ascii_uppercase(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gpu_configs() {
        let gpu = parse_gpu_config("a100-80gb:4").unwrap();
        assert_eq!((gpu.gpu_type.as_str(), gpu.count), ("A100-80GB", 4));
        assert_eq!(parse_gpu_config("T4").unwrap().count, 1);
        assert!(parse_gpu_config("T4:0").is_err());
        assert!(parse_gpu_config("T4:x").is_err());
    }

    #[test]
    fn rejects_local_copy() {
        assert!(validate_dockerfile_commands(&["COPY . /app".into()]).is_err());
        assert!(validate_dockerfile_commands(&["COPY --from=builder /x /y".into()]).is_ok());
    }

    #[test]
    fn layering_a_built_image_starts_from_its_id() {
        let built = Image::from_id("im-123");
        let extended = built.dockerfile_commands(["RUN true"]);
        assert_eq!(extended.base_image_id.as_deref(), Some("im-123"));
        assert_eq!(extended.layers.len(), 1);
        assert!(extended.image_id().is_none());
    }
}
