use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::OnceCell;
use tonic::Code;

use crate::client::{Client, cp_call};
use crate::error::{Error, Result};
use crate::proto::client::{
    self as pb, ObjectCreationType, SecretSource, StringMap, secret_source,
};

/// A Modal Secret: a set of environment variables injected into a Sandbox,
/// an exec, or an image build. Resolved lazily and cached per value, so
/// reusing one `Secret` across many Sandboxes costs one lookup.
#[derive(Clone, Debug)]
pub struct Secret {
    kind: Kind,
    id: Arc<OnceCell<String>>,
}

#[derive(Clone, Debug)]
enum Kind {
    Id,
    Named {
        name: String,
        environment: Option<String>,
        required_keys: Vec<String>,
    },
    Map(HashMap<String, String>),
}

impl Secret {
    /// A deployed Secret, looked up by name on first use.
    pub fn from_name(name: impl Into<String>) -> Self {
        Self::new(Kind::Named {
            name: name.into(),
            environment: None,
            required_keys: Vec::new(),
        })
    }

    /// A Secret by ID.
    pub fn from_id(id: impl Into<String>) -> Self {
        Self {
            kind: Kind::Id,
            id: Arc::new(OnceCell::new_with(Some(id.into()))),
        }
    }

    /// Inline key/value pairs. V2 Sandboxes and execs send these directly to
    /// the worker; elsewhere they become an ephemeral Secret.
    pub fn from_map(env: HashMap<String, String>) -> Self {
        Self::new(Kind::Map(env))
    }

    /// For [`Secret::from_name`]: the environment to look the Secret up in.
    pub fn environment(mut self, environment: impl Into<String>) -> Self {
        if let Kind::Named {
            environment: env, ..
        } = &mut self.kind
        {
            *env = Some(environment.into());
        }
        self
    }

    /// For [`Secret::from_name`]: keys the Secret must contain.
    pub fn required_keys<I: IntoIterator<Item = S>, S: Into<String>>(mut self, keys: I) -> Self {
        if let Kind::Named { required_keys, .. } = &mut self.kind {
            *required_keys = keys.into_iter().map(Into::into).collect();
        }
        self
    }

    fn new(kind: Kind) -> Self {
        Self {
            kind,
            id: Arc::new(OnceCell::new()),
        }
    }

    fn inline_env(&self) -> Option<&HashMap<String, String>> {
        match &self.kind {
            Kind::Map(env) => Some(env),
            _ => None,
        }
    }

    /// The Secret's ID, looking it up or creating it on first use.
    pub(crate) async fn resolve(&self, client: &Client) -> Result<String> {
        self.id
            .get_or_try_init(|| async {
                match &self.kind {
                    Kind::Id => unreachable!("ID secrets are created resolved"),
                    Kind::Named {
                        name,
                        environment,
                        required_keys,
                    } => {
                        let response = cp_call!(
                            client,
                            secret_get_or_create,
                            pb::SecretGetOrCreateRequest {
                                deployment_name: name.clone(),
                                environment_name: client.environment_name(environment.as_deref()),
                                required_keys: required_keys.clone(),
                                ..Default::default()
                            }
                        )
                        .await
                        .map_err(|status| match status.code() {
                            Code::NotFound => Error::NotFound(status.message().to_string()),
                            _ => Error::Grpc(status),
                        })?;
                        Ok(response.secret_id)
                    }
                    Kind::Map(env) => {
                        let response = cp_call!(
                            client,
                            secret_get_or_create,
                            pb::SecretGetOrCreateRequest {
                                object_creation_type: ObjectCreationType::Ephemeral as i32,
                                env_dict: env.clone(),
                                environment_name: client.environment_name(None),
                                ..Default::default()
                            }
                        )
                        .await?;
                        Ok(response.secret_id)
                    }
                }
            })
            .await
            .cloned()
    }
}

pub(crate) fn validate_env_var_names(env: &HashMap<String, String>) -> Result<()> {
    for key in env.keys() {
        let mut chars = key.chars();
        let valid = chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            return Err(Error::Invalid(format!(
                "{key:?} is not a valid environment variable name: use letters, digits and underscores, not starting with a digit"
            )));
        }
    }
    Ok(())
}

/// Resolves every Secret to an ID, in order. For V1 Sandboxes and image builds,
/// which only take Secret IDs.
pub(crate) async fn resolve_ids(client: &Client, secrets: &[Secret]) -> Result<Vec<String>> {
    let mut ids = Vec::with_capacity(secrets.len());
    for secret in secrets {
        ids.push(secret.resolve(client).await?);
    }
    Ok(ids)
}

/// Secrets and env vars as ordered sources for V2 Sandboxes and execs: inline
/// Secrets and `env` are sent as values, the rest by ID. Env goes last so it
/// wins. Also returns the IDs of the Secrets sent by reference.
pub(crate) async fn secret_sources(
    client: &Client,
    secrets: &[Secret],
    env: &HashMap<String, String>,
) -> Result<(Vec<SecretSource>, Vec<String>)> {
    validate_env_var_names(env)?;
    let mut sources = Vec::new();
    let mut ids = Vec::new();
    for secret in secrets {
        match secret.inline_env() {
            Some(inline) => {
                validate_env_var_names(inline)?;
                if !inline.is_empty() {
                    sources.push(env_source(inline));
                }
            }
            None => {
                let id = secret.resolve(client).await?;
                sources.push(SecretSource {
                    source: Some(secret_source::Source::SecretId(id.clone())),
                });
                ids.push(id);
            }
        }
    }
    if !env.is_empty() {
        sources.push(env_source(env));
    }
    Ok((sources, ids))
}

fn env_source(env: &HashMap<String, String>) -> SecretSource {
    SecretSource {
        source: Some(secret_source::Source::Env(StringMap {
            contents: env.clone(),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_env_var_names() {
        let ok = HashMap::from([
            ("FOO_1".to_string(), String::new()),
            ("_X".to_string(), String::new()),
        ]);
        assert!(validate_env_var_names(&ok).is_ok());
        for bad in ["1FOO", "FOO-BAR", "", "FOO BAR"] {
            let env = HashMap::from([(bad.to_string(), String::new())]);
            assert!(
                validate_env_var_names(&env).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }
}
