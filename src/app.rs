use tonic::Code;

use crate::client::{Client, cp_call};
use crate::error::{Error, Result};
use crate::proto::client::{self as pb, ObjectCreationType};

/// A Modal App, which Sandboxes and Images belong to.
#[derive(Clone, Debug)]
pub struct App {
    pub app_id: String,
    pub name: String,
    /// The environment the App was looked up in (empty for the workspace default).
    pub environment: String,
}

#[derive(Clone, Debug, Default)]
pub struct AppLookupParams {
    /// Defaults to the client's configured environment.
    pub environment: Option<String>,
    pub create_if_missing: bool,
}

impl Client {
    /// Looks up an App by name, optionally creating it.
    pub async fn app_from_name(&self, name: &str, params: AppLookupParams) -> Result<App> {
        let environment = self.environment_name(params.environment.as_deref());
        let object_creation_type = if params.create_if_missing {
            ObjectCreationType::CreateIfMissing
        } else {
            ObjectCreationType::Unspecified
        };
        let response = cp_call!(
            self,
            app_get_or_create,
            pb::AppGetOrCreateRequest {
                app_name: name.to_string(),
                environment_name: environment.clone(),
                object_creation_type: object_creation_type as i32,
            }
        )
        .await
        .map_err(|status| match status.code() {
            Code::NotFound => Error::NotFound(format!("App '{name}' not found")),
            _ => Error::Grpc(status),
        })?;
        tracing::debug!(app_id = %response.app_id, app_name = name, "looked up Modal App");
        Ok(App {
            app_id: response.app_id,
            name: name.to_string(),
            environment,
        })
    }
}
