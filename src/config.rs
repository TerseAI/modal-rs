//! Resolves credentials and settings the way Modal's other SDKs do: environment
//! variables override the active profile in `~/.modal.toml`.

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use crate::error::{Error, Result};

pub const DEFAULT_SERVER_URL: &str = "https://api.modal.com:443";

/// Client configuration. Build one with [`Config::from_env`] or
/// [`Config::with_token`].
#[derive(Clone)]
pub struct Config {
    pub server_url: String,
    pub token_id: String,
    pub token_secret: String,
    /// Modal environment to use when a call doesn't name one.
    pub environment: Option<String>,
    /// Overrides the image builder version the environment reports.
    pub image_builder_version: Option<String>,
    /// Caps the total time spent honouring server-requested throttle delays.
    /// `None` waits as long as the server asks; `Some(ZERO)` disables them.
    pub max_throttle_wait: Option<Duration>,
    /// Create CPU Sandboxes on Modal's V2 backend (the Go SDK's default).
    /// GPU Sandboxes always use V1.
    pub sandbox_v2: bool,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("server_url", &self.server_url)
            .field("token_id", &self.token_id)
            .field("token_secret", &"<redacted>")
            .field("environment", &self.environment)
            .field("image_builder_version", &self.image_builder_version)
            .field("max_throttle_wait", &self.max_throttle_wait)
            .field("sandbox_v2", &self.sandbox_v2)
            .finish()
    }
}

#[derive(Debug, Default, Deserialize)]
struct RawProfile {
    server_url: Option<String>,
    token_id: Option<String>,
    token_secret: Option<String>,
    environment: Option<String>,
    image_builder_version: Option<String>,
    sandbox_v2: Option<bool>,
    #[serde(default)]
    active: bool,
}

impl Config {
    /// Explicit token credentials with default settings.
    pub fn with_token(token_id: impl Into<String>, token_secret: impl Into<String>) -> Self {
        Self {
            server_url: DEFAULT_SERVER_URL.to_string(),
            token_id: token_id.into(),
            token_secret: token_secret.into(),
            environment: None,
            image_builder_version: None,
            max_throttle_wait: None,
            sandbox_v2: true,
        }
    }

    /// Reads `MODAL_*` environment variables and the profile named by
    /// `MODAL_PROFILE` (or the `active` one) in `~/.modal.toml`
    /// (or `MODAL_CONFIG_PATH`).
    pub fn from_env() -> Result<Self> {
        let env = |key: &str| std::env::var(key).ok().filter(|v| !v.is_empty());
        let path = match env("MODAL_CONFIG_PATH") {
            Some(path) => Some(PathBuf::from(path)),
            None => env("HOME").map(|home| PathBuf::from(home).join(".modal.toml")),
        };
        let file = match path {
            Some(path) => match std::fs::read_to_string(&path) {
                Ok(contents) => Some(contents),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                Err(err) => {
                    return Err(Error::Config(format!("reading {}: {err}", path.display())));
                }
            },
            None => None,
        };
        Self::resolve(file.as_deref(), env)
    }

    /// Resolves a config from the contents of a `.modal.toml` and an
    /// environment lookup. Split out from [`Config::from_env`] for tests.
    pub(crate) fn resolve(
        file: Option<&str>,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<Self> {
        let mut profiles: HashMap<String, RawProfile> = match file {
            Some(contents) => toml::from_str(contents)
                .map_err(|err| Error::Config(format!("parsing .modal.toml: {err}")))?,
            None => HashMap::new(),
        };
        let name = env("MODAL_PROFILE").or_else(|| {
            profiles
                .iter()
                .find(|(_, profile)| profile.active)
                .map(|(name, _)| name.clone())
        });
        let raw = name
            .and_then(|name| profiles.remove(&name))
            .unwrap_or_default();

        if env("MODAL_OAUTH_REFRESH_TOKEN").is_some() {
            return Err(Error::Config(
                "OAuth credentials are not supported by this client; use MODAL_TOKEN_ID and MODAL_TOKEN_SECRET".into(),
            ));
        }

        let token_id = env("MODAL_TOKEN_ID").or(raw.token_id).unwrap_or_default();
        let token_secret = env("MODAL_TOKEN_SECRET")
            .or(raw.token_secret)
            .unwrap_or_default();
        if token_id.is_empty() || token_secret.is_empty() {
            return Err(Error::Config(
                "missing credentials: set MODAL_TOKEN_ID and MODAL_TOKEN_SECRET, or run `modal token new`".into(),
            ));
        }

        let max_throttle_wait = env("MODAL_MAX_THROTTLE_WAIT")
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs);

        let mut sandbox_v2 = raw.sandbox_v2.unwrap_or(true);
        if let Some(v) = env("MODAL_SANDBOX_V2") {
            sandbox_v2 = !matches!(v.to_ascii_lowercase().as_str(), "0" | "false");
        }

        Ok(Self {
            server_url: env("MODAL_SERVER_URL")
                .or(raw.server_url)
                .unwrap_or_else(|| DEFAULT_SERVER_URL.to_string()),
            token_id,
            token_secret,
            environment: env("MODAL_ENVIRONMENT").or(raw.environment),
            image_builder_version: env("MODAL_IMAGE_BUILDER_VERSION").or(raw.image_builder_version),
            max_throttle_wait,
            sandbox_v2,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_from(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |key| map.get(key).cloned()
    }

    const FILE: &str = r#"
[default]
token_id = "ak-default"
token_secret = "as-default"

[work]
token_id = "ak-work"
token_secret = "as-work"
environment = "staging"
active = true
"#;

    #[test]
    fn picks_the_active_profile() {
        let config = Config::resolve(Some(FILE), env_from(&[])).unwrap();
        assert_eq!(config.token_id, "ak-work");
        assert_eq!(config.environment.as_deref(), Some("staging"));
        assert_eq!(config.server_url, DEFAULT_SERVER_URL);
        assert!(config.sandbox_v2);
    }

    #[test]
    fn modal_profile_and_env_vars_take_precedence() {
        let config = Config::resolve(
            Some(FILE),
            env_from(&[
                ("MODAL_PROFILE", "default"),
                ("MODAL_TOKEN_SECRET", "as-env"),
                ("MODAL_SANDBOX_V2", "false"),
                ("MODAL_MAX_THROTTLE_WAIT", "0"),
            ]),
        )
        .unwrap();
        assert_eq!(config.token_id, "ak-default");
        assert_eq!(config.token_secret, "as-env");
        assert!(!config.sandbox_v2);
        assert_eq!(config.max_throttle_wait, Some(Duration::ZERO));
    }

    #[test]
    fn missing_credentials_is_an_error() {
        let err = Config::resolve(None, env_from(&[])).unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn debug_redacts_the_secret() {
        let config = Config::with_token("ak-1", "as-very-secret");
        assert!(!format!("{config:?}").contains("as-very-secret"));
    }
}
