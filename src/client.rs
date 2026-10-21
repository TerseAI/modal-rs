//! Connection to Modal's control plane (`api.modal.com`): required headers,
//! auth tokens, and the retry policy every unary call goes through.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex as AsyncMutex;
use tonic::codegen::http::Uri;
use tonic::metadata::{MetadataMap, MetadataValue};
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tonic::{Request, Response, Status};

use crate::auth::AuthTokenManager;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::proto::client::modal_client_client::ModalClientClient;
use crate::proto::client::{self as pb, ClientType};
use crate::retry::{is_retryable, server_retry_after};

pub(crate) type Stub = ModalClientClient<Channel>;

pub(crate) const MAX_MESSAGE_SIZE: usize = 100 * 1024 * 1024;
pub(crate) const WINDOW_SIZE: u32 = 64 * 1024 * 1024;

/// Modal assigns a client type per official SDK and has none for Rust. This
/// crate is a port of the Go SDK and identifies as it; confirm with Modal
/// before relying on that in production.
const CLIENT_TYPE: ClientType = ClientType::LibmodalGo;
/// "Behaves like this Python SDK version", the same value the Go SDK sends.
const CLIENT_VERSION: &str = "1.0.0";
/// Modal reads the SDK version for its client type from this header and
/// refuses to create Apps without one it can parse, so it has to be
/// `modal-go/<semver>`. The version is the Go SDK this crate ports (see
/// proto/UPSTREAM.md); this crate's own version rides along as semver build
/// metadata.
const SDK_VERSION: &str = concat!("modal-go/0.11.1+modal-rs.", env!("CARGO_PKG_VERSION"));

/// Calls a control plane RPC through [`Client::unary`]:
/// `cp_call!(client, sandbox_wait_v2, request)` or with explicit
/// [`CallOptions`] as a fourth argument.
macro_rules! cp_call {
    ($client:expr, $method:ident, $req:expr) => {
        $client.unary(
            stringify!($method),
            $req,
            |mut stub: $crate::client::Stub, request| async move { stub.$method(request).await },
        )
    };
    ($client:expr, $method:ident, $req:expr, $opts:expr) => {
        $client.unary_with(
            stringify!($method),
            $opts,
            $req,
            |mut stub: $crate::client::Stub, request| async move { stub.$method(request).await },
        )
    };
}
pub(crate) use cp_call;

/// Retry settings for one control plane call.
#[derive(Clone, Debug)]
pub(crate) struct CallOptions {
    pub retries: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub factor: f64,
    /// Per-attempt deadline.
    pub timeout: Option<Duration>,
}

impl Default for CallOptions {
    fn default() -> Self {
        Self {
            retries: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(1),
            factor: 2.0,
            timeout: None,
        }
    }
}

/// A Modal client. Cheap to clone; clones share one connection.
#[derive(Clone)]
pub struct Client {
    pub(crate) inner: Arc<Inner>,
}

pub(crate) struct Inner {
    pub(crate) config: Config,
    stub: Stub,
    /// Headers sent on every control plane call.
    headers: MetadataMap,
    auth: AuthTokenManager,
    /// Image builder version per environment name.
    builder_versions: AsyncMutex<HashMap<String, String>>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("config", &self.inner.config)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Creates a client from `MODAL_*` environment variables and `~/.modal.toml`.
    ///
    /// Must be called from within a Tokio runtime. The connection is opened
    /// lazily by the first call.
    pub fn from_env() -> Result<Self> {
        Self::new(Config::from_env()?)
    }

    /// Creates a client from an explicit config. Must be called from within a
    /// Tokio runtime.
    pub fn new(config: Config) -> Result<Self> {
        let uri: Uri = config
            .server_url
            .parse()
            .map_err(|_| Error::Config(format!("invalid server URL: {}", config.server_url)))?;
        let host = uri
            .host()
            .ok_or_else(|| Error::Config(format!("invalid server URL: {}", config.server_url)))?
            .to_string();
        let mut endpoint = configure_endpoint(Endpoint::from(uri.clone()));
        match uri.scheme_str() {
            Some("https") => {
                endpoint = endpoint.tls_config(
                    ClientTlsConfig::new()
                        .with_webpki_roots()
                        .domain_name(&host),
                )?;
            }
            Some("http") => {}
            _ => {
                return Err(Error::Config(format!(
                    "server URL must start with https:// or http://: {}",
                    config.server_url
                )));
            }
        }
        let stub = ModalClientClient::new(endpoint.connect_lazy())
            .max_decoding_message_size(MAX_MESSAGE_SIZE)
            .max_encoding_message_size(MAX_MESSAGE_SIZE);

        let mut headers = MetadataMap::new();
        let mut put = |key: &'static str, value: &str| -> Result<()> {
            let value = MetadataValue::try_from(value)
                .map_err(|_| Error::Config(format!("{key} is not a valid header value")))?;
            headers.insert(key, value);
            Ok(())
        };
        put("x-modal-client-type", &(CLIENT_TYPE as i32).to_string())?;
        put("x-modal-client-version", CLIENT_VERSION)?;
        put("x-modal-libmodal-version", SDK_VERSION)?;
        put("x-modal-host", &host)?;
        put("x-modal-token-id", &config.token_id)?;
        put("x-modal-token-secret", &config.token_secret)?;

        Ok(Self {
            inner: Arc::new(Inner {
                config,
                stub,
                headers,
                auth: AuthTokenManager::new(),
                builder_versions: AsyncMutex::new(HashMap::new()),
            }),
        })
    }

    pub fn config(&self) -> &Config {
        &self.inner.config
    }

    /// The environment a call should target: the explicit one, else the
    /// configured default, else the workspace default (empty).
    pub(crate) fn environment_name(&self, explicit: Option<&str>) -> String {
        explicit
            .or(self.inner.config.environment.as_deref())
            .unwrap_or_default()
            .to_string()
    }

    /// Runs a unary control plane call with auth and the default retry policy.
    pub(crate) async fn unary<Req, Resp, F, Fut>(
        &self,
        method: &'static str,
        req: Req,
        f: F,
    ) -> Result<Resp, Status>
    where
        Req: Clone,
        F: Fn(Stub, Request<Req>) -> Fut,
        Fut: Future<Output = Result<Response<Resp>, Status>>,
    {
        self.unary_with(method, CallOptions::default(), req, f)
            .await
    }

    pub(crate) async fn unary_with<Req, Resp, F, Fut>(
        &self,
        method: &'static str,
        opts: CallOptions,
        req: Req,
        f: F,
    ) -> Result<Resp, Status>
    where
        Req: Clone,
        F: Fn(Stub, Request<Req>) -> Fut,
        Fut: Future<Output = Result<Response<Resp>, Status>>,
    {
        let token = self.inner.auth.get_token(self).await?;
        self.call_with_retries(method, &opts, Some(&token), req, f)
            .await
    }

    /// The retry loop from the Go SDK's retry interceptor. Every attempt of a
    /// logical call shares one idempotency key. Transient codes are retried
    /// with exponential backoff; a server-attached `RPCRetryPolicy` is honoured
    /// without counting against the retry budget.
    pub(crate) async fn call_with_retries<Req, Resp, F, Fut>(
        &self,
        method: &'static str,
        opts: &CallOptions,
        auth_token: Option<&str>,
        req: Req,
        f: F,
    ) -> Result<Resp, Status>
    where
        Req: Clone,
        F: Fn(Stub, Request<Req>) -> Fut,
        Fut: Future<Output = Result<Response<Resp>, Status>>,
    {
        let auth_token = auth_token
            .map(MetadataValue::try_from)
            .transpose()
            .map_err(|_| Status::internal("auth token is not a valid header value"))?;
        let idempotency_key = MetadataValue::try_from(uuid::Uuid::new_v4().to_string())
            .expect("a UUID is a valid header value");
        let max_throttle_wait = self.inner.config.max_throttle_wait;
        let throttle_enabled = max_throttle_wait != Some(Duration::ZERO);
        let start = Instant::now();
        let mut delay = opts.base_delay;
        let mut attempt: u32 = 0;
        let mut throttle_retries: u32 = 0;

        loop {
            let mut request = Request::new(req.clone());
            let md = request.metadata_mut();
            *md = self.inner.headers.clone();
            if let Some(token) = &auth_token {
                md.insert("x-modal-auth-token", token.clone());
            }
            md.insert("x-idempotency-key", idempotency_key.clone());
            md.insert("x-retry-attempt", attempt.into());
            md.insert("x-throttle-retry-attempt", throttle_retries.into());
            if attempt > 0 || throttle_retries > 0 {
                let elapsed =
                    MetadataValue::try_from(format!("{:.3}", start.elapsed().as_secs_f64()))
                        .expect("a number is a valid header value");
                if attempt > 0 {
                    md.insert("x-retry-delay", elapsed.clone());
                }
                if throttle_retries > 0 {
                    md.insert("x-throttle-retry-delay", elapsed);
                }
            }
            if let Some(timeout) = opts.timeout {
                request.set_timeout(timeout);
            }

            let status = match f(self.inner.stub.clone(), request).await {
                Ok(response) => return Ok(response.into_inner()),
                Err(status) => status,
            };

            if throttle_enabled && let Some(server_delay) = server_retry_after(&status) {
                if let Some(max) = max_throttle_wait
                    && start.elapsed() + server_delay >= max
                {
                    return Err(status);
                }
                if throttle_retries.is_multiple_of(10) {
                    tracing::warn!(
                        method,
                        ?server_delay,
                        throttle_retries,
                        "Modal requested a retry delay; retrying"
                    );
                } else {
                    tracing::debug!(
                        method,
                        ?server_delay,
                        throttle_retries,
                        "Modal requested a retry delay"
                    );
                }
                tokio::time::sleep(server_delay).await;
                throttle_retries += 1;
                continue;
            }

            if !is_retryable(status.code()) || attempt >= opts.retries {
                return Err(status);
            }
            tracing::debug!(method, code = ?status.code(), message = status.message(), attempt, ?delay, "retrying Modal call");
            tokio::time::sleep(delay).await;
            delay = delay.mul_f64(opts.factor).min(opts.max_delay);
            attempt += 1;
        }
    }

    /// A request carrying the required headers, for streaming calls. Like the
    /// Go SDK, streams get no auth token and no retries.
    pub(crate) fn stream_request<Req>(&self, req: Req) -> Request<Req> {
        let mut request = Request::new(req);
        *request.metadata_mut() = self.inner.headers.clone();
        request
    }

    pub(crate) fn stub(&self) -> Stub {
        self.inner.stub.clone()
    }

    /// The image builder version for an environment, from the config override
    /// or the environment's settings (cached).
    pub(crate) async fn image_builder_version(&self, environment: Option<&str>) -> Result<String> {
        if let Some(version) = &self.inner.config.image_builder_version {
            return Ok(version.clone());
        }
        let name = self.environment_name(environment);
        let mut cache = self.inner.builder_versions.lock().await;
        if let Some(version) = cache.get(&name) {
            return Ok(version.clone());
        }
        let response = cp_call!(
            self,
            environment_get_or_create,
            pb::EnvironmentGetOrCreateRequest {
                deployment_name: name.clone(),
                ..Default::default()
            }
        )
        .await?;
        let version = response
            .metadata
            .and_then(|metadata| metadata.settings)
            .map(|settings| settings.image_builder_version)
            .unwrap_or_default();
        cache.insert(name, version.clone());
        Ok(version)
    }
}

/// HTTP/2 settings shared by the control plane and command router connections.
pub(crate) fn configure_endpoint(endpoint: Endpoint) -> Endpoint {
    endpoint
        .initial_stream_window_size(Some(WINDOW_SIZE))
        .initial_connection_window_size(Some(WINDOW_SIZE))
        .http2_keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(10))
        .keep_alive_while_idle(true)
        .connect_timeout(Duration::from_secs(30))
}
