//! Client for the task command router: the gRPC service on the worker running a
//! Sandbox, reached directly rather than through `api.modal.com`. Exec and
//! stdio go through it, authenticated with a short-lived JWT that the control
//! plane hands out per task.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tonic::codegen::http::Uri;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tonic::{Code, Request, Response, Status};

use crate::client::{Client, MAX_MESSAGE_SIZE, configure_endpoint, cp_call};
use crate::error::{Error, Result};
use crate::proto::client::{
    SandboxGetCommandRouterAccessRequest, TaskGetCommandRouterAccessRequest,
    sandbox_get_command_router_access_request::Target,
};
use crate::proto::task_command_router::{
    self as tcr, task_command_router_client::TaskCommandRouterClient,
};
use crate::retry::{is_retryable, jwt_expiry, server_retry_after, unix_now};

pub(crate) type RouterStub = TaskCommandRouterClient<Channel>;

/// Refresh the JWT when it has less than this left.
const JWT_REFRESH_BUFFER_SECS: i64 = 30;

/// Where to reach a task's command router and the token to present.
#[derive(Clone, Debug)]
pub(crate) struct Access {
    pub jwt: String,
    pub url: String,
}

/// Retry settings for one command router call.
#[derive(Clone, Debug)]
pub(crate) struct RetryOpts {
    pub base_delay: Duration,
    pub factor: f64,
    /// `None` retries until `deadline`.
    pub max_retries: Option<u32>,
    pub deadline: Option<Instant>,
    /// Codes not to retry even though they are normally transient.
    pub exclude: &'static [Code],
    /// Per-attempt deadline, clamped to `deadline`.
    pub call_timeout: Option<Duration>,
}

impl Default for RetryOpts {
    fn default() -> Self {
        Self {
            base_delay: Duration::from_millis(10),
            factor: 2.0,
            max_retries: Some(10),
            deadline: None,
            exclude: &[],
            call_timeout: None,
        }
    }
}

/// Returned by [`CommandRouter::call`] when `RetryOpts::deadline` passes.
pub(crate) const DEADLINE_REACHED: &str = "command router deadline reached";

struct Jwt {
    header: MetadataValue<tonic::metadata::Ascii>,
    exp: Option<i64>,
}

pub(crate) struct CommandRouter {
    client: Client,
    stub: RouterStub,
    pub(crate) task_id: String,
    pub(crate) sandbox_id: String,
    is_v2: bool,
    url: String,
    jwt: Mutex<Jwt>,
    refresh: tokio::sync::Mutex<()>,
}

impl CommandRouter {
    /// Connects to a task's command router. `access` is what `SandboxCreateV2`
    /// returned, which saves a round trip; `None` looks it up.
    pub(crate) async fn connect(
        client: &Client,
        task_id: &str,
        sandbox_id: &str,
        is_v2: bool,
        access: Option<Access>,
    ) -> Result<Arc<Self>> {
        let access = match access {
            Some(access) => access,
            None => fetch_access(client, task_id, sandbox_id, is_v2).await?,
        };
        let uri: Uri = access
            .url
            .parse()
            .map_err(|_| Error::Remote(format!("invalid command router URL: {}", access.url)))?;
        if uri.scheme_str() != Some("https") {
            return Err(Error::Remote(format!(
                "command router URL must be https, got {}",
                access.url
            )));
        }
        let host = uri
            .host()
            .ok_or_else(|| Error::Remote(format!("invalid command router URL: {}", access.url)))?
            .to_string();
        let port = uri.port_u16().unwrap_or(443);
        let authority = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };

        // Against a local Modal server the router is plaintext, as in the Go SDK.
        let endpoint = if is_localhost(&client.inner.config.server_url) {
            configure_endpoint(Endpoint::from_shared(format!("http://{authority}"))?)
        } else {
            configure_endpoint(Endpoint::from_shared(format!("https://{authority}"))?).tls_config(
                ClientTlsConfig::new()
                    .with_webpki_roots()
                    .domain_name(&host),
            )?
        };
        let stub = TaskCommandRouterClient::new(endpoint.connect_lazy())
            .max_decoding_message_size(MAX_MESSAGE_SIZE)
            .max_encoding_message_size(MAX_MESSAGE_SIZE);

        tracing::debug!(task_id, url = %access.url, "connected to command router");
        Ok(Arc::new(Self {
            client: client.clone(),
            stub,
            task_id: task_id.to_string(),
            sandbox_id: sandbox_id.to_string(),
            is_v2,
            url: access.url,
            jwt: Mutex::new(parse_jwt(&access.jwt)?),
            refresh: tokio::sync::Mutex::new(()),
        }))
    }

    pub(crate) fn stub(&self) -> RouterStub {
        self.stub.clone()
    }

    /// Wraps a request with the router's auth headers.
    pub(crate) fn request<Req>(&self, req: Req, throttle_attempt: u32) -> Request<Req> {
        let mut request = Request::new(req);
        let md = request.metadata_mut();
        md.insert("authorization", self.jwt.lock().unwrap().header.clone());
        md.insert("x-throttle-retry-attempt", throttle_attempt.into());
        request
    }

    fn jwt_is_fresh(&self) -> bool {
        self.jwt
            .lock()
            .unwrap()
            .exp
            .is_some_and(|exp| exp - unix_now() > JWT_REFRESH_BUFFER_SECS)
    }

    /// Fetches a new JWT unless the current one has a while left. Concurrent
    /// callers share one fetch.
    pub(crate) async fn refresh_jwt(&self) -> Result<()> {
        if self.jwt_is_fresh() {
            return Ok(());
        }
        let _guard = self.refresh.lock().await;
        if self.jwt_is_fresh() {
            return Ok(());
        }
        let access =
            fetch_access(&self.client, &self.task_id, &self.sandbox_id, self.is_v2).await?;
        if access.url != self.url {
            tracing::warn!(task_id = %self.task_id, "command router URL changed during the session");
        }
        let jwt = match parse_jwt(&access.jwt) {
            Ok(jwt) => jwt,
            Err(err) => {
                // Use it anyway; the next auth failure refreshes again.
                tracing::warn!(error = %err, "could not read command router JWT expiry");
                Jwt {
                    header: bearer(&access.jwt)?,
                    exp: None,
                }
            }
        };
        *self.jwt.lock().unwrap() = jwt;
        Ok(())
    }

    /// Runs a unary router call: one JWT refresh on `Unauthenticated`,
    /// server-requested throttle delays on `ResourceExhausted`, and backoff on
    /// transient codes. Port of the Go SDK's `callWithRetriesOnTransientErrors`.
    pub(crate) async fn call<Req, Resp, F, Fut>(
        &self,
        opts: &RetryOpts,
        req: Req,
        f: F,
    ) -> Result<Resp>
    where
        Req: Clone,
        F: Fn(RouterStub, Request<Req>) -> Fut,
        Fut: Future<Output = Result<Response<Resp>, Status>>,
    {
        let max_throttle_wait = self.client.inner.config.max_throttle_wait;
        let throttle_disabled = max_throttle_wait == Some(Duration::ZERO);
        let mut delay = opts.base_delay;
        let mut retries: u32 = 0;
        let mut throttled: u32 = 0;
        let mut throttle_waited = Duration::ZERO;

        loop {
            if let Some(deadline) = opts.deadline
                && Instant::now() >= deadline
            {
                return Err(Error::Timeout(DEADLINE_REACHED.into()));
            }
            let attempt = |throttled| {
                let mut request = self.request(req.clone(), throttled);
                let remaining = opts
                    .deadline
                    .map(|d| d.saturating_duration_since(Instant::now()));
                let timeout = match (opts.call_timeout, remaining) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
                if let Some(timeout) = timeout {
                    request.set_timeout(timeout.max(Duration::from_millis(1)));
                }
                f(self.stub.clone(), request)
            };

            let mut result = attempt(throttled).await;
            if let Err(status) = &result
                && status.code() == Code::Unauthenticated
            {
                self.refresh_jwt().await?;
                result = attempt(throttled).await;
            }
            let status = match result {
                Ok(response) => return Ok(response.into_inner()),
                Err(status) => status,
            };
            let excluded = opts.exclude.contains(&status.code());

            if status.code() == Code::ResourceExhausted
                && !throttle_disabled
                && !excluded
                && let Some(retry_after) = server_retry_after(&status)
            {
                if let Some(deadline) = opts.deadline
                    && Instant::now() + retry_after >= deadline
                {
                    return Err(Error::Timeout(DEADLINE_REACHED.into()));
                }
                if let Some(max) = max_throttle_wait
                    && throttle_waited + retry_after > max
                {
                    return Err(status.into());
                }
                tracing::debug!(
                    ?retry_after,
                    throttled,
                    "command router requested a retry delay"
                );
                tokio::time::sleep(retry_after).await;
                throttled += 1;
                throttle_waited += retry_after;
                continue;
            }

            if !is_retryable(status.code()) || excluded {
                return Err(status.into());
            }
            if opts.max_retries.is_some_and(|max| retries >= max) {
                return Err(status.into());
            }
            let mut sleep_for = delay;
            if let Some(deadline) = opts.deadline {
                sleep_for = sleep_for.min(deadline.saturating_duration_since(Instant::now()));
            }
            tracing::debug!(code = ?status.code(), message = status.message(), retries, "retrying command router call");
            tokio::time::sleep(sleep_for).await;
            delay = delay.mul_f64(opts.factor);
            retries += 1;
        }
    }

    pub(crate) async fn exec_start(&self, request: tcr::TaskExecStartRequest) -> Result<()> {
        self.call(
            &RetryOpts::default(),
            request,
            |mut stub, request| async move { stub.task_exec_start(request).await },
        )
        .await?;
        Ok(())
    }

    pub(crate) async fn exec_stdin_write(
        &self,
        exec_id: &str,
        offset: u64,
        data: Vec<u8>,
        eof: bool,
    ) -> Result<()> {
        let request = tcr::TaskExecStdinWriteRequest {
            task_id: self.task_id.clone(),
            exec_id: exec_id.to_string(),
            offset,
            data,
            eof,
        };
        self.call(
            &RetryOpts::default(),
            request,
            |mut stub, request| async move { stub.task_exec_stdin_write(request).await },
        )
        .await?;
        Ok(())
    }

    /// Waits for an exec to finish. Retries every second for as long as it
    /// takes, or until the exec's own deadline.
    pub(crate) async fn exec_wait(
        &self,
        exec_id: &str,
        deadline: Option<Instant>,
    ) -> Result<tcr::TaskExecWaitResponse> {
        let timed_out = || {
            Error::ExecTimeout(format!(
                "deadline exceeded while waiting for exec {exec_id}"
            ))
        };
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(timed_out());
        }
        let opts = RetryOpts {
            base_delay: Duration::from_secs(1),
            factor: 1.0,
            max_retries: None,
            deadline,
            exclude: &[],
            call_timeout: Some(Duration::from_secs(60)),
        };
        let request = tcr::TaskExecWaitRequest {
            task_id: self.task_id.clone(),
            exec_id: exec_id.to_string(),
        };
        let result = self
            .call(&opts, request, |mut stub, request| async move {
                stub.task_exec_wait(request).await
            })
            .await;
        match result {
            Err(Error::Timeout(_)) => Err(timed_out()),
            Err(err) if err.grpc_code() == Some(Code::DeadlineExceeded) && deadline.is_some() => {
                Err(timed_out())
            }
            other => other,
        }
    }

    pub(crate) async fn sandbox_stdin_write(
        &self,
        offset: u64,
        data: Vec<u8>,
        eof: bool,
    ) -> Result<()> {
        let request = tcr::SandboxStdinWriteV2Request {
            task_id: self.task_id.clone(),
            offset,
            data,
            eof,
        };
        self.call(
            &RetryOpts::default(),
            request,
            |mut stub, request| async move { stub.sandbox_stdin_write_v2(request).await },
        )
        .await?;
        Ok(())
    }

    /// Waits until the Sandbox's readiness probe passes.
    pub(crate) async fn wait_until_ready(&self, timeout: Duration) -> Result<()> {
        let opts = RetryOpts {
            deadline: Some(Instant::now() + timeout),
            ..Default::default()
        };
        let request = tcr::SandboxWaitUntilReadyTcrRequest {
            task_id: self.task_id.clone(),
            timeout: timeout.as_secs_f32(),
        };
        let result = self
            .call(&opts, request, |mut stub, request| async move {
                stub.sandbox_wait_until_ready(request).await
            })
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(Error::Timeout(_)) => Err(Error::Timeout(
                "Sandbox did not become ready in time".into(),
            )),
            Err(err) => Err(err),
        }
    }
}

async fn fetch_access(
    client: &Client,
    task_id: &str,
    sandbox_id: &str,
    is_v2: bool,
) -> Result<Access> {
    if is_v2 {
        let response = cp_call!(
            client,
            sandbox_get_command_router_access,
            SandboxGetCommandRouterAccessRequest {
                target: Some(Target::SandboxId(sandbox_id.to_string())),
            }
        )
        .await?;
        Ok(Access {
            jwt: response.jwt,
            url: response.url,
        })
    } else {
        let response = cp_call!(
            client,
            task_get_command_router_access,
            TaskGetCommandRouterAccessRequest {
                task_id: task_id.to_string(),
            }
        )
        .await?;
        Ok(Access {
            jwt: response.jwt,
            url: response.url,
        })
    }
}

fn bearer(jwt: &str) -> Result<MetadataValue<tonic::metadata::Ascii>> {
    MetadataValue::try_from(format!("Bearer {jwt}"))
        .map_err(|_| Error::Remote("command router JWT is not a valid header value".into()))
}

fn parse_jwt(jwt: &str) -> Result<Jwt> {
    let exp = jwt_expiry(jwt).map_err(Error::Remote)?;
    Ok(Jwt {
        header: bearer(jwt)?,
        exp,
    })
}

fn is_localhost(server_url: &str) -> bool {
    server_url
        .parse::<Uri>()
        .ok()
        .and_then(|uri| uri.host().map(str::to_string))
        .is_some_and(|host| {
            matches!(
                host.trim_start_matches('[').trim_end_matches(']'),
                "localhost" | "127.0.0.1" | "::1" | "172.21.0.1"
            )
        })
}
