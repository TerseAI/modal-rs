use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tonic::Code;

use crate::app::App;
use crate::client::{Client, cp_call};
use crate::error::{Error, Result};
use crate::image::{Image, parse_gpu_config};
use crate::process::{ContainerProcess, OutputStream, Stdin, StdioBehavior, StdioStream};
use crate::proto::client::{
    self as pb, GenericResult, PtyInfo, generic_result::GenericStatus,
    network_access::NetworkAccessType, probe::ProbeOneof, pty_info::PtyType,
};
use crate::proto::task_command_router::{self as tcr, TaskExecStderrConfig, TaskExecStdoutConfig};
use crate::router::{Access, CommandRouter};
use crate::secret::{self, Secret};

/// How long a V1 create waits for capacity before giving up.
const SANDBOX_SCHEDULING_TIMEOUT: Duration = Duration::from_secs(21 * 60);
/// How long operations that need a running task wait for one.
const GET_TASK_ID_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const TASK_ID_POLL_INTERVAL: Duration = Duration::from_millis(500);
/// Linux allows 2^17 bytes of exec arguments; leave room for the runtime's own.
const MAX_EXEC_ARG_BYTES: usize = 1 << 16;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

/// Calls the V1 or V2 flavour of a Sandbox RPC depending on the Sandbox.
macro_rules! sb_call {
    ($sb:expr, $v1:ident, $v2:ident, $req:expr) => {
        if $sb.inner.is_v2 {
            cp_call!($sb.inner.client, $v2, $req).await
        } else {
            cp_call!($sb.inner.client, $v1, $req).await
        }
    };
}

/// Options for [`Client::create_sandbox`]. Everything defaults to Modal's
/// defaults.
#[derive(Clone, Debug, Default)]
pub struct SandboxCreateParams {
    /// Command to run on startup. Without one the Sandbox idles until terminated.
    pub command: Vec<String>,
    /// CPU request in physical cores.
    pub cpu: Option<f64>,
    /// Hard CPU limit in physical cores. Requires `cpu`.
    pub cpu_limit: Option<f64>,
    pub memory_mib: Option<u32>,
    /// Hard memory limit. Requires `memory_mib`.
    pub memory_limit_mib: Option<u32>,
    /// GPU, e.g. "T4", "A100-80GB:4". GPU Sandboxes run on Modal's V1 backend.
    pub gpu: Option<String>,
    /// Maximum lifetime, in whole seconds. Defaults to 5 minutes.
    pub timeout: Option<Duration>,
    /// Terminate after this long without activity, in whole seconds.
    pub idle_timeout: Option<Duration>,
    /// Absolute working directory.
    pub workdir: Option<String>,
    pub env: HashMap<String, String>,
    pub secrets: Vec<Secret>,
    /// Run the entrypoint under a PTY; stderr is then merged into stdout.
    pub pty: bool,
    /// Ports exposed through TLS tunnels.
    pub encrypted_ports: Vec<u16>,
    /// Ports exposed through HTTP/2 tunnels.
    pub h2_ports: Vec<u16>,
    /// Ports exposed as plain TCP.
    pub unencrypted_ports: Vec<u16>,
    /// Block all network access, including i6pn.
    pub block_network: bool,
    /// When set, outbound traffic is limited to these CIDRs (empty blocks all).
    pub outbound_cidr_allowlist: Option<Vec<String>>,
    /// When set, outbound traffic is limited to these domains (`*.example.com` allowed).
    pub outbound_domain_allowlist: Option<Vec<String>>,
    /// CIDRs allowed to connect inbound through tunnels and connect tokens.
    pub inbound_cidr_allowlist: Option<Vec<String>>,
    /// Private IPv6 networking between Sandboxes in the workspace.
    pub i6pn: bool,
    pub cloud: Option<String>,
    pub regions: Vec<String>,
    /// Unique within the App; lets [`Client::sandbox_from_name`] find it.
    pub name: Option<String>,
    pub tags: HashMap<String, String>,
    pub readiness_probe: Option<Probe>,
    pub runtime: Option<SandboxRuntime>,
    pub verbose: bool,
    pub custom_domain: Option<String>,
    pub include_oidc_identity_token: bool,
    /// Allow memory snapshots of this Sandbox.
    pub enable_snapshot: bool,
    pub experimental_options: HashMap<String, String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SandboxRuntime {
    Gvisor,
    Vm,
}

/// A readiness probe, checked by [`Sandbox::wait_until_ready`].
#[derive(Clone, Debug)]
pub struct Probe {
    check: ProbeOneof,
    interval: Duration,
}

impl Probe {
    /// Ready once the port accepts TCP connections.
    pub fn tcp(port: u16) -> Self {
        Self {
            check: ProbeOneof::TcpPort(port.into()),
            interval: Duration::from_millis(100),
        }
    }

    /// Ready once the command exits 0.
    pub fn exec<I: IntoIterator<Item = S>, S: Into<String>>(argv: I) -> Self {
        Self {
            check: ProbeOneof::ExecCommand(pb::probe::ExecCommand {
                argv: argv.into_iter().map(Into::into).collect(),
            }),
            interval: Duration::from_millis(100),
        }
    }

    /// How often to check, in whole milliseconds. Defaults to 100ms.
    pub fn interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    fn to_proto(&self) -> Result<pb::Probe> {
        if let ProbeOneof::ExecCommand(command) = &self.check
            && command.argv.is_empty()
        {
            return Err(Error::Invalid("an exec probe needs a command".into()));
        }
        let ms = self.interval.as_millis();
        if ms == 0
            || !self.interval.subsec_nanos().is_multiple_of(1_000_000)
            || ms > u32::MAX as u128
        {
            return Err(Error::Invalid(format!(
                "probe interval must be a positive whole number of milliseconds, got {:?}",
                self.interval
            )));
        }
        Ok(pb::Probe {
            interval_ms: Some(ms as u32),
            probe_oneof: Some(self.check.clone()),
        })
    }
}

/// Options for [`Sandbox::exec`].
#[derive(Clone, Debug, Default)]
pub struct ExecParams {
    pub stdout: StdioBehavior,
    pub stderr: StdioBehavior,
    /// Absolute working directory.
    pub workdir: Option<String>,
    /// Kill the command after this long, in whole seconds.
    pub timeout: Option<Duration>,
    pub env: HashMap<String, String>,
    pub secrets: Vec<Secret>,
    /// Run under a PTY; stderr is then merged into stdout.
    pub pty: bool,
}

/// A port forwarded out of a Sandbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tunnel {
    pub host: String,
    pub port: u16,
    pub unencrypted_host: Option<String>,
    pub unencrypted_port: Option<u16>,
}

impl Tunnel {
    /// The public HTTPS URL.
    pub fn url(&self) -> String {
        if self.port == 443 {
            format!("https://{}", self.host)
        } else {
            format!("https://{}:{}", self.host, self.port)
        }
    }

    /// The plain TCP endpoint, for ports opened with `unencrypted_ports`.
    pub fn tcp_socket(&self) -> Option<(&str, u16)> {
        Some((self.unencrypted_host.as_deref()?, self.unencrypted_port?))
    }
}

impl From<pb::TunnelData> for Tunnel {
    fn from(t: pb::TunnelData) -> Self {
        Self {
            host: t.host,
            port: t.port as u16,
            unencrypted_host: t.unencrypted_host.filter(|h| !h.is_empty()),
            unencrypted_port: t.unencrypted_port.filter(|p| *p != 0).map(|p| p as u16),
        }
    }
}

/// Filters for [`Client::list_sandboxes`].
#[derive(Clone, Debug, Default)]
pub struct SandboxListParams {
    /// The App to list. Without one the whole environment is listed, which
    /// Modal discourages.
    pub app_id: Option<String>,
    /// Only Sandboxes carrying all of these tags.
    pub tags: HashMap<String, String>,
    /// Used only without `app_id`. Defaults to the client's environment.
    pub environment: Option<String>,
}

/// A running Sandbox, as returned by [`Client::list_sandboxes`].
#[derive(Clone, Debug)]
pub struct SandboxInfo {
    pub sandbox_id: String,
    pub app_id: String,
    pub name: Option<String>,
    /// Seconds since the Unix epoch.
    pub created_at: f64,
    /// When the readiness probe first passed, if the Sandbox has one.
    pub ready_at: Option<f64>,
    pub tags: HashMap<String, String>,
    pub regions: Vec<String>,
    pub tunnels: HashMap<u16, Tunnel>,
}

impl From<pb::SandboxInfo> for SandboxInfo {
    fn from(info: pb::SandboxInfo) -> Self {
        Self {
            sandbox_id: info.id,
            app_id: info.app_id,
            name: Some(info.name).filter(|name| !name.is_empty()),
            created_at: info.created_at,
            ready_at: info.ready_at,
            tags: info
                .tags
                .into_iter()
                .map(|tag| (tag.tag_name, tag.tag_value))
                .collect(),
            regions: info.regions,
            tunnels: tunnel_map(info.tunnels),
        }
    }
}

/// Credentials for HTTP connections to a Sandbox port through Modal's proxy.
#[derive(Clone, Debug)]
pub struct ConnectToken {
    pub url: String,
    pub token: String,
}

/// A Modal Sandbox. Cheap to clone; clones share the connection to the worker.
#[derive(Clone)]
pub struct Sandbox {
    inner: Arc<SandboxInner>,
}

struct SandboxInner {
    client: Client,
    sandbox_id: String,
    is_v2: bool,
    task_id: Mutex<Option<String>>,
    /// Router access returned at creation, used for the first connection.
    initial_access: Mutex<Option<Access>>,
    router: tokio::sync::Mutex<Option<Arc<CommandRouter>>>,
    tunnels: Mutex<Option<HashMap<u16, Tunnel>>>,
}

impl std::fmt::Debug for Sandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sandbox")
            .field("sandbox_id", &self.inner.sandbox_id)
            .field("is_v2", &self.inner.is_v2)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Creates a Sandbox, building the image first if needed.
    ///
    /// CPU Sandboxes use Modal's V2 backend unless `Config::sandbox_v2` is off;
    /// GPU Sandboxes use V1, and this waits until one is scheduled.
    pub async fn create_sandbox(
        &self,
        app: &App,
        image: &Image,
        params: SandboxCreateParams,
    ) -> Result<Sandbox> {
        if self.inner.config.sandbox_v2 && params.gpu.is_none() {
            self.create_sandbox_v2(app, image, params).await
        } else {
            self.create_sandbox_v1(app, image, params).await
        }
    }

    async fn create_sandbox_v2(
        &self,
        app: &App,
        image: &Image,
        params: SandboxCreateParams,
    ) -> Result<Sandbox> {
        let image_id = image.build(self, app).await?;
        let (sources, secret_ids) =
            secret::secret_sources(self, &params.secrets, &params.env).await?;
        let (definition, tags) = build_definition(&params, image_id, secret_ids)?;
        let port_count = definition_port_count(&definition);

        let response = cp_call!(
            self,
            sandbox_create_v2,
            pb::SandboxCreateV2Request {
                app_id: app.app_id.clone(),
                definition: Some(definition),
                tags,
                secret_sources: sources,
                ..Default::default()
            }
        )
        .await
        .map_err(|status| Error::from_status_with(status, String::new))?;

        tracing::debug!(sandbox_id = %response.sandbox_id, "created V2 Sandbox");
        let sandbox = Sandbox::new(self.clone(), response.sandbox_id);
        if !response.task_id.is_empty() {
            *sandbox.inner.task_id.lock().unwrap() = Some(response.task_id);
        }
        if let Some(access) = response.command_router_access {
            *sandbox.inner.initial_access.lock().unwrap() = Some(Access {
                jwt: access.jwt,
                url: access.url,
            });
        }
        // Unencrypted tunnel endpoints aren't known at create time, so only a
        // complete set is cached.
        if !response.tunnels.is_empty() && response.tunnels.len() == port_count {
            *sandbox.inner.tunnels.lock().unwrap() = Some(tunnel_map(response.tunnels));
        }
        Ok(sandbox)
    }

    async fn create_sandbox_v1(
        &self,
        app: &App,
        image: &Image,
        params: SandboxCreateParams,
    ) -> Result<Sandbox> {
        let image_id = image.build(self, app).await?;
        secret::validate_env_var_names(&params.env)?;
        let mut secrets = params.secrets.clone();
        if !params.env.is_empty() {
            secrets.push(Secret::from_map(params.env.clone()));
        }
        let secret_ids = secret::resolve_ids(self, &secrets).await?;
        let (definition, tags) = build_definition(&params, image_id, secret_ids)?;

        let response = cp_call!(
            self,
            sandbox_create,
            pb::SandboxCreateRequest {
                app_id: app.app_id.clone(),
                definition: Some(definition),
                tags,
                ..Default::default()
            }
        )
        .await
        .map_err(|status| Error::from_status_with(status, String::new))?;

        tracing::debug!(sandbox_id = %response.sandbox_id, "created V1 Sandbox");
        let sandbox = Sandbox::new(self.clone(), response.sandbox_id);
        sandbox.wait_for_scheduling().await?;
        Ok(sandbox)
    }

    /// A handle to an existing Sandbox. Makes no call.
    pub fn sandbox_from_id(&self, sandbox_id: impl Into<String>) -> Sandbox {
        Sandbox::new(self.clone(), sandbox_id.into())
    }

    /// Running Sandboxes, newest first, filtered by App and tags. With the V2
    /// backend enabled this lists V1 and V2 Sandboxes alike.
    pub async fn list_sandboxes(&self, params: SandboxListParams) -> Result<Vec<SandboxInfo>> {
        let tags: Vec<pb::SandboxTag> = params
            .tags
            .iter()
            .map(|(name, value)| pb::SandboxTag {
                tag_name: name.clone(),
                tag_value: value.clone(),
            })
            .collect();
        let environment_name = match &params.app_id {
            Some(_) => String::new(),
            None => self.environment_name(params.environment.as_deref()),
        };
        let mut sandboxes = Vec::new();
        let mut before = 0.0;
        loop {
            let request = pb::SandboxListRequest {
                app_id: params.app_id.clone().unwrap_or_default(),
                before_timestamp: before,
                environment_name: environment_name.clone(),
                include_finished: false,
                tags: tags.clone(),
            };
            let response = if self.inner.config.sandbox_v2 {
                cp_call!(self, sandbox_list_v2, request).await?
            } else {
                cp_call!(self, sandbox_list, request).await?
            };
            let Some(last) = response.sandboxes.last() else {
                break;
            };
            let next_before = last.created_at;
            sandboxes.extend(response.sandboxes.into_iter().map(SandboxInfo::from));
            // Pages go back in time; stop rather than loop if one doesn't.
            if before != 0.0 && next_before >= before {
                break;
            }
            before = next_before;
        }
        Ok(sandboxes)
    }

    /// Finds a running Sandbox by the name it was created with.
    pub async fn sandbox_from_name(
        &self,
        app_name: &str,
        name: &str,
        environment: Option<&str>,
    ) -> Result<Sandbox> {
        let request = pb::SandboxGetFromNameRequest {
            sandbox_name: name.to_string(),
            app_name: app_name.to_string(),
            environment_name: self.environment_name(environment),
            include_terminated: false,
        };
        let not_found = || format!("Sandbox '{name}' not found in App '{app_name}'");
        if self.inner.config.sandbox_v2 {
            match cp_call!(self, sandbox_get_from_name_v2, request.clone()).await {
                Ok(response) => return Ok(self.sandbox_from_id(response.sandbox_id)),
                Err(status) if status.code() == Code::NotFound => {}
                Err(status) => return Err(status.into()),
            }
        }
        let response = cp_call!(self, sandbox_get_from_name, request)
            .await
            .map_err(|status| Error::from_status_with(status, not_found))?;
        Ok(self.sandbox_from_id(response.sandbox_id))
    }
}

impl Sandbox {
    fn new(client: Client, sandbox_id: String) -> Self {
        let is_v2 = !is_v1_sandbox_id(&sandbox_id);
        Self {
            inner: Arc::new(SandboxInner {
                client,
                sandbox_id,
                is_v2,
                task_id: Mutex::new(None),
                initial_access: Mutex::new(None),
                router: tokio::sync::Mutex::new(None),
                tunnels: Mutex::new(None),
            }),
        }
    }

    pub fn id(&self) -> &str {
        &self.inner.sandbox_id
    }

    /// Whether this Sandbox runs on Modal's V2 backend.
    pub fn is_v2(&self) -> bool {
        self.inner.is_v2
    }

    /// The ID of the task running the Sandbox, waiting up to 5 minutes for one.
    pub async fn task_id(&self) -> Result<String> {
        self.wait_for_task_id(GET_TASK_ID_TIMEOUT, false).await
    }

    /// Waits for the Sandbox to exit and returns its exit code. A timeout
    /// reports 124 and termination 137.
    pub async fn wait(&self) -> Result<i32> {
        loop {
            let response = sb_call!(
                self,
                sandbox_wait,
                sandbox_wait_v2,
                pb::SandboxWaitRequest {
                    sandbox_id: self.inner.sandbox_id.clone(),
                    timeout: 10.0,
                }
            )?;
            if let Some(result) = response.result {
                return Ok(return_code(Some(&result)).unwrap_or(0));
            }
        }
    }

    /// The exit code if the Sandbox has finished, without waiting.
    pub async fn poll(&self) -> Result<Option<i32>> {
        let response = sb_call!(
            self,
            sandbox_wait,
            sandbox_wait_v2,
            pb::SandboxWaitRequest {
                sandbox_id: self.inner.sandbox_id.clone(),
                timeout: 0.0,
            }
        )?;
        Ok(return_code(response.result.as_ref()))
    }

    /// Stops the Sandbox. Follow with [`Sandbox::wait`] for its exit code.
    pub async fn terminate(&self) -> Result<()> {
        sb_call!(
            self,
            sandbox_terminate,
            sandbox_terminate_v2,
            pb::SandboxTerminateRequest {
                sandbox_id: self.inner.sandbox_id.clone(),
            }
        )?;
        Ok(())
    }

    /// Tunnels keyed by container port, waiting up to `timeout` for them.
    pub async fn tunnels(&self, timeout: Duration) -> Result<HashMap<u16, Tunnel>> {
        if let Some(tunnels) = self.inner.tunnels.lock().unwrap().clone() {
            return Ok(tunnels);
        }
        let response = sb_call!(
            self,
            sandbox_get_tunnels,
            sandbox_get_tunnels_v2,
            pb::SandboxGetTunnelsRequest {
                sandbox_id: self.inner.sandbox_id.clone(),
                timeout: timeout.as_secs_f32(),
            }
        )?;
        if response
            .result
            .as_ref()
            .is_some_and(|result| result.status() == GenericStatus::Timeout)
        {
            return Err(Error::Timeout(
                "Sandbox tunnels were not ready in time".into(),
            ));
        }
        let tunnels = tunnel_map(response.tunnels);
        *self.inner.tunnels.lock().unwrap() = Some(tunnels.clone());
        Ok(tunnels)
    }

    /// A token for HTTP connections to `port` (default 8080) through Modal's proxy.
    pub async fn create_connect_token(
        &self,
        port: Option<u16>,
        user_metadata: Option<String>,
    ) -> Result<ConnectToken> {
        let request = pb::SandboxCreateConnectTokenRequest {
            sandbox_id: self.inner.sandbox_id.clone(),
            user_metadata: user_metadata.unwrap_or_default(),
            port: Some(port.unwrap_or(8080).into()),
        };
        let response = sb_call!(
            self,
            sandbox_create_connect_token,
            sandbox_create_connect_token_v2,
            request
        )?;
        Ok(ConnectToken {
            url: response.url,
            token: response.token,
        })
    }

    /// Runs a command in the Sandbox.
    pub async fn exec<I, S>(&self, command: I, params: ExecParams) -> Result<ContainerProcess>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let command: Vec<String> = command.into_iter().map(Into::into).collect();
        if command.is_empty() {
            return Err(Error::Invalid("exec needs a command".into()));
        }
        let arg_bytes: usize = command.iter().map(String::len).sum();
        if arg_bytes > MAX_EXEC_ARG_BYTES {
            return Err(Error::Invalid(format!(
                "exec arguments must total less than {MAX_EXEC_ARG_BYTES} bytes, got {arg_bytes}"
            )));
        }
        validate_workdir(params.workdir.as_deref())?;
        let timeout_secs = params
            .timeout
            .map(|t| whole_seconds(t, "exec timeout"))
            .transpose()?;

        let (secret_sources, _) =
            secret::secret_sources(&self.inner.client, &params.secrets, &params.env).await?;
        let router = self.router().await?;
        let exec_id = uuid::Uuid::new_v4().to_string();
        let pipe_or_null = |behavior| matches!(behavior, StdioBehavior::Pipe);

        router
            .exec_start(tcr::TaskExecStartRequest {
                task_id: router.task_id.clone(),
                exec_id: exec_id.clone(),
                command_args: command,
                stdout_config: if pipe_or_null(params.stdout) {
                    TaskExecStdoutConfig::Pipe
                } else {
                    TaskExecStdoutConfig::Devnull
                } as i32,
                stderr_config: if pipe_or_null(params.stderr) {
                    TaskExecStderrConfig::Pipe
                } else {
                    TaskExecStderrConfig::Devnull
                } as i32,
                timeout_secs: timeout_secs.filter(|s| *s > 0),
                workdir: params.workdir.clone(),
                secret_sources,
                pty_info: params.pty.then(default_pty_info),
                ..Default::default()
            })
            .await?;

        tracing::debug!(exec_id, sandbox_id = %self.inner.sandbox_id, "started exec");
        let deadline = params
            .timeout
            .filter(|t| !t.is_zero())
            .map(|t| Instant::now() + t);
        Ok(ContainerProcess::new(
            router,
            exec_id,
            params.stdout,
            params.stderr,
            deadline,
        ))
    }

    /// The entrypoint's stdout. V2 Sandboxes only; the router keeps only recent
    /// output, so read it as it is produced.
    pub async fn stdout(&self) -> Result<OutputStream> {
        self.entrypoint_stream(StdioStream::Stdout).await
    }

    /// The entrypoint's stderr. V2 Sandboxes only.
    pub async fn stderr(&self) -> Result<OutputStream> {
        self.entrypoint_stream(StdioStream::Stderr).await
    }

    /// The entrypoint's stdin. V2 Sandboxes only.
    pub async fn stdin(&self) -> Result<Stdin> {
        self.ensure_v2("stdin")?;
        Ok(Stdin::sandbox(self.router().await?))
    }

    /// Waits until the readiness probe passes.
    pub async fn wait_until_ready(&self, timeout: Duration) -> Result<()> {
        if timeout.is_zero() {
            return Err(Error::Invalid("timeout must be positive".into()));
        }
        self.router().await?.wait_until_ready(timeout).await
    }

    async fn entrypoint_stream(&self, which: StdioStream) -> Result<OutputStream> {
        self.ensure_v2("entrypoint stdio")?;
        Ok(OutputStream::sandbox(self.router().await?, which))
    }

    fn ensure_v2(&self, what: &str) -> Result<()> {
        if self.inner.is_v2 {
            Ok(())
        } else {
            Err(Error::Invalid(format!(
                "{what} is only supported for V2 Sandboxes in this client"
            )))
        }
    }

    /// The connection to this Sandbox's command router, opened on first use.
    async fn router(&self) -> Result<Arc<CommandRouter>> {
        let task_id = self.wait_for_task_id(GET_TASK_ID_TIMEOUT, false).await?;
        let mut router = self.inner.router.lock().await;
        if let Some(router) = router.as_ref() {
            return Ok(router.clone());
        }
        // Take the access from create so a failed connection falls back to a
        // fresh lookup next time instead of reusing it.
        let access = self.inner.initial_access.lock().unwrap().take();
        let connected = CommandRouter::connect(
            &self.inner.client,
            &task_id,
            &self.inner.sandbox_id,
            self.inner.is_v2,
            access,
        )
        .await?;
        *router = Some(connected.clone());
        Ok(connected)
    }

    /// Blocks until the Sandbox has a task. On failure, terminates it so a
    /// queued Sandbox can't start later with nobody holding it.
    async fn wait_for_scheduling(&self) -> Result<()> {
        let err = match self
            .wait_for_task_id(SANDBOX_SCHEDULING_TIMEOUT, true)
            .await
        {
            Ok(_) => return Ok(()),
            Err(err @ Error::Conflict(_)) => return Err(err),
            Err(err) => err,
        };
        if let Err(terminate_err) = self.terminate().await {
            tracing::debug!(sandbox_id = %self.inner.sandbox_id, error = %terminate_err, "failed to terminate unscheduled Sandbox");
        }
        match err {
            Error::Timeout(_) => Err(Error::ResourceExhausted(
                "insufficient capacity to create the Sandbox".into(),
            )),
            err => Err(err),
        }
    }

    /// Polls until the Sandbox is assigned a task. With `retry_transient`,
    /// transient lookup errors keep polling until the deadline.
    async fn wait_for_task_id(&self, timeout: Duration, retry_transient: bool) -> Result<String> {
        if let Some(task_id) = self.inner.task_id.lock().unwrap().clone() {
            return Ok(task_id);
        }
        let deadline = Instant::now() + timeout;
        let no_time_left =
            || deadline.saturating_duration_since(Instant::now()) <= TASK_ID_POLL_INTERVAL;
        let timed_out = || {
            Error::Timeout(format!(
                "timed out waiting for a task for Sandbox {}",
                self.inner.sandbox_id
            ))
        };
        loop {
            let result = sb_call!(
                self,
                sandbox_get_task_id,
                sandbox_get_task_id_v2,
                pb::SandboxGetTaskIdRequest {
                    sandbox_id: self.inner.sandbox_id.clone(),
                    ..Default::default()
                }
            );
            match result {
                Err(status) => {
                    let transient = matches!(
                        status.code(),
                        Code::Unavailable | Code::DeadlineExceeded | Code::Internal
                    );
                    if !transient || !retry_transient {
                        return Err(status.into());
                    }
                    if no_time_left() {
                        return Err(if status.code() == Code::Internal {
                            status.into()
                        } else {
                            timed_out()
                        });
                    }
                }
                Ok(response) => {
                    if let Some(task_id) = response.task_id.filter(|id| !id.is_empty()) {
                        *self.inner.task_id.lock().unwrap() = Some(task_id.clone());
                        return Ok(task_id);
                    }
                    if let Some(result) = response.task_result {
                        return Err(Error::Conflict(if result.exception.is_empty() {
                            format!("Sandbox {} has already finished", self.inner.sandbox_id)
                        } else {
                            result.exception
                        }));
                    }
                    if no_time_left() {
                        return Err(timed_out());
                    }
                }
            }
            tokio::time::sleep(TASK_ID_POLL_INTERVAL).await;
        }
    }
}

/// V1 Sandbox IDs are `sb-` plus 22 base62 characters. Anything else is
/// treated as V2, so newer ID formats route to the newer backend.
pub(crate) fn is_v1_sandbox_id(sandbox_id: &str) -> bool {
    sandbox_id.strip_prefix("sb-").is_some_and(|suffix| {
        suffix.len() == 22 && suffix.chars().all(|c| c.is_ascii_alphanumeric())
    })
}

/// Maps a result to an exit code the way `subprocess` would.
pub(crate) fn return_code(result: Option<&GenericResult>) -> Option<i32> {
    let result = result?;
    match result.status() {
        GenericStatus::Unspecified => None,
        GenericStatus::Timeout => Some(124),
        GenericStatus::Terminated => Some(137),
        _ => Some(result.exitcode),
    }
}

fn tunnel_map(tunnels: Vec<pb::TunnelData>) -> HashMap<u16, Tunnel> {
    tunnels
        .into_iter()
        .map(|t| (t.container_port as u16, Tunnel::from(t)))
        .collect()
}

fn definition_port_count(definition: &pb::Sandbox) -> usize {
    match &definition.open_ports_oneof {
        Some(pb::sandbox::OpenPortsOneof::OpenPorts(ports)) => ports.ports.len(),
        None => 0,
    }
}

fn default_pty_info() -> PtyInfo {
    PtyInfo {
        enabled: true,
        winsz_rows: 24,
        winsz_cols: 80,
        env_term: "xterm-256color".into(),
        env_colorterm: "truecolor".into(),
        pty_type: PtyType::Shell as i32,
        no_terminate_on_idle_stdin: true,
        ..Default::default()
    }
}

fn validate_workdir(workdir: Option<&str>) -> Result<()> {
    match workdir {
        Some(dir) if !dir.starts_with('/') => Err(Error::Invalid(format!(
            "workdir must be an absolute path, got {dir:?}"
        ))),
        _ => Ok(()),
    }
}

fn whole_seconds(duration: Duration, what: &str) -> Result<u32> {
    if duration.subsec_nanos() != 0 {
        return Err(Error::Invalid(format!(
            "{what} must be a whole number of seconds, got {duration:?}"
        )));
    }
    u32::try_from(duration.as_secs()).map_err(|_| Error::Invalid(format!("{what} is too large")))
}

/// The Sandbox definition shared by the V1 and V2 create paths, with the Go
/// SDK's validation.
pub(crate) fn build_definition(
    params: &SandboxCreateParams,
    image_id: String,
    secret_ids: Vec<String>,
) -> Result<(pb::Sandbox, Vec<pb::SandboxTag>)> {
    validate_workdir(params.workdir.as_deref())?;
    if let Some(name) = &params.name {
        validate_name(name)?;
    }

    if params.block_network {
        if params.outbound_cidr_allowlist.is_some() || params.outbound_domain_allowlist.is_some() {
            return Err(Error::Invalid(
                "outbound allowlists cannot be used with block_network".into(),
            ));
        }
        if params.i6pn {
            return Err(Error::Invalid(
                "block_network disables all networking, including i6pn; use an empty outbound_cidr_allowlist to keep i6pn".into(),
            ));
        }
        if params.inbound_cidr_allowlist.is_some() {
            return Err(Error::Invalid(
                "inbound_cidr_allowlist cannot be used with block_network".into(),
            ));
        }
    }
    let network_access = if params.block_network {
        pb::NetworkAccess {
            network_access_type: NetworkAccessType::Blocked as i32,
            ..Default::default()
        }
    } else if params.outbound_cidr_allowlist.is_some() || params.outbound_domain_allowlist.is_some()
    {
        pb::NetworkAccess {
            network_access_type: NetworkAccessType::Allowlist as i32,
            allowed_cidrs: params.outbound_cidr_allowlist.clone().unwrap_or_default(),
            allowed_domains: params.outbound_domain_allowlist.clone().unwrap_or_default(),
        }
    } else {
        pb::NetworkAccess {
            network_access_type: NetworkAccessType::Open as i32,
            ..Default::default()
        }
    };

    let timeout_secs = match params.timeout {
        Some(timeout) => whole_seconds(timeout, "timeout")?,
        None => 0,
    };
    // Zero isn't a meaningful lifetime, so it means the default, as in the Go SDK.
    let timeout_secs = if timeout_secs == 0 {
        DEFAULT_TIMEOUT.as_secs() as u32
    } else {
        timeout_secs
    };
    let idle_timeout_secs = params
        .idle_timeout
        .filter(|t| !t.is_zero())
        .map(|t| whole_seconds(t, "idle_timeout"))
        .transpose()?;

    let mut resources = pb::Resources::default();
    match (params.cpu, params.cpu_limit) {
        (None, Some(_)) => return Err(Error::Invalid("cpu_limit requires cpu".into())),
        (Some(cpu), _) if cpu.is_nan() || cpu <= 0.0 => {
            return Err(Error::Invalid(format!("cpu must be positive, got {cpu}")));
        }
        (Some(cpu), limit) => {
            resources.milli_cpu = (cpu * 1000.0) as u32;
            if let Some(limit) = limit {
                if limit < cpu {
                    return Err(Error::Invalid(format!(
                        "cpu ({cpu}) cannot be higher than cpu_limit ({limit})"
                    )));
                }
                resources.milli_cpu_max = (limit * 1000.0) as u32;
            }
        }
        (None, None) => {}
    }
    match (params.memory_mib, params.memory_limit_mib) {
        (None, Some(_)) => {
            return Err(Error::Invalid(
                "memory_limit_mib requires memory_mib".into(),
            ));
        }
        (Some(0), _) => return Err(Error::Invalid("memory_mib must be positive".into())),
        (Some(memory), limit) => {
            resources.memory_mb = memory;
            if let Some(limit) = limit {
                if limit < memory {
                    return Err(Error::Invalid(format!(
                        "memory_mib ({memory}) cannot be higher than memory_limit_mib ({limit})"
                    )));
                }
                resources.memory_mb_max = limit;
            }
        }
        (None, None) => {}
    }
    resources.gpu_config = Some(match &params.gpu {
        Some(gpu) => parse_gpu_config(gpu)?,
        None => pb::GpuConfig::default(),
    });

    let mut ports = Vec::new();
    ports.extend(params.encrypted_ports.iter().map(|&port| pb::PortSpec {
        port: port.into(),
        unencrypted: false,
        tunnel_type: None,
    }));
    ports.extend(params.h2_ports.iter().map(|&port| pb::PortSpec {
        port: port.into(),
        unencrypted: false,
        tunnel_type: Some(pb::TunnelType::H2 as i32),
    }));
    ports.extend(params.unencrypted_ports.iter().map(|&port| pb::PortSpec {
        port: port.into(),
        unencrypted: true,
        tunnel_type: None,
    }));

    let runtime = params.runtime.map(|runtime| match runtime {
        SandboxRuntime::Gvisor => "gvisor".to_string(),
        SandboxRuntime::Vm => "vm".to_string(),
    });

    let tags = params
        .tags
        .iter()
        .map(|(name, value)| pb::SandboxTag {
            tag_name: name.clone(),
            tag_value: value.clone(),
        })
        .collect();

    let definition = pb::Sandbox {
        entrypoint_args: params.command.clone(),
        image_id,
        secret_ids,
        timeout_secs,
        idle_timeout_secs,
        workdir: params.workdir.clone(),
        network_access: Some(network_access),
        resources: Some(resources),
        pty_info: params.pty.then(default_pty_info),
        open_ports_oneof: Some(pb::sandbox::OpenPortsOneof::OpenPorts(pb::PortSpecs {
            ports,
        })),
        cloud_provider_str: params.cloud.clone().unwrap_or_default(),
        scheduler_placement: (!params.regions.is_empty()).then(|| pb::SchedulerPlacement {
            regions: params.regions.clone(),
            ..Default::default()
        }),
        verbose: params.verbose,
        readiness_probe: params
            .readiness_probe
            .as_ref()
            .map(Probe::to_proto)
            .transpose()?,
        // The Go SDK always sends the name, empty when unset.
        name: Some(params.name.clone().unwrap_or_default()),
        experimental_options_v2: params.experimental_options.clone(),
        custom_domain: params.custom_domain.clone().unwrap_or_default(),
        include_oidc_identity_token: params.include_oidc_identity_token,
        inbound_cidr_allowlist: params.inbound_cidr_allowlist.clone().unwrap_or_default(),
        i6pn_enabled: params.i6pn,
        enable_snapshot: params.enable_snapshot,
        runtime,
        ..Default::default()
    };
    Ok((definition, tags))
}

fn validate_name(name: &str) -> Result<()> {
    let looks_like_app_id = name
        .strip_prefix("ap-")
        .is_some_and(|rest| rest.len() == 22 && rest.chars().all(|c| c.is_ascii_alphanumeric()));
    let valid = !name.is_empty()
        && name.len() <= 64
        && !looks_like_app_id
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if valid {
        Ok(())
    } else {
        Err(Error::Invalid(format!(
            "invalid Sandbox name {name:?}: use up to 64 letters, digits, '-', '_' or '.', not shaped like an App ID"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_v1_ids() {
        assert!(is_v1_sandbox_id("sb-AbCdEfGhIjKlMnOpQrStUv"));
        assert!(!is_v1_sandbox_id("sb-short"));
        assert!(!is_v1_sandbox_id("sbx-AbCdEfGhIjKlMnOpQrStUv"));
        assert!(!is_v1_sandbox_id("sb2-0123456789abcdef0123456789abcdef"));
    }

    #[test]
    fn maps_results_to_exit_codes() {
        let result = |status: GenericStatus, exitcode| GenericResult {
            status: status as i32,
            exitcode,
            ..Default::default()
        };
        assert_eq!(return_code(None), None);
        assert_eq!(
            return_code(Some(&result(GenericStatus::Unspecified, 3))),
            None
        );
        assert_eq!(
            return_code(Some(&result(GenericStatus::Success, 0))),
            Some(0)
        );
        assert_eq!(
            return_code(Some(&result(GenericStatus::Failure, 3))),
            Some(3)
        );
        assert_eq!(
            return_code(Some(&result(GenericStatus::Timeout, 0))),
            Some(124)
        );
        assert_eq!(
            return_code(Some(&result(GenericStatus::Terminated, 0))),
            Some(137)
        );
    }

    #[test]
    fn definition_defaults_and_resources() {
        let params = SandboxCreateParams {
            cpu: Some(0.5),
            cpu_limit: Some(2.0),
            memory_mib: Some(512),
            encrypted_ports: vec![8080],
            h2_ports: vec![9000],
            ..Default::default()
        };
        let (definition, _) = build_definition(&params, "im-1".into(), vec![]).unwrap();
        assert_eq!(definition.timeout_secs, 300);
        let resources = definition.resources.as_ref().unwrap();
        assert_eq!((resources.milli_cpu, resources.milli_cpu_max), (500, 2000));
        assert_eq!(resources.memory_mb, 512);
        assert_eq!(definition_port_count(&definition), 2);
        assert_eq!(
            definition
                .network_access
                .as_ref()
                .unwrap()
                .network_access_type,
            NetworkAccessType::Open as i32
        );
    }

    #[test]
    fn definition_rejects_bad_combinations() {
        let bad = [
            SandboxCreateParams {
                cpu_limit: Some(1.0),
                ..Default::default()
            },
            SandboxCreateParams {
                cpu: Some(2.0),
                cpu_limit: Some(1.0),
                ..Default::default()
            },
            SandboxCreateParams {
                memory_limit_mib: Some(1024),
                ..Default::default()
            },
            SandboxCreateParams {
                timeout: Some(Duration::from_millis(1500)),
                ..Default::default()
            },
            SandboxCreateParams {
                workdir: Some("relative".into()),
                ..Default::default()
            },
            SandboxCreateParams {
                block_network: true,
                i6pn: true,
                ..Default::default()
            },
            SandboxCreateParams {
                block_network: true,
                outbound_cidr_allowlist: Some(vec![]),
                ..Default::default()
            },
        ];
        for params in bad {
            assert!(
                build_definition(&params, "im-1".into(), vec![]).is_err(),
                "{params:?}"
            );
        }
    }

    #[test]
    fn allowlist_mode() {
        let params = SandboxCreateParams {
            outbound_domain_allowlist: Some(vec!["*.example.com".into()]),
            ..Default::default()
        };
        let access = build_definition(&params, "im-1".into(), vec![])
            .unwrap()
            .0
            .network_access
            .unwrap();
        assert_eq!(
            access.network_access_type,
            NetworkAccessType::Allowlist as i32
        );
        assert_eq!(access.allowed_domains, vec!["*.example.com".to_string()]);
    }
}
