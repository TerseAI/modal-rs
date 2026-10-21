//! Handles for running processes: output streams, stdin, and exit status.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tonic::{Code, Status, Streaming};

use crate::error::{Error, Result};
use crate::proto::task_command_router::{
    self as tcr, SandboxStdioFileDescriptor, TaskExecStdioFileDescriptor,
    task_exec_wait_response::ExitStatus,
};
use crate::retry::is_retryable;
use crate::router::CommandRouter;

const STDIO_RETRY_INITIAL_DELAY: Duration = Duration::from_millis(10);
const STDIO_RETRY_FACTOR: u32 = 2;
const STDIO_MAX_RETRIES: u32 = 10;

/// Which stream of a process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StdioStream {
    Stdout,
    Stderr,
}

/// What to do with an exec's stdout or stderr.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StdioBehavior {
    /// Make the output readable from the [`ContainerProcess`].
    #[default]
    Pipe,
    /// Discard it.
    Ignore,
}

/// A process's stdout or stderr. Nothing is fetched until it is read. If the
/// connection drops, reading resumes from the last byte received.
pub struct OutputStream {
    state: Option<StreamState>,
}

enum Source {
    Exec {
        exec_id: String,
        fd: TaskExecStdioFileDescriptor,
    },
    Sandbox {
        fd: SandboxStdioFileDescriptor,
    },
}

enum Live {
    Exec(Streaming<tcr::TaskExecStdioReadResponse>),
    Sandbox(Streaming<tcr::SandboxStdioReadV2Response>),
}

struct StreamState {
    router: Arc<CommandRouter>,
    source: Source,
    live: Option<Live>,
    offset: u64,
    /// The exec's deadline; reading past it is an [`Error::ExecTimeout`].
    deadline: Option<Instant>,
    done: bool,
    delay: Duration,
    retries_left: u32,
    did_auth_retry: bool,
}

impl OutputStream {
    pub(crate) fn empty() -> Self {
        Self { state: None }
    }

    pub(crate) fn exec(
        router: Arc<CommandRouter>,
        exec_id: &str,
        stream: StdioStream,
        deadline: Option<Instant>,
    ) -> Self {
        let fd = match stream {
            StdioStream::Stdout => TaskExecStdioFileDescriptor::Stdout,
            StdioStream::Stderr => TaskExecStdioFileDescriptor::Stderr,
        };
        Self::new(
            router,
            Source::Exec {
                exec_id: exec_id.to_string(),
                fd,
            },
            deadline,
        )
    }

    pub(crate) fn sandbox(router: Arc<CommandRouter>, stream: StdioStream) -> Self {
        let fd = match stream {
            StdioStream::Stdout => SandboxStdioFileDescriptor::Stdout,
            StdioStream::Stderr => SandboxStdioFileDescriptor::Stderr,
        };
        Self::new(router, Source::Sandbox { fd }, None)
    }

    fn new(router: Arc<CommandRouter>, source: Source, deadline: Option<Instant>) -> Self {
        Self {
            state: Some(StreamState {
                router,
                source,
                live: None,
                offset: 0,
                deadline,
                done: false,
                delay: STDIO_RETRY_INITIAL_DELAY,
                retries_left: STDIO_MAX_RETRIES,
                did_auth_retry: false,
            }),
        }
    }

    /// The next chunk of output, or `None` once the stream has ended.
    pub async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        match &mut self.state {
            None => Ok(None),
            Some(state) => state.next_chunk().await,
        }
    }

    /// Reads until the stream ends.
    pub async fn read_to_end(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(chunk) = self.next_chunk().await? {
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    /// Reads until the stream ends, replacing invalid UTF-8.
    pub async fn read_to_string(&mut self) -> Result<String> {
        Ok(String::from_utf8_lossy(&self.read_to_end().await?).into_owned())
    }
}

impl StreamState {
    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        if self.done {
            return Ok(None);
        }
        loop {
            if self.deadline.is_some_and(|d| Instant::now() >= d) {
                return Err(self.timeout_error());
            }

            let mut opened = false;
            if self.live.is_none() {
                let Some(opened_stream) = within(self.deadline, self.open()).await else {
                    return Err(self.timeout_error());
                };
                match opened_stream {
                    Ok(live) => {
                        self.live = Some(live);
                        opened = true;
                    }
                    Err(status) => {
                        self.recover(status).await?;
                        continue;
                    }
                }
            }

            let Some(received) = within(self.deadline, self.recv()).await else {
                return Err(self.timeout_error());
            };
            match received {
                Ok(None) => {
                    self.done = true;
                    self.live = None;
                    return Ok(None);
                }
                Err(status) => {
                    self.live = None;
                    self.recover(status).await?;
                }
                Ok(Some((data, starting_offset))) => {
                    match starting_offset {
                        // Sandbox stdio: the router keeps only recent output,
                        // so a (re)opened stream may start past where we were.
                        Some(start) => {
                            if data.is_empty() {
                                return Err(Error::Remote(format!(
                                    "received an empty message streaming stdio from Sandbox {}",
                                    self.router.sandbox_id
                                )));
                            }
                            if opened {
                                if start > self.offset {
                                    tracing::warn!(
                                        sandbox_id = %self.router.sandbox_id,
                                        dropped_bytes = start - self.offset,
                                        "Sandbox stdio dropped bytes; only the most recent output is retained"
                                    );
                                }
                                self.offset = start;
                            }
                        }
                        None if data.is_empty() => continue,
                        None => {}
                    }
                    self.delay = STDIO_RETRY_INITIAL_DELAY;
                    self.retries_left = STDIO_MAX_RETRIES;
                    self.did_auth_retry = false;
                    self.offset += data.len() as u64;
                    return Ok(Some(data));
                }
            }
        }
    }

    async fn open(&self) -> Result<Live, Status> {
        let mut stub = self.router.stub();
        match &self.source {
            Source::Exec { exec_id, fd } => {
                let request = self.router.request(
                    tcr::TaskExecStdioReadRequest {
                        task_id: self.router.task_id.clone(),
                        exec_id: exec_id.clone(),
                        offset: self.offset,
                        file_descriptor: *fd as i32,
                    },
                    0,
                );
                Ok(Live::Exec(
                    stub.task_exec_stdio_read(request).await?.into_inner(),
                ))
            }
            Source::Sandbox { fd } => {
                let request = self.router.request(
                    tcr::SandboxStdioReadV2Request {
                        task_id: self.router.task_id.clone(),
                        offset: self.offset,
                        file_descriptor: *fd as i32,
                    },
                    0,
                );
                Ok(Live::Sandbox(
                    stub.sandbox_stdio_read_v2(request).await?.into_inner(),
                ))
            }
        }
    }

    /// The next message's data, and for Sandbox stdio its starting offset.
    async fn recv(&mut self) -> Result<Option<(Vec<u8>, Option<u64>)>, Status> {
        match self.live.as_mut().expect("stream is open") {
            Live::Exec(stream) => Ok(stream.message().await?.map(|m| (m.data, None))),
            Live::Sandbox(stream) => Ok(stream
                .message()
                .await?
                .map(|m| (m.data, Some(m.starting_offset)))),
        }
    }

    /// Decides whether a failed open or read is worth another try, waiting out
    /// the backoff if so.
    async fn recover(&mut self, status: Status) -> Result<()> {
        if status.code() == Code::Unauthenticated && !self.did_auth_retry {
            self.router.refresh_jwt().await?;
            self.did_auth_retry = true;
            return Ok(());
        }
        if !is_retryable(status.code()) || self.retries_left == 0 {
            return Err(status.into());
        }
        if let Some(deadline) = self.deadline
            && deadline.saturating_duration_since(Instant::now()) <= self.delay
        {
            return Err(self.timeout_error());
        }
        tracing::debug!(code = ?status.code(), delay = ?self.delay, "retrying stdio read");
        tokio::time::sleep(self.delay).await;
        self.delay *= STDIO_RETRY_FACTOR;
        self.retries_left -= 1;
        Ok(())
    }

    fn timeout_error(&self) -> Error {
        match &self.source {
            Source::Exec { exec_id, .. } => Error::ExecTimeout(format!(
                "deadline exceeded while streaming stdio for exec {exec_id}"
            )),
            Source::Sandbox { .. } => {
                Error::Timeout("deadline exceeded while streaming Sandbox stdio".into())
            }
        }
    }
}

/// Runs `fut` until `deadline`; `None` if the deadline came first.
async fn within<T>(deadline: Option<Instant>, fut: impl Future<Output = T>) -> Option<T> {
    match deadline {
        None => Some(fut.await),
        Some(deadline) => tokio::time::timeout_at(deadline.into(), fut).await.ok(),
    }
}

/// A process's stdin. Writes are ordered by byte offset, so a retried write is
/// never applied twice.
pub struct Stdin {
    router: Arc<CommandRouter>,
    /// `None` for a Sandbox's entrypoint, else the exec.
    exec_id: Option<String>,
    offset: u64,
}

impl Stdin {
    pub(crate) fn exec(router: Arc<CommandRouter>, exec_id: &str) -> Self {
        Self {
            router,
            exec_id: Some(exec_id.to_string()),
            offset: 0,
        }
    }

    pub(crate) fn sandbox(router: Arc<CommandRouter>) -> Self {
        Self {
            router,
            exec_id: None,
            offset: 0,
        }
    }

    pub async fn write(&mut self, data: impl Into<Vec<u8>>) -> Result<()> {
        let data = data.into();
        let len = data.len() as u64;
        self.send(data, false).await?;
        self.offset += len;
        Ok(())
    }

    /// Sends EOF.
    pub async fn close(&mut self) -> Result<()> {
        self.send(Vec::new(), true).await
    }

    async fn send(&self, data: Vec<u8>, eof: bool) -> Result<()> {
        match &self.exec_id {
            Some(exec_id) => {
                self.router
                    .exec_stdin_write(exec_id, self.offset, data, eof)
                    .await
            }
            None => {
                self.router
                    .sandbox_stdin_write(self.offset, data, eof)
                    .await
            }
        }
    }
}

/// A command started with [`Sandbox::exec`](crate::Sandbox::exec).
///
/// `stdout` and `stderr` are separate fields so both can be read at once:
/// `tokio::try_join!(p.stdout.read_to_end(), p.stderr.read_to_end())`.
pub struct ContainerProcess {
    pub stdin: Stdin,
    pub stdout: OutputStream,
    pub stderr: OutputStream,
    router: Arc<CommandRouter>,
    exec_id: String,
    deadline: Option<Instant>,
}

impl std::fmt::Debug for ContainerProcess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContainerProcess")
            .field("exec_id", &self.exec_id)
            .field("task_id", &self.router.task_id)
            .finish_non_exhaustive()
    }
}

/// Everything a finished process produced.
#[derive(Clone, Debug)]
pub struct ProcessOutput {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl ContainerProcess {
    pub(crate) fn new(
        router: Arc<CommandRouter>,
        exec_id: String,
        stdout: StdioBehavior,
        stderr: StdioBehavior,
        deadline: Option<Instant>,
    ) -> Self {
        let stream = |behavior, which| match behavior {
            StdioBehavior::Pipe => OutputStream::exec(router.clone(), &exec_id, which, deadline),
            StdioBehavior::Ignore => OutputStream::empty(),
        };
        Self {
            stdin: Stdin::exec(router.clone(), &exec_id),
            stdout: stream(stdout, StdioStream::Stdout),
            stderr: stream(stderr, StdioStream::Stderr),
            router: router.clone(),
            exec_id,
            deadline,
        }
    }

    pub fn exec_id(&self) -> &str {
        &self.exec_id
    }

    /// Waits for the process to exit. A process killed by a signal reports
    /// `128 + signal`, like a shell.
    pub async fn wait(&self) -> Result<i32> {
        let response = self.router.exec_wait(&self.exec_id, self.deadline).await?;
        match response.exit_status {
            Some(ExitStatus::Code(code)) => Ok(code),
            Some(ExitStatus::Signal(signal)) => Ok(128 + signal),
            None => Err(Error::Remote(format!(
                "exec {} returned no exit status",
                self.exec_id
            ))),
        }
    }

    /// Reads stdout and stderr to the end, then waits for the exit code.
    pub async fn output(mut self) -> Result<ProcessOutput> {
        let (stdout, stderr) =
            tokio::try_join!(self.stdout.read_to_end(), self.stderr.read_to_end())?;
        let exit_code = self.wait().await?;
        Ok(ProcessOutput {
            exit_code,
            stdout,
            stderr,
        })
    }
}
