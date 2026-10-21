use tonic::{Code, Status};

/// Errors returned by the Modal client.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The arguments were rejected before anything was sent.
    #[error("invalid argument: {0}")]
    Invalid(String),
    /// Credentials or other configuration are missing or malformed.
    #[error("configuration error: {0}")]
    Config(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("already exists: {0}")]
    AlreadyExists(String),
    /// The Sandbox finished before the operation could run (e.g. before a task was scheduled).
    #[error("conflict: {0}")]
    Conflict(String),
    /// Modal could not find capacity for the Sandbox in time.
    #[error("resource exhausted: {0}")]
    ResourceExhausted(String),
    #[error("timed out: {0}")]
    Timeout(String),
    /// An exec ran past the timeout it was started with.
    #[error("exec timed out: {0}")]
    ExecTimeout(String),
    /// Modal reported a failure, such as a failed image build.
    #[error("remote error: {0}")]
    Remote(String),
    #[error("transport error: {0}")]
    Transport(#[from] tonic::transport::Error),
    #[error("grpc error ({:?}): {}", .0.code(), .0.message())]
    Grpc(#[from] Status),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    /// The gRPC status code, when the error came from a call.
    pub fn grpc_code(&self) -> Option<Code> {
        match self {
            Error::Grpc(status) => Some(status.code()),
            _ => None,
        }
    }

    /// Maps NotFound and AlreadyExists statuses to their dedicated variants.
    /// `what` describes a missing object; when it's empty the server's message is used.
    pub(crate) fn from_status_with(status: Status, what: impl FnOnce() -> String) -> Self {
        match status.code() {
            Code::NotFound => {
                let what = what();
                Error::NotFound(if what.is_empty() {
                    status.message().to_string()
                } else {
                    what
                })
            }
            Code::AlreadyExists => Error::AlreadyExists(status.message().to_string()),
            _ => Error::Grpc(status),
        }
    }
}
