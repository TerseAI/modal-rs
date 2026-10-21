//! Unofficial Rust client for [Modal](https://modal.com) Sandboxes.
//!
//! A port of the sandbox subset of Modal's Go SDK (`modal-labs/modal-client`,
//! `go/`), talking to the same gRPC API through protos vendored from that repo.
//!
//! ```no_run
//! use modal::{AppLookupParams, Client, ExecParams, Image, SandboxCreateParams};
//!
//! # async fn run() -> modal::Result<()> {
//! let client = Client::from_env()?;
//! let app = client
//!     .app_from_name("my-app", AppLookupParams { create_if_missing: true, ..Default::default() })
//!     .await?;
//! let image = Image::from_registry("python:3.12-slim");
//! let sandbox = client.create_sandbox(&app, &image, SandboxCreateParams::default()).await?;
//!
//! let output = sandbox
//!     .exec(["python", "-c", "print(6 * 7)"], ExecParams::default())
//!     .await?
//!     .output()
//!     .await?;
//! assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "42");
//!
//! sandbox.terminate().await?;
//! # Ok(())
//! # }
//! ```

mod app;
mod auth;
mod client;
mod config;
mod error;
mod image;
mod process;
mod retry;
mod router;
mod sandbox;
mod secret;

#[cfg(test)]
mod tests;

/// Generated protobuf types for Modal's API, for calls this crate doesn't wrap.
#[allow(clippy::all, rustdoc::all)]
pub mod proto {
    pub mod client {
        tonic::include_proto!("modal.client");
    }
    pub mod task_command_router {
        tonic::include_proto!("modal.task_command_router");
    }
}

pub use app::{App, AppLookupParams};
pub use client::Client;
pub use config::{Config, DEFAULT_SERVER_URL};
pub use error::{Error, Result};
pub use image::{Image, ImageLayerParams};
pub use process::{
    ContainerProcess, OutputStream, ProcessOutput, Stdin, StdioBehavior, StdioStream,
};
pub use sandbox::{
    ConnectToken, ExecParams, Probe, Sandbox, SandboxCreateParams, SandboxInfo, SandboxListParams,
    SandboxRuntime, Tunnel,
};
pub use secret::Secret;
