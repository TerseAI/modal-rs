# modal-rs

Unofficial Rust client for [Modal](https://modal.com) Sandboxes: a port of the sandbox part of Modal's Go SDK, using protos vendored from [modal-labs/modal-client](https://github.com/modal-labs/modal-client). Not affiliated with Modal Labs.

## Install

```toml
[dependencies]
modal-rs = { git = "https://github.com/TerseAI/modal-rs" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Requires Rust 1.91+. Credentials come from `~/.modal.toml` (`modal token new`) or `MODAL_TOKEN_ID` / `MODAL_TOKEN_SECRET`.

## Usage

```rust
use modal::{AppLookupParams, Client, ExecParams, Image, SandboxCreateParams};

#[tokio::main]
async fn main() -> modal::Result<()> {
    let client = Client::from_env()?;
    let app = client
        .app_from_name("my-app", AppLookupParams { create_if_missing: true, ..Default::default() })
        .await?;
    let image = Image::from_registry("python:3.12-slim").dockerfile_commands(["RUN pip install httpx"]);

    let sandbox = client
        .create_sandbox(&app, &image, SandboxCreateParams { cpu: Some(1.0), ..Default::default() })
        .await?;
    let output = sandbox.exec(["python", "-V"], ExecParams::default()).await?.output().await?;
    println!("{}", String::from_utf8_lossy(&output.stdout));
    sandbox.terminate().await?;
    Ok(())
}
```

## Features

- **Config**: `~/.modal.toml` profiles and `MODAL_*` env vars, token auth only
- **Apps**: lookup and create-if-missing
- **Images**: public and private registries, ECR, GCP, by ID, Dockerfile layers
- **Secrets**: by name, by ID, or inline
- **Sandboxes**: create (V1 and V2), attach by ID or name, list by tags, `wait`, `poll`, `terminate`, tunnels, connect tokens, readiness probes
- **Exec**: streamed stdout/stderr that resume after a dropped connection, stdin, exit codes, timeouts

Retries, auth token refresh and idempotency keys follow the Go SDK.

**Not ported:** volumes, cloud bucket mounts, proxies, memory/full-filesystem snapshots, the filesystem API, sidecars, tag updates, V1 entrypoint stdio. For anything missing, use the generated `modal::proto` types.

## Good to know

- `Sandbox::snapshot_directory(path, ttl)` creates an image from a directory; `mount_image(path, image)` mounts it in a running Sandbox. A `None` TTL retains the snapshot indefinitely. Clone and retain the Sandbox handle to reuse its authenticated command connection.

- Modal keeps the image's `ENTRYPOINT` and passes `command` to it as arguments. Add `.dockerfile_commands(["ENTRYPOINT []"])` to run the command as given.
- Tunnel URLs are public. Authenticate what you serve or set `inbound_cidr_allowlist`.
- Sandboxes run as root under gVisor, and `timeout` defaults to 5 minutes.
- `wait` returns 137 after `terminate` and 124 after a timeout.
- Read `sandbox.stdout()` soon after create, because Modal keeps only recent entrypoint output.
- `Client` must be created inside a Tokio runtime.

## Caveats

- Modal has no client type for Rust, so this crate identifies itself as the Go SDK (`modal-go/0.11.1+modal-rs.<version>`). Check with Modal before relying on it in production.
- This uses Modal's internal API, which can change. [`proto/UPSTREAM.md`](proto/UPSTREAM.md) has the pinned commit and update steps.

## Examples

Live examples run in the Modal App `modal-rs-examples` and clean up after themselves.

```sh
cargo run --example smoke       # exec, stderr, exit codes, stdin
cargo run --example tunnels     # web servers, readiness probes, HTTPS + WebSocket, tags
cargo run --example images      # Dockerfile layers, ENTRYPOINT, a look inside a Sandbox
cargo run --example leftovers   # list (or --terminate) anything still running
cargo test                      # unit tests against an in-process fake Modal
```

## License

MIT. The protos in `proto/modal_proto/` and the Go SDK this ports are Apache-2.0 ([license](proto/modal_proto/LICENSE)).
