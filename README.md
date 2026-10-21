# modal-rs

An unofficial Rust client for [Modal](https://modal.com) Sandboxes. Modal ships
SDKs for Python, JavaScript and Go but not Rust; this crate ports the sandbox
part of the Go SDK onto the same gRPC API, using protos vendored from
[modal-labs/modal-client](https://github.com/modal-labs/modal-client) (see
[`proto/UPSTREAM.md`](proto/UPSTREAM.md) for the pinned commit).

Not affiliated with or endorsed by Modal Labs.

## Install

The crate isn't on crates.io yet; depend on it from Git. The library is named `modal`.

```toml
[dependencies]
modal-rs = { git = "https://github.com/TerseAI/modal-rs" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

It needs Rust 1.91 or newer. Credentials come from `~/.modal.toml` (written by
`modal token new`) or the `MODAL_TOKEN_ID` / `MODAL_TOKEN_SECRET` env vars.

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

The [examples](#examples) go further: stdin, tunnels, WebSockets, readiness probes, tags and image layers.

## What it covers

- **Config**: `~/.modal.toml` profiles and `MODAL_*` env vars, with the same precedence as the Go SDK. Token auth only (no OAuth).
- **Apps**: lookup and create-if-missing.
- **Images**: registry (public, private, ECR, GCP), by ID, and Dockerfile command layers. Builds are cached per `Image` value.
- **Secrets**: by name, by ID, or inline maps. Named Secrets are looked up once per `Secret` value.
- **Sandboxes**:
  - create on the V2 backend (the default for CPU) or V1 (GPU, or `sandbox_v2 = false`)
  - attach by ID or by name
  - list running Sandboxes by App and tags
  - `wait`, `poll`, `terminate`, `tunnels`, connect tokens, readiness probes
- **Exec**: streamed stdout/stderr that resume from their byte offset after a dropped connection, offset-ordered stdin, exit codes, and timeouts.
- **Entrypoint stdio** for V2 Sandboxes.

Wire behaviour follows the Go SDK:
- headers on every call
- a cached `x-modal-auth-token`, refreshed partway through its lifetime
- per-call idempotency keys with exponential backoff on transient codes
- server-requested throttle delays (`RPCRetryPolicy`)
- a direct connection to the task command router with JWT refresh on `Unauthenticated`

Not ported: volumes, cloud bucket mounts, proxies, snapshots, the filesystem API, sidecars, Sandbox tag updates, V1 entrypoint stdio, streaming stdin, and the Go SDK's release of idle worker connections. Each `Sandbox` handle keeps one HTTP/2 connection to its worker until every clone of it is dropped. Re-attach later with `client.sandbox_from_id(id)`.

Anything else can go through the generated `modal::proto` types; the control plane and router calls in `src/client.rs` and `src/router.rs` show how to add auth and retries.

## Sandbox behaviour worth knowing

Checked live with the examples:

1. **ENTRYPOINT is kept.** Modal passes the Sandbox `command` to the image's `ENTRYPOINT` as arguments, where Docker's `--entrypoint` and Kubernetes' `command` replace it. Add an `ENTRYPOINT []` layer to run the command as given: `image.dockerfile_commands(["ENTRYPOINT []"])`.
2. **Tunnels are public.** `encrypted_ports` become `https://….modal.host` URLs on the public internet. Authenticate what you serve, or limit callers with `inbound_cidr_allowlist`. Clients get HTTP/1.1 through the tunnel even when they offer HTTP/2, and WebSocket upgrades pass through.
3. **Root and gVisor.** Processes run as root and `/` is writable. Isolation is gVisor.
4. **Modal env vars.** Every Sandbox gets `MODAL_TASK_ID`, `MODAL_SANDBOX_ID`, `MODAL_REGION`, `MODAL_IMAGE_ID`, `MODAL_CLOUD_PROVIDER` and `MODAL_CONTAINER_ARGUMENTS_PATH`, plus `MODAL_IDENTITY_TOKEN` (an OIDC token) when `include_oidc_identity_token` is set. Leave that off if the Sandbox runs untrusted code.
5. **Lifetime.** `timeout` defaults to 5 minutes and Modal caps it (24h at the time of writing), so set it explicitly for long-lived Sandboxes.
6. **Lifecycle.**
   - `terminate` is idempotent. An unknown ID returns `NotFound`.
   - Terminated Sandboxes drop out of `list_sandboxes` right away.
   - `wait` reports 137 after `terminate` and 124 after a timeout.
7. **Entrypoint output is short-lived.** Open `sandbox.stdout()` soon after create, because the command router keeps only recent output.

## Caveats

- **Client identity.** Modal has no client type for Rust, so this crate sends the Go SDK's (`CLIENT_TYPE_LIBMODAL_GO`) with `x-modal-libmodal-version: modal-go/0.11.1+modal-rs.<version>`. Modal rejects App creation unless that header parses as `modal-go/<semver>`, so the crate reports the Go version it ports and adds its own version as build metadata. If you depend on this in production, check with Modal first.
- **Unofficial API.** The protocol is Modal's internal one and can change. Pin a commit of this repo, run the live examples in CI, and diff the Go SDK when you update (steps in `proto/UPSTREAM.md`).
- **Tokio.** `Client::new` / `Client::from_env` must run inside a Tokio runtime (connections open lazily).

## Examples

All of them need Modal credentials, run in the App `modal-rs-examples`, and terminate what they create.

| Example | What it shows |
| --- | --- |
| `cargo run --example smoke` | One small Sandbox: env vars, exec with exit code and stderr, stdin. |
| `cargo run --example tunnels` | Web servers in three Sandboxes: readiness probes, HTTPS and WebSocket through tunnels, listing by tag, terminating by ID. |
| `cargo run --example images` | Dockerfile layers, how `ENTRYPOINT` interacts with `command`, entrypoint stdout, and what a Sandbox looks like inside. |
| `cargo run --example leftovers [-- --terminate]` | Lists anything still running in `modal-rs-examples`, and terminates it with `--terminate`. |

Set `RUST_LOG=modal=debug` to see each RPC.

## Testing

```sh
cargo test    # unit tests + an in-process fake Modal and fake worker
```

The fake-server tests in `src/tests.rs` check, over real gRPC:
- headers, auth token caching, and auth failures that fail fast
- throttle retries, and idempotency keys reused across retries
- a two-layer image build that follows the build log stream
- secret sources, V2 create, exec stdin and output
- stdout resuming after a dropped stream, a router JWT refresh, and exec timeouts
- list pagination

## License

MIT, see [`LICENSE`](LICENSE).

The client logic in `src/` is a port of the Go SDK in
[modal-labs/modal-client](https://github.com/modal-labs/modal-client), and the
protos in `proto/modal_proto/` are copied from it unchanged. Both come from
that repo under Apache-2.0 ([`proto/modal_proto/LICENSE`](proto/modal_proto/LICENSE)).
