//! Layers Dockerfile commands onto a registry image, shows how Modal treats an
//! image's ENTRYPOINT, reads a Sandbox's own stdout, and looks around inside a
//! running Sandbox (user, kernel, Modal's env vars, writable paths).
//!
//!     cargo run --example images
//!
//! Runs three small Sandboxes for under a minute in the App `modal-rs-examples`.

use std::time::{Duration, Instant};

use anyhow::{Result, ensure};
use modal::{AppLookupParams, Client, ExecParams, Image, Sandbox, SandboxCreateParams};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let client = Client::from_env()?;
    let app = client
        .app_from_name(
            "modal-rs-examples",
            AppLookupParams {
                create_if_missing: true,
                ..Default::default()
            },
        )
        .await?;

    // An ENTRYPOINT that wraps whatever runs, as many published images have.
    // Each `dockerfile_commands` call adds a layer; Modal builds it once and
    // caches it.
    let base = Image::from_registry("alpine:3.20");
    let wrapped = base.dockerfile_commands([r#"ENTRYPOINT ["echo", "entrypoint got:"]"#]);
    let started = Instant::now();
    println!(
        "image {} ({:?})",
        wrapped.build(&client, &app).await?,
        started.elapsed()
    );

    // Modal keeps the ENTRYPOINT and passes the Sandbox command to it as
    // arguments, so this runs `echo entrypoint got: uname -s`. Docker's
    // `--entrypoint` and Kubernetes' `command` would replace it instead.
    let stdout = run_to_exit(&client, &app, &wrapped, &["uname", "-s"]).await?;
    println!("[with ENTRYPOINT] stdout {stdout:?}");
    ensure!(stdout == "entrypoint got: uname -s\n");

    // An empty ENTRYPOINT layer clears it, so the command runs as given.
    let cleared = wrapped.dockerfile_commands(["ENTRYPOINT []"]);
    let stdout = run_to_exit(&client, &app, &cleared, &["uname", "-s"]).await?;
    println!("[ENTRYPOINT []] stdout {stdout:?}");
    ensure!(stdout == "Linux\n");

    // Without a command the Sandbox idles until terminated, which suits exec.
    let idle = client
        .create_sandbox(
            &app,
            &base,
            SandboxCreateParams {
                cpu: Some(0.25),
                memory_mib: Some(256),
                timeout: Some(Duration::from_secs(120)),
                ..Default::default()
            },
        )
        .await?;
    let result = look_around(&idle).await;
    idle.terminate().await?;
    result
}

/// Runs `command` as a Sandbox's main process and returns its stdout.
async fn run_to_exit(
    client: &Client,
    app: &modal::App,
    image: &Image,
    command: &[&str],
) -> Result<String> {
    let sandbox = client
        .create_sandbox(
            app,
            image,
            SandboxCreateParams {
                command: command.iter().map(|arg| arg.to_string()).collect(),
                cpu: Some(0.25),
                memory_mib: Some(256),
                timeout: Some(Duration::from_secs(60)),
                ..Default::default()
            },
        )
        .await?;
    // Open the stream right away: Modal keeps only recent entrypoint output.
    let mut stdout = sandbox.stdout().await?;
    let text =
        tokio::time::timeout(Duration::from_secs(40), stdout.read_to_string()).await??;
    let code = tokio::time::timeout(Duration::from_secs(40), sandbox.wait()).await??;
    ensure!(code == 0, "{command:?} exited {code}");
    Ok(text)
}

async fn look_around(sandbox: &Sandbox) -> Result<()> {
    let checks = [
        ("user", "id"),
        ("kernel", "uname -r"),
        (
            "modal env",
            "env | grep -E '^MODAL_' | cut -d= -f1 | sort | tr '\\n' ' '; echo",
        ),
        (
            "writable",
            "for d in /tmp /; do (touch $d/.w 2>/dev/null && echo \"$d writable\") || echo \"$d read-only\"; done",
        ),
    ];
    for (name, script) in checks {
        let output = sandbox
            .exec(["sh", "-c", script], ExecParams::default())
            .await?
            .output()
            .await?;
        print!(
            "[{name}] exit {}\n{}{}",
            output.exit_code,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}
