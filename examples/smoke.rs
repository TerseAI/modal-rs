//! Live smoke test against Modal: creates a small Sandbox, runs a command in
//! it, and terminates it. Uses credentials from `~/.modal.toml` or
//! `MODAL_TOKEN_ID` / `MODAL_TOKEN_SECRET`.
//!
//!     RUST_LOG=modal=debug cargo run --example smoke
//!
//! Costs a few seconds of a 0.25-core Sandbox in the App `modal-rs-examples`.

use std::time::{Duration, Instant};

use modal::{AppLookupParams, Client, ExecParams, Image, SandboxCreateParams};

#[tokio::main]
async fn main() -> modal::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let client = Client::from_env()?;
    let started = Instant::now();

    let app = client
        .app_from_name(
            "modal-rs-examples",
            AppLookupParams {
                create_if_missing: true,
                ..Default::default()
            },
        )
        .await?;
    println!("app {} ({:?})", app.app_id, started.elapsed());

    let image = Image::from_registry("alpine:3.20");
    let sandbox = client
        .create_sandbox(
            &app,
            &image,
            SandboxCreateParams {
                cpu: Some(0.25),
                memory_mib: Some(256),
                timeout: Some(Duration::from_secs(120)),
                env: [("GREETING".to_string(), "hello from modal-rs".to_string())].into(),
                ..Default::default()
            },
        )
        .await?;
    println!(
        "sandbox {} (v2: {}) ({:?})",
        sandbox.id(),
        sandbox.is_v2(),
        started.elapsed()
    );

    let result = run(&sandbox).await;
    // Always clean up, even if a step failed.
    sandbox.terminate().await?;
    let exit_code = sandbox.wait().await?;
    println!(
        "terminated, exit code {exit_code} ({:?})",
        started.elapsed()
    );
    result
}

async fn run(sandbox: &modal::Sandbox) -> modal::Result<()> {
    let output = sandbox
        .exec(
            ["sh", "-c", "echo \"$GREETING\"; echo oops >&2; exit 7"],
            ExecParams::default(),
        )
        .await?
        .output()
        .await?;
    println!(
        "exec: exit {} stdout {:?} stderr {:?}",
        output.exit_code,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.exit_code, 7);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "hello from modal-rs\n"
    );
    assert_eq!(String::from_utf8_lossy(&output.stderr), "oops\n");

    let mut cat = sandbox.exec(["cat"], ExecParams::default()).await?;
    cat.stdin.write("piped through stdin\n").await?;
    cat.stdin.close().await?;
    let echoed = cat.stdout.read_to_string().await?;
    println!("cat: {echoed:?} (exit {})", cat.wait().await?);
    assert_eq!(echoed, "piped through stdin\n");
    Ok(())
}
