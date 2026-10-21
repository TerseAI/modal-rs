//! Lists Sandboxes still running in the App the live examples use, and
//! terminates them with `--terminate`.
//!
//!     cargo run --example leftovers [-- --terminate]

use modal::{AppLookupParams, Client, SandboxListParams};

#[tokio::main]
async fn main() -> modal::Result<()> {
    let client = Client::from_env()?;
    let app = client.app_from_name("modal-rs-examples", AppLookupParams::default()).await?;
    let running = client
        .list_sandboxes(SandboxListParams {
            app_id: Some(app.app_id),
            ..Default::default()
        })
        .await?;
    println!("{} running in modal-rs-examples", running.len());
    let terminate = std::env::args().any(|arg| arg == "--terminate");
    for sandbox in running {
        println!("{} {:?} {:?}", sandbox.sandbox_id, sandbox.name, sandbox.tags);
        if terminate {
            client.sandbox_from_id(&sandbox.sandbox_id).terminate().await?;
        }
    }
    Ok(())
}
