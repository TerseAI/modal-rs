//! Runs a small web server in a few Sandboxes and reaches them through Modal
//! tunnels:
//!
//! - create the Sandboxes concurrently from a digest-pinned image, each with a
//!   readiness probe, an exposed port, and a tag shared by the group
//! - call one over HTTPS and open a WebSocket to it through its tunnel
//! - find the group by tag, terminate one by ID from a fresh handle, and watch
//!   it drop out of the list
//!
//!     cargo run --example tunnels
//!
//! Runs three 0.5-core Sandboxes for under a minute in the App `modal-rs-examples`.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use futures_util::{SinkExt, StreamExt};
use modal::{AppLookupParams, Client, Image, Probe, SandboxCreateParams, SandboxListParams};
use tokio_tungstenite::tungstenite::Message;

const IMAGE: &str =
    "python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1";
const SERVERS: usize = 3;
const PORT: u16 = 8000;
const READY_FILE: &str = "/tmp/ready";

/// Answers HTTP with JSON describing the request and echoes one WebSocket text
/// frame on /ws, then writes the ready file once it is listening.
const SERVER: &str = r#"
import asyncio, base64, hashlib, json, os
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

async def handle(reader, writer):
    head = (await reader.readuntil(b"\r\n\r\n")).decode()
    lines = head.split("\r\n")
    method, path, _ = lines[0].split(" ", 2)
    headers = {k.strip().lower(): v.strip() for k, v in (l.split(":", 1) for l in lines[1:] if ":" in l)}
    if path.startswith("/ws") and headers.get("upgrade", "").lower() == "websocket":
        accept = base64.b64encode(hashlib.sha1((headers["sec-websocket-key"] + GUID).encode()).digest()).decode()
        writer.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                      f"Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").encode())
        await writer.drain()
        _, b1 = await reader.readexactly(2)
        length = b1 & 0x7F
        if length == 126:
            length = int.from_bytes(await reader.readexactly(2), "big")
        mask = await reader.readexactly(4)
        payload = bytes(c ^ mask[i % 4] for i, c in enumerate(await reader.readexactly(length)))
        head = bytes([0x81, length]) if length < 126 else bytes([0x81, 126]) + length.to_bytes(2, "big")
        writer.write(head + payload)
    else:
        data = json.dumps({"name": os.environ["SERVER_NAME"], "method": method, "path": path}).encode()
        writer.write((f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                      f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n").encode() + data)
    await writer.drain()
    writer.close()

async def main():
    await asyncio.start_server(handle, "0.0.0.0", int(os.environ["PORT"]))
    open(os.environ["READY_FILE"], "w").close()
    await asyncio.Event().wait()

asyncio.run(main())
"#;

struct Server {
    name: String,
    sandbox_id: String,
    url: String,
    timings: String,
}

#[tokio::main]
async fn main() -> Result<()> {
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
    let image = Image::from_registry(IMAGE);
    let built = Instant::now();
    let image_id = image.build(&client, &app).await?;
    println!("image {image_id} from {IMAGE} in {:?}", built.elapsed());

    // A random tag value marks this run's Sandboxes for listing and cleanup.
    let group = format!("group-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let results = futures_util::future::join_all(
        (0..SERVERS).map(|i| create_server(&client, &app, &image, &group, i)),
    )
    .await;
    let mut servers = Vec::new();
    let mut failures = Vec::new();
    for result in results {
        match result {
            Ok(server) => servers.push(server),
            Err(error) => failures.push(error),
        }
    }
    for server in &servers {
        println!(
            "server {} {} {}",
            server.name, server.sandbox_id, server.timings
        );
    }

    let outcome = if let Some(error) = failures.into_iter().next() {
        Err(error)
    } else {
        exercise(&client, &app.app_id, &group, &servers).await
    };

    // Terminate everything this run created, whatever happened.
    for sandbox_id in list_group(&client, &app.app_id, &group).await? {
        client.sandbox_from_id(&sandbox_id).terminate().await?;
    }
    println!("cleaned up after {:?}", started.elapsed());
    outcome
}

async fn create_server(
    client: &Client,
    app: &modal::App,
    image: &Image,
    group: &str,
    i: usize,
) -> Result<Server> {
    let started = Instant::now();
    // Names are unique within an App.
    let name = format!("{group}-server-{i}");
    let sandbox = client
        .create_sandbox(
            app,
            image,
            SandboxCreateParams {
                name: Some(name.clone()),
                command: vec!["python".into(), "-c".into(), SERVER.into()],
                env: HashMap::from([
                    ("SERVER_NAME".into(), name.clone()),
                    ("PORT".into(), PORT.to_string()),
                    ("READY_FILE".into(), READY_FILE.into()),
                ]),
                cpu: Some(0.5),
                memory_mib: Some(256),
                encrypted_ports: vec![PORT],
                readiness_probe: Some(
                    Probe::exec(["/usr/bin/test", "-f", READY_FILE])
                        .interval(Duration::from_millis(250)),
                ),
                timeout: Some(Duration::from_secs(600)),
                tags: HashMap::from([("group".into(), group.into())]),
                ..Default::default()
            },
        )
        .await
        .with_context(|| format!("create {name}"))?;
    let created = started.elapsed();
    sandbox
        .wait_until_ready(Duration::from_secs(60))
        .await
        .with_context(|| format!("ready {name}"))?;
    let ready = started.elapsed();
    let tunnels = sandbox.tunnels(Duration::from_secs(30)).await?;
    let url = tunnels
        .get(&PORT)
        .with_context(|| format!("no tunnel for port {PORT}"))?
        .url();
    Ok(Server {
        name,
        sandbox_id: sandbox.id().to_string(),
        url,
        timings: format!(
            "created {created:?}, ready {ready:?}, routable {:?}",
            started.elapsed()
        ),
    })
}

async fn exercise(client: &Client, app_id: &str, group: &str, servers: &[Server]) -> Result<()> {
    let server = &servers[0];
    println!("{} is at {}", server.name, server.url);

    // Tunnels are public HTTPS endpoints.
    let reply = reqwest::get(format!("{}/hello", server.url)).await?;
    let version = reply.version();
    let body: serde_json::Value = reply.error_for_status()?.json().await?;
    ensure!(
        body["name"] == server.name && body["path"] == "/hello",
        "unexpected reply {body}"
    );
    println!("GET /hello over {version:?}: {body}");

    // WebSocket upgrades pass through the tunnel too.
    let ws_url = format!("{}/ws", server.url.replacen("https://", "wss://", 1));
    let (mut socket, _) = tokio::time::timeout(
        Duration::from_secs(10),
        tokio_tungstenite::connect_async(ws_url.as_str()),
    )
    .await
    .context("websocket connect timed out")??;
    socket.send(Message::text("hello through the tunnel")).await?;
    let echoed = tokio::time::timeout(Duration::from_secs(10), socket.next())
        .await
        .context("websocket echo timed out")?
        .context("websocket closed")??;
    ensure!(
        echoed.to_text()? == "hello through the tunnel",
        "unexpected websocket echo {echoed:?}"
    );
    println!("websocket echo through the tunnel: ok");

    // The group by tag, then terminate one by ID from a fresh handle.
    let listed = list_group(client, app_id, group).await?;
    ensure!(
        listed.len() == servers.len(),
        "listed {} of {} servers",
        listed.len(),
        servers.len()
    );
    println!("listed {} Sandboxes tagged group={group}", listed.len());

    let stopped = client.sandbox_from_id(&server.sandbox_id);
    stopped.terminate().await?;
    let exit = tokio::time::timeout(Duration::from_secs(30), stopped.wait()).await??;
    println!(
        "terminated {} (exit {exit}); poll: {:?}",
        server.sandbox_id,
        stopped.poll().await?
    );

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let listed = list_group(client, app_id, group).await?;
        if !listed.contains(&server.sandbox_id) {
            println!("terminated Sandbox dropped out of the list: {} left", listed.len());
            break;
        }
        if Instant::now() > deadline {
            bail!("terminated Sandbox still listed after 30s");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    match stopped.terminate().await {
        Ok(()) => println!("terminating it again: ok (idempotent)"),
        Err(error) => println!("terminating it again: {error}"),
    }
    match client
        .sandbox_from_id("sb-00000000000000000000000000")
        .terminate()
        .await
    {
        Ok(()) => println!("terminating an unknown ID: ok"),
        Err(error) => println!("terminating an unknown ID: {error}"),
    }
    Ok(())
}

async fn list_group(client: &Client, app_id: &str, group: &str) -> Result<Vec<String>> {
    Ok(client
        .list_sandboxes(SandboxListParams {
            app_id: Some(app_id.into()),
            tags: HashMap::from([("group".into(), group.into())]),
            ..Default::default()
        })
        .await?
        .into_iter()
        .map(|info| info.sandbox_id)
        .collect())
}
