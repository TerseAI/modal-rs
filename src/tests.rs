//! End-to-end tests against an in-process fake of Modal's control plane and a
//! fake task command router, checking what goes over the wire: headers, auth,
//! retries, throttling, image builds, exec streaming and JWT refresh.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::codegen::BoxStream;
use tonic::{Code, Request, Response, Status};

use crate::retry::{fake_jwt, status_with_retry_policy, unix_now};
use crate::{
    AppLookupParams, Client, Config, Error, ExecParams, Image, SandboxCreateParams, Secret,
};

#[allow(clippy::all, dead_code)]
mod server_proto {
    pub mod client {
        include!(concat!(env!("OUT_DIR"), "/server/modal.client.rs"));
    }
    pub mod task_command_router {
        include!(concat!(
            env!("OUT_DIR"),
            "/server/modal.task_command_router.rs"
        ));
    }
}

use server_proto::client::{self as pb, modal_client_server};
use server_proto::task_command_router::{self as tcr, task_command_router_server};

/// One call as the fake saw it.
#[derive(Clone, Debug)]
struct Call {
    method: &'static str,
    headers: HashMap<String, String>,
}

#[derive(Default)]
struct Recorded {
    calls: Vec<Call>,
    router_calls: Vec<Call>,
    image_requests: Vec<pb::ImageGetOrCreateRequest>,
    join_entry_ids: Vec<String>,
    create_requests: Vec<pb::SandboxCreateV2Request>,
    exec_starts: Vec<tcr::TaskExecStartRequest>,
    stdio_offsets: Vec<(i32, u64)>,
    stdin_writes: Vec<(u64, Vec<u8>, bool)>,
    terminated: bool,
    snapshots: Vec<tcr::TaskSnapshotDirectoryRequest>,
    mounts: Vec<tcr::TaskMountDirectoryRequest>,
}

/// Faults the fake injects.
#[derive(Clone, Copy)]
struct Faults {
    /// Throttle the first AppGetOrCreate with a server retry policy.
    throttle_app_lookup: bool,
    /// Fail the first SandboxCreateV2 with Unavailable.
    fail_first_create: bool,
    /// Reject the router's initial JWT once, forcing a refresh.
    reject_initial_jwt: bool,
    /// Drop the stdout stream after the first chunk.
    drop_stdout_once: bool,
    /// Refuse every AuthTokenGet.
    deny_auth: bool,
}

impl Faults {
    fn all() -> Self {
        Self {
            throttle_app_lookup: true,
            fail_first_create: true,
            reject_initial_jwt: true,
            drop_stdout_once: true,
            deny_auth: false,
        }
    }

    fn none() -> Self {
        Self {
            throttle_app_lookup: false,
            fail_first_create: false,
            reject_initial_jwt: false,
            drop_stdout_once: false,
            deny_auth: false,
        }
    }
}

#[derive(Clone)]
struct Fake {
    state: Arc<Mutex<Recorded>>,
    faults: Faults,
    router_addr: SocketAddr,
    /// Close enough to expiry that the client will refresh it.
    initial_jwt: String,
    refreshed_jwt: String,
}

impl Fake {
    fn record<T>(&self, method: &'static str, request: &Request<T>) {
        self.state.lock().unwrap().calls.push(Call {
            method,
            headers: headers(request),
        });
    }

    fn count(&self, method: &str) -> usize {
        self.state
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|c| c.method == method)
            .count()
    }

    /// Records a router call and checks its JWT.
    fn record_router<T>(&self, method: &'static str, request: &Request<T>) -> Result<(), Status> {
        let headers = headers(request);
        let authorization = headers.get("authorization").cloned().unwrap_or_default();
        let mut state = self.state.lock().unwrap();
        let seen_before = state
            .router_calls
            .iter()
            .any(|c| c.headers.get("authorization") == Some(&authorization));
        state.router_calls.push(Call { method, headers });
        if authorization == format!("Bearer {}", self.refreshed_jwt) {
            Ok(())
        } else if authorization == format!("Bearer {}", self.initial_jwt) {
            if self.faults.reject_initial_jwt && !seen_before {
                Err(Status::unauthenticated("token expired"))
            } else {
                Ok(())
            }
        } else {
            Err(Status::unauthenticated("unknown token"))
        }
    }
}

fn headers<T>(request: &Request<T>) -> HashMap<String, String> {
    request
        .metadata()
        .clone()
        .into_headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect()
}

fn stream_of<T: Send + 'static>(items: Vec<Result<T, Status>>) -> BoxStream<T> {
    Box::pin(tokio_stream::iter(items))
}

#[tonic::async_trait]
impl modal_client_server::ModalClient for Fake {
    async fn auth_token_get(
        &self,
        request: Request<pb::AuthTokenGetRequest>,
    ) -> Result<Response<pb::AuthTokenGetResponse>, Status> {
        self.record("auth_token_get", &request);
        if self.faults.deny_auth {
            return Err(Status::unauthenticated("bad token"));
        }
        Ok(Response::new(pb::AuthTokenGetResponse {
            token: fake_jwt(unix_now() + 3600),
        }))
    }

    async fn app_get_or_create(
        &self,
        request: Request<pb::AppGetOrCreateRequest>,
    ) -> Result<Response<pb::AppGetOrCreateResponse>, Status> {
        self.record("app_get_or_create", &request);
        if self.faults.throttle_app_lookup && self.count("app_get_or_create") == 1 {
            return Err(status_with_retry_policy(Code::ResourceExhausted, 0.05));
        }
        Ok(Response::new(pb::AppGetOrCreateResponse {
            app_id: "ap-test".into(),
            handle_metadata: None,
        }))
    }

    async fn environment_get_or_create(
        &self,
        request: Request<pb::EnvironmentGetOrCreateRequest>,
    ) -> Result<Response<pb::EnvironmentGetOrCreateResponse>, Status> {
        self.record("environment_get_or_create", &request);
        Ok(Response::new(pb::EnvironmentGetOrCreateResponse {
            environment_id: "en-test".into(),
            metadata: Some(pb::EnvironmentMetadata {
                settings: Some(pb::EnvironmentSettings {
                    image_builder_version: "2025.06".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        }))
    }

    async fn secret_get_or_create(
        &self,
        request: Request<pb::SecretGetOrCreateRequest>,
    ) -> Result<Response<pb::SecretGetOrCreateResponse>, Status> {
        self.record("secret_get_or_create", &request);
        Ok(Response::new(pb::SecretGetOrCreateResponse {
            secret_id: format!("st-{}", request.into_inner().deployment_name),
            metadata: None,
        }))
    }

    async fn image_get_or_create(
        &self,
        request: Request<pb::ImageGetOrCreateRequest>,
    ) -> Result<Response<pb::ImageGetOrCreateResponse>, Status> {
        self.record("image_get_or_create", &request);
        self.state
            .lock()
            .unwrap()
            .image_requests
            .push(request.into_inner());
        // No result yet, so the client has to follow the build.
        Ok(Response::new(pb::ImageGetOrCreateResponse {
            image_id: "im-built".into(),
            ..Default::default()
        }))
    }

    async fn image_join_streaming(
        &self,
        request: Request<pb::ImageJoinStreamingRequest>,
    ) -> Result<Response<BoxStream<pb::ImageJoinStreamingResponse>>, Status> {
        self.record("image_join_streaming", &request);
        let entry_id = request.into_inner().last_entry_id;
        let first = entry_id.is_empty();
        self.state.lock().unwrap().join_entry_ids.push(entry_id);
        let item = if first {
            // A log entry, then the long poll ends without a result.
            pb::ImageJoinStreamingResponse {
                entry_id: "e1".into(),
                ..Default::default()
            }
        } else {
            pb::ImageJoinStreamingResponse {
                entry_id: "e2".into(),
                result: Some(pb::GenericResult {
                    status: pb::generic_result::GenericStatus::Success as i32,
                    ..Default::default()
                }),
                ..Default::default()
            }
        };
        Ok(Response::new(stream_of(vec![Ok(item)])))
    }

    async fn sandbox_create_v2(
        &self,
        request: Request<pb::SandboxCreateV2Request>,
    ) -> Result<Response<pb::SandboxCreateV2Response>, Status> {
        self.record("sandbox_create_v2", &request);
        if self.faults.fail_first_create && self.count("sandbox_create_v2") == 1 {
            return Err(Status::unavailable("try again"));
        }
        self.state
            .lock()
            .unwrap()
            .create_requests
            .push(request.into_inner());
        Ok(Response::new(pb::SandboxCreateV2Response {
            sandbox_id: "sb2-0123456789abcdef".into(),
            task_id: "ta-test".into(),
            command_router_access: Some(pb::CommandRouterAccess {
                jwt: self.initial_jwt.clone(),
                url: format!("https://{}", self.router_addr),
            }),
            tunnels: vec![pb::TunnelData {
                host: "abc.modal.host".into(),
                port: 443,
                container_port: 8080,
                ..Default::default()
            }],
            ..Default::default()
        }))
    }

    async fn sandbox_get_task_id_v2(
        &self,
        request: Request<pb::SandboxGetTaskIdRequest>,
    ) -> Result<Response<pb::SandboxGetTaskIdResponse>, Status> {
        self.record("sandbox_get_task_id_v2", &request);
        Ok(Response::new(pb::SandboxGetTaskIdResponse {
            task_id: Some("ta-test".into()),
            task_result: None,
        }))
    }

    async fn sandbox_get_command_router_access(
        &self,
        request: Request<pb::SandboxGetCommandRouterAccessRequest>,
    ) -> Result<Response<pb::SandboxGetCommandRouterAccessResponse>, Status> {
        self.record("sandbox_get_command_router_access", &request);
        Ok(Response::new(pb::SandboxGetCommandRouterAccessResponse {
            jwt: self.refreshed_jwt.clone(),
            url: format!("https://{}", self.router_addr),
            ..Default::default()
        }))
    }

    async fn sandbox_terminate_v2(
        &self,
        request: Request<pb::SandboxTerminateRequest>,
    ) -> Result<Response<pb::SandboxTerminateResponse>, Status> {
        self.record("sandbox_terminate_v2", &request);
        self.state.lock().unwrap().terminated = true;
        Ok(Response::new(Default::default()))
    }

    async fn sandbox_wait_v2(
        &self,
        request: Request<pb::SandboxWaitRequest>,
    ) -> Result<Response<pb::SandboxWaitResponse>, Status> {
        self.record("sandbox_wait_v2", &request);
        let result = self
            .state
            .lock()
            .unwrap()
            .terminated
            .then(|| pb::GenericResult {
                status: pb::generic_result::GenericStatus::Terminated as i32,
                ..Default::default()
            });
        Ok(Response::new(pb::SandboxWaitResponse {
            result,
            metadata: None,
        }))
    }

    async fn sandbox_list_v2(
        &self,
        request: Request<pb::SandboxListRequest>,
    ) -> Result<Response<pb::SandboxListResponse>, Status> {
        self.record("sandbox_list_v2", &request);
        let request = request.into_inner();
        if request.app_id != "ap-test"
            || request.tags.len() != 1
            || request.tags[0].tag_value != "pool-1"
        {
            return Err(Status::invalid_argument(format!(
                "unexpected filter: {request:?}"
            )));
        }
        let info = |id: &str, created_at: f64| pb::SandboxInfo {
            id: id.into(),
            app_id: "ap-test".into(),
            name: format!("web-{id}"),
            created_at,
            tags: request.tags.clone(),
            tunnels: vec![pb::TunnelData {
                host: format!("{id}.modal.host"),
                port: 443,
                container_port: 8000,
                ..Default::default()
            }],
            ..Default::default()
        };
        // Two pages, newest first, then an empty one.
        let sandboxes = match request.before_timestamp {
            0.0 => vec![info("sb2-a", 300.0), info("sb2-b", 200.0)],
            200.0 => vec![info("sb2-c", 100.0)],
            _ => vec![],
        };
        Ok(Response::new(pb::SandboxListResponse { sandboxes }))
    }
}

#[tonic::async_trait]
impl task_command_router_server::TaskCommandRouter for Fake {
    async fn task_snapshot_directory(
        &self,
        request: Request<tcr::TaskSnapshotDirectoryRequest>,
    ) -> Result<Response<tcr::TaskSnapshotDirectoryResponse>, Status> {
        self.record_router("task_snapshot_directory", &request)?;
        self.state
            .lock()
            .unwrap()
            .snapshots
            .push(request.into_inner());
        Ok(Response::new(tcr::TaskSnapshotDirectoryResponse {
            image_id: "im-snapshot".into(),
        }))
    }

    async fn task_mount_directory(
        &self,
        request: Request<tcr::TaskMountDirectoryRequest>,
    ) -> Result<Response<()>, Status> {
        self.record_router("task_mount_directory", &request)?;
        self.state.lock().unwrap().mounts.push(request.into_inner());
        Ok(Response::new(()))
    }

    async fn task_exec_start(
        &self,
        request: Request<tcr::TaskExecStartRequest>,
    ) -> Result<Response<tcr::TaskExecStartResponse>, Status> {
        self.record_router("task_exec_start", &request)?;
        self.state
            .lock()
            .unwrap()
            .exec_starts
            .push(request.into_inner());
        Ok(Response::new(Default::default()))
    }

    async fn task_exec_stdin_write(
        &self,
        request: Request<tcr::TaskExecStdinWriteRequest>,
    ) -> Result<Response<tcr::TaskExecStdinWriteResponse>, Status> {
        self.record_router("task_exec_stdin_write", &request)?;
        let r = request.into_inner();
        self.state
            .lock()
            .unwrap()
            .stdin_writes
            .push((r.offset, r.data, r.eof));
        Ok(Response::new(Default::default()))
    }

    async fn task_exec_stdio_read(
        &self,
        request: Request<tcr::TaskExecStdioReadRequest>,
    ) -> Result<Response<BoxStream<tcr::TaskExecStdioReadResponse>>, Status> {
        self.record_router("task_exec_stdio_read", &request)?;
        let r = request.into_inner();
        self.state
            .lock()
            .unwrap()
            .stdio_offsets
            .push((r.file_descriptor, r.offset));
        let chunk = |data: &[u8]| {
            Ok(tcr::TaskExecStdioReadResponse {
                data: data.to_vec(),
            })
        };
        let items = if r.file_descriptor == tcr::TaskExecStdioFileDescriptor::Stderr as i32 {
            vec![chunk(b"warn\n")]
        } else {
            let full = b"hello world\n";
            let rest = &full[r.offset as usize..];
            if r.offset == 0 && self.faults.drop_stdout_once {
                vec![
                    chunk(&rest[..6]),
                    Err(Status::unavailable("connection reset")),
                ]
            } else {
                vec![chunk(rest)]
            }
        };
        Ok(Response::new(stream_of(items)))
    }

    async fn task_exec_wait(
        &self,
        request: Request<tcr::TaskExecWaitRequest>,
    ) -> Result<Response<tcr::TaskExecWaitResponse>, Status> {
        self.record_router("task_exec_wait", &request)?;
        let exec_id = request.into_inner().exec_id;
        let sleeps = self.state.lock().unwrap().exec_starts.iter().any(|e| {
            e.exec_id == exec_id && e.command_args.first().map(String::as_str) == Some("sleep")
        });
        if sleeps {
            // Never finishes; the client has to give up at its deadline.
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
        Ok(Response::new(tcr::TaskExecWaitResponse {
            exit_status: Some(tcr::task_exec_wait_response::ExitStatus::Code(3)),
        }))
    }
}

async fn start(faults: Faults) -> (Client, Fake) {
    let router_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fake = Fake {
        state: Arc::default(),
        faults,
        router_addr: router_listener.local_addr().unwrap(),
        initial_jwt: fake_jwt(unix_now() + 10),
        refreshed_jwt: fake_jwt(unix_now() + 3600),
    };
    let cp_addr = cp_listener.local_addr().unwrap();

    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(task_command_router_server::TaskCommandRouterServer::new(
                fake.clone(),
            ))
            .serve_with_incoming(TcpListenerStream::new(router_listener)),
    );
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(modal_client_server::ModalClientServer::new(fake.clone()))
            .serve_with_incoming(TcpListenerStream::new(cp_listener)),
    );

    let mut config = Config::with_token("ak-test", "as-test");
    config.server_url = format!("http://{cp_addr}");
    (Client::new(config).unwrap(), fake)
}

#[tokio::test]
async fn sandbox_lifecycle_against_fake_modal() {
    let (client, fake) = start(Faults::all()).await;

    let app = client
        .app_from_name(
            "test-app",
            AppLookupParams {
                create_if_missing: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(app.app_id, "ap-test");

    let image = Image::from_registry("python:3.12-slim").dockerfile_commands(["RUN echo hi"]);
    let sandbox = client
        .create_sandbox(
            &app,
            &image,
            SandboxCreateParams {
                env: HashMap::from([("FOO".into(), "bar".into())]),
                secrets: vec![Secret::from_name("db-creds")],
                encrypted_ports: vec![8080],
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(sandbox.is_v2());
    assert_eq!(image.image_id(), Some("im-built"));

    // Tunnels came back complete at create, so this makes no call.
    let tunnels = sandbox.tunnels(Duration::from_secs(1)).await.unwrap();
    assert_eq!(tunnels[&8080].url(), "https://abc.modal.host");

    let mut process = sandbox
        .exec(["echo", "hello world"], ExecParams::default())
        .await
        .unwrap();
    process.stdin.write("abc").await.unwrap();
    process.stdin.write("de").await.unwrap();
    process.stdin.close().await.unwrap();
    let output = process.output().await.unwrap();
    assert_eq!(output.stdout, b"hello world\n");
    assert_eq!(output.stderr, b"warn\n");
    assert_eq!(output.exit_code, 3);

    sandbox.terminate().await.unwrap();
    assert_eq!(sandbox.wait().await.unwrap(), 137);

    let state = fake.state.lock().unwrap();

    // Every control plane call carries the client identity and credentials,
    // and every unary call but AuthTokenGet carries the auth token.
    for call in &state.calls {
        assert_eq!(call.headers["x-modal-client-type"], "9", "{call:?}");
        assert_eq!(call.headers["x-modal-client-version"], "1.0.0");
        assert!(call.headers["x-modal-libmodal-version"].starts_with("modal-go/0.11.1+modal-rs."));
        assert_eq!(call.headers["x-modal-token-id"], "ak-test");
        assert_eq!(call.headers["x-modal-token-secret"], "as-test");
        assert_eq!(call.headers["x-modal-host"], "127.0.0.1");
        let has_auth = call.headers.contains_key("x-modal-auth-token");
        let expect_auth = !matches!(call.method, "auth_token_get" | "image_join_streaming");
        assert_eq!(has_auth, expect_auth, "{call:?}");
    }
    assert_eq!(
        state
            .calls
            .iter()
            .filter(|c| c.method == "auth_token_get")
            .count(),
        1,
        "the auth token is fetched once and cached"
    );

    // The throttled lookup was retried as a throttle retry, not a regular one.
    let lookups: Vec<_> = state
        .calls
        .iter()
        .filter(|c| c.method == "app_get_or_create")
        .collect();
    assert_eq!(lookups.len(), 2);
    assert_eq!(lookups[1].headers["x-throttle-retry-attempt"], "1");
    assert_eq!(lookups[1].headers["x-retry-attempt"], "0");
    assert!(lookups[1].headers.contains_key("x-throttle-retry-delay"));

    // The failed create was retried with the same idempotency key.
    let creates: Vec<_> = state
        .calls
        .iter()
        .filter(|c| c.method == "sandbox_create_v2")
        .collect();
    assert_eq!(creates.len(), 2);
    assert_eq!(
        creates[0].headers["x-idempotency-key"],
        creates[1].headers["x-idempotency-key"]
    );
    assert_eq!(creates[0].headers["x-retry-attempt"], "0");
    assert_eq!(creates[1].headers["x-retry-attempt"], "1");

    // The registry base and the RUN layer build separately, as in the Go SDK,
    // and each build follows the join stream across a reopen.
    assert_eq!(state.join_entry_ids, vec!["", "e1", "", "e1"]);
    assert_eq!(state.image_requests.len(), 2);
    for request in &state.image_requests {
        assert_eq!(request.builder_version, "2025.06");
        assert_eq!(request.app_id, "ap-test");
    }
    let base = state.image_requests[0].image.as_ref().unwrap();
    assert_eq!(base.dockerfile_commands, vec!["FROM python:3.12-slim"]);
    assert!(base.base_images.is_empty());
    let layer = state.image_requests[1].image.as_ref().unwrap();
    assert_eq!(layer.dockerfile_commands, vec!["FROM base", "RUN echo hi"]);
    assert_eq!(layer.base_images[0].image_id, "im-built");
    assert_eq!(layer.base_images[0].docker_tag, "base");

    // Named secrets go by ID, env inline and last.
    let create = &state.create_requests[0];
    let definition = create.definition.as_ref().unwrap();
    assert_eq!(definition.secret_ids, vec!["st-db-creds".to_string()]);
    assert_eq!(definition.timeout_secs, 300);
    use pb::secret_source::Source;
    match (
        &create.secret_sources[0].source,
        &create.secret_sources[1].source,
    ) {
        (Some(Source::SecretId(id)), Some(Source::Env(env))) => {
            assert_eq!(id, "st-db-creds");
            assert_eq!(env.contents["FOO"], "bar");
        }
        other => panic!("unexpected secret sources: {other:?}"),
    }

    // The router rejected the near-expiry JWT once and the client refreshed it.
    let starts: Vec<_> = state
        .router_calls
        .iter()
        .filter(|c| c.method == "task_exec_start")
        .collect();
    assert_eq!(starts.len(), 2);
    assert_eq!(
        starts[0].headers["authorization"],
        format!("Bearer {}", fake.initial_jwt)
    );
    assert_eq!(
        starts[1].headers["authorization"],
        format!("Bearer {}", fake.refreshed_jwt)
    );
    assert_eq!(
        state
            .calls
            .iter()
            .filter(|c| c.method == "sandbox_get_command_router_access")
            .count(),
        1
    );
    let exec = &state.exec_starts[0];
    assert_eq!(exec.command_args, vec!["echo", "hello world"]);
    assert_eq!(exec.task_id, "ta-test");
    assert_eq!(exec.stdout_config, tcr::TaskExecStdoutConfig::Pipe as i32);

    // Stdout resumed from the byte after the dropped chunk.
    let stdout = tcr::TaskExecStdioFileDescriptor::Stdout as i32;
    let stdout_offsets: Vec<u64> = state
        .stdio_offsets
        .iter()
        .filter(|(fd, _)| *fd == stdout)
        .map(|(_, offset)| *offset)
        .collect();
    assert_eq!(stdout_offsets, vec![0, 6]);

    // Stdin writes are offset-ordered and end with EOF.
    let writes: Vec<(u64, bool)> = state
        .stdin_writes
        .iter()
        .map(|(o, _, eof)| (*o, *eof))
        .collect();
    assert_eq!(writes, vec![(0, false), (3, false), (5, true)]);
}

#[tokio::test]
async fn rejected_credentials_fail_fast() {
    let (client, fake) = start(Faults {
        deny_auth: true,
        ..Faults::none()
    })
    .await;
    let err = client
        .app_from_name("test-app", AppLookupParams::default())
        .await
        .unwrap_err();
    assert_eq!(err.grpc_code(), Some(Code::Unauthenticated), "{err}");
    assert_eq!(
        fake.count("auth_token_get"),
        1,
        "auth failures are not retried"
    );
    assert_eq!(fake.count("app_get_or_create"), 0);
}

#[tokio::test]
async fn reattached_sandbox_execs_and_times_out() {
    let (client, fake) = start(Faults::none()).await;
    // A handle from an ID looks up its task and router access itself.
    let sandbox = client.sandbox_from_id("sb2-0123456789abcdef");

    let output = sandbox
        .exec(["true"], ExecParams::default())
        .await
        .unwrap()
        .output()
        .await
        .unwrap();
    assert_eq!(output.exit_code, 3);
    assert_eq!(fake.count("sandbox_get_task_id_v2"), 1);
    assert_eq!(fake.count("sandbox_get_command_router_access"), 1);

    let started = Instant::now();
    let process = sandbox
        .exec(
            ["sleep", "100"],
            ExecParams {
                timeout: Some(Duration::from_secs(1)),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let err = process.wait().await.unwrap_err();
    assert!(matches!(err, Error::ExecTimeout(_)), "{err}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "took {:?}",
        started.elapsed()
    );

    let err = sandbox
        .exec(
            ["sleep", "1"],
            ExecParams {
                timeout: Some(Duration::from_millis(1500)),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Invalid(_)), "{err}");
}

#[tokio::test]
async fn lists_sandboxes_across_pages() {
    let (client, fake) = start(Faults::none()).await;
    let sandboxes = client
        .list_sandboxes(crate::SandboxListParams {
            app_id: Some("ap-test".into()),
            tags: HashMap::from([("pool".into(), "pool-1".into())]),
            ..Default::default()
        })
        .await
        .unwrap();
    let ids: Vec<&str> = sandboxes.iter().map(|s| s.sandbox_id.as_str()).collect();
    assert_eq!(ids, vec!["sb2-a", "sb2-b", "sb2-c"]);
    assert_eq!(sandboxes[0].name.as_deref(), Some("web-sb2-a"));
    assert_eq!(sandboxes[0].tags["pool"], "pool-1");
    assert_eq!(
        sandboxes[2].tunnels[&8000].url(),
        "https://sb2-c.modal.host"
    );
    assert_eq!(fake.count("sandbox_list_v2"), 3);
}

#[tokio::test]
async fn directory_snapshots_and_mounts_use_the_authenticated_router() {
    let (client, fake) = start(Faults::all()).await;
    let app = client
        .app_from_name("test-app", AppLookupParams::default())
        .await
        .unwrap();
    let sb = client
        .create_sandbox(
            &app,
            &Image::from_id("im-base"),
            SandboxCreateParams::default(),
        )
        .await
        .unwrap();
    assert!(sb.snapshot_directory("relative", None).await.is_err());
    assert!(
        sb.snapshot_directory("/customer", Some(Duration::ZERO))
            .await
            .is_err()
    );
    assert!(
        sb.mount_image("/", &Image::from_id("im-code"))
            .await
            .is_err()
    );
    assert!(
        sb.mount_image("/customer", &Image::from_registry("busybox"))
            .await
            .is_err()
    );
    let image = sb
        .snapshot_directory("/customer", Some(Duration::from_secs(3600)))
        .await
        .unwrap();
    sb.mount_image("/customer", &image).await.unwrap();
    sb.snapshot_directory("/customer", None).await.unwrap();
    let state = fake.state.lock().unwrap();
    assert_eq!(state.snapshots.len(), 2);
    assert_eq!(state.snapshots[0].path, b"/customer");
    assert_eq!(state.snapshots[0].ttl_seconds, Some(3600));
    assert_eq!(state.snapshots[1].ttl_seconds, Some(-1));
    assert_ne!(
        state.snapshots[0].snapshot_id,
        state.snapshots[1].snapshot_id
    );
    assert!(uuid::Uuid::parse_str(&state.snapshots[0].snapshot_id).is_ok());
    assert_eq!(state.mounts[0].image_id, "im-snapshot");
    assert_eq!(state.mounts[0].path, b"/customer");
}
