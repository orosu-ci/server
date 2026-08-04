//! End-to-end tests against a real `Server` bound to a real TCP port,
//! exercised with real WebSocket clients (mirroring how orosu-client and the
//! JS action both actually talk to it). This is the highest-risk code in
//! the crate — auth, the WS task-launch/file-upload handshake, IP
//! filtering — so it's deliberately tested at this level rather than only
//! unit-tested in isolation.
//!
//! Deliberately NOT using `ApiClient` (api/client.rs) here: its
//! `start_task` calls `std::process::exit()` directly on receiving the
//! task's exit code — correct for the real CLI, but it would kill this
//! whole test binary, not just fail one test. Every test below drives the
//! wire protocol manually instead.
//!
//! `Server::serve()` doesn't expose the OS-assigned port when binding to
//! `:0`, so each test picks its own fixed, distinct port.

use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use orosu::api::envelopes::{
    FileChunkRequestEnvelope, TaskEventResponseEnvelope, TaskLaunchRequestEnvelope,
    TaskLaunchStatusResponseEnvelope,
};
use orosu::api::file_chunk::FileChunk;
use orosu::api::protocol_version::{PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER_NAME};
use orosu::api::{FileAttachment, ServerTaskNotification, StartTaskRequest, TaskLaunchStatus};
use orosu::configuration::Configuration;
use orosu::cryptography::{ClientKey, Keygen};
use orosu::server::Server;
use std::io::Write;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};

fn build_config(yaml: &str) -> Configuration {
    serde_saphyr::from_str(yaml).unwrap()
}

async fn wait_for_port(port: u16) {
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("server on port {port} never became reachable");
}

async fn spawn_server(configuration: Configuration, port: u16) {
    tokio::spawn(async move {
        let server = Server::new(
            configuration.listen,
            configuration.ip_whitelist,
            configuration.ip_blacklist,
            configuration.clients,
        );
        let _ = server.serve().await;
    });
    wait_for_port(port).await;
}

fn write_public_key(dir: &std::path::Path, keygen: &Keygen) -> std::path::PathBuf {
    let path = dir.join("public.key");
    std::fs::write(&path, keygen.public_key_base64()).unwrap();
    path
}

/// Mirrors `ApiClient::connect`'s own JWT construction (api/client.rs),
/// parameterized so error-path tests can hand it a wrong client name or an
/// already-expired `exp` — things the real `ApiClient` never produces.
/// `Claims` (cryptography.rs) has crate-private fields, so this defines an
/// equivalent local shape rather than needing access to it.
#[derive(serde::Serialize)]
struct TestClaims {
    sub: String,
    exp: i64,
}

fn sign_jwt(client_name: &str, seed: &[u8], exp_offset_secs: i64) -> String {
    let seed: [u8; 32] = seed.try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&seed).to_pkcs8_der().unwrap();
    let encoding_key = EncodingKey::from_ed_der(signing_key.as_bytes());
    let header = Header::new(Algorithm::EdDSA);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = TestClaims {
        sub: client_name.to_string(),
        exp: now + exp_offset_secs,
    };
    jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap()
}

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Connects with fully custom headers (rather than through `ApiClient`), so
/// handshake-rejection paths can be exercised directly. Always sends a
/// correct protocol version, so tests using this aren't accidentally
/// short-circuited by that check instead of the one they mean to exercise —
/// see `connect_raw_with_protocol_version` for the tests that specifically
/// need to control it.
async fn connect_raw(
    port: u16,
    authorization: Option<&str>,
    user_agent: Option<&str>,
) -> Result<WsStream, tokio_tungstenite::tungstenite::Error> {
    connect_raw_with_protocol_version(
        port,
        authorization,
        user_agent,
        Some(&PROTOCOL_VERSION.to_string()),
    )
    .await
}

async fn connect_raw_with_protocol_version(
    port: u16,
    authorization: Option<&str>,
    user_agent: Option<&str>,
    protocol_version: Option<&str>,
) -> Result<WsStream, tokio_tungstenite::tungstenite::Error> {
    let mut request = format!("ws://127.0.0.1:{port}/")
        .into_client_request()
        .unwrap();
    let headers = request.headers_mut();
    headers.remove("user-agent");
    if let Some(auth) = authorization {
        headers.insert("authorization", HeaderValue::from_str(auth).unwrap());
    }
    if let Some(ua) = user_agent {
        headers.insert("user-agent", HeaderValue::from_str(ua).unwrap());
    }
    if let Some(pv) = protocol_version {
        headers.insert(
            HeaderName::from_static(PROTOCOL_VERSION_HEADER_NAME),
            HeaderValue::from_str(pv).unwrap(),
        );
    }
    let (stream, _response) = tokio_tungstenite::connect_async(request).await?;
    Ok(stream)
}

/// A valid connection: real key, real signature, correctly-formed headers.
async fn connect_authenticated(port: u16, client_name: &str, seed: &[u8]) -> WsStream {
    let token = sign_jwt(client_name, seed, 10);
    connect_raw(
        port,
        Some(&format!("Token {token}")),
        Some("Orosu/test-suite"),
    )
    .await
    .unwrap()
}

fn rejection_status(err: &tokio_tungstenite::tungstenite::Error) -> Option<u16> {
    match err {
        tokio_tungstenite::tungstenite::Error::Http(response) => Some(response.status().as_u16()),
        _ => None,
    }
}

async fn send_launch(
    ws: &mut WsStream,
    script: &str,
    args: Vec<String>,
    file: Option<FileAttachment>,
) {
    let envelope = TaskLaunchRequestEnvelope {
        body: StartTaskRequest {
            script_name: script.to_string(),
            arguments: args,
            file,
        },
    };
    ws.send(Message::Binary(envelope.into())).await.unwrap();
}

async fn recv_launch_response(ws: &mut WsStream) -> TaskLaunchStatusResponseEnvelope {
    let msg = ws.next().await.unwrap().unwrap();
    let Message::Binary(bytes) = msg else {
        panic!("expected a binary message, got {msg:?}");
    };
    bytes.into()
}

async fn recv_task_event(ws: &mut WsStream) -> Option<TaskEventResponseEnvelope> {
    match ws.next().await {
        Some(Ok(Message::Binary(bytes))) => Some(bytes.into()),
        Some(Ok(Message::Close(_))) | None => None,
        Some(Ok(other)) => panic!("expected a binary message or close, got {other:?}"),
        Some(Err(e)) => panic!("websocket error: {e}"),
    }
}

fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, contents) in entries {
        writer
            .start_file(*name, zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(contents).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

/// Runs the full launch handshake for a script with no file attachment,
/// asserting it reaches `launched`.
async fn launch_without_file(ws: &mut WsStream, script: &str, args: Vec<String>) {
    send_launch(ws, script, args, None).await;
    let response = recv_launch_response(ws).await;
    match response {
        TaskLaunchStatusResponseEnvelope::Success {
            body: TaskLaunchStatus::Launched { .. },
        } => {}
        other => panic!("expected Launched, got {other:?}"),
    }
}

#[tokio::test]
async fn happy_path_launches_streams_output_and_exit_code() {
    let port = 19100;
    let key_dir = tempfile::tempdir().unwrap();
    let keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &keygen);

    let config = build_config(&format!(
        r#"
listen:
  tcp: "127.0.0.1:{port}"
clients:
  - name: "test-client"
    secret_file: "{}"
    scripts:
      - name: "hello"
        command: ["echo", "hello from integration test"]
"#,
        public_key_path.display()
    ));
    spawn_server(config, port).await;

    let client_key = ClientKey::from_string(keygen.private_key_base64()).unwrap();
    let mut ws = connect_authenticated(port, "test-client", &client_key.key).await;

    launch_without_file(&mut ws, "hello", vec![]).await;

    let mut saw_output = false;
    loop {
        match recv_task_event(&mut ws).await {
            Some(TaskEventResponseEnvelope::Success {
                body: ServerTaskNotification::Output(event),
            }) => {
                assert_eq!(
                    event.value,
                    orosu::tasks::TaskOutput::Stdout("hello from integration test".to_string())
                );
                saw_output = true;
            }
            Some(TaskEventResponseEnvelope::Success {
                body: ServerTaskNotification::ExitCode(code),
            }) => {
                assert_eq!(code, 0);
                break;
            }
            Some(other) => panic!("unexpected event: {other:?}"),
            None => panic!("connection closed before an exit code arrived"),
        }
    }
    assert!(saw_output, "expected at least one stdout event");
}

fn single_client_config(
    port: u16,
    public_key_path: &std::path::Path,
    extra: &str,
) -> Configuration {
    build_config(&format!(
        r#"
listen:
  tcp: "127.0.0.1:{port}"
clients:
  - name: "test-client"
    secret_file: "{}"
    {extra}
    scripts:
      - name: "hello"
        command: ["echo", "hi"]
"#,
        public_key_path.display()
    ))
}

#[tokio::test]
async fn rejects_a_jwt_for_an_unregistered_client_name() {
    let port = 19101;
    let key_dir = tempfile::tempdir().unwrap();
    let keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &keygen);
    spawn_server(single_client_config(port, &public_key_path, ""), port).await;

    let client_key = ClientKey::from_string(keygen.private_key_base64()).unwrap();
    let token = sign_jwt("nobody-registered-with-this-name", &client_key.key, 10);
    let result = connect_raw(port, Some(&format!("Token {token}")), Some("Orosu/x")).await;

    let err = result.unwrap_err();
    assert_eq!(rejection_status(&err), Some(401));
}

#[tokio::test]
async fn rejects_a_signature_that_does_not_match_the_registered_public_key() {
    let port = 19102;
    let key_dir = tempfile::tempdir().unwrap();
    let real_keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &real_keygen);
    spawn_server(single_client_config(port, &public_key_path, ""), port).await;

    // Correct client name, but signed with an entirely different keypair
    // than the one whose public key the server has on file.
    let impostor_keygen = Keygen::new("test-client".to_string());
    let impostor_key = ClientKey::from_string(impostor_keygen.private_key_base64()).unwrap();
    let token = sign_jwt("test-client", &impostor_key.key, 10);
    let result = connect_raw(port, Some(&format!("Token {token}")), Some("Orosu/x")).await;

    let err = result.unwrap_err();
    assert_eq!(rejection_status(&err), Some(401));
}

#[tokio::test]
async fn rejects_an_expired_token() {
    let port = 19103;
    let key_dir = tempfile::tempdir().unwrap();
    let keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &keygen);
    spawn_server(single_client_config(port, &public_key_path, ""), port).await;

    let client_key = ClientKey::from_string(keygen.private_key_base64()).unwrap();
    let token = sign_jwt("test-client", &client_key.key, -100);
    let result = connect_raw(port, Some(&format!("Token {token}")), Some("Orosu/x")).await;

    let err = result.unwrap_err();
    assert_eq!(rejection_status(&err), Some(401));
}

#[tokio::test]
async fn rejects_a_missing_authorization_header() {
    let port = 19104;
    let key_dir = tempfile::tempdir().unwrap();
    let keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &keygen);
    spawn_server(single_client_config(port, &public_key_path, ""), port).await;

    let result = connect_raw(port, None, Some("Orosu/x")).await;
    let err = result.unwrap_err();
    assert_eq!(rejection_status(&err), Some(401));
}

#[tokio::test]
async fn rejects_a_missing_user_agent_header() {
    let port = 19105;
    let key_dir = tempfile::tempdir().unwrap();
    let keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &keygen);
    spawn_server(single_client_config(port, &public_key_path, ""), port).await;

    let client_key = ClientKey::from_string(keygen.private_key_base64()).unwrap();
    let token = sign_jwt("test-client", &client_key.key, 10);
    let result = connect_raw(port, Some(&format!("Token {token}")), None).await;

    let err = result.unwrap_err();
    assert_eq!(rejection_status(&err), Some(401));
}

#[tokio::test]
async fn rejects_a_user_agent_with_the_wrong_product_name() {
    let port = 19106;
    let key_dir = tempfile::tempdir().unwrap();
    let keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &keygen);
    spawn_server(single_client_config(port, &public_key_path, ""), port).await;

    let client_key = ClientKey::from_string(keygen.private_key_base64()).unwrap();
    let token = sign_jwt("test-client", &client_key.key, 10);
    let result = connect_raw(port, Some(&format!("Token {token}")), Some("curl/8.0.0")).await;

    let err = result.unwrap_err();
    assert_eq!(rejection_status(&err), Some(401));
}

#[tokio::test]
async fn treats_a_missing_protocol_version_header_as_version_zero_and_rejects_it() {
    // A missing header isn't a malformed request — it's every client built
    // before this header existed (every currently released orosu-client and
    // JS action). The server treats that as protocol version 0, which
    // still doesn't match PROTOCOL_VERSION, so the outcome is the same 400
    // as an explicit wrong version — see auth_scope.rs and
    // protocol_version.rs's PROTOCOL_VERSION doc comment.
    let port = 19117;
    let key_dir = tempfile::tempdir().unwrap();
    let keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &keygen);
    spawn_server(single_client_config(port, &public_key_path, ""), port).await;

    let client_key = ClientKey::from_string(keygen.private_key_base64()).unwrap();
    let token = sign_jwt("test-client", &client_key.key, 10);
    let result = connect_raw_with_protocol_version(
        port,
        Some(&format!("Token {token}")),
        Some("Orosu/x"),
        None,
    )
    .await;

    // Distinct from the 401s used for actual auth failures above — a
    // version mismatch and a bad credential need different fixes.
    let err = result.unwrap_err();
    assert_eq!(rejection_status(&err), Some(400));
}

#[tokio::test]
async fn rejects_a_protocol_version_that_does_not_match_the_servers() {
    let port = 19118;
    let key_dir = tempfile::tempdir().unwrap();
    let keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &keygen);
    spawn_server(single_client_config(port, &public_key_path, ""), port).await;

    let client_key = ClientKey::from_string(keygen.private_key_base64()).unwrap();
    let token = sign_jwt("test-client", &client_key.key, 10);
    let wrong_version = (PROTOCOL_VERSION + 1).to_string();
    let result = connect_raw_with_protocol_version(
        port,
        Some(&format!("Token {token}")),
        Some("Orosu/x"),
        Some(&wrong_version),
    )
    .await;

    let err = result.unwrap_err();
    assert_eq!(rejection_status(&err), Some(400));
}

#[tokio::test]
async fn script_not_found_returns_a_failure_envelope_not_a_hang() {
    let port = 19107;
    let key_dir = tempfile::tempdir().unwrap();
    let keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &keygen);
    spawn_server(single_client_config(port, &public_key_path, ""), port).await;

    let client_key = ClientKey::from_string(keygen.private_key_base64()).unwrap();
    let mut ws = connect_authenticated(port, "test-client", &client_key.key).await;

    send_launch(&mut ws, "does-not-exist", vec![], None).await;
    let response = recv_launch_response(&mut ws).await;
    match response {
        TaskLaunchStatusResponseEnvelope::Failure { error } => {
            assert!(matches!(
                error,
                orosu::api::ServerErrorResponse::ScriptNotFound
            ));
        }
        other => panic!("expected Failure(ScriptNotFound), got {other:?}"),
    }
}

fn config_with_attachment_script(port: u16, public_key_path: &std::path::Path) -> Configuration {
    build_config(&format!(
        r#"
listen:
  tcp: "127.0.0.1:{port}"
clients:
  - name: "test-client"
    secret_file: "{}"
    scripts:
      - name: "cat-file"
        command: ["bash", "-c", "cat $ATTACHMENTS_DIR/test.txt"]
"#,
        public_key_path.display()
    ))
}

#[tokio::test]
async fn file_upload_happy_path_extracts_and_exposes_the_attachment() {
    let port = 19108;
    let key_dir = tempfile::tempdir().unwrap();
    let keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &keygen);
    spawn_server(config_with_attachment_script(port, &public_key_path), port).await;

    let client_key = ClientKey::from_string(keygen.private_key_base64()).unwrap();
    let mut ws = connect_authenticated(port, "test-client", &client_key.key).await;

    let zip_bytes = build_zip(&[("test.txt", b"hello attachment")]);
    let hash = md5::compute(&zip_bytes).0.to_vec();
    let size = zip_bytes.len();

    send_launch(
        &mut ws,
        "cat-file",
        vec![],
        Some(FileAttachment { hash, size }),
    )
    .await;

    // Single chunk is enough for this small a payload — respond to
    // whatever offset the server actually asks for rather than assuming 0,
    // so this stays correct even if chunking behavior changes.
    loop {
        match recv_launch_response(&mut ws).await {
            TaskLaunchStatusResponseEnvelope::Success {
                body: TaskLaunchStatus::AwaitingFiles { offset },
            } => {
                assert_eq!(offset, 0, "expected a single chunk for this small payload");
                let chunk = FileChunkRequestEnvelope {
                    body: FileChunk {
                        offset,
                        data: zip_bytes.clone(),
                    },
                };
                ws.send(Message::Binary(chunk.into())).await.unwrap();
            }
            TaskLaunchStatusResponseEnvelope::Success {
                body: TaskLaunchStatus::Launched { .. },
            } => break,
            other => panic!("expected AwaitingFiles or Launched, got {other:?}"),
        }
    }

    loop {
        match recv_task_event(&mut ws).await {
            Some(TaskEventResponseEnvelope::Success {
                body: ServerTaskNotification::Output(event),
            }) => {
                assert_eq!(
                    event.value,
                    orosu::tasks::TaskOutput::Stdout("hello attachment".to_string())
                );
            }
            Some(TaskEventResponseEnvelope::Success {
                body: ServerTaskNotification::ExitCode(code),
            }) => {
                assert_eq!(code, 0);
                break;
            }
            Some(other) => panic!("unexpected event: {other:?}"),
            None => panic!("connection closed before an exit code arrived"),
        }
    }
}

#[tokio::test]
async fn file_hash_mismatch_is_reported_as_a_failure() {
    let port = 19109;
    let key_dir = tempfile::tempdir().unwrap();
    let keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &keygen);
    spawn_server(config_with_attachment_script(port, &public_key_path), port).await;

    let client_key = ClientKey::from_string(keygen.private_key_base64()).unwrap();
    let mut ws = connect_authenticated(port, "test-client", &client_key.key).await;

    let zip_bytes = build_zip(&[("test.txt", b"hello attachment")]);
    let size = zip_bytes.len();
    let wrong_hash = vec![0u8; 16]; // real MD5 of this content is never all-zero

    send_launch(
        &mut ws,
        "cat-file",
        vec![],
        Some(FileAttachment {
            hash: wrong_hash,
            size,
        }),
    )
    .await;

    loop {
        match recv_launch_response(&mut ws).await {
            TaskLaunchStatusResponseEnvelope::Success {
                body: TaskLaunchStatus::AwaitingFiles { offset },
            } => {
                let chunk = FileChunkRequestEnvelope {
                    body: FileChunk {
                        offset,
                        data: zip_bytes.clone(),
                    },
                };
                ws.send(Message::Binary(chunk.into())).await.unwrap();
            }
            TaskLaunchStatusResponseEnvelope::Failure { error } => {
                assert!(matches!(
                    error,
                    orosu::api::ServerErrorResponse::CannotLaunchScript
                ));
                return;
            }
            other => panic!("expected AwaitingFiles or Failure, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn a_file_chunk_at_the_wrong_offset_disconnects_rather_than_hanging() {
    let port = 19110;
    let key_dir = tempfile::tempdir().unwrap();
    let keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &keygen);
    spawn_server(config_with_attachment_script(port, &public_key_path), port).await;

    let client_key = ClientKey::from_string(keygen.private_key_base64()).unwrap();
    let mut ws = connect_authenticated(port, "test-client", &client_key.key).await;

    let zip_bytes = build_zip(&[("test.txt", b"hello attachment")]);
    let hash = md5::compute(&zip_bytes).0.to_vec();
    let size = zip_bytes.len();

    send_launch(
        &mut ws,
        "cat-file",
        vec![],
        Some(FileAttachment { hash, size }),
    )
    .await;
    match recv_launch_response(&mut ws).await {
        TaskLaunchStatusResponseEnvelope::Success {
            body: TaskLaunchStatus::AwaitingFiles { .. },
        } => {}
        other => panic!("expected AwaitingFiles, got {other:?}"),
    }

    // Deliberately wrong offset — documents current server behavior
    // (server/handler/tasks.rs): it just returns without sending any
    // failure envelope or close frame, dropping the TCP connection
    // instead. A client-side read timeout is what actually catches this in
    // practice (see client/src/wsClient.js's FRAME_TIMEOUT_MS on the JS
    // side); this test asserts the connection ends, not that a clean error
    // envelope arrives, since the server doesn't send one here.
    let bad_chunk = FileChunkRequestEnvelope {
        body: FileChunk {
            offset: 999,
            data: zip_bytes,
        },
    };
    ws.send(Message::Binary(bad_chunk.into())).await.unwrap();

    let outcome = tokio::time::timeout(Duration::from_secs(5), ws.next()).await;
    match outcome {
        Ok(None) | Ok(Some(Err(_))) | Ok(Some(Ok(Message::Close(_)))) => {}
        Ok(Some(Ok(other))) => panic!("expected disconnection, got a message: {other:?}"),
        Err(_) => panic!("connection did not close within 5s after a bad chunk offset"),
    }
}

#[tokio::test]
async fn per_client_whitelist_rejects_a_non_matching_ip() {
    let port = 19111;
    let key_dir = tempfile::tempdir().unwrap();
    let keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &keygen);
    // Excludes 127.0.0.1, which is where every test connection comes from.
    let config = single_client_config(port, &public_key_path, "whitelisted_ips: [\"10.0.0.0/8\"]");
    spawn_server(config, port).await;

    let client_key = ClientKey::from_string(keygen.private_key_base64()).unwrap();
    let token = sign_jwt("test-client", &client_key.key, 10);
    let result = connect_raw(port, Some(&format!("Token {token}")), Some("Orosu/x")).await;

    let err = result.unwrap_err();
    assert_eq!(rejection_status(&err), Some(403));
}

#[tokio::test]
async fn per_client_whitelist_allows_a_matching_ip() {
    let port = 19112;
    let key_dir = tempfile::tempdir().unwrap();
    let keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &keygen);
    let config = single_client_config(
        port,
        &public_key_path,
        "whitelisted_ips: [\"127.0.0.1/32\"]",
    );
    spawn_server(config, port).await;

    let client_key = ClientKey::from_string(keygen.private_key_base64()).unwrap();
    // Full round trip, not just a successful handshake, confirms the
    // whitelist doesn't just avoid the 403 but leaves the rest working.
    let mut ws = connect_authenticated(port, "test-client", &client_key.key).await;
    launch_without_file(&mut ws, "hello", vec![]).await;
}

#[tokio::test]
async fn per_client_blacklist_rejects_a_matching_ip() {
    let port = 19113;
    let key_dir = tempfile::tempdir().unwrap();
    let keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &keygen);
    let config = single_client_config(
        port,
        &public_key_path,
        "blacklisted_ips: [\"127.0.0.1/32\"]",
    );
    spawn_server(config, port).await;

    let client_key = ClientKey::from_string(keygen.private_key_base64()).unwrap();
    let token = sign_jwt("test-client", &client_key.key, 10);
    let result = connect_raw(port, Some(&format!("Token {token}")), Some("Orosu/x")).await;

    let err = result.unwrap_err();
    assert_eq!(rejection_status(&err), Some(403));
}

fn config_with_global_filter(
    port: u16,
    public_key_path: &std::path::Path,
    filter_key: &str,
    cidr: &str,
) -> Configuration {
    build_config(&format!(
        r#"
listen:
  tcp: "127.0.0.1:{port}"
{filter_key}:
  - "{cidr}"
clients:
  - name: "test-client"
    secret_file: "{}"
    scripts:
      - name: "hello"
        command: ["echo", "hi"]
"#,
        public_key_path.display()
    ))
}

#[tokio::test]
async fn global_blacklist_rejects_before_auth_even_runs() {
    let port = 19114;
    let key_dir = tempfile::tempdir().unwrap();
    let keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &keygen);
    let config =
        config_with_global_filter(port, &public_key_path, "blacklisted_ips", "127.0.0.1/32");
    spawn_server(config, port).await;

    // No Authorization header at all — if this still comes back 403 (not
    // 401), that proves the blacklist middleware runs before the auth
    // extractor, matching the layer ordering in server/mod.rs::build_router
    // (middleware layers wrap outside-in in reverse declaration order).
    let result = connect_raw(port, None, Some("Orosu/x")).await;
    let err = result.unwrap_err();
    assert_eq!(rejection_status(&err), Some(403));
}

#[tokio::test]
async fn global_whitelist_rejects_a_non_matching_ip() {
    let port = 19115;
    let key_dir = tempfile::tempdir().unwrap();
    let keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &keygen);
    let config = config_with_global_filter(port, &public_key_path, "whitelisted_ips", "10.0.0.0/8");
    spawn_server(config, port).await;

    let result = connect_raw(port, None, Some("Orosu/x")).await;
    let err = result.unwrap_err();
    assert_eq!(rejection_status(&err), Some(403));
}

#[tokio::test]
async fn global_whitelist_allows_a_matching_ip_through_to_auth() {
    let port = 19116;
    let key_dir = tempfile::tempdir().unwrap();
    let keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &keygen);
    let config =
        config_with_global_filter(port, &public_key_path, "whitelisted_ips", "127.0.0.1/32");
    spawn_server(config, port).await;

    let client_key = ClientKey::from_string(keygen.private_key_base64()).unwrap();
    let mut ws = connect_authenticated(port, "test-client", &client_key.key).await;
    launch_without_file(&mut ws, "hello", vec![]).await;
}
