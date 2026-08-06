//! End-to-end tests against a real `Server` bound to a real TCP port,
//! exercised with real WebSocket clients (mirroring how the JS action
//! actually talks to it — the Rust CLI client this crate used to ship has
//! been discontinued in its favor). This is the highest-risk code in the
//! crate — auth, the WS task-launch/file-upload handshake, IP filtering —
//! so it's deliberately tested at this level rather than only unit-tested
//! in isolation.
//!
//! There's no in-crate client library to drive this handshake with — every
//! test below constructs the wire protocol manually instead, mirroring what
//! client/src/*.js does.
//!
//! `Server::serve()` doesn't expose the OS-assigned port when binding to
//! `:0`, so each test picks its own fixed, distinct port.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use orosu::api::envelopes::{
    FileChunkRequestEnvelope, TaskEventResponseEnvelope, TaskLaunchRequestEnvelope,
    TaskLaunchStatusResponseEnvelope,
};
use orosu::api::file_chunk::FileChunk;
use orosu::api::handshake::{ConnectionSecurity, SessionKeys, verify_confirmation_frame};
use orosu::api::protocol_version::{
    PROTOCOL_VERSION, PROTOCOL_VERSION_ENCRYPTED_V2, PROTOCOL_VERSION_HEADER_NAME,
};
use orosu::api::{FileAttachment, ServerTaskNotification, StartTaskRequest, TaskLaunchStatus};
use orosu::configuration::{Configuration, ListenConfiguration};
use orosu::cryptography::{ClientKey, Keygen, ServerKeygen, ServerStaticKey};
use orosu::server::Server;
use std::io::Write;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};
use x25519_dalek::{PublicKey, StaticSecret};

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

// Loads encryption_key_file the same way api/server/src/main.rs does. No
// existing test's config sets this field, so encryption_key stays None for
// every test above this point — proving, structurally rather than just by
// assertion, that a server binary upgrade changes nothing for a deployment
// that hasn't opted into encryption.
async fn spawn_server(configuration: Configuration, port: u16) {
    let encryption_key = configuration
        .encryption_key_file
        .as_ref()
        .map(|path| ServerStaticKey::from_file(path).unwrap());
    tokio::spawn(async move {
        let server = Server::new(
            configuration.listen,
            configuration.ip_whitelist,
            configuration.ip_blacklist,
            configuration.clients,
            encryption_key,
        );
        let _ = server.serve().await;
    });
    wait_for_port(port).await;
}

async fn wait_for_socket(path: &std::path::Path) {
    for _ in 0..200 {
        if tokio::net::UnixStream::connect(path).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("unix socket at {} never became reachable", path.display());
}

/// Same as `spawn_server`, but for a `listen: {socket: ...}` configuration —
/// the socket path is read back out of the configuration rather than passed
/// separately, since (unlike a TCP port) it isn't known ahead of the config
/// existing.
async fn spawn_server_unix(configuration: Configuration) {
    let ListenConfiguration::Socket(socket_path) = &configuration.listen else {
        panic!("spawn_server_unix requires a `socket` listen configuration");
    };
    let socket_path = socket_path.clone();
    let encryption_key = configuration
        .encryption_key_file
        .as_ref()
        .map(|path| ServerStaticKey::from_file(path).unwrap());
    tokio::spawn(async move {
        let server = Server::new(
            configuration.listen,
            configuration.ip_whitelist,
            configuration.ip_blacklist,
            configuration.clients,
            encryption_key,
        );
        let _ = server.serve().await;
    });
    wait_for_socket(&socket_path).await;
}

fn write_public_key(dir: &std::path::Path, keygen: &Keygen) -> std::path::PathBuf {
    let path = dir.join("public.key");
    std::fs::write(&path, keygen.public_key_base64()).unwrap();
    path
}

fn write_server_key(dir: &std::path::Path, keygen: &ServerKeygen) -> std::path::PathBuf {
    let path = dir.join("server.key");
    std::fs::write(&path, keygen.private_key_base64()).unwrap();
    path
}

/// Mirrors the real clients' JWT construction (see client/src/auth.js's JS
/// implementation), parameterized so error-path tests can hand it a wrong
/// client name or an already-expired `exp` — things a real client never
/// produces. `Claims` (cryptography.rs) has crate-private fields, so this
/// defines an equivalent local shape rather than needing access to it.
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

/// Connects with fully custom headers, so handshake-rejection paths can be
/// exercised directly. Always sends a
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

type UnixWsStream = tokio_tungstenite::WebSocketStream<tokio::net::UnixStream>;

/// The unix-socket equivalent of `connect_authenticated`. There's no host:port
/// to dial, so this connects the `UnixStream` directly and hands it to
/// `tokio_tungstenite::client_async` — the URL in the handshake request is
/// only used to build the `Host` header and is otherwise irrelevant.
async fn connect_authenticated_unix(
    socket_path: &std::path::Path,
    client_name: &str,
    seed: &[u8],
) -> UnixWsStream {
    let token = sign_jwt(client_name, seed, 10);
    let stream = tokio::net::UnixStream::connect(socket_path).await.unwrap();
    let mut request = "ws://localhost/".into_client_request().unwrap();
    let headers = request.headers_mut();
    headers.remove("user-agent");
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Token {token}")).unwrap(),
    );
    headers.insert("user-agent", HeaderValue::from_static("Orosu/test-suite"));
    headers.insert(
        HeaderName::from_static(PROTOCOL_VERSION_HEADER_NAME),
        HeaderValue::from_str(&PROTOCOL_VERSION.to_string()).unwrap(),
    );
    let (ws, _response) = tokio_tungstenite::client_async(request, stream)
        .await
        .unwrap();
    ws
}

fn rejection_status(err: &tokio_tungstenite::tungstenite::Error) -> Option<u16> {
    match err {
        tokio_tungstenite::tungstenite::Error::Http(response) => Some(response.status().as_u16()),
        _ => None,
    }
}

async fn send_launch<S: AsyncRead + AsyncWrite + Unpin>(
    ws: &mut tokio_tungstenite::WebSocketStream<S>,
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

async fn recv_launch_response<S: AsyncRead + AsyncWrite + Unpin>(
    ws: &mut tokio_tungstenite::WebSocketStream<S>,
) -> TaskLaunchStatusResponseEnvelope {
    let msg = ws.next().await.unwrap().unwrap();
    let Message::Binary(bytes) = msg else {
        panic!("expected a binary message, got {msg:?}");
    };
    bytes.into()
}

async fn recv_task_event<S: AsyncRead + AsyncWrite + Unpin>(
    ws: &mut tokio_tungstenite::WebSocketStream<S>,
) -> Option<TaskEventResponseEnvelope> {
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
async fn launch_without_file<S: AsyncRead + AsyncWrite + Unpin>(
    ws: &mut tokio_tungstenite::WebSocketStream<S>,
    script: &str,
    args: Vec<String>,
) {
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
async fn treats_a_missing_protocol_version_header_as_version_zero_and_accepts_it() {
    // A missing header isn't a malformed request — it's every client built
    // before this header existed (every currently released orosu-client and
    // JS action, and the still-live pre-rewrite orosu-ci/orosu@v0 action).
    // The server treats that as protocol version 0, which stays in
    // SUPPORTED_PROTOCOL_VERSIONS alongside the current PROTOCOL_VERSION —
    // dropping it would reject that live traffic outright. Full round trip,
    // not just a successful handshake, confirms it's genuinely accepted
    // rather than merely not rejected at connect time.
    let port = 19117;
    let key_dir = tempfile::tempdir().unwrap();
    let keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &keygen);
    spawn_server(single_client_config(port, &public_key_path, ""), port).await;

    let client_key = ClientKey::from_string(keygen.private_key_base64()).unwrap();
    let token = sign_jwt("test-client", &client_key.key, 10);
    let mut ws = connect_raw_with_protocol_version(
        port,
        Some(&format!("Token {token}")),
        Some("Orosu/x"),
        None,
    )
    .await
    .unwrap();

    launch_without_file(&mut ws, "hello", vec![]).await;
}

#[tokio::test]
async fn rejects_a_protocol_version_that_is_not_supported_by_the_server() {
    let port = 19118;
    let key_dir = tempfile::tempdir().unwrap();
    let keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &keygen);
    spawn_server(single_client_config(port, &public_key_path, ""), port).await;

    let client_key = ClientKey::from_string(keygen.private_key_base64()).unwrap();
    let token = sign_jwt("test-client", &client_key.key, 10);
    // One past the newest version this build knows about — outside
    // SUPPORTED_PROTOCOL_VERSIONS regardless of how many versions it lists.
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

/// Zip-slip: an attachment whose entry name attempts to escape the
/// extraction directory (`../evil.txt`) must be rejected as a clean
/// failure, not extracted outside the temp directory and not a panic/hang.
#[tokio::test]
async fn zip_slip_attempt_is_rejected_as_a_clean_failure() {
    let port = 19123;
    let key_dir = tempfile::tempdir().unwrap();
    let keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &keygen);
    spawn_server(config_with_attachment_script(port, &public_key_path), port).await;

    let client_key = ClientKey::from_string(keygen.private_key_base64()).unwrap();
    let mut ws = connect_authenticated(port, "test-client", &client_key.key).await;

    let zip_bytes = build_zip(&[("../evil.txt", b"pwned")]);
    let hash = md5::compute(&zip_bytes).0.to_vec();
    let size = zip_bytes.len();

    send_launch(
        &mut ws,
        "cat-file",
        vec![],
        Some(FileAttachment { hash, size }),
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

/// Zip-slip via an absolute entry path, not just relative `../` traversal —
/// `enclosed_name()` rejects both, but they're distinct code paths worth
/// covering independently (a fix that only handled `../` would miss this).
#[tokio::test]
async fn zip_entry_with_an_absolute_path_is_rejected_as_a_clean_failure() {
    let port = 19124;
    let key_dir = tempfile::tempdir().unwrap();
    let keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &keygen);
    spawn_server(config_with_attachment_script(port, &public_key_path), port).await;

    let client_key = ClientKey::from_string(keygen.private_key_base64()).unwrap();
    let mut ws = connect_authenticated(port, "test-client", &client_key.key).await;

    let zip_bytes = build_zip(&[("/etc/evil.txt", b"pwned")]);
    let hash = md5::compute(&zip_bytes).0.to_vec();
    let size = zip_bytes.len();

    send_launch(
        &mut ws,
        "cat-file",
        vec![],
        Some(FileAttachment { hash, size }),
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

/// Full-stack proof that `ClientKey::from_string`'s rkyv fallback
/// (cryptography.rs) isn't just a parsing detail: a private key written in
/// the pre-JSON-migration binary format still authenticates against a real
/// server and runs a script end to end, exactly like a JSON-format key does
/// in `happy_path_launches_streams_output_and_exit_code`.
#[tokio::test]
async fn a_client_key_written_in_the_old_rkyv_format_still_authenticates_end_to_end() {
    let port = 19119;
    let key_dir = tempfile::tempdir().unwrap();
    let keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &keygen);
    spawn_server(single_client_config(port, &public_key_path, ""), port).await;

    let old_format_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(keygen.private_key()).unwrap();
    let old_format_key_base64 = STANDARD.encode(old_format_bytes);

    let client_key = ClientKey::from_string(old_format_key_base64).unwrap();
    let mut ws = connect_authenticated(port, "test-client", &client_key.key).await;

    launch_without_file(&mut ws, "hello", vec![]).await;

    loop {
        match recv_task_event(&mut ws).await {
            Some(TaskEventResponseEnvelope::Success {
                body: ServerTaskNotification::ExitCode(code),
            }) => {
                assert_eq!(code, 0);
                break;
            }
            Some(TaskEventResponseEnvelope::Success {
                body: ServerTaskNotification::Output(_),
            }) => {}
            Some(other) => panic!("unexpected event: {other:?}"),
            None => panic!("connection closed before an exit code arrived"),
        }
    }
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

fn config_with_encryption(
    port: u16,
    public_key_path: &std::path::Path,
    server_key_path: &std::path::Path,
) -> Configuration {
    build_config(&format!(
        r#"
listen:
  tcp: "127.0.0.1:{port}"
encryption_key_file: "{}"
clients:
  - name: "test-client"
    secret_file: "{}"
    scripts:
      - name: "hello"
        command: ["echo", "hi"]
"#,
        server_key_path.display(),
        public_key_path.display()
    ))
}

fn server_public_key(keygen: &ServerKeygen) -> PublicKey {
    let bytes = STANDARD.decode(keygen.public_key_base64()).unwrap();
    let bytes: [u8; 32] = bytes.as_slice().try_into().unwrap();
    bytes.into()
}

/// Connects speaking protocol version 2 and drives the real client-side
/// handshake through the actual production `api::handshake` module, rather
/// than a second hand-rolled implementation — unlike `sign_jwt` above
/// (which deliberately duplicates JWT construction), exercising the real
/// shared code here is more valuable than reimplementing it; independent
/// reimplementation testing for the handshake belongs on the JS side (see
/// client/test/handshake.test.js).
async fn connect_encrypted(
    port: u16,
    client_name: &str,
    seed: &[u8],
    server_keygen: &ServerKeygen,
) -> (WsStream, ConnectionSecurity) {
    let token = sign_jwt(client_name, seed, 10);
    let mut ws = connect_raw_with_protocol_version(
        port,
        Some(&format!("Token {token}")),
        Some("Orosu/test-suite"),
        Some(&PROTOCOL_VERSION_ENCRYPTED_V2.to_string()),
    )
    .await
    .unwrap();

    let client_ephemeral_secret = StaticSecret::random();
    let client_ephemeral_public = PublicKey::from(&client_ephemeral_secret);
    ws.send(Message::Binary(
        client_ephemeral_public.to_bytes().to_vec().into(),
    ))
    .await
    .unwrap();

    let shared = client_ephemeral_secret.diffie_hellman(&server_public_key(server_keygen));
    let mut session_keys = SessionKeys::derive_for_client(&shared);

    let confirm_msg = ws.next().await.unwrap().unwrap();
    let Message::Binary(confirm_frame) = confirm_msg else {
        panic!("expected a binary confirmation frame, got {confirm_msg:?}");
    };
    verify_confirmation_frame(&mut session_keys, &confirm_frame).unwrap();

    (ws, ConnectionSecurity::Encrypted(session_keys))
}

async fn send_launch_secured(
    ws: &mut WsStream,
    security: &mut ConnectionSecurity,
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
    let plaintext: Bytes = envelope.into();
    let sealed = security.seal(&plaintext).unwrap();
    ws.send(Message::Binary(sealed.into())).await.unwrap();
}

async fn recv_launch_response_secured(
    ws: &mut WsStream,
    security: &mut ConnectionSecurity,
) -> TaskLaunchStatusResponseEnvelope {
    let msg = ws.next().await.unwrap().unwrap();
    let Message::Binary(bytes) = msg else {
        panic!("expected a binary message, got {msg:?}");
    };
    let opened = security.open(&bytes).unwrap();
    Bytes::from(opened).into()
}

async fn recv_task_event_secured(
    ws: &mut WsStream,
    security: &mut ConnectionSecurity,
) -> Option<TaskEventResponseEnvelope> {
    match ws.next().await {
        Some(Ok(Message::Binary(bytes))) => {
            let opened = security.open(&bytes).unwrap();
            Some(Bytes::from(opened).into())
        }
        Some(Ok(Message::Close(_))) | None => None,
        Some(Ok(other)) => panic!("expected a binary message or close, got {other:?}"),
        Some(Err(e)) => panic!("websocket error: {e}"),
    }
}

#[tokio::test]
async fn encrypted_connection_rejects_when_server_has_no_key_configured() {
    let port = 19120;
    let key_dir = tempfile::tempdir().unwrap();
    let keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &keygen);
    // No encryption_key_file — an unmodified server config, exactly what
    // an operator has before opting in.
    spawn_server(single_client_config(port, &public_key_path, ""), port).await;

    let client_key = ClientKey::from_string(keygen.private_key_base64()).unwrap();
    let token = sign_jwt("test-client", &client_key.key, 10);
    let result = connect_raw_with_protocol_version(
        port,
        Some(&format!("Token {token}")),
        Some("Orosu/x"),
        Some(&PROTOCOL_VERSION_ENCRYPTED_V2.to_string()),
    )
    .await;

    let err = result.unwrap_err();
    assert_eq!(rejection_status(&err), Some(400));
}

#[tokio::test]
async fn encrypted_handshake_with_wrong_pinned_server_key_fails_confirmation() {
    let port = 19121;
    let key_dir = tempfile::tempdir().unwrap();
    let keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &keygen);
    let server_keygen = ServerKeygen::new();
    let server_key_path = write_server_key(key_dir.path(), &server_keygen);
    spawn_server(
        config_with_encryption(port, &public_key_path, &server_key_path),
        port,
    )
    .await;

    let client_key = ClientKey::from_string(keygen.private_key_base64()).unwrap();
    let token = sign_jwt("test-client", &client_key.key, 10);
    let mut ws = connect_raw_with_protocol_version(
        port,
        Some(&format!("Token {token}")),
        Some("Orosu/x"),
        Some(&PROTOCOL_VERSION_ENCRYPTED_V2.to_string()),
    )
    .await
    .unwrap();

    let client_ephemeral_secret = StaticSecret::random();
    let client_ephemeral_public = PublicKey::from(&client_ephemeral_secret);
    ws.send(Message::Binary(
        client_ephemeral_public.to_bytes().to_vec().into(),
    ))
    .await
    .unwrap();

    // Pins a DIFFERENT server key than the one actually configured — the
    // scenario for a stale/wrong `server_key` action input, or a real
    // man-in-the-middle at a TLS-terminating proxy answering in the real
    // server's place.
    let wrong_server_keygen = ServerKeygen::new();
    let shared = client_ephemeral_secret.diffie_hellman(&server_public_key(&wrong_server_keygen));
    let mut session_keys = SessionKeys::derive_for_client(&shared);

    let confirm_msg = ws.next().await.unwrap().unwrap();
    let Message::Binary(confirm_frame) = confirm_msg else {
        panic!("expected a binary confirmation frame, got {confirm_msg:?}");
    };
    assert!(verify_confirmation_frame(&mut session_keys, &confirm_frame).is_err());
}

/// The full-stack proof: handshake, launch, and streamed output/exit code
/// all correctly round-trip through the encryption layer — the encrypted
/// counterpart to `happy_path_launches_streams_output_and_exit_code`.
#[tokio::test]
async fn encrypted_happy_path_launches_streams_output_and_exit_code() {
    let port = 19122;
    let key_dir = tempfile::tempdir().unwrap();
    let keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &keygen);
    let server_keygen = ServerKeygen::new();
    let server_key_path = write_server_key(key_dir.path(), &server_keygen);
    spawn_server(
        config_with_encryption(port, &public_key_path, &server_key_path),
        port,
    )
    .await;

    let client_key = ClientKey::from_string(keygen.private_key_base64()).unwrap();
    let (mut ws, mut security) =
        connect_encrypted(port, "test-client", &client_key.key, &server_keygen).await;

    send_launch_secured(&mut ws, &mut security, "hello", vec![], None).await;
    match recv_launch_response_secured(&mut ws, &mut security).await {
        TaskLaunchStatusResponseEnvelope::Success {
            body: TaskLaunchStatus::Launched { .. },
        } => {}
        other => panic!("expected Launched, got {other:?}"),
    }

    let mut saw_output = false;
    loop {
        match recv_task_event_secured(&mut ws, &mut security).await {
            Some(TaskEventResponseEnvelope::Success {
                body: ServerTaskNotification::Output(event),
            }) => {
                assert_eq!(
                    event.value,
                    orosu::tasks::TaskOutput::Stdout("hi".to_string())
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

// `listen: {socket: ...}` is a second, independent listener implementation
// (server/mod.rs binds a UnixListener and hands the router to axum::serve
// directly, rather than going through into_make_service_with_connect_info
// like the TCP path does) — it needs its own coverage rather than relying on
// the TCP tests above to stand in for it.

#[tokio::test]
async fn unix_socket_happy_path_launches_streams_output_and_exit_code() {
    let socket_dir = tempfile::tempdir().unwrap();
    let socket_path = socket_dir.path().join("orosu.sock");
    let key_dir = tempfile::tempdir().unwrap();
    let keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &keygen);

    let config = build_config(&format!(
        r#"
listen:
  socket: "{}"
clients:
  - name: "test-client"
    secret_file: "{}"
    scripts:
      - name: "hello"
        command: ["echo", "hello from unix socket integration test"]
"#,
        socket_path.display(),
        public_key_path.display()
    ));
    spawn_server_unix(config).await;

    let client_key = ClientKey::from_string(keygen.private_key_base64()).unwrap();
    let mut ws = connect_authenticated_unix(&socket_path, "test-client", &client_key.key).await;

    launch_without_file(&mut ws, "hello", vec![]).await;

    let mut saw_output = false;
    loop {
        match recv_task_event(&mut ws).await {
            Some(TaskEventResponseEnvelope::Success {
                body: ServerTaskNotification::Output(event),
            }) => {
                assert_eq!(
                    event.value,
                    orosu::tasks::TaskOutput::Stdout(
                        "hello from unix socket integration test".to_string()
                    )
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

// Unix domain socket peers have no IP address at all, so an IP allow/deny
// list can't be meaningfully applied to them — the socket file's own
// filesystem permissions are the access-control boundary instead. This
// proves that configuring one doesn't crash (or silently reject) unix
// socket connections; it should be a no-op for them.
#[tokio::test]
async fn unix_socket_connection_succeeds_even_when_a_global_whitelist_is_configured() {
    let socket_dir = tempfile::tempdir().unwrap();
    let socket_path = socket_dir.path().join("orosu.sock");
    let key_dir = tempfile::tempdir().unwrap();
    let keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &keygen);

    let config = build_config(&format!(
        r#"
listen:
  socket: "{}"
whitelisted_ips:
  - "10.0.0.0/8"
clients:
  - name: "test-client"
    secret_file: "{}"
    scripts:
      - name: "hello"
        command: ["echo", "hi"]
"#,
        socket_path.display(),
        public_key_path.display()
    ));
    spawn_server_unix(config).await;

    let client_key = ClientKey::from_string(keygen.private_key_base64()).unwrap();
    let mut ws = connect_authenticated_unix(&socket_path, "test-client", &client_key.key).await;
    launch_without_file(&mut ws, "hello", vec![]).await;
}

// A crashed (rather than cleanly-shutdown) server leaves its socket file
// behind. `UnixListener::bind` refuses to bind over any existing path, so
// without cleanup a restart would fail with "Address already in use" even
// though nothing is actually listening there anymore.
#[tokio::test]
async fn rebinding_a_unix_socket_removes_a_stale_socket_file_from_a_previous_run() {
    let socket_dir = tempfile::tempdir().unwrap();
    let socket_path = socket_dir.path().join("orosu.sock");
    std::fs::write(&socket_path, b"").unwrap();

    let config = build_config(&format!(
        r#"
listen:
  socket: "{}"
clients: []
"#,
        socket_path.display()
    ));

    // spawn_server_unix's wait_for_socket already proves the bind
    // succeeded: connecting to a stale, non-socket file fails immediately,
    // so a wedged bind would surface as this call timing out and panicking.
    spawn_server_unix(config).await;
}

// Both tests below pause the tokio clock *after* the real setup I/O
// (connecting, authenticating) has already completed, then never send the
// message the server is waiting on. On this single-threaded runtime — the
// server's spawned task and the test body share it — once both the server
// (blocked inside `timeout(...)`) and this task (blocked on `ws.next()`,
// real socket I/O) are parked with nothing left to do, tokio auto-advances
// the paused clock straight to the server's timeout deadline instead of
// really sleeping, so these assert a real 10s/30s server-side timeout fires
// without costing 10s/30s of wall-clock test time.

#[tokio::test]
async fn a_client_that_never_sends_a_launch_message_is_disconnected_after_the_timeout() {
    let port = 19125;
    let key_dir = tempfile::tempdir().unwrap();
    let keygen = Keygen::new("test-client".to_string());
    let public_key_path = write_public_key(key_dir.path(), &keygen);
    spawn_server(single_client_config(port, &public_key_path, ""), port).await;

    let client_key = ClientKey::from_string(keygen.private_key_base64()).unwrap();
    let mut ws = connect_authenticated(port, "test-client", &client_key.key).await;

    tokio::time::pause();

    // Deliberately never sends a StartTaskRequest.
    match ws.next().await {
        None | Some(Err(_)) | Some(Ok(Message::Close(_))) => {}
        Some(Ok(other)) => panic!("expected disconnection, got a message: {other:?}"),
    }
}

#[tokio::test]
async fn a_client_that_stalls_mid_upload_is_disconnected_after_the_timeout() {
    let port = 19126;
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

    tokio::time::pause();

    // Deliberately never sends the requested file chunk.
    match ws.next().await {
        None | Some(Err(_)) | Some(Ok(Message::Close(_))) => {}
        Some(Ok(other)) => panic!("expected disconnection, got a message: {other:?}"),
    }
}
