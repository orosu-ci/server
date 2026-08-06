use crate::api::envelopes::{
    RequestEnvelope, TaskEventResponseEnvelope, TaskLaunchStatusResponseEnvelope,
};
use crate::api::file_chunk::FileChunk;
use crate::api::handshake::ConnectionSecurity;
use crate::api::{ServerErrorResponse, ServerTaskNotification, StartTaskRequest, TaskLaunchStatus};
use crate::client::Client;
use crate::server::handler::TasksHandler;
use crate::server::handshake::establish_security;
use crate::server::{AuthContext, ServerState};
use crate::tasks::TaskLaunchResult;
use crate::tasks::task::Task;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{ConnectInfo, FromRequestParts, Request, State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum_client_ip::ClientIp;
use futures_util::{SinkExt, StreamExt};
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tempfile::{NamedTempFile, TempDir};
use tokio::time::timeout;
use zip::ZipArchive;

/// Independent of `establish_security`'s own 10s handshake timeout — bounds
/// how long a connection can sit idle after the handshake (if any)
/// completes without ever sending the StartTaskRequest.
const LAUNCH_MESSAGE_TIMEOUT: Duration = Duration::from_secs(10);

/// Matches the client's own per-frame read timeout (30s, see
/// client/src/wsClient.js's FRAME_TIMEOUT_MS) — a well-behaved client sends
/// each file chunk well within that window, so waiting the same amount of
/// time here bounds how long a stalled or malicious upload can tie up this
/// connection, its temp file, and its tokio task.
const FILE_CHUNK_TIMEOUT: Duration = Duration::from_secs(30);

/// The only place outgoing envelope bytes get sealed. Failure is only
/// reachable if this connection's per-direction nonce counter has been
/// exhausted (u64::MAX messages on one connection, not reachable in
/// practice) — rather than ever falling back to sending the envelope
/// unsealed, this logs and returns an empty frame, which fails to decrypt
/// on the client's side exactly like any other transport error would.
fn seal_or_log(security: &mut ConnectionSecurity, envelope: impl Into<bytes::Bytes>) -> Vec<u8> {
    match security.seal(&envelope.into()) {
        Ok(sealed) => sealed,
        Err(e) => {
            tracing::error!("Failed to seal outgoing message: {e}");
            Vec::new()
        }
    }
}

impl TasksHandler {
    pub async fn attach(
        State(state): State<Arc<ServerState>>,
        auth_context: AuthContext,
        ws: WebSocketUpgrade,
        request: Request,
    ) -> impl IntoResponse {
        let (client, protocol_version) = match auth_context {
            AuthContext::Worker(worker_auth_context) => (
                worker_auth_context.client,
                worker_auth_context.protocol_version,
            ),
        };

        let (mut parts, _) = request.into_parts();

        // Unix domain socket peers have no IP address at all —
        // `ConnectInfo<SocketAddr>` is only ever inserted for TCP
        // connections (see `Server::serve`). When neither it nor a
        // forwarded-for header is present, there's no IP to filter on, so
        // per-client allow/deny lists are skipped rather than treated as a
        // hard extraction failure.
        let ip = match ClientIp::from_request_parts(&mut parts, &()).await {
            Ok(ip) => Some(ip.0),
            Err(_) => parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(addr)| addr.ip()),
        };

        if let Some(ip) = ip {
            if let Some(whitelist) = &client.whitelisted_ips
                && !whitelist.iter().any(|cidr| cidr.contains(&ip))
            {
                tracing::warn!("Client {} is not whitelisted for {}", ip, client.name);
                return StatusCode::FORBIDDEN.into_response();
            };

            if let Some(blacklist) = &client.blacklisted_ips
                && blacklist.iter().any(|cidr| cidr.contains(&ip))
            {
                tracing::warn!("Client {} is blacklisted for {}", ip, client.name);
                return StatusCode::FORBIDDEN.into_response();
            }
        }

        ws.on_upgrade(move |socket| handle_task_run_output(socket, client, protocol_version, state))
    }
}

async fn handle_task_run_output(
    mut socket: WebSocket,
    client: Client,
    protocol_version: u32,
    state: Arc<ServerState>,
) {
    let mut security = match establish_security(
        &mut socket,
        protocol_version,
        state.encryption_key.as_ref(),
    )
    .await
    {
        Ok(security) => security,
        Err(e) => {
            tracing::error!("Encryption handshake failed: {e}");
            _ = socket.send(Message::Close(None)).await;
            return;
        }
    };

    let task_message_result = match timeout(LAUNCH_MESSAGE_TIMEOUT, socket.recv()).await {
        Ok(Some(result)) => result,
        Ok(None) => {
            tracing::info!("Client disconnected");
            _ = socket.send(Message::Close(None)).await;
            return;
        }
        Err(_) => {
            tracing::warn!("Client did not send a launch message in time");
            _ = socket.send(Message::Close(None)).await;
            return;
        }
    };
    let Ok(task_message) = task_message_result else {
        tracing::error!("Cannot receive task message");
        _ = socket.send(Message::Close(None)).await;
        return;
    };

    let Message::Binary(start_task_message) = task_message else {
        tracing::error!("Cannot deserialize task message");
        _ = socket.send(Message::Close(None)).await;
        return;
    };

    let Ok(start_task_message) = security.open(&start_task_message) else {
        tracing::error!("Cannot decrypt task message");
        _ = socket.send(Message::Close(None)).await;
        return;
    };

    let Ok(start_task_message_payload) =
        serde_json::from_slice::<RequestEnvelope<StartTaskRequest>>(&start_task_message)
    else {
        tracing::error!("Cannot deserialize task message from bytes");
        _ = socket.send(Message::Close(None)).await;
        return;
    };

    tracing::info!("Received task message: {:?}", start_task_message_payload);

    let (mut sender, mut receiver) = socket.split();

    let arguments = start_task_message_payload.body.arguments;
    let attachment = start_task_message_payload.body.file;
    let script_name = start_task_message_payload.body.script_name;

    let script = client.scripts.iter().find(|e| e.name == script_name);

    let Some(script) = script else {
        tracing::error!("Script {} not found", script_name);
        let error_message = TaskLaunchStatusResponseEnvelope::Failure {
            error: ServerErrorResponse::ScriptNotFound,
        };
        let sealed = seal_or_log(&mut security, error_message);
        _ = sender.send(Message::Binary(sealed.into())).await;
        _ = sender.send(Message::Close(None)).await;
        return;
    };

    let attachment = match attachment {
        None => None,
        Some(attachment) => {
            let mut output = NamedTempFile::with_suffix(".zip").unwrap();
            let mut offset = 0;
            let size = attachment.size;
            let hash = attachment.hash;
            let mut hasher = md5::Context::new();
            while offset < size {
                let chunk_message = TaskLaunchStatusResponseEnvelope::Success {
                    body: TaskLaunchStatus::AwaitingFiles { offset },
                };
                let sealed = seal_or_log(&mut security, chunk_message);
                _ = sender.send(Message::Binary(sealed.into())).await;
                let response = match timeout(FILE_CHUNK_TIMEOUT, receiver.next()).await {
                    Ok(Some(response)) => response,
                    Ok(None) => {
                        tracing::error!("Client disconnected during file transfer");
                        _ = sender.send(Message::Close(None)).await;
                        return;
                    }
                    Err(_) => {
                        tracing::warn!("Client did not send the next file chunk in time");
                        _ = sender.send(Message::Close(None)).await;
                        return;
                    }
                };
                let Ok(response) = response else {
                    tracing::error!("Cannot deserialize file chunk message");
                    _ = sender.send(Message::Close(None)).await;
                    return;
                };
                let Message::Binary(chunk) = response else {
                    tracing::error!("Cannot deserialize file chunk message");
                    _ = sender.send(Message::Close(None)).await;
                    return;
                };
                let Ok(chunk) = security.open(&chunk) else {
                    tracing::error!("Cannot decrypt file chunk message");
                    _ = sender.send(Message::Close(None)).await;
                    return;
                };
                let Ok(chunk) = serde_json::from_slice::<RequestEnvelope<FileChunk>>(&chunk) else {
                    tracing::error!("Cannot deserialize file chunk message from bytes");
                    _ = sender.send(Message::Close(None)).await;
                    return;
                };
                let body = chunk.body;
                let chunk_offset = body.offset;
                if chunk_offset != offset {
                    tracing::error!("Unexpected chunk offset {chunk_offset}, expected {offset}");
                    return;
                }
                output.write_all(&body.data).unwrap();
                hasher.consume(&body.data);
                offset += body.data.len();
                tracing::debug!("Received attachment chunk with offset {chunk_offset}");
            }
            output.seek(SeekFrom::Start(0)).unwrap();
            tracing::debug!(
                "Finished attached file, saved into {}",
                output.path().display()
            );

            let computed_hash = hasher.finalize().0.to_vec();
            if computed_hash != hash {
                tracing::error!("File hash mismatch");
                let error_message = TaskLaunchStatusResponseEnvelope::Failure {
                    error: ServerErrorResponse::CannotLaunchScript,
                };
                let sealed = seal_or_log(&mut security, error_message);
                _ = sender.send(Message::Binary(sealed.into())).await;
                _ = sender.send(Message::Close(None)).await;
                return;
            }
            tracing::debug!("File hash validated successfully");

            Some(output)
        }
    };

    let directory = match attachment {
        None => None,
        Some(mut file) => {
            let directory = TempDir::new().unwrap();
            tracing::debug!(
                "Created temporary directory for attached files: {}",
                directory.path().display()
            );

            let mut archive = ZipArchive::new(&mut file).unwrap();
            for i in 0..archive.len() {
                let mut entry = archive.by_index(i).unwrap();

                // entry.name() is the raw, attacker-controlled name from the
                // zip's central directory — joining it onto directory.path()
                // directly would let a `../` or absolute entry escape the
                // extraction directory entirely (zip-slip). enclosed_name()
                // validates the name can't contain NULL bytes, can't be
                // absolute, and can't resolve outside the archive root
                // before it's ever joined onto a real path.
                let Some(relative_path) = entry.enclosed_name() else {
                    tracing::error!(
                        "Attachment contains an unsafe zip entry name: {:?}",
                        entry.name()
                    );
                    let error_message = TaskLaunchStatusResponseEnvelope::Failure {
                        error: ServerErrorResponse::CannotLaunchScript,
                    };
                    let sealed = seal_or_log(&mut security, error_message);
                    _ = sender.send(Message::Binary(sealed.into())).await;
                    _ = sender.send(Message::Close(None)).await;
                    return;
                };
                let output_path = directory.path().join(relative_path);

                if entry.is_dir() {
                    std::fs::create_dir_all(&output_path).unwrap();
                } else {
                    if let Some(parent) = output_path.parent() {
                        std::fs::create_dir_all(parent).unwrap();
                    }
                    let mut outfile = File::create(&output_path).unwrap();
                    std::io::copy(&mut entry, &mut outfile).unwrap();
                }
                tracing::debug!("Extracted: {}", output_path.display());
            }
            tracing::debug!(
                "Successfully extracted archive to {}",
                directory.path().display()
            );

            Some(directory)
        }
    };

    let task = Task::create(script.clone());

    let TaskLaunchResult {
        created_on,
        handler,
    } = match task.run(arguments, directory).await {
        Ok(task) => task,
        Err(e) => {
            tracing::error!("Unable to launch script {}: {:?}", script_name, e);
            let error_message = TaskLaunchStatusResponseEnvelope::Failure {
                error: ServerErrorResponse::CannotLaunchScript,
            };
            let sealed = seal_or_log(&mut security, error_message);
            _ = sender.send(Message::Binary(sealed.into())).await;
            _ = sender.send(Message::Close(None)).await;
            return;
        }
    };

    let created_message = TaskLaunchStatusResponseEnvelope::Success {
        body: TaskLaunchStatus::Launched {
            started_on: created_on,
        },
    };
    let sealed = seal_or_log(&mut security, created_message);
    _ = sender.send(Message::Binary(sealed.into())).await;

    tracing::info!("Starting task for script {}", script_name);

    let mut rx = task.output_rx;

    let mut handler_fuse = handler;
    let exit_code = loop {
        tokio::select! {
            maybe_event = rx.recv() => {
                match maybe_event {
                    Some(event) => {
                        tracing::info!("Task event: {:?}", event);
                        let message = TaskEventResponseEnvelope::Success {
                            body: ServerTaskNotification::Output(event),
                        };
                        let sealed = seal_or_log(&mut security, message);
                        if let Err(e) = sender.send(Message::Binary(sealed.into())).await {
                            tracing::error!("Cannot send real-time event: {:?}", e);
                            break None;
                        };
                    }
                    None => {
                        tracing::warn!("Receiver was closed");
                    }
                }
            }
            res = &mut handler_fuse => break Some(res.unwrap()),
        }
    };
    let Some(exit_code) = exit_code else {
        tracing::info!("Script {} was not awaited to be finished", script_name);
        return;
    };
    tracing::info!(
        "Script {} has finished with {} exit code",
        script_name,
        exit_code
    );
    let message = TaskEventResponseEnvelope::Success {
        body: ServerTaskNotification::ExitCode(exit_code),
    };
    let sealed = seal_or_log(&mut security, message);
    if let Err(e) = sender.send(Message::Binary(sealed.into())).await {
        tracing::error!("Cannot send exit-code event: {:?}", e);
    };

    if let Err(e) = sender.send(Message::Close(None)).await {
        tracing::error!("Cannot send close message: {:?}", e);
    };

    tracing::debug!("Send close message");

    let wait_for_close = async {
        while let Some(msg) = receiver.next().await {
            match msg {
                Ok(Message::Close(cause)) => {
                    tracing::info!("Client disconnected: {:?}", cause);
                    return;
                }
                Ok(msg) => {
                    tracing::debug!("Received message: {:?}", msg);
                }
                Err(e) => {
                    tracing::error!("Cannot receive message: {:?}", e);
                    return;
                }
            }
        }

        tracing::debug!("Client disconnected");
    };

    if timeout(Duration::from_secs(3), wait_for_close)
        .await
        .is_err()
    {
        tracing::warn!("Client did not close connection in time");
    }
}
