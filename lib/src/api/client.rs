use crate::api::envelopes::{
    FileChunkRequestEnvelope, TaskEventResponseEnvelope, TaskLaunchRequestEnvelope,
    TaskLaunchStatusResponseEnvelope,
};
use crate::api::file_chunk::AttachedFiles;
use crate::api::{
    FileAttachment, ProtocolVersionHeader, ServerErrorResponse, ServerTaskNotification,
    StartTaskRequest, TaskLaunchStatus, UserAgentHeader,
};
use crate::cryptography::{Claims, ClientKey};
use crate::server_address::ServerAddress;
use crate::tasks::TaskOutput;
use anyhow::Context;
use axum::http::HeaderName;
use axum::http::header::{AUTHORIZATION, USER_AGENT};
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use std::process::exit;
use std::time::SystemTime;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

pub struct ApiClient {
    ws_stream: Mutex<WebSocketStream<MaybeTlsStream<TcpStream>>>,
}

impl ApiClient {
    pub async fn connect(endpoint: ServerAddress, key: ClientKey) -> anyhow::Result<Self> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs() as usize;

        let encoding_key = {
            let secret_key = key
                .key
                .as_slice()
                .try_into()
                .context("invalid key format")?;
            let signing_key = SigningKey::from_bytes(secret_key)
                .to_pkcs8_der()
                .context("unable to encode signing key")?;
            EncodingKey::from_ed_der(signing_key.as_bytes())
        };
        let header = Header::new(Algorithm::EdDSA);

        let claims = Claims {
            sub: key.client_name,
            exp: now + 10, // 10-second expiration
        };
        let token = encode(&header, &claims, &encoding_key).context("cannot encode JWT")?;

        let user_agent_header = UserAgentHeader::default();
        let protocol_version_header = ProtocolVersionHeader::default();
        let mut request = endpoint
            .clone()
            .into_client_request()
            .context("Cannot create request")?;
        request
            .headers_mut()
            .insert(AUTHORIZATION, format!("Token {token}").parse()?);
        request
            .headers_mut()
            .insert(USER_AGENT, user_agent_header.into());
        request.headers_mut().insert(
            HeaderName::from_static(crate::api::protocol_version::PROTOCOL_VERSION_HEADER_NAME),
            protocol_version_header.into(),
        );

        let (ws_stream, _) = tokio_tungstenite::connect_async(request)
            .await
            .context("Cannot connect")?;
        let ws_stream = Mutex::new(ws_stream);
        Ok(Self { ws_stream })
    }

    pub async fn start_task(
        &self,
        arguments: Vec<String>,
        script_name: String,
        files: Vec<String>,
        chunk_size: usize,
    ) -> anyhow::Result<()> {
        let file_chunks = if !files.is_empty() {
            let archive = AttachedFiles::from_input(files);
            Some(archive.chunks(chunk_size)?)
        } else {
            None
        };

        let file = file_chunks.as_ref().map(FileAttachment::from);

        let mut ws_stream = self.ws_stream.lock().await;

        let start_task_request = TaskLaunchRequestEnvelope {
            body: StartTaskRequest {
                script_name,
                arguments,
                file,
            },
        };
        ws_stream
            .send(Message::Binary(start_task_request.into()))
            .await?;

        loop {
            let response = ws_stream.next().await;
            let Some(response) = response else {
                anyhow::bail!("Server did not respond")
            };
            let response = response?;
            let Message::Binary(response_bytes) = response else {
                anyhow::bail!("Server did not respond with a valid response, got {response}")
            };
            let response: TaskLaunchStatusResponseEnvelope = response_bytes.into();
            match response {
                TaskLaunchStatusResponseEnvelope::Success { body, .. } => match body {
                    TaskLaunchStatus::AwaitingFiles { offset, .. } => {
                        match file_chunks.as_ref() {
                            None => {
                                ws_stream.send(Message::Close(None)).await?;
                                anyhow::bail!("No files were attached to the task");
                            }
                            Some(chunks) => {
                                let chunk = chunks.chunks.iter().find(|e| e.offset == offset);
                                if let Some(chunk) = chunk {
                                    let file_chunk_envelope = FileChunkRequestEnvelope {
                                        body: chunk.clone(),
                                    };
                                    ws_stream
                                        .send(Message::Binary(file_chunk_envelope.into()))
                                        .await?;
                                } else {
                                    ws_stream.send(Message::Close(None)).await?;
                                    anyhow::bail!("Chunk not found for offset {offset}");
                                }
                            }
                        };
                    }
                    TaskLaunchStatus::Launched { .. } => break,
                },
                TaskLaunchStatusResponseEnvelope::Failure { error, .. } => error.panic(),
            }
        }

        while let Some(event) = ws_stream.next().await {
            let event = event?;
            match event {
                Message::Binary(event) => {
                    let event: TaskEventResponseEnvelope = event.into();
                    match event {
                        TaskEventResponseEnvelope::Success { body, .. } => match body {
                            ServerTaskNotification::Output(output) => {
                                output.value.print();
                            }
                            ServerTaskNotification::ExitCode(exit_code) => {
                                ws_stream.send(Message::Close(None)).await?;
                                exit(exit_code);
                            }
                        },
                        TaskEventResponseEnvelope::Failure { error, .. } => {
                            ws_stream.send(Message::Close(None)).await?;
                            error.panic();
                        }
                    }
                }
                Message::Close(cause) => {
                    tracing::info!("WebSocket closed: {cause:?}");
                    break;
                }
                _ => {
                    panic!("Unexpected message: {event:?}");
                }
            }
        }

        Ok(())
    }
}

impl TaskOutput {
    fn print(&self) {
        match self {
            TaskOutput::Stdout(line) => println!("{line}"),
            TaskOutput::Stderr(line) => eprintln!("{line}"),
        }
    }
}

impl ServerErrorResponse {
    fn panic(&self) {
        match self {
            ServerErrorResponse::CannotLaunchScript => panic!("Cannot launch script"),
            ServerErrorResponse::ScriptNotFound => panic!("Script not found"),
            ServerErrorResponse::Unknown => panic!("Unknown error"),
        }
    }
}
