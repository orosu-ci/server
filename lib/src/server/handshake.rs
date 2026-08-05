use crate::api::handshake::{
    CLIENT_HELLO_LEN, ConnectionSecurity, SessionKeys, build_confirmation_frame,
};
use crate::api::protocol_version::PROTOCOL_VERSION_ENCRYPTED_V2;
use crate::cryptography::ServerStaticKey;
use axum::extract::ws::{Message, WebSocket};
use std::time::Duration;
use tokio::time::timeout;

/// Independent of the client's own read timeout (30s, see
/// client/src/wsClient.js's FRAME_TIMEOUT_MS) — bounds how long a
/// half-completed handshake can tie up a connection before the server gives
/// up on it.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Establishes this connection's `ConnectionSecurity`. For protocol
/// versions 0/1, this is a no-op (`Plaintext`) — the connection behaves
/// exactly as it always has. For version 2, it drives the ClientHello /
/// ServerConfirm exchange, deriving session keys from the server's static
/// key and the client's fresh ephemeral key.
///
/// `server_key` being `None` while `protocol_version` is
/// `PROTOCOL_VERSION_ENCRYPTED_V2` is a contract violation by the caller —
/// `auth_scope.rs` only ever accepts that version when
/// `state.encryption_key` is `Some`, via `supported_protocol_versions`.
pub async fn establish_security(
    socket: &mut WebSocket,
    protocol_version: u32,
    server_key: Option<&ServerStaticKey>,
) -> anyhow::Result<ConnectionSecurity> {
    if protocol_version != PROTOCOL_VERSION_ENCRYPTED_V2 {
        return Ok(ConnectionSecurity::Plaintext);
    }
    let server_key = server_key.expect(
        "invariant violated: protocol version 2 was accepted without an encryption key \
         configured — this should have been rejected in auth_scope.rs's \
         supported_protocol_versions check",
    );

    let hello = timeout(HANDSHAKE_TIMEOUT, socket.recv())
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for ClientHello"))?
        .ok_or_else(|| anyhow::anyhow!("client disconnected before sending ClientHello"))?
        .map_err(|e| anyhow::anyhow!("failed to receive ClientHello: {e}"))?;
    let Message::Binary(hello) = hello else {
        return Err(anyhow::anyhow!("expected a binary ClientHello frame"));
    };
    if hello.len() != CLIENT_HELLO_LEN {
        return Err(anyhow::anyhow!(
            "ClientHello has unexpected length {}",
            hello.len()
        ));
    }
    let client_ephemeral_public: [u8; CLIENT_HELLO_LEN] = hello.as_ref().try_into().unwrap();
    let client_ephemeral_public = x25519_dalek::PublicKey::from(client_ephemeral_public);

    let shared_secret = server_key
        .as_static_secret()
        .diffie_hellman(&client_ephemeral_public);
    let mut session_keys = SessionKeys::derive_for_server(&shared_secret);

    let confirmation_frame = build_confirmation_frame(&mut session_keys)?;
    timeout(
        HANDSHAKE_TIMEOUT,
        socket.send(Message::Binary(confirmation_frame.to_vec().into())),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timed out sending ServerConfirm"))?
    .map_err(|e| anyhow::anyhow!("failed to send ServerConfirm: {e}"))?;

    Ok(ConnectionSecurity::Encrypted(session_keys))
}
