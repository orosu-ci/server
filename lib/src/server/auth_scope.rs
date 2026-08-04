use crate::api::protocol_version::{PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER_NAME};
use crate::api::{ProtocolVersionHeader, UserAgentHeader};
use crate::cryptography::Claims;
use crate::server::{AuthContext, AuthScope, ServerState, WorkerAuthContext};
use axum::Extension;
use axum::extract::FromRequestParts;
use axum::http::HeaderName;
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::VerifyingKey;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use std::sync::Arc;
use std::time::SystemTime;
use tokio_tungstenite::tungstenite::http::header::USER_AGENT;

impl AuthScope {
    pub const fn into_extension(self) -> Extension<Self> {
        Extension(self)
    }
}

impl FromRequestParts<Arc<ServerState>> for AuthContext {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<ServerState>,
    ) -> Result<Self, Self::Rejection> {
        let scope = parts
            .extensions
            .get::<AuthScope>()
            .cloned()
            .ok_or(StatusCode::UNAUTHORIZED)?;

        let Some(user_agent_header) = parts.headers.get(USER_AGENT) else {
            tracing::error!("User agent header is missing");
            return Err(StatusCode::UNAUTHORIZED);
        };

        let user_agent_header: UserAgentHeader = match user_agent_header.try_into() {
            Ok(value) => value,
            Err(e) => {
                tracing::error!("Unexpected user agent header format: {e}");
                return Err(StatusCode::UNAUTHORIZED);
            }
        };

        // Checked separately from auth on purpose: a version mismatch and a
        // bad credential are different problems needing different fixes
        // (upgrade software vs. rotate a key), so this gets its own status
        // code (400) rather than folding into the 401s below.
        let Some(protocol_version_header) = parts
            .headers
            .get(HeaderName::from_static(PROTOCOL_VERSION_HEADER_NAME))
        else {
            tracing::error!("Protocol version header is missing");
            return Err(StatusCode::BAD_REQUEST);
        };

        let protocol_version_header: ProtocolVersionHeader =
            match protocol_version_header.try_into() {
                Ok(value) => value,
                Err(e) => {
                    tracing::error!("Unexpected protocol version header format: {e}");
                    return Err(StatusCode::BAD_REQUEST);
                }
            };

        if protocol_version_header.version != PROTOCOL_VERSION {
            tracing::error!(
                "Client protocol version {} does not match server protocol version {}",
                protocol_version_header.version,
                PROTOCOL_VERSION
            );
            return Err(StatusCode::BAD_REQUEST);
        }

        match scope {
            AuthScope::Worker => {
                let Some(auth_header) = &parts.headers.get(AUTHORIZATION) else {
                    tracing::error!("Authorization header is missing");
                    return Err(StatusCode::UNAUTHORIZED);
                };
                let auth_header_value =
                    auth_header.to_str().map_err(|_| StatusCode::UNAUTHORIZED)?;
                let parts = auth_header_value
                    .split_once(' ')
                    .ok_or(StatusCode::UNAUTHORIZED)?;
                if parts.0 != "Token" {
                    tracing::error!("Invalid authorization header format");
                    return Err(StatusCode::UNAUTHORIZED);
                }
                let token = parts.1;

                let token_data = jsonwebtoken::dangerous::insecure_decode::<Claims>(token)
                    .map_err(|e| {
                        tracing::error!("Invalid JWT token: {e}");
                        StatusCode::UNAUTHORIZED
                    })?;

                let exp = token_data.claims.exp;

                let now = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_err(|e| {
                        tracing::error!("Failed to get current time: {e}");
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?
                    .as_secs() as usize;

                if exp < now {
                    tracing::error!("Token expired");
                    return Err(StatusCode::UNAUTHORIZED);
                }

                let client_name = token_data.claims.sub;

                let Some(client) = state.clients.iter().find(|e| e.name == client_name) else {
                    tracing::error!("Client with provided secret not found");
                    return Err(StatusCode::UNAUTHORIZED);
                };

                let secret_file = client.secret_file.clone();
                let public_key = {
                    let file = secret_file;
                    let key = std::fs::read_to_string(file).map_err(|e| {
                        tracing::error!("Failed to read public key file: {e}");
                        StatusCode::UNAUTHORIZED
                    })?;
                    let Ok(bytes) = STANDARD.decode(key.trim()) else {
                        tracing::error!("Invalid public key format");
                        return Err(StatusCode::UNAUTHORIZED);
                    };
                    let key: VerifyingKey = bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| StatusCode::UNAUTHORIZED)?;
                    DecodingKey::from_ed_der(key.as_bytes())
                };

                if let Err(e) = jsonwebtoken::decode::<Claims>(
                    token,
                    &public_key,
                    &Validation::new(Algorithm::EdDSA),
                ) {
                    tracing::error!("Invalid JWT token: {e}");
                    return Err(StatusCode::UNAUTHORIZED);
                };

                tracing::info!(
                    "Client {}, version {} authenticated",
                    client.name,
                    user_agent_header.version
                );

                Ok(AuthContext::Worker(WorkerAuthContext {
                    client: client.clone(),
                }))
            }
        }
    }
}

impl FromRequestParts<Arc<ServerState>> for WorkerAuthContext {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<ServerState>,
    ) -> Result<Self, Self::Rejection> {
        let context = AuthContext::from_request_parts(parts, state).await?;
        match context {
            AuthContext::Worker(token) => Ok(token),
        }
    }
}
