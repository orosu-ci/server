use crate::api::protocol_version::{PROTOCOL_VERSION_HEADER_NAME, supported_protocol_versions};
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

        // Checked separately from auth on purpose: an unsupported version and
        // a bad credential are different problems needing different fixes
        // (upgrade software vs. rotate a key), so this gets its own status
        // code (400) rather than folding into the 401s below.
        //
        // A missing header isn't a malformed request — it's every client
        // built before this header existed, which is version 0 by
        // definition (see PROTOCOL_VERSION's doc comment). Folding it into
        // the same version-check path as an explicit version, and never a
        // separate "header is missing" case, keeps the log message
        // meaningful for what's currently the overwhelmingly common case.
        let client_protocol_version = match parts
            .headers
            .get(HeaderName::from_static(PROTOCOL_VERSION_HEADER_NAME))
        {
            None => 0,
            Some(header_value) => match ProtocolVersionHeader::try_from(header_value) {
                Ok(value) => value.version,
                Err(e) => {
                    tracing::error!("Unexpected protocol version header format: {e}");
                    return Err(StatusCode::BAD_REQUEST);
                }
            },
        };

        // Accepts a *set* of versions, not just the current one, so that
        // clients built against the previous version keep working while a
        // rollout is in progress — see supported_protocol_versions's doc
        // comment for why version 0 specifically can't be dropped yet, and
        // why version 2 is conditional on state.encryption_key.
        let supported_versions = supported_protocol_versions(state.encryption_key.is_some());
        if !supported_versions.contains(&client_protocol_version) {
            tracing::error!(
                "Client protocol version {} is not supported by this server (supported: {:?})",
                client_protocol_version,
                supported_versions
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
                    protocol_version: client_protocol_version,
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
