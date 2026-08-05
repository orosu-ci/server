use crate::client::Client;
use crate::configuration::ListenConfiguration;
use crate::cryptography::ServerStaticKey;
use crate::server::handler::TasksHandler;
use anyhow::Context;
use axum::extract::{ConnectInfo, FromRequestParts, Request, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum_client_ip::{ClientIp, ClientIpSource};
use cidr::IpCidr;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::trace::TraceLayer;

mod auth_scope;
mod handler;
pub mod handshake;

pub struct ServerState {
    clients: Vec<Client>,
    /// The server's own static X25519 identity key, present only once an
    /// operator has opted into end-to-end encryption (see
    /// Configuration.encryption_key_file). Its presence is what
    /// `supported_protocol_versions` gates protocol version 2 on — see
    /// auth_scope.rs.
    encryption_key: Option<ServerStaticKey>,
}

pub struct Server {
    listen: ListenConfiguration,
    state: Arc<ServerState>,
    whitelist: Option<Vec<IpCidr>>,
    blacklist: Option<Vec<IpCidr>>,
}

#[derive(Clone, Debug)]
pub enum AuthScope {
    Worker,
}

#[derive(Clone, Debug)]
pub struct WorkerAuthContext {
    pub client: Client,
    /// The protocol version this connection authenticated with (already
    /// validated against `supported_protocol_versions` by the time this is
    /// populated) — threaded through to the WS handler so it knows whether
    /// to run the encryption handshake.
    pub protocol_version: u32,
}

#[derive(Clone, Debug)]
pub enum AuthContext {
    Worker(WorkerAuthContext),
}

impl Server {
    pub fn new(
        listen: ListenConfiguration,
        whitelist: Option<Vec<IpCidr>>,
        blacklist: Option<Vec<IpCidr>>,
        clients: Vec<Client>,
        encryption_key: Option<ServerStaticKey>,
    ) -> Self {
        let state = Arc::new(ServerState {
            clients,
            encryption_key,
        });
        Self {
            listen,
            state,
            whitelist,
            blacklist,
        }
    }

    pub async fn serve(&self) -> anyhow::Result<()> {
        let router = self.build_router();

        match &self.listen {
            ListenConfiguration::Tcp(address) => {
                let listener = tokio::net::TcpListener::bind(address)
                    .await
                    .with_context(|| "Failed to bind to TCP address")?;
                axum::serve(
                    listener,
                    router.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .await?;
            }

            ListenConfiguration::Socket(path) => {
                let listener = tokio::net::UnixListener::bind(path).with_context(|| {
                    format!("Failed to bind to unix socket path {}", path.display())
                })?;
                axum::serve(listener, router).await?;
            }
        };
        Ok(())
    }

    fn build_router(&self) -> axum::Router {
        axum::Router::new()
            .route("/", get(TasksHandler::attach))
            .with_state(self.state.clone())
            .layer(TraceLayer::new_for_http())
            .layer(AuthScope::Worker.into_extension())
            .layer(middleware::from_fn_with_state(
                self.whitelist.clone(),
                whitelist_layer,
            ))
            .layer(middleware::from_fn_with_state(
                self.blacklist.clone(),
                blacklist_layer,
            ))
            .layer(ClientIpSource::RightmostXForwardedFor.into_extension())
    }
}

async fn blacklist_layer(
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    State(blacklist): State<Option<Vec<IpCidr>>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(blacklist) = blacklist else {
        return next.run(request).await;
    };
    let (mut parts, body) = request.into_parts();
    let ip = ClientIp::from_request_parts(&mut parts, &())
        .await
        .map(|e| e.0)
        .unwrap_or_else(|_| remote_addr.ip());
    if blacklist.iter().any(|cidr| cidr.contains(&ip)) {
        tracing::warn!("Client {} is blacklisted", ip);
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(Request::from_parts(parts, body)).await
}

async fn whitelist_layer(
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    State(whitelist): State<Option<Vec<IpCidr>>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(whitelist) = whitelist else {
        return next.run(request).await;
    };
    let (mut parts, body) = request.into_parts();
    let ip = ClientIp::from_request_parts(&mut parts, &())
        .await
        .map(|e| e.0)
        .unwrap_or_else(|_| remote_addr.ip());
    if !whitelist.iter().any(|cidr| cidr.contains(&ip)) {
        tracing::warn!("Client {} is not whitelisted", ip);
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(Request::from_parts(parts, body)).await
}
