use anyhow::{Context, Result};
use axum::Json;
use axum::Router;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use server::axum::Server;
use std::sync::Arc;

use crate::routes::{proxy, text};
use crate::state::{ProxyConfig, ProxyState};

pub fn app(config: ProxyConfig) -> Result<Router> {
    let state = ProxyState::from_config(&config)?;
    Ok(router().with_state(state))
}

pub async fn run_proxy(config: ProxyConfig) -> Result<()> {
    let bound = Server::new_with_state(config.server_config()?, router())
        .bind()
        .context("failed to bind proxy listener")?;
    bound
        .run_with_graceful_shutdown(shutdown_signal())
        .await
        .context("proxy server terminated unexpectedly")
}

fn router() -> Router<Arc<ProxyState>> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/redact/text", post(text::redact_text))
        .route("/restore/text", post(text::restore_text))
        .route("/inspect/session", post(text::inspect_session))
        .route("/v1/chat/completions", post(proxy::proxy_chat))
        .route("/v1/responses", post(proxy::proxy_responses))
}

async fn healthz() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
