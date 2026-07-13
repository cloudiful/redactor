use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{Json, Router};
use serde::Serialize;
use server::axum::Server;
use utoipa::ToSchema;
use utoipa::openapi::{Info, OpenApi, Paths};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::routes::{inspect, redact, restore};
use crate::state::{HttpServerConfig, HttpState};

#[derive(Debug, Serialize, ToSchema)]
struct HealthResponse {
    status: &'static str,
}

pub fn app(config: HttpServerConfig) -> Result<Router> {
    let state = HttpState::from_config(&config)?;
    Ok(router().with_state(state))
}

pub fn openapi() -> OpenApi {
    openapi_router().split_for_parts().1
}

pub async fn run_server(config: HttpServerConfig) -> Result<()> {
    let bound = Server::new_with_state(config.server_config()?, router())
        .bind()
        .context("failed to bind HTTP listener")?;
    bound
        .run_with_graceful_shutdown(shutdown_signal())
        .await
        .context("HTTP server terminated unexpectedly")
}

fn router() -> Router<Arc<HttpState>> {
    openapi_router().split_for_parts().0
}

fn openapi_router() -> OpenApiRouter<Arc<HttpState>> {
    let mut info = Info::new("Redactor HTTP API", env!("CARGO_PKG_VERSION"));
    info.description = Some(
        "Structured text redaction, permit-scoped restoration, and authenticated session inspection."
            .to_string(),
    );
    let openapi = OpenApi::new(info, Paths::new());
    OpenApiRouter::with_openapi(openapi)
        .routes(routes!(healthz))
        .routes(routes!(redact::redact_text))
        .routes(routes!(restore::restore_text))
        .routes(routes!(inspect::inspect_session))
}

#[utoipa::path(
    get,
    path = "/healthz",
    responses((status = 200, body = HealthResponse))
)]
async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::openapi;

    #[test]
    fn generated_openapi_matches_tracked_specification() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../openapi/redactor-http.yaml");
        let tracked: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(path).expect("read tracked OpenAPI"))
                .expect("parse tracked OpenAPI");
        let generated = serde_yaml::to_value(openapi()).expect("serialize generated OpenAPI");
        assert_eq!(tracked, generated, "run the export-openapi binary");
    }
}
