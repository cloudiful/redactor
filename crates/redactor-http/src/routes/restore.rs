use std::sync::Arc;

use anyhow::{Context, Result};
use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Response, StatusCode};
use redactor::{
    RestoreContext, decrypt_permits, require_external_id, restore_text_from_encrypted_session,
};
use secrecy::ExposeSecret;

use crate::headers::json_response;
use crate::http_error::{error_response, status_for_error};
use crate::routes::models::{RestoreTextRequest, RestoreTextResponse};
use crate::state::HttpState;

#[utoipa::path(
    post,
    path = "/restore/text",
    request_body = RestoreTextRequest,
    responses(
        (status = 200, body = redactor::RestoreResult),
        (status = 400, body = crate::http_error::ErrorResponse),
        (status = 404, body = crate::http_error::ErrorResponse),
        (status = 422, body = crate::http_error::ErrorResponse),
        (status = 503, body = crate::http_error::ErrorResponse),
        (status = 500, body = crate::http_error::ErrorResponse)
    )
)]
pub(crate) async fn restore_text(
    State(state): State<Arc<HttpState>>,
    Json(request): Json<RestoreTextRequest>,
) -> Response<Body> {
    match restore_text_inner(state, request).await {
        Ok(response) => response,
        Err(error) => error_response(status_for_error(&error), error.to_string(), "restore_error"),
    }
}

async fn restore_text_inner(
    state: Arc<HttpState>,
    request: RestoreTextRequest,
) -> Result<Response<Body>> {
    let restored: RestoreTextResponse = match (request.encrypted_session, request.external_id) {
        (Some(session), None) => {
            let passphrase = state.session_passphrase.clone();
            let text = request.text;
            let permits = request.restore_permits;
            state
                .blocking
                .run(move || {
                    restore_text_from_encrypted_session(
                        &text,
                        &session,
                        &permits,
                        passphrase.expose_secret(),
                    )
                })
                .await?
        }
        (None, Some(external_id)) => {
            let store = state
                .session_store
                .clone()
                .context("external_id requires a configured session store")?;
            let passphrase = state.session_passphrase.clone();
            let encrypted = request.restore_permits;
            let permits = state
                .blocking
                .run(move || decrypt_permits(&encrypted, passphrase.expose_secret()))
                .await?;
            let external_id = require_external_id(Some(&external_id))?;
            let stored = store
                .load_latest(external_id)
                .await
                .context("failed to load stateful session")?
                .with_context(|| {
                    format!("no latest session found for external_id `{external_id}`")
                })?;
            let text = request.text;
            state
                .blocking
                .run(move || {
                    let result = RestoreContext::with_permits(&stored.session, &permits)?
                        .restore_text(&text);
                    redactor::ensure_restore_valid(&result)?;
                    Ok(result)
                })
                .await?
        }
        (Some(_), Some(_)) => anyhow::bail!(
            "restore request must provide either encrypted_session or external_id, not both"
        ),
        (None, None) => {
            anyhow::bail!("restore request must provide encrypted_session or external_id")
        }
    };
    Ok(json_response(
        StatusCode::OK,
        serde_json::to_vec(&restored)?,
    ))
}
