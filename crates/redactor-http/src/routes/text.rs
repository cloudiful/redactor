use std::sync::Arc;

use anyhow::{Context, Result};
use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Response, StatusCode};
use redactor::{
    RedactorBuilder, inspect_encrypted_session, redact_text_with_encrypted_session,
    restore_text_from_encrypted_session,
};

use crate::audit::{maybe_write_audit, resolve_service_passphrase};
use crate::headers::json_response;
use crate::http_error::error_response;
use crate::routes::text_models::{
    InspectSessionRequest, RedactTextRequest, RedactTextResponse, RestoreTextRequest,
};
use crate::state::ProxyState;

pub(crate) async fn redact_text(
    State(state): State<Arc<ProxyState>>,
    Json(request): Json<RedactTextRequest>,
) -> Response<Body> {
    match redact_text_inner(state, request).await {
        Ok(response) => response,
        Err(error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            error.to_string(),
            "redact_error",
        ),
    }
}

async fn redact_text_inner(
    state: Arc<ProxyState>,
    request: RedactTextRequest,
) -> Result<Response<Body>> {
    let passphrase = resolve_service_passphrase(&state)?;
    let redactor = RedactorBuilder::new().build();
    let secured = redact_text_with_encrypted_session(
        &redactor,
        &request.text,
        request.input_kind,
        passphrase,
    )
    .context("failed to redact text request")?;

    maybe_write_audit(&state, &secured.artifact.session)?;

    let payload = serde_json::to_vec(&RedactTextResponse {
        redacted_text: secured.artifact.session.redacted_text,
        encrypted_session: secured.encrypted_session,
        session_summary: secured.session_summary,
    })
    .context("failed to serialize text redaction response")?;

    Ok(json_response(StatusCode::OK, payload))
}

pub(crate) async fn restore_text(
    State(state): State<Arc<ProxyState>>,
    Json(request): Json<RestoreTextRequest>,
) -> Response<Body> {
    match restore_text_inner(state, request).await {
        Ok(response) => response,
        Err(error) => error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            error.to_string(),
            "restore_error",
        ),
    }
}

async fn restore_text_inner(
    state: Arc<ProxyState>,
    request: RestoreTextRequest,
) -> Result<Response<Body>> {
    let passphrase = resolve_service_passphrase(&state)?;
    let redactor = RedactorBuilder::new().build();
    let restored = restore_text_from_encrypted_session(
        &redactor,
        &request.text,
        &request.encrypted_session,
        passphrase,
    )
    .context("failed to restore text response")?;
    let payload = serde_json::to_vec(&restored).context("failed to serialize restore response")?;
    Ok(json_response(StatusCode::OK, payload))
}

pub(crate) async fn inspect_session(
    State(_state): State<Arc<ProxyState>>,
    Json(request): Json<InspectSessionRequest>,
) -> Response<Body> {
    match inspect_encrypted_session(&request.encrypted_session) {
        Ok(summary) => {
            let payload = serde_json::to_vec(&summary).unwrap_or_else(|_| {
                b"{\"error\":\"failed to serialize session summary\"}".to_vec()
            });
            json_response(StatusCode::OK, payload)
        }
        Err(error) => error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            error.to_string(),
            "inspect_error",
        ),
    }
}
