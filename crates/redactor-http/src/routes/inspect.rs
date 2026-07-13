use std::sync::Arc;

use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Response, StatusCode};
use redactor::inspect_encrypted_session;
use secrecy::ExposeSecret;

use crate::headers::json_response;
use crate::http_error::error_response;
use crate::routes::models::InspectSessionRequest;
use crate::state::HttpState;

#[utoipa::path(
    post,
    path = "/inspect/session",
    request_body = InspectSessionRequest,
    responses(
        (status = 200, body = redactor::SessionSummary),
        (status = 422, body = crate::http_error::ErrorResponse),
        (status = 500, body = crate::http_error::ErrorResponse)
    )
)]
pub(crate) async fn inspect_session(
    State(state): State<Arc<HttpState>>,
    Json(request): Json<InspectSessionRequest>,
) -> Response<Body> {
    let passphrase = state.session_passphrase.clone();
    match state
        .blocking
        .run(move || {
            inspect_encrypted_session(&request.encrypted_session, passphrase.expose_secret())
        })
        .await
    {
        Ok(summary) => json_response(
            StatusCode::OK,
            serde_json::to_vec(&summary).unwrap_or_default(),
        ),
        Err(error) => error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            error.to_string(),
            "inspect_error",
        ),
    }
}
