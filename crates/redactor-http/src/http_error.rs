use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, HeaderValue};
use axum::http::{Response, StatusCode};
use redactor::SessionStoreError;
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ErrorResponse {
    error: ErrorEnvelope,
}

#[derive(Debug, Serialize, ToSchema)]
struct ErrorEnvelope {
    message: String,
    kind: &'static str,
}

pub(crate) fn error_response(
    status: StatusCode,
    message: String,
    kind: &'static str,
) -> Response<Body> {
    let payload = serde_json::to_vec(&ErrorResponse {
        error: ErrorEnvelope { message, kind },
    })
    .unwrap_or_else(|_| {
        b"{\"error\":{\"message\":\"internal service error\",\"kind\":\"service_error\"}}".to_vec()
    });
    let mut response = Response::new(Body::from(payload));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

pub(crate) fn status_for_error(error: &anyhow::Error) -> StatusCode {
    if let Some(store_error) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<SessionStoreError>())
    {
        return match store_error {
            SessionStoreError::Conflict => StatusCode::CONFLICT,
            SessionStoreError::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            SessionStoreError::CorruptData(_) | SessionStoreError::Crypto(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
    }
    let message = error.to_string();
    if message.contains("no latest session") {
        StatusCode::NOT_FOUND
    } else if message.contains("external_id")
        || message.contains("must provide")
        || message.contains("invalid redaction policy")
    {
        StatusCode::BAD_REQUEST
    } else if message.contains("permit")
        || message.contains("decrypt")
        || message.contains("restore")
    {
        StatusCode::UNPROCESSABLE_ENTITY
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}
