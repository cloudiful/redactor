use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, HeaderValue};
use axum::http::{Response, StatusCode};
use serde::Serialize;

#[derive(Debug, Serialize)]
struct ProxyErrorBody {
    error: ProxyErrorEnvelope,
}

#[derive(Debug, Serialize)]
struct ProxyErrorEnvelope {
    message: String,
    kind: &'static str,
}

pub(crate) fn error_response(
    status: StatusCode,
    message: String,
    kind: &'static str,
) -> Response<Body> {
    let payload = serde_json::to_vec(&ProxyErrorBody {
        error: ProxyErrorEnvelope { message, kind },
    })
    .unwrap_or_else(|_| {
        b"{\"error\":{\"message\":\"internal proxy error\",\"kind\":\"proxy_error\"}}".to_vec()
    });
    let mut response = Response::new(Body::from(payload));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

pub(crate) fn sse_error_event(message: &str) -> String {
    let escaped = serde_json::json!({
        "error": {
            "message": message,
            "kind": "restore_error"
        }
    });
    format!("event: error\ndata: {}\n\n", escaped)
}
