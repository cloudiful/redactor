use axum::body::Body;
use axum::http::header::{
    AUTHORIZATION, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST, HeaderName, HeaderValue,
    PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use axum::http::{HeaderMap, Response, StatusCode};
use serde::Serialize;
use std::env;

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

pub(crate) fn filtered_headers(
    headers: &HeaderMap,
    api_key_env: &Option<String>,
) -> anyhow::Result<Vec<(HeaderName, HeaderValue)>> {
    let mut forwarded = Vec::new();
    let mut has_authorization = false;

    for (name, value) in headers {
        if is_hop_by_hop(name)
            || name == HOST
            || name == CONTENT_LENGTH
            || name.as_str().eq_ignore_ascii_case("x-redactor-external-id")
        {
            continue;
        }
        if name == AUTHORIZATION {
            has_authorization = true;
        }
        forwarded.push((name.clone(), value.clone()));
    }

    if !has_authorization
        && let Some(env_name) = api_key_env
        && let Ok(api_key) = env::var(env_name)
    {
        let value = HeaderValue::from_str(&format!("Bearer {api_key}"))
            .map_err(|error| anyhow::anyhow!("invalid API key header: {error}"))?;
        forwarded.push((AUTHORIZATION, value));
    }

    Ok(forwarded)
}

pub(crate) fn build_response(
    status: StatusCode,
    upstream_headers: &reqwest::header::HeaderMap,
    body: Body,
) -> Response<Body> {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    let headers = response.headers_mut();
    for (name, value) in upstream_headers {
        if is_hop_by_hop(name) || name == CONTENT_LENGTH {
            continue;
        }
        headers.insert(name.clone(), value.clone());
    }
    response
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        *name,
        CONNECTION
            | CONTENT_LENGTH
            | TRANSFER_ENCODING
            | UPGRADE
            | TE
            | TRAILER
            | PROXY_AUTHENTICATE
            | PROXY_AUTHORIZATION
    )
}
