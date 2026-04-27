use std::sync::Arc;

use anyhow::{Context, Result};
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, Response, StatusCode};
use redactor::{RedactorBuilder, ensure_restore_valid};
use serde_json::Value;

use crate::audit::maybe_write_audit;
use crate::headers::{build_response, filtered_headers};
use crate::http_error::error_response;
use crate::openrouter::{ApiEndpoint, redact_json_request, restore_json_response};
use crate::state::ProxyState;
use crate::stream::restore_sse_stream;

pub(crate) async fn proxy_chat(
    State(state): State<Arc<ProxyState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    proxy_request(ApiEndpoint::ChatCompletions, state, headers, body).await
}

pub(crate) async fn proxy_responses(
    State(state): State<Arc<ProxyState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    proxy_request(ApiEndpoint::Responses, state, headers, body).await
}

async fn proxy_request(
    endpoint: ApiEndpoint,
    state: Arc<ProxyState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    match proxy_request_inner(endpoint, state, headers, body).await {
        Ok(response) => response,
        Err(error) => error_response(StatusCode::BAD_GATEWAY, error.to_string(), "proxy_error"),
    }
}

async fn proxy_request_inner(
    endpoint: ApiEndpoint,
    state: Arc<ProxyState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response<Body>> {
    let body_json: Value = serde_json::from_slice(&body).context("invalid JSON request body")?;
    let is_stream = body_json
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let redactor = RedactorBuilder::new()
        .with_redaction_rules(state.redaction_rules)
        .build();
    let redacted = redact_json_request(endpoint, body_json, &redactor)?;

    maybe_write_audit(&state, &redacted.session)?;

    let upstream_url = match endpoint {
        ApiEndpoint::ChatCompletions => format!("{}/chat/completions", state.upstream),
        ApiEndpoint::Responses => format!("{}/responses", state.upstream),
    };

    let mut request = state.client.post(upstream_url);
    for (name, value) in filtered_headers(&headers, &state.api_key_env)? {
        request = request.header(name, value);
    }
    request = request.json(&redacted.body);

    let upstream_response = request.send().await.context("failed to contact upstream")?;
    let status = StatusCode::from_u16(upstream_response.status().as_u16())
        .context("invalid upstream status code")?;
    let upstream_headers = upstream_response.headers().clone();

    if !status.is_success() {
        let bytes = upstream_response
            .bytes()
            .await
            .context("failed to read upstream error body")?;
        return Ok(build_response(status, &upstream_headers, Body::from(bytes)));
    }

    if is_stream {
        let session = redacted.session.clone();
        let response_stream = restore_sse_stream(upstream_response.bytes_stream(), session);

        return Ok(build_response(
            status,
            &upstream_headers,
            Body::from_stream(response_stream),
        ));
    }

    let bytes = upstream_response
        .bytes()
        .await
        .context("failed to read upstream response body")?;
    let body_json: Value =
        serde_json::from_slice(&bytes).context("upstream response was not valid JSON")?;
    let restored = restore_json_response(body_json, &redacted.session)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    ensure_restore_valid(&restored.report)?;
    let payload =
        serde_json::to_vec(&restored.body).context("failed to serialize restored response")?;

    Ok(build_response(
        status,
        &upstream_headers,
        Body::from(payload),
    ))
}
