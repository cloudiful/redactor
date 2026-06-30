mod audit;
mod chat_completions;
mod http;
mod responses;
mod stream;
mod transform;

use anyhow::{Context, Result};
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Response, StatusCode};
use redactor::{RedactorBuilder, ensure_restore_valid};
use reqwest::Client;
use serde_json::Value;
use std::path::PathBuf;

use crate::audit::maybe_write_audit;
use crate::http::{build_response, error_response, filtered_headers};
use crate::stream::restore_sse_stream;
use crate::transform::{ApiEndpoint, redact_json_request, restore_json_response};

#[derive(Debug, Clone)]
pub struct ChatResponsesProxyContext {
    upstream: String,
    api_key_env: Option<String>,
    audit_dir: Option<PathBuf>,
    session_passphrase_env: String,
    session_passphrase: Option<String>,
    redaction_policy: redactor::RedactionPolicy,
    client: Client,
}

impl ChatResponsesProxyContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        upstream: String,
        api_key_env: Option<String>,
        audit_dir: Option<PathBuf>,
        session_passphrase_env: String,
        session_passphrase: Option<String>,
        redaction_policy: redactor::RedactionPolicy,
        client: Client,
    ) -> Self {
        Self {
            upstream,
            api_key_env,
            audit_dir,
            session_passphrase_env,
            session_passphrase,
            redaction_policy,
            client,
        }
    }
}

pub async fn proxy_chat(
    ctx: &ChatResponsesProxyContext,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    proxy_request(ApiEndpoint::ChatCompletions, ctx, headers, body).await
}

pub async fn proxy_responses(
    ctx: &ChatResponsesProxyContext,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    proxy_request(ApiEndpoint::Responses, ctx, headers, body).await
}

async fn proxy_request(
    endpoint: ApiEndpoint,
    ctx: &ChatResponsesProxyContext,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    match proxy_request_inner(endpoint, ctx, headers, body).await {
        Ok(response) => response,
        Err(error) => error_response(StatusCode::BAD_GATEWAY, error.to_string(), "proxy_error"),
    }
}

async fn proxy_request_inner(
    endpoint: ApiEndpoint,
    ctx: &ChatResponsesProxyContext,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response<Body>> {
    let body_json: Value = serde_json::from_slice(&body).context("invalid JSON request body")?;
    let is_stream = body_json
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let redactor = RedactorBuilder::new()
        .with_redaction_policy(ctx.redaction_policy.clone())
        .build();
    let redacted = redact_json_request(endpoint, body_json, &redactor)?;

    maybe_write_audit(ctx, &redacted.session)?;

    let upstream_url = match endpoint {
        ApiEndpoint::ChatCompletions => format!("{}/chat/completions", ctx.upstream),
        ApiEndpoint::Responses => format!("{}/responses", ctx.upstream),
    };

    let mut request = ctx.client.post(upstream_url);
    for (name, value) in filtered_headers(&headers, &ctx.api_key_env)? {
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
