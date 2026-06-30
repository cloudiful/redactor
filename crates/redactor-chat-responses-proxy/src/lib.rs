mod audit;
mod chat_completions;
mod http;
mod responses;
mod stream;
mod transform;

use anyhow::{Context, Result};
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Response, StatusCode};
use redactor::{RedactorBuilder, SessionStore, ensure_restore_valid};
use reqwest::Client;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;

use crate::audit::maybe_write_audit;
use crate::http::{build_response, error_response, filtered_headers};
use crate::stream::restore_sse_stream;
use crate::transform::{ApiEndpoint, redact_json_request, restore_json_response};

#[derive(Clone)]
pub struct ChatResponsesProxyContext {
    upstream: String,
    api_key_env: Option<String>,
    audit_dir: Option<PathBuf>,
    session_passphrase_env: String,
    session_passphrase: Option<String>,
    redaction_policy: redactor::RedactionPolicy,
    session_store: Option<Arc<dyn SessionStore>>,
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
        session_store: Option<Arc<dyn SessionStore>>,
        client: Client,
    ) -> Self {
        Self {
            upstream,
            api_key_env,
            audit_dir,
            session_passphrase_env,
            session_passphrase,
            redaction_policy,
            session_store,
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
        Err(error) => {
            let status = error
                .downcast_ref::<ProxyRequestError>()
                .map(ProxyRequestError::status)
                .unwrap_or(StatusCode::BAD_GATEWAY);
            let kind = error
                .downcast_ref::<ProxyRequestError>()
                .map(ProxyRequestError::kind)
                .unwrap_or("proxy_error");
            error_response(status, error.to_string(), kind)
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum ProxyRequestError {
    #[error("invalid JSON request body")]
    InvalidJson,
    #[error("body external_id does not match x-redactor-external-id header")]
    ExternalIdConflict,
    #[error("external_id stateful session operations require a configured session store provider")]
    MissingSessionStore,
}

impl ProxyRequestError {
    fn status(&self) -> StatusCode {
        match self {
            Self::InvalidJson | Self::ExternalIdConflict => StatusCode::BAD_REQUEST,
            Self::MissingSessionStore => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::InvalidJson => "invalid_request",
            Self::ExternalIdConflict => "invalid_request",
            Self::MissingSessionStore => "proxy_config_error",
        }
    }
}

async fn proxy_request_inner(
    endpoint: ApiEndpoint,
    ctx: &ChatResponsesProxyContext,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response<Body>> {
    let body_json: Value =
        serde_json::from_slice(&body).map_err(|_| anyhow::Error::new(ProxyRequestError::InvalidJson))?;
    let body_external_id = body_json
        .get("external_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let header_external_id = headers
        .get("x-redactor-external-id")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    if body_external_id.is_some()
        && header_external_id.is_some()
        && body_external_id != header_external_id
    {
        return Err(anyhow::Error::new(ProxyRequestError::ExternalIdConflict));
    }
    let external_id = body_external_id.or(header_external_id);
    if external_id.is_some() && ctx.session_store.is_none() {
        return Err(anyhow::Error::new(ProxyRequestError::MissingSessionStore));
    }
    let is_stream = body_json
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let redactor = RedactorBuilder::new()
        .with_redaction_policy(ctx.redaction_policy.clone())
        .build();
    let redacted = redact_json_request(
        endpoint,
        body_json,
        &redactor,
        external_id.as_deref(),
        ctx.session_store.as_deref(),
    )?;

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
