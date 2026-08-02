use std::sync::Arc;

use anyhow::{Context, Result};
use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Response, StatusCode};
use redactor::{
    EncryptedRedactionArtifact, InputKind, RedactionArtifact, Redactor, RedactorBuilder,
    SessionStore, SessionSummary, create_restore_permit, encrypt_restore_permit,
    encrypt_session_to_string, redact_text_with_encrypted_session,
    redact_text_with_encrypted_session_and_source, require_external_id,
};
use secrecy::ExposeSecret;

use crate::audit::maybe_write_audit;
use crate::headers::json_response;
use crate::http_error::{error_response, status_for_error};
use crate::routes::models::{RedactTextRequest, RedactTextResponse};
use crate::state::HttpState;

#[utoipa::path(
    post,
    path = "/redact/text",
    request_body = RedactTextRequest,
    responses(
        (status = 200, body = RedactTextResponse),
        (status = 400, body = crate::http_error::ErrorResponse),
        (status = 409, body = crate::http_error::ErrorResponse),
        (status = 503, body = crate::http_error::ErrorResponse),
        (status = 500, body = crate::http_error::ErrorResponse)
    )
)]
pub(crate) async fn redact_text(
    State(state): State<Arc<HttpState>>,
    Json(request): Json<RedactTextRequest>,
) -> Response<Body> {
    match redact_text_inner(state, request).await {
        Ok(response) => response,
        Err(error) => error_response(status_for_error(&error), error.to_string(), "redact_error"),
    }
}

async fn redact_text_inner(
    state: Arc<HttpState>,
    request: RedactTextRequest,
) -> Result<Response<Body>> {
    let policy = request
        .redaction
        .unwrap_or_else(|| state.redaction_policy.clone());
    let redactor = RedactorBuilder::new()
        .with_redaction_policy(policy)
        .try_build()
        .map_err(|error| anyhow::anyhow!("invalid redaction policy: {error}"))?;

    let secured = if let Some(external_id) = request.external_id {
        let store = state
            .session_store
            .clone()
            .context("external_id requires a configured session store")?;
        let artifact = stateful_artifact(
            &state,
            store,
            redactor,
            request.text,
            request.input_kind,
            request.source_path,
            external_id,
        )
        .await?;
        secure_artifact(&state, artifact).await?
    } else {
        let passphrase = state.session_passphrase.clone();
        let source_path = request.source_path;
        state
            .blocking
            .run(move || match source_path {
                Some(path) => redact_text_with_encrypted_session_and_source(
                    &redactor,
                    &request.text,
                    request.input_kind,
                    &path,
                    passphrase.expose_secret(),
                ),
                None => redact_text_with_encrypted_session(
                    &redactor,
                    &request.text,
                    request.input_kind,
                    passphrase.expose_secret(),
                ),
            })
            .await
            .context("failed to redact text request")?
    };

    maybe_write_audit(
        &state,
        &secured.artifact.session.session_id,
        &secured.encrypted_session,
    )
    .await?;
    let payload = serde_json::to_vec(&RedactTextResponse {
        redacted_text: secured.artifact.session.redacted_text,
        encrypted_session: secured.encrypted_session,
        restore_permit: secured.restore_permit,
        session_summary: secured.session_summary,
    })?;
    Ok(json_response(StatusCode::OK, payload))
}

async fn stateful_artifact(
    state: &HttpState,
    store: Arc<dyn SessionStore>,
    redactor: Redactor,
    text: String,
    input_kind: InputKind,
    source_path: Option<String>,
    external_id: String,
) -> Result<RedactionArtifact> {
    let external_id = require_external_id(Some(&external_id))?.to_string();
    let stored = store
        .load_latest(&external_id)
        .await
        .context("failed to load stateful session")?;
    let expected_version = stored.as_ref().map(|stored| stored.version.clone());
    let prior = stored.map(|stored| stored.session);
    let operation_external_id = external_id.clone();
    let artifact = state
        .blocking
        .run(move || {
            redactor
                .redact_artifact_with_input_kind_source_and_prior_session(
                    &text,
                    input_kind,
                    source_path.as_deref(),
                    prior.as_ref(),
                    Some(&operation_external_id),
                )
                .map_err(anyhow::Error::new)
        })
        .await?;
    store
        .save_latest(&external_id, &artifact.session, expected_version.as_deref())
        .await
        .context("failed to save stateful session")?;
    Ok(artifact)
}

async fn secure_artifact(
    state: &HttpState,
    artifact: redactor::RedactionArtifact,
) -> Result<EncryptedRedactionArtifact> {
    let passphrase = state.session_passphrase.clone();
    state
        .blocking
        .run(move || {
            let encrypted_session =
                encrypt_session_to_string(&artifact.session, passphrase.expose_secret())?;
            let restore_permit = encrypt_restore_permit(
                &create_restore_permit(&artifact.session),
                passphrase.expose_secret(),
            )?;
            let session_summary = SessionSummary::from(&artifact.session);
            Ok(EncryptedRedactionArtifact {
                artifact,
                encrypted_session,
                restore_permit,
                session_summary,
            })
        })
        .await
}
