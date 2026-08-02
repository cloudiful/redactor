use anyhow::{Context, Result};

use crate::session::SessionStore;
use crate::{
    InputKind, RedactionArtifact, RedactionSession, Redactor, RestorePermit, RestoreResult,
    StoredSession, create_restore_permit, decrypt_restore_permit, decrypt_session_from_str,
    encrypt_restore_permit, encrypt_session_to_string, ensure_restore_valid, require_external_id,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedRedactionArtifact {
    pub artifact: RedactionArtifact,
    pub encrypted_session: String,
    pub restore_permit: String,
    pub session_summary: crate::SessionSummary,
}

pub fn redact_text_artifact(
    redactor: &Redactor,
    text: &str,
    input_kind: InputKind,
) -> Result<RedactionArtifact> {
    redact_text_artifact_internal(redactor, text, input_kind, None, None, None)
}

pub fn redact_text_artifact_with_source(
    redactor: &Redactor,
    text: &str,
    input_kind: InputKind,
    source_path: &str,
) -> Result<RedactionArtifact> {
    redact_text_artifact_internal(redactor, text, input_kind, Some(source_path), None, None)
}

pub async fn redact_text_artifact_with_stateful_session(
    redactor: &Redactor,
    text: &str,
    input_kind: InputKind,
    external_id: &str,
    store: &dyn SessionStore,
) -> Result<RedactionArtifact> {
    let external_id = require_external_id(Some(external_id))?;
    let (prior_session, expected_version) = load_stateful_session(store, external_id).await?;
    let artifact = redact_text_artifact_internal(
        redactor,
        text,
        input_kind,
        None,
        prior_session.as_ref(),
        Some(external_id),
    )?;
    save_stateful_session(
        store,
        external_id,
        &artifact.session,
        expected_version.as_deref(),
    )
    .await?;
    Ok(artifact)
}

pub async fn redact_text_artifact_with_source_and_stateful_session(
    redactor: &Redactor,
    text: &str,
    input_kind: InputKind,
    source_path: &str,
    external_id: &str,
    store: &dyn SessionStore,
) -> Result<RedactionArtifact> {
    let external_id = require_external_id(Some(external_id))?;
    let (prior_session, expected_version) = load_stateful_session(store, external_id).await?;
    let artifact = redact_text_artifact_internal(
        redactor,
        text,
        input_kind,
        Some(source_path),
        prior_session.as_ref(),
        Some(external_id),
    )?;
    save_stateful_session(
        store,
        external_id,
        &artifact.session,
        expected_version.as_deref(),
    )
    .await?;
    Ok(artifact)
}

pub fn redact_text_with_encrypted_session(
    redactor: &Redactor,
    text: &str,
    input_kind: InputKind,
    passphrase: &str,
) -> Result<EncryptedRedactionArtifact> {
    let artifact =
        redact_text_artifact(redactor, text, input_kind).context("failed to redact text input")?;
    encrypt_artifact(artifact, passphrase)
}

pub fn redact_text_with_encrypted_session_and_source(
    redactor: &Redactor,
    text: &str,
    input_kind: InputKind,
    source_path: &str,
    passphrase: &str,
) -> Result<EncryptedRedactionArtifact> {
    let artifact = redact_text_artifact_with_source(redactor, text, input_kind, source_path)
        .context("failed to redact text input")?;
    encrypt_artifact(artifact, passphrase)
}

fn redact_text_artifact_internal(
    redactor: &Redactor,
    text: &str,
    input_kind: InputKind,
    source_path: Option<&str>,
    prior_session: Option<&RedactionSession>,
    external_id: Option<&str>,
) -> Result<RedactionArtifact> {
    redactor
        .redact_artifact_with_input_kind_source_and_prior_session(
            text,
            input_kind,
            source_path,
            prior_session,
            external_id,
        )
        .map_err(anyhow::Error::new)
}

fn encrypt_artifact(
    artifact: RedactionArtifact,
    passphrase: &str,
) -> Result<EncryptedRedactionArtifact> {
    let encrypted_session = encrypt_session_to_string(&artifact.session, passphrase)
        .context("failed to encrypt redaction session")?;
    let restore_permit =
        encrypt_restore_permit(&create_restore_permit(&artifact.session), passphrase)
            .context("failed to encrypt restore permit")?;
    let session_summary = crate::SessionSummary::from(&artifact.session);

    Ok(EncryptedRedactionArtifact {
        artifact,
        encrypted_session,
        restore_permit,
        session_summary,
    })
}

pub fn decrypt_redaction_session(
    encrypted_session: &str,
    passphrase: &str,
) -> Result<RedactionSession> {
    decrypt_session_from_str(encrypted_session, passphrase)
        .context("failed to decrypt provided session")
}

pub fn restore_text_from_encrypted_session(
    text: &str,
    encrypted_session: &str,
    encrypted_permits: &[String],
    passphrase: &str,
) -> Result<RestoreResult> {
    let session = decrypt_redaction_session(encrypted_session, passphrase)?;
    let permits = decrypt_permits(encrypted_permits, passphrase)?;
    let restored = crate::RestoreContext::with_permits(&session, &permits)?.restore_text(text);
    ensure_restore_valid(&restored)?;
    Ok(restored)
}

async fn load_stateful_session(
    store: &dyn SessionStore,
    external_id: &str,
) -> Result<(Option<RedactionSession>, Option<String>)> {
    let prior = store.load_latest(external_id).await.with_context(|| {
        format!("failed to load latest session for external_id `{external_id}`")
    })?;
    Ok(split_stored_session(prior))
}

async fn save_stateful_session(
    store: &dyn SessionStore,
    external_id: &str,
    session: &RedactionSession,
    expected_version: Option<&str>,
) -> Result<()> {
    store
        .save_latest(external_id, session, expected_version)
        .await
        .with_context(|| {
            format!("failed to save latest session for external_id `{external_id}`")
        })?;
    Ok(())
}

fn split_stored_session(
    stored: Option<StoredSession>,
) -> (Option<RedactionSession>, Option<String>) {
    match stored {
        Some(stored) => (Some(stored.session), Some(stored.version)),
        None => (None, None),
    }
}

pub async fn restore_text_from_store(
    text: &str,
    external_id: &str,
    store: &dyn SessionStore,
    permits: &[RestorePermit],
) -> Result<RestoreResult> {
    let session = store
        .load_latest(require_external_id(Some(external_id))?)
        .await
        .with_context(|| format!("failed to load latest session for external_id `{external_id}`"))?
        .ok_or_else(|| {
            anyhow::anyhow!("no latest session found for external_id `{external_id}`")
        })?;
    let restored =
        crate::RestoreContext::with_permits(&session.session, permits)?.restore_text(text);
    ensure_restore_valid(&restored)?;
    Ok(restored)
}

pub fn decrypt_permits(encrypted: &[String], passphrase: &str) -> Result<Vec<RestorePermit>> {
    encrypted
        .iter()
        .map(|permit| decrypt_restore_permit(permit, passphrase))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        redact_text_artifact, redact_text_with_encrypted_session,
        restore_text_from_encrypted_session,
    };
    use crate::types::FindingKind;
    use crate::{InputKind, RedactionPolicy, RedactorBuilder};

    fn full_redactor() -> crate::Redactor {
        RedactorBuilder::new()
            .with_redaction_policy(
                RedactionPolicy::default()
                    .with_kind(FindingKind::Domain, true)
                    .with_kind(FindingKind::Secret, true)
                    .with_kind(FindingKind::Url, true),
            )
            .try_build()
            .expect("test policy is valid")
    }

    #[test]
    fn encrypted_redaction_matches_plain_artifact_output() {
        let redactor = full_redactor();
        let text = "host=service.example.com secret=EJ2QEVC6AKELW0k2kkVY4NgGKONC";
        let plain = redact_text_artifact(&redactor, text, InputKind::Text).expect("plain");
        let encrypted =
            redact_text_with_encrypted_session(&redactor, text, InputKind::Text, "pass")
                .expect("encrypted");

        assert_eq!(
            encrypted.artifact.session.entries.len(),
            plain.session.entries.len()
        );
        assert_eq!(
            encrypted
                .artifact
                .session
                .entries
                .iter()
                .map(|entry| (&entry.kind, &entry.original))
                .collect::<Vec<_>>(),
            plain
                .session
                .entries
                .iter()
                .map(|entry| (&entry.kind, &entry.original))
                .collect::<Vec<_>>()
        );
        assert_ne!(
            encrypted.artifact.result.redacted_text,
            plain.result.redacted_text
        );
    }

    #[test]
    fn encrypted_session_restore_round_trips() {
        let redactor = full_redactor();
        let text = "host=service.example.com";
        let encrypted =
            redact_text_with_encrypted_session(&redactor, text, InputKind::Text, "pass")
                .expect("encrypted");

        let restored = restore_text_from_encrypted_session(
            &encrypted.artifact.result.redacted_text,
            &encrypted.encrypted_session,
            &[encrypted.restore_permit],
            "pass",
        )
        .expect("restore");

        assert_eq!(restored.restored_text, text);
    }
}
