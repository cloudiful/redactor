use anyhow::{Context, Result};

use crate::{
    InputKind, RedactionArtifact, RedactionSession, Redactor, RestoreResult,
    decrypt_session_from_str, encrypt_session_to_string, ensure_restore_valid,
    inspect_encrypted_session,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedRedactionArtifact {
    pub artifact: RedactionArtifact,
    pub encrypted_session: String,
    pub session_summary: crate::SessionSummary,
}

pub fn redact_text_artifact(
    redactor: &Redactor,
    text: &str,
    input_kind: InputKind,
) -> Result<RedactionArtifact> {
    redactor
        .redact_artifact_with_input_kind(text, input_kind)
        .map_err(anyhow::Error::new)
}

pub fn redact_text_artifact_with_source(
    redactor: &Redactor,
    text: &str,
    input_kind: InputKind,
    source_path: &str,
) -> Result<RedactionArtifact> {
    redactor
        .redact_artifact_with_input_kind_and_source(text, input_kind, Some(source_path))
        .map_err(anyhow::Error::new)
}

pub fn redact_text_with_encrypted_session(
    redactor: &Redactor,
    text: &str,
    input_kind: InputKind,
    passphrase: &str,
) -> Result<EncryptedRedactionArtifact> {
    let artifact =
        redact_text_artifact(redactor, text, input_kind).context("failed to redact text input")?;
    let encrypted_session = encrypt_session_to_string(&artifact.session, passphrase)
        .context("failed to encrypt redaction session")?;
    let session_summary = inspect_encrypted_session(&encrypted_session)
        .context("failed to inspect encrypted session")?;

    Ok(EncryptedRedactionArtifact {
        artifact,
        encrypted_session,
        session_summary,
    })
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
    let encrypted_session = encrypt_session_to_string(&artifact.session, passphrase)
        .context("failed to encrypt redaction session")?;
    let session_summary = inspect_encrypted_session(&encrypted_session)
        .context("failed to inspect encrypted session")?;

    Ok(EncryptedRedactionArtifact {
        artifact,
        encrypted_session,
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
    redactor: &Redactor,
    text: &str,
    encrypted_session: &str,
    passphrase: &str,
) -> Result<RestoreResult> {
    let session = decrypt_redaction_session(encrypted_session, passphrase)?;
    let restored = redactor.restore_text(text, &session);
    ensure_restore_valid(&restored)?;
    Ok(restored)
}

#[cfg(test)]
mod tests {
    use super::{
        redact_text_artifact, redact_text_with_encrypted_session,
        restore_text_from_encrypted_session,
    };
    use crate::{InputKind, RedactionPolicy, RedactorBuilder};
    use crate::types::FindingKind;

    fn full_redactor() -> crate::Redactor {
        RedactorBuilder::new()
            .with_redaction_policy(
                RedactionPolicy::default()
                    .with_kind(FindingKind::Domain, true)
                    .with_kind(FindingKind::Secret, true)
                    .with_kind(FindingKind::Url, true),
            )
            .build()
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
            encrypted.artifact.result.redacted_text,
            plain.result.redacted_text
        );
        assert_eq!(
            encrypted.artifact.session.redacted_text,
            plain.session.redacted_text
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
            &redactor,
            &encrypted.artifact.result.redacted_text,
            &encrypted.encrypted_session,
            "pass",
        )
        .expect("restore");

        assert_eq!(restored.restored_text, text);
    }
}