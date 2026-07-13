mod detect;
mod input;
mod llm;
mod redactor;
mod replace;
mod service;
mod session;
mod session_types;
#[cfg(test)]
mod tests;
mod types;

pub use input::InputKind;
pub use llm::LlmConfig;
pub use redactor::{Redactor, RedactorBuilder, SessionRedactor};
pub use service::{
    EncryptedRedactionArtifact, decrypt_permits, decrypt_redaction_session, redact_text_artifact,
    redact_text_artifact_with_source, redact_text_artifact_with_source_and_stateful_session,
    redact_text_artifact_with_stateful_session, redact_text_with_encrypted_session,
    redact_text_with_encrypted_session_and_source, restore_text_from_encrypted_session,
    restore_text_from_store,
};
pub use session::{
    RestoreContext, RestoreState, SessionStore, SessionStoreError, StoredSession,
    StreamingRestoreContext, authorized_tokens, create_restore_permit, decrypt_restore_permit,
    decrypt_session_from_storage, decrypt_session_from_str, encrypt_restore_permit,
    encrypt_session_for_storage, encrypt_session_to_string, ensure_restore_valid,
    inspect_encrypted_session, require_external_id, restore_patch_with_session,
    restore_text_with_session,
};
use thiserror::Error;
pub use types::{
    AppliedReplacement, CustomFileRule, CustomStringMatch, CustomStringRule, CustomStringScope,
    Finding, FindingKind, FindingSource, RedactionArtifact, RedactionPolicy, RedactionResult,
    RedactionRules, RedactionSession, RedactionStats, ReplacementStrategy, RestorationEntry,
    RestorePermit, RestoreResult, SessionEntrySummary, SessionSummary,
};

#[derive(Debug, Error)]
pub enum RedactorError {
    #[error("llm error: {0}")]
    Llm(String),
    #[error("validation error: {0}")]
    Validation(String),
}
