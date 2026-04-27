mod detect;
mod input;
mod llm;
mod redactor;
mod replace;
mod service;
mod session;
#[cfg(test)]
mod tests;
mod types;

pub use input::InputKind;
pub use llm::LlmConfig;
pub use redactor::{Redactor, RedactorBuilder, SessionRedactor};
pub use service::{
    EncryptedRedactionArtifact, decrypt_redaction_session, redact_text_artifact,
    redact_text_with_encrypted_session, restore_text_from_encrypted_session,
};
pub use session::{
    decrypt_session_from_str, encrypt_session_to_string, ensure_restore_valid,
    inspect_encrypted_session, restore_patch_with_session, restore_text_with_session,
};
use thiserror::Error;
pub use types::{
    AppliedReplacement, Finding, FindingKind, FindingSource, RedactionArtifact, RedactionResult,
    RedactionRules, RedactionSession, RedactionStats, ReplacementStrategy, RestorationEntry,
    RestoreResult, SessionEntrySummary, SessionSummary,
};

#[derive(Debug, Error)]
pub enum RedactorError {
    #[error("llm error: {0}")]
    Llm(String),
    #[error("validation error: {0}")]
    Validation(String),
}
