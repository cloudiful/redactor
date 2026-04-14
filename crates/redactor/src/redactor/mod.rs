mod detection;
mod session;
mod stats;

use crate::replace::apply_replacements;
use crate::{
    Finding, InputKind, LlmConfig, RedactionArtifact, RedactionResult, RedactionSession,
    RedactorError, RestoreResult, restore_patch_with_session, restore_text_with_session,
};
use detection::detect_internal;
use session::SessionRedactorExt;
use stats::stats_for;

#[derive(Debug, Clone, Default)]
pub struct RedactorBuilder {
    llm: Option<LlmConfig>,
    person_detection: bool,
}

impl RedactorBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_llm(mut self, config: LlmConfig) -> Self {
        self.llm = Some(config);
        self
    }

    pub fn with_person_detection(mut self, enabled: bool) -> Self {
        self.person_detection = enabled;
        self
    }

    pub fn build(self) -> Redactor {
        Redactor {
            llm: self.llm,
            person_detection: self.person_detection,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Redactor {
    pub(super) llm: Option<LlmConfig>,
    pub(super) person_detection: bool,
}

#[derive(Debug, Default)]
pub struct SessionRedactor {
    pub(super) processor: crate::replace::ReplacementProcessor,
}

impl Redactor {
    pub fn redact(&self, text: &str) -> Result<RedactionResult, RedactorError> {
        self.redact_with_input_kind(text, InputKind::Text)
    }

    pub fn redact_with_input_kind(
        &self,
        text: &str,
        input_kind: InputKind,
    ) -> Result<RedactionResult, RedactorError> {
        let artifact = self.redact_artifact_with_input_kind(text, input_kind)?;
        Ok(artifact.result)
    }

    pub fn redact_artifact(&self, text: &str) -> Result<RedactionArtifact, RedactorError> {
        self.redact_artifact_with_input_kind(text, InputKind::Text)
    }

    pub fn redact_artifact_with_input_kind(
        &self,
        text: &str,
        input_kind: InputKind,
    ) -> Result<RedactionArtifact, RedactorError> {
        let outcome = detect_internal(self, text, input_kind)?;
        let findings = outcome.findings;
        let output = apply_replacements(text, &findings);
        let stats = stats_for(self.llm.is_some(), &findings, outcome.stats);

        Ok(RedactionArtifact {
            result: RedactionResult {
                redacted_text: output.redacted_text,
                findings,
                applied_replacements: output.applied_replacements,
                stats,
            },
            session: output.session,
        })
    }

    pub fn redact_with_session(&self, text: &str) -> Result<RedactionSession, RedactorError> {
        self.redact_with_session_input_kind(text, InputKind::Text)
    }

    pub fn redact_with_session_input_kind(
        &self,
        text: &str,
        input_kind: InputKind,
    ) -> Result<RedactionSession, RedactorError> {
        Ok(self
            .redact_artifact_with_input_kind(text, input_kind)?
            .session)
    }

    pub fn detect(&self, text: &str) -> Result<Vec<Finding>, RedactorError> {
        self.detect_with_input_kind(text, InputKind::Text)
    }

    pub fn detect_with_input_kind(
        &self,
        text: &str,
        input_kind: InputKind,
    ) -> Result<Vec<Finding>, RedactorError> {
        Ok(detect_internal(self, text, input_kind)?.findings)
    }

    pub fn restore_text(&self, text: &str, session: &RedactionSession) -> RestoreResult {
        restore_text_with_session(text, session)
    }

    pub fn restore_patch(&self, patch: &str, session: &RedactionSession) -> RestoreResult {
        restore_patch_with_session(patch, session)
    }
}

impl SessionRedactor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn redact_fragment(
        &mut self,
        redactor: &Redactor,
        text: &str,
    ) -> Result<String, RedactorError> {
        self.redact_text_fragment(redactor, text)
    }

    pub fn build_session(&self, original_text: &str, redacted_text: &str) -> RedactionSession {
        self.build_redaction_session(original_text, redacted_text)
    }

    pub fn max_token_len(&self) -> usize {
        self.max_replacement_token_len()
    }
}
