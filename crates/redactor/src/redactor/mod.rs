use crate::{
    Finding, InputKind, LlmConfig, RedactionArtifact, RedactionPolicy, RedactionResult,
    RedactionRules, RedactionSession, RedactorError, RestoreResult, restore_patch_with_session,
    restore_text_with_session,
};

mod detection;
mod session;
mod stats;

use detection::detect_internal;
use session::SessionRedactorExt;
use stats::stats_for;

#[derive(Debug, Clone, Default)]
pub struct RedactorBuilder {
    llm: Option<LlmConfig>,
    policy: RedactionPolicy,
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
        self.policy.rules.person = enabled;
        self
    }

    pub fn with_redaction_rules(mut self, rules: RedactionRules) -> Self {
        self.policy.rules = rules;
        self
    }

    pub fn with_redaction_policy(mut self, policy: RedactionPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn build(self) -> Redactor {
        Redactor {
            llm: self.llm,
            policy: self.policy,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Redactor {
    pub(super) llm: Option<LlmConfig>,
    pub(super) policy: RedactionPolicy,
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

    pub fn redact_with_source_path(
        &self,
        text: &str,
        source_path: &str,
    ) -> Result<RedactionResult, RedactorError> {
        let artifact = self.redact_artifact_with_input_kind_and_source(
            text,
            InputKind::Text,
            Some(source_path),
        )?;
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
        self.redact_artifact_with_input_kind_and_source(text, input_kind, None)
    }

    pub fn redact_artifact_with_input_kind_and_source(
        &self,
        text: &str,
        input_kind: InputKind,
        source_path: Option<&str>,
    ) -> Result<RedactionArtifact, RedactorError> {
        let outcome = detect_internal(self, text, input_kind, source_path);
        let findings = outcome.findings;
        let output = crate::replace::apply_replacements(text, &findings, &self.policy);
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
        Ok(detect_internal(self, text, input_kind, None).findings)
    }

    pub fn detect_with_source_path(
        &self,
        text: &str,
        source_path: &str,
    ) -> Result<Vec<Finding>, RedactorError> {
        Ok(detect_internal(self, text, InputKind::Text, Some(source_path)).findings)
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
        self.build_redaction_session(
            original_text,
            redacted_text,
            &crate::RedactionPolicy::default(),
        )
    }

    pub fn max_token_len(&self) -> usize {
        self.max_replacement_token_len()
    }
}
