use crate::replace::ReplacementProcessor;
use crate::{InputKind, RedactionSession, Redactor, RedactorError};

use super::SessionRedactor;

pub(super) trait SessionRedactorExt {
    fn redact_text_fragment(
        &mut self,
        redactor: &Redactor,
        text: &str,
    ) -> Result<String, RedactorError>;
    fn redact_text_fragment_with_input_kind(
        &mut self,
        redactor: &Redactor,
        text: &str,
        input_kind: InputKind,
    ) -> Result<String, RedactorError>;
    fn build_redaction_session(
        &self,
        original_text: &str,
        redacted_text: &str,
        policy: &crate::RedactionPolicy,
    ) -> RedactionSession;
    fn max_replacement_token_len(&self) -> usize;
}

impl SessionRedactorExt for SessionRedactor {
    fn redact_text_fragment(
        &mut self,
        redactor: &Redactor,
        text: &str,
    ) -> Result<String, RedactorError> {
        self.redact_text_fragment_with_input_kind(redactor, text, InputKind::Text)
    }

    fn redact_text_fragment_with_input_kind(
        &mut self,
        redactor: &Redactor,
        text: &str,
        input_kind: InputKind,
    ) -> Result<String, RedactorError> {
        let findings = redactor.detect_with_input_kind(text, input_kind)?;
        Ok(self.processor.redact_fragment(text, &findings))
    }

    fn build_redaction_session(
        &self,
        original_text: &str,
        redacted_text: &str,
        policy: &crate::RedactionPolicy,
    ) -> RedactionSession {
        self.processor
            .build_session(original_text, redacted_text, policy)
    }

    fn max_replacement_token_len(&self) -> usize {
        self.processor.max_token_len()
    }
}

impl From<ReplacementProcessor> for SessionRedactor {
    fn from(processor: ReplacementProcessor) -> Self {
        Self { processor }
    }
}
