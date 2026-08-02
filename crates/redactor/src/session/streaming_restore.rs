use anyhow::Result;

use crate::replace::{MAX_TOKEN_CANDIDATE_BYTES, TOKEN_PREFIX, TOKEN_SUFFIX};
use crate::{RedactionSession, RestorePermit, RestoreResult};

use super::RestoreContext;

/// Incrementally restores one decoded logical text stream.
///
/// Create a separate context for each logical stream. JSON string escapes must be decoded before
/// calling `push_str`; serialize the restored text again after restoration. This type does not
/// parse bytes, JSON framing, SSE, HTTP, or any other transport framing.
#[derive(Debug)]
pub struct StreamingRestoreContext<'a> {
    restore: RestoreContext<'a>,
    pending: String,
}

impl<'a> StreamingRestoreContext<'a> {
    pub fn new(session: &'a RedactionSession) -> Self {
        Self {
            restore: RestoreContext::new(session),
            pending: String::new(),
        }
    }

    pub fn with_permits(session: &'a RedactionSession, permits: &[RestorePermit]) -> Result<Self> {
        Ok(Self {
            restore: RestoreContext::with_permits(session, permits)?,
            pending: String::new(),
        })
    }

    pub fn push_str(&mut self, fragment: &str) -> RestoreResult {
        let mut result = empty_result(fragment.len());
        for ch in fragment.chars() {
            self.push_char(ch, &mut result);
        }
        result
    }

    pub fn finish(self) -> RestoreResult {
        let mut result = empty_result(self.pending.len());
        if self.pending.starts_with(TOKEN_PREFIX) {
            result.unresolved_tokens.push(self.pending.clone());
            result.validation_errors.push(format!(
                "truncated token `{}`: missing closing `{TOKEN_SUFFIX}`",
                self.pending
            ));
        }
        result.restored_text = self.pending;
        result
    }

    fn push_char(&mut self, ch: char, result: &mut RestoreResult) {
        if self.pending.starts_with(TOKEN_PREFIX)
            && self.pending.len() + ch.len_utf8() > MAX_TOKEN_CANDIDATE_BYTES
        {
            let overflow = std::mem::take(&mut self.pending);
            result.restored_text.push_str(&overflow);
            result.unresolved_tokens.push(overflow.clone());
            result.validation_errors.push(format!(
                "token candidate exceeds {MAX_TOKEN_CANDIDATE_BYTES} byte pending limit"
            ));
        }

        self.pending.push(ch);
        if self.pending.starts_with(TOKEN_PREFIX) {
            if self.pending.ends_with(TOKEN_SUFFIX) {
                let candidate = std::mem::take(&mut self.pending);
                merge_result(result, self.restore.restore_text(&candidate));
            }
            return;
        }

        self.flush_non_marker_prefix(result);
    }

    fn flush_non_marker_prefix(&mut self, result: &mut RestoreResult) {
        if TOKEN_PREFIX.starts_with(&self.pending) {
            return;
        }

        let keep_from = self
            .pending
            .char_indices()
            .map(|(index, _)| index)
            .find(|&index| TOKEN_PREFIX.starts_with(&self.pending[index..]))
            .unwrap_or(self.pending.len());
        result.restored_text.push_str(&self.pending[..keep_from]);
        self.pending.drain(..keep_from);
    }
}

fn empty_result(capacity: usize) -> RestoreResult {
    RestoreResult {
        restored_text: String::with_capacity(capacity),
        restored_count: 0,
        skipped_tokens: Vec::new(),
        unresolved_tokens: Vec::new(),
        validation_errors: Vec::new(),
    }
}

fn merge_result(target: &mut RestoreResult, source: RestoreResult) {
    target.restored_text.push_str(&source.restored_text);
    target.restored_count += source.restored_count;
    target.skipped_tokens.extend(source.skipped_tokens);
    target.unresolved_tokens.extend(source.unresolved_tokens);
    target.validation_errors.extend(source.validation_errors);
}
