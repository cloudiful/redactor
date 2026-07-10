use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use crate::RedactorError;
use crate::types::{
    AppliedReplacement, Finding, FindingKind, RedactionPolicy, RedactionSession,
    ReplacementStrategy, RestorationEntry,
};

use super::hints::display_hint;
use super::{format_token, parse_token, random_id, random_scope_id, sha256_hex};

#[derive(Debug, Clone)]
struct Allocation {
    token: String,
    kind: FindingKind,
    original: String,
    replacement_hint: Option<String>,
    occurrences: usize,
}

#[derive(Debug, Default)]
struct SessionState {
    allocations: BTreeMap<(FindingKind, String), Allocation>,
    counters: BTreeMap<FindingKind, usize>,
    scope_id: String,
    external_id: Option<String>,
}

#[derive(Debug)]
pub(crate) struct ReplacementProcessor {
    state: SessionState,
    applied_replacements: Vec<AppliedReplacement>,
}

impl Default for ReplacementProcessor {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplacementProcessor {
    pub(crate) fn new() -> Self {
        Self {
            state: SessionState {
                scope_id: random_scope_id(),
                ..SessionState::default()
            },
            applied_replacements: Vec::new(),
        }
    }

    pub(crate) fn with_prior_session(
        prior_session: Option<&RedactionSession>,
        external_id: Option<&str>,
    ) -> Result<Self, RedactorError> {
        let mut processor = Self::new();
        processor.state.external_id = external_id.map(ToOwned::to_owned);

        let Some(prior_session) = prior_session else {
            return Ok(processor);
        };

        if let Some(expected) = external_id
            && let Some(existing) = prior_session.external_id.as_deref()
            && existing != expected
        {
            return Err(RedactorError::Validation(format!(
                "prior session external_id `{existing}` does not match requested external_id `{expected}`"
            )));
        }

        processor.state.scope_id = prior_session.scope_id.clone();
        if processor.state.external_id.is_none() {
            processor.state.external_id = prior_session.external_id.clone();
        }

        for entry in &prior_session.entries {
            let parsed = parse_token(&entry.token).map_err(RedactorError::Validation)?;
            if parsed.scope_id != processor.state.scope_id {
                return Err(RedactorError::Validation(format!(
                    "session entry token scope `{}` does not match session scope `{}`",
                    parsed.scope_id, processor.state.scope_id
                )));
            }

            let counter = processor.state.counters.entry(parsed.kind).or_insert(0);
            *counter = (*counter).max(parsed.counter);
            processor.state.allocations.insert(
                (entry.kind, entry.original.clone()),
                Allocation {
                    token: entry.token.clone(),
                    kind: entry.kind,
                    original: entry.original.clone(),
                    replacement_hint: entry.replacement_hint.clone(),
                    occurrences: entry.occurrences,
                },
            );
        }

        Ok(processor)
    }

    pub(crate) fn redact_fragment(&mut self, text: &str, findings: &[Finding]) -> String {
        let mut output = String::with_capacity(text.len());
        let mut cursor = 0;

        for finding in findings {
            output.push_str(&text[cursor..finding.start]);
            let (token, replacement_hint) = allocation_for(&mut self.state, finding);
            output.push_str(token);
            self.applied_replacements.push(AppliedReplacement {
                kind: finding.kind,
                original: finding.match_text.clone(),
                replacement: token.to_string(),
                strategy: ReplacementStrategy::StructuredToken,
                display_value: replacement_hint.cloned(),
            });
            cursor = finding.end;
        }

        output.push_str(&text[cursor..]);
        output
    }

    pub(crate) fn max_token_len(&self) -> usize {
        self.state
            .allocations
            .values()
            .map(|allocation| allocation.token.len())
            .max()
            .unwrap_or(0)
    }

    pub(crate) fn has_applied_replacements(&self) -> bool {
        !self.applied_replacements.is_empty()
    }

    pub(crate) fn build_session(
        &self,
        original_text: &str,
        redacted_text: &str,
        policy: &RedactionPolicy,
    ) -> RedactionSession {
        let entries = self
            .state
            .allocations
            .values()
            .cloned()
            .map(|allocation| RestorationEntry {
                token: allocation.token,
                kind: allocation.kind,
                original: allocation.original,
                replacement_hint: allocation.replacement_hint,
                occurrences: allocation.occurrences,
            })
            .collect::<Vec<_>>();

        RedactionSession {
            version: 2,
            session_id: random_id(),
            scope_id: self.state.scope_id.clone(),
            external_id: self.state.external_id.clone(),
            fingerprint: sha256_hex(original_text),
            redacted_fingerprint: sha256_hex(redacted_text),
            redacted_text: redacted_text.to_string(),
            policy: policy.clone(),
            entries,
        }
    }

    pub(crate) fn into_applied_replacements(self) -> Vec<AppliedReplacement> {
        self.applied_replacements
    }
}

fn allocation_for<'a>(
    state: &'a mut SessionState,
    finding: &Finding,
) -> (&'a str, Option<&'a String>) {
    let key = (finding.kind, finding.match_text.clone());
    match state.allocations.entry(key) {
        Entry::Occupied(entry) => {
            let allocation = entry.into_mut();
            allocation.occurrences += 1;
            (
                allocation.token.as_str(),
                allocation.replacement_hint.as_ref(),
            )
        }
        Entry::Vacant(entry) => {
            let counter = state.counters.entry(finding.kind).or_insert(0);
            *counter += 1;
            let allocation = entry.insert(Allocation {
                token: format_token(&state.scope_id, finding.kind, *counter),
                kind: finding.kind,
                original: finding.match_text.clone(),
                replacement_hint: display_hint(finding),
                occurrences: 1,
            });
            (
                allocation.token.as_str(),
                allocation.replacement_hint.as_ref(),
            )
        }
    }
}
