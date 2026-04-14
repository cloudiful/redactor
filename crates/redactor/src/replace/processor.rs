use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use crate::types::{
    AppliedReplacement, Finding, FindingKind, RedactionSession, ReplacementStrategy,
    RestorationEntry,
};

use super::hints::display_hint;
use super::token::{format_token, random_id, sha256_hex};

#[derive(Debug)]
pub(crate) struct ReplacementOutput {
    pub redacted_text: String,
    pub applied_replacements: Vec<AppliedReplacement>,
    pub session: RedactionSession,
}

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
}

#[derive(Debug, Default)]
pub(crate) struct ReplacementProcessor {
    state: SessionState,
    applied_replacements: Vec<AppliedReplacement>,
}

impl ReplacementProcessor {
    pub(crate) fn new() -> Self {
        Self::default()
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

    pub(crate) fn build_session(
        &self,
        original_text: &str,
        redacted_text: &str,
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
            version: 1,
            session_id: random_id(),
            fingerprint: sha256_hex(original_text),
            redacted_fingerprint: sha256_hex(redacted_text),
            redacted_text: redacted_text.to_string(),
            entries,
        }
    }

    fn into_applied_replacements(self) -> Vec<AppliedReplacement> {
        self.applied_replacements
    }
}

pub(crate) fn apply_replacements(text: &str, findings: &[Finding]) -> ReplacementOutput {
    let mut processor = ReplacementProcessor::new();
    let redacted_text = processor.redact_fragment(text, findings);
    let session = processor.build_session(text, &redacted_text);
    let applied_replacements = processor.into_applied_replacements();

    ReplacementOutput {
        redacted_text,
        applied_replacements,
        session,
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
                token: format_token(finding.kind, *counter),
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
