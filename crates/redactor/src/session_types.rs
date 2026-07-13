use serde::{Deserialize, Serialize};

use crate::{FindingKind, RedactionPolicy};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestorationEntry {
    pub token: String,
    pub kind: FindingKind,
    pub original: String,
    pub replacement_hint: Option<String>,
    pub occurrences: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionSession {
    pub version: u32,
    pub session_id: String,
    pub scope_id: String,
    pub external_id: Option<String>,
    pub fingerprint: String,
    pub redacted_fingerprint: String,
    pub redacted_text: String,
    #[serde(default)]
    pub policy: RedactionPolicy,
    pub entries: Vec<RestorationEntry>,
    #[serde(default)]
    pub issued_tokens: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RestoreResult {
    pub restored_text: String,
    pub restored_count: usize,
    pub skipped_tokens: Vec<String>,
    pub unresolved_tokens: Vec<String>,
    pub validation_errors: Vec<String>,
}

impl RestoreResult {
    pub fn is_valid(&self) -> bool {
        self.validation_errors.is_empty() && self.unresolved_tokens.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestorePermit {
    pub version: u32,
    pub permit_id: String,
    pub scope_id: String,
    pub external_id: Option<String>,
    pub issued_tokens: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SessionEntrySummary {
    pub token: String,
    pub kind: FindingKind,
    pub replacement_hint: Option<String>,
    pub occurrences: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SessionSummary {
    pub version: u32,
    pub session_id: String,
    pub scope_id: String,
    pub external_id: Option<String>,
    pub fingerprint: String,
    pub redacted_fingerprint: String,
    pub entry_count: usize,
    pub entries: Vec<SessionEntrySummary>,
}

impl From<&RedactionSession> for SessionSummary {
    fn from(session: &RedactionSession) -> Self {
        Self {
            version: session.version,
            session_id: session.session_id.clone(),
            scope_id: session.scope_id.clone(),
            external_id: session.external_id.clone(),
            fingerprint: session.fingerprint.clone(),
            redacted_fingerprint: session.redacted_fingerprint.clone(),
            entry_count: session.entries.len(),
            entries: session
                .entries
                .iter()
                .map(|entry| SessionEntrySummary {
                    token: entry.token.clone(),
                    kind: entry.kind,
                    replacement_hint: entry.replacement_hint.clone(),
                    occurrences: entry.occurrences,
                })
                .collect(),
        }
    }
}
