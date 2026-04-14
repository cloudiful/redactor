use serde::{Deserialize, Serialize};
use std::ops::Range;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    Secret,
    Domain,
    Url,
    Email,
    Ip,
    Cidr,
    Phone,
    Person,
    Organization,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FindingKindMeta {
    label: &'static str,
    token_label: &'static str,
    priority: u8,
    containment_priority: u8,
}

impl FindingKind {
    const fn meta(self) -> FindingKindMeta {
        match self {
            Self::Secret => FindingKindMeta {
                label: "secret",
                token_label: "SECRET",
                priority: 100,
                containment_priority: 75,
            },
            Self::Domain => FindingKindMeta {
                label: "domain",
                token_label: "DOMAIN",
                priority: 70,
                containment_priority: 80,
            },
            Self::Url => FindingKindMeta {
                label: "url",
                token_label: "URL",
                priority: 90,
                containment_priority: 100,
            },
            Self::Email => FindingKindMeta {
                label: "email",
                token_label: "EMAIL",
                priority: 85,
                containment_priority: 95,
            },
            Self::Ip => FindingKindMeta {
                label: "ip",
                token_label: "IP",
                priority: 75,
                containment_priority: 85,
            },
            Self::Cidr => FindingKindMeta {
                label: "cidr",
                token_label: "CIDR",
                priority: 80,
                containment_priority: 90,
            },
            Self::Phone => FindingKindMeta {
                label: "phone",
                token_label: "PHONE",
                priority: 60,
                containment_priority: 70,
            },
            Self::Person => FindingKindMeta {
                label: "person",
                token_label: "PERSON",
                priority: 50,
                containment_priority: 50,
            },
            Self::Organization => FindingKindMeta {
                label: "organization",
                token_label: "ORG",
                priority: 45,
                containment_priority: 45,
            },
        }
    }

    pub fn label(self) -> &'static str {
        self.meta().label
    }

    pub fn token_label(self) -> &'static str {
        self.meta().token_label
    }

    pub fn priority(self) -> u8 {
        self.meta().priority
    }

    pub fn containment_priority(self) -> u8 {
        self.meta().containment_priority
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSource {
    Rule,
    Llm,
}

impl FindingSource {
    pub fn bonus(self) -> u8 {
        match self {
            Self::Rule => 10,
            Self::Llm => 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub kind: FindingKind,
    pub source: FindingSource,
    pub match_text: String,
    pub normalized_key: String,
    pub confidence: u8,
    pub start: usize,
    pub end: usize,
}

impl Finding {
    pub fn range(&self) -> Range<usize> {
        self.start..self.end
    }

    pub fn score(&self) -> u16 {
        u16::from(self.kind.priority())
            + u16::from(self.source.bonus())
            + u16::from(self.confidence)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplacementStrategy {
    StructuredToken,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedReplacement {
    pub kind: FindingKind,
    #[serde(skip_serializing)]
    pub original: String,
    pub replacement: String,
    pub strategy: ReplacementStrategy,
    pub display_value: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionStats {
    pub total_findings: usize,
    pub applied_replacements: usize,
    pub dropped_findings: usize,
    pub llm_configured: bool,
    pub llm_request_failed: bool,
    pub llm_candidates_accepted: usize,
    pub llm_candidates_rejected: usize,
    pub llm_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionResult {
    pub redacted_text: String,
    pub findings: Vec<Finding>,
    pub applied_replacements: Vec<AppliedReplacement>,
    pub stats: RedactionStats,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionArtifact {
    pub result: RedactionResult,
    pub session: RedactionSession,
}

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
    pub fingerprint: String,
    pub redacted_fingerprint: String,
    pub redacted_text: String,
    pub entries: Vec<RestorationEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreResult {
    pub restored_text: String,
    pub restored_count: usize,
    pub unresolved_tokens: Vec<String>,
    pub validation_errors: Vec<String>,
}

impl RestoreResult {
    pub fn is_valid(&self) -> bool {
        self.validation_errors.is_empty() && self.unresolved_tokens.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEntrySummary {
    pub token: String,
    pub kind: FindingKind,
    pub replacement_hint: Option<String>,
    pub occurrences: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSummary {
    pub version: u32,
    pub session_id: String,
    pub fingerprint: String,
    pub redacted_fingerprint: String,
    pub entry_count: usize,
    pub entries: Vec<SessionEntrySummary>,
}
