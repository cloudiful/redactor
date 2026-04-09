use serde::Serialize;
use std::collections::BTreeMap;
use std::ops::Range;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
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

impl FindingKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Domain => "domain",
            Self::Url => "url",
            Self::Email => "email",
            Self::Ip => "ip",
            Self::Cidr => "cidr",
            Self::Phone => "phone",
            Self::Person => "person",
            Self::Organization => "organization",
        }
    }

    pub fn priority(self) -> u8 {
        match self {
            Self::Secret => 100,
            Self::Url => 90,
            Self::Email => 85,
            Self::Cidr => 80,
            Self::Ip => 75,
            Self::Domain => 70,
            Self::Phone => 60,
            Self::Person => 50,
            Self::Organization => 45,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplacementStrategy {
    StablePlaceholder,
    StableExampleDomain,
    StableExampleEmail,
    StableUrlRewrite,
    StableIpRewrite,
    StablePhoneMask,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AppliedReplacement {
    pub kind: FindingKind,
    pub original: String,
    pub replacement: String,
    pub strategy: ReplacementStrategy,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RedactionStats {
    pub total_findings: usize,
    pub applied_replacements: usize,
    pub dropped_findings: usize,
    pub llm_candidates_accepted: usize,
    pub llm_candidates_rejected: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RedactionResult {
    pub redacted_text: String,
    pub findings: Vec<Finding>,
    pub applied_replacements: Vec<AppliedReplacement>,
    pub stats: RedactionStats,
}

#[derive(Debug, Clone)]
pub struct ReplacementEngine {
    secret_map: BTreeMap<String, String>,
    domain_map: BTreeMap<String, String>,
    email_map: BTreeMap<String, String>,
    url_map: BTreeMap<String, String>,
    ip_map: BTreeMap<String, String>,
    phone_map: BTreeMap<String, String>,
}

impl ReplacementEngine {
    pub fn new() -> Self {
        Self {
            secret_map: BTreeMap::new(),
            domain_map: BTreeMap::new(),
            email_map: BTreeMap::new(),
            url_map: BTreeMap::new(),
            ip_map: BTreeMap::new(),
            phone_map: BTreeMap::new(),
        }
    }

    pub fn map_mut(&mut self, kind: FindingKind) -> &mut BTreeMap<String, String> {
        match kind {
            FindingKind::Secret | FindingKind::Person | FindingKind::Organization => {
                &mut self.secret_map
            }
            FindingKind::Domain => &mut self.domain_map,
            FindingKind::Email => &mut self.email_map,
            FindingKind::Url => &mut self.url_map,
            FindingKind::Ip | FindingKind::Cidr => &mut self.ip_map,
            FindingKind::Phone => &mut self.phone_map,
        }
    }
}
