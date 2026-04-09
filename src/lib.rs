mod llm;
mod replacement;
mod rules;
mod types;

pub use llm::LlmConfig;
pub use types::{
    AppliedReplacement, Finding, FindingKind, FindingSource, RedactionResult, RedactionStats,
    ReplacementStrategy,
};

use llm::discover_candidates;
use replacement::apply_replacements;
use rules::{detect_with_rules, select_non_overlapping};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RedactorError {
    #[error("llm error: {0}")]
    Llm(String),
}

#[derive(Debug, Clone, Default)]
pub struct RedactorBuilder {
    llm: Option<LlmConfig>,
}

impl RedactorBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_llm(mut self, config: LlmConfig) -> Self {
        self.llm = Some(config);
        self
    }

    pub fn build(self) -> Redactor {
        Redactor { llm: self.llm }
    }
}

#[derive(Debug, Clone)]
pub struct Redactor {
    llm: Option<LlmConfig>,
}

impl Redactor {
    pub fn redact(&self, text: &str) -> Result<RedactionResult, RedactorError> {
        let mut findings = detect_with_rules(text);
        let rule_count = findings.len();
        let mut stats = RedactionStats {
            total_findings: findings.len(),
            ..RedactionStats::default()
        };

        if let Some(config) = &self.llm {
            match discover_candidates(config, text) {
                Ok(mut llm_findings) => {
                    stats.total_findings += llm_findings.len();
                    findings.append(&mut llm_findings);
                }
                Err(_error) => {}
            }
        }

        let total_before_merge = findings.len();
        let (findings, dropped) = select_non_overlapping(findings);
        stats.llm_candidates_accepted = findings
            .iter()
            .filter(|finding| matches!(finding.source, FindingSource::Llm))
            .count();
        stats.llm_candidates_rejected = total_before_merge
            .saturating_sub(rule_count)
            .saturating_sub(stats.llm_candidates_accepted);
        let (redacted_text, applied_replacements) = apply_replacements(text, &findings);
        stats.total_findings = total_before_merge;
        stats.applied_replacements = applied_replacements.len();
        stats.dropped_findings = dropped;

        Ok(RedactionResult {
            redacted_text,
            findings,
            applied_replacements,
            stats,
        })
    }

    pub fn detect(&self, text: &str) -> Result<Vec<Finding>, RedactorError> {
        let mut findings = detect_with_rules(text);
        if let Some(config) = &self.llm {
            if let Ok(mut llm_findings) = discover_candidates(config, text) {
                findings.append(&mut llm_findings);
            }
        }
        let (findings, _) = select_non_overlapping(findings);
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::{RedactorBuilder, ReplacementStrategy};

    const SAMPLE: &str = r#"  nctalk:
    image: nexus.cloud1ful.com/ghcr/nextcloud-releases/aio-talk
    container_name: nctalk
    networks:
      - internal
    ports:
      - 3478:3478/tcp
      - 3478:3478/udp
    environment:
      - NC_DOMAIN=nextcloud.cloud1ful.com
      - TALK_HOST=talk.cloud1ful.com
      - TURN_SECRET=EJ2QEVC6AKELW0k2kkVY4NgGKONC
      - SIGNALING_SECRET=W1DDPgM3ymrHuGMDev6N4pW9Re96
      - TZ=Asia/Shanghai
      - TALK_PORT=3478
      - INTERNAL_SECRET=ulDo3hHfxb6tS1z02RdZmf6bAD2w
      - IPv4_ADDRESS_TALK=172.18.0.0/24
    restart: unless-stopped
    depends_on:
      - nextcloud
"#;

    #[test]
    fn redacts_compose_sample_without_reformatting() {
        let result = RedactorBuilder::new()
            .build()
            .redact(SAMPLE)
            .expect("redact sample");

        assert!(result.redacted_text.contains("nextcloud.example.com"));
        assert!(result.redacted_text.contains("talk.example.com"));
        assert!(result.redacted_text.contains("<SECRET:1>"));
        assert!(result.redacted_text.contains("<SECRET:2>"));
        assert!(result.redacted_text.contains("<SECRET:3>"));
        assert!(result.redacted_text.contains("198.51.100."));
        assert!(
            !result
                .redacted_text
                .contains("EJ2QEVC6AKELW0k2kkVY4NgGKONC")
        );
        assert_eq!(SAMPLE.lines().count(), result.redacted_text.lines().count());
    }

    #[test]
    fn keeps_replacements_stable_for_repeated_values() {
        let input = "TOKEN=abcDEF1234567890\nagain=abcDEF1234567890\nHOST=api.cloud1ful.com\nURL=https://api.cloud1ful.com/v1";
        let result = RedactorBuilder::new()
            .build()
            .redact(input)
            .expect("redact repeated");

        let lines: Vec<&str> = result.redacted_text.lines().collect();
        assert_eq!(lines[0], "TOKEN=<SECRET:1>");
        assert_eq!(lines[1], "again=<SECRET:1>");
        assert!(lines[2].ends_with("api.example.com"));
        assert!(lines[3].contains("https://api.example.com/v1"));
    }

    #[test]
    fn redacts_emails_phones_and_urls() {
        let input =
            "Email: alice@example.org Phone: +86 138 0013 8000 URL: https://internal.example.org/a";
        let result = RedactorBuilder::new()
            .build()
            .redact(input)
            .expect("redact text");

        assert!(result.redacted_text.contains("alice@example.com"));
        assert!(result.redacted_text.contains("1550000"));
        assert!(
            result
                .redacted_text
                .contains("https://internal.example.com/a")
        );
        assert!(
            result
                .applied_replacements
                .iter()
                .any(|item| item.strategy == ReplacementStrategy::StableExampleEmail)
        );
    }
}
