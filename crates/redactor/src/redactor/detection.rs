use crate::input::redactable_ranges;
use crate::types::Finding;

use super::Redactor;

#[derive(Debug, Default)]
pub(super) struct DetectionStats {
    pub(super) dropped_findings: usize,
    pub(super) llm_candidates_total: usize,
    pub(super) llm_request_failed: bool,
    pub(super) llm_error: Option<String>,
}

#[derive(Debug)]
pub(super) struct DetectionOutcome {
    pub(super) findings: Vec<Finding>,
    pub(super) stats: DetectionStats,
}

pub(super) fn detect_internal(
    redactor: &Redactor,
    text: &str,
    input_kind: crate::InputKind,
    source_path: Option<&str>,
) -> DetectionOutcome {
    let ranges = redactable_ranges(text, input_kind, source_path);
    if ranges.is_empty() {
        return DetectionOutcome {
            findings: Vec::new(),
            stats: DetectionStats::default(),
        };
    }

    let result = crate::detect::detect_with_policy(text, &redactor.policy, &ranges);
    let mut findings = result.findings;
    let mut stats = DetectionStats {
        dropped_findings: result.dropped_findings,
        ..DetectionStats::default()
    };

    if let Some(config) = &redactor.llm {
        match crate::llm::discover_candidates(config, text, redactor.policy.rules) {
            Ok(mut llm_findings) => {
                stats.llm_candidates_total += llm_findings.len();
                findings.append(&mut llm_findings);
            }
            Err(error) => {
                stats.llm_request_failed = true;
                stats.llm_error = Some(error.to_string());
            }
        }
        let (merged, dropped) = crate::detect::select_non_overlapping(findings);
        stats.dropped_findings += dropped;
        findings = merged;
    }

    DetectionOutcome { findings, stats }
}
