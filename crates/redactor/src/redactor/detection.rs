use crate::detect::{detect_with_rules, select_non_overlapping};
use crate::input::redactable_ranges;
use crate::llm::discover_candidates;
use crate::{Finding, InputKind, RedactorError};

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
    input_kind: InputKind,
) -> Result<DetectionOutcome, RedactorError> {
    let ranges = redactable_ranges(text, input_kind);
    if ranges.is_empty() {
        return Ok(DetectionOutcome {
            findings: Vec::new(),
            stats: DetectionStats::default(),
        });
    }
    if ranges.len() == 1 && ranges[0].start == 0 && ranges[0].end == text.len() {
        return Ok(detect_fragment(redactor, text));
    }

    let mut findings = Vec::new();
    let mut stats = DetectionStats::default();
    let mut has_cross_fragment_overlap = false;

    for range in ranges {
        let fragment = &text[range.clone()];
        let fragment_outcome = detect_fragment(redactor, fragment);
        let offset = range.start;
        findings.extend(fragment_outcome.findings.into_iter().map(|mut finding| {
            finding.start += offset;
            finding.end += offset;
            finding
        }));
        if let (Some(previous), Some(current)) = (
            findings.get(findings.len().saturating_sub(2)),
            findings.last(),
        ) {
            has_cross_fragment_overlap |= previous.end > current.start;
        }
        stats.dropped_findings += fragment_outcome.stats.dropped_findings;
        stats.llm_candidates_total += fragment_outcome.stats.llm_candidates_total;
        stats.llm_request_failed |= fragment_outcome.stats.llm_request_failed;
        if stats.llm_error.is_none() {
            stats.llm_error = fragment_outcome.stats.llm_error;
        }
    }

    if has_cross_fragment_overlap {
        let (findings, dropped) = select_non_overlapping(findings);
        stats.dropped_findings += dropped;
        Ok(DetectionOutcome { findings, stats })
    } else {
        Ok(DetectionOutcome { findings, stats })
    }
}

fn detect_fragment(redactor: &Redactor, text: &str) -> DetectionOutcome {
    let mut findings = detect_with_rules(text, redactor.person_detection);
    let mut stats = DetectionStats::default();
    if let Some(config) = &redactor.llm {
        match discover_candidates(config, text, redactor.person_detection) {
            Ok(mut llm_findings) => {
                stats.llm_candidates_total += llm_findings.len();
                findings.append(&mut llm_findings);
            }
            Err(error) => {
                stats.llm_request_failed = true;
                stats.llm_error = Some(error.to_string());
            }
        }
    }

    let (findings, dropped) = select_non_overlapping(findings);
    stats.dropped_findings = dropped;

    DetectionOutcome { findings, stats }
}
