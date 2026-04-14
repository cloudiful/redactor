use crate::{Finding, FindingSource, RedactionStats};

use super::detection::DetectionStats;

pub(super) fn stats_for(
    llm_configured: bool,
    findings: &[Finding],
    detection_stats: DetectionStats,
) -> RedactionStats {
    let llm_candidates_accepted = findings
        .iter()
        .filter(|finding| matches!(finding.source, FindingSource::Llm))
        .count();

    RedactionStats {
        total_findings: findings.len(),
        applied_replacements: findings.len(),
        dropped_findings: detection_stats.dropped_findings,
        llm_configured,
        llm_request_failed: detection_stats.llm_request_failed,
        llm_candidates_accepted,
        llm_candidates_rejected: detection_stats
            .llm_candidates_total
            .saturating_sub(llm_candidates_accepted),
        llm_error: detection_stats.llm_error,
    }
}
