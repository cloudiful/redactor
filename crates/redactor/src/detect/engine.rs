use std::collections::HashSet;

use crate::input::RedactableRange;
use crate::types::{Finding, RedactionPolicy, RedactionRules};

use super::contextual::{detect_contextual_assignments, propagate_repeated_secrets};
use super::custom::{CompiledCustomStrings, detect_custom_files, detect_custom_strings};
use super::regexes::{cidr_regex, ip_regex, secret_regex, url_regex};
use super::scanners::{detect_domains, detect_emails, detect_pattern, detect_phones};
use super::select_non_overlapping;
use super::validators::{is_valid_cidr, is_valid_ip, looks_like_secret};

pub(crate) struct PolicyDetectionResult {
    pub findings: Vec<Finding>,
    pub dropped_findings: usize,
}

pub(crate) fn detect_with_policy(
    text: &str,
    policy: &RedactionPolicy,
    custom_strings: &CompiledCustomStrings,
    custom_files: &HashSet<String>,
    ranges: &[RedactableRange],
) -> PolicyDetectionResult {
    let mut findings = Vec::new();

    if !custom_files.is_empty() {
        findings.extend(detect_custom_files(text, ranges, custom_files));
    }

    for range_info in ranges {
        let file_matches_custom = range_info
            .file_path
            .as_ref()
            .map(|p| custom_files.contains(p))
            .unwrap_or(false);

        if file_matches_custom {
            continue;
        }

        let fragment = &text[range_info.range.clone()];
        let offset = range_info.range.start;
        let mut fragment_findings = detect_builtins(fragment, &policy.rules);
        fragment_findings.extend(detect_custom_strings(fragment, custom_strings));

        for finding in &mut fragment_findings {
            finding.start += offset;
            finding.end += offset;
        }
        findings.extend(fragment_findings);
    }

    let (findings, dropped) = select_non_overlapping(findings);
    PolicyDetectionResult {
        findings,
        dropped_findings: dropped,
    }
}

fn detect_builtins(text: &str, rules: &RedactionRules) -> Vec<Finding> {
    let mut findings = Vec::new();
    detect_contextual_assignments(text, &mut findings, *rules);
    if rules.secret {
        propagate_repeated_secrets(text, &mut findings);
        detect_pattern(
            text,
            secret_regex(),
            crate::types::FindingKind::Secret,
            92,
            &mut findings,
            looks_like_secret,
        );
    }
    if rules.email {
        detect_emails(text, &mut findings);
    }
    if rules.url {
        detect_pattern(
            text,
            url_regex(),
            crate::types::FindingKind::Url,
            96,
            &mut findings,
            |_| true,
        );
    }
    if rules.cidr {
        detect_pattern(
            text,
            cidr_regex(),
            crate::types::FindingKind::Cidr,
            94,
            &mut findings,
            is_valid_cidr,
        );
    }
    if rules.ip {
        detect_pattern(
            text,
            ip_regex(),
            crate::types::FindingKind::Ip,
            90,
            &mut findings,
            is_valid_ip,
        );
    }
    if rules.phone {
        detect_phones(text, &mut findings);
    }
    if rules.domain {
        detect_domains(text, &mut findings);
    }
    findings
}
