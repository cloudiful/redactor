use crate::types::{Finding, FindingKind};

use super::contextual::{detect_contextual_assignments, propagate_repeated_secrets};
use super::regexes::{cidr_regex, ip_regex, secret_regex, url_regex};
use super::scanners::{detect_domains, detect_emails, detect_pattern, detect_phones};
use super::validators::{is_valid_cidr, is_valid_ip, looks_like_secret};

pub(crate) fn detect_with_rules(text: &str, person_detection: bool) -> Vec<Finding> {
    let mut findings = Vec::new();
    detect_contextual_assignments(text, &mut findings, person_detection);
    propagate_repeated_secrets(text, &mut findings);
    detect_pattern(
        text,
        secret_regex(),
        FindingKind::Secret,
        92,
        &mut findings,
        looks_like_secret,
    );
    detect_emails(text, &mut findings);
    detect_pattern(
        text,
        url_regex(),
        FindingKind::Url,
        96,
        &mut findings,
        |_| true,
    );
    detect_pattern(
        text,
        cidr_regex(),
        FindingKind::Cidr,
        94,
        &mut findings,
        is_valid_cidr,
    );
    detect_pattern(
        text,
        ip_regex(),
        FindingKind::Ip,
        90,
        &mut findings,
        is_valid_ip,
    );
    detect_phones(text, &mut findings);
    detect_domains(text, &mut findings);
    findings
}
