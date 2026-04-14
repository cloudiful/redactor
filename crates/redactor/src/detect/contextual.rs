use crate::types::{Finding, FindingKind, FindingSource};
use std::collections::HashSet;

use super::regexes::{assignment_regex, url_regex};
use super::validators::{
    is_likely_code_expression, is_plain_config_value, is_valid_domain, is_valid_email,
    is_valid_phone, looks_like_secret, normalize, trim_wrapped,
};

pub(crate) fn propagate_repeated_secrets(text: &str, findings: &mut Vec<Finding>) {
    let mut known_ranges = findings
        .iter()
        .map(|finding| (finding.start, finding.end))
        .collect::<HashSet<_>>();
    let mut seen_values = HashSet::new();
    let repeated = findings
        .iter()
        .filter(|finding| finding.kind == FindingKind::Secret)
        .filter(|finding| seen_values.insert(finding.match_text.clone()))
        .map(|finding| (finding.match_text.clone(), finding.normalized_key.clone()))
        .collect::<Vec<_>>();

    for (match_text, normalized_key) in repeated {
        for (start, _) in text.match_indices(&match_text) {
            let end = start + match_text.len();
            if !known_ranges.insert((start, end)) {
                continue;
            }

            findings.push(Finding {
                kind: FindingKind::Secret,
                source: FindingSource::Rule,
                match_text: match_text.clone(),
                normalized_key: normalized_key.clone(),
                confidence: 95,
                start,
                end,
            });
        }
    }
}

pub(crate) fn detect_contextual_assignments(
    text: &str,
    findings: &mut Vec<Finding>,
    person_detection: bool,
) {
    let mut offset = 0;

    for line in text.split_inclusive('\n') {
        for captures in assignment_regex().captures_iter(line) {
            let Some(key_match) = captures.name("key") else {
                continue;
            };
            let Some(value_match) = captures.name("value") else {
                continue;
            };
            let Some(separator_match) = captures.name("separator") else {
                continue;
            };

            let key = key_match.as_str();
            let raw_value = value_match.as_str().trim();
            let value = trim_wrapped(raw_value);
            if value.is_empty() {
                continue;
            }

            let separator = separator_match.as_str().chars().next().unwrap_or('=');
            let Some(kind) = contextual_kind(key, value, raw_value, separator, person_detection)
            else {
                continue;
            };

            let value_start = value_match.start() + value_match.as_str().find(value).unwrap_or(0);
            let value_end = value_start + value.len();

            findings.push(Finding {
                kind,
                source: FindingSource::Rule,
                match_text: value.to_string(),
                normalized_key: normalize(kind, value),
                confidence: 99,
                start: offset + value_start,
                end: offset + value_end,
            });
        }

        offset += line.len();
    }
}

fn contextual_kind(
    key: &str,
    value: &str,
    raw_value: &str,
    separator: char,
    person_detection: bool,
) -> Option<FindingKind> {
    let lower = key.to_ascii_lowercase();

    if lower.contains("secret")
        || lower.contains("token")
        || lower.contains("password")
        || lower.contains("passwd")
        || lower.contains("api_key")
        || lower.contains("apikey")
        || lower.contains("private_key")
    {
        return contextual_secret_kind(value, raw_value, separator);
    }

    if lower.contains("email") && is_valid_email(value) {
        return Some(FindingKind::Email);
    }

    if (lower.contains("domain") || lower.contains("host"))
        && is_plain_config_value(raw_value)
        && is_valid_domain(value)
    {
        return Some(FindingKind::Domain);
    }

    if lower.contains("url") && url_regex().is_match(value) {
        return Some(FindingKind::Url);
    }

    if lower.contains("phone") && is_valid_phone(value) {
        return Some(FindingKind::Phone);
    }

    if person_detection && lower.contains("name") && value.split_whitespace().count() >= 2 {
        return Some(FindingKind::Person);
    }

    looks_like_secret(value).then_some(FindingKind::Secret)
}

fn contextual_secret_kind(value: &str, raw_value: &str, separator: char) -> Option<FindingKind> {
    if looks_like_secret(value) {
        return Some(FindingKind::Secret);
    }

    if separator == ':'
        && (is_likely_code_expression(raw_value) || !is_plain_config_value(raw_value))
    {
        return None;
    }

    (separator == '=' && is_plain_config_value(raw_value) && !is_likely_code_expression(raw_value))
        .then_some(FindingKind::Secret)
}

#[cfg(test)]
mod tests {
    use super::propagate_repeated_secrets;
    use crate::types::{Finding, FindingKind, FindingSource};

    #[test]
    fn repeated_secret_propagation_adds_missing_occurrences_once() {
        let text = "token=ABCDEF1234567890XYZ token=ABCDEF1234567890XYZ";
        let mut findings = vec![Finding {
            kind: FindingKind::Secret,
            source: FindingSource::Rule,
            match_text: "ABCDEF1234567890XYZ".to_string(),
            normalized_key: "ABCDEF1234567890XYZ".to_string(),
            confidence: 99,
            start: 6,
            end: 25,
        }];

        propagate_repeated_secrets(text, &mut findings);
        propagate_repeated_secrets(text, &mut findings);

        let secret_ranges = findings
            .iter()
            .filter(|finding| finding.kind == FindingKind::Secret)
            .map(|finding| (finding.start, finding.end))
            .collect::<Vec<_>>();
        assert_eq!(secret_ranges, vec![(6, 25), (32, 51)]);
    }
}
