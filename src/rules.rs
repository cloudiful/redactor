use crate::types::{Finding, FindingKind, FindingSource};
use regex::Regex;
use std::sync::OnceLock;

pub fn detect_with_rules(text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    detect_contextual_assignments(text, &mut findings);
    propagate_repeated_secrets(text, &mut findings);
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
    detect_pattern(
        text,
        domain_regex(),
        FindingKind::Domain,
        76,
        &mut findings,
        is_valid_domain,
    );
    findings
}

fn propagate_repeated_secrets(text: &str, findings: &mut Vec<Finding>) {
    let repeated = findings
        .iter()
        .filter(|finding| finding.kind == FindingKind::Secret)
        .cloned()
        .collect::<Vec<_>>();

    for finding in repeated {
        for (start, _) in text.match_indices(&finding.match_text) {
            let end = start + finding.match_text.len();
            if findings
                .iter()
                .any(|existing| existing.start == start && existing.end == end)
            {
                continue;
            }

            findings.push(Finding {
                kind: FindingKind::Secret,
                source: FindingSource::Rule,
                match_text: finding.match_text.clone(),
                normalized_key: finding.normalized_key.clone(),
                confidence: 95,
                start,
                end,
            });
        }
    }
}

fn detect_contextual_assignments(text: &str, findings: &mut Vec<Finding>) {
    let mut offset = 0;

    for line in text.split_inclusive('\n') {
        for captures in assignment_regex().captures_iter(line) {
            let Some(key_match) = captures.name("key") else {
                continue;
            };
            let Some(value_match) = captures.name("value") else {
                continue;
            };

            let key = key_match.as_str();
            let value = trim_wrapped(value_match.as_str());
            if value.is_empty() {
                continue;
            }

            let kind = contextual_kind(key, value);
            if kind.is_none() {
                continue;
            }

            let value_start = value_match.start() + value_match.as_str().find(value).unwrap_or(0);
            let value_end = value_start + value.len();
            let normalized_key = normalize(kind.unwrap(), value);

            findings.push(Finding {
                kind: kind.unwrap(),
                source: FindingSource::Rule,
                match_text: value.to_string(),
                normalized_key,
                confidence: 99,
                start: offset + value_start,
                end: offset + value_end,
            });
        }

        offset += line.len();
    }
}

fn detect_pattern<F>(
    text: &str,
    regex: &Regex,
    kind: FindingKind,
    confidence: u8,
    findings: &mut Vec<Finding>,
    validator: F,
) where
    F: Fn(&str) -> bool,
{
    for matched in regex.find_iter(text) {
        let value = matched.as_str();
        if !validator(value) {
            continue;
        }

        findings.push(Finding {
            kind,
            source: FindingSource::Rule,
            match_text: value.to_string(),
            normalized_key: normalize(kind, value),
            confidence,
            start: matched.start(),
            end: matched.end(),
        });
    }
}

fn detect_emails(text: &str, findings: &mut Vec<Finding>) {
    for (index, ch) in text.char_indices() {
        if ch != '@' {
            continue;
        }

        let start = expand_left(text, index, is_email_local);
        let end = expand_right(text, index + ch.len_utf8(), is_email_domain);
        if end <= start || end - start < 5 {
            continue;
        }

        let value = &text[start..end];
        if !is_valid_email(value) {
            continue;
        }

        findings.push(Finding {
            kind: FindingKind::Email,
            source: FindingSource::Rule,
            match_text: value.to_string(),
            normalized_key: normalize(FindingKind::Email, value),
            confidence: 98,
            start,
            end,
        });
    }
}

fn detect_phones(text: &str, findings: &mut Vec<Finding>) {
    let chars = text.char_indices().collect::<Vec<_>>();
    let mut index = 0;

    while index < chars.len() {
        let (start_byte, ch) = chars[index];
        if !ch.is_ascii_digit() && ch != '+' {
            index += 1;
            continue;
        }

        let mut end_index = index;
        let mut digit_count = 0;

        while end_index < chars.len() {
            let current = chars[end_index].1;
            if current.is_ascii_digit() {
                digit_count += 1;
                end_index += 1;
                continue;
            }

            if matches!(current, ' ' | '\t' | '(' | ')' | '.' | '-') {
                end_index += 1;
                continue;
            }

            break;
        }

        if digit_count >= 7 {
            let end_byte = if end_index < chars.len() {
                chars[end_index].0
            } else {
                text.len()
            };
            let value = text[start_byte..end_byte].trim();
            if is_valid_phone(value) {
                let leading_trim = text[start_byte..end_byte].find(value).unwrap_or(0);
                let start = start_byte + leading_trim;
                let end = start + value.len();
                findings.push(Finding {
                    kind: FindingKind::Phone,
                    source: FindingSource::Rule,
                    match_text: value.to_string(),
                    normalized_key: normalize(FindingKind::Phone, value),
                    confidence: 80,
                    start,
                    end,
                });
            }
        }

        index = end_index.max(index + 1);
    }
}

fn contextual_kind(key: &str, value: &str) -> Option<FindingKind> {
    let lower = key.to_ascii_lowercase();

    if lower.contains("secret")
        || lower.contains("token")
        || lower.contains("password")
        || lower.contains("passwd")
        || lower.contains("api_key")
        || lower.contains("apikey")
        || lower.contains("private_key")
    {
        return Some(FindingKind::Secret);
    }

    if lower.contains("email") && is_valid_email(value) {
        return Some(FindingKind::Email);
    }

    if (lower.contains("domain") || lower.contains("host")) && is_valid_domain(value) {
        return Some(FindingKind::Domain);
    }

    if lower.contains("url") && url_regex().is_match(value) {
        return Some(FindingKind::Url);
    }

    if lower.contains("phone") && is_valid_phone(value) {
        return Some(FindingKind::Phone);
    }

    if lower.contains("name") && value.split_whitespace().count() >= 2 {
        return Some(FindingKind::Person);
    }

    if looks_like_secret(value) {
        return Some(FindingKind::Secret);
    }

    None
}

pub fn normalize(kind: FindingKind, value: &str) -> String {
    match kind {
        FindingKind::Domain => value.trim().trim_matches('.').to_ascii_lowercase(),
        FindingKind::Email => value.trim().to_ascii_lowercase(),
        FindingKind::Url => value.trim().to_string(),
        FindingKind::Ip | FindingKind::Cidr | FindingKind::Phone | FindingKind::Secret => {
            value.trim().to_string()
        }
        FindingKind::Person | FindingKind::Organization => {
            value.split_whitespace().collect::<Vec<_>>().join(" ")
        }
    }
}

pub fn select_non_overlapping(mut findings: Vec<Finding>) -> (Vec<Finding>, usize) {
    findings.sort_by(|left, right| {
        left.start
            .cmp(&right.start)
            .then_with(|| right.score().cmp(&left.score()))
            .then_with(|| (right.end - right.start).cmp(&(left.end - left.start)))
    });

    let mut selected = Vec::new();
    let mut dropped = 0;

    for finding in findings {
        if let Some(previous) = selected.last_mut() {
            if overlaps(previous, &finding) {
                if finding.score() > previous.score()
                    || (finding.score() == previous.score()
                        && (finding.end - finding.start) > (previous.end - previous.start))
                {
                    *previous = finding;
                } else {
                    dropped += 1;
                }
                continue;
            }
        }

        selected.push(finding);
    }

    selected.sort_by_key(|item| item.start);
    (selected, dropped)
}

fn overlaps(left: &Finding, right: &Finding) -> bool {
    left.start < right.end && right.start < left.end
}

fn looks_like_secret(value: &str) -> bool {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() < 20 || chars.len() > 128 {
        return false;
    }

    let has_upper = chars.iter().any(char::is_ascii_uppercase);
    let has_lower = chars.iter().any(char::is_ascii_lowercase);
    let has_digit = chars.iter().any(char::is_ascii_digit);
    let allowed = chars
        .iter()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '/' | '+'));

    allowed
        && has_digit
        && (has_upper || has_lower)
        && !(value.contains('.') || value.contains(':'))
}

fn trim_wrapped(value: &str) -> &str {
    value.trim().trim_matches('"').trim_matches('\'')
}

fn is_valid_domain(value: &str) -> bool {
    if is_valid_email(value) || value.contains("://") || value.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }

    let labels: Vec<&str> = value.trim_end_matches('.').split('.').collect();
    if labels.len() < 2 {
        return false;
    }

    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

fn is_valid_email(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    if local.is_empty() || domain.is_empty() || domain.ends_with('.') {
        return false;
    }
    if !local
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '%' | '+' | '-'))
    {
        return false;
    }
    is_valid_domain(domain)
}

fn is_valid_cidr(value: &str) -> bool {
    value.parse::<ipnet::IpNet>().is_ok()
}

fn is_valid_ip(value: &str) -> bool {
    value.parse::<std::net::IpAddr>().is_ok()
}

fn is_valid_phone(value: &str) -> bool {
    let digits = value.chars().filter(char::is_ascii_digit).count();
    (7..=15).contains(&digits)
}

fn assignment_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r"^\s*(?:-\s*)?(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)\s*[:=]\s*(?P<value>[^\n#]+?)\s*$",
        )
        .expect("assignment regex")
    })
}

fn url_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r#"\bhttps?://[^\s'"<>]+"#).expect("url regex"))
}

fn cidr_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b|\b[0-9A-Fa-f:]+/[0-9]{1,3}\b")
            .expect("cidr regex")
    })
}

fn ip_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b")
            .expect("ip regex")
    })
}

fn domain_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b")
            .expect("domain regex")
    })
}

fn expand_left(text: &str, mut index: usize, predicate: fn(char) -> bool) -> usize {
    while index > 0 {
        let previous = text[..index].char_indices().last();
        let Some((start, ch)) = previous else {
            break;
        };
        if !predicate(ch) {
            break;
        }
        index = start;
    }
    index
}

fn expand_right(text: &str, mut index: usize, predicate: fn(char) -> bool) -> usize {
    while index < text.len() {
        let Some(ch) = text[index..].chars().next() else {
            break;
        };
        if !predicate(ch) {
            break;
        }
        index += ch.len_utf8();
    }
    index
}

fn is_email_local(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '%' | '+' | '-')
}

fn is_email_domain(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-')
}
