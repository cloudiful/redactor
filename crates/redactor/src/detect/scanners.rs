use crate::types::{Finding, FindingKind, FindingSource};
use regex::Regex;

use super::regexes::domain_regex;
use super::validators::{
    is_email_domain, is_email_local, is_valid_domain_match, is_valid_email, is_valid_phone,
    normalize,
};

pub(crate) fn detect_pattern<F>(
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

pub(crate) fn detect_emails(text: &str, findings: &mut Vec<Finding>) {
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

pub(crate) fn detect_phones(text: &str, findings: &mut Vec<Finding>) {
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
            if current == '+' && end_index == index {
                end_index += 1;
                continue;
            }

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
            let end_byte = chars
                .get(end_index)
                .map(|(offset, _)| *offset)
                .unwrap_or(text.len());
            let segment = &text[start_byte..end_byte];
            let value = segment.trim();
            if is_valid_phone(value) {
                let leading_trim = segment.find(value).unwrap_or(0);
                let start = start_byte + leading_trim;
                let end = start + value.len();
                let previous = text[..start].chars().next_back();
                let next = text[end..].chars().next();
                if matches!(previous, Some(ch) if ch.is_ascii_alphanumeric())
                    || matches!(next, Some(ch) if ch.is_ascii_alphanumeric())
                {
                    index = end_index.max(index + 1);
                    continue;
                }

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

pub(crate) fn detect_domains(text: &str, findings: &mut Vec<Finding>) {
    for matched in domain_regex().find_iter(text) {
        if !is_valid_domain_match(text, matched.start(), matched.end()) {
            continue;
        }

        let value = matched.as_str();
        findings.push(Finding {
            kind: FindingKind::Domain,
            source: FindingSource::Rule,
            match_text: value.to_string(),
            normalized_key: normalize(FindingKind::Domain, value),
            confidence: 76,
            start: matched.start(),
            end: matched.end(),
        });
    }
}

fn expand_left(text: &str, mut index: usize, predicate: fn(char) -> bool) -> usize {
    while index > 0 {
        let Some((start, ch)) = text[..index].char_indices().last() else {
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
