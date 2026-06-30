use regex::Regex;
use std::collections::BTreeMap;

use crate::types::{
    CustomFileRule, CustomStringMatch, CustomStringRule, CustomStringScope, Finding, FindingKind,
    FindingSource,
};

use super::validators::normalize;

pub(crate) fn detect_custom_strings(text: &str, rules: &[CustomStringRule]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut line_matches = BTreeMap::<(usize, usize), Finding>::new();
    for rule in rules {
        match rule.match_type {
            CustomStringMatch::Exact => {
                let pattern = regex::escape(&rule.pattern);
                if let Ok(re) = Regex::new(&pattern) {
                    for mat in re.find_iter(text) {
                        push_custom_string_finding(
                            &mut findings,
                            &mut line_matches,
                            text,
                            mat.start(),
                            mat.end(),
                            mat.as_str(),
                            rule,
                        );
                    }
                }
            }
            CustomStringMatch::Contains => {
                let pattern = regex::escape(&rule.pattern);
                if let Ok(re) = Regex::new(&format!("(?i){pattern}")) {
                    for mat in re.find_iter(text) {
                        push_custom_string_finding(
                            &mut findings,
                            &mut line_matches,
                            text,
                            mat.start(),
                            mat.end(),
                            mat.as_str(),
                            rule,
                        );
                    }
                }
            }
            CustomStringMatch::Regex => {
                if let Ok(re) = Regex::new(&rule.pattern) {
                    for mat in re.find_iter(text) {
                        push_custom_string_finding(
                            &mut findings,
                            &mut line_matches,
                            text,
                            mat.start(),
                            mat.end(),
                            mat.as_str(),
                            rule,
                        );
                    }
                }
            }
        }
    }
    findings.extend(line_matches.into_values());
    findings
}

fn push_custom_string_finding(
    findings: &mut Vec<Finding>,
    line_matches: &mut BTreeMap<(usize, usize), Finding>,
    text: &str,
    start: usize,
    end: usize,
    match_text: &str,
    rule: &CustomStringRule,
) {
    let (finding_start, finding_end, finding_text) = match rule.scope {
        CustomStringScope::Text => (start, end, match_text.to_string()),
        CustomStringScope::Line => {
            let line_start = text[..start].rfind('\n').map(|i| i + 1).unwrap_or(0);
            let line_end = text[end..]
                .find('\n')
                .map(|i| end + i)
                .unwrap_or(text.len());
            let key = (line_start, line_end);
            line_matches.entry(key).or_insert_with(|| Finding {
                kind: FindingKind::CustomString,
                source: FindingSource::Rule,
                match_text: text[line_start..line_end].to_string(),
                normalized_key: normalize(FindingKind::CustomString, &text[line_start..line_end]),
                confidence: 100,
                start: line_start,
                end: line_end,
            });
            return;
        }
    };

    findings.push(Finding {
        kind: FindingKind::CustomString,
        source: FindingSource::Rule,
        match_text: finding_text,
        normalized_key: normalize(FindingKind::CustomString, &rule.pattern),
        confidence: 100,
        start: finding_start,
        end: finding_end,
    });
}

pub(crate) fn detect_custom_files(
    text: &str,
    ranges: &[super::super::input::RedactableRange],
    rules: &[CustomFileRule],
) -> Vec<Finding> {
    if rules.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    for range_info in ranges {
        let Some(ref file_path) = range_info.file_path else {
            continue;
        };
        if !rules.iter().any(|rule| rule.path == file_path.as_str()) {
            continue;
        }

        let content = &text[range_info.range.clone()];
        findings.push(Finding {
            kind: FindingKind::CustomFile,
            source: FindingSource::Rule,
            match_text: content.to_string(),
            normalized_key: format!("file:{file_path}"),
            confidence: 100,
            start: range_info.range.start,
            end: range_info.range.end,
        });
    }
    findings
}
