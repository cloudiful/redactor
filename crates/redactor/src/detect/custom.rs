use regex::{Regex, RegexSet};
use std::collections::BTreeMap;

use crate::types::{
    CustomFileRule, CustomStringMatch, CustomStringRule, CustomStringScope, Finding, FindingKind,
    FindingSource,
};

use super::validators::normalize;

#[derive(Debug)]
struct CompiledRule {
    index: usize,
    rule: CustomStringRule,
    regex: Regex,
}

#[derive(Debug, Default)]
struct CompiledRuleSet {
    set: Option<RegexSet>,
    rules: Vec<CompiledRule>,
}

#[derive(Debug, Default)]
pub(crate) struct CompiledCustomStrings {
    exact: CompiledRuleSet,
    contains: CompiledRuleSet,
    regex: Vec<CompiledRule>,
}

impl CompiledCustomStrings {
    pub(crate) fn new(rules: &[CustomStringRule]) -> Self {
        let exact = compile_rule_set(rules, CustomStringMatch::Exact, |pattern| {
            regex::escape(pattern)
        });
        let contains = compile_rule_set(rules, CustomStringMatch::Contains, |pattern| {
            format!("(?i:{})", regex::escape(pattern))
        });
        let regex = rules
            .iter()
            .enumerate()
            .filter(|(_, rule)| rule.match_type == CustomStringMatch::Regex)
            .filter_map(|(index, rule)| {
                Regex::new(&rule.pattern).ok().map(|regex| CompiledRule {
                    index,
                    rule: rule.clone(),
                    regex,
                })
            })
            .collect();
        Self {
            exact,
            contains,
            regex,
        }
    }
}

fn compile_rule_set(
    rules: &[CustomStringRule],
    match_type: CustomStringMatch,
    pattern_for: impl Fn(&str) -> String,
) -> CompiledRuleSet {
    let compiled = rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| rule.match_type == match_type)
        .filter_map(|(index, rule)| {
            let pattern = pattern_for(&rule.pattern);
            Regex::new(&pattern).ok().map(|regex| CompiledRule {
                index,
                rule: rule.clone(),
                regex,
            })
        })
        .collect::<Vec<_>>();
    let set = (!compiled.is_empty())
        .then(|| RegexSet::new(compiled.iter().map(|rule| rule.regex.as_str())).ok())
        .flatten();
    CompiledRuleSet {
        set,
        rules: compiled,
    }
}

pub(crate) fn detect_custom_strings(text: &str, compiled: &CompiledCustomStrings) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut line_matches = BTreeMap::<(usize, usize), Finding>::new();
    let mut candidates = matched_rules(text, &compiled.exact);
    candidates.extend(matched_rules(text, &compiled.contains));
    candidates.extend(&compiled.regex);
    candidates.sort_unstable_by_key(|rule| rule.index);
    for compiled_rule in candidates {
        push_rule_matches(text, compiled_rule, &mut findings, &mut line_matches);
    }
    findings.extend(line_matches.into_values());
    findings
}

fn matched_rules<'a>(text: &str, compiled: &'a CompiledRuleSet) -> Vec<&'a CompiledRule> {
    let Some(set) = &compiled.set else {
        return compiled.rules.iter().collect();
    };
    set.matches(text)
        .iter()
        .filter_map(|index| compiled.rules.get(index))
        .collect()
}

fn push_rule_matches(
    text: &str,
    compiled: &CompiledRule,
    findings: &mut Vec<Finding>,
    line_matches: &mut BTreeMap<(usize, usize), Finding>,
) {
    for mat in compiled.regex.find_iter(text) {
        push_custom_string_finding(
            findings,
            line_matches,
            text,
            mat.start(),
            mat.end(),
            mat.as_str(),
            &compiled.rule,
        );
    }
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
