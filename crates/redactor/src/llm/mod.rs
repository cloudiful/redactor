#![cfg_attr(not(feature = "ollama"), allow(dead_code))]

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, ops::Range, time::Duration};

#[cfg(feature = "ollama")]
use std::io::Read;

use crate::detect::normalize;
use crate::input::RedactableRange;
use crate::types::{Finding, FindingKind, FindingSource, RedactionRules};

const LLM_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_LLM_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub struct LlmConfig {
    pub base_url: String,
    pub model: String,
}

#[derive(Debug, Clone, Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<Message<'a>>,
    stream: bool,
    temperature: f32,
    response_format: ResponseFormat<'a>,
}

#[derive(Debug, Clone, Serialize)]
struct Message<'a> {
    role: &'a str,
    content: String,
}

#[derive(Debug, Clone, Serialize)]
struct ResponseFormat<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
}

#[derive(Debug, Clone, Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Debug, Clone, Deserialize)]
struct Choice {
    message: ChatMessage,
}

#[derive(Debug, Clone, Deserialize)]
struct ChatMessage {
    content: String,
}

#[derive(Debug, Clone, Deserialize)]
struct CandidateEnvelope {
    candidates: Vec<Candidate>,
}

#[derive(Debug, Clone, Deserialize)]
struct Candidate {
    kind: String,
    value: String,
    confidence: Option<u8>,
}

#[cfg(feature = "ollama")]
pub fn discover_candidates(
    config: &LlmConfig,
    text: &str,
    rules: RedactionRules,
    ranges: &[RedactableRange],
) -> Result<Vec<Finding>> {
    let allowed_kinds = allowed_llm_kinds(rules);
    if allowed_kinds.is_empty() {
        return Ok(Vec::new());
    }
    let allowed_kinds = allowed_kinds.join(", ");
    let prompt = format!(
        "Find sensitive items in the input text. Return JSON only with a top-level key named candidates. \
         Each candidate must include kind, value, confidence. Allowed kinds: {allowed_kinds}. \
         Only include exact values copied from the input text.\n\nInput:\n{text}"
    );
    let request = ChatRequest {
        model: &config.model,
        messages: vec![
            Message {
                role: "system",
                content: "Return compact JSON only. Do not rewrite the source text.".to_string(),
            },
            Message {
                role: "user",
                content: prompt,
            },
        ],
        stream: false,
        temperature: 0.0,
        response_format: ResponseFormat {
            kind: "json_object",
        },
    };
    let endpoint = format!(
        "{}/v1/chat/completions",
        config.base_url.trim_end_matches('/')
    );
    let client = reqwest::blocking::Client::builder()
        .timeout(LLM_REQUEST_TIMEOUT)
        .build()
        .context("failed to build Ollama HTTP client")?;
    let mut response = client
        .post(endpoint)
        .json(&request)
        .send()
        .context("failed to call Ollama")?
        .error_for_status()
        .context("Ollama returned an error response")?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_LLM_RESPONSE_BYTES as u64)
    {
        anyhow::bail!("Ollama response exceeds {MAX_LLM_RESPONSE_BYTES} bytes");
    }
    let mut response_body = Vec::new();
    response
        .by_ref()
        .take((MAX_LLM_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut response_body)
        .context("failed to read Ollama response")?;
    if response_body.len() > MAX_LLM_RESPONSE_BYTES {
        anyhow::bail!("Ollama response exceeds {MAX_LLM_RESPONSE_BYTES} bytes");
    }
    let response: ChatResponse =
        serde_json::from_slice(&response_body).context("failed to decode Ollama response")?;
    let content = response
        .choices
        .into_iter()
        .next()
        .context("Ollama response did not contain any choices")?
        .message
        .content;
    let findings = parse_candidates(text, &content, rules)?;
    Ok(filter_findings_to_ranges(findings, ranges))
}

#[cfg(not(feature = "ollama"))]
pub fn discover_candidates(
    _config: &LlmConfig,
    _text: &str,
    _rules: RedactionRules,
    _ranges: &[RedactableRange],
) -> Result<Vec<Finding>> {
    anyhow::bail!("this binary was built without the `ollama` feature")
}

fn filter_findings_to_ranges(findings: Vec<Finding>, ranges: &[RedactableRange]) -> Vec<Finding> {
    findings
        .into_iter()
        .filter(|finding| {
            ranges
                .iter()
                .any(|range| range.range.start <= finding.start && finding.end <= range.range.end)
        })
        .collect()
}

fn allowed_llm_kinds(rules: RedactionRules) -> Vec<&'static str> {
    let mut kinds = Vec::new();
    if rules.person {
        kinds.push("person");
    }
    if rules.organization {
        kinds.push("organization");
    }
    kinds
}

fn parse_candidates(text: &str, content: &str, rules: RedactionRules) -> Result<Vec<Finding>> {
    let envelope: CandidateEnvelope =
        serde_json::from_str(content).context("failed to parse LLM JSON response")?;
    let mut findings = Vec::new();
    let mut occupied_ranges: Vec<Range<usize>> = Vec::new();
    let match_positions = build_match_positions(
        text,
        envelope
            .candidates
            .iter()
            .map(|candidate| candidate.value.as_str()),
    );
    let mut consumed_positions = HashMap::<String, usize>::new();

    for candidate in envelope.candidates {
        let Some(kind) = map_kind(&candidate.kind, rules) else {
            continue;
        };
        if let Some(start) = find_next_unoccupied_match(
            &candidate.value,
            &match_positions,
            &mut consumed_positions,
            &occupied_ranges,
        ) {
            let range = start..start + candidate.value.len();
            occupied_ranges.push(range.clone());
            findings.push(Finding {
                kind,
                source: FindingSource::Llm,
                match_text: candidate.value.clone(),
                normalized_key: normalize(kind, &candidate.value),
                confidence: candidate.confidence.unwrap_or(60).min(100),
                start: range.start,
                end: range.end,
            });
        }
    }

    Ok(findings)
}

fn build_match_positions<'a>(
    text: &str,
    values: impl IntoIterator<Item = &'a str>,
) -> HashMap<String, Vec<usize>> {
    let mut positions = HashMap::new();
    for value in values {
        if value.is_empty() || positions.contains_key(value) {
            continue;
        }
        positions.insert(value.to_string(), collect_match_positions(text, value));
    }
    positions
}

fn find_next_unoccupied_match(
    value: &str,
    match_positions: &HashMap<String, Vec<usize>>,
    consumed_positions: &mut HashMap<String, usize>,
    occupied_ranges: &[Range<usize>],
) -> Option<usize> {
    let positions = match_positions.get(value)?;
    let next_index = consumed_positions.entry(value.to_string()).or_insert(0);

    while *next_index < positions.len() {
        let start = positions[*next_index];
        *next_index += 1;
        let candidate = start..start + value.len();
        if occupied_ranges
            .iter()
            .all(|used| candidate.end <= used.start || used.end <= candidate.start)
        {
            return Some(start);
        }
    }

    None
}

fn collect_match_positions(text: &str, value: &str) -> Vec<usize> {
    let mut positions = Vec::new();
    if value.is_empty() {
        return positions;
    }

    let mut search_start = 0;
    while search_start <= text.len() {
        let Some(offset) = text[search_start..].find(value) else {
            break;
        };
        let start = search_start + offset;
        positions.push(start);
        search_start = start + 1;
    }

    positions
}

fn map_kind(kind: &str, rules: RedactionRules) -> Option<FindingKind> {
    match kind {
        "person" if rules.person => Some(FindingKind::Person),
        "organization" if rules.organization => Some(FindingKind::Organization),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::{FindingKind, RedactionRules, input::RedactableRange};

    use super::{filter_findings_to_ranges, parse_candidates};

    #[test]
    fn parse_candidates_maps_duplicate_values_to_distinct_occurrences() {
        let text = "Alice met Alice at Acme. Alice returned to Acme.";
        let content = r#"{
            "candidates": [
                {"kind":"person","value":"Alice","confidence":70},
                {"kind":"person","value":"Alice","confidence":65},
                {"kind":"organization","value":"Acme","confidence":80},
                {"kind":"organization","value":"Acme","confidence":75}
            ]
        }"#;

        let findings = parse_candidates(
            text,
            content,
            RedactionRules::default()
                .with_kind(FindingKind::Person, true)
                .with_kind(FindingKind::Organization, true),
        )
        .expect("parse candidates");
        let spans = findings
            .iter()
            .map(|finding| (finding.match_text.as_str(), finding.start, finding.end))
            .collect::<Vec<_>>();

        assert_eq!(
            spans,
            vec![
                ("Alice", 0, 5),
                ("Alice", 10, 15),
                ("Acme", 19, 23),
                ("Acme", 43, 47),
            ]
        );
    }

    #[test]
    fn parse_candidates_drops_extra_duplicate_values_without_available_matches() {
        let text = "Alice joined Acme with Alice.";
        let content = r#"{
            "candidates": [
                {"kind":"person","value":"Alice","confidence":70},
                {"kind":"person","value":"Alice","confidence":65},
                {"kind":"person","value":"Alice","confidence":60}
            ]
        }"#;

        let findings = parse_candidates(
            text,
            content,
            RedactionRules::default().with_kind(FindingKind::Person, true),
        )
        .expect("parse candidates");
        let alice_positions = findings
            .iter()
            .map(|finding| (finding.start, finding.end))
            .collect::<Vec<_>>();

        assert_eq!(alice_positions, vec![(0, 5), (23, 28)]);
    }

    #[test]
    fn llm_findings_are_limited_to_redactable_ranges() {
        let text = "Alice in a header\nAlice in a hunk";
        let findings = parse_candidates(
            text,
            r#"{"candidates":[{"kind":"person","value":"Alice"},{"kind":"person","value":"Alice"}]}"#,
            RedactionRules::default().with_kind(FindingKind::Person, true),
        )
        .expect("parse candidates");
        let filtered = filter_findings_to_ranges(
            findings,
            &[RedactableRange {
                range: text.find("Alice in a hunk").expect("hunk")..text.len(),
                file_path: None,
            }],
        );

        assert_eq!(filtered.len(), 1);
        assert_eq!(
            filtered[0].start,
            text.find("Alice in a hunk").expect("hunk")
        );
    }

    #[test]
    fn parse_candidates_keeps_different_values_from_stealing_each_other() {
        let text = "Alice Acme Alice";
        let content = r#"{
            "candidates": [
                {"kind":"organization","value":"Acme","confidence":80},
                {"kind":"person","value":"Alice","confidence":70},
                {"kind":"person","value":"Alice","confidence":65}
            ]
        }"#;

        let findings = parse_candidates(
            text,
            content,
            RedactionRules::default()
                .with_kind(FindingKind::Person, true)
                .with_kind(FindingKind::Organization, true),
        )
        .expect("parse candidates");
        let spans = findings
            .iter()
            .map(|finding| (finding.match_text.as_str(), finding.start, finding.end))
            .collect::<Vec<_>>();

        assert_eq!(
            spans,
            vec![("Acme", 6, 10), ("Alice", 0, 5), ("Alice", 11, 16)]
        );
    }

    #[test]
    fn parse_candidates_skips_people_when_person_detection_is_disabled() {
        let text = "Alice met Acme.";
        let content = r#"{
            "candidates": [
                {"kind":"person","value":"Alice","confidence":70},
                {"kind":"organization","value":"Acme","confidence":80}
            ]
        }"#;

        let findings = parse_candidates(
            text,
            content,
            RedactionRules::default().with_kind(FindingKind::Organization, true),
        )
        .expect("parse candidates");
        let values = findings
            .iter()
            .map(|finding| (finding.kind, finding.match_text.as_str()))
            .collect::<Vec<_>>();

        assert_eq!(values, vec![(FindingKind::Organization, "Acme")]);
    }
}
