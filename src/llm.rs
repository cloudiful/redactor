#![cfg_attr(not(feature = "ollama"), allow(dead_code))]

use crate::rules::normalize;
use crate::types::{Finding, FindingKind, FindingSource};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

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
pub fn discover_candidates(config: &LlmConfig, text: &str) -> Result<Vec<Finding>> {
    let prompt = format!(
        "Find sensitive items in the input text. Return JSON only with a top-level key named candidates. \
         Each candidate must include kind, value, confidence. Allowed kinds: person, organization. \
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
    let client = reqwest::blocking::Client::new();
    let response: ChatResponse = client
        .post(endpoint)
        .json(&request)
        .send()
        .context("failed to call Ollama")?
        .error_for_status()
        .context("Ollama returned an error response")?
        .json()
        .context("failed to decode Ollama response")?;
    let content = response
        .choices
        .into_iter()
        .next()
        .context("Ollama response did not contain any choices")?
        .message
        .content;
    parse_candidates(text, &content)
}

#[cfg(not(feature = "ollama"))]
pub fn discover_candidates(_config: &LlmConfig, _text: &str) -> Result<Vec<Finding>> {
    anyhow::bail!("this binary was built without the `ollama` feature")
}

fn parse_candidates(text: &str, content: &str) -> Result<Vec<Finding>> {
    let envelope: CandidateEnvelope =
        serde_json::from_str(content).context("failed to parse LLM JSON response")?;
    let mut findings = Vec::new();

    for candidate in envelope.candidates {
        let Some(kind) = map_kind(&candidate.kind) else {
            continue;
        };
        if let Some(start) = text.find(&candidate.value) {
            findings.push(Finding {
                kind,
                source: FindingSource::Llm,
                match_text: candidate.value.clone(),
                normalized_key: normalize(kind, &candidate.value),
                confidence: candidate.confidence.unwrap_or(60).min(100),
                start,
                end: start + candidate.value.len(),
            });
        }
    }

    Ok(findings)
}

fn map_kind(kind: &str) -> Option<FindingKind> {
    match kind {
        "person" => Some(FindingKind::Person),
        "organization" => Some(FindingKind::Organization),
        _ => None,
    }
}
