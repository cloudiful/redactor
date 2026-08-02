use crate::types::FindingKind;
use sha2::{Digest, Sha256};
use std::ops::Range;

pub(crate) const TOKEN_PREFIX: &str = "[[RDX:v2:";
pub(crate) const TOKEN_SUFFIX: &str = "]]";
pub(crate) const MAX_TOKEN_CANDIDATE_BYTES: usize = 4096;
const CHECK_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedToken {
    pub(crate) scope_id: String,
    pub(crate) kind: FindingKind,
    pub(crate) counter: usize,
}

pub(crate) fn format_token(scope_id: &str, kind: FindingKind, counter: usize) -> String {
    let check = token_check(scope_id, kind, counter);
    format!(
        "{TOKEN_PREFIX}{scope_id}:{}:{counter:03}:{check}{TOKEN_SUFFIX}",
        kind.token_label()
    )
}

pub(crate) fn parse_token(candidate: &str) -> Result<ParsedToken, String> {
    let inner = candidate
        .strip_prefix(TOKEN_PREFIX)
        .and_then(|value| value.strip_suffix(TOKEN_SUFFIX))
        .ok_or_else(|| "token does not match v2 marker format".to_string())?;
    let mut parts = inner.split(':');
    let scope_id = parts
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "token scope is missing".to_string())?
        .to_string();
    let kind_label = parts
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "token kind is missing".to_string())?;
    let counter_raw = parts
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "token counter is missing".to_string())?;
    let check = parts
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "token checksum is missing".to_string())?;
    if parts.next().is_some() {
        return Err("token contains unexpected trailing fields".to_string());
    }

    let kind = FindingKind::from_token_label(kind_label)
        .ok_or_else(|| format!("unknown token kind `{kind_label}`"))?;
    let counter = counter_raw
        .parse::<usize>()
        .map_err(|_| format!("invalid token counter `{counter_raw}`"))?;
    let expected = token_check(&scope_id, kind, counter);
    if check != expected {
        return Err(format!(
            "invalid token checksum `{check}`, expected `{expected}`"
        ));
    }

    Ok(ParsedToken {
        scope_id,
        kind,
        counter,
    })
}

pub(crate) fn scan_token_like_ranges(text: &str, mut visit: impl FnMut(Range<usize>)) {
    let mut index = 0;

    while let Some(offset) = text[index..].find(TOKEN_PREFIX) {
        let start = index + offset;
        let search_start = start + TOKEN_PREFIX.len();
        let end = if let Some(close_offset) = text[search_start..].find(TOKEN_SUFFIX) {
            search_start + close_offset + TOKEN_SUFFIX.len()
        } else {
            let mut end = (search_start + MAX_TOKEN_CANDIDATE_BYTES).min(text.len());
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            end
        };
        visit(start..end);
        index = end.max(start + TOKEN_PREFIX.len());
    }
}

pub(crate) fn random_scope_id() -> String {
    random_id_with_len(8)
}

pub(crate) fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    hex::encode(digest)
}

pub(crate) fn random_id() -> String {
    random_id_with_len(16)
}

fn token_check(scope_id: &str, kind: FindingKind, counter: usize) -> String {
    sha256_hex(&format!("v2:{scope_id}:{}:{counter}", kind.token_label()))[..CHECK_LEN].to_string()
}

fn random_id_with_len(byte_len: usize) -> String {
    let mut bytes = vec![0u8; byte_len];
    getrandom::fill(&mut bytes).expect("os randomness");
    hex::encode(bytes)
}
