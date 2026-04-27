use std::collections::{BTreeSet, HashMap};

use anyhow::{Result, anyhow};

use crate::types::{RedactionSession, RestoreResult};

pub fn restore_text_with_session(input: &str, session: &RedactionSession) -> RestoreResult {
    let known_tokens = session
        .entries
        .iter()
        .map(|entry| entry.token.clone())
        .collect::<BTreeSet<_>>();
    let token_map = session
        .entries
        .iter()
        .map(|entry| (entry.token.as_str(), entry.original.as_str()))
        .collect::<HashMap<_, _>>();

    let mut restored_text = String::with_capacity(input.len());
    let mut restored_count = 0;
    let mut validation_errors = Vec::new();
    let mut cursor = 0;

    for token_range in token_like_ranges(input) {
        restored_text.push_str(&input[cursor..token_range.start]);
        let candidate = &input[token_range.clone()];
        if !known_tokens.contains(candidate) {
            validation_errors.push(format!("unknown or malformed token `{candidate}`"));
            restored_text.push_str(candidate);
        } else if let Some(original) = token_map.get(candidate) {
            restored_text.push_str(original);
            restored_count += 1;
        } else {
            restored_text.push_str(candidate);
        }
        cursor = token_range.end;
    }
    restored_text.push_str(&input[cursor..]);

    let unresolved_tokens = token_like_ranges(&restored_text)
        .into_iter()
        .map(|range| restored_text[range].to_string())
        .filter(|candidate| candidate.starts_with("__R_"))
        .collect::<Vec<_>>();

    if !unresolved_tokens.is_empty() {
        validation_errors.extend(
            unresolved_tokens
                .iter()
                .map(|candidate| format!("unresolved token remained after restore: `{candidate}`")),
        );
    }

    RestoreResult {
        restored_text,
        restored_count,
        unresolved_tokens,
        validation_errors,
    }
}

pub fn restore_patch_with_session(patch: &str, session: &RedactionSession) -> RestoreResult {
    restore_text_with_session(patch, session)
}

pub fn ensure_restore_valid(result: &RestoreResult) -> Result<()> {
    if result.is_valid() {
        return Ok(());
    }

    let mut messages = Vec::new();
    if !result.validation_errors.is_empty() {
        messages.extend(result.validation_errors.clone());
    }
    if !result.unresolved_tokens.is_empty() {
        messages.push(format!(
            "unresolved tokens: {}",
            result.unresolved_tokens.join(", ")
        ));
    }
    Err(anyhow!(messages.join("; ")))
}

fn token_like_ranges(text: &str) -> Vec<std::ops::Range<usize>> {
    let mut ranges = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;

    while index + 4 <= bytes.len() {
        if &bytes[index..index + 4] != b"__R_" {
            index += 1;
            continue;
        }

        let mut end = index + 4;
        while end < bytes.len() {
            let byte = bytes[end];
            if byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_' {
                end += 1;
                continue;
            }
            break;
        }

        if end + 1 < bytes.len() && bytes[end] == b'_' && bytes[end + 1] == b'_' {
            end += 2;
        }

        ranges.push(index..end);
        index = end.max(index + 1);
    }

    ranges
}

#[cfg(test)]
mod tests {
    use super::restore_text_with_session;
    use crate::{FindingKind, RedactionRules, Redactor, RedactorBuilder};

    fn domain_redactor() -> Redactor {
        RedactorBuilder::new()
            .with_redaction_rules(RedactionRules::default().with_kind(FindingKind::Domain, true))
            .build()
    }

    #[test]
    fn restore_streams_multiple_tokens_and_repetitions() {
        let redactor = domain_redactor();
        let text = "host=service.example.com alt=service.example.com";
        let session = redactor.redact_with_session(text).expect("session");

        let restored = restore_text_with_session(&session.redacted_text, &session);

        assert!(restored.is_valid());
        assert_eq!(restored.restored_text, text);
        assert_eq!(restored.restored_count, 2);
    }

    #[test]
    fn restore_preserves_unknown_token_validation() {
        let redactor = domain_redactor();
        let session = redactor
            .redact_with_session("host=service.example.com")
            .expect("session");
        let restored = restore_text_with_session("__R_DOMAIN_001__ __R_DOMAIN_999__", &session);

        assert!(
            restored
                .validation_errors
                .iter()
                .any(|message| message.contains("unknown or malformed token `__R_DOMAIN_999__`"))
        );
        assert_eq!(restored.unresolved_tokens, vec!["__R_DOMAIN_999__"]);
    }
}
