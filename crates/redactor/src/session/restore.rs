use std::collections::{BTreeSet, HashMap};

use anyhow::{Result, anyhow};

use crate::replace::{is_v2_token_like, parse_token, token_like_ranges};
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
        match parse_token(candidate) {
            Ok(parsed) if parsed.scope_id != session.scope_id => {
                validation_errors.push(format!(
                    "token `{candidate}` does not belong to session scope `{}`",
                    session.scope_id
                ));
                restored_text.push_str(candidate);
            }
            Ok(_) if !known_tokens.contains(candidate) => {
                validation_errors.push(format!("unknown token `{candidate}`"));
                restored_text.push_str(candidate);
            }
            Ok(_) => {
                if let Some(original) = token_map.get(candidate) {
                    restored_text.push_str(original);
                    restored_count += 1;
                } else {
                    restored_text.push_str(candidate);
                }
            }
            Err(error) => {
                validation_errors.push(format!("malformed token `{candidate}`: {error}"));
                restored_text.push_str(candidate);
            }
        }
        cursor = token_range.end;
    }
    restored_text.push_str(&input[cursor..]);

    let unresolved_tokens = token_like_ranges(&restored_text)
        .into_iter()
        .map(|range| restored_text[range].to_string())
        .filter(|candidate| is_v2_token_like(candidate))
        .collect::<Vec<_>>();

    if !unresolved_tokens.is_empty() {
        validation_errors.extend(unresolved_tokens.iter().map(|candidate| {
            format!("unresolved token remained after restore: `{candidate}`")
        }));
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

#[cfg(test)]
mod tests {
    use super::restore_text_with_session;
    use crate::{FindingKind, RedactionPolicy, Redactor, RedactorBuilder};

    fn domain_redactor() -> Redactor {
        RedactorBuilder::new()
            .with_redaction_policy(
                RedactionPolicy::default()
                    .with_kind(FindingKind::Domain, true)
                    .with_kind(FindingKind::Secret, true)
                    .with_kind(FindingKind::Url, true),
            )
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
        let unknown = crate::replace::format_token(&session.scope_id, FindingKind::Domain, 999);
        let restored = restore_text_with_session(
            &format!("{} {}", session.entries[0].token, unknown),
            &session,
        );

        assert!(
            restored
                .validation_errors
                .iter()
                .any(|message| message.contains("unknown token") || message.contains("unresolved token"))
        );
        assert_eq!(restored.unresolved_tokens, vec![unknown]);
    }

    #[test]
    fn restore_rejects_scope_mismatch() {
        let redactor = domain_redactor();
        let left = redactor
            .redact_with_session("host=service.example.com")
            .expect("left session");
        let right = redactor
            .redact_with_session("host=backup.example.com")
            .expect("right session");
        let restored = restore_text_with_session(&left.redacted_text, &right);

        assert!(!restored.is_valid());
        assert!(
            restored
                .validation_errors
                .iter()
                .any(|message| message.contains("does not belong to session scope"))
        );
    }
}
