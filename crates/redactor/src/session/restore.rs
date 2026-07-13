use std::collections::{HashMap, HashSet};

use anyhow::{Result, anyhow};

use crate::replace::{parse_token, token_like_ranges};
use crate::types::{RedactionSession, RestorePermit, RestoreResult};

use super::permit::authorized_tokens;

#[derive(Debug)]
pub struct RestoreContext<'a> {
    authorized_tokens: HashSet<&'a str>,
    token_map: HashMap<&'a str, &'a str>,
}

impl<'a> RestoreContext<'a> {
    pub fn new(session: &'a RedactionSession) -> Self {
        let issued = session.issued_tokens.iter().map(String::as_str).collect();
        Self::from_authorized_tokens(session, issued)
    }

    pub fn with_permits(session: &'a RedactionSession, permits: &[RestorePermit]) -> Result<Self> {
        let authorized = authorized_tokens(session, permits)?;
        Ok(Self::from_authorized_tokens(session, authorized))
    }

    fn from_authorized_tokens(
        session: &'a RedactionSession,
        authorized_tokens: HashSet<&'a str>,
    ) -> Self {
        let token_map = session
            .entries
            .iter()
            .map(|entry| (entry.token.as_str(), entry.original.as_str()))
            .collect();
        Self {
            authorized_tokens,
            token_map,
        }
    }

    pub fn restore_text(&self, input: &str) -> RestoreResult {
        restore_text(input, &self.authorized_tokens, &self.token_map)
    }
}

pub fn restore_text_with_session(input: &str, session: &RedactionSession) -> RestoreResult {
    RestoreContext::new(session).restore_text(input)
}

fn restore_text(
    input: &str,
    authorized_tokens: &HashSet<&str>,
    token_map: &HashMap<&str, &str>,
) -> RestoreResult {
    let mut restored_text = String::with_capacity(input.len());
    let mut restored_count = 0;
    let mut skipped_tokens = Vec::new();
    let mut unresolved_tokens = Vec::new();
    let mut validation_errors = Vec::new();
    let mut cursor = 0;

    for token_range in token_like_ranges(input) {
        restored_text.push_str(&input[cursor..token_range.start]);
        let candidate = &input[token_range.clone()];
        match parse_token(candidate) {
            Ok(_) if !authorized_tokens.contains(candidate) => {
                skipped_tokens.push(candidate.to_string());
                restored_text.push_str(candidate);
            }
            Ok(_) => {
                if let Some(original) = token_map.get(candidate) {
                    restored_text.push_str(original);
                    restored_count += 1;
                } else {
                    unresolved_tokens.push(candidate.to_string());
                    validation_errors.push(format!(
                        "authorized token `{candidate}` is missing from session"
                    ));
                    restored_text.push_str(candidate);
                }
            }
            Err(error) => {
                unresolved_tokens.push(candidate.to_string());
                validation_errors.push(format!("malformed token `{candidate}`: {error}"));
                restored_text.push_str(candidate);
            }
        }
        cursor = token_range.end;
    }
    restored_text.push_str(&input[cursor..]);

    RestoreResult {
        restored_text,
        restored_count,
        skipped_tokens,
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
    use super::{RestoreContext, restore_text_with_session};
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
    fn restore_context_reuses_session_index_across_fragments() {
        let redactor = domain_redactor();
        let session = redactor
            .redact_with_session("first.example.com second.example.com")
            .expect("session");
        let context = RestoreContext::new(&session);

        for entry in &session.entries {
            let restored = context.restore_text(&entry.token);
            assert!(restored.is_valid());
            assert_eq!(restored.restored_text, entry.original);
        }
    }

    #[test]
    fn restore_skips_unknown_unpermitted_token() {
        let redactor = domain_redactor();
        let session = redactor
            .redact_with_session("host=service.example.com")
            .expect("session");
        let unknown = crate::replace::format_token(&session.scope_id, FindingKind::Domain, 999);
        let restored = restore_text_with_session(
            &format!("{} {}", session.entries[0].token, unknown),
            &session,
        );

        assert!(restored.is_valid());
        assert_eq!(restored.skipped_tokens, vec![unknown]);
    }

    #[test]
    fn restore_skips_scope_mismatch() {
        let redactor = domain_redactor();
        let left = redactor
            .redact_with_session("host=service.example.com")
            .expect("left session");
        let right = redactor
            .redact_with_session("host=backup.example.com")
            .expect("right session");
        let restored = restore_text_with_session(&left.redacted_text, &right);

        assert!(restored.is_valid());
        assert_eq!(restored.skipped_tokens, vec![left.entries[0].token.clone()]);
    }
}
