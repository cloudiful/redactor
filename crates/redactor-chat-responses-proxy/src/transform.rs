use redactor::{
    RedactionSession, Redactor, RestoreResult, SessionRedactor, SessionStore,
    restore_text_with_session,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::chat_completions::redact_chat_request;
use crate::responses::redact_responses_request;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ApiEndpoint {
    ChatCompletions,
    Responses,
}

#[derive(Debug, Clone)]
pub(crate) struct JsonRedactionResult {
    pub body: Value,
    pub session: RedactionSession,
    #[cfg_attr(not(test), allow(dead_code))]
    pub max_token_len: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct JsonRestoreResult {
    pub body: Value,
    pub report: RestoreResult,
}

pub(crate) fn redact_string_value(
    value: &mut Value,
    redactor: &Redactor,
    processor: &mut SessionRedactor,
) -> Result<bool, redactor::RedactorError> {
    let Some(text) = value.as_str() else {
        return Ok(false);
    };

    let redacted = processor.redact_fragment(redactor, text)?;
    *value = Value::String(redacted);
    Ok(true)
}

pub(crate) fn redact_object_string_field(
    object: &mut Map<String, Value>,
    field: &str,
    redactor: &Redactor,
    processor: &mut SessionRedactor,
) -> Result<bool, redactor::RedactorError> {
    let Some(value) = object.get_mut(field) else {
        return Ok(false);
    };
    redact_string_value(value, redactor, processor)
}

pub(crate) fn redact_text_array_parts(
    value: &mut Value,
    allowed_types: &[&str],
    text_field: &str,
    redactor: &Redactor,
    processor: &mut SessionRedactor,
) -> Result<(), redactor::RedactorError> {
    let Some(parts) = value.as_array_mut() else {
        return Ok(());
    };

    for part in parts {
        let is_text = part
            .get("type")
            .and_then(Value::as_str)
            .map(|kind| allowed_types.contains(&kind))
            .unwrap_or(false);
        if !is_text {
            continue;
        }

        if let Some(text) = part.get(text_field).and_then(Value::as_str) {
            let redacted = processor.redact_fragment(redactor, text)?;
            part[text_field] = Value::String(redacted);
        }
    }

    Ok(())
}

pub(crate) fn walk_nested_content(
    value: &mut Value,
    redactor: &Redactor,
    processor: &mut SessionRedactor,
) -> Result<(), redactor::RedactorError> {
    if redact_string_value(value, redactor, processor)? {
        return Ok(());
    }

    let Some(items) = value.as_array_mut() else {
        return Ok(());
    };

    for item in items {
        let Some(object) = item.as_object_mut() else {
            continue;
        };

        let _ = redact_object_string_field(object, "text", redactor, processor)?;
        if let Some(content) = object.get_mut("content") {
            walk_nested_content(content, redactor, processor)?;
        }
    }

    Ok(())
}

pub(crate) fn redact_json_request(
    endpoint: ApiEndpoint,
    body: Value,
    redactor: &Redactor,
    external_id: Option<&str>,
    session_store: Option<&dyn SessionStore>,
) -> Result<JsonRedactionResult, redactor::RedactorError> {
    let original_body = serde_json::to_string(&body)
        .map_err(|error| redactor::RedactorError::Validation(error.to_string()))?;
    let mut body = body;
    if let Some(object) = body.as_object_mut() {
        object.remove("external_id");
    }
    let stored_prior = match (external_id, session_store) {
        (Some(external_id), Some(store)) => store
            .load_latest(external_id)
            .map_err(|error| redactor::RedactorError::Validation(error.to_string()))?,
        _ => None,
    };
    let expected_version = stored_prior.as_ref().and_then(|stored| stored.version.clone());
    let prior_session = stored_prior.map(|stored| stored.session);
    let mut processor =
        SessionRedactor::with_prior_session(prior_session.as_ref(), external_id)?;

    match endpoint {
        ApiEndpoint::ChatCompletions => redact_chat_request(&mut body, redactor, &mut processor)?,
        ApiEndpoint::Responses => redact_responses_request(&mut body, redactor, &mut processor)?,
    }

    let redacted_body = serde_json::to_string(&body)
        .map_err(|error| redactor::RedactorError::Validation(error.to_string()))?;
    let session = processor.build_session(&original_body, &redacted_body);
    if let (Some(external_id), Some(store)) = (external_id, session_store) {
        store
            .save_latest(external_id, &session, expected_version.as_deref())
            .map_err(|error| redactor::RedactorError::Validation(error.to_string()))?;
    }
    let max_token_len = processor.max_token_len();

    Ok(JsonRedactionResult {
        body,
        session,
        max_token_len,
    })
}

pub(crate) fn restore_json_response(
    body: Value,
    session: &RedactionSession,
) -> Result<JsonRestoreResult, redactor::RedactorError> {
    let serialized = serde_json::to_string(&body)
        .map_err(|error| redactor::RedactorError::Validation(error.to_string()))?;
    let restored = restore_text_with_session(&serialized, session);
    if !restored.is_valid() {
        return Err(redactor::RedactorError::Validation(
            restored.validation_errors.join("; "),
        ));
    }
    let body: Value = serde_json::from_str(&restored.restored_text)
        .map_err(|error| redactor::RedactorError::Validation(error.to_string()))?;

    Ok(JsonRestoreResult {
        body,
        report: restored,
    })
}

#[cfg(test)]
mod tests {
    use redactor::{
        FindingKind, RedactionPolicy, RedactionSession, Redactor, RedactorBuilder, SessionStore,
        StoredSession,
    };
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use super::{ApiEndpoint, redact_json_request, restore_json_response};

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

    #[derive(Debug, Default, Clone)]
    struct MemorySessionStore {
        sessions: Arc<Mutex<BTreeMap<String, StoredSession>>>,
    }

    impl SessionStore for MemorySessionStore {
        fn load_latest(&self, external_id: &str) -> anyhow::Result<Option<StoredSession>> {
            Ok(self
                .sessions
                .lock()
                .expect("lock")
                .get(external_id)
                .cloned())
        }

        fn save_latest(
            &self,
            external_id: &str,
            session: &RedactionSession,
            expected_version: Option<&str>,
        ) -> anyhow::Result<Option<String>> {
            let mut sessions = self.sessions.lock().expect("lock");
            let current = sessions.get(external_id).cloned();
            match (current.as_ref(), expected_version) {
                (None, None) => {}
                (Some(stored), Some(expected)) if stored.version.as_deref() == Some(expected) => {}
                _ => anyhow::bail!("version_conflict"),
            }
            let next_version = current
                .and_then(|stored| stored.version)
                .and_then(|value| value.parse::<u64>().ok())
                .map(|value| value + 1)
                .unwrap_or(1)
                .to_string();
            sessions.insert(
                external_id.to_string(),
                StoredSession {
                    session: session.clone(),
                    version: Some(next_version.clone()),
                },
            );
            Ok(Some(next_version))
        }
    }

    #[test]
    fn redacts_chat_request_text_fields() {
        let body = json!({
            "model": "openrouter/test",
            "messages": [
                { "role": "user", "content": "connect to service.example.com with secret EJ2QEVC6AKELW0k2kkVY4NgGKONC" },
                { "role": "assistant", "content": [ { "type": "text", "text": "mirror service.example.com" } ] }
            ]
        });
        let redactor = domain_redactor();
        let result = redact_json_request(ApiEndpoint::ChatCompletions, body, &redactor, None, None)
            .expect("redact chat request");

        let serialized = serde_json::to_string(&result.body).expect("serialize");
        assert!(serialized.contains("[[RDX:v2:"));
        assert!(serialized.contains(":DOMAIN:001:"));
        assert!(serialized.contains(":SECRET:001:"));
        assert!(result.max_token_len >= "[[RDX:v2:".len());
    }

    #[test]
    fn restores_json_response_from_tokens() {
        let body = json!({
            "model": "openrouter/test",
            "messages": [{ "role": "user", "content": "service.example.com" }]
        });
        let redactor = domain_redactor();
        let redacted =
            redact_json_request(ApiEndpoint::ChatCompletions, body, &redactor, None, None)
                .expect("redact");
        let token = redacted
            .session
            .entries
            .iter()
            .find(|entry| entry.kind.label() == "domain")
            .map(|entry| entry.token.clone())
            .expect("domain token");
        let response = json!({
            "choices": [
                {
                    "message": {
                        "content": format!("Use {} now", token)
                    }
                }
            ]
        });

        let restored = restore_json_response(response, &redacted.session).expect("restore");
        let serialized = serde_json::to_string(&restored.body).expect("serialize");
        assert!(serialized.contains("service.example.com"));
    }

    #[test]
    fn redacts_nested_responses_request_text_fields() {
        let body = json!({
            "instructions": "connect service.example.com",
            "input": [
                {
                    "type": "message",
                    "content": [
                        { "type": "input_text", "text": "secret EJ2QEVC6AKELW0k2kkVY4NgGKONC" },
                        { "type": "image", "image_url": "https://example.com/demo.png" }
                    ]
                }
            ]
        });
        let redactor = domain_redactor();
        let result = redact_json_request(ApiEndpoint::Responses, body, &redactor, None, None)
            .expect("redact responses request");

        let serialized = serde_json::to_string(&result.body).expect("serialize");
        assert!(serialized.contains("[[RDX:v2:"));
        assert!(serialized.contains(":DOMAIN:001:"));
        assert!(serialized.contains(":SECRET:001:"));
        assert!(serialized.contains("https://example.com/demo.png"));
    }

    #[test]
    fn stateful_redaction_reuses_tokens_for_same_external_id() {
        let store = MemorySessionStore::default();
        let redactor = domain_redactor();
        let first = json!({
            "model": "openrouter/test",
            "messages": [
                { "role": "user", "content": "connect service.example.com" }
            ]
        });
        let second = json!({
            "model": "openrouter/test",
            "messages": [
                { "role": "user", "content": "mirror service.example.com" }
            ]
        });

        let first = redact_json_request(
            ApiEndpoint::ChatCompletions,
            first,
            &redactor,
            Some("conv-1"),
            Some(&store),
        )
        .expect("first redaction");
        let second = redact_json_request(
            ApiEndpoint::ChatCompletions,
            second,
            &redactor,
            Some("conv-1"),
            Some(&store),
        )
        .expect("second redaction");

        assert_eq!(first.session.scope_id, second.session.scope_id);
        assert_eq!(first.session.entries[0].token, second.session.entries[0].token);
    }
}
