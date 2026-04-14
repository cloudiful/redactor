use redactor::{
    RedactionSession, Redactor, RestoreResult, SessionRedactor, restore_text_with_session,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::chat::redact_chat_request;
use super::responses::redact_responses_request;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiEndpoint {
    ChatCompletions,
    Responses,
}

#[derive(Debug, Clone)]
pub struct JsonRedactionResult {
    pub body: Value,
    pub session: RedactionSession,
    pub max_token_len: usize,
}

#[derive(Debug, Clone)]
pub struct JsonRestoreResult {
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

pub fn redact_json_request(
    endpoint: ApiEndpoint,
    body: Value,
    redactor: &Redactor,
) -> Result<JsonRedactionResult, redactor::RedactorError> {
    let original_body = serde_json::to_string(&body)
        .map_err(|error| redactor::RedactorError::Validation(error.to_string()))?;
    let mut body = body;
    let mut processor = SessionRedactor::new();

    match endpoint {
        ApiEndpoint::ChatCompletions => redact_chat_request(&mut body, redactor, &mut processor)?,
        ApiEndpoint::Responses => redact_responses_request(&mut body, redactor, &mut processor)?,
    }

    let redacted_body = serde_json::to_string(&body)
        .map_err(|error| redactor::RedactorError::Validation(error.to_string()))?;
    let session = processor.build_session(&original_body, &redacted_body);
    let max_token_len = processor.max_token_len();

    Ok(JsonRedactionResult {
        body,
        session,
        max_token_len,
    })
}

pub fn restore_json_response(
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
    use redactor::RedactorBuilder;
    use serde_json::json;

    use crate::stream::SseRestoreBuffer;

    use super::{ApiEndpoint, redact_json_request, restore_json_response};

    #[test]
    fn redacts_chat_request_text_fields() {
        let body = json!({
            "model": "openrouter/test",
            "messages": [
                { "role": "user", "content": "connect to service.example.com with secret EJ2QEVC6AKELW0k2kkVY4NgGKONC" },
                { "role": "assistant", "content": [ { "type": "text", "text": "mirror service.example.com" } ] }
            ]
        });
        let redactor = RedactorBuilder::new().build();
        let result = redact_json_request(ApiEndpoint::ChatCompletions, body, &redactor)
            .expect("redact chat request");

        let serialized = serde_json::to_string(&result.body).expect("serialize");
        assert!(serialized.contains("__R_DOMAIN_001__"));
        assert!(serialized.contains("__R_SECRET_001__"));
        assert!(result.max_token_len >= "__R_SECRET_001__".len());
    }

    #[test]
    fn restores_json_response_from_tokens() {
        let body = json!({
            "model": "openrouter/test",
            "messages": [{ "role": "user", "content": "service.example.com" }]
        });
        let redactor = RedactorBuilder::new().build();
        let redacted =
            redact_json_request(ApiEndpoint::ChatCompletions, body, &redactor).expect("redact");
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
        let redactor = RedactorBuilder::new().build();
        let result = redact_json_request(ApiEndpoint::Responses, body, &redactor)
            .expect("redact responses request");

        let serialized = serde_json::to_string(&result.body).expect("serialize");
        assert!(serialized.contains("__R_DOMAIN_001__"));
        assert!(serialized.contains("__R_SECRET_001__"));
        assert!(serialized.contains("https://example.com/demo.png"));
    }

    #[test]
    fn sse_restore_buffer_handles_split_tokens() {
        let redactor = RedactorBuilder::new().build();
        let session = redactor
            .redact_with_session("domain=service.example.com")
            .expect("session");
        let token = session.entries[0].token.clone();
        let mut buffer = SseRestoreBuffer::new(session);
        let first = buffer
            .push(&format!("data: {{\"delta\":\"{}", &token[..8]))
            .expect("first push");
        let second = buffer
            .push(&(token[8..].to_string() + "\"}\n\n"))
            .expect("second push");
        let tail = buffer.finish().expect("finish");
        let combined = format!("{first}{second}{tail}");

        assert!(combined.contains("service.example.com"));
    }
}
