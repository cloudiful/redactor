use redactor::{Redactor, SessionRedactor};
use serde_json::Value;

use crate::transform::{redact_string_value, redact_text_array_parts};

pub(crate) fn redact_chat_request(
    body: &mut Value,
    redactor: &Redactor,
    processor: &mut SessionRedactor,
) -> Result<(), redactor::RedactorError> {
    let Some(messages) = body.get_mut("messages").and_then(Value::as_array_mut) else {
        return Ok(());
    };

    for message in messages {
        redact_chat_content_value(message.get_mut("content"), redactor, processor)?;
    }

    Ok(())
}

fn redact_chat_content_value(
    content: Option<&mut Value>,
    redactor: &Redactor,
    processor: &mut SessionRedactor,
) -> Result<(), redactor::RedactorError> {
    let Some(content) = content else {
        return Ok(());
    };

    if redact_string_value(content, redactor, processor)? {
        return Ok(());
    }

    redact_text_array_parts(
        content,
        &["text", "input_text"],
        "text",
        redactor,
        processor,
    )
}
