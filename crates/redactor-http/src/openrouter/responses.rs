use redactor::{Redactor, SessionRedactor};
use serde_json::Value;

use super::transform::{redact_string_value, walk_nested_content};

pub(crate) fn redact_responses_request(
    body: &mut Value,
    redactor: &Redactor,
    processor: &mut SessionRedactor,
) -> Result<(), redactor::RedactorError> {
    if let Some(instructions) = body.get_mut("instructions") {
        let _ = redact_string_value(instructions, redactor, processor)?;
    }

    if let Some(input) = body.get_mut("input") {
        walk_nested_content(input, redactor, processor)?;
    }

    Ok(())
}
