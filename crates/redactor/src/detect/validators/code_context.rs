use super::domain::has_known_host_suffix;
use super::normalize::trim_wrapped;

pub(crate) fn is_likely_code_expression(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }

    if trimmed.contains("::")
        || trimmed.contains("->")
        || trimmed.contains('&')
        || trimmed.contains('(')
        || trimmed.contains(')')
        || trimmed.contains('{')
        || trimmed.contains('}')
        || trimmed.contains('[')
        || trimmed.contains(']')
        || trimmed.ends_with(',')
        || trimmed.ends_with(';')
    {
        return true;
    }

    if trimmed.contains(char::is_whitespace)
        && trimmed
            .chars()
            .any(|ch| matches!(ch, '=' | '+' | '*' | '%' | '|' | '&'))
    {
        return true;
    }

    looks_like_member_access_chain(trimmed) && !has_known_host_suffix(trimmed)
}

pub(crate) fn is_plain_config_value(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() || is_likely_code_expression(trimmed) {
        return false;
    }

    let inner = trim_wrapped(trimmed);
    !inner.is_empty() && !inner.contains(char::is_whitespace)
}

pub(crate) fn is_code_like_domain_context(text: &str, start: usize, end: usize) -> bool {
    let line_start = text[..start]
        .rfind('\n')
        .map(|index| index + 1)
        .unwrap_or(0);
    let line_end = text[end..]
        .find('\n')
        .map(|index| end + index)
        .unwrap_or(text.len());
    let line = &text[line_start..line_end];
    let relative_start = start - line_start;
    let relative_end = end - line_start;

    if is_wrapped_in_quotes(line, relative_start, relative_end) {
        return false;
    }

    let before = line[..relative_start].trim_end();
    let after = line[relative_end..].trim_start();

    let has_code_keywords = [
        "let ", "const ", "var ", "fn ", "for ", "if ", "while ", "match ", "return ", "impl ",
        "struct ",
    ]
    .iter()
    .any(|keyword| line.contains(keyword));

    let has_code_tokens = line.contains("::")
        || line.contains("->")
        || line.contains('&')
        || line.contains('(')
        || line.contains(')')
        || line.contains('{')
        || line.contains('}')
        || line.contains('[')
        || line.contains(']')
        || line.contains(';');

    let bare_expression_position = before.ends_with('=')
        || before.ends_with(':')
        || before.ends_with(',')
        || before.ends_with('(')
        || before.ends_with('[')
        || before.ends_with('{');
    let loop_expression_position = before.ends_with(" in");
    let method_call_position = after.starts_with('(') || after.starts_with('[');
    let expression_terminator = after.is_empty()
        || after
            .chars()
            .next()
            .is_some_and(|ch| matches!(ch, ',' | ';' | ')' | ']' | '}'));

    (has_code_keywords || has_code_tokens)
        && ((bare_expression_position && expression_terminator)
            || loop_expression_position
            || method_call_position)
}

pub(crate) fn is_wrapped_in_quotes(line: &str, start: usize, end: usize) -> bool {
    let previous = line[..start].trim_end().chars().next_back();
    let next = line[end..].trim_start().chars().next();
    matches!(
        (previous, next),
        (Some('"'), Some('"')) | (Some('\''), Some('\''))
    )
}

fn looks_like_member_access_chain(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() < 2 {
        return false;
    }

    parts.iter().all(|part| {
        let mut chars = part.chars();
        matches!(chars.next(), Some(ch) if ch.is_ascii_alphabetic() || ch == '_')
            && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    })
}

#[cfg(test)]
mod tests {
    use super::{is_likely_code_expression, is_plain_config_value};

    #[test]
    fn distinguishes_code_expressions_from_plain_values() {
        assert!(is_likely_code_expression("data.put"));
        assert!(is_likely_code_expression(
            "format_redaction_preview(&entries)"
        ));
        assert!(!is_likely_code_expression("prod.internal.example.com"));

        assert!(is_plain_config_value("prod.internal.example.com"));
        assert!(!is_plain_config_value("budget.is_token_mode()"));
    }
}
