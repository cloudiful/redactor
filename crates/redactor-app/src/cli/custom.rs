use redactor::{CustomFileRule, CustomStringMatch, CustomStringRule, CustomStringScope};

#[derive(Debug, Clone)]
pub(super) struct CustomArgs {
    pub(super) custom_strings: Vec<CustomStringRule>,
    pub(super) custom_files: Vec<CustomFileRule>,
    pub(super) source_path: Option<String>,
}

pub(super) struct RedactCommandParts {
    pub(super) custom_string: Vec<String>,
    pub(super) custom_string_contains: Vec<String>,
    pub(super) custom_string_regex: Vec<String>,
    pub(super) custom_string_line: Vec<String>,
    pub(super) custom_string_contains_line: Vec<String>,
    pub(super) custom_string_regex_line: Vec<String>,
    pub(super) custom_file: Vec<String>,
    pub(super) source_path: Option<String>,
}

impl From<&RedactCommandParts> for CustomArgs {
    fn from(parts: &RedactCommandParts) -> Self {
        let mut custom_strings = Vec::new();
        extend_rules(
            &mut custom_strings,
            &parts.custom_string,
            CustomStringMatch::Exact,
            CustomStringScope::Text,
        );
        extend_rules(
            &mut custom_strings,
            &parts.custom_string_contains,
            CustomStringMatch::Contains,
            CustomStringScope::Text,
        );
        extend_rules(
            &mut custom_strings,
            &parts.custom_string_regex,
            CustomStringMatch::Regex,
            CustomStringScope::Text,
        );
        extend_rules(
            &mut custom_strings,
            &parts.custom_string_line,
            CustomStringMatch::Exact,
            CustomStringScope::Line,
        );
        extend_rules(
            &mut custom_strings,
            &parts.custom_string_contains_line,
            CustomStringMatch::Contains,
            CustomStringScope::Line,
        );
        extend_rules(
            &mut custom_strings,
            &parts.custom_string_regex_line,
            CustomStringMatch::Regex,
            CustomStringScope::Line,
        );
        Self {
            custom_strings,
            custom_files: parts
                .custom_file
                .iter()
                .map(|path| CustomFileRule { path: path.clone() })
                .collect(),
            source_path: parts.source_path.clone(),
        }
    }
}

fn extend_rules(
    output: &mut Vec<CustomStringRule>,
    patterns: &[String],
    match_type: CustomStringMatch,
    scope: CustomStringScope,
) {
    output.extend(patterns.iter().map(|pattern| CustomStringRule {
        pattern: pattern.clone(),
        match_type: match_type.clone(),
        scope: scope.clone(),
    }));
}
