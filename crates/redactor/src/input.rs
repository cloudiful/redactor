use serde::{Deserialize, Serialize};
use std::ops::Range;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    #[default]
    Text,
    GitDiff,
}

#[derive(Debug, Clone)]
pub(crate) struct RedactableRange {
    pub range: Range<usize>,
    pub file_path: Option<String>,
}

pub(crate) fn redactable_ranges(
    text: &str,
    input_kind: InputKind,
    source_path: Option<&str>,
) -> Vec<RedactableRange> {
    match input_kind {
        InputKind::Text => {
            let file_path = source_path.map(|s| s.to_string());
            vec![RedactableRange {
                range: 0..text.len(),
                file_path,
            }]
        }
        InputKind::GitDiff => git_diff_redactable_ranges(text),
    }
}

fn git_diff_redactable_ranges(text: &str) -> Vec<RedactableRange> {
    let mut ranges = Vec::new();
    let mut offset = 0;
    let mut in_hunk = false;
    let mut in_binary_patch = false;
    let mut current_file_path: Option<String> = None;

    for line in text.split_inclusive('\n') {
        if line.starts_with("diff --git ") {
            in_hunk = false;
            in_binary_patch = false;
            current_file_path = parse_diff_git_path(line);
            offset += line.len();
            continue;
        }

        if line.starts_with("+++ ") || line.starts_with("--- ") {
            current_file_path = parse_diff_path_line(line)
                .or(current_file_path.take())
                .or(current_file_path.clone());
            if line.starts_with("+++ ") {
                current_file_path = parse_diff_path_line(line).or(current_file_path);
            }
            offset += line.len();
            continue;
        }

        if line.starts_with("GIT binary patch") || line.starts_with("Binary files ") {
            in_hunk = false;
            in_binary_patch = true;
            offset += line.len();
            continue;
        }

        if in_binary_patch {
            offset += line.len();
            continue;
        }

        if line.starts_with("@@") {
            in_hunk = true;
            offset += line.len();
            continue;
        }

        if !in_hunk {
            offset += line.len();
            continue;
        }

        if line.starts_with("\\ No newline at end of file") {
            offset += line.len();
            continue;
        }

        if matches!(
            line.as_bytes().first(),
            Some(b'+') | Some(b'-') | Some(b' ')
        ) && line.len() > 1
        {
            ranges.push(RedactableRange {
                range: (offset + 1)..(offset + line.len()),
                file_path: current_file_path.clone(),
            });
        }

        offset += line.len();
    }

    ranges
}

fn parse_diff_git_path(line: &str) -> Option<String> {
    let rest = line.strip_prefix("diff --git ")?;
    let path_part = rest.split_whitespace().next()?;
    let path = path_part
        .strip_prefix("a/")
        .unwrap_or(path_part)
        .to_string();
    Some(path)
}

fn parse_diff_path_line(line: &str) -> Option<String> {
    let rest = if line.starts_with("+++ ") {
        line.strip_prefix("+++ ")?
    } else if line.starts_with("--- ") {
        line.strip_prefix("--- ")?
    } else {
        return None;
    };
    let path = rest
        .strip_prefix("b/")
        .or_else(|| rest.strip_prefix("a/"))
        .unwrap_or(rest);
    let path = path.trim();
    if path.is_empty() || path == "/dev/null" {
        return None;
    }
    Some(path.to_string())
}

#[cfg(test)]
mod tests {
    use super::{InputKind, redactable_ranges};

    #[test]
    fn git_diff_ranges_only_cover_hunk_lines() {
        let diff = concat!(
            "diff --git a/config.yml b/config.yml\n",
            "index 1111111..2222222 100644\n",
            "--- a/config.yml\n",
            "+++ b/config.yml\n",
            "@@ -1,2 +1,3 @@\n",
            "-old_secret=abc123\n",
            "+new_secret=def456\n",
            " unchanged=value\n",
        );

        let ranges = redactable_ranges(diff, InputKind::GitDiff, None);
        let covered = ranges
            .into_iter()
            .map(|r| &diff[r.range])
            .collect::<Vec<_>>();

        assert_eq!(
            covered,
            vec![
                "old_secret=abc123\n",
                "new_secret=def456\n",
                "unchanged=value\n"
            ]
        );
    }

    #[test]
    fn text_mode_covers_entire_input() {
        let text = "plain text";
        let ranges = redactable_ranges(text, InputKind::Text, None);
        assert_eq!(ranges.len(), 1);
        assert_eq!(&text[ranges[0].range.clone()], text);
    }

    #[test]
    fn text_mode_with_source_path() {
        let text = "content";
        let ranges = redactable_ranges(text, InputKind::Text, Some("secrets/env"));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].file_path.as_deref(), Some("secrets/env"));
    }

    #[test]
    fn git_diff_extracts_file_path_from_headers() {
        let diff = concat!(
            "diff --git a/app/config.yml b/app/config.yml\n",
            "index 1111111..2222222 100644\n",
            "--- a/app/config.yml\n",
            "+++ b/app/config.yml\n",
            "@@ -1,1 +1,1 @@\n",
            "-old_secret=abc123\n",
        );

        let ranges = redactable_ranges(diff, InputKind::GitDiff, None);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].file_path.as_deref(), Some("app/config.yml"));
    }
}
