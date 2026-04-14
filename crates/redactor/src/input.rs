use serde::{Deserialize, Serialize};
use std::ops::Range;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    #[default]
    Text,
    GitDiff,
}

pub(crate) fn redactable_ranges(text: &str, input_kind: InputKind) -> Vec<Range<usize>> {
    match input_kind {
        InputKind::Text => std::iter::once(0..text.len()).collect(),
        InputKind::GitDiff => git_diff_redactable_ranges(text),
    }
}

fn git_diff_redactable_ranges(text: &str) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut offset = 0;
    let mut in_hunk = false;
    let mut in_binary_patch = false;

    for line in text.split_inclusive('\n') {
        if line.starts_with("diff --git ") {
            in_hunk = false;
            in_binary_patch = false;
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
            ranges.push((offset + 1)..(offset + line.len()));
        }

        offset += line.len();
    }

    ranges
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

        let ranges = redactable_ranges(diff, InputKind::GitDiff);
        let covered = ranges
            .into_iter()
            .map(|range| &diff[range])
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
        let ranges = redactable_ranges(text, InputKind::Text);
        assert_eq!(ranges.len(), 1);
        assert_eq!(&text[ranges[0].clone()], text);
    }
}
