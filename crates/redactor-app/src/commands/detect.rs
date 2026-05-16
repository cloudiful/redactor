use anyhow::{Context, Result};
use redactor::RedactionPolicy;

use crate::cli::{InputArgs, InputKindArgs, ReportArgs, ReportFormat};
use crate::io::read_input;
use crate::support::{ResolvedLlmArgs, build_redactor};

pub(crate) fn run(
    input: InputArgs,
    report: ReportArgs,
    input_kind: InputKindArgs,
    llm: ResolvedLlmArgs,
    policy: RedactionPolicy,
    source_path: Option<String>,
) -> Result<()> {
    let text = read_input(input.input)?;
    let redactor = build_redactor(llm, policy);
    let input_kind = redactor::InputKind::from(input_kind.input_kind);

    let findings = if let Some(ref source) = source_path {
        redactor
            .detect_with_source_path(&text, source)
            .context("failed to detect sensitive values")?
    } else {
        redactor
            .detect_with_input_kind(&text, input_kind)
            .context("failed to detect sensitive values")?
    };

    match report.report {
        ReportFormat::Human => {
            for finding in findings {
                println!(
                    "{} [{}..{}] {} ({:?})",
                    finding.kind.label(),
                    finding.start,
                    finding.end,
                    finding.match_text,
                    finding.source
                );
            }
            Ok(())
        }
        ReportFormat::Json => {
            print!("{}", serde_json::to_string_pretty(&findings)?);
            Ok(())
        }
    }
}