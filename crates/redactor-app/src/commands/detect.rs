use anyhow::{Context, Result};
use redactor::RedactionRules;

use crate::cli::{InputArgs, InputKindArgs, ReportArgs, ReportFormat};
use crate::io::read_input;
use crate::support::{ResolvedLlmArgs, build_redactor};

pub(crate) fn run(
    input: InputArgs,
    report: ReportArgs,
    input_kind: InputKindArgs,
    llm: ResolvedLlmArgs,
    rules: RedactionRules,
) -> Result<()> {
    let text = read_input(input.input)?;
    let redactor = build_redactor(llm, rules);
    let findings = redactor
        .detect_with_input_kind(&text, input_kind.input_kind.into())
        .context("failed to detect sensitive values")?;

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
