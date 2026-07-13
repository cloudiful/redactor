use anyhow::Result;
use redactor::{RedactionStats, RestoreResult, SessionSummary};
use serde::Serialize;

use crate::cli::ReportFormat;

#[derive(Debug, Serialize)]
pub(crate) struct SanitizedRedactionOutput {
    pub(crate) redacted_text: String,
    pub(crate) session_file: Option<String>,
    pub(crate) restore_permit_file: Option<String>,
    pub(crate) stats: RedactionStats,
}

pub(crate) fn print_report<T: Serialize>(
    report: ReportFormat,
    payload: &T,
    human_text: &str,
) -> Result<()> {
    match report {
        ReportFormat::Human => print!("{human_text}"),
        ReportFormat::Json => print!("{}", serde_json::to_string_pretty(payload)?),
    }
    Ok(())
}

pub(crate) fn print_restore_report(report: ReportFormat, result: &RestoreResult) -> Result<()> {
    match report {
        ReportFormat::Human => print!("{}", result.restored_text),
        ReportFormat::Json => print!("{}", serde_json::to_string_pretty(result)?),
    }
    Ok(())
}

pub(crate) fn print_session_summary(summary: &SessionSummary) -> Result<()> {
    println!("session_id: {}", summary.session_id);
    println!("version: {}", summary.version);
    println!("fingerprint: {}", summary.fingerprint);
    println!("redacted_fingerprint: {}", summary.redacted_fingerprint);
    println!("entry_count: {}", summary.entry_count);
    for entry in &summary.entries {
        println!(
            "{} {} x{}{}",
            entry.token,
            entry.kind.label(),
            entry.occurrences,
            entry
                .replacement_hint
                .as_ref()
                .map(|hint| format!(" hint={hint}"))
                .unwrap_or_default()
        );
    }
    Ok(())
}
