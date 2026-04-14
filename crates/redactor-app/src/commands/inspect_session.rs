use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;

use redactor::inspect_encrypted_session;

use crate::cli::{ReportArgs, ReportFormat};
use crate::output::print_session_summary;

pub(crate) fn run(session: PathBuf, report: ReportArgs) -> Result<()> {
    let encrypted = fs::read_to_string(&session)
        .with_context(|| format!("failed to read session file {}", session.display()))?;
    let summary =
        inspect_encrypted_session(&encrypted).context("failed to inspect session file")?;

    match report.report {
        ReportFormat::Human => print_session_summary(&summary),
        ReportFormat::Json => {
            print!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
    }
}
