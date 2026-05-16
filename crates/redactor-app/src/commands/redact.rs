use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;

use redactor::{
    InputKind, RedactionPolicy, redact_text_artifact, redact_text_with_encrypted_session,
};

use crate::cli::{InputArgs, InputKindArgs, ReportArgs, SessionPassphraseArgs};
use crate::io::read_input;
use crate::output::{SanitizedRedactionOutput, print_report};
use crate::support::{ResolvedLlmArgs, build_redactor, resolve_session_passphrase};

pub(crate) fn run(
    input: InputArgs,
    report: ReportArgs,
    input_kind: InputKindArgs,
    llm: ResolvedLlmArgs,
    policy: RedactionPolicy,
    source_path: Option<String>,
    session_out: Option<PathBuf>,
    session_passphrase: SessionPassphraseArgs,
) -> Result<()> {
    let text = read_input(input.input)?;
    let redactor = build_redactor(llm, policy);
    let input_kind = InputKind::from(input_kind.input_kind);

    if let Some(path) = session_out {
        let passphrase = resolve_session_passphrase(session_passphrase)?;
        let secured = if let Some(ref source) = source_path {
            redactor::redact_text_with_encrypted_session_and_source(
                &redactor,
                &text,
                input_kind,
                source,
                &passphrase,
            )
            .context("failed to redact input")?
        } else {
            redact_text_with_encrypted_session(&redactor, &text, input_kind, &passphrase)
                .context("failed to redact input")?
        };
        fs::write(&path, &secured.encrypted_session)
            .with_context(|| format!("failed to write session file {}", path.display()))?;
        print_report(
            report.report,
            &SanitizedRedactionOutput {
                redacted_text: secured.artifact.session.redacted_text.clone(),
                session_file: Some(path.display().to_string()),
                stats: secured.artifact.result.stats.clone(),
            },
            &secured.artifact.session.redacted_text,
        )
    } else {
        let artifact = if let Some(ref source) = source_path {
            redactor::redact_text_artifact_with_source(&redactor, &text, input_kind, source)
                .context("failed to redact input")?
        } else {
            redact_text_artifact(&redactor, &text, input_kind).context("failed to redact input")?
        };
        print_report(
            report.report,
            &SanitizedRedactionOutput {
                redacted_text: artifact.result.redacted_text.clone(),
                session_file: None,
                stats: artifact.result.stats.clone(),
            },
            &artifact.result.redacted_text,
        )
    }
}