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

pub(crate) struct RedactCommand {
    pub(crate) input: InputArgs,
    pub(crate) report: ReportArgs,
    pub(crate) input_kind: InputKindArgs,
    pub(crate) llm: ResolvedLlmArgs,
    pub(crate) policy: RedactionPolicy,
    pub(crate) source_path: Option<String>,
    pub(crate) external_id: Option<String>,
    pub(crate) session_out: Option<PathBuf>,
    pub(crate) session_passphrase: SessionPassphraseArgs,
}

pub(crate) fn run(command: RedactCommand) -> Result<()> {
    let text = read_input(command.input.input)?;
    let redactor = build_redactor(command.llm, command.policy);
    let input_kind = InputKind::from(command.input_kind.input_kind);

    if command.external_id.is_some() {
        return Err(anyhow::anyhow!(
            "external_id stateful redaction requires an injected session store provider; the CLI does not ship a built-in provider"
        ));
    }

    if let Some(path) = command.session_out {
        let passphrase = resolve_session_passphrase(command.session_passphrase)?;
        let secured = if let Some(ref source) = command.source_path {
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
            command.report.report,
            &SanitizedRedactionOutput {
                redacted_text: secured.artifact.session.redacted_text.clone(),
                session_file: Some(path.display().to_string()),
                stats: secured.artifact.result.stats.clone(),
            },
            &secured.artifact.session.redacted_text,
        )
    } else {
        let artifact = if let Some(ref source) = command.source_path {
            redactor::redact_text_artifact_with_source(&redactor, &text, input_kind, source)
                .context("failed to redact input")?
        } else {
            redact_text_artifact(&redactor, &text, input_kind).context("failed to redact input")?
        };
        print_report(
            command.report.report,
            &SanitizedRedactionOutput {
                redacted_text: artifact.result.redacted_text.clone(),
                session_file: None,
                stats: artifact.result.stats.clone(),
            },
            &artifact.result.redacted_text,
        )
    }
}
