use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;

use redactor::{
    RedactorBuilder, decrypt_redaction_session, ensure_restore_valid,
    restore_text_from_encrypted_session,
};

use crate::cli::{InputArgs, ReportArgs, SessionPassphraseArgs};
use crate::git_apply::check_patch_applies;
use crate::io::read_input;
use crate::output::print_restore_report;
use crate::support::resolve_session_passphrase;

pub(crate) struct RestoreCommand {
    pub(crate) input: InputArgs,
    pub(crate) session: PathBuf,
    pub(crate) external_id: Option<String>,
    pub(crate) patch: Option<PathBuf>,
    pub(crate) report: ReportArgs,
    pub(crate) session_passphrase: SessionPassphraseArgs,
    pub(crate) repo: Option<PathBuf>,
    pub(crate) skip_apply_check: bool,
}

pub(crate) fn run(command: RestoreCommand) -> Result<()> {
    if command.external_id.is_some() {
        return Err(anyhow::anyhow!(
            "external_id stateful restore requires an injected session store provider; the CLI does not ship a built-in provider"
        ));
    }
    let passphrase = resolve_session_passphrase(command.session_passphrase)?;
    let encrypted = fs::read_to_string(&command.session)
        .with_context(|| format!("failed to read session file {}", command.session.display()))?;
    let redactor = RedactorBuilder::new().build();

    let restore_result = if let Some(patch_path) = command.patch {
        let session = decrypt_redaction_session(&encrypted, &passphrase)
            .context("failed to load encrypted session")?;
        let patch_text = fs::read_to_string(&patch_path)
            .with_context(|| format!("failed to read patch file {}", patch_path.display()))?;
        let result = redactor.restore_patch(&patch_text, &session);
        if !command.skip_apply_check {
            let repo_root = command
                .repo
                .unwrap_or(std::env::current_dir().context("failed to resolve current directory")?);
            check_patch_applies(&repo_root, &result)?;
        }
        result
    } else {
        let text = read_input(command.input.input)?;
        restore_text_from_encrypted_session(&redactor, &text, &encrypted, &passphrase)
            .context("failed to restore text from encrypted session")?
    };

    ensure_restore_valid(&restore_result)?;
    print_restore_report(command.report.report, &restore_result)
}
