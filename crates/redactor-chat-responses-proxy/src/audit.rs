use anyhow::{Context, Result, anyhow};
use redactor::{RedactionSession, encrypt_session_to_string};

use crate::ChatResponsesProxyContext;

pub(crate) fn maybe_write_audit(
    ctx: &ChatResponsesProxyContext,
    session: &RedactionSession,
) -> Result<()> {
    let Some(dir) = &ctx.audit_dir else {
        return Ok(());
    };
    let passphrase = ctx.session_passphrase.as_ref().ok_or_else(|| {
        anyhow!(
            "audit directory is configured without an audit passphrase; set {}",
            ctx.session_passphrase_env
        )
    })?;
    std::fs::create_dir_all(dir)
        .with_context(|| format!("failed to create audit directory {}", dir.display()))?;
    let encrypted = encrypt_session_to_string(session, passphrase)
        .context("failed to encrypt audit session")?;
    let path = dir.join(format!("{}.redaction.json.enc", session.session_id));
    std::fs::write(&path, encrypted)
        .with_context(|| format!("failed to write audit session {}", path.display()))?;
    Ok(())
}
