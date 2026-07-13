use anyhow::{Context, Result};

use crate::state::HttpState;

pub(crate) async fn maybe_write_audit(
    state: &HttpState,
    session_id: &str,
    encrypted_session: &str,
) -> Result<()> {
    let Some(dir) = &state.audit_dir else {
        return Ok(());
    };
    tokio::fs::create_dir_all(dir)
        .await
        .with_context(|| format!("failed to create audit directory {}", dir.display()))?;
    let path = dir.join(format!("{session_id}.redaction.json.enc"));
    tokio::fs::write(&path, encrypted_session)
        .await
        .with_context(|| format!("failed to write audit session {}", path.display()))
}
