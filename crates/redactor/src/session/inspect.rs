use anyhow::Result;

use crate::types::SessionSummary;

use super::crypto::parse_envelope;

pub fn inspect_encrypted_session(data: &str) -> Result<SessionSummary> {
    let envelope = parse_envelope(data)?;
    Ok(SessionSummary {
        version: envelope.version,
        session_id: envelope.session_id,
        scope_id: envelope.scope_id,
        external_id: envelope.external_id,
        fingerprint: envelope.fingerprint,
        redacted_fingerprint: envelope.redacted_fingerprint,
        entry_count: envelope.entry_count,
        entries: envelope.entries,
    })
}
