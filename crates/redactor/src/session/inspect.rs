use anyhow::Result;

use crate::types::SessionSummary;

use super::crypto::decrypt_session_from_str;

pub fn inspect_encrypted_session(data: &str, passphrase: &str) -> Result<SessionSummary> {
    let session = decrypt_session_from_str(data, passphrase)?;
    Ok(SessionSummary::from(&session))
}

#[cfg(test)]
mod tests {
    use super::inspect_encrypted_session;
    use crate::{RedactorBuilder, encrypt_session_to_string};

    #[test]
    fn inspect_uses_authenticated_session_not_outer_metadata() {
        let session = RedactorBuilder::new()
            .build()
            .redact_with_session("alice@example.com")
            .expect("session");
        let encrypted = encrypt_session_to_string(&session, "inspect-passphrase").expect("encrypt");
        let mut envelope: serde_json::Value = serde_json::from_str(&encrypted).expect("json");
        envelope["session_id"] = serde_json::Value::String("forged".to_string());
        let summary = inspect_encrypted_session(&envelope.to_string(), "inspect-passphrase")
            .expect("inspect");
        assert_eq!(summary.session_id, session.session_id);
    }

    #[test]
    fn inspect_rejects_wrong_passphrase() {
        let session = RedactorBuilder::new()
            .build()
            .redact_with_session("alice@example.com")
            .expect("session");
        let encrypted = encrypt_session_to_string(&session, "inspect-passphrase").expect("encrypt");
        assert!(inspect_encrypted_session(&encrypted, "wrong-passphrase").is_err());
    }
}
