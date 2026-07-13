use anyhow::Error as AnyError;
use async_trait::async_trait;
use thiserror::Error;

use crate::RedactionSession;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSession {
    pub session: RedactionSession,
    pub version: String,
}

#[derive(Debug, Error)]
pub enum SessionStoreError {
    #[error("session version conflict")]
    Conflict,
    #[error("session store unavailable: {0}")]
    Unavailable(#[source] AnyError),
    #[error("stored session is invalid: {0}")]
    CorruptData(#[source] AnyError),
    #[error("stored session encryption failed: {0}")]
    Crypto(#[source] AnyError),
}

#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn load_latest(
        &self,
        external_id: &str,
    ) -> Result<Option<StoredSession>, SessionStoreError>;

    async fn save_latest(
        &self,
        external_id: &str,
        session: &RedactionSession,
        expected_version: Option<&str>,
    ) -> Result<String, SessionStoreError>;
}

pub fn require_external_id(external_id: Option<&str>) -> anyhow::Result<&str> {
    let value = external_id
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("external_id is required for stateful session operations")
        })?;
    if value.len() > 256 {
        anyhow::bail!("external_id must not exceed 256 UTF-8 bytes");
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::require_external_id;

    #[test]
    fn validates_external_id_boundaries() {
        assert!(require_external_id(None).is_err());
        assert!(require_external_id(Some("   ")).is_err());
        assert!(require_external_id(Some(&"x".repeat(257))).is_err());
        assert_eq!(require_external_id(Some("thread-1")).unwrap(), "thread-1");
    }
}
