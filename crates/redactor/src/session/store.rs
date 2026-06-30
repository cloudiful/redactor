use anyhow::{Result, anyhow};

use crate::RedactionSession;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSession {
    pub session: RedactionSession,
    pub version: Option<String>,
}

pub trait SessionStore: Send + Sync {
    fn load_latest(&self, external_id: &str) -> Result<Option<StoredSession>>;
    fn save_latest(
        &self,
        external_id: &str,
        session: &RedactionSession,
        expected_version: Option<&str>,
    ) -> Result<Option<String>>;
}

pub fn require_external_id(external_id: Option<&str>) -> Result<&str> {
    external_id
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("external_id is required for stateful session operations"))
}
