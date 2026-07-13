use std::collections::{HashMap, HashSet};

use anyhow::{Result, anyhow};
use serde::{Deserialize, Deserializer, Serialize};

use crate::replace::parse_token;
use crate::{RedactionSession, RestorationEntry, RestorePermit, RestoreResult};

use super::permit::{PERMIT_VERSION, create_restore_permit};
use super::{RestoreContext, StreamingRestoreContext};

const SESSION_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RestoreState {
    session: RedactionSession,
    permits: Vec<RestorePermit>,
}

impl RestoreState {
    pub fn new(session: RedactionSession) -> Result<Self> {
        validate_session(&session)?;
        let permits = if session.issued_tokens.is_empty() {
            Vec::new()
        } else {
            vec![create_restore_permit(&session)]
        };
        Self::from_parts(session, permits)
    }

    pub fn from_parts(session: RedactionSession, permits: Vec<RestorePermit>) -> Result<Self> {
        validate_session(&session)?;
        let permits = normalize_permits(&session, permits)?;
        Ok(Self { session, permits })
    }

    pub fn advance(&self, session: RedactionSession) -> Result<Self> {
        validate_session(&session)?;
        validate_continuity(&self.session, &session)?;

        let mut permits = self.permits.clone();
        if !session.issued_tokens.is_empty() {
            permits.push(create_restore_permit(&session));
        }
        Self::from_parts(session, permits)
    }

    pub fn session(&self) -> &RedactionSession {
        &self.session
    }

    pub fn permits(&self) -> &[RestorePermit] {
        &self.permits
    }

    pub fn restore_context(&self) -> Result<RestoreContext<'_>> {
        RestoreContext::with_permits(&self.session, &self.permits)
    }

    pub fn streaming_restore_context(&self) -> Result<StreamingRestoreContext<'_>> {
        StreamingRestoreContext::with_permits(&self.session, &self.permits)
    }

    pub fn restore_text(&self, text: &str) -> Result<RestoreResult> {
        Ok(self.restore_context()?.restore_text(text))
    }

    pub fn has_authorized_tokens(&self) -> bool {
        self.permits
            .iter()
            .any(|permit| !permit.issued_tokens.is_empty())
    }
}

impl<'de> Deserialize<'de> for RestoreState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Parts {
            session: RedactionSession,
            permits: Vec<RestorePermit>,
        }

        let parts = Parts::deserialize(deserializer)?;
        Self::from_parts(parts.session, parts.permits).map_err(serde::de::Error::custom)
    }
}

fn validate_session(session: &RedactionSession) -> Result<()> {
    if session.version != SESSION_VERSION {
        return Err(anyhow!(
            "unsupported redaction session version {}",
            session.version
        ));
    }
    if session.session_id.is_empty() {
        return Err(anyhow!("redaction session ID must not be empty"));
    }
    if session.scope_id.is_empty() {
        return Err(anyhow!("redaction session scope must not be empty"));
    }

    let mut entries = HashSet::new();
    for entry in &session.entries {
        if !entries.insert(entry.token.as_str()) {
            return Err(anyhow!("duplicate session entry token `{}`", entry.token));
        }
        validate_entry(session, entry)?;
    }

    let mut issued = HashSet::new();
    for token in &session.issued_tokens {
        if !issued.insert(token.as_str()) {
            return Err(anyhow!("duplicate issued token `{token}`"));
        }
        if !entries.contains(token.as_str()) {
            return Err(anyhow!(
                "issued token `{token}` is missing from session entries"
            ));
        }
    }
    Ok(())
}

fn validate_entry(session: &RedactionSession, entry: &RestorationEntry) -> Result<()> {
    let parsed = parse_token(&entry.token)
        .map_err(|error| anyhow!("invalid session entry token `{}`: {error}", entry.token))?;
    if parsed.scope_id != session.scope_id {
        return Err(anyhow!("session entry token scope does not match session"));
    }
    if parsed.kind != entry.kind {
        return Err(anyhow!(
            "session entry token kind does not match entry kind"
        ));
    }
    Ok(())
}

fn normalize_permits(
    session: &RedactionSession,
    permits: Vec<RestorePermit>,
) -> Result<Vec<RestorePermit>> {
    let known = session
        .entries
        .iter()
        .map(|entry| entry.token.as_str())
        .collect::<HashSet<_>>();
    let mut permit_ids = HashSet::new();
    let mut authorized = HashSet::new();
    let mut normalized = Vec::new();

    for mut permit in permits {
        validate_permit(session, &permit, &known, &mut permit_ids)?;
        permit
            .issued_tokens
            .retain(|token| authorized.insert(token.clone()));
        if !permit.issued_tokens.is_empty() {
            normalized.push(permit);
        }
    }
    Ok(normalized)
}

fn validate_permit(
    session: &RedactionSession,
    permit: &RestorePermit,
    known: &HashSet<&str>,
    permit_ids: &mut HashSet<String>,
) -> Result<()> {
    if permit.version != PERMIT_VERSION {
        return Err(anyhow!(
            "unsupported restore permit version {}",
            permit.version
        ));
    }
    if permit.permit_id.is_empty() {
        return Err(anyhow!("restore permit ID must not be empty"));
    }
    if !permit_ids.insert(permit.permit_id.clone()) {
        return Err(anyhow!(
            "duplicate restore permit ID `{}`",
            permit.permit_id
        ));
    }
    if permit.scope_id != session.scope_id || permit.external_id != session.external_id {
        return Err(anyhow!("restore permit does not match session context"));
    }
    for token in &permit.issued_tokens {
        if !known.contains(token.as_str()) {
            return Err(anyhow!("restore permit authorizes unknown token `{token}`"));
        }
    }
    Ok(())
}

fn validate_continuity(previous: &RedactionSession, next: &RedactionSession) -> Result<()> {
    if previous.version != next.version {
        return Err(anyhow!("redaction session version changed"));
    }
    if previous.scope_id != next.scope_id {
        return Err(anyhow!("redaction session scope changed"));
    }
    if previous.external_id != next.external_id {
        return Err(anyhow!("redaction session external ID changed"));
    }

    let next_entries = next
        .entries
        .iter()
        .map(|entry| (entry.token.as_str(), entry))
        .collect::<HashMap<_, _>>();
    for old in &previous.entries {
        let Some(new) = next_entries.get(old.token.as_str()) else {
            return Err(anyhow!("new session removed entry `{}`", old.token));
        };
        if old.original != new.original
            || old.kind != new.kind
            || old.replacement_hint != new.replacement_hint
        {
            return Err(anyhow!("new session changed entry mapping `{}`", old.token));
        }
        if new.occurrences < old.occurrences {
            return Err(anyhow!(
                "new session reduced occurrences for `{}`",
                old.token
            ));
        }
    }
    Ok(())
}
