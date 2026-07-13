use std::collections::HashSet;

use anyhow::{Result, anyhow};

use crate::{RedactionSession, RestorePermit};

use super::crypto::{open_json, seal_json};

pub(super) const PERMIT_VERSION: u32 = 1;
const PERMIT_AAD: &[u8] = b"redactor:restore-permit:v1";

pub fn create_restore_permit(session: &RedactionSession) -> RestorePermit {
    RestorePermit {
        version: PERMIT_VERSION,
        permit_id: crate::replace::random_id(),
        scope_id: session.scope_id.clone(),
        external_id: session.external_id.clone(),
        issued_tokens: session.issued_tokens.clone(),
    }
}

pub fn encrypt_restore_permit(permit: &RestorePermit, passphrase: &str) -> Result<String> {
    seal_json(permit, passphrase, PERMIT_AAD)
}

pub fn decrypt_restore_permit(data: &str, passphrase: &str) -> Result<RestorePermit> {
    let permit: RestorePermit = open_json(data, passphrase, PERMIT_AAD)
        .map_err(|error| anyhow!("failed to decrypt restore permit: {error}"))?;
    if permit.version != PERMIT_VERSION {
        return Err(anyhow!(
            "unsupported restore permit version {}",
            permit.version
        ));
    }
    Ok(permit)
}

pub fn authorized_tokens<'a>(
    session: &'a RedactionSession,
    permits: &[RestorePermit],
) -> Result<HashSet<&'a str>> {
    let known = session
        .entries
        .iter()
        .map(|entry| entry.token.as_str())
        .collect::<HashSet<_>>();
    let mut authorized = HashSet::new();
    for permit in permits {
        if permit.version != PERMIT_VERSION {
            return Err(anyhow!(
                "unsupported restore permit version {}",
                permit.version
            ));
        }
        if permit.scope_id != session.scope_id || permit.external_id != session.external_id {
            return Err(anyhow!("restore permit does not match session context"));
        }
        for token in &permit.issued_tokens {
            let Some(known_token) = known.get(token.as_str()) else {
                return Err(anyhow!("restore permit authorizes unknown token `{token}`"));
            };
            authorized.insert(*known_token);
        }
    }
    Ok(authorized)
}
