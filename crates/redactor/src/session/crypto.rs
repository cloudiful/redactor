use aes_gcm_siv::aead::{Aead, KeyInit, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use pbkdf2::pbkdf2_hmac_array;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::types::{RedactionSession, SessionEntrySummary};

const KDF_ROUNDS: u32 = 600_000;
const SESSION_VERSION: u32 = 2;
const OPAQUE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OpaqueEncryptedPayload {
    version: u32,
    salt_b64: String,
    nonce_b64: String,
    ciphertext_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EncryptedSessionFile {
    pub(crate) version: u32,
    pub(crate) session_id: String,
    pub(crate) scope_id: String,
    pub(crate) external_id: Option<String>,
    pub(crate) fingerprint: String,
    pub(crate) redacted_fingerprint: String,
    pub(crate) entry_count: usize,
    pub(crate) entries: Vec<SessionEntrySummary>,
    pub(crate) salt_b64: String,
    pub(crate) nonce_b64: String,
    pub(crate) ciphertext_b64: String,
}

pub fn encrypt_session_to_string(session: &RedactionSession, passphrase: &str) -> Result<String> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut salt)
        .map_err(|error| anyhow!("failed to generate session salt: {error}"))?;
    getrandom::fill(&mut nonce)
        .map_err(|error| anyhow!("failed to generate session nonce: {error}"))?;

    let key = derive_key(passphrase, &salt);
    let cipher = Aes256GcmSiv::new_from_slice(&key)
        .map_err(|error| anyhow!("failed to initialize session cipher: {error}"))?;
    let plaintext = serde_json::to_vec(session).context("failed to serialize session")?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|_| anyhow!("failed to encrypt session"))?;

    let envelope = EncryptedSessionFile {
        version: SESSION_VERSION,
        session_id: session.session_id.clone(),
        scope_id: session.scope_id.clone(),
        external_id: session.external_id.clone(),
        fingerprint: session.fingerprint.clone(),
        redacted_fingerprint: session.redacted_fingerprint.clone(),
        entry_count: session.entries.len(),
        entries: session
            .entries
            .iter()
            .map(|entry| SessionEntrySummary {
                token: entry.token.clone(),
                kind: entry.kind,
                replacement_hint: entry.replacement_hint.clone(),
                occurrences: entry.occurrences,
            })
            .collect(),
        salt_b64: STANDARD.encode(salt),
        nonce_b64: STANDARD.encode(nonce),
        ciphertext_b64: STANDARD.encode(ciphertext),
    };

    serde_json::to_string_pretty(&envelope)
        .context("failed to serialize encrypted session envelope")
}

pub fn encrypt_session_for_storage(
    session: &RedactionSession,
    passphrase: &str,
    external_id: &str,
) -> Result<String> {
    seal_json(session, passphrase, storage_aad(external_id).as_bytes())
}

pub fn decrypt_session_from_storage(
    data: &str,
    passphrase: &str,
    external_id: &str,
) -> Result<RedactionSession> {
    open_json(data, passphrase, storage_aad(external_id).as_bytes())
        .context("failed to decrypt stored session")
}

pub fn decrypt_session_from_str(data: &str, passphrase: &str) -> Result<RedactionSession> {
    let envelope = parse_envelope(data)?;
    if envelope.version != SESSION_VERSION {
        return Err(anyhow!(
            "unsupported encrypted session version {}, expected {}",
            envelope.version,
            SESSION_VERSION
        ));
    }
    let salt = decode_exact::<16>(&envelope.salt_b64).context("invalid encrypted session salt")?;
    let nonce =
        decode_exact::<12>(&envelope.nonce_b64).context("invalid encrypted session nonce")?;
    let ciphertext = STANDARD
        .decode(envelope.ciphertext_b64.as_bytes())
        .context("invalid encrypted session ciphertext")?;

    let key = derive_key(passphrase, &salt);
    let cipher = Aes256GcmSiv::new_from_slice(&key)
        .map_err(|error| anyhow!("failed to initialize session cipher: {error}"))?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| anyhow!("failed to decrypt session"))?;

    serde_json::from_slice(&plaintext).context("failed to deserialize decrypted session")
}

pub(crate) fn parse_envelope(data: &str) -> Result<EncryptedSessionFile> {
    serde_json::from_str(data).context("failed to parse encrypted session file")
}

pub(crate) fn seal_json<T: Serialize>(value: &T, passphrase: &str, aad: &[u8]) -> Result<String> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut salt).map_err(|error| anyhow!("failed to generate salt: {error}"))?;
    getrandom::fill(&mut nonce).map_err(|error| anyhow!("failed to generate nonce: {error}"))?;
    let key = derive_key(passphrase, &salt);
    let cipher = Aes256GcmSiv::new_from_slice(&key)
        .map_err(|error| anyhow!("failed to initialize cipher: {error}"))?;
    let plaintext = serde_json::to_vec(value).context("failed to serialize encrypted payload")?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("failed to encrypt payload"))?;
    serde_json::to_string(&OpaqueEncryptedPayload {
        version: OPAQUE_VERSION,
        salt_b64: STANDARD.encode(salt),
        nonce_b64: STANDARD.encode(nonce),
        ciphertext_b64: STANDARD.encode(ciphertext),
    })
    .context("failed to serialize encrypted payload")
}

pub(crate) fn open_json<T: for<'de> Deserialize<'de>>(
    data: &str,
    passphrase: &str,
    aad: &[u8],
) -> Result<T> {
    let payload: OpaqueEncryptedPayload =
        serde_json::from_str(data).context("failed to parse encrypted payload")?;
    if payload.version != OPAQUE_VERSION {
        return Err(anyhow!(
            "unsupported encrypted payload version {}",
            payload.version
        ));
    }
    let salt = decode_exact::<16>(&payload.salt_b64).context("invalid encrypted payload salt")?;
    let nonce =
        decode_exact::<12>(&payload.nonce_b64).context("invalid encrypted payload nonce")?;
    let ciphertext = STANDARD
        .decode(payload.ciphertext_b64.as_bytes())
        .context("invalid encrypted payload ciphertext")?;
    let key = derive_key(passphrase, &salt);
    let cipher = Aes256GcmSiv::new_from_slice(&key)
        .map_err(|error| anyhow!("failed to initialize cipher: {error}"))?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("failed to decrypt payload"))?;
    serde_json::from_slice(&plaintext).context("failed to deserialize encrypted payload")
}

fn storage_aad(external_id: &str) -> String {
    format!("redactor:session-store:v1:{external_id}")
}

fn derive_key(passphrase: &str, salt: &[u8; 16]) -> [u8; 32] {
    pbkdf2_hmac_array::<Sha256, 32>(passphrase.as_bytes(), salt, KDF_ROUNDS)
}

fn decode_exact<const N: usize>(data: &str) -> Result<[u8; N]> {
    let decoded = STANDARD
        .decode(data.as_bytes())
        .context("invalid base64 data")?;
    decoded
        .try_into()
        .map_err(|_| anyhow!("unexpected decoded length"))
}
