use crate::types::FindingKind;
use sha2::{Digest, Sha256};

pub(crate) fn format_token(kind: FindingKind, counter: usize) -> String {
    format!("__R_{}_{counter:03}__", kind.token_label())
}

pub(crate) fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    hex::encode(digest)
}

pub(crate) fn random_id() -> String {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).expect("os randomness");
    hex::encode(bytes)
}
