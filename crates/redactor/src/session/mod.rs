mod crypto;
mod inspect;
mod permit;
#[cfg(test)]
mod permit_tests;
mod restore;
mod state;
#[cfg(test)]
mod state_tests;
mod store;
mod streaming_restore;
#[cfg(test)]
mod streaming_restore_tests;

pub use crypto::{
    decrypt_session_from_storage, decrypt_session_from_str, encrypt_session_for_storage,
    encrypt_session_to_string,
};
pub use inspect::inspect_encrypted_session;
pub use permit::{
    authorized_tokens, create_restore_permit, decrypt_restore_permit, encrypt_restore_permit,
};
pub use restore::{
    RestoreContext, ensure_restore_valid, restore_patch_with_session, restore_text_with_session,
};
pub use state::RestoreState;
pub(crate) use state::validate_prior_session;
pub use store::{SessionStore, SessionStoreError, StoredSession, require_external_id};
pub use streaming_restore::StreamingRestoreContext;
