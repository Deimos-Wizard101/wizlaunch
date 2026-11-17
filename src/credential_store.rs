//! Account credential storage.
//!
//! The backing store is the platform's: Credential Manager on Windows, sealed
//! by DPAPI; a passphrase-sealed file on Linux, because no secret-service
//! daemon can be relied on there. See [`crate::platform`] for the details and
//! the trade-offs of each.

pub use crate::platform::creds::{
    delete_credential, list_credential_nicknames, read_credential, write_credential,
};

/// Prefix on every stored entry's name, so enumeration can tell this
/// application's credentials apart from the rest of the user's vault.
pub const TARGET_PREFIX: &str = "Deimos/account/";

pub fn target_name(nickname: &str) -> String {
    format!("{TARGET_PREFIX}{nickname}")
}

pub fn has_credential(nickname: &str) -> bool {
    read_credential(nickname).is_ok()
}
