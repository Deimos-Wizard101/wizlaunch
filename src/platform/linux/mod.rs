pub mod creds;
pub mod launch;
pub mod process;
pub mod prompt;
pub mod steam;
pub mod window;

use crate::errors::VaultError;
use std::path::PathBuf;

/// Directory holding `account_metadata.json`, the credential store, and
/// anything else per-user. The Win32 build puts this under `%APPDATA%`; here it
/// follows the XDG base-directory spec.
pub fn config_dir() -> Result<PathBuf, VaultError> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => {
            let home = std::env::var_os("HOME")
                .ok_or_else(|| VaultError::MetadataIo("HOME not set".to_string()))?;
            PathBuf::from(home).join(".config")
        }
    };
    let dir = base.join("Deimos");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}
