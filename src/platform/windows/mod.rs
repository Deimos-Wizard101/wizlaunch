pub mod creds;
pub mod launch;
pub mod process;
pub mod prompt;
pub mod steam;
pub mod window;

use crate::errors::VaultError;
use std::path::PathBuf;

/// Directory holding `account_metadata.json` and anything else per-user.
pub fn config_dir() -> Result<PathBuf, VaultError> {
    let appdata = std::env::var("APPDATA")
        .map_err(|_| VaultError::MetadataIo("APPDATA not set".to_string()))?;
    let dir = PathBuf::from(appdata).join("Deimos");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}
