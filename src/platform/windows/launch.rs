//! Launching the client on Windows: it is a native binary, so it is spawned
//! directly.

use crate::errors::VaultError;
use std::path::Path;
use std::process::Command;

/// Spawn the client against `host:port`.
///
/// When `steam` is set the client is started in Steam mode (`-ST`); the caller
/// is responsible for having made Steam ready (see [`super::steam`]).
pub fn spawn_client(
    _game_path: &Path,
    exe: &Path,
    host: &str,
    port: &str,
    steam: bool,
) -> Result<(), VaultError> {
    let bin_dir = exe.parent().ok_or_else(|| {
        VaultError::LaunchFailed(format!("{} has no parent directory", exe.display()))
    })?;

    let mut cmd = Command::new(exe);
    if steam {
        cmd.arg("-ST");
    }
    cmd.arg("-L")
        .arg(host)
        .arg(port)
        .current_dir(bin_dir)
        .spawn()
        .map_err(|e| VaultError::LaunchFailed(e.to_string()))?;

    Ok(())
}

/// Default game location when `--path` is not given.
pub fn default_game_path() -> String {
    let steam = r"C:\Program Files (x86)\Steam\steamapps\common\Wizard101";
    let default = r"C:\ProgramData\KingsIsle Entertainment\Wizard101";
    if Path::new(steam).is_dir() {
        steam.to_string()
    } else {
        default.to_string()
    }
}
