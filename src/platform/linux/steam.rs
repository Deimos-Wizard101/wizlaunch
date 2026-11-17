//! Steam state on Linux.
//!
//! Steam mode DOES work here: a client spawned by `proton run` reaches the
//! Steamworks API once a `steam_appid.txt` (Wizard101's app id) sits next to it
//! and the Steam client is running, so a Steam-mode account signs in through
//! Steam instead of a username/password. [`ensure_appid`] drops that file and
//! [`ensure_ready`] requires a running Steam; the launcher then passes `-ST`.
//!
//! Live login state is only best-effort observable: Linux Steam keeps no
//! `ActiveProcess` tree like the Win32 build reads — `~/.steam/steam.pid` gives
//! the client pid and `~/.steam/registry.vdf` holds `AutoLoginUser`, which is
//! all [`is_steam_running`] / [`is_steam_logged_in`] rely on.

use crate::errors::VaultError;
use std::path::PathBuf;

/// Wizard101's Steam App ID.
pub const WIZARD101_APP_ID: &str = "799960";

/// Unused on Linux; kept so the constant exists on both targets.
pub const STEAM_LOGIN_TIMEOUT_SECS: u64 = 180;

fn steam_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".steam"))
}

/// Whether the Steam client is running, via the pid it records for itself.
/// The file outlives the process, so the pid is checked for liveness.
pub fn is_steam_running() -> bool {
    let Some(raw) = steam_home().and_then(|dir| std::fs::read_to_string(dir.join("steam.pid")).ok())
    else {
        return false;
    };
    raw.trim()
        .parse::<u32>()
        .is_ok_and(|pid| std::path::Path::new(&format!("/proc/{pid}")).exists())
}

/// Best effort: Linux Steam records no live login state, so this reports
/// whether a running client has an account configured to sign in with.
pub fn is_steam_logged_in() -> bool {
    if !is_steam_running() {
        return false;
    }
    steam_home()
        .and_then(|dir| std::fs::read_to_string(dir.join("registry.vdf")).ok())
        .is_some_and(|vdf| {
            vdf.split_once("\"AutoLoginUser\"")
                .and_then(|(_, rest)| rest.split('"').nth(1))
                .is_some_and(|user| !user.is_empty())
        })
}

pub fn steam_exe_path() -> Option<String> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join("steam"))
        .find(|candidate| candidate.is_file())
        .map(|path| path.to_string_lossy().into_owned())
}

pub fn launch_steam() -> Result<(), VaultError> {
    let exe = steam_exe_path().ok_or_else(|| {
        VaultError::SteamUnavailable("could not find steam on PATH".to_string())
    })?;
    std::process::Command::new(&exe)
        .spawn()
        .map_err(|e| VaultError::SteamUnavailable(format!("failed to launch Steam: {e}")))?;
    Ok(())
}

/// A Steam-mode client authenticates through the running Steam client (the
/// `steam_appid.txt` dropped by [`ensure_appid`] lets its Steamworks API reach
/// that client), so Steam must be up and signed in. We require it rather than
/// cold-starting Steam, which is slow and may prompt for sign-in.
pub fn ensure_ready(_timeout_secs: u64) -> Result<(), VaultError> {
    if is_steam_running() {
        Ok(())
    } else {
        Err(VaultError::SteamUnavailable(
            "Steam must be running and signed in to launch a Steam-mode account; \
             start Steam, then retry (or set the account to non-Steam mode)"
                .to_string(),
        ))
    }
}

/// Drop `steam_appid.txt` (Wizard101's app id) next to the client in `Bin/`.
///
/// A client started directly by `proton run` has no Steam app-launch context, so
/// its Steamworks API cannot otherwise identify itself. With this file present it
/// initializes against the running Steam client as Wizard101 — which is exactly
/// what lets a Steam-mode account sign in through Steam instead of a username and
/// password. (Earlier belief that `-ST` "demands an API it cannot initialize" was
/// wrong: the file is the missing piece, not a blocker.)
pub fn ensure_appid(game_path: &str) -> Result<(), VaultError> {
    let bin = std::path::Path::new(game_path).join("Bin");
    std::fs::create_dir_all(&bin)
        .map_err(|e| VaultError::LaunchFailed(format!("creating {}: {e}", bin.display())))?;
    let appid = bin.join("steam_appid.txt");
    std::fs::write(&appid, WIZARD101_APP_ID)
        .map_err(|e| VaultError::LaunchFailed(format!("writing {}: {e}", appid.display())))?;
    Ok(())
}
