//! Launching the Windows client on Linux, through Proton.
//!
//! The client is a Windows binary, so it is started the way Steam starts one:
//! `proton run <exe>`, with `STEAM_COMPAT_DATA_PATH` naming the prefix and
//! `STEAM_COMPAT_CLIENT_INSTALL_PATH` naming the Steam install. Nothing here
//! requires the Steam client to be running.
//!
//! All three moving parts are discovered, and all three can be overridden:
//!
//! | Variable               | Overrides                      | Default                      |
//! |------------------------|--------------------------------|------------------------------|
//! | `WIZLAUNCH_PROTON`     | the Proton build (dir or script) | newest installed Proton    |
//! | `WIZLAUNCH_PREFIX`     | the Wine prefix                | `<game_path>/proton-prefix`  |
//! | `WIZLAUNCH_STEAM_RUN`  | the FHS wrapper; `0` disables it | `steam-run` if on `PATH`   |

use crate::errors::VaultError;
use std::path::{Path, PathBuf};
use std::process::Command;

fn env_path(key: &str) -> Option<PathBuf> {
    std::env::var_os(key)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

fn home_dir() -> Result<PathBuf, VaultError> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| VaultError::LaunchFailed("HOME not set".to_string()))
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

fn which(binary: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(binary))
        .find(|candidate| is_executable(candidate))
}

/// Locate the Steam install that owns the Proton builds.
pub fn steam_root() -> Result<PathBuf, VaultError> {
    if let Some(root) = env_path("STEAM_COMPAT_CLIENT_INSTALL_PATH") {
        return Ok(root);
    }

    let home = home_dir()?;
    [".local/share/Steam", ".steam/root", ".steam/steam"]
        .iter()
        .map(|rel| home.join(rel))
        .find(|candidate| candidate.is_dir())
        .ok_or_else(|| {
            VaultError::LaunchFailed(
                "could not locate the Steam install; set STEAM_COMPAT_CLIENT_INSTALL_PATH"
                    .to_string(),
            )
        })
}

/// Preference order for an auto-detected Proton build. `Proton - Experimental`
/// tracks the newest code and wins outright; otherwise the highest version
/// number in the directory name wins. A build with no version in its name (such
/// as `Proton Hotfix`) is a last resort.
fn rank(name: &str) -> (u8, u32) {
    if name.contains("Experimental") {
        return (2, 0);
    }

    let digits: Vec<u32> = name
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect();

    match digits.as_slice() {
        [] => (0, 0),
        [major] => (1, major * 100),
        [major, minor, ..] => (1, major * 100 + minor.min(&99)),
    }
}

/// Find the Proton build to run the client with.
pub fn find_proton(steam_root: &Path) -> Result<PathBuf, VaultError> {
    if let Some(override_path) = env_path("WIZLAUNCH_PROTON") {
        let script = if override_path.is_dir() {
            override_path.join("proton")
        } else {
            override_path
        };
        if !is_executable(&script) {
            return Err(VaultError::LaunchFailed(format!(
                "WIZLAUNCH_PROTON does not point at a Proton runner: {}",
                script.display()
            )));
        }
        return Ok(script);
    }

    let mut best: Option<((u8, u32), PathBuf)> = None;

    for dir in ["steamapps/common", "compatibilitytools.d"] {
        let Ok(entries) = std::fs::read_dir(steam_root.join(dir)) else {
            continue;
        };
        for entry in entries.flatten() {
            // Not every Proton* directory is a runner: the EasyAntiCheat
            // runtime, for one, ships no `proton` script.
            let script = entry.path().join("proton");
            if !is_executable(&script) {
                continue;
            }
            let score = rank(&entry.file_name().to_string_lossy());
            if best.as_ref().is_none_or(|(b, _)| score > *b) {
                best = Some((score, script));
            }
        }
    }

    best.map(|(_, script)| script).ok_or_else(|| {
        VaultError::LaunchFailed(format!(
            "no Proton build found under {}; install one or set WIZLAUNCH_PROTON",
            steam_root.display()
        ))
    })
}

/// The Wine prefix to run in.
///
/// For a Steam install, prefer the game's own Steam `compatdata` prefix:
/// Steam provisions it with the graphics stack (DXVK state, driver mapping) the
/// client needs to render. Launching the same client into a bare prefix beside
/// the game produces a white, never-drawn window — the prefix, not the launch
/// method, is what makes Steam's launch render correctly. Fall back to a
/// self-contained prefix only when no Steam compatdata prefix exists.
fn prefix_for(game_path: &Path) -> PathBuf {
    if let Some(p) = env_path("WIZLAUNCH_PREFIX") {
        return p;
    }
    if let Ok(root) = steam_root() {
        let compat = root
            .join("steamapps/compatdata")
            .join(super::steam::WIZARD101_APP_ID);
        if compat.join("pfx").is_dir() {
            return compat;
        }
    }
    game_path.join("proton-prefix")
}

/// Proton's bundled binaries are not patched for a non-FHS filesystem, so on
/// distributions that need it (NixOS, Guix) the whole thing runs inside
/// `steam-run`. Harmless to use elsewhere, absent elsewhere anyway.
fn steam_run() -> Option<PathBuf> {
    match std::env::var("WIZLAUNCH_STEAM_RUN") {
        Ok(value) if matches!(value.as_str(), "" | "0" | "no" | "off" | "none") => None,
        Ok(value) => Some(PathBuf::from(value)),
        Err(_) => which("steam-run"),
    }
}

/// Spawn the client against `host:port`.
///
/// In Steam mode the client is started with `-ST`; the caller must have dropped a
/// `steam_appid.txt` and confirmed Steam is running first (see [`super::steam`]),
/// so the directly-spawned client can authenticate through Steam.
pub fn spawn_client(
    game_path: &Path,
    exe: &Path,
    host: &str,
    port: &str,
    steam: bool,
) -> Result<(), VaultError> {
    let root = steam_root()?;
    let proton = find_proton(&root)?;
    let prefix = prefix_for(game_path);

    // Proton populates an empty prefix on first run but will not create the
    // directory itself.
    std::fs::create_dir_all(&prefix)?;

    let bin_dir = exe.parent().unwrap_or(game_path);

    // steam_appid.txt must match the launch mode at spawn time. A Steam client
    // (-ST) needs it to reach the Steamworks API; a non-Steam client started
    // without -ST hits a Steam-mismatch error dialog and never reaches its login
    // screen if the file is still present from an earlier Steam launch. Set the
    // correct state right before spawning so mixed/sequential launches stay sane.
    let appid_file = bin_dir.join("steam_appid.txt");
    if steam {
        let _ = std::fs::write(&appid_file, super::steam::WIZARD101_APP_ID);
    } else {
        let _ = std::fs::remove_file(&appid_file);
    }

    let mut cmd = match steam_run() {
        Some(wrapper) => {
            let mut cmd = Command::new(wrapper);
            cmd.arg(&proton);
            cmd
        }
        None => Command::new(&proton),
    };

    cmd.arg("run").arg(exe);
    if steam {
        cmd.arg("-ST");
    }
    cmd.arg("-L")
        .arg(host)
        .arg(port)
        .current_dir(bin_dir)
        .env("STEAM_COMPAT_DATA_PATH", &prefix)
        .env("STEAM_COMPAT_CLIENT_INSTALL_PATH", &root);

    // Xalia renders an overlay UI for gamepad navigation and can take focus
    // from the client while we are driving its login.
    if std::env::var_os("PROTON_USE_XALIA").is_none() {
        cmd.env("PROTON_USE_XALIA", "0");
    }

    cmd.spawn()
        .map_err(|e| VaultError::LaunchFailed(format!("{}: {e}", proton.display())))?;

    Ok(())
}

/// Default game location when `--path` is not given.
pub fn default_game_path() -> String {
    if let Some(path) = env_path("WIZLAUNCH_GAME_PATH") {
        return path.to_string_lossy().into_owned();
    }

    steam_root()
        .map(|root| root.join("steamapps/common/Wizard101"))
        .unwrap_or_else(|_| PathBuf::from("Wizard101"))
        .to_string_lossy()
        .into_owned()
}
