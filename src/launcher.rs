//! Starting instances and tracking the ones that are running.
//!
//! The instance identifier (`handle`) is whatever the platform uses to name a
//! running client: an `HWND` on Windows, a pid on Linux. It is opaque to
//! callers — pass it back to [`login_to_instance`][crate::login::login_to_instance],
//! [`is_window_valid`] or [`kill_process_by_handle`] and nothing else.

use crate::errors::VaultError;
use crate::platform::{launch, window};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

pub use window::{enable_window, get_wizard_handles, is_window_valid, kill_process_by_handle};

const WIZARD_EXE: &str = "WizardGraphicalClient.exe";

/// Normalize a user-supplied path to the platform's native separators.
fn normalize_path(path: &str) -> PathBuf {
    Path::new(path).components().collect()
}

/// Launch the Wizard101 game process.
/// `login_server` is "host:port" (e.g. "login.us.wizard101.com:12000").
///
/// When `steam` is true the client is started in Steam mode; callers are
/// responsible for ensuring Steam is ready first (see [`crate::steam`]). The
/// flag has no effect on Linux.
pub fn launch_game(game_path: &str, login_server: &str, steam: bool) -> Result<(), VaultError> {
    let game_dir = normalize_path(game_path);
    let exe = game_dir.join("Bin").join(WIZARD_EXE);

    if !exe.exists() {
        return Err(VaultError::LaunchFailed(format!(
            "Executable not found: {}",
            exe.display()
        )));
    }

    let (host, port) = login_server.rsplit_once(':').ok_or_else(|| {
        VaultError::LaunchFailed(format!(
            "Invalid login server format '{login_server}', expected host:port"
        ))
    })?;

    launch::spawn_client(&game_dir, &exe, host, port, steam)
}

/// Wait for a new Wizard101 instance to appear that wasn't in `before_handles`.
/// Returns the new handle, or error on timeout.
pub fn wait_for_new_handle(
    before_handles: &HashSet<isize>,
    timeout_secs: u64,
) -> Result<isize, VaultError> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);

    while Instant::now() < deadline {
        let current = get_wizard_handles();
        for h in &current {
            if !before_handles.contains(h) {
                return Ok(*h);
            }
        }
        thread::sleep(Duration::from_millis(500));
    }

    Err(VaultError::LaunchTimeout(
        "No new wizard instance detected".to_string(),
    ))
}

/// Where the game is expected to live when no path is given.
pub fn default_game_path() -> String {
    launch::default_game_path()
}
