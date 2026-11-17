//! Instance discovery on Linux.
//!
//! The Win32 build identifies an instance by its `HWND`, found by matching the
//! window class `Wizard Graphical Client`, and derives the pid from it. That
//! does not work under Proton: winex11 reports `WM_CLASS` as `steam_proton` for
//! every window it creates, so the Win32 class is not observable from outside
//! the prefix, and a single client owns half a dozen X11 windows (the toplevel
//! plus IME and input helpers).
//!
//! So on this target the instance *is* the process, and a `handle` carries the
//! pid. Everything the shared code asks of a handle — resolve a pid, check it
//! is alive, kill it — is a direct answer rather than a window lookup, and no
//! X11 connection is needed at all.

use crate::errors::VaultError;

const WIZARD_EXE: &str = "WizardGraphicalClient.exe";

/// Enumerate running Wizard101 client processes.
pub fn get_wizard_handles() -> Vec<isize> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };

    entries
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter(|&pid| is_wizard_process(pid))
        .map(|pid| pid as isize)
        .collect()
}

/// Every process in the Proton chain carries the client's path *somewhere* in
/// its arguments — the bubblewrap sandbox, the `proton` script and the prefix's
/// `steam.exe` all do. Only the client itself has it as `argv[0]`.
fn is_wizard_process(pid: u32) -> bool {
    let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    let argv0 = raw.split(|&b| b == 0).next().unwrap_or_default();
    String::from_utf8_lossy(argv0)
        .rsplit(['/', '\\'])
        .next()
        .is_some_and(|base| base.eq_ignore_ascii_case(WIZARD_EXE))
}

/// Resolve an instance handle to the pid of the client process.
pub fn pid_for_handle(handle: isize) -> Option<u32> {
    u32::try_from(handle).ok()
}

/// Whether the instance behind this handle is still running.
pub fn is_window_valid(handle: isize) -> bool {
    pid_for_handle(handle).is_some_and(|pid| std::path::Path::new(&format!("/proc/{pid}")).exists())
}

/// No-op on Linux.
///
/// On Windows this calls `EnableWindow` to swallow clicks while credentials are
/// being injected. X11 has no per-window input gate an outside process can
/// flip; the closest equivalents either grab the whole desktop
/// (`XGrabPointer`) or need the XFixes shape extension. Since this only guards
/// a sub-second window, it is left undone rather than faked.
pub fn enable_window(_handle: isize, _enable: bool) {}

/// Kill the client process behind a handle.
pub fn kill_process_by_handle(handle: isize) -> Result<bool, VaultError> {
    let Some(pid) = pid_for_handle(handle) else {
        return Ok(false);
    };

    if unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) } == 0 {
        return Ok(true);
    }

    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        // Already gone: the Win32 build reports the same as a non-failure.
        Some(libc::ESRCH) => Ok(false),
        _ => Err(VaultError::LaunchFailed(format!("kill {pid}: {err}"))),
    }
}
