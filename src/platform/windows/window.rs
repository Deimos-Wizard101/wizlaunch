//! Instance discovery on Windows, where an instance handle is its `HWND`.

use crate::errors::VaultError;
use std::ffi::c_void;
use windows::Win32::Foundation::{BOOL, HWND, LPARAM};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetClassNameW, GetWindowThreadProcessId, IsWindow,
};

const WIZARD_CLASS: &str = "Wizard Graphical Client";

fn hwnd_from_isize(h: isize) -> HWND {
    HWND(h as *mut c_void)
}

/// Enumerate all open Wizard101 window handles.
pub fn get_wizard_handles() -> Vec<isize> {
    let mut handles: Vec<isize> = Vec::new();

    unsafe extern "system" fn enum_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let handles = &mut *(lparam.0 as *mut Vec<isize>);
        let mut class_buf = [0u16; 64];
        let len = GetClassNameW(hwnd, &mut class_buf);
        if len > 0 {
            let class_name = String::from_utf16_lossy(&class_buf[..len as usize]);
            if class_name == WIZARD_CLASS {
                handles.push(hwnd.0 as isize);
            }
        }
        BOOL(1) // continue enumeration
    }

    unsafe {
        let _ = EnumWindows(
            Some(enum_callback),
            LPARAM(&mut handles as *mut Vec<isize> as isize),
        );
    }

    handles
}

/// Resolve an instance handle to the pid that owns the window.
pub fn pid_for_handle(handle: isize) -> Option<u32> {
    let mut pid: u32 = 0;
    unsafe {
        GetWindowThreadProcessId(hwnd_from_isize(handle), Some(&mut pid));
    }
    (pid != 0).then_some(pid)
}

/// Check if a window handle is still valid.
pub fn is_window_valid(handle: isize) -> bool {
    unsafe { IsWindow(hwnd_from_isize(handle)).as_bool() }
}

/// Disable or enable a window (prevents user input during login).
pub fn enable_window(handle: isize, enable: bool) {
    #[link(name = "user32")]
    extern "system" {
        fn EnableWindow(hwnd: *mut c_void, enable: i32) -> i32;
    }
    unsafe {
        EnableWindow(handle as *mut c_void, if enable { 1 } else { 0 });
    }
}

/// Kill the process that owns a given window handle.
pub fn kill_process_by_handle(handle: isize) -> Result<bool, VaultError> {
    let Some(pid) = pid_for_handle(handle) else {
        return Ok(false);
    };

    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    unsafe {
        let process = OpenProcess(PROCESS_TERMINATE, false, pid)
            .map_err(|e| VaultError::WindowsApi(e.to_string()))?;
        let result = TerminateProcess(process, 1);
        let _ = windows::Win32::Foundation::CloseHandle(process);
        Ok(result.is_ok())
    }
}
