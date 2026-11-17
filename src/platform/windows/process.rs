//! Remote-process access on Windows, via the debug and memory APIs.

use crate::errors::VaultError;
use std::ffi::c_void;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE,
};

pub struct RemoteProcess {
    handle: HANDLE,
}

impl RemoteProcess {
    pub fn open(pid: u32) -> Result<Self, VaultError> {
        let access =
            PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION;
        let handle = unsafe {
            OpenProcess(access, false, pid)
                .map_err(|e| VaultError::LoginFailed(format!("OpenProcess: {e}")))?
        };
        Ok(Self { handle })
    }

    pub fn read(&self, addr: u64, size: usize) -> Result<Vec<u8>, VaultError> {
        let mut buf = vec![0u8; size];
        unsafe {
            ReadProcessMemory(
                self.handle,
                addr as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
                size,
                None,
            )
            .map_err(|e| VaultError::LoginFailed(format!("ReadProcessMemory @ {addr:#x}: {e}")))?;
        }
        Ok(buf)
    }

    pub fn write(&self, addr: u64, data: &[u8]) -> Result<(), VaultError> {
        unsafe {
            WriteProcessMemory(
                self.handle,
                addr as *const c_void,
                data.as_ptr() as *const c_void,
                data.len(),
                None,
            )
            .map_err(|e| VaultError::LoginFailed(format!("WriteProcessMemory @ {addr:#x}: {e}")))?;
        }
        Ok(())
    }

    /// Read a whole mapped module for pattern scanning. A loaded PE image is
    /// contiguous and readable here, so this is a single read.
    pub fn read_image(&self, base: u64, size: usize) -> Result<Vec<u8>, VaultError> {
        self.read(base, size)
    }

    /// Allocate `size` bytes of scratch space in the remote process. When
    /// `executable`, the allocation is placed within ±2 GB of `near` so a rel32
    /// jump from there can reach it.
    pub fn alloc(&self, near: u64, size: usize, executable: bool) -> Result<u64, VaultError> {
        if executable {
            return self.alloc_near(near, size);
        }

        let ptr = unsafe {
            VirtualAllocEx(
                self.handle,
                None,
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if ptr.is_null() {
            return Err(VaultError::LoginFailed(
                "VirtualAllocEx returned NULL".into(),
            ));
        }
        Ok(ptr as u64)
    }

    fn alloc_near(&self, near: u64, size: usize) -> Result<u64, VaultError> {
        let granularity = 0x10000u64; // Windows allocation granularity
        let max_range = 0x7FFF_0000u64; // ~2 GB

        for offset in (granularity..max_range).step_by(granularity as usize) {
            for &dir in &[1i64, -1i64] {
                let candidate = (near as i64 + dir * offset as i64) as u64;
                let candidate = candidate & !(granularity - 1);
                let ptr = unsafe {
                    VirtualAllocEx(
                        self.handle,
                        Some(candidate as *const c_void),
                        size,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE,
                    )
                };
                if !ptr.is_null() {
                    return Ok(ptr as u64);
                }
            }
        }
        Err(VaultError::LoginFailed(
            "Failed to allocate executable memory within jump range".into(),
        ))
    }

    pub fn free(&self, addr: u64) -> Result<(), VaultError> {
        unsafe {
            VirtualFreeEx(self.handle, addr as *mut c_void, 0, MEM_RELEASE)
                .map_err(|e| VaultError::LoginFailed(format!("VirtualFreeEx: {e}")))?;
        }
        Ok(())
    }
}

impl Drop for RemoteProcess {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

/// Returns (base_address, module_size) for the named module.
pub fn find_module(pid: u32, name: &str) -> Result<(u64, u32), VaultError> {
    let name_lower = name.to_lowercase();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
            .map_err(|e| VaultError::LoginFailed(format!("CreateToolhelp32Snapshot: {e}")))?;

        let mut entry: MODULEENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

        if Module32FirstW(snap, &mut entry).is_ok() {
            loop {
                let mod_name = String::from_utf16_lossy(
                    &entry.szModule[..entry.szModule.iter().position(|&c| c == 0).unwrap_or(256)],
                );
                if mod_name.to_lowercase() == name_lower {
                    let base = entry.modBaseAddr as u64;
                    let size = entry.modBaseSize;
                    let _ = CloseHandle(snap);
                    return Ok((base, size));
                }
                if Module32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    Err(VaultError::LoginFailed(format!("Module '{name}' not found")))
}
