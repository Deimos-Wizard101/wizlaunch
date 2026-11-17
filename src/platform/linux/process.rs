//! Remote-process access on Linux, where the client runs under Wine/Proton.
//!
//! `/proc/<pid>/mem` is the read/write channel. Writes through it are performed
//! with `FOLL_FORCE`, so they land on the module's read-only executable pages
//! without an `mprotect` — the same mechanism a debugger uses to plant a
//! breakpoint.
//!
//! There is no `VirtualAllocEx` equivalent: nothing lets one process allocate
//! memory in another. The textbook substitute is to ptrace-attach and inject an
//! `mmap` syscall, but that means stopping a thread of a game Proton runs with
//! `WINEFSYNC=1`. Instead, scratch space is carved out of the zero padding at
//! the tail of the PE image's executable section. Nothing reads that padding,
//! and because it lives inside the module it is always within rel32 reach of
//! the code being hooked — which also makes the Win32 build's ±2 GB search for
//! a reachable page unnecessary here.

use crate::errors::VaultError;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::Mutex;

/// Smallest run of padding worth treating as a cave. The caller needs roughly
/// 600 bytes; requiring more than that keeps us off a section whose padding
/// happens to be short.
const MIN_CAVE: u64 = 1024;

/// One line of `/proc/<pid>/maps`.
struct Region {
    start: u64,
    end: u64,
    readable: bool,
    writable: bool,
    executable: bool,
    path: String,
}

/// Fields are single-space separated, then variable padding before the path —
/// which can itself contain spaces (Proton's directories do).
fn parse_maps_line(line: &str) -> Option<Region> {
    let mut rest = line;
    let mut fields = [""; 5];
    for field in fields.iter_mut() {
        rest = rest.trim_start_matches(' ');
        let end = rest.find(' ')?;
        *field = &rest[..end];
        rest = &rest[end..];
    }

    let (start, end) = fields[0].split_once('-')?;
    let perms = fields[1].as_bytes();

    Some(Region {
        start: u64::from_str_radix(start, 16).ok()?,
        end: u64::from_str_radix(end, 16).ok()?,
        readable: perms.first() == Some(&b'r'),
        writable: perms.get(1) == Some(&b'w'),
        executable: perms.get(2) == Some(&b'x'),
        path: rest.trim().to_string(),
    })
}

fn read_maps(pid: u32) -> Result<Vec<Region>, VaultError> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .map_err(|e| VaultError::LoginFailed(format!("read /proc/{pid}/maps: {e}")))?;
    Ok(raw.lines().filter_map(parse_maps_line).collect())
}

/// Returns (base_address, module_size) for the named module.
///
/// Wine's preloader maps only the PE header from the file and lays the sections
/// out as anonymous memory, so `maps` cannot tell us how far the image reaches;
/// the extent comes from `SizeOfImage` in the header itself.
pub fn find_module(pid: u32, name: &str) -> Result<(u64, u32), VaultError> {
    let wanted = name.to_lowercase();
    let base = read_maps(pid)?
        .iter()
        .filter(|r| {
            Path::new(&r.path)
                .file_name()
                .is_some_and(|f| f.to_string_lossy().to_lowercase() == wanted)
        })
        .map(|r| r.start)
        .min()
        .ok_or_else(|| VaultError::LoginFailed(format!("Module '{name}' not found")))?;

    let mem = open_mem(pid)?;
    Ok((base, size_of_image(&mem, base)?))
}

fn open_mem(pid: u32) -> Result<File, VaultError> {
    File::options()
        .read(true)
        .write(true)
        .open(format!("/proc/{pid}/mem"))
        .map_err(|e| VaultError::LoginFailed(format!("open /proc/{pid}/mem: {e}")))
}

fn read_u32(mem: &File, addr: u64) -> Result<u32, VaultError> {
    let mut buf = [0u8; 4];
    mem.read_exact_at(&mut buf, addr)
        .map_err(|e| VaultError::LoginFailed(format!("read @ {addr:#x}: {e}")))?;
    Ok(u32::from_le_bytes(buf))
}

/// `SizeOfImage` sits 56 bytes into the optional header, at the same offset for
/// PE32 and PE32+.
fn size_of_image(mem: &File, base: u64) -> Result<u32, VaultError> {
    let lfanew = read_u32(mem, base + 0x3C)? as u64;

    let mut sig = [0u8; 4];
    mem.read_exact_at(&mut sig, base + lfanew)
        .map_err(|e| VaultError::LoginFailed(format!("read PE signature: {e}")))?;
    if &sig != b"PE\0\0" {
        return Err(VaultError::LoginFailed(format!(
            "no PE signature at {:#x}",
            base + lfanew
        )));
    }

    read_u32(mem, base + lfanew + 24 + 56)
}

/// Bump allocator over a run of section padding.
struct Cave {
    next: u64,
    end: u64,
    allocs: Vec<(u64, usize)>,
}

pub struct RemoteProcess {
    pid: u32,
    mem: File,
    /// Scratch carved from executable `.text` padding — for the injected bytecode
    /// block, which the CPU jumps to and executes.
    exec_cave: Mutex<Option<Cave>>,
    /// Scratch carved from writable `.data` padding — for everything the injected
    /// code writes to with a CPU store (the completion flag) or that the game may
    /// write through (the command string + its struct). The exec cave is mapped
    /// read+execute only, so a CPU write there faults and kills the client; a
    /// `/proc/mem` write dodges that via FOLL_FORCE but the running code cannot.
    write_cave: Mutex<Option<Cave>>,
}

impl RemoteProcess {
    pub fn open(pid: u32) -> Result<Self, VaultError> {
        Ok(Self {
            pid,
            mem: open_mem(pid)?,
            exec_cave: Mutex::new(None),
            write_cave: Mutex::new(None),
        })
    }

    pub fn read(&self, addr: u64, size: usize) -> Result<Vec<u8>, VaultError> {
        let mut buf = vec![0u8; size];
        self.mem
            .read_exact_at(&mut buf, addr)
            .map_err(|e| VaultError::LoginFailed(format!("read @ {addr:#x}: {e}")))?;
        Ok(buf)
    }

    pub fn write(&self, addr: u64, data: &[u8]) -> Result<(), VaultError> {
        self.mem
            .write_all_at(data, addr)
            .map_err(|e| VaultError::LoginFailed(format!("write @ {addr:#x}: {e}")))?;
        Ok(())
    }

    /// Read a whole mapped module for pattern scanning.
    ///
    /// A single read across the image would fail at the first unmapped page, so
    /// this copies each readable region into its place in a zero-filled buffer.
    /// Offsets therefore still correspond to `base + offset`.
    pub fn read_image(&self, base: u64, size: usize) -> Result<Vec<u8>, VaultError> {
        let image_end = base + size as u64;
        let mut buf = vec![0u8; size];
        let mut mapped = 0usize;

        for region in read_maps(self.pid)? {
            if !region.readable || region.end <= base || region.start >= image_end {
                continue;
            }
            let from = region.start.max(base);
            let to = region.end.min(image_end);
            let at = (from - base) as usize;
            let len = (to - from) as usize;
            if self.mem.read_exact_at(&mut buf[at..at + len], from).is_ok() {
                mapped += len;
            }
        }

        if mapped == 0 {
            return Err(VaultError::LoginFailed(format!(
                "no readable memory in the module at {base:#x}"
            )));
        }
        Ok(buf)
    }

    /// Allocate `size` bytes of scratch space out of section padding.
    ///
    /// `executable` picks the cave: the executable `.text` tail (reachable by a
    /// rel32 jump from `near`, for code the CPU runs) or the writable `.data`
    /// tail (for anything the running code or the game writes to). Getting this
    /// wrong is fatal — a CPU store into the read-execute cave faults and the
    /// client dies — so the flag and string must be allocated non-executable.
    pub fn alloc(&self, near: u64, size: usize, executable: bool) -> Result<u64, VaultError> {
        let mut guard = if executable {
            self.exec_cave.lock().unwrap()
        } else {
            self.write_cave.lock().unwrap()
        };
        let cave = match guard.as_mut() {
            Some(cave) => cave,
            None => {
                let found = if executable {
                    self.find_cave(near, CaveKind::Executable)?
                } else {
                    self.find_cave(near, CaveKind::Writable)?
                };
                guard.insert(found)
            }
        };

        // 16-byte align so the bytecode block and the string struct are both
        // naturally aligned.
        let addr = (cave.next + 15) & !15;
        if addr + size as u64 > cave.end {
            return Err(VaultError::LoginFailed(format!(
                "section padding exhausted: {} bytes left, {size} wanted",
                cave.end.saturating_sub(addr)
            )));
        }

        cave.next = addr + size as u64;
        cave.allocs.push((addr, size));
        Ok(addr)
    }

    /// Zero the allocation so the padding is clean for the next login, which
    /// finds the cave by looking for a run of zeros.
    pub fn free(&self, addr: u64) -> Result<(), VaultError> {
        let find = |guard: &Option<Cave>| {
            guard
                .as_ref()
                .and_then(|c| c.allocs.iter().find(|(a, _)| *a == addr))
                .map(|(_, size)| *size)
        };
        let size = find(&self.exec_cave.lock().unwrap())
            .or_else(|| find(&self.write_cave.lock().unwrap()));

        if let Some(size) = size {
            self.write(addr, &vec![0u8; size])?;
        }
        Ok(())
    }

    /// Find the trailing zero padding of a section to carve scratch from.
    ///
    /// For [`CaveKind::Executable`] it is the executable mapping containing `near`
    /// (so a rel32 jump reaches it); for [`CaveKind::Writable`] it is the nearest
    /// writable, non-executable mapping at or after `near` — the module's `.data`,
    /// whose tail padding the running code can store into without faulting.
    fn find_cave(&self, near: u64, kind: CaveKind) -> Result<Cave, VaultError> {
        let region = match kind {
            CaveKind::Executable => read_maps(self.pid)?
                .into_iter()
                .find(|r| r.executable && r.start <= near && near < r.end)
                .ok_or_else(|| {
                    VaultError::LoginFailed(format!("{near:#x} is not in an executable mapping"))
                })?,
            CaveKind::Writable => {
                // Prefer the nearest writable mapping at/after the hook (the
                // module's own .data); fall back to any writable mapping.
                let mut writable: Vec<Region> = read_maps(self.pid)?
                    .into_iter()
                    .filter(|r| r.readable && r.writable && !r.executable)
                    .collect();
                writable.sort_by_key(|r| (r.start < near, r.start.abs_diff(near)));
                return writable.into_iter().find_map(|r| self.cave_in(&r)).ok_or_else(|| {
                    VaultError::LoginFailed(
                        "no writable section padding found for login scratch".to_string(),
                    )
                });
            }
        };

        self.cave_in(&region).ok_or_else(|| {
            VaultError::LoginFailed(format!(
                "only short padding at the end of the section ({:#x}), need at least {MIN_CAVE}",
                region.end
            ))
        })
    }

    /// Carve the trailing run of zero padding out of `region`, if it is long
    /// enough. 64 KB spans any section-alignment run.
    fn cave_in(&self, region: &Region) -> Option<Cave> {
        let probe_len = (64 * 1024).min(region.end - region.start) as usize;
        let probe_at = region.end - probe_len as u64;
        let probe = self.read(probe_at, probe_len).ok()?;

        let zeros = probe.len() - probe.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        if (zeros as u64) < MIN_CAVE {
            return None;
        }
        Some(Cave {
            next: region.end - zeros as u64,
            end: region.end,
            allocs: Vec::new(),
        })
    }
}

/// Which section padding to carve a [`Cave`] from.
#[derive(Clone, Copy)]
enum CaveKind {
    Executable,
    Writable,
}
