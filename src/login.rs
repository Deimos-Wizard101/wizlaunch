//! Memory-based login.
//!
//! Credentials are written straight into the client's address space and
//! dispatched through its own command handler, so they never reach a location
//! Python can read. Everything in this module — the signatures, the injected
//! bytecode, the sequencing — is shared across platforms; only the mechanics of
//! reading, writing and allocating remote memory differ, and those live behind
//! [`crate::platform::process`].

use crate::errors::VaultError;
use crate::platform::process::{find_module, RemoteProcess};
use crate::platform::window::pid_for_handle;
use std::thread;
use std::time::{Duration, Instant};

const WIZARD_MODULE: &str = "WizardGraphicalClient.exe";

// Pattern to locate the game's internal command dispatcher.
// Matches: mov r9b,1 / xor r8d,r8d / lea rdx,[rbp-31h] / mov rcx,[rip+??]
const LOGIN_PATTERN: &[u8] = &[
    0x41, 0xB1, 0x01, 0x45, 0x33, 0xC0, 0x48, 0x8D, 0x55, 0xCF, 0x48, 0x8B, 0x0D,
];

// RootWindowHook injection-point pattern (wildcards = None).
// 7 ?? bytes | 48 8B 01 | 7 ?? bytes | FF 50 70 84
const HOOK_PATTERN: &[Option<u8>] = &[
    None, None, None, None, None, None, None,
    Some(0x48), Some(0x8B), Some(0x01),
    None, None, None, None, None, None, None,
    Some(0xFF), Some(0x50), Some(0x70), Some(0x84),
];
const HOOK_INSTR_LEN: usize = 7;

/// How long to wait for the game client object to be constructed. The window
/// existing is not proof of it: the injected code dereferences the client
/// pointer, so it has to be non-null before anything is armed. Under Proton the
/// client can take ~2 minutes to get this far, and callers (the GUI) arm login
/// right after the process appears, so the default is generous; override with
/// `WIZLAUNCH_CLIENT_WAIT`.
const CLIENT_READY_TIMEOUT_SECS: u64 = 180;

fn client_ready_timeout() -> u64 {
    std::env::var("WIZLAUNCH_CLIENT_WAIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(CLIENT_READY_TIMEOUT_SECS)
}

// ── Pattern scanning ───────────────────────────────────────────────

/// Exact-byte pattern scan.  Returns offset within `data`.
fn scan_exact(data: &[u8], pattern: &[u8]) -> Option<usize> {
    data.windows(pattern.len()).position(|w| w == pattern)
}

/// Wildcard pattern scan (None = any byte).  Returns offset within `data`.
fn scan_wild(data: &[u8], pattern: &[Option<u8>]) -> Option<usize> {
    data.windows(pattern.len()).position(|window| {
        window.iter().zip(pattern.iter()).all(|(&b, pat)| match pat {
            Some(expected) => b == *expected,
            None => true,
        })
    })
}

// ── Bytecode builder ───────────────────────────────────────────────

/// Build the injected bytecode that:
///  1. Checks the flag — skips login if flag != 1
///  2. Saves registers, calls the game's command dispatcher
///  3. Clears flag
///  4. Restores registers
///  5. Executes the original hooked instruction
///  6. Jumps back
fn build_login_bytecode(
    block_addr: u64,
    flag_addr: u64,
    string_struct_addr: u64,
    dat_addr: u64,
    func_addr: u64,
    orig_instr: &[u8],
    ret_addr: u64,
) -> Vec<u8> {
    let mut bc = Vec::with_capacity(256);

    // ── Check flag ──
    // push rax
    bc.push(0x50);
    // mov rax, flag_addr
    bc.extend_from_slice(&[0x48, 0xB8]);
    bc.extend_from_slice(&flag_addr.to_le_bytes());
    // cmp byte [rax], 1
    bc.extend_from_slice(&[0x80, 0x38, 0x01]);
    // pop rax
    bc.push(0x58);
    // jne <skip past login code>
    bc.extend_from_slice(&[0x0F, 0x85]);
    let skip_fixup = bc.len();
    bc.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // placeholder

    // ── Login code (only executes when flag == 1) ──
    // push rax, rcx, rdx, r8, r9, r10, r11  (save volatiles the dispatcher clobbers)
    bc.extend_from_slice(&[0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53]);
    // The hook fires at an arbitrary instruction, so rsp's 16-byte phase here is
    // whatever the game left it, yet the dispatcher must be entered 16-aligned per
    // the x64 ABI (it spills SSE). A fixed `sub rsp,0x28` assumes the hook fires on
    // an aligned boundary; force alignment instead so it holds regardless:
    //   push rbp; mov rbp,rsp; and rsp,-16; sub rsp,0x20 (32B shadow space)
    bc.push(0x55); // push rbp
    bc.extend_from_slice(&[0x48, 0x89, 0xE5]); // mov rbp, rsp
    bc.extend_from_slice(&[0x48, 0x83, 0xE4, 0xF0]); // and rsp, -16
    bc.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]); // sub rsp, 0x20
    // Clear the flag BEFORE dispatching, not after. The hook sits on a hot
    // RootWindow path; if running the login command pumps the UI and re-enters
    // this hook, the flag must already read 0 so the nested fire skips instead of
    // dispatching again and recursing. (Needs the flag in writable memory — see
    // RemoteProcess::alloc; a CPU store into the exec cave would fault.)
    // mov rax, flag_addr ; mov byte [rax], 0
    bc.extend_from_slice(&[0x48, 0xB8]);
    bc.extend_from_slice(&flag_addr.to_le_bytes());
    bc.extend_from_slice(&[0xC6, 0x00, 0x00]);
    // mov r9b, 1
    bc.extend_from_slice(&[0x41, 0xB1, 0x01]);
    // xor r8d, r8d
    bc.extend_from_slice(&[0x45, 0x33, 0xC0]);
    // mov rdx, string_struct_addr
    bc.extend_from_slice(&[0x48, 0xBA]);
    bc.extend_from_slice(&string_struct_addr.to_le_bytes());
    // mov rax, dat_addr
    bc.extend_from_slice(&[0x48, 0xB8]);
    bc.extend_from_slice(&dat_addr.to_le_bytes());
    // mov rcx, [rax]  (dereference to get game client pointer)
    bc.extend_from_slice(&[0x48, 0x8B, 0x08]);
    // mov rax, func_addr
    bc.extend_from_slice(&[0x48, 0xB8]);
    bc.extend_from_slice(&func_addr.to_le_bytes());
    // call rax
    bc.extend_from_slice(&[0xFF, 0xD0]);
    // mov rsp, rbp; pop rbp  (undo the alignment frame)
    bc.extend_from_slice(&[0x48, 0x89, 0xEC]); // mov rsp, rbp
    bc.push(0x5D); // pop rbp
    // pop r11, r10, r9, r8, rdx, rcx, rax
    bc.extend_from_slice(&[0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58]);

    // ── Fix up jne offset ──
    let skip_target = bc.len();
    let skip_offset = (skip_target as i32) - (skip_fixup as i32) - 4;
    bc[skip_fixup..skip_fixup + 4].copy_from_slice(&skip_offset.to_le_bytes());

    // ── Original instruction (always runs) ──
    bc.extend_from_slice(orig_instr);

    // ── Jump back to return address ──
    bc.push(0xE9);
    let jmp_from = block_addr + bc.len() as u64 + 4; // address after this E9 instruction
    let jmp_offset = (ret_addr as i64 - jmp_from as i64) as i32;
    bc.extend_from_slice(&jmp_offset.to_le_bytes());

    bc
}

/// Build the 32-byte game string struct in memory.
///   offset  0: u64 — pointer to char data
///   offset  8: u64 — 0
///   offset 16: u64 — string length (excl. null)
///   offset 24: u64 — string capacity (excl. null)
fn build_string_struct(data_addr: u64, len: usize) -> [u8; 32] {
    let mut ss = [0u8; 32];
    ss[0..8].copy_from_slice(&data_addr.to_le_bytes());
    // ss[8..16] stays 0
    ss[16..24].copy_from_slice(&(len as u64).to_le_bytes());
    ss[24..32].copy_from_slice(&(len as u64).to_le_bytes());
    ss
}

/// Wait until the game client pointer the injected code dereferences is set.
fn wait_for_client(proc: &RemoteProcess, dat_addr: u64, timeout_secs: u64) -> Result<(), VaultError> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);

    loop {
        if let Ok(bytes) = proc.read(dat_addr, 8) {
            if u64::from_le_bytes(bytes.try_into().unwrap()) != 0 {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err(VaultError::LoginFailed(format!(
                "Game client was not initialized within {timeout_secs}s"
            )));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

// ── Public API ─────────────────────────────────────────────────────

/// Log in to a Wizard101 instance using buffer-write injection.
///
/// Credentials are written directly into the game process memory and dispatched
/// through the game's own command handler.  They never appear in any Python-
/// accessible location.
pub fn login_to_instance(handle: isize, username: &str, password: &str) -> Result<(), VaultError> {
    // 1. Resolve the instance handle to a process
    let pid = pid_for_handle(handle).ok_or_else(|| {
        VaultError::LoginFailed("Could not get PID from instance handle".into())
    })?;

    // 2. Open the game process
    let proc = RemoteProcess::open(pid)?;

    // 3. Find WizardGraphicalClient.exe module
    let (mod_base, mod_size) = find_module(pid, WIZARD_MODULE)?;

    // 4. Read module memory for pattern scanning
    let module_mem = proc.read_image(mod_base, mod_size as usize)?;

    // 5. Find the login function via LOGIN_PATTERN
    let login_offset = scan_exact(&module_mem, LOGIN_PATTERN)
        .ok_or_else(|| VaultError::LoginFailed("LOGIN_PATTERN not found".into()))?;
    let login_addr = mod_base + login_offset as u64;

    // Resolve dat (game-client pointer) and func (command dispatcher) via RIP-relative offsets
    //   m+13: 4-byte disp for `mov rcx,[rip+disp]`  →  dat = m+17 + disp
    //   m+18: 4-byte disp for `call rip+disp`        →  func = m+22 + disp
    let t = proc.read(login_addr + 13, 9)?;
    let dat_disp = i32::from_le_bytes(t[0..4].try_into().unwrap());
    let func_disp = i32::from_le_bytes(t[5..9].try_into().unwrap());
    let dat_addr = (login_addr as i64 + 17 + dat_disp as i64) as u64;
    let func_addr = (login_addr as i64 + 22 + func_disp as i64) as u64;

    // 6. Find the hook injection point via HOOK_PATTERN
    let hook_offset = scan_wild(&module_mem, HOOK_PATTERN)
        .ok_or_else(|| VaultError::LoginFailed("HOOK_PATTERN not found".into()))?;
    let hook_addr = mod_base + hook_offset as u64;
    let ret_addr = hook_addr + HOOK_INSTR_LEN as u64;

    let dbg = std::env::var("WIZLAUNCH_DEBUG").is_ok();
    if dbg {
        eprintln!(
            "[login] mod_base={mod_base:#x} login@{login_addr:#x} dat={dat_addr:#x} \
             func={func_addr:#x} hook@{hook_addr:#x}"
        );
    }

    // 7. Wait for the client object, so the injected code has something to call
    let wait_start = Instant::now();
    wait_for_client(&proc, dat_addr, client_ready_timeout())?;
    if dbg {
        eprintln!("[login] client ready after {:?}", wait_start.elapsed());
    }

    // 8. Save original bytes at hook site
    let orig_instr = proc.read(hook_addr, HOOK_INSTR_LEN)?;

    // 9. Build the login command string
    let cmd = format!("login {} {}", username, password);
    let cmd_bytes: Vec<u8> = cmd.bytes().chain(std::iter::once(0)).collect();
    let cmd_len = cmd.len(); // length without null

    // 10. Allocate remote memory. Everything is anchored near the hook so the
    //     bytecode block stays within rel32 reach of it.
    let str_data_addr = proc.alloc(hook_addr, cmd_bytes.len(), false)?;
    let str_struct_addr = proc.alloc(hook_addr, 32, false)?;
    let flag_addr = proc.alloc(hook_addr, 8, false)?;
    let block_addr = proc.alloc(hook_addr, 512, true)?;

    // Track allocations for cleanup
    let allocs = [str_data_addr, str_struct_addr, flag_addr, block_addr];
    let cleanup = |proc: &RemoteProcess, restore: bool| {
        if restore {
            let _ = proc.write(hook_addr, &orig_instr);
        }
        for &a in &allocs {
            let _ = proc.free(a);
        }
    };

    // 11. Write string data + struct + flag
    if let Err(e) = proc.write(str_data_addr, &cmd_bytes) {
        cleanup(&proc, false);
        return Err(e);
    }
    let ss = build_string_struct(str_data_addr, cmd_len);
    if let Err(e) = proc.write(str_struct_addr, &ss) {
        cleanup(&proc, false);
        return Err(e);
    }
    if let Err(e) = proc.write(flag_addr, &[0u8; 8]) {
        cleanup(&proc, false);
        return Err(e);
    }

    // 12. Build and write bytecode
    let bytecode = build_login_bytecode(
        block_addr,
        flag_addr,
        str_struct_addr,
        dat_addr,
        func_addr,
        &orig_instr,
        ret_addr,
    );
    if let Err(e) = proc.write(block_addr, &bytecode) {
        cleanup(&proc, false);
        return Err(e);
    }

    // 13. Set the flag to arm the login
    if let Err(e) = proc.write(flag_addr, &[0x01]) {
        cleanup(&proc, false);
        return Err(e);
    }

    if dbg {
        eprintln!(
            "[login] allocs: str_data={str_data_addr:#x} str_struct={str_struct_addr:#x} \
             flag={flag_addr:#x} block={block_addr:#x} (block-hook={}B)",
            block_addr as i64 - hook_addr as i64
        );
    }

    // 14. Patch the hook site: E9 <rel32 to block> + 2 NOOPs
    let jmp_offset = (block_addr as i64 - (hook_addr as i64 + 5)) as i32;
    let mut jmp_bytes = vec![0xE9];
    jmp_bytes.extend_from_slice(&jmp_offset.to_le_bytes());
    jmp_bytes.extend_from_slice(&[0x90, 0x90]); // 2 NOOPs to fill 7 bytes
    if let Err(e) = proc.write(hook_addr, &jmp_bytes) {
        cleanup(&proc, false);
        return Err(e);
    }

    // 15. Poll until the flag is cleared (bytecode sets it to 0 after login call).
    //     The hook only fires once the client's UI loop reaches the RootWindow
    //     path — i.e. when the login screen renders, which under Proton is ~90s
    //     after launch. Callers arm right after the process appears, so this wait
    //     has to span the whole render, not just the dispatch. Override with
    //     WIZLAUNCH_LOGIN_WAIT.
    let flag_wait_secs: u64 = std::env::var("WIZLAUNCH_LOGIN_WAIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(180);
    let deadline = Instant::now() + Duration::from_secs(flag_wait_secs);
    loop {
        thread::sleep(Duration::from_millis(50));

        match proc.read(flag_addr, 1) {
            Ok(data) if data[0] == 0x00 => break,
            Ok(_) => {}
            Err(e) => {
                cleanup(&proc, true);
                return Err(e);
            }
        }

        if Instant::now() > deadline {
            if dbg {
                let flag = proc.read(flag_addr, 1).ok().map(|b| b[0]);
                let at_hook = proc.read(hook_addr, 7).ok();
                eprintln!(
                    "[login] timeout: flag={flag:?} (1 = hook never executed) hook_bytes={at_hook:02x?}"
                );
            }
            cleanup(&proc, true);
            return Err(VaultError::LoginFailed(
                "Timed out waiting for login bytecode to execute".into(),
            ));
        }
    }

    // 16. Restore original bytes and free allocations
    cleanup(&proc, true);

    Ok(())
}
