# wizlaunch
A module (via CLI, import, or FFI) for reliably and securely managing and launching Wizard101 clients.

Windows and Linux are both supported from one source tree. The client is a
Windows binary either way; on Linux it is run through Proton.

## CLI
- TODO

## Building

```sh
cargo build --release                      # library + wizlaunch-cli
cargo build --release --no-default-features # skip the Python extension
maturin build --release                     # the Python extension
```

## Linux

The same commands and the same Python API, with four differences worth knowing.

**The client runs under Proton.** `launch` starts it with `proton run … -L <host>
<port>`, pointing `STEAM_COMPAT_DATA_PATH` at a prefix and
`STEAM_COMPAT_CLIENT_INSTALL_PATH` at the Steam install. The Steam client itself
is never needed. All three moving parts are detected and all three can be
overridden:

| Variable | Overrides | Default |
|---|---|---|
| `WIZLAUNCH_PROTON` | the Proton build (directory or `proton` script) | newest installed — `Proton - Experimental` if present, else the highest version |
| `WIZLAUNCH_PREFIX` | the Wine prefix | `<game_path>/proton-prefix` |
| `WIZLAUNCH_STEAM_RUN` | the FHS wrapper; `0` disables it | `steam-run` if on `PATH` |
| `WIZLAUNCH_GAME_PATH` | the install `--path` defaults to | `<steam>/steamapps/common/Wizard101` |

`steam-run` matters only on distributions whose filesystem Proton's bundled
binaries cannot cope with (NixOS, Guix). Elsewhere it is simply absent and
skipped.

**Credentials are sealed with a passphrase.** Windows stores them in Credential
Manager, where DPAPI seals them against your logon credentials. Linux has no
equivalent that can be relied on — the Secret Service API needs a daemon that a
bare Wayland or headless session does not run — so accounts live in a single
file, `~/.config/Deimos/credentials.bin`, with Argon2id deriving the key and
ChaCha20-Poly1305 sealing the whole account map. The file reveals neither
passwords nor which accounts exist, and the passphrase is asked for once per
process. **There is no recovery if you forget it.**

Because the prompts read the terminal rather than a dialog, `add` must be run
from a terminal, and so must anything that opens the store (including
`list_accounts()` from Python).

**Steam mode does nothing.** `--steam` and the per-account flag are still
accepted and stored, so metadata and the Python API stay identical across
platforms, but they change nothing here. Linux Steam keeps no registry tree to
read run/login state from (`~/.steam/registry.vdf` holds only `AutoLoginUser`),
and a client started by `proton run` has no Steam app context for `-ST` to
initialize against.

**A handle is a process id.** On Windows an instance is identified by its
`HWND`, found by matching the window class `Wizard Graphical Client`. Proton
reports `WM_CLASS` as `steam_proton` for every window it creates, so that class
is not observable from outside the prefix — and one client owns several X11
windows. Instances are therefore identified by process instead. Handles stay
opaque; pass them back to this library and nothing else.

Memory login works the same way, through `/proc/<pid>/mem` instead of
`ReadProcessMemory`/`WriteProcessMemory`. The one real difference is that Linux
has no `VirtualAllocEx`: scratch space is taken from the zero padding at the end
of the client image's executable section, which avoids having to ptrace-stop a
thread of the running game and is always within rel32 reach of the hook site.

## Credits
- [Click](https://github.com/CIick): RE and initial development effort behind memory based login
- [Slackaduts](https://github.com/Slackaduts): Rust port, integrations
