"""Type stubs for the wizlaunch native module.

Windows and Linux are both supported. Where behaviour differs it is noted on
the function; the two that matter are that a ``handle`` is an HWND on Windows
but a process id on Linux, and that Steam mode does nothing on Linux.
"""

def prompt_save_account(nickname: str) -> None:
    """Prompt for and store credentials for the given nickname.

    Python never sees the username or password: on Windows they are collected by
    CredUI, a dialog the OS owns and draws, and on Linux they are read straight
    off the controlling terminal. Either way they are used and dropped inside
    the native module.

    Because the Linux prompt needs a terminal, this raises RuntimeError when
    called with no tty attached. It also raises if the user cancels or the
    prompt fails.
    """
    ...

def delete_account(nickname: str) -> None:
    """Delete an account from the credential store and metadata."""
    ...

def list_accounts() -> list[str]:
    """List all account nicknames in stored order."""
    ...

def reorder_accounts(ordered: list[str]) -> None:
    """Reorder accounts to the given nickname order."""
    ...

def has_account(nickname: str) -> bool:
    """Check if an account exists in the credential store."""
    ...

def validate_account(nickname: str) -> str | None:
    """Validate an account entry.

    Returns a human-readable error string if the entry needs attention (e.g. an
    older account saved before Steam support, which lacks a Steam-mode flag), or
    None if it is fully configured.
    """
    ...

def get_account_steam(nickname: str) -> bool | None:
    """Get an account's Steam-mode flag, or None if it has never been set."""
    ...

def set_account_steam(nickname: str, steam: bool) -> None:
    """Set whether an account launches in Steam mode.

    Stored on every platform, but only acted on by Windows. A Linux client is
    launched through Proton with ``-L`` alone, so the flag changes nothing there.
    """
    ...

def get_window_config(
    nickname: str,
) -> tuple[int, int, int, int, int, int, bool] | None:
    """Get an account's window placement/resolution config, or None if unset.

    Returns ``(x, y, w, h, res_w, res_h, locked)``: window top-left in virtual-
    desktop screen coords, window client size, forced render resolution, and
    whether resolution is locked to the client size (crisp 1:1).
    """
    ...

def set_window_config(
    nickname: str,
    x: int, y: int, w: int, h: int,
    res_w: int, res_h: int, locked: bool,
) -> None:
    """Set an account's window placement/resolution config."""
    ...

def clear_window_config(nickname: str) -> None:
    """Clear an account's window config (revert to default behavior)."""
    ...

def update_player_gid(nickname: str, gid: int) -> None:
    """Update the player GID (global ID) for a nickname."""
    ...

def get_player_gid(nickname: str) -> int | None:
    """Get the player GID for a nickname, or None if not set."""
    ...

def get_nickname_by_gid(gid: int) -> str | None:
    """Look up a nickname by its player GID, or None if not found."""
    ...

def launch_instance(
    nickname: str, game_path: str,
    login_server: str | None = None,
    timeout_secs: int = 30,
) -> int:
    """Launch one game instance, log in, and return its handle.

    The handle is an HWND on Windows and a process id on Linux; treat it as
    opaque and pass it only back to this module.

    Credentials are read from the credential store internally and never enter
    Python. This function blocks — call via ``asyncio.to_thread()``.
    """
    ...

def launch_instances(
    nicknames: list[str], game_path: str,
    login_server: str | None = None,
    timeout_secs: int = 30,
) -> dict[str, int]:
    """Launch multiple game instances and return {nickname: handle}.

    Credentials never enter Python.  Blocks — call via ``asyncio.to_thread()``.
    """
    ...

def kill_instance(handle: int) -> bool:
    """Kill the process behind the given handle. Returns True on success."""
    ...

def get_wizard_handles() -> list[int]:
    """Get a handle for every currently running Wizard101 instance."""
    ...
