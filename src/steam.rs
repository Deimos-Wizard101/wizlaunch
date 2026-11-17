//! Steam client detection, launch, and per-app setup for Wizard101.
//!
//! Fully implemented on Windows, where the client's Steam build authenticates
//! against a running, signed-in Steam client.
//!
//! Inert on Linux: the per-account flag is still stored so metadata and the
//! Python API are identical across platforms, but Steam is never required or
//! touched and the client is launched through Proton with `-L` alone. See
//! [`crate::platform::steam`] for why it cannot be ported faithfully.

pub use crate::platform::steam::{
    ensure_appid as ensure_steam_appid, ensure_ready as ensure_steam_ready, is_steam_logged_in,
    is_steam_running, launch_steam, steam_exe_path, STEAM_LOGIN_TIMEOUT_SECS, WIZARD101_APP_ID,
};
