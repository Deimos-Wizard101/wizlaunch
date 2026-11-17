//! Per-target implementations of everything that touches the OS.
//!
//! Both targets expose the same submodules with the same signatures, so the
//! shared code above this layer — the login bytecode in [`crate::login`], the
//! launch/login sequencing in [`crate::launcher`], and the facades the Python
//! module calls — never branches on the platform.
//!
//! Where a concept simply does not exist on a target, the difference is
//! documented at the implementation rather than papered over. The two that
//! matter: an instance `handle` is an `HWND` on Windows but a pid on Linux
//! (Proton gives every window the same class, so there is nothing to match on),
//! and Steam mode is inert on Linux (see [`linux::steam`]).

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

#[cfg(unix)]
mod linux;
#[cfg(unix)]
pub use linux::*;
