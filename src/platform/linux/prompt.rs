//! Credential prompts on Linux.
//!
//! The Win32 build uses `CredUIPromptForWindowsCredentialsW`, a dialog the OS
//! owns and draws. Nothing on Linux offers that, so the prompt is read straight
//! off the controlling terminal. The property that matters is preserved — the
//! password is read, used and dropped inside this library, never crossing the
//! Python boundary — but it does mean the prompting commands have to be run
//! from a terminal.

use crate::errors::VaultError;
use std::io::{self, BufRead, Write};

/// Opt-in non-interactive credential entry, for automation and testing where no
/// terminal is attached. When the matching variables are set they are used in
/// place of a terminal prompt; otherwise the terminal prompt is used exactly as
/// before. These expose the secret in the process environment, so they are a
/// deliberate, caller-set convenience — never a default.
const ENV_PASSPHRASE: &str = "WIZLAUNCH_STORE_PASSPHRASE";
const ENV_USERNAME: &str = "WIZLAUNCH_ACCOUNT_USERNAME";
const ENV_PASSWORD: &str = "WIZLAUNCH_ACCOUNT_PASSWORD";

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// Fail early and clearly rather than block on a stdin nobody is attached to.
fn require_tty() -> Result<(), VaultError> {
    if unsafe { libc::isatty(libc::STDIN_FILENO) } == 1 {
        return Ok(());
    }
    Err(VaultError::CredUiFailed(
        "no terminal is attached, so credentials cannot be entered; \
         run this from a terminal"
            .to_string(),
    ))
}

fn hidden(prompt: &str) -> Result<String, VaultError> {
    rpassword::prompt_password(prompt).map_err(|e| VaultError::CredUiFailed(e.to_string()))
}

/// Collect an account's username and password.
pub fn prompt_credentials(caption: &str, message: &str) -> Result<(String, String), VaultError> {
    if let (Some(username), Some(password)) = (env_nonempty(ENV_USERNAME), env_nonempty(ENV_PASSWORD))
    {
        return Ok((username, password));
    }

    require_tty()?;

    let mut err = io::stderr();
    writeln!(err, "{caption}").ok();
    writeln!(err, "{message}").ok();
    write!(err, "Username: ").ok();
    err.flush().ok();

    let mut username = String::new();
    io::stdin()
        .lock()
        .read_line(&mut username)
        .map_err(|e| VaultError::CredUiFailed(e.to_string()))?;
    let username = username.trim().to_string();
    if username.is_empty() {
        return Err(VaultError::CredUiCancelled);
    }

    let password = hidden("Password: ")?;
    if password.is_empty() {
        return Err(VaultError::CredUiCancelled);
    }

    Ok((username, password))
}

/// Collect the passphrase that unlocks the credential store, asking twice when
/// the store is being created.
pub fn prompt_passphrase(confirm: bool) -> Result<String, VaultError> {
    if let Some(passphrase) = env_nonempty(ENV_PASSPHRASE) {
        return Ok(passphrase);
    }

    require_tty()?;

    if confirm {
        writeln!(
            io::stderr(),
            "Creating the credential store. This passphrase protects every saved \
             account; there is no way to recover it."
        )
        .ok();
    }

    let passphrase = hidden("Credential store passphrase: ")?;
    if passphrase.is_empty() {
        return Err(VaultError::CredUiCancelled);
    }

    if confirm && hidden("Confirm passphrase: ")? != passphrase {
        return Err(VaultError::CredUiFailed(
            "the passphrases did not match".to_string(),
        ));
    }

    Ok(passphrase)
}
