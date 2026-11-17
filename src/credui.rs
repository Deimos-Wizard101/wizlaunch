//! Credential prompting.
//!
//! Windows uses CredUI, a dialog the OS owns and draws. Linux has no equivalent
//! and reads the controlling terminal instead. Either way the credentials are
//! collected, used and dropped inside this library, so Python never sees them.

pub use crate::platform::prompt::prompt_credentials;
