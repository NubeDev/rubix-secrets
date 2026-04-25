use thiserror::Error;

/// Errors returned by a [`crate::SecretStore`] backend.
#[derive(Error, Debug)]
pub enum SecretError {
    /// Backend cannot be reached at all (Linux Secret Service not running,
    /// macOS keychain unavailable, etc). Caller decides whether to degrade
    /// or refuse to start.
    #[error("backend unavailable: {0}")]
    Unavailable(String),

    /// User explicitly denied the access prompt (macOS keychain dialog,
    /// Linux gnome-keyring unlock, …).
    #[error("denied by user")]
    Denied,

    /// Anything else — wraps the underlying backend error so callers can
    /// log it without coupling to a specific OS keystore library.
    #[error("backend error: {0}")]
    Backend(#[from] anyhow::Error),
}
