//! OS-keystore [`SecretStore`] backend.
//!
//! Wraps the `keyring` crate (v3). Per-platform mapping:
//!
//! | OS      | Backend                                          |
//! |---------|--------------------------------------------------|
//! | Windows | Credential Manager (DPAPI, per-user)             |
//! | macOS   | Keychain (login keychain, per-user)              |
//! | Linux   | Secret Service / libsecret (gnome-keyring, …)    |
//!
//! The keyring crate exposes a sync API and individual platforms vary widely
//! in how they treat enumeration. We:
//!
//! - run every `Entry` call inside [`tokio::task::spawn_blocking`] so the
//!   async runtime stays responsive when a Linux unlock dialog extensions;
//! - persist a small index entry under the reserved account `__index__` so
//!   [`SecretStore::list`] is portable. Without this, Windows Credential
//!   Manager and macOS Keychain enumeration require platform-specific code
//!   and (on macOS) a per-entry user prompt.
//!
//! The index is best-effort. A stale index entry never produces a wrong
//! secret — `get` always returns whatever the OS keystore has now.

mod store;

pub use store::KeyringSecretStore;
