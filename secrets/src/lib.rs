//! Block OS secret-storage trait.
//!
//! Three classes of secret material exist on a Block OS install:
//!
//! 1. **Long-lived bearers** — OIDC refresh tokens, fleet bootstrap secrets,
//!    blockd `owner_token`. Loss = account takeover. These belong in a
//!    [`SecretStore`].
//! 2. **Short-lived bearers** — OIDC access tokens, SSE `?token=` values.
//!    Held in process memory only; this crate does not address them.
//! 3. **Non-secret config** — graph data, prefs, fleet endpoint URL. Lives in
//!    SQLite. Not this crate's concern.
//!
//! See `block-agent/docs/design/desktop/SECRETS.md` for the full design rationale,
//! key namespace, and Tauri-handshake flow.

mod error;
mod key;
mod secret;
mod store;

pub use error::SecretError;
pub use key::SecretKey;
pub use secret::Secret;
pub use store::SecretStore;
