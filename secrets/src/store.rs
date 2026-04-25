use async_trait::async_trait;

use crate::{Secret, SecretError, SecretKey};

/// Backend-agnostic secret store.
///
/// Backends live in sibling crates (`secrets-memory`, `secrets-keyring`, …)
/// and are selected at startup the same way `data-sqlite` vs `data-postgres`
/// is selected today. Consumers depend on this trait, never on a concrete
/// backend.
#[async_trait]
pub trait SecretStore: Send + Sync {
    /// Fetch a secret. Returns `Ok(None)` when the key is absent — that is
    /// the *normal* "not found" case and is not an error.
    async fn get(&self, key: &SecretKey) -> Result<Option<Secret>, SecretError>;

    /// Store a secret, overwriting any prior value at the same key.
    async fn put(&self, key: &SecretKey, value: Secret) -> Result<(), SecretError>;

    /// Remove a secret. Deleting a non-existent key is a no-op success;
    /// callers should not rely on this to detect existence.
    async fn delete(&self, key: &SecretKey) -> Result<(), SecretError>;

    /// Enumerate stored keys. Some backends (e.g. macOS keychain without
    /// explicit user consent) may surface a prompt on each call — list with
    /// care.
    async fn list(&self) -> Result<Vec<SecretKey>, SecretError>;
}
