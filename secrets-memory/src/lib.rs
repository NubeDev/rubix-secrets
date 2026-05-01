//! In-memory [`SecretStore`] backend.
//!
//! Used by:
//! - unit and integration tests, where pulling the OS keystore is wrong;
//! - the agent in roles where no host keystore exists (cloud, ephemeral
//!   containers) and bearers are injected at startup over a privileged
//!   channel rather than persisted.
//!
//! Values live in process memory only and are wiped on drop along with the
//! [`Secret`] wrapper.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use secrets::{Secret, SecretError, SecretKey, SecretStore};
use tokio::sync::RwLock;

/// In-memory secret store. Cheap to clone — the inner map is shared.
#[derive(Clone, Default)]
pub struct MemorySecretStore {
    inner: Arc<RwLock<HashMap<SecretKey, Secret>>>,
}

impl MemorySecretStore {
    /// Construct an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SecretStore for MemorySecretStore {
    async fn get(&self, key: &SecretKey) -> Result<Option<Secret>, SecretError> {
        let guard = self.inner.read().await;
        Ok(guard.get(key).cloned())
    }

    async fn put(&self, key: &SecretKey, value: Secret) -> Result<(), SecretError> {
        let mut guard = self.inner.write().await;
        guard.insert(key.clone(), value);
        Ok(())
    }

    async fn delete(&self, key: &SecretKey) -> Result<(), SecretError> {
        let mut guard = self.inner.write().await;
        guard.remove(key);
        Ok(())
    }

    async fn list(&self) -> Result<Vec<SecretKey>, SecretError> {
        let guard = self.inner.read().await;
        Ok(guard.keys().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(kind: &str, scope: &str) -> SecretKey {
        SecretKey::new(kind, scope)
    }

    #[tokio::test]
    async fn get_missing_returns_none() {
        let store = MemorySecretStore::new();
        let got = store.get(&key("oidc.refresh", "p1")).await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn put_then_get_roundtrips() {
        let store = MemorySecretStore::new();
        let k = key("oidc.refresh", "p1");
        store
            .put(&k, Secret::from_string("hunter2".into()))
            .await
            .unwrap();
        let got = store.get(&k).await.unwrap().expect("stored");
        assert_eq!(got.expose(), b"hunter2");
    }

    #[tokio::test]
    async fn put_overwrites_prior_value() {
        let store = MemorySecretStore::new();
        let k = key("fleet.session", "f1");
        store
            .put(&k, Secret::from_string("old".into()))
            .await
            .unwrap();
        store
            .put(&k, Secret::from_string("new".into()))
            .await
            .unwrap();
        let got = store.get(&k).await.unwrap().expect("stored");
        assert_eq!(got.expose(), b"new");
    }

    #[tokio::test]
    async fn delete_removes_value_and_is_idempotent() {
        let store = MemorySecretStore::new();
        let k = key("rubixd.owner", "m1");
        store
            .put(&k, Secret::from_string("token".into()))
            .await
            .unwrap();
        store.delete(&k).await.unwrap();
        assert!(store.get(&k).await.unwrap().is_none());
        // Second delete is a no-op success.
        store.delete(&k).await.unwrap();
    }

    #[tokio::test]
    async fn list_returns_inserted_keys() {
        let store = MemorySecretStore::new();
        let a = key("oidc.refresh", "p1");
        let b = key("fleet.bootstrap", "f1");
        store
            .put(&a, Secret::from_string("x".into()))
            .await
            .unwrap();
        store
            .put(&b, Secret::from_string("y".into()))
            .await
            .unwrap();
        let mut keys = store.list().await.unwrap();
        keys.sort_by_key(|k| k.account());
        assert_eq!(keys, vec![b, a]);
    }

    #[tokio::test]
    async fn account_encoding_is_kind_colon_scope() {
        assert_eq!(key("oidc.refresh", "p1").account(), "oidc.refresh:p1");
    }
}
