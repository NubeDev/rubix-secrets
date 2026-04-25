use std::collections::BTreeSet;

use async_trait::async_trait;
use keyring::Entry;
use secrets::{Secret, SecretError, SecretKey, SecretStore};

/// Reserved keystore account used to persist the list of known
/// `<kind>:<scope>` pairs. Must not collide with a real `kind` — the leading
/// double underscore makes that obvious to a human reading the keystore.
const INDEX_ACCOUNT: &str = "__index__";

/// OS-keystore backed secret store.
///
/// `service` is the keystore "service" / "target" / "application" name,
/// shared across every secret this process owns. The recommended value is
/// `"block-os"`; tests and dev installs may use `"block-os-dev"` to avoid
/// stomping a real install's entries.
#[derive(Clone)]
pub struct KeyringSecretStore {
    service: String,
}

impl KeyringSecretStore {
    /// Construct a backend bound to a single keystore service name.
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry(&self, account: &str) -> Result<Entry, SecretError> {
        Entry::new(&self.service, account).map_err(map_keyring_err)
    }

    async fn read_index(&self) -> Result<BTreeSet<String>, SecretError> {
        let svc = self.service.clone();
        run_blocking(move || {
            let entry = Entry::new(&svc, INDEX_ACCOUNT).map_err(map_keyring_err)?;
            match entry.get_password() {
                Ok(s) => Ok(parse_index(&s)),
                Err(keyring::Error::NoEntry) => Ok(BTreeSet::new()),
                Err(e) => Err(map_keyring_err(e)),
            }
        })
        .await
    }

    async fn write_index(&self, index: BTreeSet<String>) -> Result<(), SecretError> {
        let svc = self.service.clone();
        run_blocking(move || {
            let entry = Entry::new(&svc, INDEX_ACCOUNT).map_err(map_keyring_err)?;
            entry
                .set_password(&serialize_index(&index))
                .map_err(map_keyring_err)
        })
        .await
    }
}

#[async_trait]
impl SecretStore for KeyringSecretStore {
    async fn get(&self, key: &SecretKey) -> Result<Option<Secret>, SecretError> {
        let svc = self.service.clone();
        let account = key.account();
        run_blocking(move || {
            let entry = Entry::new(&svc, &account).map_err(map_keyring_err)?;
            match entry.get_secret() {
                Ok(bytes) => Ok(Some(Secret::from_bytes(bytes))),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(map_keyring_err(e)),
            }
        })
        .await
    }

    async fn put(&self, key: &SecretKey, value: Secret) -> Result<(), SecretError> {
        let account = key.account();
        let bytes = value.expose().to_vec();
        let entry = self.entry(&account)?;
        run_blocking(move || entry.set_secret(&bytes).map_err(map_keyring_err)).await?;

        let mut index = self.read_index().await.unwrap_or_default();
        if index.insert(account) {
            // Index updates are best-effort — a write failure does not roll
            // back the secret. Worst case `list()` is incomplete until the
            // next successful put.
            let _ = self.write_index(index).await;
        }
        Ok(())
    }

    async fn delete(&self, key: &SecretKey) -> Result<(), SecretError> {
        let account = key.account();
        let entry = self.entry(&account)?;
        let acc_for_blocking = account.clone();
        run_blocking(move || match entry.delete_credential() {
            Ok(()) => Ok(()),
            // Deleting an absent key is a no-op success per the trait contract.
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(map_keyring_err(e)),
        })
        .await?;

        let mut index = self.read_index().await.unwrap_or_default();
        if index.remove(&acc_for_blocking) {
            let _ = self.write_index(index).await;
        }
        Ok(())
    }

    async fn list(&self) -> Result<Vec<SecretKey>, SecretError> {
        let index = self.read_index().await?;
        Ok(index
            .into_iter()
            .filter_map(|s| parse_account(&s))
            .collect())
    }
}

fn parse_account(s: &str) -> Option<SecretKey> {
    let (kind, scope) = s.split_once(':')?;
    Some(SecretKey::new(kind, scope))
}

fn parse_index(raw: &str) -> BTreeSet<String> {
    raw.lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn serialize_index(set: &BTreeSet<String>) -> String {
    set.iter().cloned().collect::<Vec<_>>().join("\n")
}

fn map_keyring_err(e: keyring::Error) -> SecretError {
    match e {
        keyring::Error::PlatformFailure(inner) => {
            SecretError::Unavailable(format!("platform failure: {inner}"))
        }
        keyring::Error::NoStorageAccess(inner) => {
            SecretError::Unavailable(format!("no storage access: {inner}"))
        }
        // `NoEntry` is handled at every call site that can produce it — by
        // the time we land here it is genuinely unexpected.
        other => SecretError::Backend(anyhow::anyhow!(other)),
    }
}

async fn run_blocking<F, T>(f: F) -> Result<T, SecretError>
where
    F: FnOnce() -> Result<T, SecretError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| SecretError::Backend(anyhow::anyhow!("join error: {e}")))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_roundtrip() {
        let k = SecretKey::new("oidc.refresh", "p1");
        let parsed = parse_account(&k.account()).unwrap();
        assert_eq!(parsed, k);
    }

    #[test]
    fn index_roundtrip_is_sorted_and_dedup() {
        let mut set = BTreeSet::new();
        set.insert("oidc.refresh:p1".to_owned());
        set.insert("fleet.bootstrap:f1".to_owned());
        let raw = serialize_index(&set);
        assert_eq!(raw, "fleet.bootstrap:f1\noidc.refresh:p1");
        assert_eq!(parse_index(&raw), set);
    }

    #[test]
    fn index_parser_ignores_blanks_and_whitespace() {
        let raw = "  oidc.refresh:p1  \n\n fleet.bootstrap:f1 \n";
        let set = parse_index(raw);
        assert!(set.contains("oidc.refresh:p1"));
        assert!(set.contains("fleet.bootstrap:f1"));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn malformed_account_is_skipped_in_list() {
        assert!(parse_account("no-colon-here").is_none());
    }
}
