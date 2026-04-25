/// Stable identity of a secret in the store.
///
/// Backends map this to whatever native identifier they support. The keyring
/// backend uses service `block-os` and account `<kind>:<scope>`.
///
/// `kind` strings are a contract surface — additions are part of a versioned
/// release. Reserved kinds today:
///
/// - `oidc.refresh`     — OIDC refresh token (scope: profile id)
/// - `fleet.bootstrap`  — one-shot fleet enrollment secret (scope: fleet id)
/// - `fleet.session`    — long-lived fleet session token (scope: fleet id)
/// - `blockd.owner`     — bearer for the local blockd loopback API (scope: machine id)
/// - `cloud.cert_pin`   — SHA-256 pin of the cloud API TLS cert (scope: host)
/// - `studio.handshake` — Tauri-shell ↔ agent loopback bearer (scope: install id)
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SecretKey {
    /// Stable namespace, e.g. `"oidc.refresh"`. Lowercase, dot-separated.
    pub kind: String,
    /// Disambiguator within a kind: profile id, tenant id, fleet id, machine id, …
    pub scope: String,
}

impl SecretKey {
    /// Convenience constructor that takes anything `Into<String>`.
    pub fn new(kind: impl Into<String>, scope: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            scope: scope.into(),
        }
    }

    /// Encoding used by the keyring backend as the "account" attribute and by
    /// any other backend that needs a single flat string.
    pub fn account(&self) -> String {
        format!("{}:{}", self.kind, self.scope)
    }
}
