# block-os-secrets

Reusable secret-storage seam for Block OS.

The trait and types defined here are consumed by:

- `block-agent` — picks a backend at startup based on role (memory for tests
  and `--role cloud`, file for headless Linux opt-in, none on the agent in the
  desktop profile because Studio owns the user's keystore).
- `block-os-desktop` — the Tauri shell's Rust side reads/writes the user's OS
  keystore (`secrets-keyring`) on behalf of the signed-in user, then hands the
  agent only the bearers it needs in memory.

See `block-agent/docs/design/desktop/SECRETS.md` for the full design.

## Crates

| Crate | Backend | Use |
|---|---|---|
| `secrets` | — | Trait, `Secret`, `SecretKey`, `SecretError` |
| `secrets-memory` | in-memory `HashMap` | Tests, ephemeral roles |
| `secrets-keyring` (TBD) | OS keystore via `keyring = "3"` | Desktop / Studio Tauri side |
| `secrets-file` (TBD) | encrypted file, opt-in | Headless Linux fallback |

The trait deliberately does not depend on any backend. Consumers link only the
backend they need; the agent in standalone offline mode must not pull the
keystore backend in.
