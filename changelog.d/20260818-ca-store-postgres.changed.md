- **`CaStore` migrated from SQLite to PostgreSQL** (schema `ca_store`, ADR-0053), covering the
  internal-CA inventory + lifecycle (root metadata, issued-cert inventory, CRL version history —
  the root private key stays behind `KeyProvider`, never in this store). A mandatory first-boot
  backfill fingerprints all three tables together per distinct legacy-file content, refusing
  closed on a half-schema legacy file, an identity mismatch on an already-established root, or a
  legacy revoked/Postgres-active lifecycle disagreement (never silently un-revokes a certificate).
  A new race-safe `try_insert_root()` entry point closes a first-boot hazard a shared Postgres
  substrate introduces that per-instance SQLite never could — two instances independently
  generating CA root material and racing to establish it now resolve to exactly one canonical
  root, with the loser refusing to serve under unusable material rather than clobbering the
  winner. `is_revoked()`, the mTLS-accept security gate, keeps its plain-boolean, fail-closed
  contract unchanged — every degradation mode (including a database outage) is treated as
  "revoked," never silently as "not revoked." This is a live-wired store, so every already-issued
  request against `/api/v1/ca/*`, the CA MCP tools, and the Settings CA panel now surfaces a
  genuine database error as a 503/error response instead of a silently-empty/-false result.
