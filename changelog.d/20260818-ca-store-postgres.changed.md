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
- **Default-cert bootstrap now self-heals a corrupt on-disk leaf set on any boot, not only a
  first-boot crash-recovery window** — if the local CA key still resolves and cryptographically
  pairs with `ca_store`'s recorded root, a missing/incomplete/mismatched local cert or key is
  regenerated in place without re-rooting or touching already-enrolled agents. Guarded by a
  Postgres session advisory lock (`yuzu:default_certs_bootstrap`) so two instances sharing one
  cert directory and one `ca_store` substrate never interleave a mismatched cert/key pair — a
  topology this release does not otherwise officially support (see ADR-0053's Decision section).
- **The revocation-sweep tick now aborts entirely on a degraded `ca_store` read**, rather than
  treating every currently-connected agent as revoked and tearing down its live stream. A
  sustained failure is now visible via `yuzu_server_ca_revocation_sweep_read_failures_total`
  instead of manifesting only as unexplained agent disconnects.
