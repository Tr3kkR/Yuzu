- **`DeviceTokenStore` migrated from SQLite to PostgreSQL** (schema `device_token_store`,
  ADR-0052), with a mandatory first-boot backfill of the legacy `device-tokens.db`, tracked per
  distinct legacy-file content (SHA-256 fingerprint) rather than a single fleet-wide flag, so a
  database replica with no local legacy file can never block a different replica's real
  device-token history from being migrated. A legacy row's identity fields
  (`token_hash`/`name`/`principal_id`/`device_id`/`definition_id`/`created_at`/`expires_at`)
  failing to match an already-migrated Postgres row fails the boot closed rather than silently
  discarding one side. A legacy row showing a token already revoked, while the matching Postgres
  row is still active, also fails the boot closed rather than silently keeping the stale "active"
  value — revocation evidence is never discarded. `list_tokens`/`revoke_token`/
  `revoke_by_principal` now surface a genuine database error distinctly from "no tokens"/"not
  found"/"nothing to revoke" (previously a bare `std::vector`/`bool`/`int64_t` that collapsed
  both cases). This store is currently **dormant** — nothing in `server.cpp` constructs a
  `DeviceTokenStore`, so this PR is a pure persistence-layer migration with no
  runtime-observable effect on any current caller; the `/api/v1/device-tokens*` REST endpoints
  (documented with new error-response tables in `docs/user-manual/rest-api.md`) remain
  unregistered until a future change re-wires construction.
