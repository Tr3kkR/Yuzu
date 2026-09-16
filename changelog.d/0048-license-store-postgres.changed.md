- **`LicenseStore` migrated from SQLite to PostgreSQL** (schema `license_store`, ADR-0048),
  with a mandatory first-boot backfill of the legacy `license.db`, tracked per distinct
  legacy-file content (SHA-256 fingerprint across both tables) rather than a single fleet-wide
  flag, so a database replica with no local legacy file can never block a different replica's
  real license/alert history from being migrated. A legacy row's identity fields
  (`license_key_hash`/`organization`/`seat_count`/`issued_at`/`expires_at`/`edition`/
  `features_json`) failing to match an already-migrated Postgres row fails the boot closed
  rather than silently discarding one side; a lifecycle-only difference (`status`/
  `activated_at`) resolves by direction, matching `DeploymentStore`'s precedent. This store is
  currently **dormant** — nothing in `server.cpp` constructs a `LicenseStore`, so this PR is a
  pure persistence-layer migration with no runtime-observable effect on any current caller; the
  `/api/v1/license*` REST endpoints (documented with new error-response tables in
  `docs/user-manual/rest-api.md`) remain unregistered until a future change re-wires
  construction.
