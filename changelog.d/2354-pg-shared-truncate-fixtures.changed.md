- **Faster `[pg]` server tests: shared-DB + `TRUNCATE` fixtures (#2354).** Convertible
  Postgres store-behaviour tests now share one migrated database + one persistent
  connection pool per test file, `TRUNCATE`-resetting between tests, instead of cloning a
  fresh database and spinning up a new pool per test. This cuts the per-test backend
  connections that dominate the Windows `[pg]`-shard cost (Postgres on Windows is
  `EXEC_BACKEND` — a fresh `postgres.exe` per connection). Behaviour-preserving: identical
  store calls and assertions; only the database provisioning/isolation substrate changes.
  Tests that DROP the store schema, rewind `schema_meta`, drop columns to force a degrade,
  or hold a session-level advisory lock keep their own per-test database. Converted:
  `test_software_inventory_store.cpp` (reference), `test_software_licensing_store.cpp`,
  `test_software_licensing_ingestion.cpp`, and `test_product_registry_store.cpp`.
  `test_helpers.hpp` gains `SharedPgDbRegistry`, which drains each persistent pool and then
  drops its shared clone at `testRunEnded` (never a static destructor, avoiding the
  OpenSSL-atexit teardown hazard).
