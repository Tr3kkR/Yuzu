- **Faster `[pg]` server tests: shared-DB + `TRUNCATE` fixtures (#2354).** Convertible
  Postgres store-behaviour tests now share one migrated database + one persistent
  connection pool per test file, `TRUNCATE`-resetting between tests, instead of cloning a
  fresh database and spinning up a new pool per test. This cuts the per-test backend
  connections that dominate the Windows `[pg]`-shard cost (Postgres on Windows is
  `EXEC_BACKEND` — a fresh `postgres.exe` per connection). Behaviour-preserving: identical
  store calls and assertions; only the database provisioning/isolation substrate changes.
  Tests that DROP the store schema, rewind `schema_meta`, or drop columns to force a
  degrade keep their own per-test database. `test_software_inventory_store.cpp` is the
  reference conversion; `test_helpers.hpp` gains `SharedPgDbRegistry`, which drops the
  shared clones at `testRunEnded` (never a static destructor, avoiding the OpenSSL-atexit
  teardown hazard).
