# Postgres store playbook — adding (or migrating) a server store

This is the step-by-step recipe for putting a store into the server's PostgreSQL substrate.
It is the *how*; the *why* lives in the ADRs — **read these first**:

| ADR | What it fixes |
|---|---|
| [0006](adr/0006-server-postgresql-substrate.md) | Postgres is the server substrate; **every** server store migrates (2026-06-22 Update) — none stays SQLite. Agent stays SQLite. |
| [0007](adr/0007-server-single-backend-no-sqlite-fallback.md) | Single backend, **fail closed** — no SQLite fallback. |
| [0008](adr/0008-postgres-substrate-architecture.md) | libpq + in-house RAII, one shared `PgPool`, schema-per-store, `PgMigrationRunner`; **schema naming**, non-transactional-migration rule, thin helper (2026-06-22 Update). |
| [0009](adr/0009-per-store-first-boot-backfill-cutover.md) | How a *migrated* store backfills its legacy SQLite data (one-time, idempotent, fail-closed). |
| [0010](adr/0010-secrets-at-rest-envelope-encryption.md) | Secret-bearing stores use `SecretCodec`, never plain columns. |
| [0012](adr/0012-server-postgres-store-contract.md) | The author-facing **contract**: failure posture, lease discipline, cross-store seam. |

The substrate code is `server/core/src/pg/`: `pg_raii.hpp` (`PgConn`/`PgResult`/`PgTxn`),
`pg_pool.{hpp,cpp}` (`PgPool`, `Lease`, `with_txn`, `Observer`), `pg_migration_runner.{hpp,cpp}`,
`pg_exec.hpp` (`exec_params`). `offline_endpoint_store.{hpp,cpp}` is the reference store.

---

## Decisions you must make up front

1. **Posture** (ADR-0012 §1) — is the store **authoritative** (the DB is the source of truth;
   a runtime error is *surfaced*, never a silent empty result) or **durability-on-top**
   (an in-memory layer is authoritative; a DB blip returns empty/`false` and degrades only
   durability)? Most stores are authoritative. State it in the header comment and the per-store
   ADR.
2. **Schema name** (ADR-0008 Update) — `snake_case(FullClassName)`, the `Store` suffix
   **included**: `WidgetStore` → `widget_store`, `ApiTokenStore` → `api_token_store`. Acronyms
   are one word (`RbacStore` → `rbac_store`); do not give a store class an all-caps acronym.
3. **Secrets?** (ADR-0010) — if any column holds secret material, it is verify-only hash or
   `SecretCodec` envelope-encrypted blob, never plaintext. `SecretCodec::init(conn)` runs
   **before** the store opens. `api_token`/`ca` are hash-/key_ref-only; `auth`, `webhooks`,
   `offload_targets`, `runtime_config` require the codec.

---

## Recipe — a new (greenfield) store

1. **Header** declares the substrate contract (copy `offline_endpoint_store.hpp`): the store
   holds a `pg::PgPool&` (not a `sqlite3*`), runs its migration at construction on a pinned
   lease, schema-qualifies every runtime statement, and uses `RETURNING` for mutate-and-return.
   State the posture in the doc comment.

2. **Migrations** — a `static const std::vector<pg::PgMigration>` of `{version, sql}`. DDL is
   **unqualified** (the runner sets `search_path` to your schema for the migration txn). One
   schema per store; `CREATE TABLE foo (...)` lands in your schema. See the
   non-transactional-migration rule below before adding an index to a table that will be large.

3. **Construct** via the thin helper (do not hand-roll): acquire a lease, run
   `PgMigrationRunner::run(lease.get(), "<schema>", migrations())`, set `open_`. The helper
   (`open_with_migrations`) makes this one call; `is_open()` is false if the lease was empty or
   the migration failed.

4. **Runtime statements** schema-qualify the table (`SELECT ... FROM widget_store.widgets`) —
   pooled connections carry **no** per-store `search_path`. Bind parameters with
   `pg::exec_params` (`$1..$N`); never string-concat SQL. Mutate-and-return uses `RETURNING`
   (the #1033-banning idiom), never `sqlite3_changes()`.

5. **Lease discipline** (ADR-0012 §2): every runtime acquire is **bounded**
   (`try_acquire_for(deadline)`) — pick the deadline from posture (hot-path fail-soft: short,
   e.g. 250 ms; user-facing authoritative: longer, e.g. 2 s). Unbounded `acquire()` is
   construction-only. Never hold a lease across network/disk/external work. Never call another
   store while holding a lease (one lease per logical operation).

6. **Wire into `server.cpp`** via the construction helper, after the `PgPool` probe and inside
   the `if (pg_pool_ && !startup_failed_)` guard. A Postgres store that cannot open is a **fatal
   startup error** — the helper flips `startup_failed_` on `!is_open()`. Member-declare the
   store so it destructs *before* the pool (declaration order governs destruction order; the
   pool resets last in `stop()`).

7. **Tests** use `PostgresTestDb` + `YUZU_REQUIRE_PG_DB(var)` (behind `YUZU_TEST_ENABLE_PG`,
   server suite only). Skip-vs-fail contract: env unset → skip cleanly; env set but broken →
   fail. Local: `docker run -d -e POSTGRES_USER=yuzu -e POSTGRES_PASSWORD=yuzu -e
   POSTGRES_DB=yuzu -p 5433:5432 postgres:18` then
   `export YUZU_TEST_POSTGRES_DSN=postgresql://yuzu:yuzu@localhost:5433/yuzu`.

8. **`meson.build`** — add the new `.cpp` to the server target (and the test). `libpq_dep` is
   already gated on `build_server`.

9. **Docs** — per-store ADR (schema + posture + secrets), user-manual touch if operator-facing,
   and tick the store off `docs/postgres-migration-ladder.md` (greenfield stores are added to
   the ladder as "born-on-Pg, no backfill").

## Extra steps when migrating an existing SQLite store

- **Backfill** (ADR-0009): a one-time, idempotent `migrate_from_sqlite()` that runs at startup,
  before serving, and **fails closed** on any error. Mandatory for config/reference and `audit`
  (SOC 2); skippable behind a flag only for purely TTL'd ephemeral stores (`response`).
- **Secret columns transform, never copy** (ADR-0010): a backfill that touches secret material
  encrypts/hashes on the way in — a plain column copy of a secret is forbidden.
- **Rollback window**: retain the legacy `<name>.db` read-only for exactly one release, then
  remove it. The upgrade-test (`scripts/test/docker-compose.upgrade-test.yml`) must assert the
  config/reference/audit data survives previous-release-SQLite → new-release-Postgres.
- **Port the transaction owner**: `SqliteTxn`/`SqliteStmt` → `pool.with_txn` (multi-statement
  invariants) or a single autocommit statement (single-statement mutate-and-return).

## Anti-patterns reviewers reject

- An **authoritative** store that returns an empty result on a DB error (fail-open). Surface it.
- Unbounded `acquire()` on a runtime path. Bound it.
- Holding a lease across an HTTP call, file I/O, or a second store call (deadlock / starvation).
- Unqualified runtime table names (works in a migration, breaks on a pooled connection).
- `sqlite3_changes()`-style mutate-then-count. Use `RETURNING`.
- A plaintext secret column. Use `SecretCodec` / verify-only hash.
- A new server **SQLite** store (ADR-0006 forbids it without an exception ADR).
- A `CREATE INDEX CONCURRENTLY` / `VACUUM` / `ALTER TYPE ADD VALUE` smuggled into a
  `PgMigration` — it cannot run in the runner's transaction (see below).

## Non-transactional migrations (the deferred kind)

`PgMigrationRunner` runs every migration in a transaction (`SET LOCAL search_path` requires it),
so statements that cannot run in a transaction block — `CREATE INDEX CONCURRENTLY`, `VACUUM`,
`ALTER TYPE ... ADD VALUE` — **cannot** be a `PgMigration` today. The non-transactional migration
kind is **deliberately not built yet** (no store needs it). The rule:

- Initial DDL on a **new/empty** table uses normal transactional migrations — a plain
  `CREATE INDEX` on an empty table takes a trivial lock and is fine.
- An index/DDL added to an **already-large** table during a live rolling upgrade would take a
  multi-minute `ACCESS EXCLUSIVE` lock with a plain `CREATE INDEX`. That requires the
  non-transactional kind, which **must be built** (self-schema-qualifying, runs outside a txn)
  *before* such a migration ships. Do not weaken the transactional default to sneak one in.
