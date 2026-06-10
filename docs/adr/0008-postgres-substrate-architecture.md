---
status: accepted
date: 2026-06-09
owner: Nathan Dornbrook (platform)
deciders: Nathan Dornbrook; grill-with-docs design session 2026-06-09
scope: platform — the shared server Postgres substrate layer (server/core/src/pg/)
builds-on: ADR-0006 (Postgres substrate), ADR-0007 (single-backend)
---

# 0008 — Postgres substrate architecture: libpq + in-house RAII, shared pool, schema-per-store

## Context

ADR-0006/0007 commit the server to a single PostgreSQL backend. Before any store is written or
migrated, the shared substrate layer must be specified: the client library, the connection
model, the schema-migration mechanism, and how the one database is namespaced. The existing
SQLite layer sets the idioms to mirror: per-store `sqlite3*` handles guarded by a
`shared_mutex`, the `SqliteTxn`/`SqliteStmt` RAII owners (`server/core/src/sqlite_raii.hpp`),
the `MigrationRunner` (numbered `{version, sql}` migrations + a per-store `schema_meta` row,
`server/core/src/migration_runner.hpp`), the `RETURNING`/#1033 atomic-mutate idiom, and one
existing shared-connection pool (`InstructionDbPool`). The Windows build is a hard constraint:
the MSVC triplet forces **static** linkage (the #375 gRPC static-link saga).

## Decision

The substrate (new `server/core/src/pg/`) is:

- **Client library: raw `libpq` wrapped in in-house RAII** (`PgConn` owns `PGconn*`/`PQfinish`,
  `PgResult` owns `PGresult*`/`PQclear`, `PgTxn` is a direct port of `SqliteTxn`, plus a
  prepared-statement helper). Chosen over `libpqxx`: `libpq` is pure C with an OpenSSL-only
  dependency (we already static-link OpenSSL), giving the **lowest Windows MSVC static-link
  risk**, and it maps almost 1:1 onto the existing per-store `sqlite3*` idiom. We already
  hand-write RAII, so `libpqxx`'s ergonomics buy little and add a second C++ static-link surface.
- **Connection model: one shared in-process `PgPool`** (bounded set of `PgConn`, checkout-per-
  operation, pin-per-transaction), injected into every store in place of the per-store handle.
  This generalizes `InstructionDbPool` to the whole server, exploits Postgres's real
  concurrency (the per-store `shared_mutex` serialization goes away), and bounds backend
  processes. Synchronous `libpq` + a thread-safe pool fits the current thread model; no async.
- **Migrations: `PgMigrationRunner`**, a port of `MigrationRunner` — numbered `{version, sql}`
  migrations registered in C++ next to each store, applied against a shared
  `schema_meta(store, version, upgraded_at)` table. No external migration tool, no new runtime
  dependency, migrations stay co-located with store code exactly as today.
- **Namespacing: one Postgres SCHEMA per store** (`response`, `audit`, `guardian`,
  `vuln_graph`, …). Preserves the logical "29 separate stores" isolation and each store's own
  migration lineage, and turns the vuln-graph scoring join (`vuln_graph.edges ⨝
  guardian.state`) into a real qualified-name SQL join instead of an application-layer stitch.
- **No virtual backend interface.** Single-backend (ADR-0007) ⇒ stores stay concrete classes
  over `PgPool`; the only shared base is an optional thin ctor helper, not a polymorphic seam.

A **Windows static-link canary** (libpq linked on the MSVC static triplet running `SELECT 1`)
is built and verified **before** the substrate timeline is committed — the #375 lesson.

## Considered and rejected

- **`libpqxx`** — ergonomic C++ transactions/typed rows, but a second C++ static-link surface
  on the platform that produced the gRPC LNK2038/LNK2005 saga, duplicating RAII we own anyway.
- **Per-store dedicated connection** (1:1 with today's `sqlite3*`) — simplest mechanical port,
  but 29+ idle backend processes per server and it keeps the per-store mutex serialization.
- **An external migration tool (Flyway/Liquibase/sqitch)** — standard versioned-SQL tooling,
  but a heavy foreign dependency (JVM for Flyway/Liquibase), a separate file format, and
  out-of-process runs — alien to the in-C++ embedded-migration idiom and the Meson build.
- **Single shared `public` schema with table-name prefixes** — simpler `search_path`, but
  weaker isolation and noisier naming than schema-per-store.

## Consequences

- The substrate is a small, well-bounded set of new files (`pg_raii.hpp`, `pg_pool.{hpp,cpp}`,
  `pg_migration_runner.{hpp,cpp}`) that every later store builds on. Getting their ownership and
  exception-safety right (cpp-safety review) is load-bearing for the whole program.
- `RETURNING` is the mandated mutate-and-return idiom (the #1033 anti-pattern becomes moot per
  migrated store but the discipline carries over).
- `vcpkg.json` gains `libpq`; `meson.build` wires a `libpq_dep` with `include_type: 'system'`.
  The Windows static-link result from the canary can still reshape the timeline (fallback:
  dynamic libpq / dynamic Windows server) — which is exactly why the canary is first.
