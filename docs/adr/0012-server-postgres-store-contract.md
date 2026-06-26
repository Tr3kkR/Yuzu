---
status: accepted
date: 2026-06-22
owner: Nathan Dornbrook (platform)
deciders: Nathan Dornbrook; grill-with-docs design session 2026-06-22
scope: platform — the author-facing contract every server-side Postgres store obeys
builds-on: ADR-0006 (Postgres substrate), ADR-0007 (single-backend), ADR-0008 (substrate architecture), ADR-0010 (secrets-at-rest)
---

# 0012 — Server Postgres store contract: failure posture, lease discipline, cross-store query seam

## Context

ADR-0008 fixed the substrate *internals* — libpq + in-house RAII, one shared `PgPool`, one
Postgres SCHEMA per store, `PgMigrationRunner`. Exactly one store has been built on it
(`OfflineEndpointStore`, schema `endpoint_state`), and ~27 SQLite stores plus the auth DB are
queued to migrate (ADR-0006, now *all-or-nothing* per its 2026-06-22 Update; the ordered queue
is `docs/postgres-migration-ladder.md`). Before that fan-out, the **author-facing** contract has
to be fixed so 28 migrations don't each re-decide it:

- what a store does when the database is unavailable **at runtime** (not at boot — that is
  already fail-closed per ADR-0007),
- how a store shares the one pool without starving or deadlocking its peers, and
- how the cross-store joins that justified Postgres (ADR-0006) get written when each store owns
  only its own schema.

`OfflineEndpointStore` answered these implicitly, for one fail-soft store. This ADR makes the
answers explicit and general.

## Decision

### 1. Every store declares a runtime failure posture

Construction failure stays fail-closed (ADR-0007): a store that cannot migrate/open sets
`startup_failed_` and the server refuses to serve. *Runtime* failure (saturated pool, query
error, transient unreachable) splits stores into two **declared** kinds:

- **durability-on-top** (fail-soft) — a bounded acquire, returns empty/`false` on error, and an
  in-memory layer remains the source of truth. The store adds durability *on top of*
  authoritative live state, so a database blip degrades durability, never correctness.
  (`OfflineEndpointStore`: the live `FleetTopologyStore` cache is authoritative; the Postgres
  row just lets an aged-out host render stale-flagged instead of vanishing.)
- **authoritative** (fail-hard) — the database **is** the source of truth. A runtime error is
  surfaced to the caller, **never** papered over with an empty result, because a silent empty
  read is a correctness or security failure (an RBAC store returning "no roles" reads as
  fail-open). Authoritative stores may wait longer for a lease, but still bound the wait.

The posture is part of the store's documented contract (header comment + per-store ADR) and
drives its acquire discipline and error handling. Most migrated stores are authoritative.

Posture is declared **per operation-class (ingest vs read), not strictly per store.** A typed
projection fed by a self-healing agent push is **ingest-fail-soft + read-authoritative**: a failed
ingest is fine (the agent re-pushes), but a read has no in-memory authoritative layer to fall back
on, so a silent empty would be fail-open. `SoftwareInventoryStore` (ADR-0016 §7) is the worked
example — classifying it durability-on-top *wholesale* (the original header did) is the
misclassification this split guards against.

### 2. One shared pool; backpressure is lease discipline, not partitioning

ADR-0008's single `PgPool` stays. No per-class pools, per-store budgets, or priority queues —
premature before observed contention. Three hard rules make a shared pool safe:

- **(a) Runtime acquires are always bounded** (`try_acquire_for` with a deadline). Unbounded
  `acquire()` is permitted **only at construction**, where boot is serial and the substrate
  probe has already proved reachability.
- **(b) Never hold a lease (or a `with_txn`) across network, disk, or other external work.** A
  lease is checked out, used for SQL, and returned; nothing slow happens while it is held.
- **(c) One logical operation holds at most one lease at a time.** A store method must not call
  another store, or re-enter the pool, while holding a lease — that is the pool-exhaustion
  deadlock (the holder waits for a connection that only frees when holders return theirs).
  Cross-store work uses rule 3 instead.

### 3. Cross-store reads/joins/atomic writes are a first-class query-owner seam

The cross-store joins that justified one database (ADR-0006 — e.g. the vuln-graph edges ⨝
Guardian state ⨝ inventory join, spanning `vuln_graph_store` / `guaranteed_state_store` /
`inventory_store`) are written by a **dedicated query owner** that takes ONE
lease and issues schema-qualified SQL spanning the schemas directly — a read join on a pool
lease, or an atomic multi-store write via `pool.with_txn` issuing every statement on that one
lease. Per-store classes stay single-schema owners and **never expose their lease**. The shape
is committed now; the seam is **built when its first consumer (vuln-graph scoring) lands**, not
speculatively. Until then no store may grow a cross-schema method.

## Considered and rejected

- **A single rule — all fail-soft, or all fail-hard.** Rejected. Fail-soft is wrong for
  authoritative data (a silent empty read is fail-open); fail-hard is wrong for the heartbeat
  hot path (it cannot block on a saturated pool or throw per heartbeat at 1M+ agents). The
  posture split is the minimum that serves both.
- **Partitioned pools / per-store budgets / priority queue.** Rejected as premature.
  `OfflineEndpointStore`'s fail-soft posture already protects ingest from a read burst, and we
  have no measured contention to size partitions against. Revisit only if the pool metrics
  (`yuzu_pg_acquire_wait_seconds`, `yuzu_pg_acquire_timeout_total`) show real starvation.
- **Stores expose their lease so callers compose cross-store work.** Rejected — breaks
  single-schema encapsulation and re-introduces exactly the nested-acquire deadlock rule 2(c)
  outlaws.

## Consequences

- Each per-store migration states its **posture** in its per-store ADR and header; reviewers
  check acquire discipline against rules 2(a)–(c). `cpp-safety` / `security-guardian` gate the
  fail-open risk on every authoritative store.
- The query-owner seam is **unbuilt** until vuln-graph scoring; cross-store stitching that
  exists stays application-layer until then, and no store grows a cross-schema method in the
  interim.
- A thin **non-polymorphic** construction helper (`open_with_migrations(...)` + a `server.cpp`
  construction helper that flips `startup_failed_` on `!is_open()`) is extracted **before** the
  fan-out so the construction-fail-closed wiring is written once, not 28 times — ADR-0008's
  "optional thin ctor helper", now mandatory (see the ADR-0008 2026-06-22 Update). Non-virtual,
  no backend abstraction (ADR-0007/0008 compliant). This is an implementation follow-up.
- The step-by-step recipe an author follows is `docs/postgres-store-playbook.md`; this ADR is
  the *why* it cites.
