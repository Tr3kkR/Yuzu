---
status: accepted
date: 2026-07-25
owner: platform (Postgres substrate migration program)
deciders: dev-team junior-developer implementation, following the ladder assignment in
  `docs/postgres-migration-ladder.md` (Wave 1)
scope: server — `ResultSetStore` (the scope-walking result-set primitive), its cutover from
  SQLite to PostgreSQL, and its ADR-0009 backfill
builds-on: ADR-0006 (Postgres substrate), ADR-0007 (single-backend, no SQLite fallback),
  ADR-0008 (substrate architecture), ADR-0009 (per-store first-boot backfill cutover),
  ADR-0012 (server Postgres store contract)
related: docs/postgres-migration-ladder.md (Wave 1 → Done); docs/scope-walking-design.md
  (the result-set primitive, lineage, and audit-chain semantics this store backs)
---

# 0036 — `ResultSetStore` Postgres migration (authoritative, with backfill)

## Context

`ResultSetStore` (`server/core/src/result_set_store.{hpp,cpp}`) is the persistence for
scope-walking (`docs/scope-walking-design.md`): named, TTL-bounded, lineage-tracked sets of
device IDs produced by a query, an action result, or operator curation. It is a Wave 1 store on
`docs/postgres-migration-ladder.md` ("inherently cross-store" — every scoped command dispatch
and the `/api/scope/estimate` preview resolve `from_result_set:` aliases against it, and it is a
future vuln-graph-scoring join input). It was previously a SQLite store (`result_sets.db`) with
a single global `shared_mutex` serializing every writer.

## Decision

**Migrate `ResultSetStore` to PostgreSQL as schema `result_set_store`, tables `result_sets` +
`result_set_members`, with a standard ADR-0009 first-boot backfill.**

### Schema

- Schema name `result_set_store` (ADR-0008 Update naming rule:
  `snake_case(FullClassName)` including the `Store` suffix).
- `result_sets` carries the existing columns unchanged in meaning and type mapping
  (`TEXT`→`TEXT`, `INTEGER` epoch columns→`BIGINT`, the `INTEGER` 0/1 `pinned` flag→`BOOLEAN`);
  the `CHECK (length(id) >= 5 AND substr(id,1,3) = 'rs_')` and `CHECK (ttl_at >= created_at)`
  constraints translate unchanged (Postgres `length`/`substr` are drop-in). `parent_id` keeps its
  self-referencing `REFERENCES result_sets(id) ON DELETE SET NULL`.
- `result_set_members` is unchanged in shape (`PRIMARY KEY (result_set_id, device_id)`,
  `REFERENCES result_sets(id) ON DELETE CASCADE` — cascade delete on `gc_sweep`/`delete_set` is
  preserved by the FK, not re-implemented in application code).
- A new table, `sqlite_backfill (id SMALLINT PRIMARY KEY CHECK (id = 1), completed_at BIGINT NOT
  NULL)`, is the backfill idempotency marker (see Backfill below) — it is not part of the
  application data model.
- No secrets. Every column is plain application data (device IDs, JSON payloads the operator or
  server itself authored, alias names) — no `SecretCodec` involvement.

### Posture

**AUTHORITATIVE / fail-hard** (ADR-0012 §1), both construction and runtime:

- **Construction fails closed**, same template as every other Postgres-backed store: a schema
  that cannot migrate/open sets `startup_failed_` in `server.cpp`.
- **The database IS the source of truth for scope-walking lineage.** There is no in-memory
  authoritative layer above this store (unlike `OfflineEndpointStore`'s durability-on-top
  relationship to `FleetTopologyStore`).
- **Authorization/targeting-relevant reads are type-distinguishable (2026-07-25, program policy —
  `docs/postgres-store-playbook.md` "Authoritative reads must be type-distinguishable", escalated
  to a MERGE-BLOCKER by the enterprise architect on first review of this ADR).** `get`, `contains`,
  `resolve_alias`, and `member_set_owned` return `std::expected<T, ResultSetError>` — a DB error is
  `std::unexpected(DbError)`, never an empty/false/nullopt value indistinguishable from a genuine
  "not found"/"not a member". This is not a theoretical hardening: `member_set_owned` backs
  `AgentRegistry::evaluate_scope`'s `from_result_set:` membership preload, and a `NOT
  from_result_set:<id>` scope resolves a missing preload entry to "no match" — which `NOT` then
  INVERTS to "matches every agent". Pre-fix, a transient Postgres blip during that preload came
  back as a silently-empty (but *present*) membership map, so a `NOT`-scoped command dispatch
  would have silently targeted the **entire connected fleet**. `evaluate_scope` itself returns
  `std::optional<std::vector<std::string>>` — `std::nullopt` on ANY preload failure, aborting the
  whole evaluation rather than proceeding with a partial map — and every dispatch call site
  (`server.cpp`'s raw/tracked/MCP command-dispatch closures, `scope_yaml.cpp`'s
  `resolve_scope_aliases`/`scope_refs_failing_owner_check`, the REST `load_owned`/
  `resolve_owned_parent` owner gates, the dashboard fragment routes' `rs_get_owned` helper) treats
  a `DbError`/`nullopt` as "abort — 503/404-as-503/deny", never as "0 matches" or "not owned".
  `tests/unit/server/test_scope_walking_authz.cpp`'s `[failclosed]` test drops the underlying
  Postgres table mid-test and asserts `evaluate_scope` returns `nullopt` rather than silently
  matching every registered agent under a `NOT` scope — the regression test for exactly this bug
  class.
- `list_by_owner`, `members`, `lineage`, `count_for_owner`, `counts`, and `list_pending` remain
  plain-optional/container reads — their failure modes are deny-or-benign (an empty sidebar page,
  a short lineage breadcrumb, an under-counted gauge; none grants/targets/enforces/skips/inverts).
  Widening them is a legitimate mechanical follow-up (tracked, not blocking) rather than a security
  gap.
- **Mutators use `std::expected` already** (`create_materialized`, `create_pending`, `pin`,
  `unpin`, `delete_set`, `materialize`) and correctly surface `DbError` — these paths already
  meet the ADR-0012 bar.
- Bounded acquires throughout (`try_acquire_for`, 2 s reads / 4 s writes — slightly longer than
  `OfflineEndpointStore`'s fail-soft budget, per ADR-0012 §1's "authoritative stores may wait
  longer for a lease, but still bound the wait"). Construction and the one-time backfill use
  unbounded `acquire()`/`with_txn` per ADR-0012 §2(a) (boot is serial).

### Backfill (ADR-0009)

`migrate_from_sqlite(legacy_db_path)` is called once at server startup, immediately after
construction proves the schema is open, before the server serves. It is idempotent via a
dedicated `sqlite_backfill` marker row — **not** inferred from `result_sets` being empty, because
`gc_sweep` legitimately empties that table over the store's normal (TTL'd) lifetime, and a
row-count-based idempotency check would re-run the backfill (re-inserting stale/expired legacy
rows) on every boot after the fleet's live result sets happen to have all expired. When no legacy
file is present (fresh install), the method stamps the marker and returns `true` without further
work. When present, it reads `result_sets` + `result_set_members` from the legacy SQLite file
read-only, and inserts every row into Postgres inside **one** transaction (`ON CONFLICT DO
NOTHING` on both tables, so a legacy row that already exists in Postgres — e.g. a retried boot
after a prior partial failure this method's own transactionality should otherwise prevent — is
inert) plus the marker insert, all-or-nothing. Any error — legacy file open/read failure, insert
failure — fails the whole method closed (returns `false`); `server.cpp` treats that identically
to `!is_open()`: a fatal startup error (`startup_failed_ = true`). This is the only fidelity this
store's TTL semantics require: because live result sets skew toward being short-lived (default
TTL 1 hour), the realistic backfill population at any given upgrade is small, so the
implementation favors simplicity (per-row `INSERT` statements inside the one transaction) over
the batched-`unnest` idiom used by higher-volume stores (`DeploymentRunStore`,
`AccessReviewStore`) — a legitimate choice for a store whose backfill population is bounded by
its own TTL policy, revisit if a future fleet is observed pinning large sets at scale.

Per ADR-0009, the legacy `result_sets.db` file is retained read-only for exactly one release (not
deleted by this migration) as the rollback breadcrumb, and this method never writes to it.

### `mark_failed` — JSON merge moved to application code

The SQLite implementation used the `json1` extension's `json_set(... CASE WHEN json_valid(...)
THEN ... ELSE '{}' END, '$.failure', ?)` to merge a failure reason into `source_payload` without a
separate read. Postgres has no direct equivalent for "is this arbitrary TEXT valid JSON" without
either a `jsonb` cast (which throws on invalid input, aborting the whole statement — unacceptable
since `source_payload` may hold operator-influenced content that is not guaranteed to already be
valid JSON) or PL/pgSQL exception handling (avoided — this store has no other stored-procedure
surface and one is not worth introducing for a single call site). `mark_failed` instead reads
`source_payload`, parses it with `nlohmann::json` (already a project dependency, used elsewhere
in `server/core/src`), falls back to an empty object on a parse failure exactly like the SQLite
`CASE WHEN json_valid` did, merges in `{"failure": reason}`, and writes the merged payload back —
same observable behavior, implemented at the layer that already has a general-purpose JSON
library instead of leaning on a Postgres-side cast this store has no other reason to need.

## Considered and rejected

- **Skip backfill (fresh-start, à la `ApiTokenStore`/ADR-0030).** Rejected: unlike bearer tokens,
  a result set is not cheap for an operator to reproduce mid-investigation — a fresh-start cutover
  would silently drop in-flight scope-walking work (and its lineage/audit trail) across an
  upgrade window. ADR-0009's default (mandatory backfill unless the store is purely TTL'd
  *ephemeral*, like `response`) is a better fit: result sets are TTL'd but not purely — pinned
  sets are explicitly designed to outlive the default TTL, and losing them is directly adverse to
  the primitive's own value proposition.
- **Row-count-based idempotency (`result_sets` empty ⇒ backfill).** Rejected — `gc_sweep` makes
  the table legitimately empty during ordinary operation, which would silently re-run the
  backfill against a live database, re-materializing rows a client already correctly saw expire.
  A dedicated marker table is unambiguous regardless of the store's later data state.
- **Bulk `unnest`-based backfill insert** (matching `DeploymentRunStore`/`AccessReviewStore`'s
  batched pattern). Deferred, not rejected outright — see the Backfill section above; the
  realistic backfill population for a TTL'd primitive does not currently justify the added
  complexity of building nullable-column-safe parallel arrays for a one-time startup path.
- **Deferring the `std::expected` widening of `get`/`contains`/`resolve_alias`/`member_set_owned`
  to a follow-up PR** (the original position of this ADR, on the theory that it was a cross-cutting
  change touching every caller in `rest_api_v1.cpp`, `scope_yaml.{hpp,cpp}`,
  `agent_registry.{hpp,cpp}`, and the result-set dashboard routes). **Rejected on review** — the
  enterprise architect escalated this to a MERGE-BLOCKER (HIGH): the deferred state was a concrete,
  reachable fail-open (the `NOT from_result_set:<id>` fleet-wide-match bug described in Posture
  above), not a theoretical hardening gap, so it could not ship as a "later" item. The four reads
  are widened in this same ADR/PR; every caller updated to fail closed on `DbError`/`nullopt`.

## Consequences

- `ResultSetStore` moves from `sqlite3*` + `mutable std::shared_mutex` to `pg::PgPool&`; the
  store no longer serializes its own writers (Postgres's real concurrency replaces the SQLite
  single-writer mutex, per `pg_pool.hpp`'s stated design intent). The per-operator quota
  (`kMaxPerOwner`) and pin-limit (`kMaxPinsPerOwner`) checks are consequently now soft DoS guards
  with a small race window under concurrent writers from the same owner, rather than exactly
  enforced — an acceptable trade for a non-security-boundary cap (unlike, e.g.,
  `DeploymentRunStore`'s execute-once CAS, which remains a hard invariant enforced via a guarded
  `UPDATE ... WHERE step = ... RETURNING`).
- All runtime statements schema-qualify `result_set_store.result_sets` /
  `result_set_store.result_set_members`; mutate-and-return paths use `RETURNING` (#1033-banning
  idiom), never `sqlite3_changes()`.
- Member-set batch inserts (`insert_row_impl`, `materialize`) use the `unnest($n::text[])` idiom
  (`pg::to_text_array`) rather than per-row `INSERT`, so a 100,000-member result set (the
  `kMaxMembersPerSet` cap) costs one round trip, not 100,000.
- `docs/postgres-migration-ladder.md`'s `ResultSetStore` row moves from Wave 1 to Done, citing
  this ADR.
- **The public C++ API's method NAMES and parameter shapes are unchanged; four return types
  widened (`get`, `contains`, `resolve_alias`, `member_set_owned` → `std::expected<...,
  ResultSetError>`; `AgentRegistry::evaluate_scope` → `std::optional<std::vector<std::string>>`).**
  Every caller in `rest_api_v1.cpp` (`load_owned`/`resolve_owned_parent`), `scope_yaml.{hpp,cpp}`
  (`resolve_scope_aliases`/`scope_refs_failing_owner_check`, now themselves
  `std::expected`-returning and propagating), `agent_registry.{hpp,cpp}`, `server.cpp`'s
  raw/tracked/MCP dispatch closures and the result-sets dashboard fragment routes (via a new
  `rs_get_owned` chokepoint helper), and `policy_evaluator.cpp` was updated to unwrap and fail
  closed on the error case. `list_by_owner`/`members`/`lineage`/etc. keep their pre-migration
  plain-container signatures (see Posture).
- **Operator-facing:** none. The backfill is transparent; existing result sets survive an upgrade
  (subject to their own TTL, unchanged).

## Follow-ups and accepted risks

- **Read-path error/not-found ambiguity — RESOLVED for the four authorization/targeting-relevant
  reads** (`get`, `contains`, `resolve_alias`, `member_set_owned`; see Posture). The remaining
  reads (`list_by_owner`, `members`, `lineage`, `count_for_owner`, `count_pinned_for_owner`,
  `counts`, `list_pending`) still return plain `std::optional`/containers with no error channel —
  their failure modes are deny-or-benign, not the fail-open class this ADR's revision fixes.
  Widening them to the same `std::expected` shape is a legitimate mechanical follow-up; tracked as
  an issue by the integrating senior rather than left as ADR prose.
- **Quota/pin-limit races under concurrent writers for the same owner (accepted risk).** See
  Consequences above — a soft DoS guard, not a security boundary; not tracked as a defect.
- **Legacy `result_sets.db` disposal.** Retained read-only for one release per ADR-0009; deletion
  in the following release is a housekeeping follow-up, not tracked as an issue yet.
