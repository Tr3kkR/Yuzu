---
status: accepted
date: 2026-07-25
owner: platform (Postgres substrate migration)
deciders: engineering (per-store migration, ADR-0006 ladder Wave 1)
scope: server — the generic `InventoryStore` (per-source inventory blob store), its cutover
  from SQLite to PostgreSQL, and its first-boot backfill from the legacy `inventory.db`
builds-on: ADR-0006 (Postgres substrate), ADR-0007 (single-backend, no SQLite fallback),
  ADR-0008 (substrate architecture), ADR-0009 (per-store first-boot backfill cutover),
  ADR-0012 (server Postgres store contract), ADR-0016 (agent daily-sync framework —
  `SoftwareInventoryStore`, the typed sibling this ADR explicitly does NOT touch)
related: docs/postgres-migration-ladder.md (Wave 1 → Done); docs/postgres-store-playbook.md
---

# 0037 — `InventoryStore` (generic per-source blob) Postgres migration

## Context

`InventoryStore` (`server/core/src/inventory_store.{hpp,cpp}`) is the sync-framework's generic
`(agent_id, plugin) -> data_json` blob store — the catch-all home for every inventory source
that has NOT been promoted to its own typed Postgres projection. It backs the scope-walking
`kInventoryQuery` source and the inventory eval engine (`inventory_eval.hpp`), and is read by
the generic `/api/inventory/*`, `/api/v1/inventory/*`, and MCP `query_inventory` /
`list_inventory_tables` / `get_agent_inventory` surfaces. It has been SQLite (`inventory.db`)
since Issue 7.17.

**This is a distinct store from `SoftwareInventoryStore`** (ADR-0016, schema
`software_inventory_store`), which is the typed, normalized projection for exactly one
source (`installed_software`). The typed sources (`installed_software`, `app_perf`,
`device_ci`, `software_licensing`) are already skipped by the generic ingest loop
(`is_typed_inventory_source`) so their rows never land in the generic store; every OTHER
plugin's blob still does. `docs/postgres-migration-ladder.md`'s Wave 1 entry for
`InventoryStore` explicitly called this out as "the generic store's own migration, still
pending" while `SoftwareInventoryStore` was already Done — this ADR closes that gap. The two
stores continue to coexist after this migration; neither routes into the other.

ADR-0006 commits every server store to Postgres; this store carries pre-existing SQLite data
(agents' last-reported inventory for every non-typed source), so ADR-0009's standard
first-boot backfill mechanism applies (unlike, e.g., `ApiTokenStore`'s ADR-0030 fresh-start
override — there is no secrets-at-rest reason to discard this data, and losing an agent's
last-reported custom-plugin inventory on upgrade would be a regression the fresh-start
argument does not justify here).

## Decision

**Migrate `InventoryStore` to PostgreSQL as schema `inventory_store`, table
`inventory_data`, with a standard ADR-0009 first-boot backfill from the legacy
`inventory.db`.**

### Schema

- Schema name `inventory_store` (ADR-0008 Update naming rule:
  `snake_case(FullClassName)` including the `Store` suffix).
- Table `inventory_data` carries the existing columns unchanged in meaning and type mapping
  (SQLite `TEXT` → Postgres `TEXT`, SQLite `INTEGER` → Postgres `BIGINT`, epoch **seconds**
  unchanged): `agent_id`, `plugin`, `data_json`, `collected_at`, primary key
  `(agent_id, plugin)` (an upsert target, unchanged). The two SQLite secondary indexes
  (`plugin`, `collected_at`) carry over as Postgres indexes on the same columns.
- A second table, `backfill_state` (single sentinel row, `id = 1`), records that the
  first-boot backfill has run — see "Backfill" below.
- No secrets (ADR-0010 does not apply): `data_json` is plugin-collected inventory content,
  never credential material.

### Posture (ADR-0012 §1), split by operation class

- **Ingest (`upsert`): FAIL-SOFT.** A transient lease/query failure is logged and the call
  returns without throwing — it must never block the gRPC/gateway ingest thread. The agent's
  next report re-sends the same blob, so a dropped write self-heals. This mirrors
  `SoftwareInventoryStore`'s ingest posture exactly.
- **Reads (`list_tables`, `get`, `query`, `get_agent_inventory`, `count`): AUTHORITATIVE.** A
  store/pool/query failure is reported as a degrade — `std::nullopt` for the list/count reads,
  `std::unexpected(InventoryReadError::kDegraded)` for the single-record `get` (mirroring
  `DeviceInventoryStore::CiReadError`'s three-state `get_device_ci` exactly, since `get` has a
  genuine found/absent/degraded three-state contract that a plain `std::optional` cannot
  express without conflating "not found" and "could not read") — **never a silent empty**. An
  empty *value* is a genuine zero-row result; a degrade means the store could not be read at
  all. Every REST (`/api/inventory/*`, `/api/v1/inventory/*`) and MCP
  (`query_inventory`/`list_inventory_tables`/`get_agent_inventory`) call site was updated to
  surface a degrade as a 503 / internal-error response rather than folding it into an empty
  200/success — closing the exact fail-open anti-pattern the playbook forbids
  ("An authoritative store that returns an empty result on a DB error").
- **`delete_agent`**: unchanged contract — returns true iff the DELETE executed successfully;
  false on a lease timeout or SQL failure, so the `AgentDecommission` cascade records the
  store Failed rather than a false "erased".

### Backfill (ADR-0009) — standard, mandatory, idempotent, fail-closed

`migrate_from_sqlite(legacy_db_path)` runs once at server startup, before serving, inside the
`if (pg_pool_ && !startup_failed_)` construction block in `server.cpp`, right after the store
opens:

- **Idempotency**: a single-row `backfill_state` table (`id = 1`, stamped with
  `migrated_at` + a `legacy_rows` diagnostic count) makes every boot after the first a cheap
  lookup — the legacy SQLite file is never re-read once stamped.
- **Never clobbers a live row**: every backfilled row is inserted
  `ON CONFLICT (agent_id, plugin) DO NOTHING` — if a live agent has already re-reported for
  that `(agent_id, plugin)` pair since this boot sequence started (a race the boot-time
  ordering makes possible only in the narrow window between store-open and backfill-run), the
  live row wins, never the stale legacy copy.
- **Fails CLOSED**: any legacy-open/read error, or any Postgres write error during the
  backfill transaction, returns `false`; `server.cpp` treats that as a fatal startup error
  (`startup_failed_ = true`) — the server refuses to serve half-migrated inventory data,
  exactly as ADR-0009 requires.
- **Read-only legacy access**: the legacy `inventory.db` is opened `SQLITE_OPEN_READONLY` and
  is never written to. Per ADR-0009 it is retained on disk, unmodified, for exactly one
  release as the rollback net, then removed in the following release (this ADR does not ship
  that removal).
- **Lease discipline note**: the idempotency check and the backfill-insert transaction each
  acquire their own single connection and release it before the other begins — holding two
  connections concurrently from this one call would deadlock a size-1 pool (e.g. a test
  pool), which the implementation avoids by construction (see the doc comment on
  `migrate_from_sqlite` in `inventory_store.hpp`).
- **Cost**: the backfill inserts one row at a time inside a single transaction. This is a
  one-time boot cost (never repeated after the stamp lands), acceptable at today's scale; a
  batched `unnest()`-based insert (mirroring `SoftwareInventoryStore`'s ingest path) is the
  follow-up if a fleet's legacy table ever proves large enough to matter.

## Considered and rejected

- **Fresh-start, no backfill** (the ADR-0030 `ApiTokenStore` pattern). Rejected: unlike a
  bearer token (cheap, self-service to re-mint), an agent's last-reported custom-plugin
  inventory is not something an operator can trivially regenerate on demand — the agent must
  re-collect and re-report it, and until it does, the fleet's inventory view for that plugin
  is silently incomplete. The standard ADR-0009 backfill is cheap here (no secret-material
  transform needed, unlike `auth`/`webhooks`), so there is no complexity reason to skip it
  either.
- **Splitting `get`'s degrade signal into a plain `std::optional<InventoryRecord>`** (folding
  degrade and not-found into one `nullopt`). Rejected — this is exactly the fail-open
  ambiguity `DeviceInventoryStore::CiReadError` was introduced to close; a caller cannot tell
  "no inventory reported yet" (safe to render as empty) from "the store could not be read"
  (must render a degrade banner / 503) without the three-state `std::expected` shape.
- **Merging this store into `SoftwareInventoryStore`** (one schema for all inventory). Rejected
  — out of scope and explicitly disclaimed by `docs/postgres-migration-ladder.md`; the two
  stores serve different shapes (generic untyped blob vs. typed normalized rows for one
  source) and different query patterns, and merging them would be a product change, not a
  substrate migration.

## Consequences

- `InventoryStore` moves from `sqlite3*` to `pg::PgPool&`. Construction follows the standard
  born-on-PG idiom (a pinned `pool_.acquire()` lease + `PgMigrationRunner::run(lease, kStoreName,
  migrations())` + `open_ = true`) and is wired into `server.cpp` inside the
  `if (pg_pool_ && !startup_failed_)` guard, immediately followed by the
  `migrate_from_sqlite()` call — both failure paths (`!is_open()` and a failed backfill) flip
  `startup_failed_`. Declared after `pg_pool_` in the member list, so it destructs before the
  pool (`server.cpp`'s existing declaration-order convention).
- All runtime statements schema-qualify `inventory_store.inventory_data` (and
  `inventory_store.backfill_state`); every mutate-and-return path checks the `PgResult`
  status directly rather than `sqlite3_changes()` (#1033) — none of this store's mutators
  needed `RETURNING` specifically (no caller consumes an affected-row count), but the
  `sqlite3_changes()` anti-pattern itself does not carry over regardless.
- Every REST (legacy `/api/inventory/*` in `server.cpp`; `/api/v1/inventory/*` in
  `rest_api_v1.cpp`, including the `evaluate` and `from-inventory-query` result-set-producer
  routes) and MCP (`mcp_server.cpp`) call site was updated for the new
  `std::optional`/`std::expected` return shapes, surfacing a degrade as 503 /
  `kInternalError` rather than an empty success response.
- `docs/postgres-migration-ladder.md`'s `InventoryStore` row moves from Wave 1 to Done, citing
  this ADR.
- The legacy `inventory.db` stays on disk, read-only, for one release per ADR-0009; its
  removal is a follow-up for the release after this one ships.

## Follow-ups and accepted risks

- **Backfill is row-by-row, not batched.** Acceptable for a one-time boot cost at today's
  scale (see "Cost" above); a batched `unnest()` insert is the follow-up if a fleet's legacy
  table ever proves large.
- **Pre-existing, harmless dead wiring noticed while touching this code**: `server.cpp`'s
  early "wire up store pointers for AgentServiceImpl" block calls
  `agent_service_.set_inventory_store(inventory_store_.get())` BEFORE `inventory_store_` is
  constructed later in the same constructor, so that call always sets a null pointer in
  practice. This is harmless: `AgentServiceImpl::inventory_store_` (the setter's target) is
  never actually READ anywhere in `agent_service_impl.cpp` — the direct `ReportInventory` path
  intentionally does not upsert generic (non-typed) sources into the generic store (documented
  gov architect A-1 / consistency S1 asymmetry: only the gateway path threads generic sources
  through today). Predates this migration; left unchanged here since fixing the ordering would
  be the first step toward a behavior change (wiring a currently-unused seam) beyond this
  substrate migration's scope — flagged for whoever picks up that generic-source direct-path
  work.
- **No new row-cap was previously enforced on `query()`'s caller-supplied `limit`**; this
  migration adds a defensive hard ceiling (`kQueryRowCap`, matching the sibling stores'
  pattern) independent of the callers' existing 1000-row REST-level caps, purely as
  belt-and-braces against a future uncapped caller.
