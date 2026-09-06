# Wave 7 PR7.2 — `app_usage` (last_used) daily-sync source: integration notes

This package (P23) adds the agent-side `app_usage` daily-sync source and the
server-side store/ingest seam. `tests/meson.build` is **not** owned by this
package (it belongs to the integration package) — the exact lines to add are
below, verbatim, for the integrator to splice in.

## New files

- `agents/core/src/sync_source_app_usage.{hpp,cpp}` — the agent source.
- `server/core/src/app_usage_store.{hpp,cpp}` — `AppUsageStore` (schema
  `app_usage_store`: `usage_state` + `agent_last_used`).
- `server/core/src/app_usage_ingestion.{hpp,cpp}` — the shared ingest seam
  called from both `AgentServiceImpl::ReportInventory` and
  `GatewayUpstreamServiceImpl::ProxyInventory`.
- `tests/unit/test_sync_source_app_usage.cpp`
- `tests/unit/server/test_app_usage_ingestion.cpp`
- `tests/unit/server/test_app_usage_store.cpp`

## `tests/meson.build` additions

Agent-core test list, next to the existing `test_sync_source_app_perf.cpp` row
(near line 301):

```meson
    'unit/test_sync_source_app_perf.cpp',
    'unit/test_sync_source_app_usage.cpp',   # Wave 7 PR7.2: app_usage (last_used) source
```

Server test list, next to the existing `test_software_licensing_*.cpp` rows
(near line 1069/1077):

```meson
      'unit/server/test_software_licensing_store.cpp',
      'unit/server/test_software_licensing_ingestion.cpp',
      'unit/server/test_app_usage_store.cpp',       # Wave 7 PR7.2
      'unit/server/test_app_usage_ingestion.cpp',   # Wave 7 PR7.2
```

## Wire formats (for reference)

- Agent → server blob: `cfg\x1fscope\x1fmachine\x1e` followed by zero or more
  `lu\x1f<exe_key>\x1f<first_seen>\x1f<last_seen>\x1f<run_count_30d>\x1f
  <total_seconds_30d>\x1e` records, sorted + deduped.
- Content hash: SHA-256 of the raw received blob bytes (never re-derived from
  parsed rows, never the agent's claim) — mirrors `software_licensing`
  (ADR-0024 Decision 3 / roadmap D-2).
- A `constrained|...` plugin output (usage source disabled / older TAR schema
  / tar.db unavailable) is parsed and the daily-sync cycle is **skipped** —
  never sent as an empty full payload (would wipe stored last-used state
  under hash-skip once the constraint lifts).

## Decommission

`AppUsageStore::delete_agent` erases `usage_state` AND `agent_last_used` in
one transaction and returns commit status. This package does **not** register
the store in `AgentDecommissionStores` (server.cpp `decommission_agent`) —
that is P26 (wave 4), behind the promoted `Decommission:Delete` securable,
moving `kCascadeStoreCount` 5→6.
