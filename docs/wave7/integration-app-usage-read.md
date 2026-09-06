# P25 → integrator/P24 handoff: app_usage read surface

Server half of PR7.2 (P25): REST GET + MCP tool over `AppUsageStore::get_agent_last_used`,
gated on `Forensics:Read`, audited per access. This file is the interface contract for
P24's user-manual doc section and for wiring into `tests/meson.build`.

## Names

- REST: `GET /api/v1/forensics/agents/{agent_id}/app-usage`
- MCP tool: `get_agent_app_usage`
- Audit action: `app_usage.agent.view`
- Securable: `Forensics:Read`, scoped to the device (tier + management group,
  ancestor-aware — the SleRoutes/query_software_licenses precedent)

## Emitted JSON (identical on both surfaces, field-for-field)

```json
{
  "agent_id": "agent-9",
  "apps": [
    {
      "exe_key": "chrome.exe",
      "first_seen": 1699000000,
      "last_seen": 1700000500,
      "run_count_30d": 12,
      "total_seconds_30d": 43200
    }
  ],
  "collected_at": 1700000600
}
```

REST wraps this under `{"data": ..., "meta": {"api_version": "v1"}}` (the A4 envelope
convention); MCP returns it as `structuredContent` directly. `collected_at` is the
agent's batch collection time (every row from one `replace_agent_last_used` call shares
it — app_usage_ingestion.cpp), hoisted to the top level rather than repeated per app; an
empty result carries `collected_at: 0`. No user names or pids appear anywhere — the store
carries none.

## Error posture

- `401`/`403`: the scoped `Forensics:Read` gate (out of scope, or unauthenticated).
- `503` (REST) / A4 internal error (MCP): the scoped gate is unwired, the app-usage
  store is unavailable, or the per-access behavioural audit row could not persist
  (REST carries `Sec-Audit-Failed: true` on the latter — the read FAILS CLOSED, PII
  posture parity with the SLE drill and the app-perf device drill).
- An empty result (agent has no rows) is a genuine `200`/success with `apps: []` —
  never conflated with a degrade.

## Files touched

- New: `server/core/src/app_usage_routes.{hpp,cpp}`,
  `tests/unit/server/test_app_usage_routes.cpp`
- Edits: `server/core/src/server.cpp` (route + MCP provider wiring only — `app_usage_routes_`
  member beside `sle_routes_`, reusing the `sle_scoped_perm_fn` lambda),
  `server/core/src/mcp_server.cpp` / `.hpp` (new `get_agent_app_usage` tool + threaded
  `AppUsageStore*` param), `server/core/src/rest_api_v1.cpp` (OpenAPI path entry beside
  the SLE agent GET block), `tests/unit/server/test_mcp_server.cpp`.

## MCP tool family assignment

`get_agent_app_usage` is in the `kInventory` family in `server/core/src/mcp_orientation.cpp`,
appended after its REST/MCP sibling `query_software_licenses` (same order as `kTools[]`).
No new family was added — Forensics is a securable, not a tool family, and this
projection is an ADR-0016 daily-sync inventory-class read like licenses. The family
tether test ("MCP 2g: tool families cover exactly the tools/list surface (staleness
tether B)") passes with this assignment; no further action needed from P24/the
integrator on this point.

## tests/meson.build (integrator applies — not owned by this package)

Add beside the existing wave-7 app_usage entries in the server test-source list
(`unit/server/test_app_usage_store.cpp` / `unit/server/test_app_usage_ingestion.cpp`):

```meson
      'unit/server/test_app_usage_routes.cpp',      # Wave 7 PR7.2
```

(`test_mcp_server.cpp` is already listed; no new meson entry needed for the MCP cases.)
