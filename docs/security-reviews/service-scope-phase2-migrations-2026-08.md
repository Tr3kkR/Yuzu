# Phase 2 migrations — real confinement (#3290)

**Date:** 2026-08-20
**Context:** guardian-confinement-2298 PR 3 ("the flip", #3278, ADR-1006) closed the
service-scope confinement gap with a blanket default-deny — any `require_permission`-gated
route not on the seeded-empty `kServiceScopeGlobalSafe` allow-list refuses a service-scoped
API token outright. That is defense, not function: the route is safe but *unusable* by a
service-scoped token. #3290 is the follow-through — migrate routes onto real per-request
confinement (`AuthRoutes::require_fleet_read`/`confine_agent_target`) so a correctly-confined
service-scoped token gets a real, filtered answer instead of a 403. This doc is the reusable
migration record: what changed, why this route first, and the backlog for what's next.

## Correction to the issue's own wording

Criterion 2 of #3290 implies migrating a route means adding an entry to
`kServiceScopeGlobalSafe`. That's backwards for the common case: `require_fleet_read` never
consults the allow-list at all — a migrated route **replaces** its `require_permission` call
with the gate (see `require_fleet_read`'s own doc comment for the BLOCKING falsifier on
pairing the two). The allow-list is only for the rare case of a fleet-wide aggregate with no
per-agent identity to confine by, re-admitted unconfined — a much higher bar, separately
security-guardian-signed-off, not exercised by this migration.

## Migration 1: `GET /api/v1/inventory/software` + MCP `query_installed_software`

### Why this route first (criterion 1 substitute — documented reasoning, not the metric)

`yuzu_auth_service_scope_default_denied_total` — the metric criterion 1 says to prioritize
by — has no real traffic to rank with: there is no production fleet yet. The substitute is
**documented reasoning**: rank read-only, high-value fleet reads an ITServiceOwner token
plausibly needs first (this route — per-service software/CVE triage is a canonical
service-token use case), defer mutations to their own later PRs (`confine_agent_target` +
`require_scoped_permission` pairing, a different primitive), and prefer a route whose REST
deny was already provably dead code (zero behavior change on that surface) with a live MCP
twin to prove the pattern on both transports in one PR.

### What changed

- `AuthRoutes::require_fleet_read` (Phase 0, PR #3216, zero callers) gained the
  elevated/engine/mcp_tier caller-class branches it was missing — mirroring
  `require_list_read`'s ladder, not `require_permission`'s (no belt-and-braces
  service-scope-allow-list check; `require_fleet_read` has no allow-list to guard). Without
  this, an engine principal under RBAC-off would have fallen through to
  `authorize_list_read`'s legacy-open `AdmitAll` — a real regression the moment a route
  migrated onto the bare Phase-0 primitive.
- `authz::FleetReadGate` — a plain, fakeable aggregate (`{bool admitted; VisibleSet scope;}`)
  is the new REST/MCP injected-callback seam, mirroring `ListReadGate`/`ListReadFn`'s existing
  pattern. `ListAuthority` itself stays move-only/`AuthRoutes`-friend-only — the right shape
  for a direct in-process caller, wrong for `std::function` injection or a test fixture that
  needs to fake an admit without a live Postgres `RbacStore`.
- Both routes: `perm_fn`/`deny_fleet_wide_service_scoped` (REST) and
  `tier_allows`/`deny_fleet_wide_service_scoped`/`perm_fn` (MCP) replaced by the gate as the
  **sole** authorization check. The REST deny was provably dead (fired after `perm_fn`); the
  MCP deny was live — its `ServiceScopeClass::confined` label was backed only by that blanket
  deny before this PR, which is the "confined label with no real mechanism" the routed-concern
  row's clause 3 forbids.
- `InventoryScopeFn` (the old per-row management-group predicate, already inert under the
  prior global gate) retired entirely on both surfaces — zero callers after migration.

### Behavior changes (all deliberate, documented at the route/tool doc comment + OpenAPI spec)

| Caller class | Before | After |
|---|---|---|
| Service-scoped token, RBAC on, correctly confined | 403 (the flip) | 200, filtered to `meet(management-group, service-scope)` — the point of this PR |
| Service-scoped token, RBAC off | 403 | 403 (unchanged) |
| Management-group-scoped-only operator (no global grant) | 403 (`check_permission` is global-only, never consulted `ManagementGroupStore`) | 200, filtered (`AdmitScoped`) — closes ADR-0017's "World A" gap for this route |
| Global-grant operator / RBAC-disabled non-service caller | 200 unfiltered | unchanged |
| RBAC store null/not-open, non-service caller | 200 unfiltered (legacy fallback) | 503 Degraded — fail-closed hardening, called out explicitly |
| JIT-elevated operator | 200 unfiltered | 200 unfiltered (new caller-class branch) |
| Engine principal, RBAC on + grant | 200 unfiltered | 200 unfiltered (new caller-class branch) |
| Engine principal, RBAC off | 403 | 403 (new caller-class branch — the regression this migration would otherwise have shipped) |
| Tag store null/degraded, service-scoped caller | 403 (never reached the tag store) | 503 Degraded (retryable) |

### Tests

Unit-level (fake gate): `test_rest_inventory_software.cpp` (`InvHarness`), rewritten —
gate-deny/401/unwired-503 tests replace the old RBAC-deny/service-scoped-deny tests (the
route no longer has its own auth to fake); scope-filter tests drive `fleet_scope` directly.
`test_mcp_server.cpp` similarly — `fleet_read_fn_for_test` replaces
`inventory_scope_fn_for_test`; the old "service-scoped token denied" test is rewritten to
assert the blanket deny is *gone*.

New `[pg]` end-to-end tests (`InvE2ERig`, real `AuthRoutes`, the same conversion lambda
production wires) prove the actual `meet()` composition against a real `RbacStore`/
`TagStore`/`ManagementGroupStore` — coverage that existed nowhere at the route level before:
service-scoped token → real filtered 200; management-group-confined operator → real filtered
200 (the `AdmitScoped` case, previously untestable at this route since it always 403'd);
unscoped operator → unchanged; tag-store degraded → 503; RBAC-off + service token → 403.

Primitive-level caller-class coverage (elevated/engine/mcp_tier branches):
`test_authz_gates.cpp` and `test_engine_principal_integration.cpp` §6c.

## Ranked backlog for subsequent migrations

1. **Bucket 1a — retire the provably-dead after-gate REST denies.** Each one's deny fires
   after its route's own `perm_fn` already ran, so retirement is zero-behavior-change:
   `schedule_routes.cpp:67`, `server.cpp`'s three schedule routes, `mcp_server.cpp`'s
   `get_dex_group_app_perf`. No route migration needed — just delete the dead call + its
   stale doc comment.
2. **Read-only fleet reads, by plausible ITServiceOwner value** (this migration's own
   reasoning, applied forward): device/network lists (`list_dex_perf_devices`,
   `list_network_devices` + REST twins) → `list_schedules` → DEX/Guardian reads.
3. **Mutations, last** — a different primitive pairing (`confine_agent_target` +
   `require_scoped_permission`, single-agent-shaped, not `require_fleet_read`).
4. **§3d — the `authorize_list_read` supersede→intersect migration** (ADR-1006's deferred
   item; two twin-pairs, `plugin_config_routes.cpp`/MCP `list_plugin_config` and the
   upload-grants resolver at `server.cpp:17722`/`:18307`). Separate stream — the
   plugin-config pair has no agent dimension, so it needs a `kServiceScopeGlobalSafe`-style
   policy decision rather than a `meet()`, unlike upload-grants' clean intersection.
5. **Bucket 3 — routes with no primary RBAC gate at all** (the `deny_service_scoped_session`
   family, the `/api/v1/result-sets` family, `/api/scope/estimate`, compliance fragments).
   **Explicitly out of scope for a `require_fleet_read` migration** — these need a gate added
   first (§3e class), a different and larger change than narrowing an existing one.

Known open items this migration surfaced but did not resolve:

- `docs/auth-architecture.md:2458` vs `docs/mcp-server.md:22` disagree on whether a bare
  `perm_fn` (no `deny_fleet_wide_service_scoped`/`scoped_perm_fn`/`exec_visible` check)
  qualifies an MCP tool's `confined` label — resolve when retiring the remaining 7 MCP denies.
- `docs/auth-architecture.md:2464`'s "Dispatch's supersede→intersect migration" sentence
  conflates `authz::meet`'s dispatch-confinement use (ADR-0033, `compose_exec_visible` —
  genuinely supersede, zero `authorize_list_read` callers) with the actual §3d targets (4
  `authorize_list_read` callers, unrelated to dispatch). Not fixed here — out of this PR's
  diff scope; flag for whoever picks up §3d.
