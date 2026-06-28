---
status: accepted
date: 2026-06-28
owner: Nathan Dornbrook (platform)
deciders: Nathan Dornbrook; issue #1714 (intent question)
scope: server — authorization shape for list/fan-out reads of per-agent data under management-group confinement
resolves: #1714
builds-on: #1634 (response-reader ruling), PR #1711 (per-row filter foundation), #1550 (query_responses scoping), #1713/#1676 (inventory)
---

# 0017 — Management-group confinement applies to list/fan-out reads: the admit-then-filter list gate

## Context

Management groups confine an operator to a subset of the fleet. For **per-device** routes this
works today: the route's admission check *is* `scoped_perm_fn_(req, res, "<securable>", "<op>", id)`
(`device_routes.cpp:535`), which calls `RbacStore::check_scoped_permission`. That function admits a
caller who holds the permission either **globally** (step 1, the global `check_permission`,
`rbac_store.cpp:1115`) **or** via a management group containing `agent_id` (steps 3-5, consulting
`ManagementGroupStore::get_group_roles` / the `management_group_roles` table, `rbac_store.cpp:1153-1180`).
A single `agent_id` is available, so the scoped check can serve as the gate.

For **list / fan-out** reads (responses, the device list, inventory, DEX/TAR list surfaces) there is
no single `agent_id` to gate on. These routes instead gate on the **global** `require_permission` /
`perm_fn` (e.g. `dashboard_routes.cpp:203`, `rest_api_v1.cpp:3479`, `mcp_server.cpp:1217`,
`server.cpp:5307`) and then — where a filter exists at all — drop out-of-scope rows per-row with
`check_scoped_permission(user, sec, op, agent_id)`.

That shape is **inert**. UAT-proven (Windows, real server, `Operator@G1`-confined user `opA`,
agent-1 ∈ G1; full reproduction in #1634 / `streamB-maintainer-finding`), grilled with 5 disproof
attempts, all failed:

- **Global holder** (admin / global Operator): passes the global gate; `check_scoped_permission`
  step 1 returns true for **every** agent → the per-row filter is a no-op → sees the whole fleet.
  *(UAT: admin saw agent-1 + agent-2.)*
- **Confined operator** (`Operator@G1`): the global gate is `check_permission`, which consults only
  `principal_roles` (user) ∪ RBAC `group_members` (`collect_roles_locked`, `rbac_store.cpp:930-944`)
  — **never** the management-group `GroupRoleAssignment`s. So the confined operator is **403'd at the
  gate** and never reaches the filter. *(UAT: opA → 403 on `/api/responses/*`, `/api/agents`,
  `/fragments/devices/list`.)*

There is **no** RBAC configuration where an operator passes the global list gate *and* the filter
narrows. The per-row filters shipped for responses (#1634 / PR #1711) and `query_responses` (#1550)
are correct-but-unreachable. The same applies to `ManagementGroupStore::get_visible_agents`
(`management_group_store.cpp:628`): it narrows by **role-existence** (any role in the group,
`principal_type='user'` only) rather than by the *specific* permission, and is itself unreachable for
a confined operator / short-circuited for a global holder.

This issue (#1714) is the intent question that gates that whole class of work: **is list-view
management-group confinement actually intended?**

- **World A — yes (latent gap):** a confined operator who holds `Response:Read` (or
  `Infrastructure:Read`, `Execution:Execute`, `Inventory:Read`) via a management group should see, in
  list/fan-out reads, only the agents inside those groups.
- **World B — no:** operators hold **global** read; management groups confine **only per-device
  routes** and organize the fleet. The per-row filters are unnecessary.

**Nothing is leaking today** — no management-group-confined operators exist in practice (they would
be 403'd everywhere), which is precisely why this sat undetected across multiple shipped features.
High-importance architecture debt, low operational urgency. Decide deliberately; do not hotfix.

## Decision

**World A.** List-view management-group confinement is intended. A confined operator who holds a
read permission via one or more management groups must, on list/fan-out reads, be **admitted** and
shown **only** the agents within those groups (ancestor-aware), exactly as the per-device routes
already behave for the single-`agent_id` case.

Three signals make World A the standing intent, not a new aspiration: the explicit #1634 ruling ("a
response is readable iff the caller holds `Response:Read` via a management group containing the
response's `agent_id`"); the scoped-grant machinery (`Operator@G1` delegation, `GroupRoleAssignment`,
`management_group_roles`) already exists and was built for confinement that cannot currently take
effect; and the per-device `scoped_perm_fn` precedent *is* World A for the single-id case.

### The blocker is the gate shape, not the RBAC model

`check_scoped_permission` (steps 3-5) **already expresses** per-agent management-group authorization.
Two pieces are missing, and World A adds exactly these — it does **not** rewrite the RBAC model:

1. **A list-admit primitive.** "Does this user hold `<securable>:<op>` via *any* management group?"
   — because a list gate has no single `agent_id` to pass to `check_scoped_permission`. New
   `RbacStore` method, e.g. `holds_permission_via_any_group(user, securable, op, mgmt_store)`,
   mirroring steps 3-5 over the union of the user's reachable management groups (deny-overrides
   preserved). Admit if global `check_permission` **or** this returns true.
2. **A permission-specific visible set.** The per-row filter must narrow by the *specific*
   permission, not by `get_visible_agents`' role-existence. PR #1711 already built the per-row
   predicate (`check_scoped_permission(user, sec, op, agent_id)`); the list path reuses it, or a
   batched `visible_agents_for_permission(user, sec, op)` equivalent.

### The admit-then-filter list gate

Every in-scope list/fan-out route adopts one shape:

1. **Admit** if the caller holds the permission globally **or** via any management group
   (the new primitive). 403 only if neither.
2. **Carry an `is_global` flag.** A global holder skips the per-row filter (correct full-fleet
   read; no wasted work). A non-global (group-confined) caller runs the filter.
3. **Filter** per row by the permission-specific scoped check, ancestor-aware, fail-closed on a
   corrupt/unavailable `rbac.db` (the PR #1711 `rbac_enforcement_in_effect` posture).
4. For **aggregates** (`aggregate_responses`), filter **before** aggregating — never aggregate the
   full fleet and trim after.

This is the product's first admit-then-filter list pattern; it is introduced **once** as a shared
helper and applied **consistently**, never re-invented per route.

### In scope (per-agent list/fan-out reads)

The surface list below is **indicative**, sourced from the #1634 / `streamB-maintainer-finding`
sweep — it is the decision's coverage map, not the authoritative wiring checklist. Each wiring PR
**re-enumerates exhaustively** within its surface (grep every `perm_fn` / `require_permission`
list-read site) so a missed route does not silently inherit the old global gate.

- **Responses** — `query_responses` (#1550), `aggregate_responses` (filter-before-aggregate),
  REST `/executions/{id}/visualization`, `/api/responses/{id}` (GET list) + `/export`, dashboard
  `/fragments/results` + the scan fragment, workflow execution-detail.
- **Device list** — `/api/agents` (`server.cpp:5312`), `/fragments/devices/list`, the dashboard
  `get_visible_agents` callers (`dashboard_routes.cpp:989/1159/1889`, `server.cpp:7892/8543`),
  `get_visible_agents_json` (`server.cpp:3784`).
- **Inventory** — `query_installed_software` (MCP, `mcp_server.cpp:1377`),
  `GET /api/v1/inventory/software` (`rest_api_v1.cpp:3026+`) — #1713 / #1676 (needs its own UAT to
  settle effective-vs-inert; the born-on-PG `SoftwareInventoryStore` path may differ).
- **DEX / TAR list surfaces** — the `VisibleSetFn` seam (`server.cpp:8516`).

### Out of scope (global by design)

Config / settings / CA / auth / discovery-write / offload / notification routes operate on
fleet-global or non-per-agent data and remain global-gated. They are not per-agent reads and World A
does not touch them.

### True in **either** world (do not block on this decision)

Two corrections are needed whether A or B is chosen and should ship independently of the gate work:

- **Doc honesty.** The docs/comments that *claim* effective list-view scoping today are false-as-
  shipped: `docs/user-manual/tar.md:302` ("scoped to your management-group visibility"), the
  inventory/MCP "out-of-scope devices omitted" strings (`mcp_server.cpp:255/1436`,
  `mcp_server.hpp:96`, `rest_api_v1.cpp:3235`, `rest_api_v1.hpp:116/129`, `docs/user-manual/inventory.md:106/141`,
  `docs/adr/0016-…:175/181`, `docs/rest-api.md:2659`, `docs/mcp-server.md:45`). Until the gate
  lands, these must read as "global read; per-device confinement only" (PR #1711 already corrected
  the response-reader strings).
- **UP-E fail-open fix (HIGH).** The deferred dashboard `/fragments/results` table
  (`dashboard_routes.cpp:1317`) and the workflow executions-drawer reader (`workflow_routes.cpp:548/550`)
  gate on flat `perm_fn` with **no per-agent filter at all** → on a corrupt/load-failed `rbac.db`
  they **fail OPEN** (full-fleet response disclosure to any authenticated principal). A focused
  `rbac_enforcement_in_effect` fail-closed filter on those two readers is independent of the gate-
  model decision and should ship at UP-1 severity.

## Consequences

- A new, named authorization pattern (admit-then-filter list gate) enters the codebase. Every
  future list/fan-out read of per-agent data must use it, not a bare global `require_permission`.
  This ADR is the contract those PRs build to.
- The per-row filter foundation (PR #1711) and `query_responses` scoping (#1550) become **live**
  rather than inert once the admit primitive is wired in; #1550's gate must be swapped to the
  admit-then-filter shape (it has the filter, the wrong gate).
- Each surface re-runs the `opA`-confined UAT reproduction to *prove* narrowing (a confined operator
  is admitted and sees only in-scope rows; a global holder still sees all; both fail closed on a
  corrupt `rbac.db`).
- Cross-operator authorization → every wiring PR runs the full governance pipeline with
  security-guardian + consistency-auditor + unhappy-path + chaos as load-bearing reviewers.

## Rejected alternative — World B

"Operators hold global read; management groups confine only per-device routes and organize the
fleet." Rejected because it contradicts the #1634 ruling, strands the `GroupRoleAssignment` /
`Operator@G1` delegation machinery (built specifically for confinement), and is inconsistent with the
per-device precedent. If World B were chosen the per-row filters would be deleted as dead weight and
the scoped-grant UI removed — a larger product reduction than building the gate. The doc corrections
above would still be required.

## Implementation ladder (separate governed PRs)

Sequenced; each its own governance round + `opA`-confined UAT re-run.

1. **PR-A — foundation.** This ADR + the list-admit primitive
   (`holds_permission_via_any_group`) + the shared admit-then-filter helper (`{admit, is_global}`)
   + the permission-specific visible-set fn + unit tests. **No route behavior change** (no call site
   switched yet), so it lands safely ahead of the wiring.
2. **PR-B — responses.** Builds on PR #1711's per-row filter; swaps the global gate for the
   admit-then-filter gate across the ~8 response readers; `aggregate_responses` filters before
   aggregating; #1550's `query_responses` gate swapped.
3. **PR-C — device list.** `/api/agents`, `/fragments/devices/list`, the `get_visible_agents`
   callers, `get_visible_agents_json`; replace role-existence narrowing with permission-specific.
4. **PR-D — inventory.** `query_installed_software` + `GET /api/v1/inventory/software` (#1713 /
   #1676), after the dedicated inventory UAT settles effective-vs-inert.
5. **PR-E — DEX / TAR.** The `VisibleSetFn` seam + remaining dashboard fragments.

Gate-independent, shippable now (not on this ladder): the doc corrections and the UP-E fail-open fix.
