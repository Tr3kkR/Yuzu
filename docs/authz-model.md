# The authz MODEL (ADR-0033 §2) and the `/api/command` per-device visibility fix (#1788)

This document covers two related but separable pieces of PR1.4:

1. **The registry-independent authz MODEL** (`server/core/src/authz_model.hpp`) — the
   securable×operation×risk_tier×mcp_tier_class classification a future runtime
   capability-declaration registry (PR1.9) will consume when a Module registers a tool or REST
   route.
2. **The #1788 fix** — closing the `/api/command` per-device visibility gap across all four
   dispatch arms.

Both live in `authz_model.hpp` because the second reuses the first's shared `VisibleSet`
primitive, but they are independent: the model does not enforce anything, and the #1788 fix does
not depend on the seed catalogue.

## Spine-version assumption

This PR is written against **ADR-0033 as accepted 2026-07-14** (`docs/adr/0033-access-control-spine.md`,
"design-only, binds prospectively"). Alex accepted the rework risk of building against that spine
before the runtime capability-declaration registry (ADR-0033 §2's own stated precondition) exists —
if the ADR is amended before PR1.9 lands, this schema may need a rework pass.

## 1. The authz MODEL

### Vocabulary

- **`securable`** — reuses an existing `RbacStore::list_securable_types()` entry (21 seeded types,
  `rbac_store.cpp:217-244`, read-only reference for this PR) wherever one accurately describes the
  protected resource. A Module minting a genuinely new securable is an ADR-0033 §2 escape hatch that
  is **not built yet** — its own stated precondition is the runtime capability-declaration registry,
  which is PR1.9's job, not this one's.
- **`operation`** — `yuzu::server::authz::Operation`. ADR-0033 §2 names "the existing six" as
  Read/Write/Execute/Delete/Approve/Push. `Attest` is a seventh, narrower operation
  (`rbac_store.cpp` seed comment: Periodic Access Reviews, SOC 2 CC6.2) — deliberately excluded from
  every CRUD loop there, and included in this model's enum for the same reason: a capability can
  genuinely declare it.
- **`risk_tier`** — `yuzu::server::authz::RiskTier` (Low/Medium/High/Critical). The routing input
  ADR-0033 §5 (D5)'s future auto-approval policy layer will consume; the ADR does not fix concrete
  thresholds (D5 is explicitly future work), so this is a deliberately small, ordered scale captured
  from day one rather than a speculative rule language. `min_risk_tier_for(operation)` is the one
  rule this PR commits to: a **floor**, so a capability cannot under-declare the risk of an
  inherently sensitive operation class (Delete/Approve/Push floor at High; Write/Execute/Attest at
  Medium; Read at Low). Declaring above the floor is always fine.
- **`mcp_tier_class`** — `yuzu::server::authz::McpTierClass` (read/write/execute). ADR-0033 §2: the
  routing input the shipped **tier-before-RBAC** ordering (`docs/mcp-server.md`,
  `mcp_policy.hpp::tier_allows`) evaluates every built-in and declared tool through — one
  chokepoint, extended, never a parallel one. This is deliberately **not** derived purely from
  `operation` in general: ADR-0033 §1 is explicit that read-vs-effect ("the one typing that must not
  be self-certified") is core's *ratified* mutability class, decided when a Module's capability
  manifest is approved. `default_mcp_tier_class(operation)` is only a convenience for classifying
  this header's own seed catalogue below.

### The PR1.9-facing declaration schema

`CapabilityDeclaration` is the per-capability record PR1.9's registration path will populate. It
carries the securable×operation×risk_tier×mcp_tier_class quadruple this PR defines, plus the fields
ADR-1005/ADR-0032 require of **every** capability — the versioned REST twin, the MCP twin (or a
recorded ADR-1005 ledger exception), the `/api/v1/openapi.json` + MCP `tools/list` discovery entry,
the A4 error envelope, agentic-context annotations (track 2g), and `data_class` + `audit_verb`
(ADR-0032 Decision 11). This schema **references** those obligations as fields to populate at
registration — it does not redefine the platform mechanisms themselves, which stay governed by
ADR-1005/ADR-0032 and `rest_a4_envelope.hpp`.

`CapabilityDeclaration::is_valid()` enforces ADR-0033 §2's "undeclared means the capability does
not exist — never defaults to read": a missing `securable`/`discovery_entry`/`data_class`/
`audit_verb`, a `risk_tier` below its operation's floor, or both twins absent with no recorded
exception all fail validation, and a Module registration that fails it must not register on **any**
surface.

There is deliberately **no `execute_roles` field** (or any role-shaped field) — which principals
hold `operation` on `securable` stays entirely in `RbacStore`'s `role_permissions` table. This model
classifies a capability; it never grants one.

### Seed catalogue

`kSeedCatalogue` is five representative rows, not a full mirror of `RbacStore`'s 21 securables × 7
operations — it exists so PR1.9 has real rows to migrate and so this header's own tests exercise
`is_valid`, not to be the registry itself. It includes an ordinary CRUD read (`Response:Read`), a
`Tag:Write` (mirrors `mcp_policy.hpp`'s existing Tag special-case), `Execution:Execute` (the
combination the #1788 fix below narrows), the Guardian-only `Push` narrow op
(`GuaranteedState:Push`), and — required by this PR's spec — `AccessReview:Attest`, deliberately
outside every CRUD loop, exactly as seeded in `rbac_store.cpp`.

### Composition with the frozen #1715 lattice

This model **never re-decides** the frozen #1715 combining lattice or the single INV-7 resolver
`RbacStore` already ships (cross-boundary combining is additive/OR; a global allow overrides a group
deny; a global deny does not override a group allow; deny-overrides applies only within a single
group). It classifies securables/operations/risk-tiers and composes strictly on top, via
`RbacStore`'s existing public API (`check_permission`, `visible_agents_for_permission`,
`check_scoped_permission`, `authorize_list_read`) — never the private `resolve_perm_groups`/
`PermGroups`.

## 2. Closing #1788: per-device visibility on every `/api/command` dispatch arm

### The gap

`/api/command` (`server.cpp`, referenced at the handler's `#1788` comment) base-gates a single,
possibly-**global** `Execution:Execute` permission and then dispatches through one of four arms:

1. **Ids** — an explicit `agent_ids` list.
2. **Broadcast** — the published `__all__` ground scope.
3. **Group** — `group:<id>`, resolved via `ManagementGroupStore::get_members`.
4. **Scope** — a scope DSL expression, resolved via `AgentRegistry::evaluate_scope`.

None of the four narrowed the actual send set to the operator's own visibility — a caller whose
`Execution:Execute` grant is scoped to a management group (or who reaches the route via JIT
elevation, an MCP tier auto-grant, or a service-scoped token) could reach a device outside that
scope through **any** arm, most directly by simply naming it in `agent_ids`.

### The fix

`server.cpp` derives **one** permission-specific visible set — `yuzu::server::authz::VisibleSet`,
`std::nullopt` meaning "unfiltered" — right after the existing destructive-action block and before
any dispatch arm runs:

- If the operator holds `Execution:Execute` **globally** (`RbacStore::check_permission`), or reaches
  the route via JIT admin elevation (`auth::is_elevated`) or a service-scoped token's ITServiceOwner
  grant (`Session::token_scope_service`) — both of which `require_permission` above already treats
  as full access without a matching `principal_roles` row — the set is unfiltered. This mirrors
  `RbacStore::check_scoped_permission`'s own internal order (global first) so a global ALLOW keeps
  overriding a group deny (#1715(b)), rather than this fix inventing a second, divergent order.
- Otherwise, the set is `RbacStore::visible_agents_for_permission(user, "Execution", "Execute",
  mgmt_store)` — the ADR-0017 per-agent visible set. Any store error narrows to "nothing visible",
  never "everything" (fail-closed).

Every dispatch arm then intersects its own already-resolved target list against this set via the
shared, pure `yuzu::server::authz::in_scope` / `filter_to_scope` primitives before calling
`send_to`:

- **Ids** — `agent_ids` is filtered directly.
- **Group** — each resolved member is checked before `send_to`.
- **Scope** — `evaluate_scope`'s matched ids are filtered directly.
- **Broadcast** (both the named `__all__` arm and the untargeted-omission fallthrough, #2500) — a
  shared `dispatch_broadcast` closure sends to `AgentRegistry::send_to_all` only when unfiltered;
  otherwise it walks the currently-known agent ids (`AgentRegistry::to_json_obj`) and sends only to
  those in scope.

A hidden id is **silently dropped**, the same posture the Scope/Group arms already had for an id
that resolves to nothing (a 503 "failed to send command to any agent" only if the visibility filter
empties the *entire* resolved set) — this fix narrows the send set, it does not add a new error
shape.

### What this fix deliberately preserves

- Every `dispatch_target_shape.hpp` invariant: `__all__` is still the one published spelling of
  broadcast and is **never inferred** from an omitted target; a targeting argument that was
  **supplied** but resolves to nothing is still refused as a 400 before any arm runs (unchanged —
  this fix only touches what happens *after* a target set is already resolved).
- The frozen #1715/INV-7 precedence — this fix calls `RbacStore`'s public resolver-backed API and
  composes on top; it does not touch `rbac_store.{hpp,cpp}` and never reaches the private
  `resolve_perm_groups`.
- The existing destructive-action securable-elevation block (`kDestructiveActionSecurable`), which
  is untouched; its own `ManagementGroupStore`-based `agent_ids` filtering for the destructive-action
  list runs first, and this fix's visibility filter composes on top of whatever `agent_ids` block
  leaves behind (intersecting twice is idempotent).

## Testing

`tests/unit/server/test_authz_model.cpp` covers:

- `CapabilityDeclaration::is_valid()` against the seed catalogue and deliberately-invalid rows.
- Composition semantics (`visible_agents_for_permission` / `check_scoped_permission` /
  `authorize_list_read`) for `Execution:Execute` specifically, mirroring
  `test_list_read_confinement.cpp`'s fixture pattern, including the global-allow-overrides-group-deny
  and global-deny-does-not-override-group-allow #1715 cases.
- `in_scope`/`filter_to_scope` directly, exercising each of the four dispatch arms' characteristic
  target-set shape (an explicit id list, resolved group members, scope-matched ids, and the full
  known-agent-id list for broadcast) against a scoped visible set, and against `std::nullopt`
  (unfiltered).

The four dispatch arms themselves live inside `Server::start()`'s raw `httplib::Server`
registration and are not independently reachable by a test harness (the same limitation
`dispatch_target_shape.hpp` documents for `classify_dispatch_arm`, #2557) — the tests above cover
the shared primitive every arm calls, not the route closures directly.
