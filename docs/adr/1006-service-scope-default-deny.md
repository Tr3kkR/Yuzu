---
status: accepted
date: 2026-08-18
owner: Dave Rae
deciders: Dave Rae (this session's implementation + review)
scope: server auth — service-scoped API token authorization posture
---

# 1006 — Service-Scoped API Token Confinement: Default-Deny, Not Admit-by-Default

Related: `docs/auth-architecture.md` "Service-scoped token fleet-wide
confinement", `.claude/routed-concerns-access-control.md`'s row for this
concern, ADR-0017 (management-group confinement of list reads, the
*other* authority axis this design intersects with), ADR-1005 / ADR-0031
(headless platform, engine principals — a related but distinct principal
class), `docs/security-reviews/service-scope-flip-route-inventory-2026-08.md`
(the closed route inventory this PR produced).

## Context

A **service-scoped API token** is minted for one IT service's integration
work — its `session->token_scope_service` field is non-empty on the
resolved session, and it is meant to reach only the devices/data belonging
to that one service, not the whole fleet.

Two independent axes govern what any session can see or do:

1. **Management-group visibility** — `RbacStore::authorize_list_read`
   (ADR-0017), the admit-then-filter chokepoint for list/fan-out reads.
2. **Service-scope visibility** — whether a session's own
   `token_scope_service` narrows it further.

Prior work on this issue (guardian-confinement-2298) found and fixed
individual instances of a recurring gap: a route's confinement check was
keyed on username, role, or resource ownership, and simply never consulted
axis 2 at all. Because the seeded `ITServiceOwner` role holds broad CRUD
across most securables, the practical effect was that **holding
`ITServiceOwner` was treated as sufficient authority on its own** —
service scope was never actually enforced as an independent, narrowing
axis. Earlier PRs in this saga (role cap at mint time; Phase 0 primitives;
gate renames) reduced blast radius and built infrastructure, but the
underlying shape — axis 2 is consulted only where some engineer remembered
to add a check — remained. This PR ("the flip") changes the *default*:
axis 2 is now consulted by construction wherever axis 1's gate
(`require_permission`/`require_scoped_permission`) runs at all, and every
route that bypassed both gates entirely now has an explicit deny.

## Decision

### The two axes intersect, never supersede

A session's effective authority is the **intersection** of what its
management-group axis permits and what its service-scope axis permits
(`authz::meet` composes the two `VisibleSet` values elsewhere in the
codebase for the *dispatch* confinement version of this same principle —
ADR-0033). For `require_permission`'s coarser securable:operation grant
check, the equivalent is: **service scope is never left unfiltered because
axis 1 already granted the permission.** `RbacStore` itself stays
single-axis (it answers "does this role/principal hold this permission",
nothing about service scope) — composing the second axis is
`AuthRoutes`'s job, not `RbacStore`'s.

### Default-deny: the seeded-empty allow-list

`AuthRoutes::require_permission`'s service-scoped branch (`auth_routes.cpp`)
now enforces, in order:

1. RBAC enforcement must be in effect (`rbac_enforcement_in_effect`, not
   raw `is_rbac_enabled()` — deny-on-degrade, same predicate the #1717
   list-read filters use, so the gate and the filter can never disagree on
   a corrupt store). Not in effect → `403`.
2. The `ITServiceOwner` role itself must hold `securable_type:operation`
   (`check_role_has_permission`) — this remains the **authority ceiling**:
   a service token can never exceed what that role grants, regardless of
   what other roles its minter separately holds.
3. The pair must **also** appear in `kServiceScopeGlobalSafe`
   (`service_scope_policy.hpp`) — seeded **empty**. Everything not
   explicitly entered `403`s.

This inverts the old shape: previously, clearing step 2 was sufficient;
now steps 2 and 3 are both required, and step 3's table starts empty. A
route that legitimately needs to serve service-scoped tokens migrates onto
`require_fleet_read`/`confine_agent_target` (Phase 2, metric-prioritized —
see `yuzu_auth_service_scope_default_denied_total{permission,path_class}`)
rather than growing the allow-list — widening the allow-list is a security
decision requiring the same rigor (security-guardian sign-off, proof
derived from what the DATA actually is) as adding a route to it in the
first place.

**Testability.** Because the allow-list ships empty, the admit branch of
both this check and MCP's mirror below is otherwise dead code — a small
testonly override seam
(`AuthRoutes::set_service_scope_global_safe_override_for_test`) exists so
it has real test coverage.

### Branch order is fixed and load-bearing

`require_permission` evaluates, in this order: `elevated → engine →
mcp_tier → service → RBAC-enforced-legacy → legacy`. This order must not
change without re-verifying every guard below, because two of the earlier
branches could otherwise become a bypass of the service branch:

- **Elevated.** JIT admin elevation is checked first and grants full
  admin for its window — but only cookie sessions can elevate; a
  service-scoped token is synthesized per-request and never carries
  `elevated_until`. The branch is still explicitly guarded
  (`is_elevated(*session) && session->token_scope_service.empty()`) as
  defense-in-depth: it must never become the thing that lets a
  service-scoped token skip the flip, even if the "can't elevate" invariant
  ever changes.
- **Engine.** Engine principals resolve RBAC-only and get their own
  belt-and-braces default-deny consult if a non-empty `scope_service` ever
  reaches an engine session (mint-time validation already rejects this —
  the check here guards a corrupted/constraint-bypassed row only).
- **MCP tier.** The tier branch enforces `tier_allows`/approval policy and
  then either **denies** (`return false`) or **falls through** — it never
  `return true`s on its own. A session carrying both a non-empty
  `mcp_tier` and a non-empty `token_scope_service` therefore still reaches
  the service branch below and is evaluated by the same default-deny rule;
  a future change that made the tier branch admit directly would silently
  reopen the flip on every route protected by `require_permission` at
  once — this is the single highest-consequence regression this design is
  exposed to, and any change to that branch must re-verify the
  fall-through property.

`require_scoped_permission`'s service branch and `require_fleet_read` both
adopt the same `rbac_enforcement_in_effect` predicate for consistency
across all three gates.

### Decision 1 — RBAC-off: hard `403`, not a narrowed view

`require_fleet_read` could, in principle, fall back to a tag-scoped view
of the fleet when RBAC is off rather than denying outright — but this ADR
decides it must **not**: a service-scoped session gets a hard `403` when
RBAC enforcement is not in effect, the identical posture
`require_permission`'s service branch already takes. A narrowed-but-open
fallback would be a second, harder-to-reason-about code path with its own
review surface, for a case (RBAC-off) that should be rare in a properly
configured deployment. Consistency across the three gates was judged more
valuable than a softer failure mode here.

### Decision 2 — closes #3218: two gates, two route classes, kept deliberately separate

`require_list_read` and `require_fleet_read` are NOT alternate names for
the same concept and must not be merged:

- **`require_list_read`** is the sole gate on fleet-wide rollup routes. It
  refuses a service-scoped session outright, because a rollup has no
  natural per-service slice to narrow to.
- **`require_fleet_read`** is meant to be **paired with**
  `require_permission` on routes migrating toward real per-request
  confinement (Phase 2). Used alone it is a coarser check; paired, it adds
  the RBAC-off hard-deny posture of Decision 1 on top of
  `require_permission`'s own default-deny.

Both gates carry a doc comment naming the other's route class, so a future
reader reaches for the correct one rather than treating them as
interchangeable.

### MCP: the C8 `ServiceScopeClass` chokepoint

Every `tools/call` dispatch consults a third field on the tool's
`kToolSecurity` row, added this PR: `denied` (default member initializer —
the existing 91-row table is untouched except rows explicitly reclassified),
`confined`, or `global_safe`. Enforcement runs immediately before
`tier_allows`, so a service-scoped caller sees `kPermissionDenied` before
tier is even consulted for a `denied` tool — tier is not bypassed by this
ordering, since deny is deny regardless of order, but it is a real,
deliberate behavior change worth naming: a small minority of tools were
previously tier-first in their own in-handler deny.

`confined` is a claim about **mechanism**, not usability: it means a real
downstream confinement check exists for this tool (a
`deny_fleet_wide_service_scoped` call, a `scoped_perm_fn` per-agent check,
or a fail-closed `exec_visible` derivation) — most `confined` tools still
deny a service-scoped caller downstream via their own handler, under the
same seeded-empty allow-list. A tool with no such mechanism defaults
`denied`, full stop, even when its data looks like it *might* be safe to
share (a genuine fleet-wide aggregate with no per-agent identity, for
example) — that determination is Phase 2's job (a `kServiceScopeGlobalSafe`
policy-table entry with security-guardian sign-off), never an inference
made while writing the C8 plumbing itself. `global_safe` cross-checks
against the identical `kServiceScopeGlobalSafe` table `require_permission`
reads, at boot — an empty table means every `global_safe` row fails boot,
which is correct until Phase 2 actually populates one.

`resources/read` bypasses C8's dispatch structurally (it is not a
`tools/call`), but calls `perm_fn` directly at every one of its ~9 call
sites, so it is covered by the flip the same way any REST route is — this
was verified, not assumed, and is recorded here so a future reader does
not need to re-derive it.

### Explicit denies for gate-less routes (§3e)

A route that never calls `require_permission`/`require_scoped_permission`/
C8 at all is untouched by everything above, no matter how the flip itself
is tuned. Every such route found in this PR — by design-time enumeration
and by a residual grep sweep of all `auth_fn`/`perm_fn` call sites in
`rest_api_v1.cpp` (74 sites) and `mcp_server.cpp` (3 sites) — now has an
explicit deny. The sweep additionally surfaced one **distinct, more
severe, not service-scope-specific** defect in the same code
(`POST /api/v1/result-sets/from-inventory-query` had no authorization
check of any kind, CWE-862) — fixed alongside, but it is a different bug,
not another instance of this pattern; its own missing-authorization fix
happens to also close the service-scope gap here, since it is gated
through the same flipped `require_permission`.

Full route-by-route inventory, verification depth per row, and the
document-only dispositions (routes deliberately left unchanged, with
reasoning): `docs/security-reviews/service-scope-flip-route-inventory-2026-08.md`.

## Consequences

- **Fleet-wide aggregates with no per-agent identity stay `denied` in v1**
  (e.g. `get_dex_perf_fleet`, `get_dex_perf_cohorts`,
  `get_dex_perf_cohort_diff`, `get_network_fleet`, and by the same
  reasoning `list_dex_perf_apps`/`get_dex_app_perf`) — even though their
  data plausibly carries no service-scope leak risk, none of them have a
  real downstream confinement mechanism today, and `confined` without one
  is exactly the unenforced claim this design exists to prevent.
  Re-admission is Phase 2 policy-table work, prioritized by the
  `yuzu_auth_service_scope_default_denied_total` metric.
- **Service-tag writes are an accepted, unhardened boundary for now.**
  Whoever can set an agent's `service` tag effectively moves that agent's
  scope membership; this PR does not harden that write path. Tracked as
  its own follow-up review, not folded in here.
- **No cached derived confinement sets.** Every check in this design reads
  live state (RBAC grants, the allow-list, tag data) — no precomputed
  "this token can see these agents" cache is introduced, avoiding a whole
  class of staleness bugs at the cost of a live lookup per gated call.
- **Dispatch's supersede→intersect migration is out of scope.** The
  `authz::meet` composition already used for dispatch confinement
  (ADR-0033) is a separate, already-decided mechanism; migrating its four
  remaining `authorize_list_read` callers off a supersede-style
  composition is deferred to Phase 2 (§3d), not part of this PR.
- **Bootstrap gap, by design.** An empty-cohort service token cannot
  bootstrap its own scope — there is no route it can call, under this
  design, that would let it discover or claim a service tag for itself.
  Onboarding a brand-new service therefore still needs an interactive or
  otherwise-unscoped path; see the operator runbook in
  `docs/user-manual/authentication.md`.
- **The per-file `deny_service_scoped_*` helpers become largely redundant
  double-denies** for any route that also calls `require_permission`
  (the flip already denies there) — kept for now, scheduled for Phase 2
  retirement once those routes migrate onto `require_fleet_read`/
  `confine_agent_target`. They remain load-bearing only for the §3e class
  (no other gate call at all).

## Rejected alternatives

- **A narrowed-not-denied `require_fleet_read` under RBAC-off** — see
  Decision 1. Rejected for consistency with `require_permission`'s
  existing hard-deny posture and to avoid a second failure-mode code path.
- **Merging `require_list_read` and `require_fleet_read` into one gate** —
  see Decision 2 (#3218). Rejected because they answer different
  questions (does this route have a per-service slice to narrow to, at
  all) and merging them would either weaken the rollup gate or complicate
  the confinement-pairing gate.
- **Consolidating every per-file `deny_service_scoped_*` helper into one
  shared chokepoint now** (the shape `authz_topology_floor.hpp`/
  `body_cap_policy.hpp` use for structurally identical problems).
  Deferred to Phase 2: the flip itself is the real consolidation for the
  majority of routes (anything that calls `require_permission`); the
  residual per-file helpers only remain for the smaller, now-closed §3e
  set, where the cost of a shared chokepoint no longer clearly outweighs
  the risk of a mid-migration call-site gap.
