- **`POST /api/command` now confines every dispatch arm to the caller's authorized devices (#1788).**
  The generic-dispatch escape hatch base-gated a single, possibly-global `Execution:Execute`
  permission and then reached its target through one of four arms — an explicit `agent_ids` list,
  the published `__all__` broadcast, a management-`group:<id>`, or a scope expression — without
  narrowing any of them to the caller's own reach. The **live** exposure was a service-scoped token:
  `require_permission` admits it via the `ITServiceOwner` role grant (independent of the minter's own
  grants), so it dispatched to the whole fleet through any arm — most directly by naming a
  foreign-service device in `agent_ids`. All
  four arms now derive one visibility decision before dispatch and intersect every resolved target
  set against it; a device the caller may not see is silently dropped from the send set rather than
  reached. The decision is by principal class: **a service-scoped token is narrowed to exactly
  the agents tagged with its own service** (the same confinement axis `require_scoped_permission`
  applies per-target, which the generic path previously skipped — so a token scoped to service A can
  no longer dispatch into service B through any arm), failing closed if the tag store is unavailable;
  a global administrator, a JIT-elevated session, and (in a legacy RBAC-disabled deployment) a legacy
  admin remain full-fleet, which is their actual authority, not a bypass. A purely
  management-group-confined operator is likewise narrowed to
  `RbacStore::visible_agents_for_permission` (`Execution:Execute`, composing on top of — never
  re-deciding — the frozen #1715 combining lattice); note this arm is **forward-wiring**, not a live
  fix — such an operator holds no global grant and is already denied by the base `require_permission`
  gate today (the ADR-0017 "correct-but-unreachable" World-A gap), so the narrowing takes effect only
  once the ADR-0017 list-admit gate (#1714/#1715) makes that principal reachable. Every
  `dispatch_target_shape.hpp` invariant is preserved: `__all__` is still never inferred from an
  omitted target, and a targeting argument supplied but resolving to nothing is still refused as a
  400 before any arm runs. Beyond the `/api/command` surface #1788 names, the same confinement now
  covers every OPERATOR dispatch surface: MCP `execute_instruction` and `execute_bundle`, REST
  `POST /api/v1/bundles`, the dashboard execute and TAR `purge_source` routes, the per-device
  DEX live query, the three async result-set producers
  (`POST /api/v1/result-sets/from-tar-query`, `/from-instruction-result` and `/{id}/re-eval` —
  which admit on a bare global `Execution:Execute` gate and then reach the fleet by scope or
  `__all__` broadcast, so a service-scoped token previously dispatched fleet-wide through them),
  and `POST /api/instructions/{id}/execute` + `POST /api/workflows/{id}/execute`, and the legacy
  `/api/chargen/start|stop` + `/api/procfetch/fetch` routes (which reached the fleet through a
  direct `send_to_all`, bypassing the dispatch closure entirely) — all intersecting the
  caller's visible set through one shared per-arm seam, and all failing CLOSED when the derivation
  is unwired: a present-empty visible set (never "unfiltered") where the confinement is a
  defense-in-depth layer behind a per-target scope gate, and an audited `500` on the three async
  producers, where it is the only per-device authorization they have. The REST layer's dispatch
  callback now REQUIRES the caller's visible set as a parameter, so the unconfined system closure
  the background engines use is no longer type-compatible with it — the wrong closure stopped
  being available to pick rather than merely being avoided. The fail-closed set itself is now
  spelled by a named constructor (`authz::deny_all()`) at every one of its call sites, because the
  bug above was a hand-written `VisibleSet{}` — which *looks* like an empty set and in fact
  default-constructs the optional to "unfiltered", the exact inverse. (Still deferred: the BACKGROUND
  dispatch paths — the scheduler, Guardian push, the policy evaluator — which dispatch as system
  rather than on behalf of an operator. Those belong to the core-owned dispatch chokepoint tracked
  with the capability-registry work: the ADR-1005 / ADR-0017 gate, #1714/#1715.)
