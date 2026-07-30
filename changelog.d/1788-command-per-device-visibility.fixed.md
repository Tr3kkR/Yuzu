- **`POST /api/command` now confines every dispatch arm to the operator's visible devices (#1788).**
  The generic-dispatch escape hatch base-gated a single, possibly-global `Execution:Execute`
  permission and then reached its target through one of four arms — an explicit `agent_ids` list,
  the published `__all__` broadcast, a management-`group:<id>`, or a scope expression — without
  narrowing any of them to the operator's own visibility. A management-group-confined operator (or a
  caller admitted via JIT elevation, an MCP-tier auto-grant, or a service-scoped token) could reach a
  device outside their confinement through any arm, most directly by naming it explicitly in
  `agent_ids`. All four arms now intersect their resolved target set against the operator's
  `Execution:Execute` visible set (`RbacStore::visible_agents_for_permission`, composing on top of —
  never re-deciding — the frozen #1715 combining lattice) before dispatch; a hidden device is
  silently dropped from the send set rather than reached. Every `dispatch_target_shape.hpp`
  invariant is preserved: `__all__` is still never inferred from an omitted target, and a targeting
  argument supplied but resolving to nothing is still refused as a 400 before any arm runs.
