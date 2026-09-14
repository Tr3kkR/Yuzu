- **Guardian (Guaranteed State) REST/MCP write + per-agent read parity (#2146 Batch B1).** Seven new MCP tools twin the remaining REST v1 Guaranteed State operations that had no MCP counterpart: `create_guardian_rule`, `get_guardian_rule`, `update_guardian_rule`, and `delete_guardian_rule` twin `POST`/`GET`/`PUT`/`DELETE /api/v1/guaranteed-state/rules{,/{id}}` (same `derive_rule_spec` structured-authoring validation, same `create_rule`/`update_rule`/`delete_rule` store calls, same fleet-wide `deny_fleet_wide_service_scoped` posture as their REST siblings — a Guard has no single owning device/service); `push_guardian_rules` twins `POST /api/v1/guaranteed-state/push` via the identical `GuardianPushFn` fan-out closure REST uses (new `McpServer::set_guardian_push_fn` seam, wired from the same `server.cpp` lambda as REST — the two surfaces cannot dispatch a different push), and is honestly annotated `idempotentHint:false`: each call re-dispatches against the current rule set, it does not converge on a no-op replay. `get_guardian_agent_status` and `get_guardian_device_compliance` close the two per-agent reads #4037 deliberately deferred, twinning `GET /api/v1/guaranteed-state/status/{agent_id}` and `GET /api/v1/guaranteed-state/device-compliance` via the same `scoped_perm_fn` per-device confinement REST uses (new `McpServer::set_baseline_store` seam for the latter). The per-agent status derivation is also extracted into a new shared `guardian_agent_status_rollup` builder in `guardian_model.hpp` (mirroring the #4037 `guardian_status_rollup` precedent) that both the REST route and its MCP twin now call — incidentally closing a pre-existing REST audit-timing gap where a degrade confined to the second of two sequential store reads was audited `success` despite the request ultimately failing.
  Known limitation, tracked separately (#4309, not introduced by this batch): MCP
  tier/approval enforcement is architecture-wide inert for an MCP-tier-less caller
  (a cookie session, a plain non-MCP-tiered API token, or an engine token -
  `mcp_tier` is only ever set on an actual MCP token) - **except** for
  `delete_guardian_rule` specifically, where a governance review round found this
  gap meaningfully widened (approval-ticket bypass AND MFA bypass together, on a
  destructive deletion of auto-remediation policy - not just an inert approval
  step) and a scoped fix landed in the same batch: an MCP-tier-less caller is now
  denied outright rather than falling through to RBAC-only enforcement. The
  architecture-wide gap remains open for `create_guardian_rule`/
  `update_guardian_rule`/`push_guardian_rules` (none of which are approval-gated
  at any tier - `GuaranteedState:Write`/`Push` aren't in `mcp_policy.hpp`'s
  `requires_approval()` list - so there is no approval to bypass on those three,
  only the MFA-step-up gap every other unmigrated approval-gated tool shares) and
  every other approval-gated MCP tool not yet migrated.
