- **`POST /api/command` and `POST /api/instructions/{id}/execute` no longer widen a supplied
  device target to the entire fleet.** A targeting argument the caller *supplied* that resolved
  to no devices was treated identically to one they never sent, and "no target named" means
  broadcast: `{"plugin":"service","action":"restart","agent_ids":[1,2,3]}` restarted the service
  on every connected agent under plain `Execution:Execute` and returned a success response, and
  so did `{"agent_ids":[]}` — the likelier shape, produced by any device filter that matched
  nothing. `/api/command` reached this through `extract_json_string_array`, which drops
  non-string entries and returns an empty list for an absent key, a non-array value and a
  malformed body alike; the one guard that would have caught it applies only to actions in
  `kDestructiveActionSecurable`, which contains a single entry. `/api/instructions/{id}/execute`
  rejected `[1,2,3]` only as a side effect of a JSON type error escaping into a generic
  `catch`, and still broadcast on `[]`, on a non-array `agent_ids` and on a non-string `scope`.
  Both routes now return `400` for every such shape, with the field named and the deliberate
  way to broadcast spelled out. This is the REST twin of the MCP fix in #2437/#2492, and it
  reuses that rule rather than restating it: the targeting checks moved into a new
  surface-neutral `dispatch_target_shape.hpp` that both surfaces call, so they cannot drift on
  what counts as a target.

- **Behaviour change worth reading before upgrading:** on `POST /api/instructions/{id}/execute`,
  "empty `agent_ids` + empty `scope` = broadcast to all agents" was *documented* behaviour, so a
  client that sends an explicitly empty `agent_ids` (or a non-array `agent_ids`, or a non-string
  `scope`) and expects a fleet-wide dispatch will now receive a `400` instead. Omitting both
  fields still broadcasts, on both routes — that is unchanged and is the supported way to target
  the whole fleet deliberately.

- **`POST /api/policies/{id}/remediate` had the same defect and is fixed with it.** An empty
  target list there means "every non-compliant agent in this policy", and the route dropped
  non-string entries silently — so `{"agent_ids":[1,2,3]}` remediated the entire non-compliant
  set, answered `202`, and audited success. A mutating remediation path, found by an independent
  review after the in-house rounds had cleared `PolicyEvaluator` as a *dispatch caller* without
  reading the *route's* own parsing. That route also now refuses a supplied `scope` outright
  (`400`): `remediate()` selects targets by `agent_ids` only, so validating a `scope` and then
  discarding it let `{"scope":"tag:canary"}` widen to every non-compliant agent — the same defect
  arriving through the guard added to stop it.

- **Behaviour change: `agent_ids` and `scope` are now exclusive.** Supplying both returns `400`
  on `POST /api/command`, `POST /api/instructions/{id}/execute` and MCP `execute_instruction`.
  They previously resolved by precedence — the scope won and the explicit id list was silently
  discarded, so `{"agent_ids":["dev-a"],"scope":"tag:prod"}` ran on every device matching
  `tag:prod`. Supply exactly one, or neither. The single exception is `"scope": "__all__"`
  alongside `agent_ids`, where the explicit list wins: `__all__` is the broadcast request rather
  than a narrowing selector.

- Refusals are observable: `yuzu_server_dispatch_target_rejected_total{route,reason}` (both
  labels closed sets, every pair pre-seeded at boot) plus an audit row —
  `command.dispatch|denied` or `instruction.execute|denied` with `detail=reason=<reason>`. A
  non-zero rate means a client believes it is targeting specific devices and is not.
