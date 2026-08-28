- **Security — raw dispatch (`POST /api/command`, MCP `execute_instruction`/`execute_bundle`/`quarantine_device`,
  dashboard, workflow, schedules, `/auto` Deploy) now enforces the approval governance an
  `InstructionDefinition` declares, closing a gap where `approval.mode: role-gated`/`always` was
  honored only on the governed `POST /api/instructions/:id/execute` path (#1398).** Every
  dispatchable `plugin.action` pair now carries a compile-time-authored `ExecuteGate`
  (`None`/`AdminOrApproval`/`AlwaysApproval`, derived strictest-wins from shipped content — a
  missing gate on a catalogue row is a **build failure**, never a silent permissive default). A
  non-admin caller with no covering approval is refused `403` on `/api/command` (naming the gate
  and pointing at the governed path) or the existing `no_agents_reached` result on MCP. ~42
  pairs are affected, including every `script_exec.*`/`filesystem.delete`/`registry.set_value`
  action — an `Execution:Execute`-only principal that previously bypassed approval by dispatching
  directly can no longer do so. `permissions.executeRoles` in `InstructionDefinition` YAML is
  retired to advisory-only content (never enforced server-side); actual authorization is the
  compiled pair-level securable/operation plus this new gate. 20 shipped content definitions with
  an invalid `approval.mode` (`manual`/`none`, never a valid value) were corrected to
  `role-gated`/`always`/`auto`; `approval.mode` is now validated at every write path (definition
  create/update/import, and the build-time content embed) against the closed
  `{auto, role-gated, always}` set. **Hardening round (governance Gate 4):** a scheduled fire's
  approval ticket is now bound to the specific `plugin.action` it was approved for, not just the
  definition id — a definition mutated (`PUT /api/instructions/{id}`) between a schedule's ticket
  approval and its next fire no longer redeems stale review for unreviewed, swapped content
  (`ApprovalManager` schema v8, additive `target_plugin`/`target_action` columns compared
  independently rather than a concatenated string, avoiding a collision class 28 shipped
  action names already brush up against).
