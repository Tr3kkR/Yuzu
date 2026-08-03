- **Breaking — the `mcp.` instruction-definition id prefix is now reserved, and every approval
  records the surface that minted it.** Approvals are one shared store with three mint paths, and the
  MCP recall matches a ticket on its definition id and scope expression without binding the submitter
  — so an approval raised through the REST instruction gate, where both of those are
  caller-influenced, could line up with an MCP tool's canonical arguments. Any such consume still had
  to pass the schema check, the tier gate, per-handler RBAC and a human approval, so this was
  namespace hygiene rather than an open escalation. Both halves are now closed: a mint that declares a
  non-MCP origin is refused the prefix, and an instruction definition can no longer be authored under
  it.

  **What breaks:** creating or importing a definition whose id starts `mcp.` is now refused with a
  400 on every authoring route that accepts an explicit id (`POST /api/instructions`,
  `/api/instructions/yaml`, `/api/instructions/import`), and such a definition is skipped at boot
  auto-import. Product-pack install is unaffected — it never carries a declared id through. No
  shipped content uses the prefix.

  A definition that already exists under the prefix and is **approval-gated also stops running**,
  on the REST execute route, the dashboard and the scheduler: the mint declares an origin, the
  reservation refuses it, and the run fails closed — with a 400 naming the prefix on the two
  request paths, and a dropped occurrence on the scheduler. A run is
  approval-gated if the definition's `approval_mode` is not `auto` OR the schedule carries its own
  `requires_approval`, so an `auto` definition on a gated schedule is affected too. **The scheduled
  case fails silently and permanently** — occurrences are dropped rather than retried while the
  schedule still shows as enabled and advertises a next run it can never make, and nothing
  self-corrects. MCP is unaffected (`execute_instruction` takes a plugin and action, not a
  definition id). Rename affected definitions before upgrading — `docs/user-manual/server-admin.md`
  carries the queries that find them and the order to rename in, which matters because deleting a
  definition does not re-point the schedules that reference it.

  The minting surface is recorded with each approval; rows predating the column are left unlabelled
  rather than assigned a surface they may not have come from, and the MCP mint itself is unlabelled
  until its own follow-up lands. Nothing reads the column yet.
