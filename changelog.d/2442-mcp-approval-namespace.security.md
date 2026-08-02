- **Breaking — the `mcp.` instruction-definition id prefix is now reserved, and every approval
  records the surface that minted it.** Approvals are one shared store with three mint paths, and the
  MCP recall matches a ticket on its definition id and scope expression without binding the submitter
  — so an approval raised through the REST instruction gate, where both of those are
  caller-influenced, could line up with an MCP tool's canonical arguments. Any such consume still had
  to pass the schema check, the tier gate, per-handler RBAC and a human approval, so this was
  namespace hygiene rather than an open escalation. Both halves are now closed: a mint that declares a
  non-MCP origin is refused the prefix, and an instruction definition can no longer be authored under
  it.

  **What breaks:** creating, importing, or reinstalling a definition whose id starts `mcp.` is now
  refused with a 400 on every authoring route (`POST /api/instructions`, `/api/instructions/yaml`,
  `/api/instructions/import`, product-pack install) and skipped at boot auto-import. No shipped
  content uses the prefix. The rule is create-time only, so a definition that already exists under it
  keeps working and stays editable — but re-importing an export of one will fail. Rename such a
  definition before upgrading.

  The minting surface is recorded with each approval; rows predating the column are left unlabelled
  rather than assigned a surface they may not have come from, and the MCP mint itself is unlabelled
  until its own follow-up lands. Nothing reads the column yet.
