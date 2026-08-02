- **The `mcp.` approval-ticket namespace is now reserved, and every ticket records the
  surface that minted it.** Approvals are one shared store with three mint paths, and the
  MCP recall matches a ticket on its definition id and scope expression without binding
  the submitter — so an approval raised through the REST instruction gate, where both of
  those are caller-influenced, could line up with an MCP tool's canonical arguments. Any
  such consume still had to pass the schema check, the tier gate, per-handler RBAC and a
  human approval, so this was namespace hygiene rather than an open escalation. Both
  halves are now closed: a mint that declares a non-MCP origin is refused the `mcp.`
  prefix, and an instruction definition can no longer be authored under it at all. The
  minting surface is persisted with each approval as evidence; rows predating the column
  are left unlabelled rather than assigned a surface they may not have come from.
