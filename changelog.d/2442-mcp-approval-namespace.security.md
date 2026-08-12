- **Breaking — the `mcp.` instruction-definition id prefix is now reserved, and every approval
  records the surface that minted it.** Approvals are one shared store with three mint paths, and the
  MCP recall matches a ticket on its definition id and scope expression without binding the submitter
  — so an approval raised through the REST instruction gate, where both of those are
  caller-influenced, could line up with an MCP tool's canonical arguments. Any such consume still had
  to pass the schema check, the tier gate, per-handler RBAC and a human approval, so this was
  namespace hygiene rather than an open escalation. The authoring half is closed: an instruction definition
  can no longer be authored under the prefix. The redemption half is closed separately, and at
  redemption rather than at mint — see the cross-surface binding entry. The approval store
  deliberately does NOT refuse a prefixed mint: doing so permanently stopped schedules on
  definitions that already carried such an id.

  **What breaks:** creating or importing a definition whose id starts `mcp.` is now refused with a
  400 on every authoring route that accepts an explicit id (`POST /api/instructions`,
  `/api/instructions/yaml`, `/api/instructions/import`), and such a definition is skipped at boot
  auto-import. Product-pack install is unaffected — it never carries a declared id through. No
  shipped content uses the prefix. The store applies the rule at create time, so a definition that
  already exists under it keeps working and can still be saved through `PUT`; the dashboard's YAML
  editor is stricter and refuses it on every save. Rename such a definition before upgrading — see
  the upgrade note in `docs/user-manual/server-admin.md` for a query that finds them.

  The minting surface is recorded with each approval; at the time of this release the MCP mint
  itself is unlabelled until its own follow-up lands, and an unlabelled ticket stays redeemable
  until then — that exemption is what keeps the MCP gate working in the meantime (a later release
  closes it, see the "MCP mint now declares its own surface" entry). Rows predating the column are
  NOT left unlabelled: unlabelled is the value that grants at this point, so they are back-filled
  to a sentinel that claims no surface and fails closed. The column is read at redemption — see the
  cross-surface binding entry.
