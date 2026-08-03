- **An approval ticket can no longer be redeemed on a surface other than the one that minted it, and
  the `mcp.` instruction-definition id prefix is reserved for new definitions.** Approvals are one
  shared store with three mint paths, and the MCP approval recall matches a ticket on its definition
  id and scope expression without binding the submitter or the minting surface — so an approval
  raised through the REST instruction gate, where both of those fields are caller-influenced, could
  line up with an MCP tool's canonical arguments and be redeemed against it.

  What that bought an attacker was **the human approval itself**, not a new permission: an
  administrator who approved what the queue showed as an instruction execution would have
  unknowingly authorised an MCP tool invocation. The schema check, the tier gate and per-handler
  RBAC all still applied, but those constrain the attacker's own principal and would have been
  satisfied anyway. It required an instruction definition to already exist under the `mcp.` prefix,
  which is what kept it narrow.

  Every approval now records its minting surface, and the recall refuses any ticket whose surface is
  not MCP. The refusal is deliberately indistinguishable from an ordinary spent-ticket response, so
  the recall cannot be used to probe which definition ids exist.

  **What changes for operators:** creating or importing a definition whose id starts `mcp.` is
  refused with a 400 on every authoring route that accepts an explicit id (`POST /api/instructions`,
  `/api/instructions/yaml`, `/api/instructions/import`), and such a definition is skipped at boot
  auto-import. Product-pack install is unaffected — it never carries a declared id through. No
  shipped content uses the prefix.

  **A definition that already exists under the prefix keeps working, and needs no action.** It still
  executes, its schedules still fire, and its approval gate still operates as before; the reservation
  applies to authoring only. It can still be saved through `PUT`, though the dashboard's YAML editor
  is stricter and refuses it on every save. Renaming one is optional housekeeping, not an upgrade
  step — and if it carries a schedule, prefer leaving it alone: moving a schedule between definitions
  is not currently supported (#2742).

  Rows predating the surface column are left unlabelled rather than assigned a surface they may not
  have come from, and the MCP mint is itself unlabelled until its own follow-up lands, so unlabelled
  tickets are still redeemable. Those age out on the existing 7-day approval expiry, and the
  exemption closes when the MCP mint declares itself.
