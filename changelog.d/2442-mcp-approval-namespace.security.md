- **Breaking — an approval ticket can no longer be redeemed on a surface other than the one that
  minted it *where that surface is recorded*, and the `mcp.` instruction-definition id prefix is
  reserved for new definitions.** Approvals are one
  shared store with three mint paths, and the MCP approval recall matches a ticket on its definition
  id and scope expression without binding the submitter or the minting surface — so an approval
  raised through the REST instruction gate, where both of those fields are caller-influenced, could
  line up with an MCP tool's canonical arguments and be redeemed against it.

  What that bought an attacker was **the human approval itself**, not a new permission: an
  administrator reviewing that ticket in the approvals queue sees a ticket id, a submitter and a
  scope expression — nothing that names the tool or the surface — so they would have been
  authorising an MCP tool invocation with no way to tell. The schema check, the tier gate and
  per-handler RBAC all still applied, but those constrain the attacker's own principal and would
  have been satisfied anyway. It required an instruction definition to already exist under the
  `mcp.` prefix, with an approval mode other than `auto`, and a scope expression byte-equal to the
  tool's canonical arguments — which is what kept it narrow.

  Every approval now records its minting surface, and the recall refuses any ticket whose
  **recorded** surface is something other than MCP. A ticket with no recorded surface is exempt —
  see the last paragraph. The refusal is deliberately indistinguishable from an ordinary
  spent-ticket response, so the recall cannot be used to probe which definition ids exist.

  **This binds the surface, not the submitter.** The recall still does not compare who obtained the
  approval against who presents it, so a valid `approval_id` remains redeemable by any principal
  that also passes the tier gate and the tool's own RBAC — and `GET /api/approvals` returns approval
  ids in full to any `Approval:Read` holder, which the seeded Viewer role has. Treat an
  `approval_id` as a secret. Both halves are tracked: #2442 stays open for the submitter binding,
  #1803 for the read exposure.

  **Alerting.** A cross-surface redemption attempt increments
  `yuzu_mcp_approval_forgery_total{tool,event="security"}` — the SIEM-routed family, and the one to
  alert on — alongside `yuzu_mcp_approval_denied_total{reason="foreign_origin"}`, and records an
  `mcp.<tool>` / `denied` audit row. Both are pre-seeded to zero for every approval-gated tool, and
  the registry resets on restart, so alert on `increase(...)` rather than a bare `> 0`. Neither
  counter fires for the unlabelled carried-across tickets described below — those are exempt from
  the check, not refused by it.

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
  tickets are still redeemable. Carried-across rows clear on the existing 7-day approval expiry —
  but that sweep is **lazy**, running only when an approval is submitted, so a queue receiving no
  new submissions does not age anything out. **There is no supported way to close the window
  early**: the redeemable rows are `approved` and unconsumed, and the reject route refuses anything
  that is not still `pending`, so rejecting the pending tickets destroys legitimate un-reviewed
  requests without touching a single redeemable one. In almost every deployment no action is needed
  — see `docs/user-manual/server-admin.md`, which explains why an early-closure procedure is not
  published and what to do if you have specific reason to think you are affected. The exemption
  itself closes when the MCP mint declares its own surface.
