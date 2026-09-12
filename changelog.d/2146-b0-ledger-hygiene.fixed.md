- **API parity ledger: 3 rows corrected from `planned:#2146` to `composed-of:...` (#2146).**
  A source-verified pass found several rows in `scripts/ci/api-parity/*.json` mismarked as
  needing independent REST/MCP twinning when they are actually pure UI compositions of data
  an existing, already-`twinned` row already exposes, with a matching authorization gate: the
  execution summary legacy route (`get.api-executions-param-summary` ->
  `get.fragments-executions-param-detail`, both `Execution:Read`) and the inventory
  software-search form and results fragments (`get.fragments-inventory-find` and
  `get.fragments-inventory-find-results` -> `get.fragments-inventory-software`, both
  `Inventory:Read`, the `find-results` fragment if anything stricter). No behavior changes;
  the ratchet baseline (`BASELINE_UNTWINNED = 213`) is unaffected since `composed-of` rows
  count as untwinned identically to `planned` rows.

  **Revised after review:** the `/auto` VERIFY config fragment
  (`get.fragments-auto-verify`, gated `Infrastructure:Read`) and the instructions list and
  editor fragments (`get.fragments-instructions`, gated bare-auth-only; `get.fragments-
  instructions-editor`, gated `InstructionDefinition:Write`) were reverted to
  `planned:#2146` rather than flipped to `composed-of` — their cited targets
  (`ManagementGroup:Read` and `InstructionDefinition:Read` respectively) are gated by a
  *stricter or independent* securable than the fragment itself, so a role holding the
  fragment's narrower grant could be denied by the "twin" the ledger would otherwise claim
  covers it. Composing the same *data* is not sufficient for a `composed-of` claim — the
  target's authorization gate must be no stricter than the original fragment's, or the
  claim silently forecloses the work of building a properly-gated twin for a real gap in
  reachability.
