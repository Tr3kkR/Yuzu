- **API parity ledger: 6 fragment rows corrected from `planned:#2146` to `composed-of:...` (#2146).**
  A source-verified pass found several `docs/api-parity-ledger.md` rows mismarked as
  needing independent REST/MCP twinning when they are actually pure UI compositions of
  data an existing, already-`twinned` row already exposes: the execution summary legacy
  route (`get.api-executions-param-summary` → `get.fragments-executions-param-detail`),
  the instructions list and editor fragments (`get.fragments-instructions` →
  `get.api-instructions`; `get.fragments-instructions-editor` → `get.api-instructions-param`),
  the `/auto` VERIFY config fragment (`get.fragments-auto-verify` →
  `get.fragments-settings-management-groups`), and the inventory software-search form and
  results fragments (`get.fragments-inventory-find` and `get.fragments-inventory-find-results`
  → `get.fragments-inventory-software`). No behavior changes; the ratchet baseline
  (`BASELINE_UNTWINNED = 213`) is unaffected since `composed-of` rows count as untwinned
  identically to `planned` rows. A further 7 rows the same pass looked at (2
  access-reviews, 2 result-sets, `/auto` VERIFY compare, network overview, scope-list)
  were left `planned:#2146` on purpose: their underlying REST/MCP capability is real and
  independently verified against source, but has no existing ledger row of its own to
  cite as a `composed-of` target (a v1-native capability with no legacy/fragment
  predecessor) - correctly reclassifying those needs a ledger-baseline change (new
  `twinned` rows with populated twin fields, lowering `BASELINE_UNTWINNED`), which is
  deliberately out of scope for this pass and left as a follow-up.
