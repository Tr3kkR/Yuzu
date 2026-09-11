- **API parity ledger: 6 rows corrected from `planned:#2146` to `composed-of:...` (#2146).**
  A source-verified pass found several `docs/api-parity-ledger.md` rows mismarked as
  needing independent REST/MCP twinning when they are actually pure UI compositions of
  data an existing, already-`twinned` row already exposes: the execution summary legacy
  route (`get.api-executions-param-summary` -> `get.fragments-executions-param-detail`),
  the instructions list and editor fragments (`get.fragments-instructions` ->
  `get.api-instructions`; `get.fragments-instructions-editor` -> `get.api-instructions-param`),
  the `/auto` VERIFY config fragment (`get.fragments-auto-verify` ->
  `get.fragments-settings-management-groups`), and the inventory software-search form and
  results fragments (`get.fragments-inventory-find` and `get.fragments-inventory-find-results`
  -> `get.fragments-inventory-software`). No behavior changes; the ratchet baseline
  (`BASELINE_UNTWINNED = 213`) is unaffected since `composed-of` rows count as untwinned
  identically to `planned` rows.
