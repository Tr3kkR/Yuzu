- **New `yuzu-ota` alert group covers the agent OTA pull bounds.** The bounds and
  their metrics shipped in #3826 (#913, #911); the rules that page on them ship
  here. Seven alerts cover per-peer and server-wide admission rejections,
  identity rejections, deadline aborts, admission-map eviction and capacity, and
  refund divergence. Two of those conditions are otherwise silent by
  construction: a deadline-aborted transfer refunds its rate token, so no bucket
  drains and every other dashboard stays green while the fleet stops updating,
  and admission-map eviction disables the rate dimension without any error
  because an evicted key is re-minted with a full burst. **Operators wiring
  Alertmanager routing need to add these alertnames** alongside the existing
  groups; six are `severity: warning` and `YuzuOtaPeerMapNearCapacity` is
  `severity: info` (a precursor signal, not a live fault). Triage steps for each
  are in the *Agent OTA pull bounds → Alert responses* table in
  [`server-admin.md`](docs/user-manual/server-admin.md#agent-ota-pull-bounds).
  **The thresholds are reasoned starting points, not fleet-validated numbers** —
  each rule's annotation records what its bar was chosen against and where it is
  known to be blind, and `YuzuOtaTransfersAborting` in particular fires on a
  PROPORTION of transfers aborting rather than a count, because agents check only
  every six hours and any fixed count goes blind below some fleet size. Expect to
  tune them. (#3837)
