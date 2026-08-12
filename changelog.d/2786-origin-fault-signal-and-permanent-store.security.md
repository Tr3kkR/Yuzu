- **A store fault at the exact moment an MCP approval recall checks a ticket's minting
  surface no longer silently swallows the forgery-detection signal (#2786 arm 1).** If the
  SQLite read backing the #2442 cross-surface origin check failed, the refusal reported as a
  plain store error and the comparison that would have caught a foreign-origin ticket never
  ran, so a cross-surface forgery attempt coinciding with the fault was indistinguishable from
  ordinary store contention — and store contention is influenceable from the same
  authenticated MCP session. The refusal is still fail-closed (nothing is redeemed either
  way), but the site is now distinguishable: a new
  `yuzu_mcp_approval_masked_denials_total{tool}` counter and an ` (origin/submitter unverified)` /
  ` (lookup)` audit-detail suffix mark a refusal where the origin
  comparison could not run, and `ApprovalManager` logs a warning at the fault site itself so
  every `consume_ticket` caller gets the signal, not only the MCP recall. The ticket remains
  approved and redeemable once the fault clears. (The suffix also covers this same release's
  submitter comparison, added to the same read — see the submitter-binding entry.)
- **An approval store that is open but failing permanently (corruption, not-a-database,
  read-only, disk full) no longer tells the caller to retry forever.** The MCP recall's
  store-fault response previously discriminated permanent from transient failures solely by
  whether the store handle was open, so a degraded-but-open store took the transient arm and
  was told "retry this call unchanged" on every attempt — each one also writing an audit row
  onto the substrate already failing to serve it. The response now also classifies the SQLite
  extended error code and routes the four permanent-shaped failures to the same
  operator-escalation body a never-opened store gets.
