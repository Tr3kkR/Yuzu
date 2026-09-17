- **macOS quarantine now verifies pf is actually enabled, not just that the
  ruleset loaded (#3283).** `pfctl -e` can exit zero without pf coming up —
  a stock macOS host ships pf disabled — so a quarantine could previously
  report success while blocking nothing. `quarantine` and `whitelist` now
  issue a follow-up `pfctl -s info` read after every enable step and fold a
  failed confirmation into the same partial-status path as an outright
  `pfctl -e` failure: `status|quarantined_partial` (was silently reported
  as `status|quarantined`), with a note that traffic may not actually be
  blocked. `status` reads the same live signal: a blocking ruleset with pf
  disabled now reports `state|degraded`, and an unreadable pf status
  reports `state|uncertain` — never the previous unconditional `active`.
