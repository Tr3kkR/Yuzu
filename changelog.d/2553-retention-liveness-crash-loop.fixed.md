- **The `YuzuAuditRetentionNotRunning` alert could not fire for a crash-looping
  server** — one of the leading causes of the condition it exists to detect. The
  rule excused any server whose `yuzu_server_uptime_seconds` was under a 3-hour
  grace, and a process restarting more often than that never accumulates uptime
  past it, so a reaper completing zero passes stayed silent on every evaluation.
  Fixed first by narrowing the grace to at-most-one-reset (measured then as
  narrowed, not closed — still blind at 164–195 minute restart cadences), and
  superseded **in this same release** by the #2854 rung D redesign, which
  replaces the uptime grace entirely with the restart-surviving last-pass stamp
  and closes the measured blind band — see the `2854-retention-alert-redesign`
  entry for the rule pair that actually ships and the new-to-you firings to
  expect.
- **The same alert could be silenced by an unrelated server.** The rule joined its
  two operands with an explicit `on(instance)`, so any other series that merely
  shared an `instance` value — a canary, an HA pair, a federated series — was
  allowed to stand in for a broken server's grace operand and suppress its alert.
  Both operands come from the same scrape target, so the join now uses PromQL's
  default all-label matching, which is what every other cross-metric rule in
  `docs/prometheus/yuzu-alerts.yml` already does.
