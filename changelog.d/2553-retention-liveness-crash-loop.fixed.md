- **The `YuzuAuditRetentionNotRunning` alert could not fire for a crash-looping
  server** — one of the leading causes of the condition it exists to detect. The
  rule excused a server whose `yuzu_server_uptime_seconds` was under a 3-hour
  grace, because `run_cleanup` sleeps a full interval before its first pass and a
  freshly started server legitimately has no pass yet. A process restarting more
  often than that window never accumulates uptime past the grace, so the guard
  excluded it on every evaluation and a reaper completing zero passes stayed
  silent. The grace now excuses a young server only while its uptime has at most
  one reset across the window — one restart is an ordinary
  install-then-config-fix, while completing zero passes at the 60-minute default
  needs at least three. It is expressed with `unless` so a missing uptime series
  cannot silence the rule either. **Expect a new-to-you firing on any
  crash-looping server.** Known limit, documented on the rule: `resets()` needs a
  continuous series per server, so if a restart changes the `instance` label
  (dynamic-port or IP-based service discovery, a rescheduled pod) the grace still
  applies forever — the fix is scrape config targeting a stable identity.
- **The same alert could be silenced by an unrelated server.** The rule joined its
  two operands with an explicit `on(instance)`, so any other young, reset-free
  `yuzu_server_uptime_seconds` series that merely shared an `instance` value — a
  canary, an HA pair, a federated series — was allowed to stand in for a broken
  server's uptime and suppress its alert. Both operands come from the same scrape
  target, so the join now uses PromQL's default all-label matching, which is what
  every other cross-metric rule in `docs/prometheus/yuzu-alerts.yml` already does.
