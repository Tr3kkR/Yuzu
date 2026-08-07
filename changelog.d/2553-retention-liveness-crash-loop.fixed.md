- **The `YuzuAuditRetentionNotRunning` alert could not fire for a crash-looping
  server** — one of the leading causes of the condition it exists to detect. The
  rule excused a server whose `yuzu_server_uptime_seconds` was under a 3-hour
  grace, because `run_cleanup` sleeps a full interval before its first pass and a
  freshly started server legitimately has no pass yet. A process restarting more
  often than that window never accumulates uptime past the grace, so the guard
  excluded it on every evaluation and a reaper completing zero passes stayed
  silent. The grace now excuses a young server only while its uptime has at most
  one reset across the window — one restart is an ordinary
  install-then-config-fix. It is expressed with `unless` so a missing uptime
  series cannot silence the rule either. **Expect a new-to-you firing on any
  crash-looping server.** **Narrowed, not closed:** the previous expression
  required `uptime > 10800` outright and was blind at every restart cadence below
  about 195 minutes; this one is still blind at cadences of roughly 160–195
  minutes, and that band moves with the Prometheus evaluation interval (measured
  164–195 at a 1-minute interval, 160–195 at 5). Closing it needs a server-side
  change rather than a rule change — the natural signal,
  `yuzu_server_audit_retention_last_pass_unixtime`, is not reloaded from its
  persisted anchor at startup, so a freshness rule built on it regresses the very
  crash-loop case this fix addresses. Two further known limits: `resets()` needs a
  continuous series per server, so if a restart changes the `instance` label
  (dynamic-port or IP-based service discovery, a rescheduled pod) the grace still
  applies forever — the fix is scrape config targeting a stable identity; and on a
  still-dead reaper the alert can resolve and re-fire, so treat a resolution as
  recovery only once a pass has actually landed.
- **The same alert could be silenced by an unrelated server.** The rule joined its
  two operands with an explicit `on(instance)`, so any other young, reset-free
  `yuzu_server_uptime_seconds` series that merely shared an `instance` value — a
  canary, an HA pair, a federated series — was allowed to stand in for a broken
  server's uptime and suppress its alert. Both operands come from the same scrape
  target, so the join now uses PromQL's default all-label matching, which is what
  every other cross-metric rule in `docs/prometheus/yuzu-alerts.yml` already does.
