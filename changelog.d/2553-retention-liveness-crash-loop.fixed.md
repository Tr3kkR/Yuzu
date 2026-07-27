- **The `YuzuAuditRetentionNotRunning` alert could not fire for a crash-looping
  server** — one of the leading causes of the condition it exists to detect. The
  rule excused a server whose `yuzu_server_uptime_seconds` was under a 3-hour
  grace, because `run_cleanup` sleeps a full interval before its first pass and a
  freshly started server legitimately has no pass yet. A process restarting more
  often than that window never accumulates uptime past the grace, so the guard
  excluded it on every evaluation and a reaper completing zero passes stayed
  silent. The grace now excuses only a server with ONE uptime segment across the
  window (`resets(yuzu_server_uptime_seconds[3h]) == 0`), and is expressed with
  `unless` so a missing uptime series cannot silence the rule either. Alert rules
  now ship with promtool unit tests (`docs/prometheus/yuzu-alerts.test.yml`) —
  the crash-loop case is red against the previous form.
