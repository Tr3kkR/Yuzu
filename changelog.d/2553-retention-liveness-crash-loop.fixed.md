- **The `YuzuAuditRetentionNotRunning` alert could not fire for a crash-looping
  server** — one of the leading causes of the condition it exists to detect. The
  rule excused a server whose `yuzu_server_uptime_seconds` was under a 3-hour
  grace, because `run_cleanup` sleeps a full interval before its first pass and a
  freshly started server legitimately has no pass yet. A process restarting more
  often than that window never accumulates uptime past the grace, so the guard
  excluded it on every evaluation and a reaper completing zero passes stayed
  silent. The grace now excuses a young server only while its uptime has at most
  one reset across the window (`resets(yuzu_server_uptime_seconds[3h]) <= 1`) —
  one restart is an ordinary install-then-config-fix, while completing zero
  passes at the 60-minute default needs at least three. It is expressed with
  `unless` so a missing uptime series cannot silence the rule either. **Expect a
  new-to-you firing on any crash-looping server.** Known limit, documented on the
  rule: if a restart changes the `instance` label (dynamic-port or IP-based
  service discovery, a rescheduled pod) each restart starts a fresh series and the
  grace applies forever — the fix is scrape config targeting a stable identity.
- **Prometheus alert rules now have unit tests**, in
  `tests/prometheus/yuzu-alerts.test.yml`, run under `promtool` by the `docs-lint`
  CI workflow's own `prometheus-rules` job (`check rules` for the parse, `test
  rules` for the behaviour). Nothing previously validated this file at all, which
  is why a rule that parsed perfectly and could never fire went unnoticed. The
  crash-loop case is red against the previous form, and so is the single-restart
  case against a stricter grace. `meson test --suite docs` runs the same cases
  where a promtool is available — it needs a native promtool of the pinned major
  or an explicit `YUZU_TEST_ENABLE_PROMTOOL_DOCKER=1`, and skips otherwise, so no
  build leg gains a container-registry dependency.
