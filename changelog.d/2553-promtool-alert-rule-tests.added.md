- **Prometheus alert rules now have unit tests**, in
  `tests/prometheus/yuzu-alerts.test.yml`, run under `promtool` by the `docs-lint`
  workflow's own `prometheus-rules` job (`check rules` for the parse, `test rules`
  for the behaviour). Nothing previously validated this file at all, which is why
  a rule that parsed perfectly and could never fire went unnoticed. The cases pin
  both the shape and the magnitude of `YuzuAuditRetentionNotRunning`: each of its
  windows, thresholds, the `for` duration, the absent-series arm and the label
  join is red against a mutation of itself. `meson test --suite docs` runs the
  same script wherever a promtool is available — it needs a native promtool of the
  pinned major or an explicit `YUZU_TEST_ENABLE_PROMTOOL_DOCKER=1`, and skips
  otherwise, so no build leg gains a container-registry dependency. Note the gate
  is parse-only for the other rules: nothing yet enforces that a rule change
  ships a case.
- **New `YuzuAuditRetentionMetricMissing` alert.** `YuzuAuditRetentionNotRunning`
  cannot detect its own input going missing — `increase()` over a metric with no
  series is an empty vector, so a Prometheus holding these rules against a server
  that does not export `yuzu_server_audit_retention_passes_total` reported healthy
  forever while the audit reaper was entirely unmonitored. Since the rules file is
  a copy operators apply themselves, it routinely runs ahead of the servers it
  points at. The new rule fires on `absent(...)` after 15m. It is fleet-wide by
  construction: it cannot see one server among many going quiet, which needs a
  `up`-based target-down alert instead.
