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
  otherwise, so no build leg gains a container-registry dependency.
