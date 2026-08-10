- **New `YuzuServerRestartLoop` alert detects a crash-looping server on its own.**
  Previously the only restart-frequency signal in the alert family was a silent
  grace-exclusion buried inside `YuzuAuditRetentionNotRunning`
  (`resets(yuzu_server_uptime_seconds[3h]) <= 1`), so a crash loop was only ever
  detected as a side effect of retention detection, never in its own right (#2854).
  The new rule fires on `resets(yuzu_server_uptime_seconds[3h]) > 3`
  (`for: 15m`, `severity: warning`) — a 30-minute restart cadence trips it, an
  install followed by a couple of config-fix restarts or a steady hourly restart
  cadence does not. **Operators wiring Alertmanager routing need to add this
  alertname** alongside the existing `yuzu-audit` group rules; see
  [`ops-runbooks/audit-store-clock-guard.md`](docs/ops-runbooks/audit-store-clock-guard.md#yuzuserverrestartloop)
  for triage. Like the retention grace it was extracted from, it needs one
  continuous `instance`-labelled series per server to detect restarts at all —
  see the derivation comment above the rule in `docs/prometheus/yuzu-alerts.yml`. (#2854)
