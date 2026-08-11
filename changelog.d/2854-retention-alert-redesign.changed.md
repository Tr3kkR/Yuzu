- **Breaking — the audit-retention liveness alerts were redesigned on the
  restart-surviving last-pass stamp, and one alertname is new (#2854 rung D).**
  `YuzuAuditRetentionNotRunning` now excuses exactly one state — a database
  with no genuine pass recorded anywhere in the trailing 3 hours (the stamp
  gauge's highest sample is `0`) — instead of the young-server uptime grace,
  and a new `YuzuAuditRetentionNeverRan` alert owns that excused state (no
  genuine stamp for a further 3 hours; a window mixing `0` seeds with the
  unreadable-anchor sentinel still counts as never-ran, so a crash-looping
  fresh install pages even when its anchor reads intermittently fail).
  **Two firings will be new to you.** First, the old grace's measured blind
  band is closed: a dead reaper at a 164–195 minute restart cadence (and the
  wider intermittent band from ~90 minutes) now pages instead of staying
  silent or flapping — coverage is machine-measured at zero uncovered
  cadences (`tests/prometheus/blind_band_manifest.json`, checked on every
  PR). Second, a **true positive the old grace hid**: a server crash-looping
  faster than the 60-minute first-pass sleep, on a database that has run
  before, now fires — the reaper genuinely completes zero passes there; that
  page is correct, not a regression. `YuzuAuditRetentionNotRunning` also no
  longer resolves while the reaper stays dead, so a RESOLVED notification now
  normally evidences recovery (still confirm
  `yuzu_server_audit_retention_passes_total` rising after a Prometheus
  restart, which can false-page for ~45 minutes — unchanged).
  **`YuzuAuditRetentionNeverRan` is a new alertname: give it an Alertmanager
  route.** Without one it lands wherever your catch-all sends unrouted
  warnings — and a config whose root receiver is a blackhole (`receiver:
  'null'` with exhaustive per-alertname routes, a common shape) drops it
  silently, leaving first-boot store failures unpaged despite a correct rules
  apply. The rules file is applied by operators — a deployment that does not
  re-apply `docs/prometheus/yuzu-alerts.yml` keeps the old blind rule and
  never gains the new alert; during a staged rollout, apply servers first
  (an old, not-yet-upgraded server that restarts reads a `0` stamp on an
  anchored database and pages `YuzuAuditRetentionNeverRan` with a
  fresh-install story that is false for it — see the runbook's rollout note).
