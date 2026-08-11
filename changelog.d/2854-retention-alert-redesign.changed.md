- **The audit-retention liveness alerts were redesigned on the restart-surviving
  last-pass stamp (#2854 rung D).** `YuzuAuditRetentionNotRunning` now excuses
  exactly one state — a last-pass stamp of `0`, a database no retention pass has
  ever run against — instead of the young-server uptime grace, and a new
  `YuzuAuditRetentionNeverRan` alert owns that excused state (stamp still `0`
  after 3 hours). **Two firings will be new to you.** First, the old grace's
  measured blind band is closed: a dead reaper at a 164–195 minute restart
  cadence (and the wider intermittent band from ~90 minutes) now pages instead
  of staying silent or flapping — coverage is machine-measured at zero uncovered
  cadences (`tests/prometheus/blind_band_manifest.json`, checked on every PR).
  Second, a **true positive the old grace hid**: a server crash-looping faster
  than the 60-minute first-pass sleep, on a database that has run before, now
  fires — the reaper genuinely completes zero passes there; that page is
  correct, not a regression. `YuzuAuditRetentionNotRunning` also no longer
  resolves while the reaper stays dead, so a RESOLVED notification now normally
  evidences recovery (still confirm `yuzu_server_audit_retention_passes_total`
  rising after a Prometheus restart, which can false-page for ~45 minutes —
  unchanged). **`YuzuAuditRetentionNeverRan` is a new alertname: give it an
  Alertmanager route**, or it lands wherever your catch-all sends unrouted
  warnings. The rules file is applied by operators — a deployment that does not
  re-apply `docs/prometheus/yuzu-alerts.yml` keeps the old blind rule and never
  gains the new alert.
