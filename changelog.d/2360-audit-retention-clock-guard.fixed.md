- Audit retention no longer trusts the server's wall clock. The hourly cleanup pass
  was a blind `DELETE FROM audit_events WHERE ttl_expires_at < now`, so a single
  forward clock step (restored VM snapshot, NTP correction after a dead CMOS
  battery, a hand-set date) could empty the SOC 2 evidence table in one statement
  with no counter and no actionable log line. A pass now declines once, latched,
  when it would expire every datable row, when the gap since the previous pass
  exceeds a fixed 7 days (an absolute threshold, deliberately NOT scaled to
  `--audit-retention-days`: at the 365-day default that would put it a year out,
  where it could never fire), or when the stored reading is ahead of the current
  clock. That reading is persisted and sanitised, so the check still fires on a
  server that BOOTED with an already-wrong clock, and an out-of-range poisoned
  value (negative, or ahead of the clock) is reported as an anomaly rather than
  quietly accepted. Every accepted pass is capped at 25,000 rows oldest-first. Rows
  whose TTL sits implausibly far in the future are excluded from the decision, so
  one forward-skewed row cannot disarm the guard. The cap is the half that always
  applies; the detectors are best effort, so this converts an instantaneous wipe
  into a paced one plus an operator signal rather than preventing every anomaly.
  Eight metrics report it: `yuzu_server_audit_clock_anomaly_skips_total` (declined),
  `yuzu_server_audit_cleanup_failed_total` (errored or store closed),
  `yuzu_server_audit_retention_cap_reached_total` (the backlog is not draining),
  `yuzu_server_audit_rows_deleted_total`, `yuzu_server_audit_retention_index_ok`,
  `yuzu_server_audit_retention_persist_failed_total`, and the two LIVENESS signals
  `yuzu_server_audit_retention_passes_total` + `..._retention_last_pass_unixtime` --
  every other counter is silence-means-healthy, so these are what distinguish a
  quiet healthy store from a reaper that stopped. All are counters except
  `retention_index_ok` and `retention_last_pass_unixtime`, which are gauges. Six
  Prometheus alert rules ship; `rows_deleted_total` and `retention_last_pass_unixtime`
  are read alongside the others rather than alerted on directly. A partial index on `audit_events(ttl_expires_at, id)`
  keeps the pass index-driven; it is built best-effort outside the migration
  runner, so a failure to create it degrades retention to full scans instead of
  taking the audit trail offline.
