- Audit retention no longer trusts the server's wall clock. The hourly cleanup pass
  was a blind `DELETE FROM audit_events WHERE ttl_expires_at < now`, so a single
  forward clock step (restored VM snapshot, NTP correction after a dead CMOS
  battery, a hand-set date) could empty the SOC 2 evidence table in one statement
  with no counter and no actionable log line. A pass now declines once, latched,
  when it would expire every datable row, when the gap since the previous pass
  exceeds a fixed 7 days (an absolute threshold, deliberately NOT scaled to
  `--audit-retention-days`: at the 365-day default that would put it a year out,
  where it could never fire), or when the stored reading is ahead of
  the current clock. That reading is persisted and sanitised, so the check still
  fires on a server that BOOTED with an already-wrong clock and cannot be
  disabled by a poisoned value. Every accepted pass is capped at 25,000 rows
  oldest-first. Rows whose TTL sits
  implausibly far in the future are excluded from the decision, so one
  forward-skewed row cannot disarm the guard. The cap is the half that always
  applies; the detectors are best effort, so this converts an instantaneous wipe
  into a paced one plus an operator signal rather than preventing every anomaly.
  Six metrics report it: `yuzu_server_audit_clock_anomaly_skips_total` (declined),
  `yuzu_server_audit_cleanup_failed_total` (errored or store closed),
  `yuzu_server_audit_retention_cap_reached_total` (the backlog is not draining),
  `yuzu_server_audit_rows_deleted_total`, `yuzu_server_audit_retention_index_ok`
  and `yuzu_server_audit_retention_persist_failed_total`. All are counters except
  `retention_index_ok`, which is a gauge. All but `rows_deleted_total` ship with a
  Prometheus alert rule. A
  partial index on `audit_events(ttl_expires_at, id)` keeps the pass index-driven;
  it is built best-effort outside the migration runner, so a failure to create it
  degrades retention to full scans instead of taking the audit trail offline.

- **Behaviour change:** audit retention is now a floor, not a ceiling. Expired rows
  age out at up to 25,000 per hourly pass instead of all at once, so a large backlog
  clears over hours rather than in a single statement. (Reducing
  `--audit-retention-days` never expired existing rows in the first place --
  `ttl_expires_at` is stamped at INSERT and is never rewritten -- so a reduction
  still does not reclaim disk retroactively.)
