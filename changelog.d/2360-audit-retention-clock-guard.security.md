- Audit retention no longer trusts the server's wall clock. The hourly cleanup pass
  was a blind `DELETE FROM audit_events WHERE ttl_expires_at < now`, so a single
  forward clock step (restored VM snapshot, NTP correction after a dead CMOS
  battery, a hand-set date) emptied the SOC 2 evidence table in one statement with
  no counter and no actionable log line. A pass now declines once, latched, when it
  would expire every datable row or when more than a whole retention window has
  elapsed since the previous pass, and every accepted pass is capped at 25,000 rows
  oldest-first so a wipe the guard allows ages out at a paced rate. Rows whose TTL
  sits implausibly far in the future are excluded from the decision, so one
  forward-skewed row cannot disarm the guard. Two new counters,
  `yuzu_server_audit_clock_anomaly_skips_total` (declined) and
  `yuzu_server_audit_cleanup_failed_total` (errored), report the two ways a pass can
  leave rows behind; both ship with Prometheus alert rules. Adds a partial index on
  `audit_events(ttl_expires_at, id)` (schema v3) so the guarded pass stays
  index-driven under the store lock - expect a one-time index build at first boot
  after upgrade on a large existing audit database.
