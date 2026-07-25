- TAR time-based retention no longer trusts the endpoint clock. A rollup tick issued
  an unbounded `DELETE FROM <table> WHERE <ts_col> < <cutoff>` per warehouse table,
  with the cutoff derived from the endpoint's own wall clock -- the clock in a fleet
  most likely to be wrong (dead CMOS battery, long suspend, cloned VM, boot before
  NTP converges). One bad reading took the device's whole forensic window with it.
  A pass now declines once per table, latched, when it would delete every datable
  row or when more than that table's retention window has elapsed since the previous
  pass -- that reading is persisted in `tar_config`, so it still fires after an agent
  restart -- and every accepted delete is capped at 5,000 rows per table per pass,
  oldest first. Rows stamped implausibly far in the future are excluded so one
  forward-skewed row cannot disarm the guard. Row-count retention is deliberately
  untouched (it trims to a fixed ceiling with no clock involved) and still shares the
  single retention transaction, which now also rolls back rather than leaving the
  shared connection wedged if a pass throws. The existing paused/errored source gate
  still runs first, so a source paused for forensics neither deletes nor reports an
  anomaly. Because the agent has no `/metrics` endpoint, the counters are surfaced
  through the `tar status` action as `retention_guard_declines_total` and
  `retention_guard_failures_total`, plus per-table `retention_guard|<table>|<n>` and
  `retention_guard_failed|<table>|<n>` lines; the two totals must be read together,
  since a table whose probes fail every pass has silently stopped being retained.
