- TAR time-based retention no longer trusts the endpoint clock. A rollup tick issued
  an unbounded `DELETE FROM <table> WHERE <ts_col> < <cutoff>` per warehouse table,
  with the cutoff derived from the endpoint's own wall clock -- the clock in a fleet
  most likely to be wrong (dead CMOS battery, long suspend, cloned VM, boot before
  NTP converges). One bad reading took the device's whole forensic window with it.
  A pass now declines once per table, latched, when it would delete every datable
  row, when the gap since the previous pass exceeds a threshold (that table's window,
  floored at 30 days so a switched-off laptop is not reported as a clock anomaly), or
  when the stored reading is ahead of the clock. That reading is persisted in
  `tar_config` and sanitised, so it still fires after an agent restart and cannot be
  disabled by a poisoned value. Every accepted delete is capped at 5,000 rows per
  table per pass, oldest first. The floor leaves a deliberate dead band: a forward
  error between a table's own window and 30 days trips neither detector, and the cap
  alone bounds it. Rows stamped implausibly far in the future are excluded so one
  forward-skewed row cannot disarm the guard. Row-count retention is deliberately
  untouched (it trims to a fixed ceiling with no clock involved) and still shares the
  single retention transaction, which now also rolls back rather than leaving the
  shared connection wedged if a pass throws. The existing paused/errored source gate
  still runs first, so a source paused for forensics neither deletes nor reports an
  anomaly. Because the agent has no `/metrics` endpoint, the counters are surfaced
  through the `tar status` action as `retention_guard_declines_total` and
  `retention_guard_failures_total`, plus per-table `retention_guard|<table>|<n>` and
  `retention_guard_failed|<table>|<n>` lines (probe and delete failures merged); the
  two totals must be read together, since a table whose probes or deletes fail every
  pass has silently stopped being retained.
