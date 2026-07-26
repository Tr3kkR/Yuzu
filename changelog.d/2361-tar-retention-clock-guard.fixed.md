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
  forward-skewed row cannot disarm the guard. Row-count retention keeps its
  clock-free ceiling semantics, but is now capped per pass too -- the whole batch runs
  under one held database mutex, so an uncapped prune over a large backlog would stall
  every collector on the endpoint; a big excess now drains over a few ticks instead.
  The retention transaction stops at the first failed statement and rolls back rather
  than letting later deletes escape as autocommits after SQLite has already aborted it.
  If the rollback itself fails with the transaction still open, the TAR database is
  CLOSED: every subsequent write would be reported durable and then lost, so all of
  them fail closed instead, and `tar status` reports `storage_state|offline` until the
  agent restarts. The existing paused/errored source gate
  still runs first, so a source paused for forensics neither deletes nor reports an
  anomaly. Because the agent has no `/metrics` endpoint, the counters are surfaced
  through the `tar status` action as `retention_guard_declines_total` and
  `retention_guard_failures_total`, plus per-table `retention_guard|<table>|<n>` and
  `retention_guard_failed|<table>|<n>` lines (probe and delete failures merged); the
  two totals must be read together, since a table whose probes or deletes fail every
  pass has silently stopped being retained.
