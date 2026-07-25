- TAR time-based retention no longer trusts the endpoint clock. A rollup tick issued an
  unbounded `DELETE FROM <table> WHERE <ts_col> < <cutoff>` per warehouse table, with the
  cutoff derived from the endpoint's own wall clock -- the clock in a fleet most likely to
  be wrong (dead CMOS battery, long suspend, cloned VM, boot before NTP converges). One bad
  reading took the device's whole forensic window with it. A pass now declines once per
  table, latched, when it would delete every datable row or when more than that table's
  retention window has elapsed since the previous pass, and every accepted delete is capped
  at 5,000 rows per table per pass, oldest first. Rows stamped implausibly far in the future
  are excluded from the decision so one forward-skewed row cannot disarm the guard.
  Row-count retention is deliberately untouched (it trims to a fixed ceiling with no clock
  involved), and the existing paused/errored source gate still runs first, so a source
  paused for forensics neither deletes nor reports an anomaly. Because the agent has no
  `/metrics` endpoint, the declines are surfaced through the `tar status` action as
  `retention_guard_declines_total` plus a per-table `retention_guard|<table>|<n>` line, with
  one aggregate warning per pass in the agent log.
