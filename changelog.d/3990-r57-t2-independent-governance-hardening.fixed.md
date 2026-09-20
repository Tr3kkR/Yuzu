- `#3990` R5.7 T2 re-measurement driver: a genuine, independently-dispatched
  full `/governance` pass (11 agents, not self-review) found and fixed a real
  BLOCKING defect in `fullsync_blackout_diag.py`'s post-run reclassification
  sweep - a cross-application fence-violation finding could be silently
  overwritten back to a generic non-confirmation by the sweep's own dispatch
  logic, discarding exactly the signal this instrument exists to surface.
  Independently re-found by three of the eleven agents after two earlier
  self-review passes had incorrectly recorded it as already fixed. Also
  fixed: a concurrent-writer race in the same finalization path that a
  content-blind line-count check could not detect; a `run_id`
  second-granularity collision that could cross-contaminate two overlapping
  invocations' evidence rows; a missing truncation guard on the sweep's own
  log re-scan that could fabricate a false reliability finding from
  truncated data; and an exception-message truncation pattern that kept the
  sensitive half of an SSH error string (the connection destination and key
  path) instead of discarding it. Selftest extended 21 to 23 fixtures,
  including two new integration-level tests exercising the actual buggy
  functions directly rather than only their extracted pure helpers.
