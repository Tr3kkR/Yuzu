- `#3990` R5.7 T2 re-measurement driver (PR #4614 review): added a genuine
  concurrency regression test constructing an in-flight arm callback racing
  `GuardianSparkRuntime::detach_all()` for its own lock - the two prior R5.7
  tests were sequential/single-threaded and would not have caught a regression
  that moved the epoch bump, the claimed-rules withdrawal loop, or the
  wedged-claim deactivation to the wrong place inside `detach_all()`'s locked
  block. Also fixed `fullsync_blackout_diag.py`'s `cohort_events_d()`, whose
  bare `except Exception: continue` used to launder a REST-fetch failure for
  the whole polling window into the same "not_observed" state a genuinely
  never-fired guard produces, folding an instrument failure into the genuine
  `functional_invalid` void bucket. Selftest extended 23 to 24 fixtures,
  mutation-tested (F24 fails when the fix is reverted). No production
  agent/server code changed in this commit - test and internal-diagnostic-tool
  only.
