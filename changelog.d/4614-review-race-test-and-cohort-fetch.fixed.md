- `#3990` R5.7 T2 re-measurement driver (PR #4614 review): added a genuine
  concurrency regression test constructing an in-flight arm callback racing
  `GuardianSparkRuntime::detach_all()` for its own lock - the two prior R5.7
  tests were sequential/single-threaded and never left a callback in flight
  across a `detach_all()` boundary. **Correction (consistency-auditor, this
  same review's later round - see the `race-test-honesty` fragment): this
  test does NOT catch a regression that moves the epoch bump, the claimed-
  rules withdrawal loop, or the wedged-claim deactivation to the wrong place
  WITHIN `detach_all()`'s already-held locked block - that class of
  regression is unobservable to any runtime concurrency test by
  construction, proven both by direct reasoning and by a reproduced mutant
  passing 3000/3000 runs including under a real TSan build. What this test
  does verify: both legal outcomes of the real two-thread race for the
  lock (a claim withdrawn before its callback can commit, or the callback
  committing before `detach_all()` begins its walk) converge to the same
  correct, fully-settled state - no double-commit, no stale live rule,
  exactly one epoch bump per call.** Also fixed `fullsync_blackout_diag.py`'s
  `cohort_events_d()`, whose
  bare `except Exception: continue` used to launder a REST-fetch failure for
  the whole polling window into the same "not_observed" state a genuinely
  never-fired guard produces, folding an instrument failure into the genuine
  `functional_invalid` void bucket. Selftest extended 23 to 24 fixtures,
  mutation-tested (F24 fails when the fix is reverted). No production
  agent/server code changed in this commit - test and internal-diagnostic-tool
  only.
