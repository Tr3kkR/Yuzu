- **Guardian spark 7.7b test seams (#2238).** Two rung-7.7a fixes (PR #2236)
  landed without regression tests because the behaviours were inert at 7.7a but
  become load-bearing at the `prefer_spark` cutover. Three gaps close: (1) a
  `set_rearm_fault_hook_for_test` seam on `GuardianEngine` proves `start_local()`'s
  per-rule re-arm loop degrades correctly when one cached rule's re-arm throws
  (returns success, logs the failure, the other rules still arm) — previously
  nothing could force that throw; (2) `started_for_test()` introspection on
  `GuardianOutboxDrainWorker`/`ConvergenceScheduler` plus engine accessors prove
  `wire_spark_engine()`'s `prefer_spark_` start gate actually gates thread
  start, not just construction — reverting that gate to always-start previously
  failed no existing test; (3) a `[tsan]`-tagged checkpoint starts the drain
  worker with a real `this`-capturing send and tears the engine down while a
  send may be in flight, exercising the race between `stop()`'s join and an
  in-flight send for the first time. All three seams are test-only (no
  production behaviour change) and every new test is mutation-verified: it goes
  red against a reversion of the fix it covers, then green again against the
  real code.
