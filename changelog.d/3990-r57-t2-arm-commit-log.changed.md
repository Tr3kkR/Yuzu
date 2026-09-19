- **Guardian spark runtime: application-fence log lines for the `#3990` R5.7 re-measurement
  (rung 9c PR-6 item 2).** `GuardianSparkRuntime::detach_all()` now stamps a monotonic
  per-application `detach_epoch_` (bumped as the first statement of its locked block) and logs
  a new `Guardian spark: detach_all complete (epoch=, incarnation_floor=, detached_rules=,
  withdrawn_claims=)` line as the last statement of that block.
  `commit_new_generation_locked()` gains a `CommitPath` tag (five values distinguishing an
  inline arm, an inline shared-watcher join, a callback-side arm, a callback-side shared join,
  and a wedge late-success adoption) and logs a new `Guardian spark: arm committed for rule
  '<id>' (epoch=, incarnation=, type=, via=, attach_to_commit_ms=)` line as its last statement.
  Both lines are the runtime-side confirmation the `#3990` diagnostic's T2 measurand reads -
  the existing `SparkEngine: armed` log fires before the OS watch call even runs and is not a
  valid proxy. No behavioral change; purely additive logging plus one new counter, firewalled
  against the same rollback paths the existing lifecycle-audit enqueue already is.
