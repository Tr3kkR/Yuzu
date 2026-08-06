- Agent: **landed dormant, no deployment setting to review** — Guardian does not route
  detection through Spark in any shipped build, and this change ships no user-facing
  behavior. An out-of-memory condition while arming a Spark watch no longer leaves a dead
  entry behind. Previously it could record a spark as armed with no watcher running, and
  a later request to watch the same target would join that dead entry and report success
  while monitoring nothing. This includes a failure while REPORTING a watch error, where
  building the error message could itself run out of memory and leave the dead entry
  behind. A watch that fails to arm still fails for every subscriber sharing it, which is
  unchanged. The same class of failure while WITHDRAWING a watch (disarming a spark, or
  removing the last subscriber) is now handled the same way: previously it could escape
  into Guardian's own bookkeeping, stranding a record that made a later re-arm of the same
  target silently do nothing and dropping the "disarmed" audit entry; now the engine's own
  bookkeeping always finishes and the audit trail stays consistent. One residual is
  deliberately left in both cases: if the operating system call that stops watching a
  target fails during this cleanup, the watch itself is not reclaimed. How long it lingers
  depends on which kind of watch it is — a file-change watch (Windows) can persist until
  the agent process restarts; a service-state watch (Windows or Linux) is reclaimed the
  next time the agent shuts down cleanly; a registry-change watch (Windows) cannot fail
  this way in the first place. The agent counts both cases and ships them in its heartbeat
  as `yuzu.spark_arm_race_unwatch_failures` (arming) and `yuzu.spark_disarm_unwatch_failures`
  (withdrawing), neither of which any fleet metric, dashboard or alert consumes yet, so
  neither is queryable today (#2270). Those two counts cover these two cleanup paths only —
  a third path, a consumer disconnecting outright rather than disarming one of its watches,
  is not yet counted, so two zeros are not an assurance that no watch was orphaned.
  `prefer_spark` (the same switch the Guardian journal entries in this release refer to)
  is a compile-time default that cannot be changed without a rebuild, so the existing
  detection path is unaffected.
