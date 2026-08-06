- Agent: an out-of-memory condition while arming a Spark watch no longer leaves a dead
  entry behind. Previously it could record a spark as armed with no watcher running, and
  a later request to watch the same target would join that dead entry and report success
  while monitoring nothing. This includes a failure while REPORTING a watch error, where
  building the error message could itself run out of memory and leave the dead entry
  behind. A watch that fails to arm still fails for every subscriber sharing it, which is
  unchanged. One residual is deliberately left: if the operating system call that stops
  watching a target fails during this cleanup, the watch is not reclaimed — on Windows it
  can persist for the life of the agent process, so only restarting the agent releases it.
  The agent counts it and ships the count in its heartbeat as
  `yuzu.spark_arm_race_unwatch_failures`; no fleet metric, dashboard or alert consumes it
  yet, so it is not queryable today (#2270). Spark detection is not the active detection
  path in a default install, so this affects deployments only where that has been turned on.
