- Agent: an out-of-memory condition while arming a Spark watch no longer leaves a dead
  entry behind. Previously it could record a spark as armed with no watcher running, and
  a later request to watch the same target would join that dead entry and report success
  while monitoring nothing. This includes a failure while REPORTING a watch error, which
  a previous attempt at this fix missed: building the error message could itself run out
  of memory and leave the dead entry behind. A watch that fails to arm still fails for
  every subscriber sharing it, which is unchanged. Spark detection is not yet the active
  path in a default install, so this affects deployments only once it is enabled.
