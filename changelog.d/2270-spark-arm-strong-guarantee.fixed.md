- Agent: an out-of-memory condition while arming a Spark watch no longer disturbs
  existing subscriptions or leaves a dead entry behind. Previously it could leave a
  spark recorded as armed with no watcher running, and a later request to watch the
  same target would join that dead entry and report success while monitoring nothing.
  A watch that fails to arm still fails for every subscriber sharing it, which is
  unchanged. Spark detection is not yet the active path in a default install, so this
  affects deployments only once it is enabled.
