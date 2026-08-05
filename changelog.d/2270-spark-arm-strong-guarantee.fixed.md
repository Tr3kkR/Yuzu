- Agent: a memory-allocation failure while arming a Spark watch no longer leaves a
  dead entry behind. Previously an allocation failure part-way through `arm()` could
  leave a spark recorded as armed with no watcher actually running; a later request
  to watch the same target would join that dead entry, report success, and monitor
  nothing until the agent restarted. Arming is now all-or-nothing.
