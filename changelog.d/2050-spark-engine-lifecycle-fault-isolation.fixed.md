- **Spark detection layer: `SparkEngine::start()` now rolls back cleanly on a
  mid-startup failure, and `stop()` no longer lets one wedged mechanism starve
  every other mechanism's teardown** (#2050). A resource-exhaustion throw during
  startup (Replay collection, mechanism-pointer collection, wheel-thread spawn,
  establishment-sink install, or a mechanism's own `start()`) now unwinds through a
  function-wide rollback guard that tears every already-started piece back down
  before the original exception reaches the caller — previously the engine could be
  left with `running_` latched true over a partially-started state. `stop()`'s
  mechanism-teardown loop is now per-iteration isolated: one mechanism throwing from
  `stop()` no longer skips every mechanism after it in that pass, and the engine's
  completion flag stays honest so a partial pass is retried, not latched away as
  done. Agent behaviour is otherwise unchanged — a startup failure still permanently
  disables Spark for that agent process, with no re-arm path.
