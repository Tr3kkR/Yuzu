- **A persistently failing File Spark worker pass now backs off, is counted and logged, and is reported
  `inert` (#4658).** The Windows agent's File Spark mechanism (Spark is the agent's event-driven change
  detection) retried a throwing worker pass with no delay, no counter and no log, so a persistent
  failure spun the worker and was invisible to the heartbeat. It now retries on a doubling backoff
  starting at the mechanism's sweep cadence (50 ms by default) and capped at 30 s, counts each failed
  pass, logs at consecutive failures 1, 2, 4, 8 and so on, and after three consecutive failed passes
  reports the mechanism `inert` (excluded from the `yuzu.spark_mechs` capability list) until a pass
  succeeds, matching the Registry mechanism's sweeper. No watch is armed through this mechanism until
  Spark detection is turned on, which it is not in production agents, so nothing is operator-visible
  on shipped agents yet; the fix is a precondition for turning Spark detection on.
