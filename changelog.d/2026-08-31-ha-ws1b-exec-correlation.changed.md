- **HA WS-1(1b), ADR-2002 section 5:** the `command_id → execution_id` correlation used to stamp
  `responses.execution_id` and drive the executions-drawer live view is now a PostgreSQL-backed
  table (`ExecutionTracker::command_execution`), replacing the former in-process
  `AgentServiceImpl::cmd_execution_ids_` map. A response now resolves its correlation identically
  regardless of which server replica receives it — closing the cross-instance correlation gap
  ADR-2002 named as a prerequisite for a second server replica. `ExecutionTracker`'s own tables
  were already migrated to Postgres (ADR-0065); this closes the remaining half of WS-1(1b). The
  mapping ages out via a new clock-guarded retention sweep (`reap_command_execution_mappings`,
  ~60m cadence) rather than growing unbounded for process lifetime. New metrics:
  `yuzu_exec_correlation_reap_total` / `_reap_clock_anomaly_total` / `_store_degrade_total` (the
  retention sweep), `_write_degrade_total` (the dispatch-time write), and `_read_degrade_total`
  (the response-receipt lookup, labelled `reason`), plus a new `YuzuExecCorrelationReapClockAnomaly`
  Prometheus alert (with promtool behavior test cases) on the clock-anomaly counter. `created_at` is
  authored from Postgres `now()` in-SQL (not the writing replica's app clock), matching the reap's
  own clock domain; the retention sweep's persisted anchor is now checked-parsed and the forward-skew
  comparison is overflow-safe (junk/negative/overflowed-string/implausibly-large values are all
  rejected as a clock anomaly, never silently coerced or fed into undefined-behavior arithmetic).
