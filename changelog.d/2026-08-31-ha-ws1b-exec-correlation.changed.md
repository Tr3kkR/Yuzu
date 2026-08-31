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
  retention sweep) and `_write_degrade_total` (the dispatch-time write, distinct from the sweep),
  plus a new `YuzuExecCorrelationReapClockAnomaly` Prometheus alert on the clock-anomaly counter.
