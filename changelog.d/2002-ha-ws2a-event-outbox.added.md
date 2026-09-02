- **HA WS-2a (ADR-2002 §5): a durable Postgres event outbox for execution
  events.** `ExecutionTracker` gains a third table (`event_outbox`, migration
  v4) that durably records the transition events it already fans out in-memory
  over `ExecutionEventBus` — `agent-transition`, `execution-progress`, and
  `execution-completed` — each carrying a global durable monotonic `event_id`
  (`BIGINT` IDENTITY). Every event is appended **inside the same transaction as
  the state mutation that produced it** (the `agent_exec_status` upsert, the
  aggregate recompute/terminal transition, and the cancel), so a crash or
  failure can never leave state without its event or vice versa; the two
  formerly-autocommit write paths (`upsert_agent_status_once`, `mark_cancelled`)
  are now transactional. The durable feed has no consumer in this slice — the
  in-memory bus still serves live SSE unchanged — and is bounded by a
  clock-guarded retention sweep (`reap_event_outbox`, 24h window) that mirrors
  the `command_execution` retention shape. This is the foundation the fenced
  leader (WS-3) and the cross-replica LISTEN/cursor-poll delivery (WS-2a-2)
  build on. Server-tier HA remains gated on the full safe-to-scale set; a single
  server is unaffected.
