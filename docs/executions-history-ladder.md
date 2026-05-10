# Executions-history ladder — invariants

Reference for the executions-history ladder PRs (PR 2 `responses.execution_id`
correlation and PR 3 SSE live updates). CLAUDE.md keeps a one-line pointer; this
document holds the hard invariants every successor PR in the ladder must check.

## PR 2 — `command_id → execution_id` mapping

`responses.execution_id` is populated at write time by an in-memory
`cmd_execution_ids_` map inside `AgentServiceImpl` (under `cmd_times_mu_`).
The mapping is registered at dispatch time INSIDE `cmd_dispatch` BEFORE any
RPC is sent — closes the FAST-agent race where a sub-millisecond loopback
agent could reply before a post-dispatch registration. The `CommandDispatchFn`
typedef carries `execution_id` as its sixth parameter; pass empty to opt out
(out-of-band dispatch / no-tracker callers).

### Known coverage gap (every PR in this ladder must check this)

Only `/api/instructions/:id/execute` (`workflow_routes.cpp`) creates an
execution row AND threads `execution_id` into `cmd_dispatch`. The following
dispatch surfaces produce `execution_id=''` responses, falling back to the
legacy timestamp-window join in the executions detail drawer:

- Workflow-step dispatch (`/api/workflows/:id/execute` step `cmd_dispatch`
  callback at `workflow_routes.cpp` line ~925)
- MCP `execute_instruction` (`mcp_server.cpp`)
- Schedule / approval-triggered dispatch
- Rerun (`/api/executions/:id/rerun` via `create_rerun` — does not currently
  dispatch a command, so the gap is structural, not a wiring bug)

Closing each gap is the scope of PR 2.x follow-ups. **When adding any new
dispatch path that creates an execution row, it MUST thread `execution_id`
into `cmd_dispatch`** — failure produces silent empty-string tagging with
no error or warning.

### Multi-agent fan-out invariant

A single `command_id` is dispatched to N agents; each agent sends its own
response with the same `command_id`. Terminal-status branches in
`agent_service_impl.cpp` do NOT erase `cmd_execution_ids_` — erasing on the
first agent's terminal would leave agents 2..N stamping empty
`execution_id`. Map entries persist for process lifetime; a periodic
sweeper is filed as PR 2.x. The accepted bounded leak matches the existing
`cmd_send_times_` / `cmd_first_seen_` shape under the same `cmd_times_mu_`.

Regression pin: `tests/unit/server/test_agent_service_impl.cpp` (9 cases /
47 assertions) drives `process_gateway_response` end-to-end into a real
`ResponseStore` and pins the no-erase rule (HF-1 fan-out across 4 agents
with mixed terminal statuses), the RUNNING/terminal stamping branches,
and the `__timing__|...` sentinel early-return. The
`test_workflow_routes.cpp:814` sibling case covers the response-store
level only.

### Server restart caveat

The mapping is in-memory; restart loses it. In-flight commands at restart
time produce responses tagged `execution_id=''` that use the legacy
fallback in the drawer.

### Terminal-frame finalize invariant (UAT 2026-05-06)

A `CommandResponse` with `status` ∈ {`SUCCESS`,`FAILURE`,`TIMEOUT`,`REJECTED`}
and **empty output** does NOT create a new `responses` row. Both
`Subscribe()` and `process_gateway_response()` call
`ResponseStore::finalize_terminal_status(instr, agent, status, err, exec_id)`,
which UPDATEs every existing RUNNING (status=0) row scoped to
`(instruction_id, agent_id, execution_id)`. A terminal frame WITH output
still inserts (rare; the data is the result). A terminal frame whose
finalize updates zero rows (no preceding RUNNING under that
execution_id — typically a re-mapped command_id retry) falls through to
insert.

Why: pre-fix, every command produced **two** rows per agent — a RUNNING
row carrying the streamed output, plus an empty terminal sentinel. The
dashboard rendered both, sorted newest-first, and operators read the
non-zero `status` enum value (1=SUCCESS, 2=FAILURE, …) on the empty row
as a failure exit code that "happened before" the data row. Now there
is exactly one logical response row per (instruction, agent, execution),
carrying the data and the terminal status.

Regression pins: `test_agent_service_impl.cpp` "terminal SUCCESS folds
into existing RUNNING rows" and "terminal frame WITH output still
inserts" cover the two branches; the re-mapping case is pinned by
"re-mapping a command_id updates the stamp" (terminal under the new
exec_id falls through to insert because no RUNNING row exists there).

### Partial-index planner contract

`idx_resp_execution_ts ON responses(execution_id, timestamp) WHERE
execution_id != ''` requires the WHERE clause to syntactically subsume the
partial-index predicate. Every query against this index must include
`AND execution_id != ''` redundantly, or SQLite falls back to a full table
scan. See `query_by_execution`'s SQL in `response_store.cpp` for the
canonical form.

## PR 3 — SSE live updates

`ExecutionEventBus` (`server/core/src/execution_event_bus.{hpp,cpp}`) is the
per-execution SSE bus that backs `GET /sse/executions/{id}`. Owned by
`ServerImpl`, declared BEFORE `execution_tracker_` in the member list so the
bus outlives the tracker (the tracker borrows the bus pointer via
`set_event_bus`). On the explicit shutdown path the order is also tracker
first, then bus.

### Publisher invariant

Three `ExecutionTracker` mutators publish onto the bus when set:

- `update_agent_status` → `agent-transition` (one event per agent state
  change; payload is the `AgentExecStatus` JSON).
- `refresh_counts` → `execution-progress` (counts snapshot) AND, when the
  recompute crosses the all-agents-responded threshold, a terminal
  `execution-completed` (status=succeeded|completed). The progress event
  precedes the terminal event so an SSE client receives counts then status.
- `mark_cancelled` → terminal `execution-completed` (status=cancelled).

### Bounded ring buffer

Per execution: `kBufferCap=1000` events FIFO, ~30 s window in practice.
Replay walks events with `id > Last-Event-ID` on reconnect. Channels marked
terminal are GC'd by `gc_terminal_channels` once
`kRetentionAfterTerminalSec=60` elapses AND no live subscribers remain. GC
runs opportunistically from `publish` so no separate timer thread is
required.

### Client-side bootstrap is data-attribute-driven

The list-row markup carries `data-execution-id` and
`data-execution-status`; the drawer's KPI strip carries
`id="exec-kpi-{id}"`; per-agent table rows carry
`id="per-agent-row-{exec_id}-{agent_id}"`; per-agent status badges carry
`.per-agent-status` and `.per-agent-exit-code` classes. **Every PR that
touches drawer markup MUST keep these stamps stable** — they are the
client SSE listener's binding contract. Renaming any of them is a silent
regression: the listener falls back to no-op and the drawer freezes
mid-execution with no error.

### Audit policy

`execution.live_subscribe` audits on first connect per session-per-execution
(deduped). SSE auto-reconnect inside the dedup window does NOT re-audit.
The forensic-grade audit on read remains on
`/fragments/executions/{id}/detail`'s `execution.detail.view`.

### Hard predecessor for PR 3

PR 2.5 (#670) replaced the 16-arg `WorkflowRoutes::register_routes` with a
`WorkflowRoutes::Deps` struct. **Do not regress that signature** — adding
new dependencies to the workflow routes goes through the struct, not new
positional arguments.
