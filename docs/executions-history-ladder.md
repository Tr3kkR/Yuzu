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

### Non-tracked correlation-id prefixes (`polchk-`, `bundle-`, `preflight-`, `deployment-`)

`notify_exec_tracker` skips four server-minted correlation-id prefixes that ride
the `execution_id` column on `responses` (so their rows are retrievable via
`ResponseStore::query_by_execution`) but are **NOT operator executions** —
creating a tracker row for them would publish a phantom `agent-transition` SSE
event and leave an orphan `agent_exec_status` row that the executions drawer /
`/api/v1/events` would surface:

- **`polchk-`** — minted by `PolicyEvaluator`; compliance-check responses only.
- **`bundle-`** — minted by `BundleOrchestrator` (ADR-0011); the N ordinary
  command responses of one live-query bundle. A bundle is N commands to ONE
  agent, so the agent-counted tracker would mark it complete after the first
  step — collate (`received`/`succeeded` vs `expected`) is the bundle's sole
  completion authority, deliberately outside this ladder.
- **`preflight-`** — minted by `PreflightRoutes` / `PreflightRunner` as
  `preflight-<run_id>-<check_key>`; the `/auto` pre-flight checks. A run
  re-dispatches each check under the same per-check id so `query_by_execution`
  unions the re-dispatches per agent. There is no `ExecutionTracker` row —
  `PreflightRunStore` is the run's completion authority, deliberately outside
  this ladder.
- **`deployment-`** — minted by the deployment engine as
  `deployment-<deployment_id>-stage` / `-exec`; the `/auto` DEPLOY stage's
  content_dist stage + execute_staged commands. The engine reads each phase's
  responses back via `query_by_execution` to advance the per-device state machine;
  `DeploymentRunStore` is the run's completion authority. (Unlike the read-only
  `preflight-` checks, the execute phase MUTATES — but that safety lives in the
  store's claim-before-dispatch CAS, not here; this ladder only keeps the phantom
  tracker rows out.)

All ids are **server-minted, never caller-supplied** into `notify_exec_tracker`,
and their namespaces are disjoint from real tracker ids (32-hex, no prefix), so a
caller cannot collide a real execution into the skip. **Any new correlation-id
prefix that stamps `responses` for internal retrieval but is not an operator
execution must be added here and guard `notify_exec_tracker` the same way.**

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

**Management-group scope is applied AFTER the LIMIT, in the handler — not in the
SQL.** The MCP `query_responses` collect path runs a per-agent
`check_scoped_permission` filter on the returned rows (#1550), *after* the store
has applied `ORDER BY timestamp DESC LIMIT`. **NOTE (#1634): this filter is INERT
under the current global `Response:Read` gate** — a holder of global `Response:Read`
(the only principal that passes the gate) admits every agent, so no rows are
dropped, while a management-group-confined operator is 403'd at the gate before the
filter runs. So it does **not** today provide cross-operator isolation: a normal
caller sees all agents' rows. Its only active effect is failing **closed** on a
corrupt/load-failed `rbac.db`. When the #1634 admit-then-filter gate makes scoping
effective, this after-LIMIT placement means an execution that fans out wider than
the row cap and spans both in- and out-of-scope agents can have the cap consumed by
out-of-scope rows, truncating the in-scope caller's view (or a row present in one
poll vanishes from the next as the window shifts) — at that point the isolation
holds (never another operator's rows) but completeness does not. The handler flags
truncation with `result_truncated_by_cap:true`; the durable fix (scope-aware keyset
pagination + pushing the predicate into the WHERE clause) is part of the #1634
follow-up. The same applies to every other operator-facing reader of this store.

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

### GC lock-ordering invariant (#1198)

`channels_` holds the only `shared_ptr` to each idle channel, and each
`Channel` carries its own `std::mutex`. **A `Channel` must never be
destroyed — via `erase` or any other `channels_` mutation — while any lock
on that channel's mutex is alive.** The required pattern, used by
`gc_terminal_channels`:

1. Pin the victim with a local `shared_ptr` copy *before* locking its mutex.
2. Erase the map entry — the local copy keeps the `Channel` alive.
3. Park the copy in a container declared *outside* the lock scopes (the
   `dead` vector), so `~Channel` runs only after the per-channel guard and
   the `map_mu_` write lock are both released.

Violating this is UB on every toolchain and a hard server-wide abort on
MSVC ("unlock of unowned mutex"). The Linux sanitizers cannot see a
regression here (the bad unlock executes inside uninstrumented libpthread,
and libstdc++/libc++ `~mutex` is trivial, so TSan gets no destroy hook) —
the MSVC test legs are the enforcement point, via the `set_clock_fn`
regression test in `test_execution_event_bus.cpp` (`[gc]` tag). Any
successor PR that restructures `gc_terminal_channels` or adds a new path
that erases from `channels_` while holding a channel mutex must preserve
this ordering. Lock hierarchy is `map_mu_` → `ch->mu`, never reversed.

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

### Second consumer (sprint W5.1, 2026-05-18)

`GET /api/v1/events?execution_id=<id>` is the agentic-first sibling of
`GET /sse/executions/{id}` — both subscribe to the same per-execution
channel from the same `ExecutionEventBus`. The dashboard route emits raw
`ev.data` (the browser already knows the channel from the URL path); the
agentic route wraps every event in
`{execution_id, event_id, timestamp_ms, type, payload}` so a worker
subscribed to one channel can still discriminate events without out-of-
band context.

**Two consumers, one bus, one set of publisher invariants** — the
publisher list above (`update_agent_status` / `refresh_counts` /
`mark_cancelled` → `agent-transition` / `execution-progress` /
`execution-completed`) is the single taxonomy both routes emit. A new
event type must be added on the bus side first; both routes pick it up
transparently. **Do not add a route-specific event type to either
sibling** — that would split the taxonomy and break the A3 invariant
that a single deterministic step name appears on every channel.

The agentic route's audit verb is `api.v1.events.subscribe` (separate
from `execution.live_subscribe` so SIEM filters can distinguish browser
vs agentic consumers). Same no-dedup deferral applies (#700 Deferred-5).
The A3 envelope shape and the A4 error envelope live in
`server/core/src/rest_a4_envelope.hpp` as testable contracts — future
discovery / MCP surfaces consuming the same bus reuse the helpers there
rather than re-implementing the envelope.

**Hardening invariants (sprint W5.1 R1):** the agentic handler exposes
ring-buffer loss and per-connection backpressure to the client rather
than letting them go silent.

- **Replay-gap signal.** If the bus's ring buffer has already evicted
  events with id ≤ `since_id`, the handler emits a synthetic
  `replay-gap` envelope as the first frame
  (`{execution_id, type:"replay-gap", missing_from, missing_to}`) so the
  worker knows state may be inconsistent rather than silently observing
  an `event_id` jump. Counted in
  `yuzu_server_sse_api_replay_gap_total`. The dashboard sibling does
  NOT emit this — adding it there is a follow-up.
- **Per-connection queue cap.** `SseSinkState::queue` is bounded at
  `kPerConnectionQueueCapDefault=500` (event_bus.hpp) with drop-oldest
  semantics. Drops accumulate in `SseSinkState::dropped_total` and the
  content provider emits one `events-dropped` envelope per batch on the
  next wake, then resets the counter. The dashboard sibling does NOT
  enforce a cap currently — same follow-up.
- **Restart loss.** The bus is in-process and in-memory. On server
  restart the buffer is empty; clients that reconnect with
  `Last-Event-ID` after a restart will not receive events that occurred
  before the restart regardless of the `since` value. Agentic workers
  should fall back to `GET /api/v1/executions/<id>` for terminal state
  recovery. This is the same characteristic the dashboard drawer
  already lives with; it is documented here for agentic-client authors
  who write reconnect logic against the executions ladder rather than
  the dashboard's bootstrap path.
