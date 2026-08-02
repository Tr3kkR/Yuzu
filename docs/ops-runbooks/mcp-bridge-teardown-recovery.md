# Runbook: MCP progress-bridge teardown incomplete

**Alerts:** `YuzuMcpBridgeTeardownIncomplete`, `YuzuMcpMaintenanceTickFailing`,
`YuzuMcpBridgeRecordsNearCap`, `YuzuMcpProgressBridgeAtCapacity`
**Severity:** warning. **This is not a page.** Nothing is losing data, and the fix is
disruptive, so do it deliberately rather than immediately.

## What has happened

The MCP progress bridge correlates an execution's events onto a client's live SSE
stream. When a correlated request finishes, a background sweep tears its record down.
It publishes any decided terminal result **first**, so a later failure cannot lose it,
then settles the three things it owns in order: the **bus subscription**, the
**streamed admission charge**, and the **records_ map entry**.

Each step is contained separately, so a failure settles some and retains the rest. The
sweep's claim is **one-way** - a record it has claimed is permanently excluded from
later sweeps - so **nothing retries**. Whatever a failed teardown leaves behind is held
until the process restarts.

`yuzu_mcp_bridge_teardown_incomplete_total{reason}` names which step failed:

| reason | settled | retained until restart |
|---|---|---|
| `unsubscribe` | the terminal disposition **if there was one** - most teardowns (session death, pin-ack, arming reap, done reap) publish nothing at all, and even a memory-pressure teardown delivers nothing if its publish failed. Every failure row carries the terminal's fate as well as the mechanical failure, in one of five forms: the frame **was published**; the intended terminal failed and the **fallback was published instead**; the publish **POISONED the session** (session-wide - every later attach 410s, client must re-initialize); the frame **could not be built**, nothing published and this teardown did not poison; or the frame was built but **publishing threw**, nothing confirmed published and the poison state is **indeterminate**. The last of those is the one to treat as probably-poisoned. | the record, its admission charge, and its bus subscription - which also stops that execution's channel and replay buffer being collected |
| `release_charge` | the terminal disposition (whatever the row names) and the subscription; the record is still erased | one per-session streamed admission slot |
| `erase` | the terminal disposition (whatever the row names) and the subscription, and the charge **unless** `release_charge` also fired | the record and one global record slot, plus the admission slot if both fired |

This table is a summary keyed on one reason at a time. The audit row is authoritative
in every case: it names what was actually published, and when two reasons fire for the
same teardown it names both retained resources. Trust the row over the table.

A retained record also pins that session's whole stream state, its replay ring and any
pinned finals, past normal session garbage collection.

**Client results are never lost.** Every execution remains durably fetchable by
`execution_id` via `get_execution_status` / `query_responses`. What degrades is live
progress streaming, not correctness.

## What it is not

This counter is **defence in depth, not the out-of-memory signal**. On current code all
three steps are find/erase and node operations that allocate nothing, so only a mutex
failure can reach them - which in practice does not happen. If you are chasing
allocation pressure, the counter you want is
`yuzu_mcp_stream_terminal_publish_failures_total`.

If `teardown_incomplete` is moving at all, treat it as a genuine anomaly worth a bug
report, not routine noise.

## Impact assessment

1. **Is it growing, or did it happen once?** The metric is a counter and the retention
   is permanent, so the alert stays firing after a single event. Check the rate, not the
   value.
2. **How close is the bridge to its cap?** `yuzu_mcp_bridge_records_active` against the
   256-record cap. Below ~80% there is no user-visible impact at all.
3. **Is anything being refused?** `yuzu_mcp_bridge_reject_total{reason="global_cap"}`
   moving means the table is full: every `execute_instruction` carrying a
   `progressToken` is silently falling back to the plain (poll) path. Clients that poll
   are unaffected; clients relying on live progress stop receiving it.
4. **Load or strand?** This is the distinction that matters. Ordinary load recedes on
   its own. If `teardown_incomplete_total` is non-zero, that share of the occupancy is
   permanent and will not recede.

## Remediation

**The only remediation is a process restart**, and it is more disruptive than the
condition:

- A restart drops **every** live MCP session and in-flight streamed request, fleet-wide,
  not just the stranded ones. Clients must re-initialize.
- The condition that provokes a teardown failure is resource pressure - which is exactly
  when a restart is riskiest and when the server may struggle to come back cleanly.

So:

- **Not near the cap:** do nothing now. Record the occurrence, file a bug with the
  `reason` label and surrounding logs (`MCP bridge teardown incomplete [reason=...]`), and
  fold the restart into the next planned maintenance window.
- **Near or at the cap, and `teardown_incomplete` is non-zero:** schedule a restart.
  Check host memory headroom first. Prefer a rolling restart if more than one replica is
  serving MCP.
- **Near the cap but `teardown_incomplete` is zero:** this is load, not a strand. Do not
  restart - look for a client holding many warm sessions with never-terminating
  executions.

## Evidence

Every incomplete teardown emits, in order of reliability:

1. An operator log line: `MCP bridge teardown incomplete [reason=<reason>
   execution_id=<id>]: resource retained until shutdown`. The field is `reason`,
   matching the metric label, so the same value greps both.
2. The metric above.
3. An audit row on the relevant `mcp.bridge.*` verb with `result=failure` and a `detail`
   naming what was retained.

The log line exists because the metric and the audit row both route through guards that
swallow failures; under severe pressure both can be lost, so the log is the floor. If
you have the metric but no log line, or vice versa, that itself is worth reporting.

## If the row says the session was poisoned

A poisoned stream is **session-wide**: every later attach on that session returns 410,
not just the affected request. The client must re-initialize the MCP session to stream
again. Poisoning is reached only on a double publish failure, so it travels with
allocation pressure; results remain fetchable by `execution_id` throughout, and no
server-side action other than the usual restart decision applies.

## If `yuzu_mcp_bridge_projection_degraded_total` is non-zero

A different failure from the ones above, reached by the same broken-mutex fault, so the
two alerts often fire together. A projection could not retake the record lock at the end
of its batch and released its projection claim **without** it.

Releasing the claim is deliberate and is the better half of the trade: a claim left set
excludes that record from every consumer until the process restarts. It used to be
worse still: before #2489, a deferred record ended the whole pressure pass, so one
wedged record stalled ring-only pressure relief for every session. The pass now
advances past a defer, so the damage is confined to the wedged record itself. What is
lost instead is that batch's settle bookkeeping:

- a progress-only batch loses **nothing** - the claim release is a complete recovery;
- a batch holding a terminal payload that had not yet been published loses that payload
  permanently (it cannot be put back and nothing re-latches it). The request is then
  answered by the success-shaped fallback final - `status:"unknown"` plus the
  `execution_id` - rather than its real result.

**What to do.** No bridge-specific remediation exists; the affected request has already
been answered. Treat a non-zero value as a host-level signal: the fault is a failing
`pthread_mutex_lock`, which on a healthy box does not happen. Check the same host for
`yuzu_mcp_bridge_teardown_incomplete_total`, for OOM-killer activity, and for thread or
file-descriptor exhaustion. Clients that saw a fallback final can fetch the real result
with `GET /api/v1/executions/{execution_id}`; a restart clears nothing here, because
nothing is retained - the record itself is reclaimed normally.

## Known gaps

Tracked follow-ups an on-call engineer may hit:

- **#2513** - a failed teardown is never retried; retention lasts until restart.
- **#2514** - the maintenance thread has other unguarded blocks, so severe pressure can still abort the process from a different call site.
- **#2515** - `shutdown()` is the sole reclaimer and its walk aborts on the first failure, silently.
- **#2518** - a wedged audit database can stall this thread every tick.

## Related

- `docs/user-manual/metrics.md` - full metric reference
- `docs/user-manual/audit-log.md` - the `mcp.bridge.*` verb family and its `result` values
- `docs/mcp-server.md` - progress-bridge design and the degradation contract
