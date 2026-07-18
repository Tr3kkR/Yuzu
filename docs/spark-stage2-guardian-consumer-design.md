---
status: draft
date: 2026-07-17
owner: Dave Rae
scope: agent — Guardian detection cutover onto SparkEngine; server — spark/guard health surface
adr: 0021 (Sparks as sole detection layer); amends Decisions 3 & 11
tracks: #1939 (Stage-2 readiness checklist), #2011, #2014, #1938, #1929, #1933, #1936, #2015
governance:
  - original design - 9-agent /governance pipeline, 2026-07-11 (report local, not committed to git); hardening round folded all findings into the sections below.
  - rung 9a addition (the §Rung-2 decision record + inner ladder) - 4-agent pipeline (security-guardian, docs-writer, architect, consistency-auditor), 2026-07-17; every embedded code-claim verified against origin/dev; security MEDIUMs on the F3 blast radius and intra-class lane exhaustion folded in.
history:
  - 2026-07-11 - initial design; 2 governance rounds; landed as PR #2051.
  - 2026-07-17 - rung 9a - §Rung-2 decision record (R1-R4) + the inner-ladder
    decomposition of rung 2 into the §Implementation PR ladder (rungs 1-7 merged as
    PR #2224; the 7.7a/7.7b/8/10/11/12 remainder). Records what was previously held
    only in commit messages and a local plan; the full as-built rewrite is rung 9b,
    after 7.7b.
---

# Spark Stage 2 — Guardian as the first SparkEngine consumer

## Context

ADR-0021 makes SparkEngine the agent's only detection layer and Guardian, DEX,
and Reflex its sovereign consumers. Stage 1 (PR #1927) shipped SparkEngine plus
the File, Registry, and Service mechanisms; the pre-Stage-2 hardening batch
(PR #2019) landed the resource/latency fixes. Both are merged to `dev`, green,
and **entirely unconsumed** — nothing in `agent.cpp` instantiates `SparkEngine`.

Guardian still runs its own detection: one dedicated OS thread per armed rule,
built by `GuardianEngine::start_guard_for_rule_locked()`
(`agents/core/src/guardian_engine.cpp`) into
`std::unordered_map<std::string, std::unique_ptr<IGuard>> guards_`
(`agents/core/include/yuzu/agent/guardian_engine.hpp:170`). Stage 2 begins the
cutover away from that per-rule-thread detection (both paths stay compiled through
rung 4; the `IGuard` files are deleted only at rung 5) and
re-homes all three guard types onto the shared, multiplexed mechanisms —
Guardian's first real use of SparkEngine, and the point at which the old and
new detection worlds first coexist on a running agent.

This document is the design; implementation follows as a governed PR ladder
(bottom of this doc). It also carries two ADR-0021 amendments — Decision 3
(§Enforce path) and Decision 11 (§Parity, §24, and gates).

## Scope

**In:** File + Registry + Service guard detection moves from per-rule `IGuard`
threads onto `SparkEngine` mechanisms; Guardian becomes a queued consumer that
keeps all of its meaning-assignment (assertions, compliance verdicts, event
shaping) on top of raw `SparkEvent`s. Agent-side kill-switch. Spark/guard health
surfaced on heartbeat metrics **and** the per-rule REST + MCP status surface.

**Out (unchanged, later stages, or other consumers):**
- Wire protocol: `GuaranteedStatePush`, the `__guard__` event channel, the
  `__guardian__` KV enforce cache, and census semantics stay byte-compatible.
  The compiled per-device policy wire (ADR-0021 Decision 8) is a **later stage**.
- DEX collectors, TriggerEngine watchers, and Reflex — separate consumer
  cutovers, separate stages.
- `PolicyEvaluator` (server-polled instruction compliance) — untouched,
  ADR-0021 Decision 12.

## Rung-2 decision record (rung 9a)

Four questions that rung 2's inner ladder depends on, settled 2026-07-17. They are
recorded here because they were previously settled only in conversation, and rung 7.7's
shape is undefined without them. Each states the ruling, the reason that decided it, and
what it costs.

### R1 - Backend selection: `--spark-disable` is the only switch

`prefer_spark` is set from the existing kill-switch, at the single production
construction site:

```cpp
guardian_ = std::make_unique<GuardianEngine>(kv_store_.get(), cfg_.agent_id,
                                             /*prefer_spark=*/!cfg_.spark_disable);
```

This lands in rung 7.7b, and **7.7b is therefore the cutover**. No second flag is added.

The problem it solves: `GuardianEngine`'s ctor takes `bool prefer_spark = false` and
production passed only two arguments, so the only `prefer_spark=true` in the tree was a
unit test. Spark was unreachable in any production configuration, which would have made
every pre-cutover gate measure the legacy path or a test constructor.

A temporary opt-in selector (`--guardian-spark`, staged cohort, removed later) was
considered and **rejected**: Yuzu is installed only in small labs, so a staged rollout has
no value, and a hard cutover is acceptable (owner decision, 2026-07-17). This matches the
rung-2 posture this document already specifies (detect-only by default; `--spark-disable`
keeps the enforcing legacy path), so **no ADR amendment is required**.

Behaviour, traced through `reconcile_rule_locked`:

| `--spark-disable` | `prefer_spark_` | `SparkAvailability` | Guardian backend |
|---|---|---|---|
| set | `false` | `SparkDisabled` | legacy - **enforcement intact** (escape hatch) |
| unset | `true` | `Available` | spark |
| unset, spark boot threw | `true` | `SparkFailed` | **errored - never a silent legacy fallback** |

`--spark-disable` carries three jobs from 7.7b on: the kill-switch, the resource gate's
legacy comparison arm, and the enforcement escape hatch.

**Fail-visible is fail-closed-for-protection, and that has a correlated-outage tail.** The
`SparkFailed` → errored path is the right posture (a boot failure must be loud, never a
silent restore of legacy enforcement), but note the residual risk it commits to: a
*correlated* spark boot failure - a bad release that throws on every agent - withdraws
every Guardian rule fleet-wide until an operator sets `--spark-disable`. The rung-11 alert
group must therefore alert on `SparkFailed` *prevalence* (a fleet-wide spike), not only
per-agent, so this failure mode is caught in minutes rather than discovered as silent
non-enforcement.

**Accepted cost:** Guardian enforcement is absent from 7.7b until rung 3, because rung-2
posture is detect-but-do-not-enforce. The enforce gap was already accepted (rung 3 follows
immediately, no extended burn-in); the hard cutover makes it start at 7.7b rather than at
a later flip. `--spark-disable` restores enforcement if that is not tolerable on a given
box.

**Consequences for the ladder:** the separate "default flip" rung dissolves into 7.7b; its
residue is the boot WARN, the `yuzu_fleet_spark_enforce_active` gauge, the `changelog.d`
fragment and the `guaranteed-state.md` upgrade note. Rung 4 no longer gates the cutover,
because R4 brings the `unsupported` telemetry forward into 7.7b (only `guard_healthy`
waits for rung 4).

**Note for any future flag:** unknown CLI flags are **fatal** (`main.cpp`'s `CLI11_PARSE`
does not set `allow_extras`). Adding a flag to a fleet agent and later removing it would
refuse to start every device whose service definition still carries it. Any flag
retirement must be staged: accepted-and-ignored with a warning for at least one release.
This applies to `--spark-disable`'s semantic change at rung 5.

### R2 - Mutual exclusion is per-agent, not per-rule

On a spark-preferred agent, `RulePlacement::Unsupported` routes to the distinct
`unsupported` state (§Platform-rejection). It **never** falls through to legacy. ADR-0021
Decision 11's "the flag selects one path" stands unamended.

What decided it: **rung 5 forces this regardless.** When the legacy backend is deleted
there is nothing to fall through to, so `Unsupported` must become a distinct terminal
state then. Keeping the fallthrough means implementing the same outcome twice, and
teaching the parity suite, the telemetry, and the operator model two behaviours.

Verified safe to change now:
- **Enforcement behaviour is identical.** The legacy File/Registry guards already return
  false from `start()` off-Windows: a silent no-op, no `guards_` entry. Nothing enforces
  either way. What changes is reporting, from silence to an explicit state.
- **Nothing server-side breaks.** The Guardian status surface is still mock/placeholder
  (§Health/status surface), so no server code validates status tokens yet. This is the
  cheapest moment to introduce one; rung 4 owns its wiring.

**Consequences to book:**
1. **The existing reconcile tests assert the old semantics.** `test_guardian_engine_spark_reconcile.cpp`
   contains `TEST_CASE("an unsupported type falls through to legacy, never attempted on spark")`
   and a same-id replace case that assumes legacy is reachable on a spark agent. They are
   rewritten in the same PR as the code change, or the suite goes red on a deliberate
   change and the next person "fixes" it back.
2. **Parity needs an intentional-delta registry.** Legacy silently no-ops where spark
   reports `unsupported`. Zero-tolerance parity cannot be literal across that dimension;
   rung 10's gate artifact must carry the documented delta list, or the gate fails
   spuriously and gets quietly weakened until it means nothing.
3. **macOS under spark preference is all-unsupported.** Both mechanism factories return
   nullptr off their platforms, so every rule on a spark-preferred macOS agent classifies
   `Unsupported`. That matches today's macOS enforcement reality, but the macOS CI leg
   must assert exactly that posture or it passes by testing nothing.

### R3 - I/O executor quota semantics

**Ruled:** the per-class bulkheads must be exact. `GuardianIoExecutor`'s class quotas
(File 4, Registry 3, Service 3) sum to 10 against `total_quota{8}`, and admission is
first-come-first-served against the two caps with no per-class floor - so File and
Registry at their own limits starve Service to 1 of its 3 slots with nothing wedged,
contradicting the header's own guarantee that "a dead mount saturating the file lane never
starves a healthy service reconcile".

The governing algebra: **if `sum(class_quota) <= total_quota`, the total can never be the
binding constraint.** Admitting class `c` requires `class_inflight[c] <= quota[c]-1`, and
every other class is bounded by its own cap, so `total_inflight <= sum(quota) - 1 < sum <=
total_quota`. The total check cannot fire while any class has room; when every class is at
cap the class caps reject anyway. So the choice is binary: exact bulkheads with a
structurally inert total, or oversubscription plus reserved floors.

Oversubscription-plus-floors is **rejected**: it buys 8 versus 10 concurrent
spawn-per-read *detached* workers (not resident threads), which does not justify new
admission logic on a safety-critical path.

**Open at time of writing:** whether to satisfy the invariant by setting `total_quota = 10`
with a constructor-time check, or to remove `total_quota` from `Config` and derive the
bound from the class quotas. Deriving cannot desynchronise; an explicit total plus an
invariant check is a tripwire that forces a conscious decision when a fourth `IoClass` is
added. A synthesis - derive the bound, and `static_assert` the default quotas against an
explicit `kMaxProcessIoWorkers` - gets both, and is the current preference. Note the check
cannot be `static_assert` alone: `Config` is runtime-injectable, so the defaults are
statically asserted and injected values runtime-checked. **Resolve when implementing;
the semantics above are settled either way.** Whichever is chosen, the `total_quota{8}`
field comment ("< sum(class quotas) so it actually binds") states the intent this ruling
*reverses* and must be corrected in the same rung, or a future reader trusts a stale intent.

**Intra-class exhaustion is a separate, unsettled axis (settle it in 7.7a).** The bulkhead
ruling above is about *cross*-class starvation only. Within a class, keyed single-flight
plus `class_quota{File:4}` means four distinct wedged file targets saturate the file lane
and silently kill detection for every file rule - at runtime, with no F3 trip and no crash.
The load-bearing question the record must pin, not leave to implementer judgement: **when a
per-class deadline elapses, the admission slot is freed immediately** (the wedged read's
orphan thread lives on under the F3 count, but the lane recovers), so a wedged target
degrades to skip-and-continue rather than holding its slot until the orphan returns. Lane
availability must be decoupled from orphan-thread liveness.

### R4 - Observability contract

**Constraint:** the agent has no `/metrics` endpoint. `spark_heartbeat.hpp` → status_tags
→ the server-side rollup is the only metric path, and rung 1 already shipped that rail, so
this is an increment on working rails. `GuardianIoExecutor` already computes per-class
`Counters{timed_out, rejected_capacity, rejected_key}`, but `stats()` has no production
caller - they are write-only today, so routing them is new wiring rather than a relabel.

**Standing rule: log state transitions and sampled failures only.** Never per-event or
per-convergence-read. A chatty file watcher at fleet scale is a self-inflicted denial of
service on the log pipeline. This rule governs the initial logging pass itself: write this
set once, rather than a "stopgap" that a later rung has to rip out.

**7.7a (threads live, no rules placed) - logs:** wiring outcome and selected backend;
scheduler and drain-worker thread start/stop; active I/O workers at shutdown, including
whether the F3 hard-exit path fired.

**7.7b (rules flow) - logs:** arm/disarm failure transitions, unsupported classification,
mechanism liveness transitions. **Heartbeat tags:** the executor's per-class counters;
outbox occupancy, oldest-entry age and drops; scheduler lag; and `yuzu.guardian_backend`,
without which the server cannot tell which backend a device is running or distinguish
`SparkFailed` from `Unsupported`.

**The F3 hard-exit signal cannot be a live heartbeat.** `hard_exit()` skips teardown by
design; the process is gone before anything could be sent. It is a best-effort marker
persisted before the exit, then read, reported and cleared on the next boot.

## Consumer architecture

Guardian becomes a SparkEngine client. The seam:

- **One queued consumer.** `GuardianEngine` calls `register_consumer(name,
  handler, queue_cap)` (`spark_engine.hpp:159`) once at startup, and `arm(consumer,
  SparkSpec)` (`:174`) once per enabled rule — replacing the per-rule guard
  construction in `start_guard_for_rule_locked()`. Arming is deduped by
  `spark_key`, so two rules watching the same unit/key share one watcher.
- **Guardian keeps its meaning layer.** Everything that made a guard *Guardian's*
  — assertion evaluation, `GuardDrift`, event-debounce/`collapsed_count`,
  compliant-edge suppression, and `emit_guard_event` → `GuaranteedStateEvent`
  (event-id minting, `event_type` mapping) — moves out of the per-guard classes
  into the **consumer handler**, operating on `SparkEvent`s. The `IGuard`
  classes' pure decision logic (`service_classify_edge`, `systemd_decide_emit`,
  the File hash-compare, the Registry value-compare) is lifted verbatim; only the
  detection plumbing underneath it is replaced.
- **Event payloads.** Service `SparkEvent`s carry `ServiceSparkData{ServiceRunState}`
  (`spark.hpp:189/199`) — the consumer reads run-state directly. File and Registry
  events are `std::monostate`; the handler re-reads the on-box state (file hash,
  registry value) to evaluate assertions.
- **Fault channel.** `SparkFaultFn` reports (a watcher that armed then went deaf —
  bus/SCM collapse) map to the existing `guard.unhealthy` event type
  (`event_state_from_type` → census state `errored`) and to the per-rule health
  field (§Health surface). The fault callback must be **non-blocking and must
  never call Guardian's meaning layer inline** on the mechanism thread (see
  §Enforce path, #2014 corollary) — it enqueues to the consumer like any event.

### spark_key → rule index and shared-watcher lifetime

Dedup-by-`spark_key` creates a structural difference from today's one-guard-per-rule
model that the meaning layer must absorb. A `SparkEvent` carries only its `key`
(`spark.hpp:202`) — no `SubscriptionId` or rule_id reaches the handler — and N
rules with different assertions may share one watcher. The consumer therefore owns
a **`spark_key → {rule_id…}` index**, populated at `arm()` and consulted on every
event/fault delivery to resolve which assertion(s) to evaluate and which rule's
remediation to run. Shared watchers are **refcounted**: disarm/redeploy of one
rule decrements; the underlying `disarm()` fires only at zero, so disarming rule A
never blinds rule B on the same unit. (Register-of-record for UP-11 / happy-path
Issue 2.)

### Re-arm and initial-evaluation contract

Today's continuity on restart comes from each `IGuard` doing an **explicit initial
evaluate at arm time** — `guard_file.cpp` `eval_now()`, `guard_registry.cpp`
`reconcile()` — so a rule that drifted while the agent was offline is caught (and,
if enforce, remediated) the instant the guard starts, with no external trigger.
The mechanisms do **not** uniformly reproduce this, and the two failure modes are
opposite:

- **File / Registry are edge-only.** `spark_registry.cpp:197` states outright a
  registry spark "fires on a CHANGE, so there is no initial emit"; the File
  mechanism only emits from an actual `ReadDirectoryChangesW` completion. Without
  intervention a pre-existing offline drift is **invisible and unremediated until
  the next on-box change** — a silent regression from today. (happy-path Issue 1.)
- **Service re-emits initial state on every arm** (`spark.hpp:186-188`). A
  `start_local()` re-arm therefore re-fires the current run-state as a fresh edge,
  risking a **duplicate GuardDrift and a re-enforce storm on every restart**.
  (architect S1.)

Resolution — the consumer owns an explicit re-arm contract, not the mechanism.
For **every** rule, at arm time the handler runs a **synthetic initial evaluate**:
re-read on-box state (file hash / registry value; for Service the arm-time seed
event `spark.hpp:186-188` supplies it) and run the full assertion → enforce path.
The `__guardian__` cache is consulted **only** to suppress a duplicate *event
emission* / reset `collapsed_count` — it does **not** short-circuit the assertion
evaluation. This keeps Service identical to File/Registry: a rule whose cached
terminal state was itself a persistent unremediated drift (a prior enforce failed,
or the rule is observe-mode) is **still re-evaluated and re-enforced** on restart,
never silently suppressed because "the state matches the cache" (architect Gate-8).
The synthetic initial evaluate is **per-rule and unconditional** — when rule B arms
onto an already-armed shared watcher the mechanism `arm()` is a dedup no-op, but the
consumer still runs B's initial evaluate, so B's offline drift is never missed
(the engine holds the watcher refcount via `sub_keys_`/`armed_`; the consumer's
`spark_key→rule` index drives the per-rule evaluate).

**Cache-read failure is fail-closed-per-rule.** If the `__guardian__` cache is
unreadable, format-skewed, or a rule's `arm()` returns a typed rejection mid-loop,
that rule is marked `errored` (surfaced on the health surface) and re-arm continues
with the next rule — never a silent skip that leaves the rule armed-but-unevaluated,
never a whole-startup abort (UP-4). `start_local()` re-arms sparks from the same
`__guardian__` KV cache; a cross-format round-trip test gates the cutover. The
"identical continuity" property is a property of this contract, verified as a
rung-2 parity assertion — not assumed from the mechanism's edge behavior.

## Enforce path (ADR-0021 Decision 3 amendment)

**Once the rung-3 enforce cutover lands, all Guardian enforce runs on the queued-consumer thread, not inline** (rung 2 is observe-only — see §Kill-switch for what enforces during the rung-2 window).

Today, service remediation (`StartServiceW`/`ControlService` on Windows; systemd
is observe-only today) runs synchronously on the guard's own per-unit watch
thread — a blocking SCM/systemd call is milliseconds-class, and it only blocks
*that unit's* detection. On the shared mechanism a blocking call on the watcher
thread would stall detection for **every** unit that mechanism multiplexes — the
exact hazard tracked by **#2014** (a blocking inline consumer wedges the Windows
IOCP worker's reap loop, refusing all new file watches fleet-wide).

Decision: Guardian enforce is a **queued** consumer. The mechanism watcher emits
the edge; the Guardian consumer thread performs remediation. This resolves #2014
by policy — **no blocking inline consumers on any mechanism**, and the emit-enqueue
and `SparkFaultFn` paths are non-blocking and never re-enter the meaning layer on
a watcher thread. Latency class is unchanged or *better*: today's Windows enforce
already blocks its own detection thread under an enforce storm, whereas the queued
path keeps detection flowing while remediation drains separately. Resilience
(`ResilienceStrategy::decide`), enforce-gating, and the ACCESS_DENIED query-only
fallback are preserved in the consumer.

**Enforce is never *silently* dropped.** The queued tier drops **oldest** on
overflow (`kDefaultQueueCap=1024`) — for the *observe* stream that is acceptable
lossy telemetry, but a silently-dropped **enforce** edge is a skipped remediation,
a compliance regression versus today's never-drop per-unit thread. Guardian
separates a **bounded enforce lane** from the observe lane with a precise overflow
contract (not literally unbounded, which would risk agent-RSS OOM under an enforce
storm — the storm today's per-unit thread survives): on enforce-lane pressure the
affected rule flips to `errored` and emits a queue-drop fault (§Health) — a **loud,
operator-visible** degradation, never a silent oldest-drop. So an enforce edge is
either delivered or converted to a visible `errored`, never discarded unseen.
(UP-3, sre F1, security-guardian, unhappy-path Gate-8.)

**Per-`spark_key` FIFO delivery + bounded coalesce (enforce correctness, not
telemetry).** Edges for one `spark_key` are delivered to the consumer in FIFO
order; a burst is **coalesced to the latest terminal state per key**, never
reordered. This is load-bearing for Service: `service_classify_edge` depends on
running→stopped→running ordering, and a reordered stop-then-start under queue
pressure could re-enforce a stale run-state (the dequeue re-gate below re-checks
local deployment/enforce-arm state, not *edge recency*). Coalesce-to-latest also gives the enforce
lane something to collapse against under a storm, bounding growth. (UP-12.)

**Enforce is re-gated at dequeue, not enqueue.** An edge can sit queued while the
rule is undeployed, its Baseline un-pushed, or its scope revoked. The agent
consumer re-checks the gate **at dequeue** against an **in-memory snapshot of the
deployed-rule set** (rule_id → `enabled`/`enforcement_mode`) that the consumer
maintains, refreshed write-through on every `GuaranteedStatePush` (the push write
and the dequeue read are synchronized under the consumer's `mtx_` — the discipline
`apply_rules` already uses — but the lock is read → copy the enforce decision →
**released before** the blocking SCM/systemd call, never held across it, or a slow
remediation would head-of-line-block the very disarm push meant to stop it; the
resulting sub-ms read-to-enforce TOCTOU is the same residual window as approval
withdrawal below). **This is an
in-memory read, never a per-edge SQLite hit:** the `__guardian__` KvStore is the
durable backing for the snapshot (persisted **before** the in-memory update — the
same persist-before-arm order `apply_rules` uses, so a crash rebuilds from the
persisted set, never a stale snapshot; read once at start/re-arm for restart continuity),
never queried per dequeued edge — a synchronous DB read on the enforce-dequeue path
would, under an enforce storm, let `__guardian__` lock/disk latency throttle the
consumer and inflate `queued_dropped_total`, converting an *authorized* enforce into
a spurious "loud degradation" (sre, UP-6). A stale queued edge for a rule the
snapshot no longer shows as deployed-and-enforce-armed is dropped, never enforced.
If the snapshot cannot be built at start/re-arm (corrupt/format-skewed `__guardian__`),
the affected rule fails **closed** — marked `errored`, never enforced off a stale or
absent snapshot, never silently skipped (UP-4, mirroring the arm-time posture above).

The server-side gates — `deployed_member_rule_ids()` (deployed snapshot),
`dangerous_enforce_in_spec`, and the Decision-9 digest-bound approval — are validated
**at push time on the server** (all three symbols are server-only; `agents/` links
none of them), and their result is what the pushed rule set encodes. **Approval
withdrawn *after* the last push** reaches the agent only via a fresh
`GuaranteedStatePush` that disarms the rule (server-mediated) — the pushed
`GuaranteedStateRule` carries no approval digest (its integrity fields are
`enforcement_mode` + a *deferred* `signature` only), so the agent **cannot** re-check
post-push approval-withdrawal at dequeue without a new proto field. **Trigger
contract (LOAD-BEARING, rung 3):** because `Push` is a human-gated step distinct from
`Write` (Baseline model), withdrawal is NOT auto-propagated — the enforce-cutover rung
MUST make approval-withdrawal *enqueue* a disarm push that **reconciles the agent's
armed set + snapshot** — today only a `full_sync` reconciles (it calls
`stop_all_guards_locked()` then re-arms); a *delta* `enabled=false` currently
persists the rule but `apply_rules`→`start_guard_for_rule_locked` re-arms it
unconditionally (no `enabled()` gate on the delta path), so the `enabled=false`
route needs a **new per-rule teardown-on-delta in `apply_rules`** at this rung.
Either way it must not merely re-gate
future dequeues (a rule with a live watcher but no queued edge would otherwise enforce
on its next drift). Until that lands, the residual window (a de-authorized rule keeps
enforcing until the next push/reconcile) is the **same window today's per-rule
`IGuard` already has** — not a Stage-2 regression — but unbounded absent the
disarm-on-withdrawal contract. The permanent close (an on-agent, dequeue-time approval
check) needs the deferred approval-digest proto field, tracked as a Guardian-wide
follow-up issue; adding it now is **out of scope for Stage 2** — the wire stays
byte-compatible (§Scope). (security-guardian, architect, compliance, unhappy-path
UP-1/2/13.)

**ADR-0021 Decision 3 wording** described the inline tier as the home of Guardian
enforce with a "µs-bounded" guarantee. As shipped (spark.hpp header, owner
decision 2026-07-06, #1938) the tier is **median-µs, not hard-bounded**, and
Stage-2 enforce is **not** an inline occupant. The amendment restates the inline
tier as **reserved for future genuinely-µs enforce**, admitted only behind the
narrow enforce-capability handler signature (no dispatcher, no plugin host — a
plugin call is a compile error, per Decision 3) *and* watchdog-histogram evidence
that a given enforce action stays inside budget. Registry write-back is the
plausible first candidate; it is **not** promoted in Stage 2.

Pre-Stage-3 dependency: `Service::watch()` SCM latency is currently unbounded
under the ops lock (`spark_engine.hpp:358-361` warns a hung SCM RPC stalls it
"with no bound at all"); #2011's per-mechanism-type lock (rung 0) removes only
*cross-mechanism* coupling. Gate rung 3 on a measured Service-arm-latency ceiling
(or the walk-off-`mu_` restructure the header defers). (architect S4.)

## Health / status surface — the #1939 checklist

Per ADR-1005 (headless platform) a new capability lands on REST **and** MCP, or
records an exception. The spark/guard health signal lands on both, carries the A4
error envelope and A2/A3 discovery metadata (enumerable via `/api/v1/openapi.json`
and MCP `tools/list`), and enforces RBAC + audit at the API layer — not a
dashboard fragment. This section ticks every #1939 item.

### Fleet metrics (agent heartbeat → Prometheus)
- **Agent:** emit `SparkEngineStats` as `yuzu.spark_*` heartbeat `status_tags`.
  `SparkEngineStats` (`spark_engine.hpp:81`) carries `armed_faulted`,
  `watch_faults_total`, `mech_watch_rejected_total`, `mech_quarantined_total`,
  `mech_slow_op_total` (the #2011 counters already exist in the struct, not yet
  emitted) **plus** `queued_dropped_total`, `consumer_errors_total`, and the
  inline-watchdog fields — the queue-drop/consumer-error counters are load-bearing
  for the never-drop-enforce guarantee and must be surfaced, not just the mech
  counters (sre F1). **Add `mech_unsupported_total{os,mechanism}` (new — not in
  `SparkEngineStats` yet):** a platform-rejected rule never arms, so none of the
  fault/watch counters count it; this dedicated counter backs the `unsupported`-state
  never-silent guarantee at rungs 2–3 (§Platform-rejection) and gives the denominator
  to distinguish "no rules of this type deployed" from "rules deployed, rejected by
  platform" (sre, consistency, happy-path). **Shape (rung-1, sre):** the agent
  exports flat key→value heartbeat tags (`kNetTag*`-style scalars), and every sibling
  `SparkEngineStats` counter is a flat scalar summed across mechanisms — so the
  `{os,mechanism}` breakdown is realized as **separate per-type scalar counters**
  (file / registry / service), not a single labelled series. **Corrected as built
  (rung 1):** these are emitted **SPARSELY — omitted when 0, never pre-seeded** (an
  earlier draft of this bullet said "pre-seeded to 0", which contradicted this same
  doc's §Server and the `yuzu_fleet_net_*` precedent). The server clears each gauge
  family per sweep, so an absent series means "no agent reported it", never a
  fabricated 0 — the absent-not-zero rule in `docs/observability-conventions.md`.
  Sparse emit also keeps a quiescent agent's heartbeat at two tags rather than ~15.
  Also emit `yuzu.spark_enforce_active` (rung 2, the detect-only-vs-enforcing signal,
  §Kill-switch).

  > **RUNG-2 TELEMETRY CONTRACT — read this before touching the counters (#2083).**
  > The obvious rung-2 move — "counter-type the `yuzu_fleet_spark_*` sums so `increase()`
  > works" — is **UNIMPLEMENTABLE**, and an earlier draft of this doc and of
  > `docs/prometheus/yuzu-alerts.yml` both said to do it. A fleet **SUM over a churning
  > agent population is not a valid counter**: it DECREASES whenever an agent ages out of
  > the staleness window or restarts (its cumulative counters reset to 0), Prometheus reads
  > any decrease in a counter as a RESET, and `increase()` then manufactures a false spike
  > out of an agent merely going away. `clear_gauge_family()` makes it worse — series go
  > absent and reappear.
  >
  > The correct design: the **agent keeps shipping the cumulative absolute value**
  > (idempotent under a duplicated or lost heartbeat — an agent-side delta is NOT: a
  > duplicate double-counts and a loss is gone forever), and the **server** holds
  > last-seen-per-agent and does `counter.inc(max(0, new − old))` with reset detection
  > (`new < old → inc(new)`). Server state is ~10k × 11 × 8B ≈ 1 MB. That single change
  > also fixes the **`absent == 0` reader contract**, which today forecloses change-gated
  > emit and forces every agent to re-ship unchanged counters on every heartbeat
  > (~68 B → ~556 B at rung 2; ~16 GB/day fleet-wide at 10k agents). Same root, both ends.

  **Rung-1 task:** introduce `kSparkTag*` tag-key constants
  (none exist yet) and pin them with a `static_assert` in a new `test_spark_*`
  test, mirroring the `kNetTag*` pin precedent (`test_network_perf_model.cpp`) —
  this doc does not reuse the net pin's own location. Omit the
  tags entirely when the kill-switch is set, so fleet rollups reflect genuine state
  (the `--dex-disable` posture).
- **Server:** mirror the net-gauge block in `AgentHealthStore::recompute_metrics`
  (`agent_registry.cpp:1290`) into `yuzu_fleet_spark_*` gauges. Use the
  `clear_gauge_family` → repopulate idiom (`:1300`) so an unreported metric goes
  **absent, not fake-zero**. Carry an **`os` label** (Registry and File are
  **Windows-only** — non-Windows `make_*_mechanism()` returns `nullptr`; Service is
  Windows-SCM **+** Linux-systemd, the only two-platform mechanism; **macOS has zero
  working mechanisms today** — so an unlabelled aggregate
  conflates "healthy, nothing armed on this OS" with "mechanism never connected",
  `docs/observability-conventions.md`) and a `yuzu_fleet_spark_reporting`
  denominator gauge mirroring `yuzu_fleet_net_reporting`. The `yuzu_fleet_spark_*`
  family includes `yuzu_fleet_spark_unsupported` (from the per-type
  `mech_unsupported_total`) and `yuzu_fleet_spark_enforce_active` (the rung-2
  detect-only-vs-enforcing signal, §Kill-switch). (sre F2.)
- **Alerts (#2011 + sre F1):** `mech_watch_rejected_total` rate > 0
  (denial-of-detection), `mech_quarantined_total > 0` (page-worthy, should stay 0),
  `mech_slow_op_total` rate (stalled watcher), an `armed_faulted` gauge, and a
  `queued_dropped_total` rate > 0 on the Guardian consumer (dropped enforce = a
  silent compliance failure). The last two ship with rung 1/3, not deferred to the
  per-rule surface. Alert expressions **must preserve the `os` label** (never
  `sum without(os)`) — a cross-OS aggregate is meaningless when a mechanism is
  single-platform, mirroring the gauge rationale above (sre).

### Per-rule health (the REST + MCP surface)
- **Ingest:** implement the `action == "status"` branch in
  `ingest_guardian_response` (`server/core/src/guardian_ingest.cpp:146`, currently
  a debug-and-drop TODO). Parse `GuaranteedStateStatus`, persist the per-rule
  `GuaranteedStateRuleStatus.guard_healthy` (proto field 8 — **defined today,
  never ingested**) plus fault counts.
- **Trust boundary (LOAD-BEARING).** Agent-reported `guard_healthy` is a **claim,
  not ground truth** — a skewed or hostile agent can self-report healthy while its
  Guardian is dead, hiding a dark endpoint (#1685 lesson). The authoritative "is
  this agent actually enforcing" signal stays **server-side report freshness**
  (heartbeat/receipt-time liveness, never agent `collected_at`); per-rule health
  goes **absent, not fake-healthy** when reports stop. Corroborate self-reported
  health against the agent-granularity mechanism-liveness tags (§Fleet metrics) —
  e.g. an agent reporting all-healthy while its Service mechanism reports inert or
  `armed_faulted` — not against per-rule event silence (a steady compliant rule is
  legitimately silent, per the mechanism-level liveness rule above).
- **Presume-dead-until-proven-live — liveness is a property of the MECHANISM, not
  the rule.** A watch that armed and then went silently deaf (bus/SCM collapse with
  no failing op) may never fire a `SparkFaultFn`. Detection is therefore **presumed
  dead absent positive mechanism liveness**: each mechanism proves liveness at the
  *connection/registration* level (sd-bus connection alive + match registered; SCM
  handle alive; IOCP port serviced), and when a mechanism's liveness lapses **all
  rules it carries** flip to `errored`. Liveness is explicitly **not** keyed on
  per-rule event cadence — a steady-state compliant File/Registry rule that nothing
  ever changes produces no events and has no periodic self-check, so a rule-cadence
  staleness bound would false-trip healthy quiescence to `errored` (independently
  flagged by both happy-path and unhappy-path at Gate-8). Likewise the trust-boundary
  corroboration (below) reads *mechanism* liveness + report freshness, not rule
  silence. (UP-5, UP-8, security-guardian — the single mitigation covering the
  widest silent-failure blast radius.)
- **Storage:** extend `guardian_agent_rule_status` (`guaranteed_state_store`) with
  a health/fault dimension beyond the current 3-way `compliant|drifted|errored`
  verdict, under the same older-event-can't-regress-newer guard as the verdict
  upsert; migration default = **unknown, never healthy**; write via `RETURNING`
  (avoid the `sqlite3_changes()`-after-`step()` hazard, #1033); the column inherits
  the parent table's retention policy (state one line, per the data-store-change
  requirement). **PG-migration interaction:** `GuaranteedStateStore` is SQLite
  today *and* on the Postgres ladder (`docs/postgres-migration-ladder.md`, "ALL
  existing server stores migrate", ADR-0006 Update 2026-06-22). Land the column in
  the store's PG-target schema, or coordinate with that store's PG author so the
  health dimension is carried across the cutover rather than stranded. (architect
  S2, UP-9, consistency, compliance.)
- **REST:** fill the zero-stub fleet + per-agent status routes
  (`rest_api_v1.cpp:7313` `/guaranteed-state/status`, `:7328`
  `/status/{agent_id}` — both hardcode zeros with a "lands in Guardian PR 4"
  note). The working `/device-compliance` route (`:7346`, scoped-perm +
  fail-closed `guardian.device.view` audit via `emit_behavioral_audit`) is the
  template — reuse its A4 envelope + audit posture.
- **MCP:** add a `get_guardian_status` tool alongside `get_guardian_schemas`
  (`mcp_server.cpp:352` def table, `:760` security `{GuaranteedState, Read}`,
  `:2922` dispatch), honoring the tier-check-before-RBAC ordering, kill-switch
  coverage (`--mcp-disable`/`--mcp-read-only`), **and audit coverage of the status
  read** — via the MCP audit path (`try_persist_audit`, **set-and-proceed**), NOT
  REST's fail-closed `emit_behavioral_audit`/503; the failure posture is deliberately
  per-surface (CLAUDE.md: REST fail-closed 503, MCP set-and-proceed), so the MCP tool
  must not copy REST's fail-closed branch — that `docs/mcp-server.md` requires,
  with `JObj`/`JArr` output. **Align with the UCE workstream's planned full MCP SSE
  streaming — this is a request/response status read, not a new streaming surface;
  live health streams ride the UCE stream when it lands, not a parallel channel
  built here.**

### Platform-rejection surfacing
**Any rule whose mechanism is unavailable on the host** — not just Service. Per the
corrected os-matrix (§Fleet metrics): Registry and File rules reject on **Linux and
macOS** (both Windows-only), Service rules reject on **macOS / Linux-without-libsystemd**,
and **every** mechanism rejects on **macOS**. In each case the factory returns
`nullptr` and `arm()` returns a typed `std::expected` rejection. Such a rule surfaces
as a **distinct terminal state — `unsupported`, NOT reason-tagged `errored`** (one
status token, not two): `errored` already means "failed to arm/evaluate" and feeds
the page-worthy `mech_quarantined`/`armed_faulted` alerts, whereas a cross-platform
Baseline reaching a host that structurally lacks the mechanism is a *routine,
expected* condition — tagging it `errored` would light up health alerts for benign
cross-platform deploys (architect S3, cross-platform, reversing the earlier draft's
recommendation). **Discriminator (not string-matching):** `unsupported` vs `errored`
is decided by *whether a mechanism is registered for the rule's type on this host* (a
pre-arm capability check), never by pattern-matching the `arm()` rejection string —
`arm()` returns an untyped `std::expected<…, std::string>`, so the consumer must not
parse the message to classify the terminal state. Likewise a
`mech_watch_rejected` (watch-cap) rule surfaces per-rule `errored`, not only a
fleet-rate alert (UP-14). **Sequencing (UP-6):** the terminal *state* is reached at
**rung 2** — arming begins there and rung 2 ships the platform-rejection state
(§ladder) — and is operator-visible from rung 2 via the **rung-1 fleet gauge**
`mech_unsupported_total{os,mechanism}` (§Fleet metrics) — deliberately NOT
`armed_faulted`/`errored`, which the paragraph above keeps the `unsupported` state
out of. The **per-rule REST + MCP status surface** that makes each rule's state
individually queryable lands at **rung 4** (§ladder); through rungs 2–3 the "never a
silent never-evaluate" guarantee is carried by the fleet metrics, not per-rule
REST/MCP — i.e. **fleet-loud but per-rule-silent**: an operator sees the aggregate
count ("N unsupported on macOS") but cannot identify *which* rule on *which* device
until the per-rule surface lands at rung 4 (unhappy-path). **Vocabulary wiring
(rung-4 task):** `unsupported` is a *new* terminal
token — a new string *value* in the existing `status` field, not a new proto field
(byte-compat holds). Until the status vocabulary is extended (the
`guaranteed_state.proto` status comment, the `guaranteed_state_store` vocab, the
OpenAPI enum, the MCP output schema, the ingest parser branch, and a fold-guard
test), the REST route folds any unrecognized state
to `pending` (`rest_api_v1.cpp:7555-7563`), so `unsupported` would surface
indistinguishably from a genuinely-unreported rule. Wire the token in the same rung
that fills the surface.

### Inert-mechanism distinguishability
A mechanism whose bus/SCM connection never opened at `start()` (non-systemd host,
container without a system bus) is today indistinguishable from "no Service sparks
configured." A mechanism-up gauge (or an `inert` reason on the fault channel)
distinguishes them; **owned by rung 1** (observe-only), not left open. (sre F3.)

> **SHIPPED IN RUNG 1 — the 2026-07-12 deferral below was WRONG and is withdrawn.**
> The rung-1 governance re-run (2026-07-13) had three agents independently reach the
> same conclusion — cross-platform, sre (which explicitly *rebutted* the deferral), and
> Gate-4 consistency. The deferral rested on "inert liveness needs arming to carry
> signal." It does not: **inertness is known at `start()`**, no arming required, and all
> three mechanisms already log it there. Worse, deferring it shipped a live
> misreport — `Dockerfile.agent` installs `libsystemd0` but a container has **no system
> bus**, so *every containerised Linux agent* advertised a `service` capability whose
> every `watch()` would be refused: "looks healthy, can detect nothing".
>
> Rung 1 therefore ships an `inert` bit on `SparkMechanismStats`, set at `start()` by
> each mechanism, and **excludes inert mechanisms from the `yuzu.spark_mechs` capability
> CSV** — so `yuzu_fleet_spark_mechanisms{os,mechanism}` now counts only mechanisms that
> are registered **and functional**. Inert mechanisms still report their counters;
> inertness suppresses the capability *claim*, not the telemetry.
>
> Still genuinely deferred to rung 2 (#2084): the **armed-but-deaf** liveness signal (a
> watcher that died after arming) and `mech_unsupported_total` (an arm-rejection counter
> — nothing arms at rung 1, so it is structurally 0). Those really do need arming.

### Not-running distinguishability (rung 1)
A spark-capable agent reports exactly one of four postures, and each is distinguishable
on the wire: **RUNNING** (`spark_running=1` + capability CSV), **FAILED** (`=0`, no
`spark_disabled` key — enabled, but boot-time instantiation threw), **DISABLED** (`=0`
plus `spark_disabled=1`), and **ABSENT** (no `yuzu.spark_*` key at all — a pre-rung-1
agent, or a dead one). Rolled up as `yuzu_fleet_spark_{reporting,failed,disabled}{os}`.

As first built, the FAILED path emitted *nothing*, making it byte-identical to DISABLED
and to ABSENT — so a fleet where spark failed to boot on 30% of endpoints was
**unobservable**, which defeats rung 1's entire stated purpose ("prove the engine runs
and reports at rest"). The DEX sibling already had this right, emitting
`dex_observer_armed=0` when enabled-but-deaf rather than going quiet. Alert on `failed`;
never on `disabled`, which is an operator decision. (Gate-4 consistency + UP-10.)

### Audit-on-arm
The arming path (Guardian's `apply_rules` / `start_local` calling
`arm(Service, …)`) emits an audit event at the Guardian layer, matching the
existing Guardian audit convention (verb + evidence-continuity mapping). Because
arming first runs for real at **rung 2**, audit-on-arm ships **at rung 2**, not
rung 4 — otherwise rungs 2–3 arm and enforce in production with no audit trail, a
control gap in the exact window enforcement first moves (compliance BLOCKING,
UP-13). Enforce-action audit verbs are lifted verbatim into the consumer and
covered by the evidence-continuity gate, not just arm.

## Kill-switch

`--spark-disable` / `YUZU_AGENT_SPARK_DISABLE`, mirroring `--dex-disable`
(`agent.hpp:56`, `agents/core/src/main.cpp:199`): a `Config` bool, CLI flag with
`envname`, read **at construction — boot-time only**. Like `--dex-disable` it is a
deploy-time opt-out requiring a restart to take effect; a live change is
**ignored-with-audit**, never a partial-path teardown (UP-1, sre F5 — the earlier
draft's "config-pushable, not a redeploy" phrasing overstated this and is
corrected). During the cutover window (rungs 2–4) both detection paths are compiled
in and the flag selects **exactly one** at instantiation.

The "never both drive enforcement at once" property (which the Decision-11
amendment leans on) requires the flag to be the single source of truth at **both
the instantiation site and the `start_local`/`apply_rules` arm sites**, plus a
central mutual-exclusion keyed on rule_id/unit so no unit is ever watched by both
an `IGuard` and a spark (invariant test: no unit appears in both `guards_` and the
spark arm set). (UP-2, security-guardian LOW-4.) The final rung deletes the legacy
guards and the switch becomes a hard on/off for spark detection.

`--spark-disable` default posture: **observe rung (2)** defaults to the spark path
(safe, detection-only); the **enforce and deletion rungs (3, 5)** default to the
legacy path until burn-in, so a first-customer fleet is not switched onto new
enforcement by default (enterprise-readiness). The default is recorded explicitly
in each rung's PR. **What enforces during the rung-2 default window:** with the
spark path selected in observe-only mode and the legacy `IGuard` not instantiated,
Guardian at rung 2 **detects but does not enforce** (spark enforce arrives at
rung 3). An operator who needs continued enforcement during rung-2 burn-in flips to
`--spark-disable`, selecting the legacy path (which still enforces). This is a
deliberate, greenfield-acceptable detect-only burn-in window, not an accidental
enforcement gap. **This window MUST be operator-visible, not doc-only (UP-7,
compliance, enterprise-readiness):** the agent emits a boot log naming the active
detection path and its enforcement posture — at rung 1 the legacy `IGuard` path
still enforces (no consumer yet) so it simply names the active path, and from
rung 2's spark-observe-only default it WARNs that enforcement is suppressed (e.g.
"Guardian: spark path OBSERVE-ONLY — enforcement suppressed for spark-managed rules;
--spark-disable restores the enforcing legacy path"). Rung 2 also emits a distinct fleet signal
(`yuzu_fleet_spark_enforce_active` gauge / heartbeat tag) separating "configured
enforce, actually enforcing" from "configured enforce, downgraded to observe" — the
same "loud, never silent" bar the enforce-lane drop already holds (§Enforce path).
A rung-2 build also ships a `changelog.d` fragment + `docs/user-manual/guaranteed-state.md`
upgrade note for this enforcement-posture default change (not deferred to rung 5).

## Dependencies & issue dispositions

- **#2011 (HARD gate, rung 0) — LANDED (lock half).** The engine-wide
  `mech_ops_mu_` (introduced by #1994's M2 fix) is downgraded to per-mechanism-type
  `mech_ops_mu_by_type_` (`std::map<SparkType, std::mutex>`), so a slow `watch()`
  on one mechanism can no longer block arm/disarm on another. Cross-mechanism
  coupling is closed; the residual same-type stall (an unbounded `watch()` still
  blocks its own type's queue) is a distinct, deferred walk-off-`mu_` follow-up,
  gated as a Stage-2/rung-3 pre-arm dependency (measured Registry/Service
  `watch()` latency ceiling). The observability half of #2011 (per-type
  `SparkEngineStats` emission + alerts) is DEFERRED to rung 1, where SparkEngine
  is first instantiated.
- **#2014 (BLOCKING-before-Stage-2):** resolved by the no-blocking-inline-consumer
  policy + never-drop enforce lane (§Enforce). Whether to *additionally* decouple
  the Windows file mechanism's emit-delivery from its completion-reap loop
  (option (b)) is recommended as rung-3 defence-in-depth given the fault path also
  rides the reap thread (UP-7) — decide at the enforce-cutover rung.
- **#1938:** closed by the Decision 3 wording amendment (median-µs, inline
  reserved). GitHub issue closed post-merge.
- **#1929** (fault severity tiering + Linux Subscribe-degrade signal) informs the
  health surface's fault mapping. **Deferred (tracked, not Stage-2 blockers):**
  #1933 (Registry re-arm retry timer), #1936 (fault-flap debounce unification),
  #2015 (promote hardcoded timing/cap constants to `Config`).

## Parity, §24, and gates (ADR-0021 Decision 11 amendment)

ADR-0021 Decision 11 specified a long-lived integration branch merged to `dev`
atomically after parity + resource + evidence gates. Stage 1 merged to `dev`
directly (unwired, so no interleave risk), de-facto departing from that posture.
Stage 2 is where old and new detection first coexist on a running agent.

**Amendment: incremental per-consumer cutover on `dev`, behind the kill-switch,
with the three gates applied per rung.** The kill-switch guarantees old and new
never *both drive enforcement* on one agent at once (the flag picks one — the
mutual-exclusion invariant above makes this airtight), which is the property
Decision 11's "never ship interleaved" protected. Because Yuzu is still greenfield
(no customer mid-fleet), this trade is safe now; it is **not** asserted as the
posture once a pilot customer is deployed — from the first customer, protocol and
cutover changes must support rolling upgrade. The wire protocol staying unchanged
(§Scope) keeps a mixed-version fleet safe across the multi-week ladder. **Each rung
runs the full 8-gate `/governance` pipeline** (not an abbreviated review); each
rung's report is retained as change-management evidence (SOC 2 Workstream F) by
posting it as a **GitHub PR review (`gh pr review`) on that rung's PR** — a durable
artifact mapping onto Workstream F's "PR review records" category, never a bare git
commit hash (which can orphan, as this doc's own prior `bbe55cc9` did).

**A PR can orphan too — the rule above is necessary but not sufficient.** Rung 1 proved
it. PR #2082 carried a complete governance review and GitHub reported it **MERGED** — but
its base was `fix/2011-spark-mech-ops-per-type`, a sibling branch that had *itself* merged
to `dev` the day before. GitHub did not retarget it, so the merge (and the code, and the
review) landed on a dangling ref and **never reached `dev`**. The rule was satisfied and
the evidence orphaned anyway, because it never checked where the PR's *base* pointed. An
auditor tracing "what review authorised the code running in production" would have found
nothing that resolves to `dev`.

Two corrections, both binding from rung 2 on:

1. **Every rung PR bases directly on `dev`.** Never on a sibling feature/fix branch, even
   one still open — that branch may merge to `dev` first and silently strand the second
   merge off-trunk. If a rung genuinely must stack, it is rebased onto `dev` and
   re-targeted *before* merge, not after.
2. **A PR is valid Workstream-F evidence only once its merge commit is reachable from
   `dev`** — verified with `git merge-base --is-ancestor <merge-sha> origin/dev`, **not**
   by trusting the GitHub "Merged" badge, which was true for #2082 the entire time.

Gates, applied at the marked rungs:
- **Parity:** Guardian §24 invariants verbatim — `Push` seed stays Guardian-only,
  the `__guard__` load-time + dispatch-time dual intercept both remain,
  `dangerous_enforce_in_spec` stays the single enforce-safety chokepoint (extend,
  never fork — a Linux service-enforce path must extend
  `dangerous_enforce_service_stop`), the enforced set stays sourced from
  `BaselineStore::deployed_member_rule_ids()` (deployed snapshot, not live
  members), and Guardian wire payloads stay gateway-safe (no raw proto bytes in
  the `map<string,string>` the Erlang gateway re-encodes). Event-stream
  equivalence on scripted scenarios uses tolerance bands **only for observe/debounce
  noise**; enforce-class and dangerous-drift `event_type`s require **zero-tolerance
  exact match** — a tolerance band would let a real enforce divergence pass (UP-10).
- **Resource:** detection threads drop O(rules) → O(mechanisms); idle CPU,
  wakeups/sec, **real OS thread count** (not the `watcher_units` gauge, which is a
  pool count, not `ps -T`, architect N1), and RSS old-vs-new via `/test` perf. This
  headline win is established at **rung 2** (Guardian becomes the consumer,
  replacing per-rule threads), so the resource gate runs at rung 2, not only 3/5
  (sre F4).
- **Evidence continuity:** capture an explicit **audit-verb + metric-label
  snapshot** before rung 3 and diff against it, so SOC 2 evidence automation drift
  is provably absent, not asserted absent (compliance). Verbs/labels preserved or
  explicitly remapped.

## Implementation PR ladder

Each rung is an independently-governed PR on `dev`, run through the full
`/governance` pipeline.

0. **#2011 gate — LANDED (lock half).** Per-mechanism-type `mech_ops_mu_by_type_`.
   Pure engine-internal refactor; acceptance tests: a blocking `watch()` on
   mechanism A does not delay `unwatch()` on mechanism B (cross-type decoupling),
   and a blocking `watch()` DOES still serialise a second arm of the same type
   (per-type control). Observability half (per-type stats + alerts) deferred to
   rung 1.
1. **Instantiate + observe — LANDED.** SparkEngine constructed in `agent.cpp` behind
   `--spark-disable`; `yuzu.spark_*` heartbeat tags (queue-drop/consumer-error +
   per-type mech counters) + `yuzu_fleet_spark_*` os-labelled gauges + reporting
   denominator + the capability signal `yuzu_fleet_spark_mechanisms{os,mechanism}` +
   a reviewed alert group shipped **commented out**, and the boot log naming the active
   detection path (legacy `IGuard` still enforcing at rung 1). No consumer yet;
   proves the engine runs and reports at rest. Guards against a boot exception (thread
   exhaustion) by degrading to no-spark.

   **Shipped beyond the original rung-1 scope**, both added by the rung-1 governance
   rounds — the ladder must not be read as still deferring them:
   - **The `inert` bit** (§Inert-mechanism distinguishability). A mechanism that started
     but could not bind its OS facility is excluded from the capability CSV. The earlier
     deferral to rung 2 was WITHDRAWN: inertness is known at `start()`, needs no arming,
     and deferring it shipped a live misreport on every containerised Linux agent
     (`libsystemd0` is installed, but a container has no system bus).
   - **The four-posture wire contract** (§Not-running distinguishability): RUNNING /
     FAILED / DISABLED / ABSENT, rolled up as
     `yuzu_fleet_spark_{reporting,failed,disabled}{os}`. Without it a fleet-wide spark
     boot failure was invisible — a failed agent emitted nothing, identical to a
     deliberate opt-out.

   **Genuinely still deferred to rung 2** (#2084): the ARMED-BUT-DEAF liveness signal (a
   watcher that dies after arming) and `mech_unsupported_total{os,mechanism}` — both need
   arming to carry signal. The alert group is enabled at rung 2 (#2083), and NOT by
   "counter-typing the fleet sums" — see §Fleet metrics for why that does not work.
2. **Guardian detection consumer** — the queued consumer + arm-per-rule (with the
   `spark_key→rule` index, refcounted shared watchers, and the re-arm/initial-eval
   contract), detection only (observe mode), behind the switch, both paths compiled
   in. **Ships audit-on-arm, platform-rejection state, the mutual-exclusion
   invariant, the `yuzu_fleet_spark_enforce_active` enforce-suppressed signal, and a
   `changelog.d` fragment + `guaranteed-state.md` upgrade note for the rung-2
   enforcement-posture default change** (detect-only by default; `--spark-disable`
   keeps the enforcing legacy path). Gates: event-stream equivalence parity + the resource gate.

   **Rung 2 is delivered as an inner ladder of its own** - the surface is too large
   for one governed PR, and ADR-0021 Decision 11 (as amended) requires the parity,
   resource, and evidence-continuity gates **per rung**, not once at the end. This
   inner ladder was previously recorded only in commit messages and a local plan
   file, which is what caused PR #2224's Gate-1 scoping error (the range was written
   against a memory-recalled merge-base and inner rungs 2-6 went in ungoverned).
   It is written down here so a gate can be scoped against it.

   Inner rungs 1-7 **merged as PR #2224** (~45 files), all pure/against-fakes
   agent-internal code with no production call site - the subsystem is compiled but
   unreachable (`wire_spark_engine()` has zero callers):
   - **1.** Tri-state + snapshot reshape of `guardian_rule_eval` (`ReadResult<Snapshot>`
     → `EvalOutcome{Silent|Emit|Unhealthy}`; Unknown never mutates the emit-decider).
   - **2.** `guardian_outbox` (header-only, pure): FIFO drain, retain-on-failure,
     coalescing domains, generation purge, cap ⇒ reject-new-key backpressure.
   - **3.** `GuardianSparkRuntime` core against fakes: registry mutex, per-rule
     generations, per-key eval mutex, one `evaluate_key` for all paths, detach-safe
     `shared_ptr` capture. TSan + ASan detached-handler checkpoint.
   - **4.** Convergence scheduler: per-type lanes, jitter, size+mtime precheck before
     re-hash, byte budget, non-droppable pending-initial priority.
   - **5.** Platform `StateReaders` (file handle-scoped #807 hashers, registry
     `RegOpenKeyExW`, service SCM/sd-bus, absent→Stopped), **plus F3** - the
     bounded/cancellable I/O executor (spawn-per-read detached workers, per-class
     deadlines, keyed single-flight, the executor's `active_worker_count()` - surfaced to
     the engine as `active_io_workers()` - for the orphan-exit count).
   - **6.** `enabled()` fix (own commit, a legacy behaviour change): a disabled rule
     in `apply_rules` no longer arms, and an already-armed rule pushed disabled is
     stopped.
   - **7.** `GuardianEngine` integration: `reconcile_rule_locked()` as the sole
     arm/disarm chokepoint, `wire_spark_engine()` as a rollback-on-failure transaction,
     the `SparkAvailability` state, decl-order/stop-order prep, and the F3 orphan-exit
     enforcement (`hard_exit()` when an I/O worker outlives the grace).

   Remaining inner rungs (this program):
   - **9a.** This decision record + the inner ladder + the gates-per-rung note.
     Docs-only; precedes 7.7 because 7.7's shape depends on R1-R4. **(this change.)**
   - **7.7a.** Lifecycle-only wiring. Reorder boot to **construct → register
     mechanisms → `SparkEngine::start()` → `wire_spark_engine()` → `start_local()`**
     (the header requires wiring before `start_local()`, and the capability set
     `reconcile` reads is only correct after `start()`; whether `arm()` before
     `start()` is safe per mechanism must be **pinned, not discovered**). Extend the
     boot latch across object publication and wiring; prove every early-return and
     concurrent-`stop()` path; exercise wiring rollback. `prefer_spark` hardcoded
     `false` - **zero placement behaviour change.** Ships R4's 7.7a log set.
     Qualifies shutdown and the F3 hard-exit path, **including its interaction with
     `Restart=always`** (see below).
   - **7.7b.** The cutover (R1): `prefer_spark = !cfg_.spark_disable`. Real rule
     placement; the `unsupported` terminal state (R2) + rung-8 telemetry co-landed;
     audit-on-arm; mechanism liveness; R4's 7.7b heartbeat tags including
     `yuzu.guardian_backend`; the reconcile-test rewrites (R2 consequence 1). Runs
     the Windows churn rig with the spark path selected. **This is where detection
     moves to spark and legacy enforcement stops** (until rung 3).
   - **8.** `mech_unsupported_total` + `yuzu_fleet_spark_unsupported` - **folded into
     7.7b** per R2, not a later rung (unsupported must be loud the moment a rule can
     land on spark).
   - **10.** Parity + durability + integration matrix. Semantic ports land **before**
     7.7b where possible; live/equivalence after. Carries the **intentional-delta
     registry** (R2 consequence 2) so zero-tolerance parity survives the legacy-no-op
     vs `unsupported` difference.
   - **11.** The `yuzu-fleet-spark` alert group (#2083) enabled + promtool CI lint,
     including the `SparkFailed`-prevalence alert (R1 correlated-outage note).
   - **12.** Dissolved into 7.7b per R1. Residue only: boot WARN, `enforce_active`
     gauge, `changelog.d` fragment, `guaranteed-state.md` upgrade note.
   - **9b.** The full as-built rewrite of this §Rung-2 decision record and the ladder
     against the shipped 7.7a/7.7b/10 code, folding R3's resolved mechanism and R2's
     `unsupported`-vocab reconciliation. Docs-only; lands after 7.7b.

   **F3 × `Restart=always` (must be answered in 7.7a).** `deploy/systemd/yuzu-agent.service`
   sets `Restart=always` + `RestartSec=10` and **no `StartLimitIntervalSec`/`StartLimitBurst`**,
   so systemd's default burst limit (5 restarts / 10s) can never trip when restarts are
   spaced ≥10s apart. The F3 `hard_exit()` fires when an I/O worker is wedged past the
   grace. Against a *permanently* wedged target (dead NFS mount, hung SCM call) this is a
   10-second crash loop: exit → restart → arm the same rule → wedge → exit. Windows SCM
   recovery policy is the equivalent.

   **This is a security finding, not only an ops one.** Anyone who can wedge a read on a
   watched target inside a Baseline's scope (a black-holed NFS/SMB mount, a hung SCM or
   registry call) gets a **whole-agent** denial-of-service primitive: the crash loop downs
   every plugin, the heartbeat, and every other rule, not just the offending one.

   So the two candidate answers are **not** equivalent, and 7.7a must not treat them as an
   implementer coin-flip:
   - **Primary: degrade-and-skip-that-rule.** A wedged read isolates to its own rule and
     the agent keeps running everything else. This bounds the blast radius to one rule and
     is the required default. (It is the same "free the admission slot on deadline"
     property R3's intra-class note pins - the two findings share one mechanism.)
   - **`hard_exit()` is reserved for a genuinely uncancellable orphan** (a worker that
     cannot be cancelled and would otherwise run through static teardown - F3's original
     purpose), never as the routine answer to a wedged target. Bound it with a per-boot
     F3-trip cap.
   - **Belt-and-braces backstop:** add `StartLimitIntervalSec`/`StartLimitBurst` to the
     unit so any regression that still loops enters `failed` (paged) instead of restarting
     forever, and pair it with a **server-side flap detector** (repeated short-lived
     sessions from one agent) - a fast crash loop may exit before the heartbeat rail is
     even wired, so the agent cannot always self-report, and the F3 KV marker (R4) can go
     unreported.

   The F3 trip should page - a wedged read in the kernel is not routine.
3. **Enforce cutover** — Service/Registry remediation on the consumer thread;
   never-drop enforce lane; dequeue-time re-gate; the withdrawal disarm-push trigger
   contract (reconcile the armed set — `full_sync` today, or a new per-rule
   teardown-on-delta in `apply_rules`; §Enforce path); #2014 policy enforced;
   resilience preserved; Service-arm-latency ceiling met. Parity (zero-tolerance for
   enforce event types) + resource + evidence-continuity gates.
4. **Health surface** — `action == "status"` ingest, `guard_healthy` persistence
   (unknown-default, PG-ladder-coordinated), REST status stubs filled,
   `get_guardian_status` MCP tool (audited via the MCP set-and-proceed path, not REST
   fail-closed — §Health/MCP), presume-dead liveness,
   trust-boundary corroboration, **and the `unsupported` status-token wiring** (proto
   comment, store vocab, OpenAPI enum, MCP output schema, ingest parser, fold-guard
   test — §Platform-rejection). Doc: rewrite the `docs/user-manual/guaranteed-state.md`
   "the `/status` endpoint returns placeholder zeros — do not consume" caveat, and add
   `unsupported` to the published status vocab in `docs/user-manual/rest-api.md` +
   `guaranteed-state.md`, now that it is live (enterprise-readiness, docs-writer).
5. **Legacy deletion** — remove `guard_service.cpp` / `guard_systemd.cpp` /
   `guard_registry.cpp` / `guard_file.cpp` and the `guards_` map; the switch
   becomes hard on/off. Ships a `changelog.d` **"Breaking"** fragment (the flag
   changes from a routing selector to a hard kill-switch) + final resource-gate
   evidence.

## Doc / CLAUDE.md follow-ups

- Add a Guardian-spark routed-concern pointer to CLAUDE.md → ADR-0021 + this doc.
  Stage 1 code is in-tree, unconsumed, with no pointer today (docs-writer SHOULD).
  Deferred to **rung 1** (when SparkEngine is first instantiated in `agent.cpp`,
  the natural trigger) because CLAUDE.md is already over its own 40k-char budget
  (42,991) — trim it in the same rung before adding the row.
- `docs/user-manual/mcp.md` carries a pre-existing gap (missing `get_guardian_schemas`);
  rung 4 documents `get_guardian_status` and closes both.
- **Rung 1:** document `--spark-disable` / `YUZU_AGENT_SPARK_DISABLE` (the per-rung
  default table + the boot-restart requirement) in `docs/user-manual/guaranteed-state.md`
  — a CLI flag is `--help`-discoverable but the posture/defaults are customer-facing
  (enterprise-readiness).
- **Rung 2:** add an interim caveat to `docs/user-manual/guaranteed-state.md` — a
  cross-platform Baseline against an unsupported mechanism (macOS; Linux-without-libsystemd
  for Service; any non-Windows host for File/Registry) shows `pending` through rung 3;
  disambiguate from a non-reporting agent via the fleet gauge / audit-on-arm trail,
  not device liveness (enterprise-readiness).
- **Rung 4:** add `unsupported` to the published status vocab in
  `docs/user-manual/rest-api.md` (`/status`, `/status/{agent_id}`, `/device-compliance`
  `guards[].status`) and `docs/user-manual/guaranteed-state.md`, alongside the
  placeholder-zeros caveat rewrite already noted in the ladder (docs-writer).

## Verification

- Rung acceptance tests as listed; full agent suite green on Linux, Windows
  (DGRHP), **and macOS/Darwin** after each rung. The Darwin suite is mandatory
  (`docs/darwin-compat.md`) because Stage 2 adds macOS-specific behaviour — the
  no-mechanism `unsupported` path (§Platform-rejection — all three mechanisms are
  absent on macOS, so File/Registry/Service rules all reject there) and the
  `--spark-disable` selection — so a macOS-only regression in exactly that path must
  not pass the per-rung gate.
- Parity: Guardian §24 invariant tests pass unchanged; scripted-scenario event
  streams within tolerance (zero-tolerance for enforce types). The
  re-arm/initial-eval contract is a rung-2 parity assertion (offline-drift-caught,
  no restart re-enforce storm).
- Resource: `/test` perf shows the O(rules)→O(mechanisms) real-OS-thread drop at
  rung 2.
- Health surface: `yuzu_fleet_spark_*` os-labelled gauges visible in UAT
  `recompute_metrics`; REST `/guaranteed-state/status[/{agent_id}]` and the
  `get_guardian_status` MCP tool return real per-rule health; a
  `service-status-change` rule (and, being Windows-only, a File/Registry rule) on
  macOS surfaces as `unsupported`, not silent; a killed system bus flips its rules to
  `errored` within the liveness bound.
