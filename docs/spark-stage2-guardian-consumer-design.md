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
  - rung 9c addition (§Async-arm acknowledgment / R5) - the design itself went through six external review rounds (Astra/Codex ×4, Fable ×multiple, Kimi K3 ×2), 2026-09-07, against the plan document, not this doc directly; a seventh round (round 7, 2026-09-07) then adversarially reviewed this PR-0 write-up itself (Kimi + Codex, two HIGH findings against the transcription, folded in - see A3's Epistemic cell and the H-section citation fix); a full `/governance` pass then ran on this PR-0 commit (2026-09-07: Gate 2 security-guardian+docs-writer, Gate 3 architect+cpp-safety, Gate 4 happy-path+unhappy-path+consistency-auditor, Gate 6 compliance-officer+sre+enterprise-readiness - 10 agents total; Gate 5 chaos-injector skipped, no executable-chaos-shaped findings). No BLOCKING findings anywhere; ~25 non-blocking findings folded in directly (citation fixes, an "episode"/"expired" terminology clarification, telemetry-tag gauge-semantics guidance, a restart-remediation caveat cross-referencing this doc's own F3 crash-loop finding, an acknowledged-≠-compliant callout, a changelog fragment). One finding is a genuine, still-open design ambiguity rather than a wording fix: whether a queued-waiter's congestion-only "expired" outcome should count toward decision 7's K-bound the same as a genuine wedge - the plan's own decision-7 headline and its D3 mechanism disagree, unnoticed across all six prior review rounds; recorded as an explicit open question (R5.2) for PR-1/PR-2's own design pass, not resolved here.
history:
  - 2026-07-11 - initial design; 2 governance rounds; landed as PR #2051.
  - 2026-07-17 - rung 9a - §Rung-2 decision record (R1-R4) + the inner-ladder
    decomposition of rung 2 into the §Implementation PR ladder (rungs 1-7 merged as
    PR #2224; the 7.7a/7.7b/8/10/11/12 remainder). Records what was previously held
    only in commit messages and a local plan; the full as-built rewrite is rung 9b,
    after 7.7b.
  - 2026-09-07 - rung 9c - §Async-arm acknowledgment (R5): decouples Guardian's rearm
    window (`apply_rules`) from OS-watch confirmation, closing the ~55ms spark-vs-legacy
    gap the #3990 diagnostic measured. Independent of 9b; sequenced after PR-2c (#3848)
    and before the `prefer_spark` flip (PR-5). Matching rows added to
    `docs/spark-legacy-delta-registry.md` (A3) and `docs/spark-flip-gate.md`.
  - 2026-09-08 - rung 9c PR-1 doc pass (no design change, corrections only): ruling 14
    recorded in R5.2/R5.3 as settled design (congestion-only outcomes excluded from K;
    late results apply by current desired state; #2012/#3840 pulled forward into rung
    9c's own ladder); "expired" split into three named outcomes (admission rejection /
    queue-wait expiry / dispatched-operation timeout) with quarantined vs
    congestion-expired stated side by side; F3's orphan-grace binding pinned to the
    PHYSICAL alive-worker count and the ceiling value pinned (#4147); R5.2(a)/R5.3/A3
    made mutually consistent (#4148); R5.4's timing split into staging /
    acknowledgment / persistence to match the PR-1 implementation. Reviewed by Astra
    (`/codex opine`) against the PR-1 plan before the edits.
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
- **Enforcement behaviour is identical for the File/Registry case.** The legacy
  File/Registry guards already return false from `start()` off-Windows: a silent
  no-op, no `guards_` entry. Nothing enforces either way. What changes is reporting,
  from silence to an explicit state. This is scoped to File/Registry, not a blanket
  guarantee across every mechanism: the Service guard's legacy path (`guard_systemd.cpp`)
  opens its own independent D-Bus connection, so a spark-side registration failure or
  registered-but-inert mechanism (a containerised host with no systemd bus, per
  `guaranteed-state.md`'s own worked example) can in principle diverge from legacy's
  outcome on that one mechanism - see `reconcile_rule_locked`'s own comment on the
  `Unsupported` branch (enterprise-readiness governance finding, F7/#2298; by
  inspection, the one documented inert case shows no delta - legacy fails identically
  there too - but the guarantee is narrower than this bullet's original wording
  implied).
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
   spuriously and gets quietly weakened until it means nothing. **Shipped (F12,
   #3386):** `docs/spark-legacy-delta-registry.md`.
3. **macOS under spark preference is all-unsupported.** Both mechanism factories return
   nullptr off their platforms, so every rule on a spark-preferred macOS agent classifies
   `Unsupported`. That matches today's macOS enforcement reality, but the macOS CI leg
   must assert exactly that posture or it passes by testing nothing.

**Landed (F7, #2298):** `reconcile_rule_locked` gives `RulePlacement::Unsupported` a
distinct terminal-state branch - withdraws from both backends, tracks the rule_id in a
new `unsupported_rules_` map (per-outcome erase/insert at every other return path, swept
against the actual push contents on `full_sync`, cleared in `stop()`). All three
consequences above are addressed: (1) the reconcile tests were rewritten in the same PR,
plus a real macOS-factory test asserting the all-unsupported posture directly (not (3),
which is a rung-10 parity-gate item, still open); (2) **shipped (F12, #3386)** -
`docs/spark-legacy-delta-registry.md`. Also shipped in **the F7 PR**: the `mech_unsupported_total`
per-mechanism fleet gauge and `yuzu.guardian_backend` heartbeat tag (§Platform-rejection,
§Fleet metrics, items 8-9 below).

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

## Async-arm acknowledgment (rung 9c)

Sequenced after PR-2c (#3848) and before the `prefer_spark` flip (PR-5) — lands dormant
behind `prefer_spark_=false`, same posture as every other pre-flip PR in this document.
Settled 2026-09-07 after six external review rounds (Astra/Codex ×4, Fable ×multiple,
Kimi K3 ×2) against the plan document, transcribed into this doc as §R5, into the
registry as row A3, and into the flip-gate as §3a - plus a seventh round, an
adversarial review of this doc's own committed PR-0 transcription (not the plan),
which found and fixed real transcription defects (**corrected round, 2026-09-07**:
an earlier version of this sentence collapsed the split, reading as if all seven
rounds reviewed the plan document - contradicted its own round-7 parenthetical in the
same sentence; see the front-matter `governance:` entry above for the precise split).

### R5 - Accepted is not acknowledged: `apply_rules` never waits for an OS watch

**Ruled:** `GuardianEngine::apply_rules()` and `GuardianSparkRuntime::attach_rule()`/
`detach_all()` stop blocking on the real backend OS call (`CreateFileW`,
`RegOpenKeyExW`, the SCM enqueue). Acceptance and acknowledgment become two distinct
events: `apply_rules()` returns as soon as a push is *accepted* (queued for arming),
and the policy generation reported to the server on `yuzu.guardian_generation` only
*advances* once every accepted rule's arm has actually resolved.

**Motivation.** The #3990 diagnostic measured Guardian's synchronous rearm window
(window B: from "full_sync cleared N prior rule(s)" to "apply_rules ok") on a 62-rule
cohort: legacy median 70-86 ms, spark 127-140 ms — both figures are the diagnostic's
own committed measurand (`b_ms` in `fullsync-blackout-results.jsonl`). A teardown-vs-
rearm-span sub-split (**corrected governance round, 2026-09-07**: an earlier version
of this sentence gave specific millisecond figures for that split — spark 39 ms
teardown / legacy 11-13 ms, spark 85-92 ms rearm / legacy 59-71 ms — attributed to the
#3990 diagnostic itself; verified directly against the diagnostic's own committed run
doc and raw results file, neither of which records any teardown/rearm sub-split at
all, only the single `B` window quoted above. The split figures traced to an
uncommitted local review brief's own log-timestamp analysis during the #3990 run, not
to the diagnostic's committed measurand — removed here rather than misattributed)
is not restated as a measured fact; the root cause below explains where within B the
gap plausibly sits, without claiming a specific measured split. Root cause:
`attach_rule()` already dispatches each rule's
`backend->arm()` onto a detached `GuardianIoExecutor` worker, but the caller blocks on
`cv.wait_until` for the result while `apply_rules()` holds `mtx_`, and `detach_all()`
blocks the same way per disarm. Legacy's guards return as soon as their own thread is
spawned; spark pays the full OS-watch establishment cost inside the window legacy
never does. The requirement is that the rearm window returns fast, not that
time-to-watch-live shrinks — those are different quantities, and this design closes
the gap between them by decoupling the two, not by making the underlying OS calls
faster.

**Warrant: zero wire-protocol change.** ADR-0021 Decision 8 states the generation
counter is a reconcile trigger only, never a compliance signal — deferring
acknowledgment past `apply_rules()`'s own return is therefore consistent with the
counter's designed meaning, not a reinterpretation of it. Two further facts confirm no
new wire surface is needed: `GuardianEngine::get_status()` is dead in production
(never dispatched; a fallback that reports every rule `errored`), and a solicited
`__guard__` reply on the direct agent-to-server path is dropped by the server on
arrival (gateway-connected agents' solicited replies ARE correlated and answered
server-side — a different path, unaffected by this design either way).
`yuzu.guardian_generation` was already the only channel a client's arm state reaches
the server's *reconcile/acknowledgment* logic through (the server separately ingests an
unsolicited `guard.armed` lifecycle stream, a different channel, D2 in the delta
registry) — reporting the *acknowledged* value on the existing reconcile tag is a
purely internal change.

**R5.1 - Executor: a non-waiting dispatch form.** `GuardianIoExecutor` gains a
`submit()` overload alongside the existing `run()`: the backend call still executes on
a detached worker, but the caller does not block for the result — it is handed to a
completion callback on the worker thread instead, with the admission-time quota/
single-flight-key checks (`Stopped`/`AlreadyRunning`/`CapacityExhausted`) unchanged and
still synchronous. Today's quota/`active_worker_count()` accounting conflates "holds a
quota slot" with "counts toward the orphan-exit grace"; those become two independent
counts. **The quota slot and single-flight key release when the backend call (`fn()`)
itself returns — before the completion callback runs, not after.** A worker wedged
*inside* the real OS call therefore still holds its slot and key for as long as it
stays wedged; the existing dead-target bulkhead against a hung backend call is
unaffected by this change. The window this design actually widens is *after* `fn()`
returns but before the worker thread fully exits — while the completion callback runs
— since a non-waiting call can dispatch a fresh operation on completion, and that
refill must not itself be starved by its own predecessor's still-unreleased slot. **A slow or wedged completion callback frees its
quota slot while its thread stays alive, so quota alone no longer bounds the total
count of simultaneously-alive detached workers** — `GuardianIoExecutor` therefore also
enforces a separate physical ceiling on total alive workers (strictly greater than the
sum of all quotas; exact value pinned in the implementing PR's description, per this
document's own §7.7b item 5, which already required this for any two-count split):
admission is refused once that ceiling is reached, regardless of quota availability. A
new `GuardianDetachedWorkerRole` thread-local marker extends the existing
`WorkerHostileMutex` tripwire (`guardian_engine.cpp`'s `abort_if_worker_thread()`) to
executor worker threads, so nothing dispatched this way can ever take
`GuardianEngine::mtx_` — enforced in debug/sanitizer builds, not only by review.

**Two counts, one F3 binding (#4147, pinned in the PR-1 doc pass, 2026-09-08).** After
the split, `GuardianIoExecutor` keeps two counts: a *quota-held* count (per class and
total, checked against the class quotas at admission) and a *physical alive* count
(every detached worker whose payload has not yet been destroyed, including one that has
already returned from `fn()` and is running its completion callback while holding no
quota). `GuardianIoExecutor::active_worker_count()` reports the PHYSICAL count, released
in `TicketCore`'s destructor when the trampoline destroys the worker's payload
(`guardian_io_executor.hpp`): the latest point a detached worker can self-observe before
its OS thread exits. The uncounted tail after that release is the `State` handle release,
a notify, the trampoline epilogue and the CRT thread exit; none of it runs library code
through DSO teardown, which is the hazard F3 guards, and the existing orphan grace is
what absorbs it. A self-decremented count cannot certify its own thread's exit, so the
release point is stated as what it is rather than as "OS-thread exit". That count is
the count `GuardianEngine::active_io_workers()` (`guardian_engine.cpp`) sums for the
F3 orphan-exit grace; F3 never binds to the early-releasing quota count.
`GuardianDetachedWorkerRole` workers are in that sum by construction, callback phase
included. The physical ceiling is `kMaxAliveIoWorkers = kAliveCeilingFactor *
kMaxProcessIoWorkers` = 2 x 10 = 20 per executor instance, derived from the instance's
clamped quota total rather than exposed as a `Config` knob (an injected ceiling at or
below the quota sum would recreate the R3 starvation). A hit is reported as
`IoFailure::CeilingExhausted`, distinct from `CapacityExhausted` because the remediation
differs: quota-full means a backend call is stuck inside `fn()`; ceiling-hit means
workers are outstanding past `fn()` with quota free (slow or wedged completion
callbacks, delayed ticket release), possibly all of one mechanism type. The factor is a
policy allowance, not a structural bound: successive submissions can reuse released
quota while earlier callbacks are still alive, so it is a per-instance backstop that
can impose cross-class back-pressure. Two disarms behave differently under a refusal:
the caller-driven R5.2 disarm claim (`submit_disarm_off_lock`) is RETAINED at the head
of its key entry and re-driven by the next same-key event, never dropped; the drain's
own compensating disarm (a subscription nobody adopted) runs as a bounded `run()` on
the worker and, on a non-timeout refusal at admission, falls back to a direct
`backend_->disarm` call on that worker: alive-counted for F3, outside the class
bulkhead, never a retained claim (`guardian_spark_runtime.cpp`, `on_arm_complete`).

**R5.2 - Runtime: a per-key claim/queue state machine.** Each spark key gets a single
entry tracking its current claim (an in-flight arm or disarm, or none) and a FIFO queue
of siblings waiting behind it. A key that is already quarantined (see R5.3) rejects a
new claim immediately, before any backend call is attempted. A second rule attaching to
a key that is mid-arm queues behind the in-flight owner rather than issuing a redundant
backend call; on the owner's success every queued sibling commits inline against the
same subscription (Guardian's existing shared-watcher reuse, unchanged); on the owner's
genuine failure every sibling fails with it, since the underlying key genuinely
couldn't be armed. A disarm claim is retained until it actually executes or is
terminally superseded — never silently dropped for capacity reasons — which is what
makes "a key's disarm completes before its own rearm dispatches" true by construction
rather than by a separately-maintained ordering rule.

**Three distinct non-success outcomes, named once (PR-1 doc pass, 2026-09-08; an
earlier version of this section used "expired" for two of them).** (1) **Admission
rejection**: the executor refuses the operation synchronously (`CapacityExhausted`,
`CeilingExhausted`, `AlreadyRunning`, `LaunchFailed`); no backend call was attempted.
(2) **Queue-wait expiry**: a queued sibling's own wait ends before its key's in-flight
claim resolves; it was never dispatched. (3) **Dispatched-operation timeout**: a
dispatched operation has not returned by its deadline, location unknown - it may be
inside the real OS call, or parked on `SparkEngine`'s per-type lock (`arm_impl()`
takes `mech_ops_mu_by_type_` before `watch_guarded()`, `spark_engine.cpp`), and the
runtime cannot tell which. Only (3) is bounded by a deadline and marks the key
**quarantined**; every waiter on a quarantined key fails without a further backend
attempt until the original worker's call completes (if ever) and clears the marker.
The two stuck states, side by side so they are never conflated: **quarantined** =
dispatched, timed out, K-waivable (R5.3), recoverable when its late result arrives
(ruling 14(b) below); **congestion-expired** = outcome (1) or (2), never dispatched,
NOT K-waivable (ruling 14(a) below), recovers only on the next successful re-apply.
This
per-key quarantine marker is distinct from — and not wired to — the existing
per-mechanism `mech_quarantined_total` counter (a fleet-alerting signal expected to
stay at 0); this design's quarantine is the ordinary, K-bounded, non-alerting outcome
of a single wedged key, not a mechanism-wide fault.

**Resolved (ruling 14, 2026-09-08 - routed to Astra via `/codex opine`, then Fable as
advisor, ruled by Dave; previously flagged open by round 7's adversarial review; closes
#4148):** (a) **Congestion-only outcomes are EXCLUDED from K.** Neither a queued
waiter's own expiry nor an admission-time `CapacityExhausted` (a push that never
reached the per-key queue) is K-qualifying; only a dispatched-and-timed-out operation
whose claim is still retained is. Both congestion outcomes therefore hold the
acknowledgment, exactly as R5.3's "genuine refusal" list already did for "arm queue
full" - the two sections now agree. Accepted cost, stated as a load consequence rather
than a silent side effect: sustained same-type mechanism contention
(`mech_ops_mu_by_type_`, #2012/#3840) holds a generation's acknowledgment indefinitely
and drives repeated 25 s `full_sync` re-applies for the congestion's duration; it
self-heals once the contention clears, and it can never K-waive a healthy sibling
whose backend call was never attempted. (b) **Late results apply by CURRENT DESIRED
STATE, not by acknowledgment status.** A late success on a still-wanted rule commits
normally (subscription retained, `yuzu.guardian_arm_failed` cleared for that rule, its
"armed" record staged per R5.4); a late success on a withdrawn, replaced, or stopping
rule is disarmed - no leak either way. This is not a reversal of #3816 (PR #3979):
#3816's invariant (exactly-once result delivery, no leaked subscription) survives
intact; what changes is that `on_abandoned`'s disarm goes from unconditional to
conditional on "rule no longer wanted", because R5 removes the synchronous-wait model
in which "the caller gave up" was the only trigger. PR-5 implements both; PR-1 records
them here so the implementing PR reads settled design. The plan record of the ruling
(`~/.claude/plans/let-s-take-a-step-jazzy-jellyfish.md`, operator-local) is provenance
only; this section is the durable statement.

**What stays deferred, and what was pulled forward (ruling 14(c), 2026-09-08):**
same-type mechanism serialization (`mech_ops_mu_by_type_`, #2012/#3840) is unchanged by
this design, and a single stalled `watch()` can still delay sibling arms of the same
type. It is no longer deferred to the post-flip mechanism-hardening package: because
ruling 14(a)'s accepted cost (unbounded `full_sync` churn under sustained same-type
contention) is only cheap while same-type stalls are rare, the #2012/#3840 fix lands
inside rung 9c's own ladder, between PR-1 and PR-2 (kickoff:
`~/.claude/plans/spark-2012-3840-mechanism-walkoffmu-KICKOFF.md`, operator-local; that
PR appends its own landed-in line here). #2011 (lock granularity) and #2014 stay in the
post-flip package. **Consequence under ruling 14(a), stated explicitly:** a same-type
stall can no longer K-waive healthy sibling keys, because admission congestion is not
K-qualifying; the consequence is instead that the affected generation's acknowledgment
is HELD, with the server's 25 s `full_sync` retry re-applying the whole push until the
contention clears. `yuzu.guardian_arm_failed` therefore carries a reason/phase
(admission-expiry / admission-rejection / dispatched-timeout, R5.3), so an operator
paged on it can tell a genuinely dead target from a key queued behind a slow sibling of
the same mechanism type.

**R5.3 - Ack model: accepted vs. acknowledged.** **Acknowledged ≠ compliant/enforced,
stated explicitly (Gate 6 compliance-officer) — mirroring this codebase's own
"flag ≠ revoke" precedent for a similarly-named-but-distinct signal** (Periodic Access
Reviews, `docs/security-reviews/access-reviews-2026-07-21.md`): a K-waived
acknowledgment (below) means the server stops re-pushing this generation, NOT that
every rule in it is actually enforced — a quarantined rule inside an acknowledged
generation is not armed, and `yuzu.guardian_arm_failed>0` (not the acknowledged
generation number itself) is the only durable signal that distinction is visible on.
"Accepted" means `reconcile_rule_locked()` returned `Accepted` specifically — the async-arm outcome, as
opposed to `Armed` (an inline type or already-committed shared watcher, resolved
synchronously with no ack tracking needed), `Failed`, or `Inert` (a legacy-guard rule,
unrelated to spark). An `Inert` outcome never enters the pending-arm set at all, exactly
as it does not today — the ack predicate is structurally blind to it, so a push whose
rules are entirely `Inert` (all legacy) satisfies the predicate immediately, with
nothing to wait on. `apply_rules()` tracks, per accepted
rule, whether its arm has resolved. The policy generation advances (and is persisted)
only once every rule accepted under it has either armed or been quarantined per the
K-bound below — never on acceptance alone. An **episode**, here, is one accepted
rule's not-yet-resolved arm attempt under a given generation — a rule that has already
armed has no episode left to be pending, so it does not count against the condition
below. A same-generation re-push (the server's 25 s `full_sync=true` heartbeat retry)
is a no-op while every *outstanding* episode for that generation is still genuinely
pending and within its deadline — including the ordinary case where SOME rules in the
push have already armed and the rest are still resolving, the common shape of a
retry landing mid-drain (R5.3's own bounded drain, below, routinely spans several
ticks) — and only triggers a full re-apply once something has actually failed,
expired, or the push's content has changed underneath it.
**A quarantined key is K-bounded, not held forever** (only a dispatched-and-timed-out
key qualifies; a congestion-expired or admission-rejected rule never does, ruling
14(a)): after three identical same-generation re-applies whose only unresolved rules
are already-quarantined, the generation acknowledges anyway, leaving
`yuzu.guardian_arm_failed>0` as the durable fleet signal — a wedged key stays
quarantined until its own worker returns or the agent restarts (**restart is a
remediation only for a *transient* wedge — for a *permanently* wedged target, restart
re-arms the same rule against the same dead target and re-wedges, matching this
document's own F3 × `Restart=always` crash-loop finding above, "a security finding,
not only an ops one"; an operator paged on this tag should not treat restart as a
default first action without first checking whether the target is transient or
permanently dead**); a later policy change re-evaluates the rule but cannot by itself
re-attempt the arm. A genuine refusal
(backend refused, worker threw, arm queue full - that is, an admission rejection) or a
queue-wait expiry is a different case and holds the acknowledgment indefinitely - K
only bounds the quarantined case, never a live refusal and never a congestion-only
outcome. **K is not a generation-wide liveness bound** (ruling 14(a)): a single wedged
worker that exhausts its class quota pushes its siblings into non-K-qualifying
`CapacityExhausted`, and those held rules keep the generation unacknowledged past the
wedged key's own K; do not read K as a promise that every generation acknowledges
within three re-applies. **Zero-accepted push:** a push whose every rule is refused at
admission has nothing pending and nothing armed; its generation does NOT advance
vacuously - it stays behind and the 25 s retry re-applies it, because an
admission-rejected rule counts as accepted-and-unresolved for the predicate.
**Completion ownership survives K:** a K-waived rule's dispatched operation still has
an owner (its retained per-key claim, R5.2), and its eventual result is applied under
ruling 14(b); acknowledging the generation never discards or orphans that completion.
**Three separate transitions, never collapsed:** quarantine-release (the wedged
worker's call returns and clears the marker), arm-recovery (a still-wanted rule's late
success commits and clears its `arm_failed` entry), and policy-acknowledgment (the
generation advances) each have their own trigger; none implies another.
`yuzu.guardian_arm_failed` carries a reason/phase per rule - admission-expiry,
admission-rejection, or dispatched-timeout - and only the last bears on whether an
agent restart is sane remediation (see the restart caveat above). **Commit timing
under the implementation (PR-1, commit-in-callback):** the runtime commits a resolved
arm on the completion callback's own thread, immediately when the backend call
returns - `commit_new_generation_locked()` (`guardian_spark_runtime.cpp`) stages the
"armed" lifecycle record right there. The heartbeat-bounded drain below is the
ACKNOWLEDGMENT bookkeeping (PR-2); durable persistence of the lifecycle journal stays
the engine layer's job; three timings, not one. The drain that resolves pending arms
against incoming results is bounded
per tick, matching the existing lifecycle-journal's 4-batch/1024-record shape, so a
large outstanding batch drains over several heartbeat ticks rather than risking a
heartbeat-thread stall.

**Telemetry-tag semantics, flagged not specified (SHOULD, Gate 6 sre):**
`yuzu.guardian_arm_pending`/`yuzu.guardian_arm_failed` (introduced here, wired in
PR-3) need their gauge-vs-counter semantics stated before PR-3 implements them, not
left to be inferred by analogy. R5.2's open question (b) above already implies
`arm_failed` must be a **re-statable gauge** (able to return to 0 on a late success),
but this row's own table placement sits next to the C1/D1-style rows in
`docs/spark-legacy-delta-registry.md`, whose tags are the OPPOSITE
pattern — monotonic per-sweep counters summed into a fleet gauge, `docs/
observability-conventions.md`'s own stated "monitor-only: neither `>0` nor
`increase()` is sound" shape. Copying that adjacent pattern by analogy would silently
break the K-bound safety argument this whole mechanism rests on (a cleared quarantine
would never be reflected). PR-3 must specify these as gauges matching the age-tag
pattern (`observability-conventions.md`'s `emit_guardian_journal_age_tags`), not the
counter-rollup pattern, and should carry the same five fields this doc's own
risk-accept register uses elsewhere (`docs/spark-flip-gate.md`'s detection-signal /
operator-action / owner / milestone / revisit-condition shape) rather than a bare tag
name. The physical-orphan ceiling (R5.1) similarly has no named observability today —
a repeated ceiling hit (outstanding workers past `fn()` while quota is free: slow or
wedged completion callbacks, possibly all of one mechanism type, structurally different
from ordinary per-class quota pressure) should be independently alert-worthy, not
folded silently into the same signal as ordinary contention
(`IoFailure::CeilingExhausted` is the distinct outcome PR-1 gives it; PR-3 names the
tag).

**R5.4 - Audit and durability.** The "armed" audit record is still staged only on a
real, confirmed backend commit — never on acceptance alone, matching today's contract
exactly. What changes is timing, in three separate steps (corrected in the PR-1 doc
pass, 2026-09-08; an earlier version described a single heartbeat-bounded delay):
(1) STAGING is immediate on completion - the runtime's completion callback commits the
arm and stages the "armed" lifecycle record on the worker thread the moment the backend
call returns (`commit_new_generation_locked()`, `guardian_spark_runtime.cpp`),
asynchronously relative to `apply_rules()`'s own return; (2) ACKNOWLEDGMENT of the
generation is what the heartbeat-bounded drain governs (R5.3): at least one heartbeat
tick (~30 s) after acceptance and, for a completion queued behind the per-tick drain
cap, however many additional ticks the drain needs to reach it (not a flat one-tick
bound for every rule in a large push, only for one selected on its first tick);
(3) DURABLE persistence of the lifecycle journal stays at the engine layer on its
existing cadence. A refused (admission-rejected), withdrawn, queue-wait-expired, or
dispatched-and-timed-out arm produces no "armed" record at that time - silence on
failure is unchanged - but a SUBSEQUENT late success on a still-wanted rule does stage
its "armed" record when it commits under ruling 14(b): expiry silences the failure, not
the eventual success.

**R5.5 - Shutdown.** `GuardianEngine::stop()` no longer parks under `mtx_` waiting on an
in-flight arm, since `apply_rules()` itself no longer blocks there either — a hung
backend call can no longer delay agent shutdown the way it can today. In-flight workers
finish on their own schedule after `stop()` returns; a late-arriving success is
disarmed rather than left live. Queued (not yet dispatched) work is dropped with a
counted total. The existing F3 hard-exit contract (`active_io_workers()`, orphan grace)
is unchanged — this design's non-waiting dispatch path is covered by the same
accounting the state-read and existing arm/disarm executors already use, and that
accounting is the PHYSICAL alive-worker count (R5.1, #4147):
`GuardianEngine::active_io_workers()` sums each
`GuardianIoExecutor::active_worker_count()`, released when the worker's payload is
destroyed in the trampoline (the latest self-observable point before OS-thread exit,
see R5.1), never the early-releasing quota count, so a worker that has returned from `fn()` and is still
inside its completion callback holds the process open exactly as a worker still inside
the OS call does.

**R5.6 - Legacy asymmetry.** Legacy acknowledges synchronously and unconditionally,
including a rule whose guard failed to start — that rule is silently stranded `Inert`,
logged but not held against the generation. Spark's acknowledgment holds on a genuine
refusal, and is K-bounded (never unconditional) on a quarantined key only - a
congestion-expired or admission-rejected rule holds it (ruling 14(a)). This is a
deliberate, documented delta (`docs/spark-legacy-delta-registry.md` row A3), not an
oversight to reconcile — spark's stricter acknowledgment is the point of this design,
and legacy's asymmetry pre-dates it and is out of scope to change here.

**R5.7 - Re-measurement methodology.** Window B (`T1 - T0`, the existing #3990
measurement) remains valid for direct comparison with prior runs, but it is a
log-to-log interval, not proof of `apply_rules()`'s actual return latency:
`apply_rules()` constructs a rollback guard whose destructor performs unbounded
lifecycle-journal persistence on scope exit, and that destructor runs *after* the T1
log line — so under this design, a smaller B does not by itself prove a faster actual
function return, since work can now be staged asynchronously before T1 while the
destructor's own persistence work still happens after it. Re-measurement must add a
second timestamp, T2, taken from the runtime's own arm-confirmation commit (a new log
line) — not from `SparkEngine`'s own "armed" log, which fires before the real OS call
completes and is not a valid proxy for it. The diagnostic script's completeness check
(confirming every expected arm actually happened) must also exclude a no-op re-push's
own log line from that count, since a no-op returns the same `rules_size()` figure
without a single real arm occurring.

## 7.7b split — pre-cutover hardening (settled 2026-07-18)

7.7b was first planned as one PR folding the #2237 send-path items and #2238 test
seams into the flip. Three independent reviews — Sol/Codex (opine), Claude
(adjudication, every claim verified against code), and Fable (advisor) — converged on:
**the flip is unsafe in one PR; split into an inert-hardening PR-1 and a thin-cutover
PR-2, with the `prefer_spark` flip as the last commit either way.** Every finding below
was verified against the worktree at `origin/dev` (b09cdd19).

**"Inert" is placement-inert, not behaviour-inert.** PR-1 changes *no* detection or
enforcement *placement* (`prefer_spark` stays false), but it is not a no-op: the shared
builder refactors the live legacy emit path (`guardian_engine.cpp:500`), the
`apply_rules` firewall changes live per-push failure semantics (`guardian_engine.cpp:326`),
and the telemetry ships new heartbeat tags every beat. State this in the PR so a gate
reviews it as a live-path change, not a rubber-stamp of a false "inert" premise.

### The cutover-blocking finding (Fable M1): `guard.unhealthy` re-emission flood

The read-failure path calls `unhealthy()` **unconditionally** on every `!read.known`
(`guardian_rule_eval.cpp:63/111/132`) — there is **no into-unknown edge guard**; only
*recovery* is edge-forced (`pack()`'s `recovered` bit). `build_entries` then pushes a
**fresh-`event_id`** health entry on every `Unhealthy` (`guardian_spark_runtime.cpp:405-413`).
An unhealthy rule stays in `pending_initial` (`:357`), which the priority lane re-sweeps
every ~5 s (`ConvergenceScheduler::Config::priority_poll_ms`, default 5000 - the
`guardian_convergence_scheduler.hpp:60` line-ref this paragraph originally cited has
since drifted; cite the symbol, not a line number, for exactly this reason). Net: one
mundane unreadable target (ACL-denied file, missing hive path) emits **~17 k
`guard.unhealthy`/day/rule/agent**, each its own server-side insert transaction. Legacy
has no health stream, so this traffic class switches on **at the flip** — a self-inflicted
fleet ingest DoS. **The `guardian_rule_eval.cpp:15` comment "edge-triggered
guard.unhealthy" is false.** Fix (send-path, flag-gated inert → PR-1, flip unsafe
without it): transition-edge health emission (emit on the false→true unknown edge + a
slow periodic refresh only) + evict never-Known rules from the 5 s priority lane to
their normal lane cadence.

**SUPERSEDED 2026-08-18 (F11, #2298) - the fix above has since shipped, in two parts,
and the ~17k/day figure is the PRE-fix number.** Transition-edge emission shipped first
(`b30e93cfd`, 2026-07-20, "edge-guard into-unknown to stop unhealthy-event flood") -
this alone removed the per-sweep flood this paragraph describes; every committed
repeat-Unknown became silent (edge-only, `unhealthy_suppressed_`) rather than a
fresh-`event_id` re-emission on every ~5s sweep. F5 (PR #3005, merged 2026-08-11) then
*added back* a deliberate, bounded, nonzero steady state on top of edge-only silence:
`errored_refresh_ms` (default 300s) re-emits a stale-but-still-errored rule so a
lost/coalesced edge cannot leave the server's view stale forever, and
`pending_demote_sweeps`/`pending_demote_ms` evict a never-Known rule off the 5s
priority lane onto its normal type-lane cadence - exactly the mechanism this
paragraph's "Fix" bullet called for. **F5 did not reduce the ~17k/day figure - edge
emission already had, to zero steady-state wire traffic; F5 set the new nonzero
ceiling on top of that silence, by design (a lost-edge backstop, not free).** The
measured ceiling (fake-clock Catch2 cases at production Config defaults,
`tests/unit/test_guardian_spark_runtime.cpp`, "F11 flood: ..." - see
`docs/spark-rebuild-baselines/f11-flood-measurement-run.md` for the full derivation and
a live-rig confirmation): **1 edge + 288 refreshes/day/rule/agent** on a 60s-cadence
lane (service/registry - refresh recurs exactly every `errored_refresh_ms`, first
landing at t=300s post-edge), **1 edge + 180 refreshes/day/rule/agent** on the 600s
file lane, accounting for the scheduler's default +/-20% jitter (every post-demotion
sweep refreshes, since even the jitter-minimum 480s spacing already exceeds the 300s
floor; 144/day is the exact-no-jitter figure, 180/day is the true production ceiling
- corrected 2026-08-18 after an adversarial review caught the original doc's false
"jitter never shortens a sweep" claim). Both corrected figures are roughly 60-95x
below the pre-fix ~17k/day this paragraph documents.

**M1's fix covers the health (Unknown) stream only.** This paragraph's flood analysis and
fix scope never mention the Known/drift path - `guardian_emit_decider.hpp`'s `decide_emit`
has no equivalent terminal-state dedup on the Drift branch, so a persistently-drifted rule
still re-emits `drift.detected` on every convergence sweep (no fix landed for it here).
Tracked as delta-registry row D3 and issue #3388 (F12, #3386) - ruled 2026-08-23 (interim
fix: a sweep-cadence-aware debounce default), fix drafted but not yet merged; see D3's
own Ruling cell for the current state.

**Landed (PARTIAL) 2026-07-20, commit `b30e93cf`:** the **transition-edge emission** + a
**counted, sparse-heartbeat suppression signal** (`yuzu.guardian_unhealthy_suppressed`) shipped.

**Landed (F5, #2298):** (a) the **slow periodic refresh** - `GuardianSparkRuntime::Config::
errored_refresh_ms` (default 300 000 ms; 0 disables) re-emits `guard.unhealthy` for a still-
errored rule at that cadence, carrying the CURRENT read-error detail (not the stale first-
episode string), counted on its own `yuzu.guardian_unhealthy_refreshed` heartbeat tag - so a
lost/coalesced edge can no longer leave the server's errored view stale forever
(unhappy-path UP-1/2/4/11 closed); and (b) the **priority-lane eviction** -
`pending_demote_sweeps`/`pending_demote_ms` (defaults 12 sweeps / 120 000 ms) demote a
still-pending-initial rule off the 5 s priority lane to its normal type-lane cadence
(service/registry ~60 s, file ~600 s) once EITHER threshold is crossed on a COMMITTED
Convergence-reason Unknown, counted on `yuzu.guardian_priority_demoted` - closing the *read*
flood (UP-6) the edge-only fix left open. Demotion is per-rule, not per-key (a key with a
mixed demoted/non-demoted pending set still pays the read cost via its non-demoted sibling);
the demoted rule keeps converging (and keeps re-arming errored_refresh_ms) at the slower
cadence, so (a) backstops (b)'s resulting wire staleness. Both land in
`guardian_spark_runtime.{hpp,cpp}` only - zero scheduler code change (the scheduler's
existing type-lane sweeps already re-drive a demoted key's `evaluate_key`).

Still OPEN and still gating the `prefer_spark` flip (folded into #2298 gate 6):
(c) **DONE (F6).** The **server-side rollup/consumer** for the suppression/refresh/demotion
tags now exists two ways: an unlabelled fleet-sum gauge family (`yuzu_fleet_guardian_unhealthy_
suppressed`/`_refreshed`/`_priority_demoted`, `guardian_health_fleet_tags.hpp`, mirroring the
guardian-journal pattern), and `/status.errored_rules` / `/status/{agent_id}.errored_rules` are
now real, derived from the `guardian_agent_rule_status` census (the same no-TTL current-state
view the dashboard reads) rather than the former hardcoded placeholder `0`. `compliant_rules`/
`drifted_rules` remain placeholder `0` - full status ingest (`action=="status"`) is a separate,
later rung. **(d) the four-artefact egress for
`arm_race_unwatch_failures_total` AND `disarm_unwatch_failures_total` (#2270)** - both heartbeat
tags ship and both keys are registered in `spark_fleet_tags.hpp`, but no rollup consumes either,
there is no `docs/user-manual/metrics.md` row and no alert rule, and no REST route or dashboard
renders raw `status_tags` - so an orphaned OS watch is not fleet-detectable and is not per-device
queryable either; the value reaches the server and is read by nothing. Same class as (c) and same
reason it matters: the residual either counter reports is a leaked watch in the agent's sole
detection primitive, and reclamation is mechanism-dependent, not simply OS-dependent - a File
watch (Windows-only mechanism) is never reclaimed short of a process restart, so for that
mechanism the cost is permanent and cumulative rather than self-healing; a Service watch (Linux or
Windows) is reclaimed the next time `stop()` runs; a Registry watch (Windows-only mechanism)
cannot fail this way at all. The census edge-record still depends
on the sole production `attach_rule` hardcoding `emit_compliant_edge=true` - do NOT sever that.

### PR-1 hardening items (commit order 1→2→3→4→7→5→6→9→8)

1. **Shared drift-event builder.** Extract `apply_drift_to_event`; legacy build at
   `guardian_engine.cpp:500`, spark at `guardian_spark_send.cpp:43` — extract, not just
   a cross-check test (a cross-check leaves two drifting impls).
2. **OutboxEntry guard_type/rule_name for Health/Lifecycle** (empty today,
   `guardian_spark_send.cpp:76`).
3. **attach_rule + live `apply_rules` exception firewall (Fable M3 — harder than #2237
   item 2).** `index_->add()` runs *before* `rollback.fn` is assigned
   (`guardian_spark_runtime.cpp:108` vs `:129`); a **throwing** `arm()` leaves a ghost
   `by_rule_` entry → the next sibling attach's `keys_.at(key)` throws `out_of_range`
   (`:143`) through the un-firewalled `apply_rules`. And `SparkKeyRuleIndex::add`'s
   emplace-throw (`spark_key_rule_index.hpp:92`) leaves an *empty set* → a false 0→1
   edge on the next add → double-arm → **untracked live subscription leak on a success
   path**. Requires a strong-guarantee/noexcept `SparkKeyRuleIndex::add` + fault
   injection of a throwing `arm()`; wrapping callers is not enough.
4. **Drain-without-lock.** `GuardianSparkRuntime::drain()` holds `outbox_mu_`
   (`:441`) across `send_guardian_outbox_entry`'s synchronous gRPC `Write()`
   (`agent.cpp:2700`); the stall cascade is `Write` → `outbox_mu_` → `evaluate_key`
   commit under `registry_mu_` → `apply_rules` under engine `mtx_` → heartbeat/status.
   Restructure to peek/copy → unlock → send → conditional-remove by `event_id` alone
   (globally unique per enqueue — `agent_id`+boot-nonce+`rule_id`+ms+seq — so it pins the
   exact sent node with no separate generation check; as implemented, `pop_front_if`).
   Sub-contracts: `drain_once()` is public/off-thread-callable → keep a drain-in-progress
   guard; the lifecycle log has no index (`guardian_outbox.hpp:294`) → conditional-remove
   needs a front-`event_id` check; a coalesce during the unlocked send replaces the node
   with a new `event_id` (`:151`) → remove-by-`event_id` handles it, write the test.
   **Drain order fix (M6):** send lifecycle *before* compliance (currently `:443-444`
   sends compliance first) so a rule's "armed" audit entry never arrives after its first
   drift event.
5. **Two-count executor + physical-orphan ceiling (Fable M4).** Today inflight counters
   free at OS-thread-exit (`guardian_io_executor.hpp:338`), so `kMaxProcessIoWorkers=10`
   is a real physical bound. Freeing the *logical* admission slot on the run() deadline
   requires a **separate physical-orphan ceiling strictly > sum(quotas)** (else 10 wedged
   orphans re-create the exact cross-class starvation R3 eliminated) + same-key
   single-flight retained until orphan exit + an exactly-once logical-vs-physical
   decrement handshake (a double-decrement inflates quota). Pin the ceiling **value** in
   the PR description (R3's own lesson).
6. **F3 KV marker** (R4): best-effort marker persisted before `hard_exit()`, read/reported/
   cleared next boot.
7. **Lifecycle-audit durability.** `GuardianLifecycleLog` is in-memory, reject-new+count-
   on-full, never-evict (`guardian_outbox.hpp:263`), and the send drops on `Write()==true`
   (queued ≠ acked) → at-most-once + capacity-lossy + crash-lossy = **not audit-grade**.
   Compliance drift stays documented best-effort telemetry; **lifecycle
   (`guard.armed/disarmed/errored`) becomes durable**: a retention-bounded journal +
   replay on boot **and every reconnect**, leaning on the server's existing `event_id`
   idempotency (PK rollback at `guaranteed_state_store.cpp:670` absorbs replay dups;
   boot-nonce'd `event_id`s). Delete-on-`Write()==true` alone re-inherits the hole — the
   entry leaves the journal only after replay-safe confirmation. **Substrate: reuse
   `KvStore`/`kv_store.db`** (already open, WAL, Guardian writes rules there) — not a new
   file. Constraints: `get()` truncates at NUL (`kv_store.cpp:178`) → payload is JSON not
   raw proto; no txn API, each `set()` is a commit+fsync → a 500-rule `full_sync` = ~1000
   fsyncs → **batch/persist-per-push, not per-entry**; do **not** journal inside
   `enqueue_lifecycle_locked` (under `registry_mu_`+`outbox_mu_`) or it recreates the
   coupling item 4 removes — journal at the engine layer under `mtx_`.
8. **Test seams + TSan** (#2238): the re-arm-throw degrade fault hook, the prefer_spark
   thread-start introspection, and a concurrent start-drain-then-stop TSan test with the
   real `this`-capturing send callback.
9. **R4 telemetry as a producer+consumer contract**, not just agent tags: each field
   needs an agent writer + `agent_registry.cpp:1323` server parser + family-clear +
   reset-handling + bounded labels + current-vs-cumulative semantics + a writer/reader
   cross-pin test; both outbox domains reported separately; the F3 marker included. The
   `SparkFailed`-prevalence alert ships here reporting the inactive posture, and needs a
   **paired `reporting`-drop condition** (a correlated crash-loop manifests as
   `yuzu_fleet_spark_reporting` dropping, not `failed` rising, because a fast loop dies
   before heartbeating).

Also folded into PR-1: the **R2 `unsupported` terminal state + rung-8 telemetry +
reconcile-test rewrites**. Verified flag-gated inert — the whole Arm/Unsupported branch
is under `if (prefer_spark_ && Available)` (`guardian_engine.cpp:845`; the legacy
fallthrough it replaces is `:882-885`) and the reconcile tests already construct
`prefer_spark=true` (`test_guardian_engine_spark_reconcile.cpp:160`). Moving it here
pulls the largest piece of unspecified new semantics off the flip PR.

### PR-2 (thin cutover)

`prefer_spark = !cfg_.spark_disable` (`agent.cpp:~579`, R1) as the **final commit**; the
**intentional-delta registry** (R2 consequence 2 — pulled forward from rung 10 because
7.7b changes the behaviour parity classifies; **shipped ahead of the flip, F12/#3386:
`docs/spark-legacy-delta-registry.md`**); **production-order cached-KV
restart/upgrade tests** (the current fixture runs `start_local()` before
`wire_spark_engine()`, the reverse of production `agent.cpp:962` vs `990`, with an empty
KV — it masks the rehydration path); parity + resource + **3-OS/gateway** evidence
(Linux File/Service/inert-systemd; Windows File/Registry/Service + shared-watcher
refcount; macOS all-unsupported + `--spark-disable` legacy-restore; slow/stalled-`Write`;
long pre-connect/outage; reconnect-during-drain; a server-side reconnect-storm
events/sec ingest figure); and the **grep-enumerated stale-prose sweep** (`"legacy
IGuard"`/`"unaffected"`/`"remediated"` — false after the flip at `guardian_engine.cpp:264`,
`agent.cpp:934-984`, `guaranteed-state.md:344`).

### Two decisions settled 2026-07-18

- **M2 — one-legged recovery.** `event_state_from_type` maps `guard.unhealthy`→errored
  but `guard.healthy`→`nullptr` (`guaranteed_state_store.cpp:64-67`); recovery clears
  `errored` only via a paired *compliance* event, which works solely because the prod
  attach hardcodes `emit_compliant_edge=true` (`guardian_engine.cpp:861`). **Ruled:** add
  a **cross-pin test** in PR-1 that fails if any attach uses `edge=false`; the real
  server-side `guard.healthy` census mapping lands with the health surface at **rung 4**.
- **Flap detector** (design-mandated, §Kill-switch / F3 notes): **deferred to rung 11**
  alongside the `SparkFailed`-prevalence alert (both server-side fleet-signal work),
  recorded here so the deferral is explicit rather than silent.

## Consumer architecture

Guardian becomes a SparkEngine client. The seam:

- **One queued consumer.** `GuardianEngine` calls `register_consumer(name,
  handler, queue_cap)` (`SparkEngine::register_consumer`'s declaration) once at
  startup, and `arm(consumer, SparkSpec)` (`SparkEngine::arm`'s declaration) once
  per enabled rule — replacing the per-rule guard
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
under the ops lock (`mech_ops_mu_by_type_`'s member comment: Registry and
Service watch latencies are "entirely UNCHARACTERISED" and the per-type stall
duration is unbounded); #2011's per-mechanism-type lock (rung 0) removes only
*cross-mechanism* coupling. Gate rung 3 on a measured Service-arm-latency ceiling
(or the walk-off-`mu_` restructure the header defers). (architect S4.)

**#2233 item 3 (landed)** bounds the wall-clock a *caller* of `GuardianSparkRuntime`
waits for one File/Registry/Service arm/disarm - a dedicated `GuardianIoExecutor`
instance runs the actual backend call off `registry_mu_`, bounded by
`Config::backend_op_deadline` (5s default) - up to 2x that on a same-key redeploy
of an already-armed rule (the prior generation's disarm and the new arm run
sequentially, each individually bounded, not concurrently). `GuardianEngine::apply_rules()` and
`GuardianEngine::stop()` no longer wedge on a hung watch; a hung watch degrades to
one rule left un-armed and retried, while every other rule and shutdown proceed.
This does **not** restructure `mech_ops_mu_by_type_` itself: a hung SCM/Registry
call inside `backend_->arm()` can still block a sibling arm/disarm of the SAME
mechanism type at the `SparkEngine` layer until this caller's own deadline elapses.
The Pre-Stage-3 dependency above is otherwise unchanged by this landing.

**#3816 (landed)**: item 3's bounded-wait deadline left a residual - a backend arm
that succeeds just after its caller gives up can mint a live subscription nothing
tracks. `GuardianIoExecutor::run()` now delivers every result `fn()` returns
normally exactly once, to either the caller's return value or an
`on_abandoned(T&&)` callback (a thrown `fn()`/`WorkerThrew` has no `T` to
deliver and correctly reaches neither), so
`GuardianSparkRuntime`'s arm consumer can disarm a late success instead of leaking
it; the state reader needs no callback (a late read is wasted work, nothing
escapes). See `docs/spark-flip-gate.md` §3 row 3.

## Health / status surface — the #1939 checklist

Per ADR-1005 (headless platform) a new capability lands on REST **and** MCP, or
records an exception. The spark/guard health signal lands on both, carries the A4
error envelope and A2/A3 discovery metadata (enumerable via `/api/v1/openapi.json`
and MCP `tools/list`), and enforces RBAC + audit at the API layer — not a
dashboard fragment. This section ticks every #1939 item.

### Fleet metrics (agent heartbeat → Prometheus)
- **`arm_race_unwatch_failures_total` / `disarm_unwatch_failures_total` (#2270 — agent
  side SHIPPED, fleet rollup DEFERRED):** two counters, both counting mechanism
  `unwatch()` calls that THREW, where the throw is contained rather than propagated —
  `arm_race_unwatch_failures_` during `arm_impl`'s consumer-race teardown
  (`teardown_arm_race`), `disarm_unwatch_failures_` during `disarm()`. Emitted as the
  sparse heartbeat tags `yuzu.spark_arm_race_unwatch_failures` and
  `yuzu.spark_disarm_unwatch_failures`. **Scope is in the names and is deliberately not
  fleet-wide:** the two together cover `teardown_arm_race` and `disarm()` only.
  `unregister_consumer()`'s unwatch site is not a peer of these two — it still
  propagates UNCONTAINED, and the consequence is worse than an uncounted orphaned
  watch: escaping a void function there permanently strands the consumer's dispatch
  thread (tracked as #2814). Two zeros do not mean "no orphaned watches", and say
  nothing about #2814 at all. The `{os}` rollup, the `docs/user-manual/metrics.md`
  row and an alert rule are **deferred to the
  `prefer_spark` flip** on the same grounds as `retiring`/`retiring_cap`
  (`spark_fleet_tags.hpp`): with `prefer_spark_` false nothing arms, so the gauges
  would be structurally absent fleet-wide and unfalsifiable. Tracked as item (d) of the
  flip gate above.
- **Agent:** emit `SparkEngineStats` as `yuzu.spark_*` heartbeat `status_tags`.
  `SparkEngineStats` (`spark_engine.hpp`, the `SparkEngineStats` struct) carries `armed_faulted`,
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

*Rung numbers in the paragraph below (not this one, nor the rung 2-4 cutover-window
paragraph above it) predate the implementation ladder's later resequencing: "rung 2"
there is impl-rung-7 (the `prefer_spark` flip, rung 7.7); "rung 3"/"rung 5" are the
P3 enforce cutover / P5 legacy deletion in the post-flip programme. Current gate
state: `docs/spark-flip-gate.md`.*

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
   - **7.7b — SPLIT into two governed PRs (settled 2026-07-18, §7.7b split below).**
     Three reviewers (Sol/Codex, Claude, Fable) found the send/placement path is not
     yet safe to make live in one PR. The flip is the **last commit** either way.

     **PR-1 is itself landed as two governed PRs (decided 2026-07-18) so each is
     reviewable as one unit and item 9's counters land before their consumers:**
     - **PR-1a** = the send/exception/drain cluster: items 1 (shared drift builder),
       2 (guard_type/rule_name), 3 (exception firewall), 4 (drain-without-lock), plus
       their two Sol/Fable hardening folds and this governance round. Behaviourally
       inert (`prefer_spark` false), but item 3's `apply_rules` firewall is a **live
       legacy-path** crash-prevention fix (see the changelog fragment).
     - **PR-1b** = items 5 (two-count executor + orphan ceiling), 6 (F3 marker),
       7 (KV lifecycle journal), 9 (R4 telemetry + the heartbeat wiring for the
       PR-1a counters), 8 (test seams), **M1 (the transition-edge health-emission
       fix)**, and the R2 `unsupported` terminal state.
     - **FLIP GATE — ELEVEN items gate PR-2**, each detailed in the bullets below: M1,
       item 9's heartbeat wiring, #2270, the lifecycle-audit journal, #2797, #2818,
       #2819, #2813, #2839, and two residues that own no issue, (a) and (b). **The
       `prefer_spark` flip must not ship while any is open.** The first four land in
       PR-1b except #2270, which ships as its own PR against `dev` ahead of it. M1 in
       particular is a fleet ingest-DoS if the flip precedes it, so it is not enough
       that it is "in PR-1" — it is specifically in PR-1b, after PR-1a.
     - **#2797 gates PR-2 as well, and is the only gate whose headline defect is
       already live pre-flip.** `apply_rules` discards
       `reconcile_rule_locked`'s bool
       (`guardian_engine.cpp:634`; the surrounding catch counts a THROW only), so a
       RETURNED arm failure leaves `reconcile_failures` at 0, the generation
       advances, the server stops re-pushing, and the rule stays persisted-but-
       unarmed. The flip raises the rate rather than creating the defect: a returned
       failure is the ordinary spark-backend arm error, whereas a legacy guard arm
       rarely throws (#2278). #2797 is the reconcile-side half split out of #2270 -
       #2270 itself closes only the strong-guarantee half, so closing #2270 does not
       discharge this gate.
     - **#2818 gated PR-2 too, now FIXED (PR-2d).** At the time this was written, the engine tore down a whole spark key
       (`SparkEngine::drop_key_locked`) while `GuardianSparkRuntime` arms one shared
       subscription per key on the 0->1 edge (`guardian_spark_runtime.cpp:159-166`),
       and nothing tells the consumer its subscription died: Guardian goes on
       believing it holds a live subscription, `backend_->disarm(sub)` is a no-op,
       and nothing is enforced for any rule on that key. It is an ENFORCEMENT gap,
       not a false-assurance one - `GuardianEngine::get_status()` is fail-closed
       (`guardian_engine.cpp:684-686`, every rule reported errored), so the
       originating findings' "get_status reports N rules armed" premise is false at
       this tip and is corrected in #2818. Dormant while `prefer_spark` is false
       because legacy `IGuard` is the live detection path - the flip is what makes
       it a live enforcement hole. #2797 removes the `apply_rules` self-heal that
       otherwise bounds it, so the two gates compound and neither alone closes the
       exposure.
     - **#2819 gates PR-2 as well — same dormancy test as #2818, applied
       consistently.** An earlier revision of this block dismissed it as "a
       shutdown-availability defect ... does not gate the flip". That was wrong:
       availability-vs-enforcement is not the criterion this list uses, dormancy is,
       and #2819 satisfies it. #2819 reaches a blocking `unwatch()`
       by TWO routes — `arm_impl`'s `teardown_arm_race`, and the ordinary withdraw
       path through `SparkEngine::disarm` — and both are dormant, for the same
       reason. `attach_rule` runs only at `guardian_engine.cpp:1153`, inside
       `try_spark = prefer_spark_ && spark_availability_ == SparkAvailability::Available`
       (`guardian_engine.cpp:1139`), and Guardian is the sole registered consumer
       (`guardian_engine.cpp:1244` is the only PRODUCTION `register_consumer`
       caller). `detach_rule` itself IS reached pre-flip — three of its five sites
       (`:1095`, `:1124`, `:1182`) sit outside the `try_spark` block, which spans
       `:1140-1179` — but it reaches `backend_->disarm` only when
       `index_->remove_rule` returns a key (`guardian_spark_runtime.cpp:253-258`),
       and pre-flip nothing was ever attached, so `keys_` is empty. Both routes are
       therefore dormant TRANSITIVELY, on the absence of a prior arm, and the wedge
       is created by the flip exactly as #2818's hole is. Its terminal outcome is a
       stalled agent shutdown whose F3 backstop is structurally unreachable, on a
       trigger that correlates fleet-wide during an OTA wave. #2819 also carries a
       related `service_win.cpp` instance that is live TODAY and needs no spark
       involvement — see its Related section.
     - **#2813 gates PR-2 on the same dormancy profile**, and is listed here rather
       than left silent. Its sink is NOT #2819's, which is a lock wedge: #2813's
       residue is a live OS watch whose `armed_` entry is gone, so its firings are
       silently dropped.
     - **#2839 gates PR-2 on the same dormancy profile.** A throwing
       `push_retiring()` (`spark_file.cpp:331-336`) frees a `DirWatch` with a live,
       uncompleted kernel I/O — not merely a leak — and separately leaves
       `dirs_[dirkey]` half-erased (key present, `unique_ptr` null/moved-from,
       since `dirs_.erase(di)` never runs after the throw). `SparkEngine::stop()`'s
       later, unrelated `cancel(*w)` sweep (`spark_file.cpp:241-246`) dereferences
       that null pointer with no check — #2270's containment is what makes this
       survivable-but-silent rather than an immediate crash near the OOM event,
       deferring and decontextualizing the eventual failure. File-mechanism-only
       (Windows), OOM-triggered. First found by round-4's own `xp-1`/`UP-1`
       (`governance.d/2270-arm-window-round4.4c0PeP.jsonl`, pass 1); the
       stop()-time null-deref consequence specifically was surfaced later, by
       this branch's own final `/governance` run's Gate 4 unhappy-path pass, and
       Gate 5 chaos-injector then synthesized two test scenarios for it — do
       NOT cite those scenarios as `CH-1`/`CH-2`, which are already distinct,
       unrelated finding_ids in the round-4 ledger file (the stranded
       consumer-dispatch-thread finding and the stop()-does-not-drain finding,
       both deferred to #2814/#2815).
     - **Two residues gate PR-2 and own no issue**, recorded here because a gate list
       that enumerates only issue-backed items reads as complete when it is not.
       (a) CLOSED by `5858844c` (`SparkEngine::disarm`'s in-lock teardown made
       allocation-free) and `444c2458` (disarm's trailing `unwatch()` contained and
       counted, matching `teardown_arm_race`) — the allocating prologue this residue
       used to describe no longer allocates. Ledger `CH8-2`/`UP8-1` were adjudged
       discharged on the merits by security-guardian after the fix (pass-10 evidence
       row owed); `UP-4` deduped separately. A narrower residual remains, different in
       kind: two ops between the (now allocation-free) bookkeeping and the
       contained `unwatch()` still propagate uncontained — `disarm()`'s two
       `std::lock_guard` constructions ahead of the released-`mu_` unwatch call,
       `ops(mech_ops_mu_by_type_.at(unwatch_type))` and `lk(mu_)` (mutex
       acquisition can raise `std::system_error`). The `.at(unwatch_type)` call
       inside the first does NOT: the map is populated in lockstep with
       `mechanisms_` at registration and frozen after `start()`, so the lookup
       key is always present (`disarm()`'s declaration comment; implemented at
       `SparkEngine::register_mechanism`'s lock-first `try_emplace` block). By
       this point `disarm`'s OWN bookkeeping (`armed_`/`sub_keys_`) is already
       committed, so a throw here does not desync the engine's own state the way
       the old defect did — the consequence is narrower: the `unwatch()` is never
       attempted, so neither counter increments and the OS watch is never even
       asked to release. `teardown_arm_race` documents the same residual on its
       own declaration; `disarm`'s declaration now does too. (b) The `{os}` fleet
       rollup, the `metrics.md` row and the alert rule for BOTH
       `arm_race_unwatch_failures` and `disarm_unwatch_failures` —
       `spark_fleet_tags.hpp:82` defers all three to this flip IN CODE, so the flip
       makes an agent-side resource leak measurable at the endpoint and invisible at
       the fleet. Ledger `arch8-2`.

     - **PR-1 (inert hardening, `prefer_spark` stays false — zero change to
       detection/enforcement *placement*).** The shared drift-event builder;
       OutboxEntry guard_type/rule_name for Health/Lifecycle; attach_rule + live
       `apply_rules` exception firewall (strong-guarantee `SparkKeyRuleIndex::add`);
       **drain-without-lock** (transport outside `outbox_mu_`); the two-count executor
       + a **physical-orphan ceiling strictly > sum(quotas)**; the F3 KV marker;
       **lifecycle-audit durability** (KV-backed journal, replay on boot+reconnect);
       the **transition-edge health-emission fix** (see §7.7b split M1 — the flip is a
       fleet ingest-DoS without it); the `unsupported` terminal state (R2) + rung-8
       telemetry + reconcile-test rewrites (flag-gated inert, so they land here not on
       the flip); R4 telemetry producers+consumers + the `SparkFailed`-prevalence
       alert, all reporting the *inactive* posture; the #2238 test seams + TSan.
     - **PR-2 (thin cutover).** `prefer_spark = !cfg_.spark_disable`; the
       intentional-delta registry (R2 consequence 2, pulled forward from rung 10 since
       7.7b changes the behaviour it classifies; **shipped ahead of the flip, F12/#3386:
       `docs/spark-legacy-delta-registry.md`**); production-order cached-KV
       restart/upgrade tests; parity + resource + **3-OS/gateway** evidence; the
       grep-enumerated stale-prose sweep; the flip as the **final commit**. **This is
       where detection moves to spark and legacy enforcement stops** (until rung 3).
   - **8.** `mech_unsupported_total` + `yuzu_fleet_spark_unsupported` - **folded into
     7.7b PR-1** per R2 (unsupported must be loud the moment a rule can land on spark);
     current-gauge vs cumulative-counter split per §7.7b split.
     **Landed (F7, #2298),** together with R2's terminal-state code and the
     `yuzu.guardian_backend` heartbeat tag (#2240 item 1 - the server-side flap/dark-
     device detector, #2240 item 2, remains open).
   - **10.** Parity + durability + integration matrix. Semantic ports land **before**
     7.7b where possible; live/equivalence after. Carries the **intentional-delta
     registry** (R2 consequence 2, **shipped ahead of schedule, F12/#3386:
     `docs/spark-legacy-delta-registry.md`**) so zero-tolerance parity survives the legacy-no-op
     vs `unsupported` difference.
   - **11.** The `yuzu-fleet-spark` alert group (#2083) enabled + promtool CI lint,
     including the `SparkFailed`-prevalence alert (R1 correlated-outage note).
   - **12.** Dissolved into 7.7b per R1. Residue only: boot WARN, `enforce_active`
     gauge, `changelog.d` fragment, `guaranteed-state.md` upgrade note.
   - **9b.** The full as-built rewrite of this §Rung-2 decision record and the ladder
     against the shipped 7.7a/7.7b/10 code, folding R3's resolved mechanism and R2's
     `unsupported`-vocab reconciliation. Docs-only; lands after 7.7b.
   - **9c.** §Async-arm acknowledgment (R5) - decouples Guardian's rearm window from
     OS-watch confirmation. Independent of 9b; sequenced after PR-2c (#3848) and before
     the `prefer_spark` flip (PR-5), lands dormant. Own PR ladder, PR-0 (this docs
     change) through PR-6 - see `docs/spark-flip-gate.md` for the ladder slot between
     PR-2d and the flip.

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
