# C0 — relocate Guardian journal prune()/page_into_window() onto the drain worker

Status: BUILT. Base: `feat/guardian-c0-thread-reloc` stacked on #2314 (`c23836c1`).
Tracking: #2298 gate 1. Anchors are from the ORIGINAL base HEAD (`af10c272`) and have drifted.

See "As built" at the bottom for every place the implementation departed from this design.

## Goal

Today the Guardian lifecycle journal's `prune()` and `page_into_window()` run
SYNCHRONOUSLY, inline, on two latency-sensitive threads:

- the **heartbeat thread** — `journal_maintenance_tick()` phase-2 (`guardian_engine.cpp:400-411`),
  once per `heartbeat_interval`; prune every 4th tick, page every tick.
- the **reconnect / run-loop thread** — `page_journal()` from the reconnect hook
  (`agent.cpp:1734`), one full re-page after each new Subscribe stream.

Both go through KvStore's single mutex + 5s busy timeout, so a large or contended
journal can stall the heartbeat (false staleness) or delay reconnect. C0 moves that
work onto the existing `GuardianOutboxDrainWorker` (CV-wake + 5s backstop,
`guardian_outbox_drain_worker.*`), leaving ONLY the circuit-broken retry-`persist()`
(phase-1, `guardian_engine.cpp:388-392`) on the heartbeat thread.

## What moves / what stays

| Work | Today (thread) | After C0 (thread) |
|---|---|---|
| retry-`persist()` (phase-1) | heartbeat | **heartbeat (unchanged)** |
| `prune()` | heartbeat phase-2 (every 4th tick) | **drain worker** |
| `page_into_window()` | heartbeat phase-2 (every tick) + reconnect | **drain worker** |
| reconnect re-send-all | reconnect thread (`page_journal`) | **drain worker, kicked by reconnect** |
| `rt.drain()` (ship entries) | drain worker | drain worker (unchanged) |
| heartbeat tag-building, `journal_stats()` read | heartbeat | heartbeat (unchanged) |

Net: paging becomes SINGLE-THREADED on the worker (today two threads page:
heartbeat phase-2 + reconnect). Prune joins it on the same thread. This REDUCES
paging-path concurrency; it does not add a new class of it.

## Core mechanism

Extend the worker's wake cycle with a journal-maintenance step. Each wake, after
`drain_once()`:

```
if (!stopping) {
    firewall {
        if (due_for_prune()) journal_->prune(now);
        journal_->page_into_window(*rt_, now);
    }  // count throws into a maintenance-exception counter, like drain_once
}
```

The worker is constructed in `wire_spark_engine` (`guardian_engine.cpp:1182-1183`)
and only `start()`ed when `prefer_spark_` (`:1193-1196`) — so the prefer_spark gate
is handled by start() gating, NOT a per-call check.

### DECISION 1 (central) — the worker must NOT take engine `mtx_`

`GuardianEngine::stop()` holds `mtx_` across its whole body (`:303`) and at `:324`
JOINS the worker. If the worker's maintenance took `mtx_`, that is a lock-vs-join
deadlock (worker blocks on mtx_ held by stop(); stop() blocks on join(worker)).
Today safe only because `drain_once()` never touches `mtx_`.

Resolution: give the worker the `GuardianLifecycleJournal*` (raw, engine-owned) and
the `shared_ptr<GuardianSparkRuntime>` at construction, and have maintenance use them
DIRECTLY, guarded only by the journal's `stopping_` atomic — never engine `mtx_`.
This mirrors how the worker's enqueue-waker already captures only a `shared_ptr<Signal>`,
never `this` (`guardian_outbox_drain_worker.cpp:23-26`). Both `spark_runtime_` and
`lifecycle_journal_` are set once in wiring and not reassigned during operation, so a
lock-free read is sound as long as the worker is joined before they are torn down
(Invariant L below).

The per-call `stopped_ && prefer_spark_` check that phase-2 does under `mtx_`
(`guardian_engine.cpp:382-383`) is replaced by: start()-gating (prefer_spark) +
the `stopping_` atomic (stop).

## Load-bearing invariants — each must survive C0

- **A. Lock order unchanged.** WRITE chain = `mtx_` held, then `outbox_mu_` and
  `KvStore.mu_` sequentially-disjoint (never nested), persist-side
  (`guardian_engine.cpp:351-366`, `guardian_lifecycle_journal.cpp:183-188`). PAGE chain
  = `paging_mutex_` → {`KvStore.mu_`, `outbox_mu_`} sequentially, never `mtx_`
  (`guardian_lifecycle_journal.cpp:397,426,461,507`). C0 changes only the CALLING THREAD
  of the PAGE chain, not the acquisitions.
- **L. worker ↔ journal lifetime.** The worker holds a raw `journal_*`; it MUST be
  joined before the journal is destroyed. Established contract: engine::stop() joins
  the worker (`:324`) and both agent teardown paths call guardian_->stop() before
  ~GuardianEngine (ScopeExit `agent.cpp:792`, AgentImpl::stop `:2682`). SEE HAZARD 3 —
  member declaration order today destroys `lifecycle_journal_` (declared last, `:373`)
  BEFORE `spark_drain_worker_` (`:366`), so this relies on stop() having run.
- **S. stop-race.** `request_stop()` is called FIRST in engine::stop() (`:318`), before
  the worker join (`:324`). `page_into_window` checks `stopping_` between batches
  (`guardian_lifecycle_journal.cpp:492`). After C0 the worker IS the thread the join
  bounds — cleaner than today (page currently on heartbeat/reconnect). SEE HAZARD 5:
  confirm prune()/prune_locked_ also honor stopping_.
- **E. engine-home / borrow-not-own.** Journal owned by engine, borrows `kv_`; runtime
  owns no KvStore. Unchanged — the worker borrows the same engine-owned journal.
- **Freeze-at-mint / Option-A.** Untouched (C0 doesn't alter persist/replay content).

## Hazards + proposed resolutions (Sol/Fable opine targets)

1. **mtx_-under-join deadlock** — resolved by DECISION 1 (worker never takes mtx_).
   Confirm no hidden mtx_ acquisition on the prune/page path.

2. **[RESOLVED in #2314 — folded, do NOT re-address in C0.]** The prune-vs-persist gauge
   lost-update was found (Sol opine + Fable advisor) to be a real ceiling-breach → indirect
   evidence-loss bug that PRE-DATES C0 and is latent in the shipped journal. Fixed in #2314
   commit 33e329b1 via **rebase-as-delta**: gauges are atomic<int64_t> running counters
   updated by RMW only (persist fetch_add; prune rebases to scanned-actual then fetch_subs
   removals; no absolute store), clamp-at-read. Pure fetch_sub was rejected (bricks writes on
   a fail-closed boot seed). C0 rebases onto the fixed base, so the retry-persist-vs-worker-
   prune interleaving C0 adds is already covered by the RMW scheme. Original (WRONG) analysis
   kept below for history:

   ~~prune-vs-persist newly concurrent.~~ Today prune (heartbeat phase-2) and persist
   (heartbeat phase-1) are sequential on ONE thread. After C0 prune runs on the worker
   while persist stays on the heartbeat → they can interleave. Both take `KvStore.mu_`
   (serialized at the DB). The size gauges can transiently skew: persist's atomic
   `+=` can be overwritten by prune's atomic `store(survivors)` → a bounded undercount
   that self-corrects next prune, within the 2x-headroom hard ceiling. NOTE: page-vs-persist
   concurrency ALREADY exists today (reconnect page vs heartbeat persist), so only the
   prune-vs-persist gauge skew is new. Proposed: ACCEPT + document (matches the existing
   "gauges are estimates" posture, the boot-seed conservatism reviewers already accepted).
   OPEN for Sol: is the transient skew acceptable, or worth serializing?

3. **worker ↔ journal destruction order.** `lifecycle_journal_` (`:373`) destructs
   BEFORE `spark_drain_worker_` (`:366`) in ~GuardianEngine (reverse decl order). Safe
   ONLY because stop() joins the worker first (the existing `:369-372` comment). C0
   makes the worker DEPEND on the journal, so this becomes load-bearing. OPTIONS:
   (a) keep relying on the stop()-before-dtor contract (both teardown paths honor it) +
   a defensive comment; (b) reorder members so the worker destructs before the journal
   (join-in-worker-dtor happens while journal still alive), removing the reliance.
   Proposed: (b) reorder — cheap, removes a footgun. OPEN for Sol.

4. **reconnect prompt re-send-all.** Reconnect must still trigger a prompt full re-page
   (flush the journal to the freshly-connected server), not wait up to 5s for the backstop.
   Proposed: replace the `page_journal()` call at `agent.cpp:1734` with a worker KICK —
   add `GuardianOutboxDrainWorker::notify()` (bump the Signal generation + cv.notify) and
   call it from the reconnect hook (via an engine method). Preserves promptness; no paging
   on the reconnect thread. OPEN: keep `page_journal()` as a thin kick-wrapper for the
   reconnect hook, or wire the worker directly?

5. **prune stopping_ honor.** `page_into_window` checks `stopping_` mid-loop; confirm
   `prune()`/`prune_locked_` bail promptly on `stopping_` too (add a check if absent), so
   a stop during a long prune scan doesn't delay the worker join.

6. **cadence on the worker.** Prune every 4th was a heartbeat-tick count. On the worker
   (CV-wake + 5s backstop), a wake-count "every 4th" would prune too often under enqueue
   storms. Proposed: TIME-based prune cadence (e.g. >= prune_interval since last prune),
   decoupled from wake frequency. Page runs every wake (bounded by the existing
   JournalPagingBucket rate limiter, so no fleet-cost regression). OPEN for Sol: interval.

## Validation plan

- Preserve/extend the existing `[tsan]` concurrent persist+page+prune+drain stress
  (added in PR-Ag FR7/QE-1) — now with prune+page actually ON the worker thread.
- New: stop-race under active maintenance (request_stop mid-prune / mid-page on the
  worker; assert clean join, no late window mutation).
- New: reconnect-kick triggers a prompt page (no 5s wait).
- Chaos CH-5/CH-6 (contended KvStore) to confirm the heartbeat no longer stalls.
- Full agent suite + TSan green.

---

## As built

Every open question above is now resolved; the deltas from the design are listed here so a
reviewer diffs against reality, not the plan.

### Resolutions of the OPEN items

- **Hazard 3 (destruction order)** — took option (b). `lifecycle_journal_` is now declared
  BEFORE `spark_scheduler_`/`spark_drain_worker_` in `guardian_engine.hpp`, so reverse-order
  destruction joins the worker (in `~GuardianOutboxDrainWorker`) while the journal is still
  alive. The stop()-before-dtor contract still holds; it is no longer the ONLY thing holding.
- **Hazard 4 (reconnect prompt re-send-all)** — kept `page_journal()` as the thin kick-wrapper.
  `agent.cpp`'s reconnect hook is unchanged; `GuardianEngine::page_journal()` now takes `mtx_`
  briefly and calls the new `GuardianOutboxDrainWorker::notify()`. The worker is never exposed
  to `AgentImpl`.
- **Hazard 5 (prune stopping_)** — added. `prune_locked_` bails on entry, inside the
  per-evicted-key classification loop, and before the label-GC / quarantine-bounding scans.
  `page_into_window` gained an entry check (taken BEFORE `paging_mutex_`, so a page never
  queues behind an in-flight prune during shutdown) and a check in the candidate-build loop,
  on top of its existing per-batch gate.
- **Hazard 6 (cadence)** — `kDefaultPruneIntervalMs = 120'000`, measured on `steady_clock`
  (the retention comparison itself still uses wall clock, since batch `ts_ms` is `system_clock`
  and must survive a reboot). The timer is seeded at CONSTRUCTION and stamped BEFORE each pass,
  so neither the boot barrier nor a throwing/stop-aborted prune causes a re-prune storm.

### Departures from the design

1. **No `shared_ptr<GuardianSparkRuntime>` was added to the worker.** It already holds
   `GuardianSparkRuntime& rt_` under exactly the lifetime contract the design wanted (joined
   before the runtime is torn down). Maintenance uses that reference. Only the journal pointer
   is new.
2. **The maintenance-exception counter lives ON the worker**
   (`journal_maint_exception_count()`), not as a pointer back to the engine's atomic.
   `GuardianEngine::journal_stats()` SUMS the engine's counter and the worker's into the single
   operator-facing `guardian_journal_maint_exceptions` tag, so the heartbeat contract is
   unchanged while the two failure domains stay separately inspectable in code.
3. **The send-wrapper fix went further than "pre-resolve the pointer".** It no longer captures
   `this` at all (`guardian_engine.cpp` `journaled_send`), which is what makes "the worker
   thread touches no engine state" a property you can check by reading the lambda's capture
   list rather than by auditing its body.
4. **`journal_maintenance_tick` does NOT kick the worker after a successful retry-persist.**
   Paging is already strictly more frequent than before (the worker's 5 s backstop vs the 30 s
   heartbeat), so the kick would buy no latency the backstop does not already bound, at the
   cost of an `mtx_ -> Signal.mu` lock edge on the heartbeat path.
5. **`journal_tick_count_` was deleted** from `GuardianEngine` — the every-4th-tick rule it
   served no longer exists (the worker's time cadence replaces it), and the static
   `journal_now_ms()` helper moved from `guardian_engine.cpp` to the worker's TU.

### Validation

- `[spark][guardian][drain][maint]` — 10 new cases in
  `tests/unit/test_guardian_outbox_drain_worker.cpp`: paging + the same-wake re-drain, the
  reconnect kick's promptness, notify-after-stop inertness, the TIME-based cadence (the
  explicit regression guard against a per-wake prune), stop-during-maintenance joining cleanly,
  and the two firewalls not starving each other.
- `[tsan]` — a new checkpoint driving the POST-C0 shape: maintenance on the worker thread
  racing a persister thread (the heartbeat's surviving phase-1) and a kicker thread (reconnect).
  The pre-existing `[spark][runtime][journal][tsan]` stress is unchanged and still passes.
- `test_guardian_engine_spark_reconcile.cpp` — the `page_journal` case now asserts the
  ASYNC contract (a pass appears well inside the 5 s backstop, i.e. the kick caused it).
