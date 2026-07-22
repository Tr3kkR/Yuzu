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
  member declaration order AT THE TIME OF WRITING destroyed `lifecycle_journal_` (declared
  last, `:373`) BEFORE `spark_drain_worker_` (`:366`), so this relied on stop() having run.
  As built this is reversed: the journal is declared FIRST, so reverse-order destruction
  joins the worker while the journal is alive without depending on stop().
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

   > **WRONG, and shipped wrong in the first cut — corrected in the governance hardening
   > round.** "Bounded by the JournalPagingBucket" is false: the bucket charges a token only
   > when a batch pages NET-NEW work, so whenever the send window already holds every
   > candidate (the normal state while the link is down and the backlog is retained) it never
   > throttles and every wake re-runs a full `list_entries` + parse + `validate_record` sweep.
   > The bucket is a WIRE limiter, not a SCAN limiter. Gate 3 measured the corrected steady
   > state at one full scan per 10-20 s even after a naive fix, against one per 30 s pre-C0.
   > Page therefore got its own 30 s time cadence, exactly like prune, with the reconnect kick
   > forcing an immediate page so replay promptness is unaffected.

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
- **Hazard 6 (cadence)** — `kGuardianJournalPruneInterval` (120 s), measured on `steady_clock`
  (the retention comparison itself still uses wall clock, since batch `ts_ms` is `system_clock`
  and must survive a reboot). The timers are LOCALS in `loop()` and, since the Sol review, stamped AFTER each pass so the
  cadence is a minimum GAP rather than start-to-start.

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

- `[spark][guardian][drain][maint]` — new cases in
  `tests/unit/test_guardian_outbox_drain_worker.cpp`: paging + the same-wake re-drain, the
  reconnect kick's promptness, notify-after-stop inertness, the TIME-based cadence (the
  explicit regression guard against a per-wake prune), stop-during-maintenance joining cleanly,
  and the two firewalls not starving each other.
- `[tsan]` — a new checkpoint driving the POST-C0 shape: maintenance on the worker thread
  racing a persister thread (the heartbeat's surviving phase-1) and a kicker thread (reconnect).
  The pre-existing `[spark][runtime][journal][tsan]` stress is unchanged and still passes.
- `test_guardian_engine_spark_reconcile.cpp` — the `page_journal` case now asserts the
  ASYNC contract (a pass appears well inside the 5 s backstop, i.e. the kick caused it).

---

## Governance hardening round (#2298 C0)

The first cut passed a full agent suite and a TSan run, then a 7-agent governance pipeline
found two BLOCKING test defects and a set of real behavioural ones. Recorded here because
several are corrections to claims made ABOVE, not just to code.

### Behavioural corrections

- **Page got its own 30 s cadence** (`kGuardianJournalPageInterval`). The design's "the
  paging bucket already bounds it" was wrong - see the callout under hazard 6. Three
  independent reviewers reached the same fix. `notify()` now also sets a `force_page_` flag
  so the reconnect kick still pages immediately, which is what keeps the cadence from
  delaying replay.
- **The drain pass is bounded** (`kGuardianDrainBudget = 512`, via the new
  `GuardianSparkRuntime::drain_bounded()`; plain `drain()` is unchanged). Unbounded, a slow stream drains the whole 4096-entry window
  - measured at ~82 s at 20 ms/send - and post-C0 that starves retention until the journal
  hits its write ceiling and DROPS audit records. Pre-C0 prune ran on the heartbeat thread and
  was immune; this coupling is created by the relocation, so it is C0's to fix. A truncated
  pass re-drains without waiting, so throughput is unchanged.
- **The loop is reordered to maintenance-then-one-drain.** This ships anything paged in the
  SAME cycle, which is what the old conditional second drain existed for - and that second
  drain ran un-gated after `stop()` was already blocked in `join()`.
- **The first cycle runs without waiting**, so the seeded boot replay no longer sits behind a
  periodic bound or the first outbox enqueue.
- **`stopping_` now PRECEDES the heavy KvStore calls** rather than straddling them: prune's
  parse/quarantine loop (up to 2000 renames x 5 s busy timeout), its `del_keys`, and page's
  `list_entries` after the boot barrier. Without this the post-`request_stop()` exit was
  unbounded, and `stop()` holds `mtx_` across the join, so everything else blocked with it.
- **`Signal::stopping` is atomic**, making `stop_requested()` lock-free and noexcept. It was
  the only call in `loop()` outside a `try`, so a `std::system_error` from its `lock_guard`
  would have terminated the agent (the #2037 class).
- **`rollback_spark_wiring_locked` signals the journal first**, mirroring `stop()`, so a
  wiring failure cannot block BOOT on a full maintenance pass.
- **`page_journal()` regained its B4a firewall**, dropped in the first cut.

### The invariant is now enforced, not just documented

`GuardianEngine::mtx_` is a `WorkerHostileMutex` that asserts in debug/sanitizer builds that
it is never locked on the drain-worker thread. The first cut hardened the wrong half: it
removed the `this` capture from the send wrapper, but the real exposure is that `send` is an
arbitrary `std::function` injected from `agent.cpp`, and nothing structural stopped a future
PR adding a `guardian_->...` call to it. A violation now fails a test instead of hanging a
fleet. The long-term shape - `stop()` not holding `mtx_` across the join, which deletes the
invariant outright - is deliberately left to a later rung.

### Test corrections (both were BLOCKING)

- The "prune cadence is TIME-based" test asserted `batches_pruned() == 0` against an EMPTY
  journal, which is true whether prune ran once or twenty times. It proved nothing, and its
  own execution pattern was a live instance of the unbounded-rescan bug it was supposed to
  guard. Rewritten to count real scans through `set_pre_scan_hook_for_test` against a running
  worker under a 200-wake storm.
- The reconcile `page_journal` test inferred "the kick caused this page" from a 1 s window
  against a 5 s backstop - but the worker starts during fixture construction, so that backstop
  was already ticking through setup and could fire inside the window. It now pins the bound to
  an hour via a new `set_drain_worker_timing_for_test` seam, so only the kick can page.
- The stop-during-maintenance test called `request_stop()` BEFORE `stop()`, so every pass
  short-circuited at the entry gate and the mid-scan gates were never executed. It now fires
  `request_stop()` from INSIDE a scan via the pre-scan hook.
- The TSan stress persisted DIRECTLY into the journal, bypassing the real phase-1 path
  (`snapshot_pending` -> `persist` -> `erase_persisted_prefix` -> `backfill_batch_provenance`)
  - precisely the state C0 splits across two threads - and used a bare sink rather than the
  `mark_batch_sent` wrapper, so no KvStore write ever raced prune's `del_keys`. Both fixed.
- Added: maintenance-exception firewalling driven nonzero (the pre-scan hook throws straight
  out of `prune_locked_`, so no new seam was needed), and an enqueue-wake-does-not-page case.

### Filed as follow-ups, not fixed here

Deliberately out of C0's scope: building `OutboxEntry` vectors before the window-headroom
check (wasted work in the link-down state); prune and page each running their own full scan
back-to-back; `JournalPagingBucket::refill` being fed `system_clock` (a backward NTP step
freezes refill); the shutdown classification-counter under-count; `erase_persisted_prefix`'s
count-based erase racing drop-oldest; renaming `GuardianOutboxDrainWorker` /
`page_journal()` now that neither name describes what it does; handing the worker a
`shared_ptr` to delete the declaration-order dependency; and documenting
`guardian_journal_maint_exceptions` in the metrics manual.

(Of that list, the `shared_ptr` change, the metrics-manual entry, and the
build-before-headroom-check waste were subsequently FOLDED IN rather than filed — see the
later rounds below.)

---

## Second hardening round (Sol adversarial review)

An independent read of the post-governance branch found one BLOCKING defect and several
material ones that the 7-agent pipeline had missed. Recorded because the BLOCKING one was
introduced BY the first hardening round - the fix for a hazard was itself a hazard.

- **The `mtx_` tripwire was a data race and a potential use-after-free.** It held a raw
  pointer to the worker, written under `mtx_` but read BEFORE `mtx_` was acquired, and
  wiring rollback destroys the worker right after clearing it. It also could not reliably
  fire: `assert` is a no-op under `NDEBUG`, so a sanitizer-enabled release build logged the
  violation and deadlocked anyway, and the enablement macro was GCC-only. Replaced with a
  thread-local role marker plus `std::abort()`, enabled on GCC and Clang sanitizers.
- **The bounded drain starved compliance.** Lifecycle drains first, so one shared budget let
  it consume a whole pass - a rationed version of the detection blackout Gate 4 UP-3
  explicitly removed, reintroduced four lines below the comment that documents it. Now a
  reserved share with allowance transferring both ways.
- **A count bound is not a time bound**, and nothing observed shutdown mid-pass: a whole
  512-send pass could BEGIN after `stop()` was blocked in `join()`. Added a wall-clock cap
  and a per-send stop predicate.
- **A prune throw silently ate a forced page**, because prune and page shared one `try` and
  both cadence stamps were taken before the pass. Separate firewalls; a forced page that did
  not run re-arms.
- **The cadence was start-to-start, not a minimum gap**, so a pass longer than its interval
  was due again the instant it finished. Stamped after the attempt.
- **Reconnect refill hole**: with a full window the kick's page places nothing, the drain
  then empties the window, and the backlog waited a full interval. Re-armed for exactly that
  case.
- **Housekeeping stop-gates were incomplete** between the sent-label GC and quarantine
  bounding.
- **An existing test was silently invalidated** by the first-cycle-immediate change.

Two further bugs surfaced while building the fairness fix, caught by the new tests rather
than by review: the allowance rollover was one-directional, and an empty log with an
exhausted budget falsely reported truncation.

The journal also moved to `shared_ptr`, which DELETES the declaration-order dependency the
first round documented as load-bearing. Section 24's invariant is kept, since the
"never take mtx_" half still stands, but the ordering half is no longer correctness-critical.

### Cutover gaps closed after the review

All three items the Sol review left open are now covered.

- **The `WorkerHostileMutex` abort is proven.** A forked-child death test installs a send that
  takes `mtx_` from the worker thread and asserts the child dies by `SIGABRT`. Proven
  load-bearing by mutation: stub the guard and the child DEADLOCKS exactly as the production
  bug would, and the test goes red. The parent polls with a deadline rather than blocking in
  `waitpid`, because the failure under test IS a hang. Skips cleanly where the guard is
  compiled out (release without sanitizers), since there the violation deadlocks instead.
- **Production boot order is tested.** `wire_spark_engine()` before `start_local()` - what
  agent.cpp actually does, and the reverse of what every prior test including the shared
  fixture did. The worker's immediate first-cycle maintenance now races the pre-network
  re-arm on one KvStore mutex; the test asserts neither starves the other.
- **The send is exercised with real `Retain` semantics.** `StreamLikeSink` mirrors
  `send_guardian_outbox_entry` (absent stream or failed write -> `Retain`), driving a full
  link-down/backlog/reconnect cycle and a mid-drain link drop. This pins that a `Retain`
  reports `truncated == false`, so a down link does not put the worker in a hot re-drain
  loop - invisible to an always-Sent sink.

That last test also corrected a misconception of mine rather than a defect: it initially
asserted exactly-once delivery and failed at 15 sends for 12 distinct events. The durable
journal is AT-LEAST-ONCE on purpose - it replays on every reconnect and the server
de-duplicates on the `event_id` PK, counting
`yuzu_server_guardian_events_redelivered_total`, which the metrics manual documents as normal
after an outage and explicitly not a loss signal. Changing the code to satisfy the original
assertion would have broken replay.


---

## Third hardening round (PR #2345 blocking review)

A human reviewer blocked the PR; two external model reviews then found more, including in the
fixes. Recorded because three of the findings were the SAME defect classes earlier rounds had
supposedly closed.

- **The wall budget was not sliced, only the count.** `drain_log_unlocked` checks the deadline
  BEFORE the count budget, so once lifecycle consumed the single shared wall, compliance
  returned on entry without ever spending a reserved slot. The compliance reserve added in
  round 3 was therefore dead under time pressure - the Gate-4 UP-3 detection blackout reached
  through the other limit. Lifecycle now takes a slice of the wall; compliance and the
  lifecycle-retry get the full pass deadline; the ratio is normalised once for `den == 0`,
  `num > den` and the wall-only case. The guarantee is stated honestly in the code: compliance
  gets an opportunity to START, not a slice of time, because an in-flight send is
  uninterruptible.
- **The headroom precheck reintroduced B2 starvation.** It `break`'d before `page_cursor_`
  advanced, so an oversized head batch pinned the rotation and smaller newer batches never
  paged. Now `continue` with the cursor advanced. Paging a newer batch ahead of an older
  blocked one was verified tolerable against the server rather than assumed.
- **The refill re-arm reintroduced UP-2 amplification.** `lifecycle_headroom() > 0` fired when
  one slot opened for a batch needing up to 256, so `force_page_` re-armed every cycle and each
  forced page is a full journal scan. It now requires room for the smallest actually-blocked
  batch (`min_blocked_headroom`), and sets `skip_wait` so it acts immediately instead of after
  the periodic bound - a latency the 20 ms-bound reconnect tests had masked entirely.
- **`drain_once()`** is documented as test-only with no production caller, noting it bypasses
  every limit the worker applies.

### The test discipline that was missing

Four hollow tests across this PR shared one signature: none asserted the discriminating
observable of the mechanism it claimed to cover. The rule now applied is that **a test claiming
to cover a branch must assert that branch's own flag or counter, and must be observed red
against the unfixed code before it counts.** Each round-4 fix has such a test. The refill test
was itself hollow on the first attempt - it forced a page that was never headroom-blocked - and
was caught by exactly that rule.

`metrics.md` is now bound to the emitter by a mechanical cross-check test in the H2/G9
bind-or-drift idiom. It proves NAME PRESENCE only; it cannot catch a row whose description is
wrong, which is the other error this round fixed. That limitation is stated in the test and
should not be trimmed.

### A pattern worth naming

The false `maint_exceptions` description was corrected in `metrics.md` and one changelog
fragment while remaining false in the OTHER fragment and in this document's own flip-list -
found by governance Gate 2 after the fix commit. Prose written from intention at time T and
never reconciled at T+n is the recurring failure of this PR, and it recurred inside the commit
that fixed it. Bind doc claims to executable checks wherever possible; treat the flip-list as a
checklist to be executed, not a record of intent.

---

## REQUIRED at the `prefer_spark` flip (Gate 6 enterprise-readiness)

Everything in this change that relocates journal maintenance is DORMANT until the Spark
detection path becomes authoritative. The changelog says so, which is the right posture for
shipping now - but it creates an obligation later, and an obligation recorded only in a review
transcript is one nobody will honour.

Whichever PR flips `prefer_spark` MUST also:

1. **Ship its own changelog entry** cross-referencing this one, stating that C0 is now live and
   what actually changes for an operator: the heartbeat and reconnect paths no longer touch the
   KvStore for journal work, and retention/paging now run on the drain worker at their own
   cadences. Without this the behaviour changes with no release note of its own, because the
   note was consumed by a release where nothing happened.
2. **Update the `yuzu.guardian_journal_maint_exceptions` row** in `docs/user-manual/metrics.md`
   to drop the dormancy framing. That counter's meaning has already shifted once during this
   branch (it aggregates the heartbeat's retry-persist and the drain worker's prune/page; convergence
   sweeps are NOT included - they have their own `yuzu.guardian_sweep_exceptions`, as does
   outbox delivery via `yuzu.guardian_drain_exceptions`) and shifts again in effect at the
   flip. All three carry dormancy framing that must be shed at the same time.
3. **Close or explicitly risk-accept the shutdown-classification undercount** (Gate 6
   compliance, CC7.2): when a stop lands mid-classification, the remaining evicted keys are
   counted in neither `evicted_sent_unacked` nor `evicted_no_send_evidence`, so the counter an
   auditor reads as "audit gap" reports a SMALLER gap than actually occurred. Under-counting a
   loss indicator is worse than under-counting a success one. Dormancy caps the severity
   today; it does not once C0 is live. This needs to be an explicit checklist item on #2298,
   not prose in a design doc.
4. **Land the `yuzu_fleet_guardian_*` server rollup** (#2298 gate 3). The loss and redelivery
   signals exist only in per-agent heartbeat tags today, so compliance evidence automation
   scraping `/metrics` cannot see them at all, and one wedged endpoint is invisible without
   inspecting that host by hand.
5. **Surface `gauge_underflow_`** (pre-existing #2303, self-flagged in
   `guardian_lifecycle_journal.hpp` as needing to land WITH the cutover): the accounting bug it
   detects camouflages as a healthy empty journal because `journal_batch_count` clamps to 0.
6. **Add a "seconds since last successful page/prune pass" gauge** (Gate 6 sre). It is the only
   viable liveness signal for the two wall-clock hazards AND for a release-build deadlock,
   where the `mtx_` guard compiles out and a wedged worker is indistinguishable from an idle
   healthy one.
7. **Run chaos scenario CH-5** (live-event latency under KvStore contention, UAT rig). It is
   the only scenario that measures the thing C0 was built to fix, so it is the flip's genuine
   go/no-go rather than a formality.

Tracked on #2298, which is the cutover gate list.
