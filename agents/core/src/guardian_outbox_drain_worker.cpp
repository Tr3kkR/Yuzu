#include "guardian_outbox_drain_worker.hpp"

#include "guardian_joined_thread_role.hpp"
#include "guardian_lifecycle_journal.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <random>
#include <stdexcept>

namespace yuzu::agent {

namespace {
/// The one instance of the joined-thread flag (see guardian_joined_thread_role.hpp for
/// why it must not be a header-inline thread_local).
thread_local bool tl_guardian_joined_thread = false;

/// Wall clock in ms - the journal's retention basis (batch ts_ms is system_clock).
/// Deliberately NOT steady_clock: prune compares against persisted timestamps that
/// survive a reboot. The maintenance CADENCE below uses steady_clock instead, so a
/// wall-clock step cannot make maintenance either stall or spin.
std::int64_t journal_now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

/// steady_clock in ms for the item-6 success stamps. Clamped >= 1: 0 is the "start() never
/// ran" sentinel, and steady_clock's epoch is unspecified (commonly boot), so an honest
/// reading CAN be 0 early in a machine's life - the clamp costs 1 ms of accuracy once ever.
std::uint64_t success_stamp_now_ms() {
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now().time_since_epoch())
                        .count();
    return ms > 0 ? static_cast<std::uint64_t>(ms) : 1;
}

/// steady_clock in ms for the item-12 forced-page jitter deadline. Unclamped, unlike the
/// stamps above: 0 here means "no deferral pending", and it is written only as
/// now + a positive offset, so it can never collide with that sentinel.
std::int64_t steady_now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}
} // namespace

std::chrono::milliseconds guardian_jitter_offset(std::mt19937& rng,
                                                 std::chrono::milliseconds upper) {
    if (upper.count() <= 0)
        return std::chrono::milliseconds{0};
    std::uniform_int_distribution<std::int64_t> dist(0, upper.count() - 1);
    return std::chrono::milliseconds{dist(rng)};
}

YUZU_EXPORT void set_guardian_joined_thread(bool on) noexcept { tl_guardian_joined_thread = on; }
YUZU_EXPORT bool on_guardian_joined_thread() noexcept { return tl_guardian_joined_thread; }

GuardianOutboxDrainWorker::GuardianOutboxDrainWorker(GuardianSparkRuntime& rt, SendFn send,
                                                     std::uint64_t periodic_bound_ms,
                                                     GuardianMaintenanceConfig maintenance)
    : rt_(rt), send_(std::move(send)), periodic_bound_ms_(periodic_bound_ms),
      maint_(maintenance), sig_(std::make_shared<Signal>()),
      jitter_rng_(std::random_device{}()) {}

GuardianOutboxDrainWorker::~GuardianOutboxDrainWorker() { stop(); }

void GuardianOutboxDrainWorker::start() {
    {
        std::lock_guard<std::mutex> lk{sig_->mu};
        if (started_ || sig_->stopping.load(std::memory_order_acquire))
            return;
        started_ = true;
        // Jitter the BOOT forced page here rather than in the loop: set before the thread
        // exists, it is already in force for the loop's very first wait, and a caller can
        // observe the deferral without racing the thread's first cycle (item 12). The boot
        // force bypasses the cadence entirely, so phasing the timers alone would not spread
        // a fleet that restarted together.
        if (maint_.jitter)
            force_page_not_before_ms_ =
                steady_now_ms() + guardian_jitter_offset(jitter_rng_, maint_.page_interval).count();
    }
    // Seed the item-6 staleness stamps NOW, not on the first pass: a thread that starts and
    // then dies (or never completes a pass) reads as an ever-growing age from its very first
    // heartbeat, which is what makes worker death visible at all (flip item 14 - sparse
    // counters at zero are indistinguishable from healthy idle).
    {
        const auto now = success_stamp_now_ms();
        last_page_success_steady_ms_.store(now, std::memory_order_relaxed);
        last_prune_success_steady_ms_.store(now, std::memory_order_relaxed);
    }
    // Captures the shared Signal (NOT `this`), so a copy that outlives this
    // worker (installed on the runtime, cleared in stop() but a copy already
    // taken by an in-flight enqueue stays safe) touches a still-alive Signal.
    auto sig = sig_;
    rt_.set_outbox_enqueue_waker([sig] {
        {
            std::lock_guard<std::mutex> lk{sig->mu};
            ++sig->gen;
        }
        sig->cv.notify_all();
    });
    thread_ = std::thread([this] {
        // TOP-LEVEL firewall. The inner passes are each firewalled, but the loop's own tail -
        // the lifecycle_headroom() call (std::mutex::lock can throw system_error) and the
        // cadence arithmetic - sits outside them, and this is a bare thread: an escape
        // terminates the whole agent daemon (the #2037 class, #2345 Gate 3 cpp-safety).
        try {
            loop();
        } catch (...) {
            // Count it BEFORE logging. start() is one-shot, so the thread never comes back;
            // without a counter a worker that dies on its first cycle is indistinguishable on
            // the heartbeat from a healthy idle one, because the journal tags are emitted
            // sparsely and a dead worker's counters simply stay at zero (#2345 Gate 6 SRE).
            // Folded into the maintenance-exception tag: an operator reading a nonzero
            // maint_exceptions is already told to expect stalled journal maintenance, which is
            // exactly what a dead loop causes - with the log line naming the difference.
            journal_maint_exceptions_.fetch_add(1, std::memory_order_relaxed);
            try {
                spdlog::critical("Guardian drain worker: loop terminated by an exception; the "
                                 "worker has stopped, journal maintenance and outbox delivery "
                                 "are no longer running on this agent.");
            } catch (...) {
            }
        }
    });
}

void GuardianOutboxDrainWorker::stop() {
    bool first_stop = false;
    {
        // Stored UNDER the mutex even though the flag is atomic: a waiter evaluating the
        // wait_for predicate holds `mu`, so this ordering is what makes a lost wakeup
        // impossible. The atomicity exists for the lock-free stop_requested() reads.
        std::lock_guard<std::mutex> lk{sig_->mu};
        if (!sig_->stopping.load(std::memory_order_relaxed)) {
            sig_->stopping.store(true, std::memory_order_release);
            first_stop = true;
        }
    }
    if (first_stop) {
        // Clear the runtime's slot so no NEW enqueue installs a wake; a copy
        // already taken by an in-flight enqueue stays safe (still-alive Signal).
        rt_.set_outbox_enqueue_waker({});
        sig_->cv.notify_all();
    }
    // The join is OUTSIDE the first_stop guard and keyed on joinable(), not on the
    // stopping flag: if a prior stop() threw after setting stopping but before joining
    // (e.g. from ~GuardianOutboxDrainWorker re-entry), a joinable thread would otherwise
    // reach ~std::thread and terminate. Always attempt the join while joinable (Fable).
    if (thread_.joinable())
        thread_.join();
}

void GuardianOutboxDrainWorker::notify() {
    {
        std::lock_guard<std::mutex> lk{sig_->mu};
        if (sig_->stopping.load(std::memory_order_acquire))
            return;
        // Force a page on the next cycle: without this the reconnect kick would only
        // wake the worker, and the page cadence could still defer the replay by up to
        // kDefaultPageInterval - exactly the promptness the kick exists to provide.
        force_page_.store(true, std::memory_order_release);
        // ...but a fleet reconnects TOGETHER - a gateway bounce, a restored snapshot - and
        // every one of those kicks is a full journal scan plus a token burst landing in the
        // same second. Spread them (item 12). The loop derives its WAIT DEADLINE from this
        // value, so the deferral is a real scheduled wake: merely polling it at the 5 s
        // backstop would re-synchronise every agent onto the backstop tick and buy nothing.
        // FIRST kick wins: only draw a deadline when none is pending. Re-drawing on every
        // kick would let a flapping link postpone the replay indefinitely - each kick lands a
        // fresh U[0,5s) offset, so the forced pass (the one that re-offers sent-labelled
        // batches whose in-flight send may have been lost) keeps being pushed back by exactly
        // the event it exists to respond to. One draw is all the fleet spread needs; making
        // the deferral monotone costs nothing and removes the starvation shape.
        if (maint_.jitter && force_page_not_before_ms_ == 0) {
            const auto offset = guardian_jitter_offset(jitter_rng_, kGuardianForcedPageJitterMax);
            force_page_not_before_ms_ = steady_now_ms() + offset.count();
        }
        ++sig_->gen;
    }
    sig_->cv.notify_all();
}

void GuardianOutboxDrainWorker::drain_once() { rt_.drain(send_); }

GuardianSparkRuntime::DrainOutcome GuardianOutboxDrainWorker::drain_bounded() {
    GuardianSparkRuntime::DrainLimits limits;
    limits.max_entries = maint_.drain_budget;
    limits.max_wall = maint_.drain_max_wall;
    // Checked before EVERY send, not once per pass: a bounded pass is still a count bound,
    // and one slow-but-succeeding send makes it arbitrarily long while GuardianEngine::stop()
    // holds mtx_ waiting on our join (#2298 Sol review). The in-flight send cannot be
    // interrupted; no further one starts.
    limits.should_stop = [this] { return stop_requested(); };
    return rt_.drain_bounded(send_, limits);
}

GuardianMaintenanceResult GuardianOutboxDrainWorker::maintenance_once(GuardianMaintenanceOps ops) {
    GuardianMaintenanceResult result;
    if (!maint_.journal)
        return result;
    // NOTE: no engine mtx_ anywhere on this path, by construction - see the class doc.
    if (ops.prune) {
        result.prune_attempted = true;
        // Capture read_ok: a prune whose scan fails returns without throwing, so the success
        // stamp cannot use "did not throw" as its liveness signal (#2452).
        result.prune_read_ok = maint_.journal->prune(journal_now_ms()).read_ok;
    }
    if (ops.page) {
        result.page_attempted = true;
        const auto stats = maint_.journal->page_into_window(rt_, journal_now_ms(), ops.replay_sent);
        result.records_paged = stats.records_paged;
        result.headroom_blocked = stats.headroom_blocked;
        result.min_blocked_headroom = stats.min_blocked_headroom;
        result.deferred_no_token = stats.deferred_no_token;
        result.skipped_already_sent = stats.skipped_already_sent;
        result.sent_scan_failed = stats.sent_scan_failed;
        result.page_read_failed = stats.read_failed;
    }
    return result;
}

void GuardianOutboxDrainWorker::loop() {
    // GuardianEngine::stop() joins this thread while holding mtx_, so mtx_ must never be
    // taken here - including from the INJECTED send. The marker is what makes that abort
    // instead of deadlock; the scheduler's lanes carry it for the same reason.
    const GuardianJoinedThreadRole role_marker;
    // The cadence timers are LOCALS, not members: nothing outside this thread can read
    // or write them, so the public maintenance_once() seam carries no timer state and
    // cannot race the worker no matter which thread a test calls it from.
    auto last_prune = std::chrono::steady_clock::now();
    auto last_page = std::chrono::steady_clock::now();
    // PHASE JITTER (item 12). Backdating each timer by a uniform offset inside its own
    // interval lands the first cadence pass anywhere in that interval instead of exactly one
    // interval after boot; the steady cadence afterwards is unchanged. This matters much less
    // than the forced-page jitter below - agents boot at their own times - but it is free, and
    // it covers the case where they do not (a fleet-wide rollout or a mass restart).
    if (maint_.jitter) {
        std::lock_guard<std::mutex> lk{sig_->mu}; // the RNG lives under this lock
        last_prune -= guardian_jitter_offset(jitter_rng_, maint_.prune_interval);
        last_page -= guardian_jitter_offset(jitter_rng_, maint_.page_interval);
    }
    std::uint64_t seen = 0;
    // The FIRST cycle runs WITHOUT waiting: force_page_ is seeded true for the boot journal
    // replay, and making that replay sit behind a full periodic bound - or, worse, behind
    // whenever the first outbox enqueue happens to arrive - contradicts the point of seeding
    // it. Nothing here takes the engine mtx_, so running concurrently with the remainder of
    // wire_spark_engine is safe.
    bool skip_wait = true;
    // Concurrent arm/disarm traffic can refill the window between the end-of-cycle headroom
    // check and the next page pass, so the immediate re-arm could chain indefinitely - each
    // link a full journal scan. The token bucket does NOT bound that: take() is charged only
    // when a batch pages net-new work, so a chain that pages NOTHING consumes no token and the
    // bucket's short-circuit never engages. The cap below is therefore the only bound on a
    // zero-page chain, and is load-bearing (#2345 Gate 3 cpp-safety + perf).
    // The refill re-arm is rate-limited by TIME, not by a cycle counter.
    //
    // A counter reset "after a real wait" is not a bound at all: cv.wait_for returns
    // IMMEDIATELY whenever the generation already moved, and every outbox enqueue bumps it, so
    // under an arm/disarm storm the wait branch runs without ever waiting and resets the
    // counter each cycle - restoring exactly the scan amplification the cap was added to
    // prevent (#2345 Gate 4 UP-1). Sharing one counter with the truncated-drain path also let a
    // sustained backlog exhaust it and silently disable the re-arm entirely (UP-2).
    //
    // A minimum interval is immune to both: it bounds forced full-journal scans to one per
    // interval no matter what wakes the loop, while staying far below the 30 s page cadence so
    // reconnect replay is still prompt.
    auto last_refill_page = std::chrono::steady_clock::now() - kGuardianMinRefillInterval;

    const auto firewalled_drain = [this, &skip_wait]() -> std::size_t {
        try {
            // A truncated pass re-arms the next cycle to run WITHOUT waiting, so bounding a
            // drain costs latency only when there is nothing left to ship.
            const auto outcome = drain_bounded();
            skip_wait = outcome.truncated;
            return outcome.sent;
        } catch (...) {
            skip_wait = false;
            const auto n = drain_exceptions_.fetch_add(1, std::memory_order_relaxed) + 1;
            if (n == 1) {
                try {
                    spdlog::error("Guardian drain worker: drain pass threw (firewalled; agent "
                                  "survives, entries retained). Further occurrences counted only.");
                } catch (...) {
                }
            }
            return 0;
        }
    };

    while (true) {
        if (!skip_wait) {
            std::unique_lock<std::mutex> lk{sig_->mu};
            // Wait no longer than the earlier of the periodic backstop and a pending forced
            // page's release time. Without the second term a deferred force is only noticed at
            // the next backstop wake, which for any deferral shorter than the backstop means
            // every agent acts at the same backstop tick - the jitter would defer the work
            // without spreading it, which is the whole point (Sol review).
            auto wait_ms = std::chrono::milliseconds(periodic_bound_ms_);
            if (force_page_not_before_ms_ != 0 && force_page_.load(std::memory_order_acquire)) {
                const auto remaining =
                    std::chrono::milliseconds{force_page_not_before_ms_ - steady_now_ms()};
                if (remaining < wait_ms)
                    // (std::max), not std::max: MSVC's max() macro would clobber it in a
                    // windows.h TU - the same convention the journal and runtime headers
                    // already document for (std::min). std:: qualification does not help;
                    // the preprocessor expands on the identifier plus '('.
                    wait_ms = (std::max)(remaining, std::chrono::milliseconds{0});
            }
            sig_->cv.wait_for(lk, wait_ms, [this, seen] {
                return sig_->stopping.load(std::memory_order_acquire) || sig_->gen != seen;
            });
            if (sig_->stopping.load(std::memory_order_acquire))
                break;
            seen = sig_->gen;
        } else if (stop_requested()) {
            break; // neither the boot cycle nor a truncated drain may outlive a stop request
        }
        // Re-armed below by a truncated drain or a refill; every other cycle waits.
        skip_wait = false;

        // MAINTENANCE FIRST, then ONE drain (C0 #2298 + governance f-1/f-3).
        //
        // Order matters: paging places entries in the send window, and try_page_batch
        // does NOT fire the enqueue waker, so running maintenance ahead of the drain
        // ships anything it paged in the SAME cycle. The previous shape (drain, then
        // maintenance, then a second conditional drain) needed that extra drain and ran
        // it un-gated after stop() was already blocked in join().
        //
        // Both passes are cadence-gated on steady_clock, NOT on wake count: this worker
        // wakes on every outbox enqueue, so gating on wakes would tie a full-journal
        // scan to the event rate. An enqueue wake therefore finds maintenance not due
        // and proceeds straight to the drain, which is what keeps live-event latency at
        // the pre-C0 level.
        const auto now = std::chrono::steady_clock::now();
        // Consume a pending force only once its jitter deadline has passed. A DEFERRAL, never
        // a drop: the flag stays set, the wait above is bounded by the deadline, and the next
        // cycle runs it. (With jitter off the deadline is 0 and this is the plain exchange it
        // always was.)
        bool forced_page = false;
        {
            std::lock_guard<std::mutex> lk{sig_->mu};
            const bool deferred =
                force_page_not_before_ms_ != 0 && steady_now_ms() < force_page_not_before_ms_;
            if (!deferred) {
                forced_page = force_page_.exchange(false, std::memory_order_acq_rel);
                force_page_not_before_ms_ = 0;
            }
        }
        const bool page_due = forced_page || now - last_page >= maint_.page_interval;
        const bool prune_due = now - last_prune >= maint_.prune_interval;

        // Prune and page are firewalled SEPARATELY. Sharing one try meant a prune throw
        // skipped the page that was already marked due - and if that page was FORCED by a
        // reconnect kick, the kick was silently swallowed for a whole cadence interval
        // (#2298 Sol review).
        const auto firewalled = [this](auto&& fn) {
            try {
                fn();
                return true;
            } catch (...) {
                const auto n = journal_maint_exceptions_.fetch_add(1, std::memory_order_relaxed) + 1;
                if (n == 1) {
                    try {
                        spdlog::error("Guardian drain worker: journal maintenance pass threw "
                                      "(firewalled; agent survives, journal retained). Further "
                                      "occurrences counted only.");
                    } catch (...) {
                    }
                }
                return false;
            }
        };

        if (prune_due && !stop_requested()) {
            GuardianMaintenanceResult prune_result;
            const bool ok = firewalled([&] { prune_result = maintenance_once({.prune = true}); });
            // Stamped AFTER the attempt, so the cadence is a minimum GAP rather than
            // start-to-start. Start-to-start means a pass that runs longer than its own
            // interval is due again the instant it finishes, which under KvStore contention
            // degenerates back into continuous scanning (#2298 Sol review).
            last_prune = std::chrono::steady_clock::now();
            // The SUCCESS stamp moves only when the pass genuinely established the retention
            // state: it did not throw (ok), a stop did not abort it, and its journal scan read
            // cleanly (prune_read_ok). A permanently-unreadable prune returns WITHOUT throwing,
            // so gating on `ok` alone would read a stalled retention loop as fresh - the same
            // blindness #2452 closes on the page side. The cadence stamp above deliberately
            // advances regardless (min-GAP pacing). A prune whose scan succeeded but whose DELETE
            // failed DOES advance here: that is surfaced by prune_failures and is a distinct
            // operator situation (#2364), not a scan stall.
            if (ok && prune_result.prune_read_ok && !stop_requested())
                last_prune_success_steady_ms_.store(success_stamp_now_ms(),
                                                    std::memory_order_relaxed);
        }

        GuardianMaintenanceResult page_result;
        if (page_due && !stop_requested()) {
            const bool ok = firewalled(
                [&] { page_result = maintenance_once({.replay_sent = forced_page, .page = true}); });
            last_page = std::chrono::steady_clock::now();
            // The page success stamp is the age gauge an on-call engineer trusts FIRST once the
            // journal is live, so it must read fresh ONLY when this pass made real replay progress
            // OR positively established there was none - never on a pass that returned without
            // doing (or being able to verify) that work (#2452). It advances iff the pass did not
            // throw, was not stop-aborted, AND either:
            //   - it PLACED records (records_paged > 0): replay is demonstrably progressing, so a
            //     stray degraded/read-failure signal on the same pass does not make it stale (this
            //     is what keeps a persistently-flaky single candidate from crying wolf while the
            //     rest of the backlog drains); or
            //   - it cleanly established there was nothing to page: not deferred_no_token (empty
            //     token bucket), not sent_scan_failed (fell back), and not page_read_failed (the
            //     candidate scan, a candidate value read, OR the boot-prune barrier's scan failed).
            // Any other clean-but-fruitless return (deferred, degraded, read-failing, or aborted)
            // now reads as a growing age - exactly the UP-11 blindness this gauge exists to close
            // (L1b #2414). page_read_failed carries the boot-barrier case, which increments
            // prune_failures_ (not page_read_failures_) and so has no page-side counter of its own.
            if (ok && !stop_requested() &&
                (page_result.records_paged > 0 ||
                 (!page_result.deferred_no_token && !page_result.sent_scan_failed &&
                  !page_result.page_read_failed)))
                last_page_success_steady_ms_.store(success_stamp_now_ms(),
                                                   std::memory_order_relaxed);
            // A FORCED page that never ran must not be lost: re-arm so the next cycle
            // retries it rather than waiting out a full cadence interval.
            // ...and one that ran but did NO work because the paging rate-limiter had no
            // token is equally lost: the pass returns clean, so `ok` alone would drop the
            // kick and replay would wait out a full cadence interval after a reconnect.
            if (forced_page && (!ok || page_result.deferred_no_token)) {
                // Under sig_->mu, and clearing the deadline with it: the flag and its
                // deadline are one piece of state and must be mutated as a pair. Set
                // outside the lock, a notify() landing in between would see a zero
                // deadline, draw a fresh one, and defer by up to 5 s a re-arm that exists
                // precisely because the forced page was LOST - the opposite of the intent.
                std::lock_guard<std::mutex> lk{sig_->mu};
                force_page_.store(true, std::memory_order_release);
                force_page_not_before_ms_ = 0;
            }
        }

        if (stop_requested())
            break;
        const auto drained = firewalled_drain();

        // TEST-ONLY item-13 seam: model a throw from the loop's OWN tail (the refill re-arm's
        // rt_.lifecycle_headroom() - std::mutex::lock can throw - and the cadence arithmetic),
        // which sits outside every inner firewall. It fires unconditionally when armed, whereas
        // the real lifecycle_headroom() runs only inside the refill condition below; the point
        // is only to reach the thread lambda's TOP-LEVEL catch, so do not "tighten" this into
        // the refill condition. Inert in production (default false; one relaxed load per cycle).
        // Placed after the top-of-cycle stop gate, so it cannot fire on a cycle where a stop was
        // already observed; a stop landing mid-drain is only seen next cycle, but the throw kills
        // this one-shot worker so no next cycle runs regardless.
        if (inject_loop_tail_throw_.exchange(false, std::memory_order_relaxed))
            throw std::runtime_error{"injected loop-tail throw (item 13 seam)"};

        // Reconnect refill: while disconnected the send window is normally FULL, so the
        // kick's page finds no headroom and places nothing. The drain that follows empties
        // the window - and without this the journal backlog would sit untouched until the
        // next cadence tick, up to a full page_interval after the link came back
        // (#2298 Sol review).
        //
        // The condition is deliberately narrow, because a loose one reintroduces the very
        // scan amplification the cadence exists to prevent (#2298 Gate 4 UP-2, which is
        // exactly what the first version of this re-arm did): "records_paged == 0" is ALSO
        // true in the benign steady state where every candidate is already a window member,
        // and "drained > 0" is true for any compliance/health send that has nothing to do
        // with lifecycle window space. Together those made a routine event stream re-arm on
        // every cycle. Requiring headroom_blocked - a candidate the window could not fit -
        // plus headroom actually existing NOW means we only re-attempt when a real backlog
        // is waiting and the drain genuinely made room for it.
        // Re-arm only once there is room for the SMALLEST batch that was actually blocked.
        // "any headroom > 0" fired when one slot opened for a batch needing up to 256, so
        // force_page_ re-armed every cycle and each forced page is a full journal scan -
        // UP-2's amplification back in the recovery regime (#2345 / Sol).
        //
        // skip_wait is set TOO. force_page_ alone only takes effect on the next wake, and an
        // untruncated drain sleeps the whole periodic bound (5 s in production) before that
        // happens - a latency the existing 20 ms-bound reconnect tests masked entirely.
        // Order matters: the cheap local checks first, so a pass with nothing blocked does not
        // take outbox_mu_ at all (#2345 Gate 2 sec-LOW).
        const auto cycle_end = std::chrono::steady_clock::now();
        if (page_result.headroom_blocked && page_result.min_blocked_headroom > 0 && drained > 0 &&
            cycle_end - last_refill_page >= kGuardianMinRefillInterval &&
            rt_.lifecycle_headroom() >= page_result.min_blocked_headroom) {
            // Deliberately NOT jittered, and any inherited deadline is cleared: this re-arm is
            // backlog RECOVERY on one agent that just made room for a batch it knows is
            // waiting, already floored by kGuardianMinRefillInterval and gated on real
            // headroom. Deferring it would fight the recovery loop rather than spread a fleet.
            // Flag and deadline are set together under sig_->mu - they are one piece of state.
            {
                std::lock_guard<std::mutex> lk{sig_->mu};
                force_page_.store(true, std::memory_order_release);
                force_page_not_before_ms_ = 0;
            }
            skip_wait = true; // act on it NOW, not after the backstop
            last_refill_page = cycle_end;
        }
    }
}

} // namespace yuzu::agent
