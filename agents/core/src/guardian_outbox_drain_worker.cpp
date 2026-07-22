#include "guardian_outbox_drain_worker.hpp"

#include "guardian_joined_thread_role.hpp"
#include "guardian_lifecycle_journal.hpp"

#include <spdlog/spdlog.h>

#include <chrono>

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
} // namespace

void set_guardian_joined_thread(bool on) noexcept { tl_guardian_joined_thread = on; }
bool on_guardian_joined_thread() noexcept { return tl_guardian_joined_thread; }

GuardianOutboxDrainWorker::GuardianOutboxDrainWorker(GuardianSparkRuntime& rt, SendFn send,
                                                     std::uint64_t periodic_bound_ms,
                                                     GuardianMaintenanceConfig maintenance)
    : rt_(rt), send_(std::move(send)), periodic_bound_ms_(periodic_bound_ms),
      maint_(maintenance), sig_(std::make_shared<Signal>()) {}

GuardianOutboxDrainWorker::~GuardianOutboxDrainWorker() { stop(); }

void GuardianOutboxDrainWorker::start() {
    {
        std::lock_guard<std::mutex> lk{sig_->mu};
        if (started_ || sig_->stopping.load(std::memory_order_acquire))
            return;
        started_ = true;
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
    thread_ = std::thread([this] { loop(); });
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
    if (ops.prune)
        maint_.journal->prune(journal_now_ms());
    if (ops.page) {
        result.page_attempted = true;
        const auto stats = maint_.journal->page_into_window(rt_, journal_now_ms());
        result.records_paged = stats.records_paged;
        result.headroom_blocked = stats.headroom_blocked;
        result.min_blocked_headroom = stats.min_blocked_headroom;
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
    std::uint64_t seen = 0;
    // The FIRST cycle runs WITHOUT waiting: force_page_ is seeded true for the boot journal
    // replay, and making that replay sit behind a full periodic bound - or, worse, behind
    // whenever the first outbox enqueue happens to arrive - contradicts the point of seeding
    // it. Nothing here takes the engine mtx_, so running concurrently with the remainder of
    // wire_spark_engine is safe.
    bool skip_wait = true;

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
            sig_->cv.wait_for(lk, std::chrono::milliseconds(periodic_bound_ms_), [this, seen] {
                return sig_->stopping.load(std::memory_order_acquire) || sig_->gen != seen;
            });
            if (sig_->stopping.load(std::memory_order_acquire))
                break;
            seen = sig_->gen;
        } else if (stop_requested()) {
            break; // neither the boot cycle nor a truncated drain may outlive a stop request
        }
        // Re-armed below ONLY by a truncated drain; every other cycle waits.
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
        const bool forced_page = force_page_.exchange(false, std::memory_order_acq_rel);
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
            firewalled([this] { maintenance_once({.prune = true}); });
            // Stamped AFTER the attempt, so the cadence is a minimum GAP rather than
            // start-to-start. Start-to-start means a pass that runs longer than its own
            // interval is due again the instant it finishes, which under KvStore contention
            // degenerates back into continuous scanning (#2298 Sol review).
            last_prune = std::chrono::steady_clock::now();
        }

        GuardianMaintenanceResult page_result;
        if (page_due && !stop_requested()) {
            const bool ok = firewalled([&] { page_result = maintenance_once({.page = true}); });
            last_page = std::chrono::steady_clock::now();
            // A FORCED page that never ran must not be lost: re-arm so the next cycle
            // retries it rather than waiting out a full cadence interval.
            if (forced_page && !ok)
                force_page_.store(true, std::memory_order_release);
        }

        if (stop_requested())
            break;
        const auto drained = firewalled_drain();

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
        if (page_result.headroom_blocked && drained > 0 &&
            rt_.lifecycle_headroom() >= page_result.min_blocked_headroom &&
            page_result.min_blocked_headroom > 0) {
            force_page_.store(true, std::memory_order_release);
            skip_wait = true; // act on it NOW, not after the backstop
        }
    }
}

} // namespace yuzu::agent
