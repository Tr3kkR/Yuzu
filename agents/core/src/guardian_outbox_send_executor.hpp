#pragma once

/**
 * guardian_outbox_send_executor.hpp - a bounded, single-flight, detached sink
 * for GuardianOutboxDrainWorker's send() call (ADR-0021 Stage 2, #2233 item 4).
 *
 * WHY: GuardianOutboxDrainWorker's own thread also runs journal maintenance
 * (prune/page, guardian_outbox_drain_worker.hpp) and is the sole reader of the
 * outbox/lifecycle logs. Calling `send()` synchronously on that thread means a
 * stalled sink (a gRPC Write() that blocks on a half-open TCP connection - the
 * agent's channel keepalive bounds detection to ~80s, not the seconds this
 * worker's own kGuardianDrainMaxWall implies) wedges maintenance and every
 * later drain for the stall's duration. #3847's acceptance bar is explicit:
 * "the drain worker's next tick proceeds while a prior send is artificially
 * stalled" - dropping drain_mu_ around send() does not achieve that (one
 * production caller; the worker thread is still inside Write() either way).
 * This decouples the caller from the blocking call, mirroring
 * guardian_io_executor.hpp's detached-worker shape (reusing its
 * io_detail::spawn_detached, not its run() - run() DISCARDS a late result on
 * timeout, which is correct for an idempotent read and wrong for a send: a
 * discarded Sent means the entry is dropped without ever being retried).
 *
 * NOT a fix for `stream_write_mu_` contention (agent.cpp): a detached send
 * still holds that mutex for the stall's duration, so another sender sharing
 * the same stream (a response, a DEX signal) still blocks on IT, regardless of
 * which thread is inside Write(). This class only frees the DRAIN WORKER's own
 * thread - maintenance and the next-tick cadence - from that stall. The send
 * path is unreachable in production today (prefer_spark_ is false at rung
 * 7.7a; see guardian_engine.cpp wire_spark_engine()), so this is pre-flip
 * hardening, not a live-traffic fix.
 *
 * SINGLE-FLIGHT BY CONSTRUCTION: exactly one send may be in flight at a time
 * (the underlying gRPC stream requires serialized Write() calls; concurrent
 * sends would also reorder delivery). offer() enforces this itself - it never
 * spawns a second worker while one is running. When the caller offers a
 * DIFFERENT entry than the one in flight (by `event_id`, the wire idempotency
 * key already fixed at enqueue - guardian_outbox.hpp - a generation-supersede
 * purge or a withdrawal moved the log's head while the old head's send was
 * still running), offer() does NOT touch that orphaned worker - no second
 * concurrent Write() on the same stream - but it MUST eventually reclaim the
 * slot once the orphan finishes, discarding its now-unattributable result, or
 * every later offer() call would find in_flight permanently true against an
 * event_id that can never recur and never launch again (found in governance
 * review of this file's first draft, independently by two reviewers; direct
 * regression coverage: tests/unit/test_guardian_outbox_send_executor.cpp).
 *
 * ORPHAN-EXIT CONTRACT: reuses the exact hazard guardian_io_executor.hpp
 * documents - a worker wedged in a blocking syscall cannot be joined or
 * force-cancelled, so normal C++ teardown must not run while one is alive.
 * active_worker_count() MUST be summed into GuardianEngine::active_io_workers()
 * (guardian_engine.cpp) alongside the state-reader and arm/disarm executors -
 * a source left out of that sum lets a detached send survive teardown
 * undetected (the same comment guards that call site).
 */

#include "guardian_io_executor.hpp" // io_detail::spawn_detached
#include "guardian_outbox.hpp"      // OutboxEntry, SendResult

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <chrono>
#include <condition_variable>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

namespace yuzu::agent {

class YUZU_EXPORT GuardianOutboxSendExecutor {
public:
    using SendFn = std::function<SendResult(const OutboxEntry&)>;

    GuardianOutboxSendExecutor() : state_(std::make_shared<State>()) {}
    GuardianOutboxSendExecutor(const GuardianOutboxSendExecutor&) = delete;
    GuardianOutboxSendExecutor& operator=(const GuardianOutboxSendExecutor&) = delete;

    /// Called once per drain attempt for the current head entry. `send` is invoked
    /// on a DETACHED worker, never on the caller's thread. Returns the completed
    /// result if a send finished within `wait` (the common case on a healthy
    /// connection), or std::nullopt if none is available yet - the caller MUST
    /// treat that as SendResult::Retain and stop draining this pass (matches the
    /// existing "Retain stops the drain" contract - see guardian_outbox.hpp), then
    /// offer the SAME head entry again on its next tick. Never blocks longer than
    /// `wait`, regardless of how long the underlying send actually takes.
    ///
    /// RE-THROWS on this call if the completed send itself threw: drain_log_unlocked
    /// (guardian_spark_runtime.cpp) has its own catch around `send(entry)` that counts
    /// send_exceptions_ and retains the head - swallowing the throw here instead (e.g.
    /// mapping it to Retain) would silently lose that counter, which is how a
    /// permanently-unsendable entry is distinguished from an ordinary down stream.
    std::optional<SendResult> offer(const OutboxEntry& entry, const SendFn& send,
                                    std::chrono::milliseconds wait) {
        // offer() has exactly one caller thread (the drain worker's own loop), so
        // there is no concurrent-submitter race to guard against here - only
        // against the detached worker thread, which the lock below still covers.
        // The launch-decision read and the launch() call itself are deliberately
        // NOT done under one held lock: launch() constructs an AliveTicket, whose
        // ctor/dtor take state_->mu themselves (see below), and that mutex is not
        // recursive.
        bool need_launch = false;
        {
            std::lock_guard<std::mutex> lk{state_->mu};
            if (state_->in_flight && state_->in_flight_event_id != entry.event_id) {
                // The head entry changed under us (generation-supersede purge or a
                // withdrawal - both ORDINARY operations, not a rare race) while a
                // send for the OLD head was still running. That worker is orphaned
                // (still holds stream_write_mu_ until it finishes).
                if (!state_->done) {
                    // Still genuinely running. Cannot touch it and must not submit a
                    // second concurrent Write() on the same stream - try again next
                    // tick. Once it finishes, the branch below reclaims the slot; NOT
                    // reclaiming here unconditionally (an earlier version of this
                    // function never reclaimed at all) would otherwise wedge every
                    // future send permanently, since `event_id` never repeats.
                    return SendResult::Retain;
                }
                // The stale worker already finished. Its result (Sent/Retain, or a
                // thrown exception now sitting in eptr) applies to an entry that no
                // longer exists in the log - there is nothing correct to do with it
                // except discard it; reporting it against THIS entry would
                // misattribute a success/failure that never happened to it. Reclaim
                // the slot and fall through to launch a fresh worker below.
                state_->in_flight = false;
                state_->done = false;
                state_->eptr = nullptr;
            }
            if (!state_->in_flight) {
                if (state_->stopping)
                    return SendResult::Retain; // do not spawn new work once stopping
                need_launch = true;
            }
            // else: in_flight for THIS SAME entry - fall through to the wait below.
        }
        if (need_launch && !launch(entry, send))
            return SendResult::Retain; // launch failed (thread exhaustion); retry next tick

        std::unique_lock<std::mutex> lk{state_->mu};
        const auto deadline = std::chrono::steady_clock::now() + wait;
        state_->cv.wait_until(lk, deadline, [&] { return state_->done; });
        if (!state_->done)
            return std::nullopt; // still running; caller retains and comes back
        auto result = state_->result;
        auto eptr = std::move(state_->eptr);
        state_->in_flight = false;
        state_->done = false;
        state_->eptr = nullptr;
        if (eptr) {
            lk.unlock(); // never rethrow while holding a lock a catch handler cannot see
            std::rethrow_exception(eptr);
        }
        return result;
    }

    /// Idempotent. Marks the executor stopping so no NEW send is launched; does
    /// NOT cancel a send already in flight (matches guardian_io_executor.hpp - a
    /// thread wedged in a blocking syscall cannot be force-cancelled). Never
    /// blocks: a caller wanting to know when the last worker is truly gone polls
    /// active_worker_count(), the same orphan-exit contract as the state reader.
    void stop() {
        std::lock_guard<std::mutex> lk{state_->mu};
        state_->stopping = true;
    }

    /// For GuardianEngine::active_io_workers() (the orphan-exit contract's sole
    /// source of truth) - normally 0 or 1 (this executor is single-flight in the
    /// sense that at most one send is ever ADMITTED), but can transiently read 2:
    /// offer() reclaiming a finished-but-orphaned worker (a stale event_id whose
    /// AliveTicket has not yet reached its thread-exit decrement) can launch a new
    /// one before the old ticket's count-1 has run. Harmless for the orphan-exit
    /// contract itself, which only distinguishes zero from nonzero.
    [[nodiscard]] std::size_t active_worker_count() const {
        std::lock_guard<std::mutex> lk{state_->mu};
        return static_cast<std::size_t>(state_->worker_count);
    }

private:
    struct State {
        std::mutex mu;
        std::condition_variable cv;
        bool in_flight{false};      ///< a send has been submitted and not yet consumed by offer()
        bool done{false};           ///< the worker published a result
        int worker_count{0};        ///< 0 or 1; see AliveTicket below for the release timing
        bool stopping{false};
        std::string in_flight_event_id;
        SendResult result{SendResult::Retain};
        std::exception_ptr eptr; ///< set instead of `result` if `send` itself threw
    };

    /// RAII orphan-exit marker, mirroring guardian_io_executor.hpp's TicketCore
    /// split: the worker's OWN captured copy is the one that decrements
    /// worker_count, and it is destroyed by the detached-thread trampoline AFTER
    /// the worker lambda body has fully returned (notify_all included) - the
    /// latest point observable before the OS thread itself exits. A copy that
    /// never reaches a launched thread (the launch-failed path) decrements
    /// immediately instead, since no thread was ever created to outlive it.
    struct AliveTicket {
        explicit AliveTicket(std::shared_ptr<State> s) : state(std::move(s)) {
            std::lock_guard<std::mutex> lk{state->mu};
            ++state->worker_count;
        }
        ~AliveTicket() {
            std::lock_guard<std::mutex> lk{state->mu};
            if (state->worker_count > 0)
                --state->worker_count;
        }
        AliveTicket(const AliveTicket&) = delete;
        AliveTicket& operator=(const AliveTicket&) = delete;
        std::shared_ptr<State> state;
    };

    /// Called from offer() with state_->mu NOT held (AliveTicket's own ctor/dtor take
    /// it, and it is not recursive). Spawns a detached worker that calls send(entry)
    /// and publishes the result; returns false only if the OS refused to create the
    /// thread (mirrors guardian_io_executor.hpp's LaunchFailed path).
    bool launch(const OutboxEntry& entry, const SendFn& send) {
        // Bookkeeping FIRST, under its own lock, BEFORE the worker is spawned - not
        // after. A fast `send` can complete, lock state_->mu, and publish done=true
        // before this function ever reaches a post-spawn lock acquisition (verified:
        // reproduced ~1-in-1000 with a fast, always-succeeding send in a tight loop).
        // Writing in_flight/in_flight_event_id/done=false only AFTER spawn_detached()
        // returns would then let this write clobber the worker's already-published
        // done=true back to false, and nothing ever sets it true again - the entry
        // wedges permanently, silently, for the life of the process. in_flight/
        // in_flight_event_id/done have exactly one writer (this function, called only
        // from offer(), which has exactly one caller thread), so writing them before
        // the worker can possibly touch `done` is race-free by construction.
        {
            std::lock_guard<std::mutex> lk{state_->mu};
            state_->in_flight = true;
            state_->in_flight_event_id = entry.event_id;
            state_->done = false;
        }
        // Everything from here through spawn_detached() can throw std::bad_alloc:
        // make_shared<AliveTicket>, copying `entry`/`send` into the worker lambda's
        // captures, and spawn_detached's own payload allocation (guardian_io_executor.hpp's
        // own doc). ALL of it is inside one try, and any failure - a thrown bad_alloc
        // OR spawn_detached returning false for an OS-level refusal - takes the SAME
        // rollback path below. An uncaught throw here would unwind past the bookkeeping
        // written above with in_flight left true and no worker ever created to set
        // done=true, wedging this entry exactly like the ordering bug this function's
        // rewrite fixed (verified in review) - just triggered by allocation failure
        // instead of a timing race. None of these failures are specific to `entry` (they
        // are thread/memory exhaustion, not an unsendable payload), so all are mapped to
        // a plain launch failure - the caller retries next tick - rather than let a
        // bad_alloc escape into drain_log_unlocked's catch and be miscounted as a
        // send_exceptions_ hit.
        bool launched = false;
        try {
            // Constructed (and counted, via its self-locking ctor) BEFORE the launch
            // attempt, inside a shared_ptr so a launch failure's synchronous destruction
            // and a launched worker's eventual thread-exit destruction both go through
            // the same self-locking decrement path.
            auto ticket = std::make_shared<AliveTicket>(state_);
            auto st = state_;
            auto worker = [st, ticket, entry, send]() mutable noexcept {
                SendResult r = SendResult::Retain;
                std::exception_ptr eptr;
                try {
                    r = send(entry);
                } catch (...) {
                    // Preserve the throw for offer() to re-raise on the CALLER's thread -
                    // drain_log_unlocked's own catch is what counts send_exceptions_ and
                    // distinguishes a permanently-unsendable entry from an ordinary Retain
                    // (guardian_spark_runtime.cpp); swallowing it here would silently lose
                    // that signal. current_exception() is noexcept; the copy into `eptr`
                    // is not documented noexcept by the standard, so it gets its own
                    // firewall - a double-fault here degrades to an ordinary Retain rather
                    // than escaping this noexcept lambda and terminating the agent.
                    try {
                        eptr = std::current_exception();
                    } catch (...) {
                        eptr = nullptr;
                    }
                }
                {
                    std::lock_guard<std::mutex> lk{st->mu};
                    st->result = r;
                    st->eptr = eptr;
                    st->done = true;
                }
                st->cv.notify_all();
                // `ticket` destructs at lambda-scope exit, after notify_all - the last
                // observable point before this OS thread actually exits. Its dtor
                // self-locks, so this runs safely with no lock held on this thread.
            };
            launched = io_detail::spawn_detached(std::move(worker));
        } catch (...) {
            launched = false;
        }
        if (!launched) {
            // Any partially-constructed ticket's local copy has already dropped by now
            // (try/catch unwound it, or the false-return path never released it) ->
            // worker_count is back to 0 either way.
            std::lock_guard<std::mutex> lk{state_->mu};
            state_->in_flight = false;
            return false;
        }
        return true;
    }

    std::shared_ptr<State> state_;
};

} // namespace yuzu::agent
