#pragma once

/**
 * guardian_legacy_sink_executor.hpp - a bounded, FIFO, gap-accounting, detached
 * sender for the legacy IGuard producers' event sink (#4783, delivery plan
 * `.claude/plans/4783-legacy-guard-sink-blocking-PLAN-v2.md` §3.1).
 *
 * WHY: FileGuard/RegistryGuard/ServiceGuard/SystemdServiceGuard each call
 * GuardianEngine::emit_guard_event() -> the injected EventSink -> (today)
 * emit_guardian_event()'s synchronous gRPC Write() on the SAME thread that runs
 * the guard's own detection loop. A stalled-but-not-dead stream (no deadline on
 * subscribe_ctx_) wedges that thread indefinitely: the guard stops detecting, and
 * if the wedge happens to land inside GuardianEngine::stop()'s mtx_-held guard
 * join, teardown itself wedges. This class decouples the producer from the send,
 * mirroring guardian_outbox_send_executor.hpp / guardian_io_executor.hpp's
 * detached-worker shape (spawn_detached, the armed-under-lock AliveTicket idiom,
 * GuardianDetachedWorkerRole, firewalled stall/recovery logging) - but is NOT
 * single-flight like those two: producers commit their decider state (last_compliant
 * etc.) BEFORE calling the sink and GuardSink returns void, so a refused/dropped
 * event here is a PERMANENT edge loss no later offer() repairs on its own. That is
 * why this class, unlike its siblings, keeps a bounded FIFO queue (not a 1-deep
 * slot) plus a sticky, per-rule integrity-gap ledger - see the loss table below.
 *
 * QUEUE POLICY - pure FIFO, never coalesced/replaced/reordered. Every admitted
 * event is delivered in admission order or counted as lost; two events for the
 * SAME rule_id never collapse into one slot (drift.detected, drift.remediated,
 * remediation.failed, guard.compliant, guard.unhealthy are all distinct census
 * signals - the server orders same-second events by ARRIVAL order, so reordering
 * is a correctness bug, not just a cardinality change). Bounded by BOTH
 * `max_events` and `max_bytes` (Event::ByteSizeLong(), computed once at offer()).
 *
 * LOSS ACCOUNTING AND THE STICKY INTEGRITY GAP. Every event this executor admitted
 * or was offered but the server will not receive is a *loss* except the two
 * shutdown/pre-network classes:
 *
 *   source                                      | counter(s)                    | gap?
 *   RefusedCapacity (count or bytes)             | backpressure_drops+events_lost | yes
 *   RefusedAdmission (allocation failure)        | admission_failures+events_lost | yes
 *   sink returned WriteFailed                    | send_failures+events_lost      | yes
 *   sink threw                                   | send_exceptions+events_lost    | yes
 *   sink returned LinkDown (no stream yet)       | dropped_link_down              | NO (D4b)
 *   discarded_at_stop (backlog cleared at stop()) | discarded_at_stop             | no
 *
 * A gap is `gaps[rule_id]` (guard_type/rule_name copied from the lost event so a
 * repair can be synthesized without touching the guard), sticky until a REPAIR
 * report (offer()'d with is_gap_repair=true) is confirmed Sent. If the gap ledger
 * itself cannot be updated (allocation failure), record_gap_locked() degrades
 * gap_ledger_degraded=true and counts gap_ledger_faults instead of throwing -
 * surfaced as its own loss signal, never silently swallowed. Gap *repair
 * synthesis and dispatch* (building a guard.unhealthy event and calling kick()'s
 * heartbeat-driven repair loop) is GuardianEngine::legacy_sink_kick()'s job
 * (commit 4 of the delivery plan) - this class only maintains the ledger and
 * exposes it via gapped_rules_needing_repair().
 *
 * CORRECTNESS PROPERTIES (each was a specific defect class found in design
 * review of the delivery plan - see the class's own test file for the regression
 * each property guards):
 *  1. FIFO only - never coalesce/replace/reorder; every offered event is
 *     delivered exactly once or counted as lost.
 *  2. Bounded by both max_events and max_bytes; a refusal always counts and
 *     records a gap, never a silent drop.
 *  3. Launch retry works from a stranded state: launch eligibility (queue
 *     non-empty, no worker running, not stopping) is evaluated on EVERY offer()
 *     outcome (Queued or Refused alike) AND inside kick() - so a failed
 *     spawn_detached is recoverable both by the next offer() of ANY key and by
 *     kick() alone with zero new offers.
 *  4. offer() never throws to its caller (a guard's own detection thread calls
 *     this - an escaping exception ends that guard's detection permanently, see
 *     guard_file.cpp's outer catch). The whole body is one try/catch; any
 *     exception rolls back to a state as if nothing happened, counts
 *     admission_failures+events_lost, records a best-effort gap, and returns
 *     RefusedAdmission.
 *  5. No self-deadlock on ticket destruction: ~AliveTicket locks state_->mu, so
 *     the LAST live reference to an armed ticket is never dropped while this
 *     thread already holds that mutex. On launch-rollback, the ticket captured
 *     BY VALUE into the (failed) worker closure is destroyed synchronously
 *     inside spawn_detached's own stack frame (unlocked); THIS function's own
 *     copy - kept alive deliberately, not moved into the closure - is dropped
 *     only after the rollback's lock_guard has already released the lock.
 *  6. A quiet, fully-stalled queue (no new offers, one send that never returns)
 *     is still eventually observed as a stall: kick() re-checks the in-flight
 *     stall condition on every call, independent of any offer() - production
 *     wires it to the engine's heartbeat tick (commit 4), not guard activity.
 *  7. stop() never blocks and never touches an in-flight send: it only flips
 *     `stopping`, discards the (counted) backlog, and returns. A send already
 *     admitted as in-flight before stop() is allowed to complete after stop()
 *     returns - a defined, tested outcome (active_worker_count() reflects it
 *     until the worker retires), not a race bug. stop() also does NOT prevent an
 *     OS thread from being *created* after `stopping` is already true (admission
 *     committed -> stop() -> spawn_detached is a real interleaving) - safe
 *     because the worker checks `stopping` under the lock before any dequeue, so
 *     it retires immediately without touching the (already-cleared) backlog.
 *  8. No claimed upper bound on transient active_worker_count() beyond "reaches
 *     0 at rest" - retiring workers may overlap successors arbitrarily; do not
 *     add a comment claiming a small fixed ceiling.
 *
 * WORKER FAULT BOUNDARY: the worker loop wraps its ENTIRE iteration body (not
 * just the send() call) in try/catch(...) - a whole-iteration boundary, counted
 * as worker_faults, with the loop continuing on the next iteration. The stall
 * check runs BEFORE `in_flight` is cleared (do NOT copy
 * guardian_outbox_send_executor.hpp's check_stall_locked() verbatim here - it
 * early-returns on `!in_flight`, which would suppress exactly the check this
 * class needs at that point).
 *
 * ORPHAN-EXIT CONTRACT: identical to the sibling executors - a worker wedged in
 * a blocking Write() cannot be joined or force-cancelled. active_worker_count()
 * MUST be summed into GuardianEngine::active_io_workers() (a later commit's job;
 * this class is not wired into GuardianEngine yet) so a detached send survives
 * teardown observably, not silently.
 *
 * NOT WIRED YET: this file is deliberately self-contained and unused in
 * production as of this commit - GuardianEngine/agent.cpp integration is a
 * separate follow-up commit per the delivery plan's sequencing.
 */

#include "guardian_detached_worker_role.hpp" // GuardianDetachedWorkerRole
#include "guardian_io_executor.hpp"          // io_detail::spawn_detached

#include "guaranteed_state.pb.h" // yuzu::guardian::v1::GuaranteedStateEvent

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <spdlog/spdlog.h> // firewalled stall/recovery logging, matching the sibling executors

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::agent {

/// Outcome of one delivery attempt, reported by the injected send function.
enum class LegacySendOutcome : std::uint8_t { Sent, LinkDown, WriteFailed };

class YUZU_EXPORT GuardianLegacySinkExecutor {
public:
    using Event = ::yuzu::guardian::v1::GuaranteedStateEvent;
    using SendFn = std::function<LegacySendOutcome(const Event&)>;

    struct Config {
        std::size_t max_events{4096};
        std::size_t max_bytes{4u << 20};
        std::chrono::milliseconds stall_threshold{5'000};
    };

    /// Admission outcome of offer(). Never describes the eventual SEND outcome -
    /// that is asynchronous and observed later via stats()/gapped_rules_needing_repair().
    enum class OfferOutcome { Queued, RefusedCapacity, RefusedAdmission, RefusedStopping };

    /// A sticky per-rule integrity gap - see the class doc comment's loss table.
    /// guard_type/rule_name are copied from the LOST event so a repair report can
    /// be synthesized without going back to the guard (guard.hpp has no query API
    /// for "give me your last known state").
    struct GapRecord {
        std::string guard_type;
        std::string rule_name;
        std::uint64_t lost{0};
        std::chrono::system_clock::time_point first_lost{};
        std::chrono::system_clock::time_point last_lost{};
        bool repair_in_flight{false};
    };

    struct Stats {
        std::uint64_t events_lost{0};
        std::uint64_t backpressure_drops{0};
        std::uint64_t admission_failures{0};
        std::uint64_t send_failures{0};
        std::uint64_t send_exceptions{0};
        std::uint64_t worker_faults{0};
        std::uint64_t dropped_link_down{0};
        std::uint64_t discarded_at_stop{0};
        std::uint64_t stalls{0};
        std::uint64_t launch_failures{0};
        std::uint64_t gap_ledger_faults{0};
        std::size_t gap_rules{0};
    };

    /// Test-only fault injection for the admission path (offer()). `ThrowOnTicket`
    /// fires at the earliest allocation (the AliveTicket, before the lock and
    /// before any State mutation - the UNARMED rollback, nothing to undo);
    /// `ThrowOnNode` fires at the list-node allocation itself (the LAST throwing
    /// step inside the locked admission block, per the class doc comment -
    /// nothing was mutated before it either). `ThrowOnGapLedger` fires inside
    /// record_gap_locked()'s own map mutation, from EITHER call site (offer()'s
    /// admission-refusal path or the worker's post-send accounting) - it is
    /// caught internally and degrades gap_ledger_degraded rather than escaping,
    /// so this exercises that degradation path specifically, not offer()'s own
    /// RefusedAdmission path.
    enum class AdmissionFaultForTest { None, ThrowOnNode, ThrowOnTicket, ThrowOnGapLedger };

    /// Test-only fault injection for the launch path (spawn_detached).
    /// `SpawnRefused` mirrors the OS refusing to create the thread;
    /// `Throw` mirrors a std::bad_alloc anywhere in the guarded launch region.
    enum class LaunchFaultForTest { None, SpawnRefused, Throw };

    GuardianLegacySinkExecutor() : GuardianLegacySinkExecutor(Config{}) {}
    explicit GuardianLegacySinkExecutor(Config cfg) : state_(std::make_shared<State>()) {
        state_->max_events = cfg.max_events;
        state_->max_bytes = cfg.max_bytes;
        state_->stall_threshold = cfg.stall_threshold;
    }
    GuardianLegacySinkExecutor(const GuardianLegacySinkExecutor&) = delete;
    GuardianLegacySinkExecutor& operator=(const GuardianLegacySinkExecutor&) = delete;

    /// Enqueue `ev` for delivery via `send`, which runs on a DETACHED worker,
    /// never on the caller's thread. Never blocks on network I/O; never throws
    /// (correctness property 4) - every exception anywhere in this function maps
    /// to RefusedAdmission. `is_gap_repair` marks this offer as a synthesized
    /// repair report for an existing gap (see the class doc comment); it is the
    /// caller's (GuardianEngine::legacy_sink_kick(), a later commit) job to build
    /// that event, not this class's.
    [[nodiscard]] OfferOutcome offer(Event ev, SendFn send, bool is_gap_repair = false) noexcept {
        // Declared here (not inside the try) so the catch block below can still
        // use whatever was successfully computed before an exception hit -
        // correctness property 4's "record a best-effort gap" clause.
        std::string rule_id;
        std::string guard_type;
        std::string rule_name;
        try {
            // (1) Compute the byte size and copy the identifying fields BEFORE
            // the lock - these allocate, and the strong-guarantee rollback below
            // relies on none of them having touched State yet.
            const std::size_t bytes = ev.ByteSizeLong();
            rule_id = ev.rule_id();
            guard_type = ev.guard_type();
            rule_name = ev.rule_name();

            // (2) The unarmed ticket, BEFORE the lock (allocates; #3966 idiom -
            // see guardian_outbox_send_executor.hpp's AliveTicket doc comment).
            if (admission_fault_for_test() == AdmissionFaultForTest::ThrowOnTicket)
                throw std::bad_alloc{};
            auto ticket = std::make_shared<AliveTicket>(state_);

            OfferOutcome outcome = OfferOutcome::Queued;
            bool need_spawn = false;
            {
                std::unique_lock<std::mutex> lk{state_->mu};
                if (state_->stopping) {
                    // Not a "loss" counter by design - see the class doc comment's
                    // loss table (discarded_at_stop is deliberately not events_lost).
                    ++state_->counters.discarded_at_stop;
                    outcome = OfferOutcome::RefusedStopping;
                } else if (state_->queue.size() >= state_->max_events ||
                           state_->bytes + bytes > state_->max_bytes) {
                    ++state_->counters.backpressure_drops;
                    ++state_->counters.events_lost;
                    record_gap_locked(*state_, rule_id, guard_type, rule_name);
                    outcome = OfferOutcome::RefusedCapacity;
                } else {
                    // (3) The list-node allocation - the LAST throwing step; on
                    // throw, nothing above this point mutated State.
                    if (admission_fault_for_test() == AdmissionFaultForTest::ThrowOnNode)
                        throw std::bad_alloc{};
                    state_->queue.push_back(
                        Item{std::move(ev), std::move(send), rule_id, bytes, is_gap_repair});
                    state_->bytes += bytes;
                    if (is_gap_repair) {
                        if (auto gi = state_->gaps.find(rule_id); gi != state_->gaps.end())
                            gi->second.repair_in_flight = true;
                    }
                }

                // (4) Regardless of outcome (Queued or any Refused* above),
                // evaluate launch eligibility in this SAME locked block -
                // correctness property 3: a stranded queue (worker_running still
                // false after an earlier failed launch) is retried by ANY
                // subsequent offer(), not only a fresh key.
                if (!state_->queue.empty() && !state_->worker_running && !state_->stopping) {
                    state_->worker_running = true;
                    ticket->arm();
                    need_spawn = true;
                }
            }
            // (5) Unlock, then spawn outside the lock.
            if (need_spawn)
                attempt_launch(std::move(ticket));
            return outcome;
        } catch (...) {
            try {
                std::lock_guard<std::mutex> lk{state_->mu};
                ++state_->counters.admission_failures;
                ++state_->counters.events_lost;
                record_gap_locked(*state_, rule_id, guard_type, rule_name);
            } catch (...) {
            }
            return OfferOutcome::RefusedAdmission;
        }
    }

    /// Re-evaluate launch eligibility and observe an in-flight stall, entirely
    /// independent of offer() (correctness properties 3 and 6). Production wires
    /// this to the agent heartbeat tick (GuardianEngine::legacy_sink_kick(), a
    /// later commit), so a stranded queue or a quiet-but-stalled send is noticed
    /// within one heartbeat interval even with zero new guard activity. Never
    /// throws; a failure here is best-effort and simply retried on the next call.
    void kick() noexcept {
        std::shared_ptr<AliveTicket> ticket;
        bool need_spawn = false;
        bool log_stall = false;
        std::string stalled_rule_id;
        try {
            std::unique_lock<std::mutex> lk{state_->mu};
            if (!state_->queue.empty() && !state_->worker_running && !state_->stopping) {
                ticket = std::make_shared<AliveTicket>(state_);
                state_->worker_running = true;
                ticket->arm();
                need_spawn = true;
            }
            // Stall observation is orthogonal to the launch decision above - a
            // wedged send and a stranded (worker-not-running) queue are
            // independent conditions and either or both can be true here.
            if (state_->in_flight && !state_->stall_logged &&
                (std::chrono::steady_clock::now() - state_->send_started_at >=
                 state_->stall_threshold)) {
                ++state_->counters.stalls;
                state_->stall_logged = true;
                log_stall = true;
                stalled_rule_id = state_->in_flight_rule_id;
            }
        } catch (...) {
            return;
        }
        if (log_stall)
            log_send_stall(stalled_rule_id);
        if (need_spawn)
            attempt_launch(std::move(ticket));
    }

    /// Prohibits new admissions; discards the (counted) backlog; never blocks;
    /// never touches an in-flight send (correctness property 7). Idempotent.
    void stop() noexcept {
        try {
            std::lock_guard<std::mutex> lk{state_->mu};
            state_->stopping = true;
            state_->counters.discarded_at_stop += state_->queue.size();
            state_->queue.clear();
            state_->bytes = 0;
        } catch (...) {
        }
    }

    /// PHYSICAL alive worker count (payload not yet destroyed) - 0 at rest, no
    /// claimed transient ceiling (correctness property 8). For
    /// GuardianEngine::active_io_workers()'s orphan-exit sum (a later commit).
    [[nodiscard]] std::size_t active_worker_count() const {
        std::lock_guard<std::mutex> lk{state_->mu};
        return static_cast<std::size_t>(state_->worker_count);
    }

    [[nodiscard]] bool has_in_flight_send() const {
        std::lock_guard<std::mutex> lk{state_->mu};
        return state_->in_flight;
    }

    [[nodiscard]] Stats stats() const {
        std::lock_guard<std::mutex> lk{state_->mu};
        Stats s = state_->counters;
        s.gap_rules = state_->gaps.size();
        return s;
    }

    /// Up to `max` gapped rules, unfiltered by repair_in_flight - the caller
    /// (GuardianEngine::legacy_sink_kick(), a later commit) decides which to
    /// actually (re)offer a repair for.
    [[nodiscard]] std::vector<std::pair<std::string, GapRecord>>
    gapped_rules_needing_repair(std::size_t max) const {
        std::lock_guard<std::mutex> lk{state_->mu};
        std::vector<std::pair<std::string, GapRecord>> out;
        out.reserve(std::min(max, state_->gaps.size()));
        for (const auto& kv : state_->gaps) {
            if (out.size() >= max)
                break;
            out.emplace_back(kv.first, kv.second);
        }
        return out;
    }

    // ---- test seams -------------------------------------------------------

    [[nodiscard]] std::size_t pending_count_for_test() const {
        std::lock_guard<std::mutex> lk{state_->mu};
        return state_->queue.size();
    }
    [[nodiscard]] std::size_t pending_bytes_for_test() const {
        std::lock_guard<std::mutex> lk{state_->mu};
        return state_->bytes;
    }

    /// True once the queue is empty AND nothing is in flight - NOT physical
    /// worker retirement (a worker that just observed an empty queue is still
    /// counted in active_worker_count() until its trampoline destroys the
    /// payload). Use wait_workers_retired_for_test() to wait for that instead.
    [[nodiscard]] bool wait_idle_for_test(std::chrono::milliseconds timeout) const {
        return poll_for_test(timeout, [&] {
            std::lock_guard<std::mutex> lk{state_->mu};
            return state_->queue.empty() && !state_->in_flight;
        });
    }

    /// True once active_worker_count() reaches 0 - physical retirement.
    [[nodiscard]] bool wait_workers_retired_for_test(std::chrono::milliseconds timeout) const {
        return poll_for_test(timeout, [&] { return active_worker_count() == 0; });
    }

    /// Fires on the calling thread, with state_->mu NOT held, right before the
    /// actual spawn attempt inside attempt_launch() - i.e. after a caller
    /// (offer() or kick()) has already committed worker_running=true and armed
    /// its ticket under the lock, and released it. A test can synchronously
    /// offer() a SECOND event from inside this hook: that second offer() sees
    /// worker_running already true, so it enqueues without attempting its own
    /// launch - deterministically reproducing "B offered while A's launch is
    /// still outstanding" via call ordering, matching the same idiom
    /// guardian_outbox_send_executor.hpp uses for its own launch-race tests.
    /// This seam is not in the delivery plan's §3.1 code sketch verbatim; it is
    /// this file's minimal addition to make that specific interleaving
    /// deterministic in a test rather than relying on real thread scheduling.
    void set_pre_launch_race_hook_for_test(std::function<void()> hook) {
        pre_launch_race_hook_for_test_ = std::move(hook);
    }

    void set_launch_fault_for_test(LaunchFaultForTest f) {
        launch_fault_for_test_.store(f, std::memory_order_relaxed);
    }
    void set_admission_fault_for_test(AdmissionFaultForTest f) {
        state_->admission_fault_for_test.store(f, std::memory_order_relaxed);
    }

private:
    struct Item {
        Event ev;
        SendFn send;
        std::string rule_id;
        std::size_t bytes{0};
        bool gap_repair{false};
    };

    struct State {
        std::mutex mu;
        std::condition_variable cv;
        std::list<Item> queue;
        std::size_t bytes{0};
        bool worker_running{false};
        bool in_flight{false};
        bool stopping{false};
        int worker_count{0};
        std::string in_flight_rule_id;
        std::chrono::steady_clock::time_point send_started_at{};
        bool stall_logged{false};
        std::unordered_map<std::string, GapRecord> gaps;
        bool gap_ledger_degraded{false};
        Stats counters{};
        std::chrono::milliseconds stall_threshold{5'000}; // copied from Config at construction
        std::size_t max_events{4096};                     // copied from Config at construction
        std::size_t max_bytes{4u << 20};                  // copied from Config at construction
        std::atomic<AdmissionFaultForTest> admission_fault_for_test{AdmissionFaultForTest::None};
    };

    /// RAII orphan-exit marker (#3966 idiom - see
    /// guardian_outbox_send_executor.hpp's AliveTicket doc comment for the full
    /// rationale). Unarmed by default; arm() is called by offer()/kick() as the
    /// LAST statement of the SAME locked block that sets worker_running=true, so
    /// admission and the physical count commit atomically under one lock
    /// acquisition. A ticket destroyed before/without arm() is a no-op.
    struct AliveTicket {
        explicit AliveTicket(std::shared_ptr<State> s) noexcept : state(std::move(s)) {}
        ~AliveTicket() {
            if (!armed)
                return;
            std::lock_guard<std::mutex> lk{state->mu};
            if (state->worker_count > 0)
                --state->worker_count;
        }
        /// CALLER MUST HOLD state->mu.
        void arm() noexcept {
            ++state->worker_count;
            armed = true;
        }
        AliveTicket(const AliveTicket&) = delete;
        AliveTicket& operator=(const AliveTicket&) = delete;
        std::shared_ptr<State> state;
        bool armed{false};
    };

    [[nodiscard]] AdmissionFaultForTest admission_fault_for_test() const {
        return state_->admission_fault_for_test.load(std::memory_order_relaxed);
    }

    template <class Pred>
    static bool poll_for_test(std::chrono::milliseconds timeout, Pred&& pred) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            if (pred())
                return true;
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
        return pred();
    }

    /// Called with state_->mu HELD, from EITHER offer() (an admission refusal)
    /// or the worker (post-send accounting) - a single chokepoint so
    /// AdmissionFaultForTest::ThrowOnGapLedger exercises the same degrade path
    /// regardless of caller. Never propagates: an allocation failure while
    /// recording the gap itself degrades gap_ledger_degraded/gap_ledger_faults
    /// rather than escaping into either caller's own noexcept contract.
    static void record_gap_locked(State& st, const std::string& rule_id,
                                  const std::string& guard_type, const std::string& rule_name) {
        try {
            if (st.admission_fault_for_test.load(std::memory_order_relaxed) ==
                AdmissionFaultForTest::ThrowOnGapLedger)
                throw std::bad_alloc{};
            const auto now = std::chrono::system_clock::now();
            auto it = st.gaps.find(rule_id);
            if (it == st.gaps.end()) {
                GapRecord g;
                g.guard_type = guard_type;
                g.rule_name = rule_name;
                g.lost = 1;
                g.first_lost = now;
                g.last_lost = now;
                st.gaps.emplace(rule_id, std::move(g)); // the one throwing step
            } else {
                ++it->second.lost;
                it->second.last_lost = now;
            }
        } catch (...) {
            st.gap_ledger_degraded = true;
            ++st.counters.gap_ledger_faults;
        }
    }

    /// Called with state_->mu HELD, on the worker thread, after one send
    /// attempt completes (normally or by throwing). Applies the loss-accounting
    /// table from the class doc comment. `rule_id`/`guard_type`/`rule_name` are
    /// read from `it` (untouched by the worker loop up to this call).
    static void account_outcome_locked(State& st, const Item& it, LegacySendOutcome r,
                                       bool threw) {
        if (threw) {
            ++st.counters.send_exceptions;
            ++st.counters.events_lost;
            record_gap_locked(st, it.rule_id, it.ev.guard_type(), it.ev.rule_name());
            if (it.gap_repair) {
                if (auto gi = st.gaps.find(it.rule_id); gi != st.gaps.end())
                    gi->second.repair_in_flight = false;
            }
            return;
        }
        switch (r) {
        case LegacySendOutcome::Sent:
            if (it.gap_repair)
                st.gaps.erase(it.rule_id); // confirmed delivered - the gap closes
            break;
        case LegacySendOutcome::WriteFailed:
            ++st.counters.send_failures;
            ++st.counters.events_lost;
            record_gap_locked(st, it.rule_id, it.ev.guard_type(), it.ev.rule_name());
            if (it.gap_repair) {
                if (auto gi = st.gaps.find(it.rule_id); gi != st.gaps.end())
                    gi->second.repair_in_flight = false; // retry on the next kick
            }
            break;
        case LegacySendOutcome::LinkDown:
            ++st.counters.dropped_link_down; // NOT a gap - D4b, today's documented
                                             // pre-network/A3 drop semantics
            if (it.gap_repair) {
                if (auto gi = st.gaps.find(it.rule_id); gi != st.gaps.end())
                    gi->second.repair_in_flight = false;
            }
            break;
        }
    }

    static void log_send_stall(const std::string& rule_id) {
        try {
            spdlog::warn("Guardian legacy sink send stalled past its threshold "
                         "(rule_id {}); the queue continues, this send stays running "
                         "detached.",
                         rule_id);
        } catch (...) {
        }
    }
    static void log_send_recovery(const std::string& rule_id) {
        try {
            spdlog::info("Guardian legacy sink send (rule_id {}) completed after "
                         "having stalled past its threshold.",
                         rule_id);
        } catch (...) {
        }
    }

    /// The detached worker body. Captures `st` and `ticket` only - never `this`
    /// (this class can be destroyed while a worker is still alive; the orphan-exit
    /// contract is what makes that safe, see the class doc comment).
    static void worker_loop(std::shared_ptr<State> st,
                            std::shared_ptr<AliveTicket> ticket) noexcept {
        const GuardianDetachedWorkerRole role; // first statement
        for (;;) {
            // Whole-iteration fault boundary: wraps the ENTIRE body, not just the
            // send() call below (which has its own inner try/catch to convert a
            // throw into a counted, accounted outcome rather than an abandoned
            // iteration). Anything else that throws here (e.g. a lock failure) is
            // counted as worker_faults and the loop simply continues.
            try {
                std::unique_lock<std::mutex> lk{st->mu};
                if (st->stopping || st->queue.empty()) {
                    st->worker_running = false;
                    lk.unlock();
                    st->cv.notify_all();
                    break;
                }
                Item it = std::move(st->queue.front());
                st->queue.pop_front();
                st->bytes -= it.bytes;
                st->in_flight = true;
                st->in_flight_rule_id = it.rule_id;
                st->send_started_at = std::chrono::steady_clock::now();
                st->stall_logged = false;
                lk.unlock();

                LegacySendOutcome r = LegacySendOutcome::WriteFailed;
                bool threw = false;
                try {
                    r = it.send(it.ev);
                } catch (...) {
                    threw = true;
                }

                lk.lock();
                // Stall check BEFORE clearing in_flight - do NOT copy
                // guardian_outbox_send_executor.hpp's check_stall_locked()
                // verbatim, it early-returns on !in_flight, which would suppress
                // this exact check (see the class doc comment).
                const bool stalled = !st->stall_logged &&
                    (std::chrono::steady_clock::now() - st->send_started_at >=
                     st->stall_threshold);
                if (stalled) {
                    ++st->counters.stalls;
                    st->stall_logged = true;
                }
                const bool recovered = st->stall_logged;
                account_outcome_locked(*st, it, r, threw);
                st->in_flight = false;
                lk.unlock();

                if (stalled)
                    log_send_stall(it.rule_id);
                if (recovered)
                    log_send_recovery(it.rule_id);
                // `it` (and its SendFn copy) destructs here, before `ticket`.
            } catch (...) {
                try {
                    std::lock_guard<std::mutex> lk{st->mu};
                    ++st->counters.worker_faults;
                    st->in_flight = false;
                } catch (...) {
                }
            }
        }
        // `role`, then `ticket`, destruct after the loop - the ticket's
        // destructor is the physical retirement point (correctness property 8).
    }

    /// Called from offer()/kick() with state_->mu NOT held. `ticket` is already
    /// ARMED (worker_running was already set to true, under the same locked
    /// block that decided to call this). On a failed launch (spawn_detached
    /// returned false, or threw before/while building the worker closure), rolls
    /// worker_running back to false and counts launch_failures; the queued
    /// backlog is left untouched, so the NEXT offer() of any key or the next
    /// kick() retries (correctness property 3). Never throws.
    ///
    /// `ticket` is captured BY VALUE (copy, not move) into the worker closure -
    /// deliberately, so THIS function keeps its own live reference. On a failed
    /// spawn, the worker closure (and its copy) is destroyed synchronously
    /// inside spawn_detached's own stack frame, UNLOCKED; this function's own
    /// copy is the one that survives to be dropped AFTER the rollback lock_guard
    /// below has already released the lock - never destroying the last live
    /// reference to an armed ticket while this thread holds state_->mu
    /// (correctness property 5).
    void attempt_launch(std::shared_ptr<AliveTicket> ticket) noexcept {
        if (pre_launch_race_hook_for_test_)
            pre_launch_race_hook_for_test_();
        bool launched = false;
        try {
            if (launch_fault_for_test_.load(std::memory_order_relaxed) ==
                LaunchFaultForTest::Throw)
                throw std::bad_alloc{};
            auto st = state_;
            auto worker = [st, ticket]() mutable noexcept { worker_loop(st, std::move(ticket)); };
            launched = (launch_fault_for_test_.load(std::memory_order_relaxed) ==
                        LaunchFaultForTest::SpawnRefused)
                           ? false
                           : io_detail::spawn_detached(std::move(worker));
        } catch (...) {
            launched = false;
        }
        if (!launched) {
            try {
                std::lock_guard<std::mutex> lk{state_->mu};
                state_->worker_running = false;
                ++state_->counters.launch_failures;
            } catch (...) {
            }
            // `ticket` (this function's own reference) goes out of scope here,
            // AFTER the lock above has already been released.
        }
    }

    std::shared_ptr<State> state_;
    std::function<void()> pre_launch_race_hook_for_test_; ///< test seam; null = no-op
    std::atomic<LaunchFaultForTest> launch_fault_for_test_{LaunchFaultForTest::None};
};

} // namespace yuzu::agent
