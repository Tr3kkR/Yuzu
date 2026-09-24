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
 * repair can be synthesized without touching the guard), sticky until CLEARED by
 * a strictly-newer confirmed-Sent delivery for that rule_id - see "SEQ-GUARDED
 * CLEARING" below (#4783 follow-up review; a REPAIR report offer()'d with
 * is_gap_repair=true is one way to close it, but so is an ordinary real event
 * whose admission-time seq postdates the loss it is closing). If the gap ledger
 * itself cannot be updated (allocation failure), record_gap_locked() degrades
 * gap_ledger_degraded=true and counts gap_ledger_faults instead of throwing -
 * surfaced as its own loss signal, never silently swallowed. Gap *repair
 * synthesis and dispatch* (building a guard.unhealthy event and calling kick()'s
 * heartbeat-driven repair loop) is GuardianEngine::legacy_sink_kick()'s job
 * (commit 4 of the delivery plan) - this class only maintains the ledger and
 * exposes it via gapped_rules_needing_repair().
 *
 * SEQ-GUARDED CLEARING (#4783 follow-up review - a correctness defect found in
 * the ORIGINAL commit-4 design, where ANY offer()'d is_gap_repair=true send that
 * came back Sent erased the gap unconditionally). Every offer() - admitted OR
 * refused alike - is assigned a strictly increasing `seq` (State::next_seq) at
 * admission time; every lost event's gap advances `GapRecord::lost_seq` to the
 * max seq of any loss recorded against it. A delivery (real OR repair) clears
 * the gap ONLY if its own seq is STRICTLY NEWER than `lost_seq` - i.e. it is
 * provably a report of state at-or-after the most recent loss, not a stale
 * in-flight item that merely happened to finish afterwards. This closes two
 * failure classes the naive "clear on any Sent" rule permits: (1) an
 * already-in-flight OLDER send completing Sent after a NEWER loss for the same
 * rule must not erase evidence of that newer loss; (2) a REPAIR queued before a
 * newer loss occurred must not silently confirm the OLD state as current. Case
 * (2) needs a second mechanism because nothing re-validates a queued repair
 * between the moment it is queued and the moment it reaches the front of the
 * FIFO - see DEQUEUE-TIME SUPERSESSION below, which is what actually closes it;
 * the seq check alone only stops a superseded repair's Sent from erasing the
 * gap after the fact, it does not stop the repair from being SENT at all.
 *
 * `GapRecord::repair_seq` (0 = no repair outstanding) records the seq of the
 * repair CURRENTLY queued for that rule, if any - the successor to a plain
 * `repair_in_flight` bool, needed because a repair can be superseded (a newer
 * loss opens/advances the gap while the old repair is still queued) and the
 * executor must be able to tell "this specific queued repair is still the
 * live one" from "a newer repair (or nothing) has since taken its place".
 *
 * DEQUEUE-TIME SUPERSESSION. Immediately after a repair item is popped off the
 * FIFO - BEFORE its send() is invoked - the worker re-checks the rule's CURRENT
 * gap state: if the gap no longer exists, or `repair_seq` no longer names THIS
 * item's own seq (a newer repair superseded it, or - the third case, see the
 * worker loop's own comment - the repair was queued after the gap had already
 * been re-cleared by a fresh real event, so it was never stamped with a live
 * repair_seq at all), the repair is SKIPPED - never sent - and counted in
 * `repairs_suppressed`. This is the piece that actually closes the reported
 * symptom (a stale synthetic repair overwriting a newer real verdict on the
 * server via its own `updated_at >=` upsert guard): checking supersession only
 * at kick/fire time is not enough, because the supersession can happen AFTER
 * the repair is already queued and BEFORE it reaches the front.
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
#include <tuple>
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

    /// A sticky per-rule integrity gap - see the class doc comment's loss table
    /// and its SEQ-GUARDED CLEARING / DEQUEUE-TIME SUPERSESSION sections.
    /// guard_type/rule_name are copied from the LOST event so a repair report can
    /// be synthesized without going back to the guard (guard.hpp has no query API
    /// for "give me your last known state"). `lost_seq` is the max admission-time
    /// seq of any loss recorded against this rule - the floor a delivery's own
    /// seq must strictly exceed to be allowed to clear the gap. `repair_seq` (0 =
    /// none outstanding) is the seq of the repair CURRENTLY queued for this rule,
    /// if any - checked again at DEQUEUE time (worker_loop) to catch the case
    /// where the gap was superseded (a newer loss, or a newer repair, or the gap
    /// being cleared outright by a fresh real delivery) after this repair was
    /// already sitting in the FIFO.
    struct GapRecord {
        std::string guard_type;
        std::string rule_name;
        std::uint64_t lost{0};
        std::chrono::system_clock::time_point first_lost{};
        std::chrono::system_clock::time_point last_lost{};
        std::uint64_t lost_seq{0};
        std::uint64_t repair_seq{0};
        /// #4783 Gate 4 UP-2: the kick_epoch (State::kick_epoch) at the moment a
        /// repair was last QUEUED for this rule (offer()'s is_gap_repair branch) -
        /// 0 if no repair has ever been queued. gapped_rules_needing_repair()'s
        /// rotation sort reads this as its PRIMARY key (least-recently-attempted
        /// first) so a stable set of >kMaxGapRepairsPerKick eligible gaps cycles
        /// through every entry instead of starving whichever ones happen to sort
        /// first. Deliberately NOT reset when a queued repair later fails
        /// (WriteFailed/threw, which resets `repair_seq` back to 0) - keeping the
        /// stale value sends a chronically-failing rule to the back of the
        /// rotation too, so it cannot starve the rules behind it either.
        std::uint64_t last_attempt_kick{0};
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
        /// #4783 follow-up: queued repairs skipped at dequeue time because they
        /// were superseded before reaching the front - see the class doc
        /// comment's DEQUEUE-TIME SUPERSESSION section. Never sent, never counted
        /// as a loss (the gap they would have repaired was either already closed
        /// by something newer, or has since advanced past them).
        std::uint64_t repairs_suppressed{0};
    };

    /// Test-only fault injection for the admission path (offer()). `ThrowOnTicket`
    /// fires at the earliest allocation (the AliveTicket, before the lock and
    /// before any State mutation - the UNARMED rollback, nothing to undo);
    /// `ThrowOnNode` fires at the list-node allocation itself (the LAST throwing
    /// step inside the locked admission block, per the class doc comment - the
    /// only State mutation ahead of it is the harmless next_seq bump, #4783
    /// follow-up). `ThrowOnGapLedger` fires inside
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
                // (2.5) Every offer that reaches the lock - admitted OR refused
                // alike - is assigned its own strictly increasing seq HERE, before
                // the outcome is even decided (#4783 follow-up: SEQ-GUARDED
                // CLEARING, see the class doc comment). This is a State mutation
                // ahead of the (3) list-node allocation below, so ThrowOnNode's
                // rollback is no longer "nothing above this point mutated State" -
                // consuming a seq on a rolled-back attempt is harmless (numbering
                // gaps are unobservable; only relative order matters), so this
                // deliberately stays ahead of the throwing step rather than being
                // pushed below it.
                const std::uint64_t seq = ++state_->next_seq;
                if (state_->stopping) {
                    // Not a "loss" counter by design - see the class doc comment's
                    // loss table (discarded_at_stop is deliberately not events_lost).
                    // Still consumes a seq above (harmless - see the comment there).
                    ++state_->counters.discarded_at_stop;
                    outcome = OfferOutcome::RefusedStopping;
                } else if (state_->queue.size() >= state_->max_events ||
                           state_->bytes + bytes > state_->max_bytes) {
                    ++state_->counters.backpressure_drops;
                    ++state_->counters.events_lost;
                    record_gap_locked(*state_, rule_id, guard_type, rule_name, seq);
                    outcome = OfferOutcome::RefusedCapacity;
                } else {
                    // (3) The list-node allocation - the LAST throwing step; on
                    // throw, nothing above this point mutated State EXCEPT the seq
                    // counter bump above, which is deliberately harmless to lose
                    // track of on rollback (see the comment on that bump).
                    if (admission_fault_for_test() == AdmissionFaultForTest::ThrowOnNode)
                        throw std::bad_alloc{};
                    state_->queue.push_back(Item{std::move(ev), std::move(send), rule_id, bytes,
                                                 is_gap_repair, seq});
                    state_->bytes += bytes;
                    if (is_gap_repair) {
                        if (auto gi = state_->gaps.find(rule_id); gi != state_->gaps.end()) {
                            gi->second.repair_seq = seq;
                            // #4783 Gate 4 UP-2: stamp the CURRENT kick round as
                            // this rule's last repair attempt - see GapRecord's own
                            // doc comment and gapped_rules_needing_repair()'s
                            // rotation sort. Read now, under this same lock, so it
                            // reflects whichever kick() call most recently bumped
                            // it (or 0 if this offer is racing ahead of the first
                            // kick() - harmless, it just sorts to the front once).
                            gi->second.last_attempt_kick = state_->kick_epoch;
                        }
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
                // This path never reached the locked block above (the throw hit
                // before or during the pre-lock ticket allocation) - its own seq
                // comes from the SAME state_->next_seq counter, under this lock,
                // so ordering stays consistent with the main path regardless of
                // which branch actually assigns it.
                const std::uint64_t seq = ++state_->next_seq;
                ++state_->counters.admission_failures;
                ++state_->counters.events_lost;
                record_gap_locked(*state_, rule_id, guard_type, rule_name, seq);
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
            // #4783 Gate 4 UP-2: bump the kick round FIRST, before any other
            // kick() logic - gapped_rules_needing_repair() (called by the
            // production caller, GuardianEngine::legacy_sink_kick(), immediately
            // after this returns) reads the now-current kick_epoch to stamp any
            // repair it queues via offer(). This is a separate lock acquisition
            // from that later call, but since nothing else can run kick() or
            // offer() concurrently against the SAME rule in a way that matters
            // here, bumping it up front is what makes it "current" for the
            // selection that follows.
            ++state_->kick_epoch;
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

    /// Up to `max` gaps ELIGIBLE for a new repair attempt right now - i.e. with
    /// `repair_seq == 0` (NOT already mid-repair; #4783 Gate 4 UP-2 - a gap with
    /// one outstanding is excluded from consideration here rather than counted
    /// against `max` and then skipped by the caller, which is what let an
    /// already-saturated kick offer fewer than `max` NEW repairs). Selection
    /// among the eligible set is a least-recently-attempted round-robin: sorted
    /// by (last_attempt_kick ascending, first_lost ascending, rule_id ascending -
    /// the rule_id tie-break makes selection fully deterministic, independent of
    /// unordered_map iteration order) and the first `max` are returned.
    ///
    /// GUARANTEE: every open gap not already mid-repair receives a repair attempt
    /// within ceil(n_eligible / kMaxGapRepairsPerKick) kicks, where n_eligible is
    /// the number of gaps with repair_seq == 0 at a given kick. Each kick selects
    /// the `max` least-recently-attempted eligible gaps, and offer()'s
    /// is_gap_repair branch stamps every queued repair's last_attempt_kick to the
    /// CURRENT kick round - so a gap selected this kick sorts to the BACK of the
    /// rotation for every following kick until every other still-eligible gap has
    /// had an equal-or-more-recent turn, guaranteeing it resurfaces within
    /// ceil(n_eligible / max) kicks of its last attempt. Because the rule_id
    /// tie-break makes the ordering deterministic rather than dependent on
    /// unordered_map iteration order, this holds even for a perfectly stable set
    /// of gaps - the failure mode this fixes was exactly that stability: a fixed
    /// subset returned (and only ever offered) by every kick, forever.
    [[nodiscard]] std::vector<std::pair<std::string, GapRecord>>
    gapped_rules_needing_repair(std::size_t max) const {
        std::lock_guard<std::mutex> lk{state_->mu};
        // Pointers into the map's own nodes - stable under this lock, so this
        // avoids copying every eligible GapRecord just to sort and then discard
        // most of them.
        std::vector<const std::pair<const std::string, GapRecord>*> eligible;
        eligible.reserve(state_->gaps.size());
        for (const auto& kv : state_->gaps) {
            if (kv.second.repair_seq == 0)
                eligible.push_back(&kv);
        }
        const std::size_t take = std::min(max, eligible.size());
        std::partial_sort(eligible.begin(), eligible.begin() + take, eligible.end(),
                          [](const auto* a, const auto* b) {
                              return std::tie(a->second.last_attempt_kick, a->second.first_lost,
                                              a->first) <
                                     std::tie(b->second.last_attempt_kick, b->second.first_lost,
                                              b->first);
                          });
        std::vector<std::pair<std::string, GapRecord>> out;
        out.reserve(take);
        for (std::size_t i = 0; i < take; ++i)
            out.emplace_back(eligible[i]->first, eligible[i]->second);
        return out;
    }

    // ---- test seams -------------------------------------------------------

    /// EVERY current gap, unfiltered by eligibility and unsorted - unlike
    /// gapped_rules_needing_repair() (production selection: eligible-only,
    /// rotation-sorted, capped), this is a raw snapshot for inspecting a gap's
    /// state (e.g. `repair_seq` while a repair is still mid-flight, which makes
    /// it ineligible and therefore invisible to gapped_rules_needing_repair()).
    [[nodiscard]] std::vector<std::pair<std::string, GapRecord>> all_gaps_for_test() const {
        std::lock_guard<std::mutex> lk{state_->mu};
        std::vector<std::pair<std::string, GapRecord>> out;
        out.reserve(state_->gaps.size());
        for (const auto& kv : state_->gaps)
            out.emplace_back(kv.first, kv.second);
        return out;
    }

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
        /// #4783 follow-up: this item's own admission-time seq (State::next_seq at
        /// the moment offer() admitted it) - see the class doc comment's
        /// SEQ-GUARDED CLEARING section.
        std::uint64_t seq{0};
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
        /// #4783 follow-up: the executor-wide admission sequence counter - every
        /// offer() call that reaches the lock (admitted or refused alike) gets the
        /// next value. See the class doc comment's SEQ-GUARDED CLEARING section.
        std::uint64_t next_seq{0};
        /// #4783 Gate 4 UP-2: bumped once per kick() call (the first statement in
        /// its locked block, before any other kick() logic) - the "round number"
        /// stamped onto GapRecord::last_attempt_kick when a repair is queued for a
        /// rule, so gapped_rules_needing_repair()'s rotation sort can tell which
        /// gaps were attempted longest ago.
        std::uint64_t kick_epoch{0};
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
    /// rather than escaping into either caller's own noexcept contract. `seq` is
    /// the LOST event's own admission-time seq - folded into `lost_seq` as
    /// `max(existing, seq)` (#4783 follow-up: SEQ-GUARDED CLEARING).
    static void record_gap_locked(State& st, const std::string& rule_id,
                                  const std::string& guard_type, const std::string& rule_name,
                                  std::uint64_t seq) {
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
                g.lost_seq = seq;
                st.gaps.emplace(rule_id, std::move(g)); // the one throwing step
            } else {
                ++it->second.lost;
                it->second.last_lost = now;
                it->second.lost_seq = std::max(it->second.lost_seq, seq);
            }
        } catch (...) {
            st.gap_ledger_degraded = true;
            ++st.counters.gap_ledger_faults;
        }
    }

    /// Called with state_->mu HELD, on the worker thread, after one send
    /// attempt completes (normally or by throwing). Applies the loss-accounting
    /// table from the class doc comment. `rule_id`/`guard_type`/`rule_name` are
    /// read from `it` (untouched by the worker loop up to this call); `it.seq` is
    /// this item's own admission-time seq, needed both to advance a freshly
    /// recorded loss's `lost_seq` and to decide (Sent case) whether this specific
    /// delivery is allowed to clear an existing gap (#4783 follow-up:
    /// SEQ-GUARDED CLEARING - see the class doc comment).
    static void account_outcome_locked(State& st, const Item& it, LegacySendOutcome r,
                                       bool threw) {
        if (threw) {
            ++st.counters.send_exceptions;
            ++st.counters.events_lost;
            record_gap_locked(st, it.rule_id, it.ev.guard_type(), it.ev.rule_name(), it.seq);
            if (it.gap_repair) {
                if (auto gi = st.gaps.find(it.rule_id); gi != st.gaps.end())
                    gi->second.repair_seq = 0;
            }
            return;
        }
        switch (r) {
        case LegacySendOutcome::Sent:
            // A delivery (real OR repair) clears the gap only if it is STRICTLY
            // NEWER than the most recent loss recorded against this rule - an
            // in-flight item whose seq predates a subsequent loss must not erase
            // evidence of that loss (#4783 follow-up). Otherwise, if this WAS a
            // repair, it completed but was superseded: reset repair_seq (not an
            // erase) so the next kick requeues a fresh repair with current eyes -
            // in practice DEQUEUE-TIME SUPERSESSION (worker_loop) means a
            // superseded repair is normally never sent at all, so this branch is
            // mainly reached by a repair that raced ahead of a loss recorded
            // AFTER it was already dequeued and sending.
            if (auto gi = st.gaps.find(it.rule_id); gi != st.gaps.end()) {
                if (it.seq > gi->second.lost_seq) {
                    st.gaps.erase(gi); // confirmed delivered, strictly newer than any known loss
                } else if (it.gap_repair) {
                    gi->second.repair_seq = 0;
                }
            }
            break;
        case LegacySendOutcome::WriteFailed:
            ++st.counters.send_failures;
            ++st.counters.events_lost;
            record_gap_locked(st, it.rule_id, it.ev.guard_type(), it.ev.rule_name(), it.seq);
            if (it.gap_repair) {
                if (auto gi = st.gaps.find(it.rule_id); gi != st.gaps.end())
                    gi->second.repair_seq = 0; // retry on the next kick
            }
            break;
        case LegacySendOutcome::LinkDown:
            ++st.counters.dropped_link_down; // NOT a gap - D4b, today's documented
                                             // pre-network/A3 drop semantics
            if (it.gap_repair) {
                if (auto gi = st.gaps.find(it.rule_id); gi != st.gaps.end())
                    gi->second.repair_seq = 0;
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

                if (it.gap_repair) {
                    // #4783 follow-up: DEQUEUE-TIME SUPERSESSION - re-validate
                    // THIS repair's seq against the rule's CURRENT gap state,
                    // immediately after popping and BEFORE its send() ever runs
                    // (never after - the whole point is to catch a supersession
                    // that happened while this item sat queued, which checking
                    // only at kick/fire time cannot). Three cases collapse into
                    // the same check: (1) a newer loss advanced lost_seq and this
                    // rule's repair_seq now belongs to a DIFFERENT (later)
                    // repair - only one repair_seq is ever live per rule, offer()
                    // overwrites it rather than appending; (2) a newer repair for
                    // the same rule superseded this one the same way; (3) the gap
                    // was already cleared outright by a fresh real delivery (see
                    // account_outcome_locked's Sent case) either before this
                    // repair was ever stamped as the live repair_seq, or after.
                    // In every case the gap no longer needs THIS item's report -
                    // skip it, never invoke its send(), never account it as any
                    // kind of loss (it was never a real report to begin with).
                    const auto gi = st->gaps.find(it.rule_id);
                    if (gi == st->gaps.end() || gi->second.repair_seq != it.seq) {
                        ++st->counters.repairs_suppressed;
                        lk.unlock();
                        continue;
                    }
                }

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
