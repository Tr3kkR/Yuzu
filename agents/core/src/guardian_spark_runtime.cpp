#include "guardian_spark_runtime.hpp"

#include "guardian_scope_guard.hpp" // GuardianRollback (terminate-safe rollback)
#include "spark_key_rule_index.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <cassert>
#include <limits>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <unordered_set>
#include <utility>
#include <variant>

namespace yuzu::agent {

namespace {

/// #2233 item 3: which of GuardianIoExecutor's three bounded-I/O lanes backs a
/// SparkType's arm/disarm, or nullopt for a type whose mechanism is never a
/// blocking OS watch (Interval/Startup/Disk - timer/poll-based, matches
/// GuardianIoExecutor's own kIoClassCount==3 scope). attach_rule/detach_rule_locked
/// use nullopt to mean "keep the call inline under registry_mu_, as before".
[[nodiscard]] constexpr std::optional<IoClass> io_class_for_spark_type(SparkType t) noexcept {
    switch (t) {
    case SparkType::File:     return IoClass::File;
    case SparkType::Registry: return IoClass::Registry;
    case SparkType::Service:  return IoClass::Service;
    case SparkType::Interval:
    case SparkType::Startup:
    case SparkType::Disk:
        return std::nullopt;
    }
    return std::nullopt;
}

/// A random 64-bit hex token fixed once per runtime construction. Folded into
/// every event_id so a restart (which resets event_seq_ and can revisit a wall_ms)
/// cannot reproduce a prior id and have the server's event_id PK drop it.
std::string make_boot_nonce() {
    std::random_device rd;
    const std::uint64_t n = (static_cast<std::uint64_t>(rd()) << 32) | rd();
    static const char* d = "0123456789abcdef";
    std::string s(16, '0');
    std::uint64_t v = n;
    for (int i = 15; i >= 0; --i) {
        s[static_cast<std::size_t>(i)] = d[v & 0xF];
        v >>= 4;
    }
    return s;
}

} // namespace

GuardianSparkRuntime::GuardianSparkRuntime(std::shared_ptr<IStateReader> reader,
                                           std::shared_ptr<ISparkBackend> backend)
    : GuardianSparkRuntime(std::move(reader), std::move(backend), Config{}, RuntimeClock{}) {}

GuardianSparkRuntime::GuardianSparkRuntime(std::shared_ptr<IStateReader> reader,
                                           std::shared_ptr<ISparkBackend> backend, Config cfg,
                                           RuntimeClock clock)
    : reader_(std::move(reader)), backend_(std::move(backend)),
      clock_(clock ? std::move(clock)
                   : RuntimeClock{[] { return std::chrono::steady_clock::now(); }}),
      cfg_(cfg), boot_nonce_(make_boot_nonce()), index_(std::make_unique<SparkKeyRuleIndex>()),
      outbox_(std::max(kMinOutboxCapacity, cfg.outbox_capacity)),
      // The LIFECYCLE window must be able to hold at least one maximum-size journal batch.
      // Paging is all-or-nothing per batch, so a window smaller than kMaxJournalEntriesPerBatch
      // makes large batches permanently unpageable - they are skipped every pass and then
      // silently deleted at retention. That loss channel is SIZE-BIASED: the largest batches
      // are mass arm/disarm bursts, i.e. the most security-relevant audit records, so it is
      // strictly worse than a random one (#2345 Gate 5 CH-4 / Gate 4 UP-5+UP-15).
      lifecycle_log_(std::max({kMinOutboxCapacity, cfg.outbox_capacity,
                               kMaxJournalEntriesPerBatch})) {
    if (cfg.outbox_capacity > 0 && cfg.outbox_capacity < kMaxJournalEntriesPerBatch)
        spdlog::info("Guardian: lifecycle audit window raised from the configured {} to {} - a "
                     "window smaller than one maximum-size journal batch makes large batches "
                     "permanently unpageable",
                     cfg.outbox_capacity, kMaxJournalEntriesPerBatch);
    // Reserve the staging vector ONCE - never from rule count. push_back then never
    // reallocates, which is what makes stage_pending_locked's noexcept contract real.
    pending_journal_.reserve(kMaxPendingJournalRecords);
}

GuardianSparkRuntime::~GuardianSparkRuntime() {
    // No in-flight pass can be running: a pass keeps the runtime alive through the
    // handler's captured shared_ptr, so ~runtime runs only once nothing references
    // it. begin_stop() is a defensive idempotent no-op here.
    begin_stop();
}

std::function<void(const SparkEvent&)>
GuardianSparkRuntime::make_handler(std::shared_ptr<GuardianSparkRuntime> rt) {
    // Capture ONLY the shared_ptr: detach-safe. A late/detached dispatch touches
    // solely runtime-owned state, which this keeps alive.
    return [rt = std::move(rt)](const SparkEvent& ev) { rt->on_event(ev); };
}

void GuardianSparkRuntime::release_claim_index_locked(KeyClaim& claim) {
    if (!claim.index_held)
        return;
    claim.index_held = false;
    index_->remove_rule(claim.rule_id); // idempotent; guarded by index_held so a stale
                                        // claim never removes a replacement's mapping
}

std::shared_ptr<GuardianSparkRuntime::KeyClaim>
GuardianSparkRuntime::try_dispatch_head_locked(const std::string& key) {
    const auto eit = claims_.find(key);
    if (eit == claims_.end() || eit->second.fifo.empty())
        return nullptr;
    auto& head = eit->second.fifo.front();
    if (head->dispatch != ClaimDispatch::Queued)
        return nullptr;
    head->dispatch = ClaimDispatch::Dispatching;
    return head;
}

void GuardianSparkRuntime::fail_all_claims_locked(const std::string& key, const std::string& reason,
                                                  ClaimEnd end) {
    const auto eit = claims_.find(key);
    if (eit == claims_.end())
        return;
    for (auto& c : eit->second.fifo) {
        release_claim_index_locked(*c);
        if (!c->outcome)
            c->outcome = std::unexpected(reason);
        if (c->end == ClaimEnd::None)
            c->end = end;
    }
    claims_.erase(eit);
}

std::string GuardianSparkRuntime::abandon_claim_locked(const std::string& key,
                                                       const std::shared_ptr<KeyClaim>& claim,
                                                       bool stopping) {
    // The caller-side half of the exactly-once decision, taken under the SAME
    // registry_mu_ acquisition the completion callback will take (#3816's shape, now on
    // the runtime side): either we get here first and the callback sees
    // waiter_abandoned, or the callback published first and the waiter never reaches
    // this. A timeout while the claim is still Dispatching (mid-submit()) is waiter
    // abandonment too - never erase a claim the dispatcher still expects to find.
    release_claim_index_locked(*claim);
    const std::string reason = stopping ? "stopping" : "arm timed out";
    if (claim->dispatch == ClaimDispatch::Queued) {
        // Never dispatched: queue-wait expiry. Erase it outright; nothing is in flight.
        if (const auto eit = claims_.find(key); eit != claims_.end()) {
            auto& fifo = eit->second.fifo;
            for (auto it = fifo.begin(); it != fifo.end(); ++it) {
                if (*it == claim) {
                    fifo.erase(it);
                    break;
                }
            }
            if (fifo.empty())
                claims_.erase(eit);
        }
        claim->end = stopping ? ClaimEnd::Stopped : ClaimEnd::WaiterTimedOutQueued;
    } else {
        claim->waiter_abandoned = true; // the completion callback finishes this episode
        claim->end = stopping ? ClaimEnd::Stopped : ClaimEnd::WaiterTimedOutDispatched;
    }
    if (!claim->outcome)
        claim->outcome = std::unexpected(reason);
    if (!stopping)
        backend_op_timeouts_.fetch_add(1, std::memory_order_relaxed);
    return reason;
}

std::expected<std::uint64_t, std::string>
GuardianSparkRuntime::wait_for_claim(const std::string& key, const std::shared_ptr<KeyClaim>& claim,
                                     std::chrono::steady_clock::time_point deadline) {
    std::unique_lock<std::mutex> lk{registry_mu_};
    claim_cv_.wait_until(lk, deadline, [&] {
        return claim->outcome.has_value() || claim->commit_exception || stopping_;
    });
    if (claim->commit_exception) {
        // The drain already undid this claim's own commit and erased it; the waiter
        // just re-raises on its own thread (existing "attach_rule throws" contract).
        const std::exception_ptr e = claim->commit_exception;
        lk.unlock();
        std::rethrow_exception(e);
    }
    if (claim->outcome)
        return *claim->outcome; // a real outcome wins over a concurrent stop
    // No outcome: the deadline elapsed, or begin_stop() flipped stopping_ while this
    // claim is dispatched (begin_stop drops QUEUED claims with an outcome itself).
    // Never dereference the empty optional - abandon under this same acquisition.
    return std::unexpected(abandon_claim_locked(key, claim, stopping_));
}

void GuardianSparkRuntime::submit_disarm_off_lock(const std::shared_ptr<KeyClaim>& claim) {
    const std::string key = claim->key;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        const auto eit = claims_.find(key);
        if (eit == claims_.end() || eit->second.fifo.empty() || eit->second.fifo.front() != claim)
            return; // completed, dropped, or not yet the head
        if (claim->dispatch != ClaimDispatch::Queued)
            return; // another caller is already driving it
        claim->dispatch = ClaimDispatch::Dispatching;
    }
    // The bounded backend disarm, exactly as before rung 9c: run() holds the class
    // quota and the single-flight key for the call's duration and bounds THIS
    // caller's wait by cfg_.backend_op_deadline; fn's own return value is discarded
    // (disarm() is void and was never awaited for success even in the old inline
    // call this replaces - see the header doc). Kept on the blocking form
    // deliberately in PR-1: the caller waits anyway, and run() supplies the bound,
    // the quota slot and the timeout accounting for free; the claim entry supplies
    // the same-key ordering (an arm that arrives meanwhile queues behind this claim).
    //
    // #3816: run() no longer has an internal throwing wait-path (a wait-lock failure
    // returns IoFailure::LaunchFailed). The try/catch is NOT dead code even so: the
    // argument evaluation (`key`'s copy into run()'s by-value parameter, the lambda's
    // captures) runs in THIS frame before run() is entered - a bad_alloc there is the
    // live trigger. Every caller treats a disarm as best-effort; a throw here leaves
    // the claim RETAINED (below) rather than dropped, so the watcher is not forgotten.
    std::expected<int, IoFailure> result{std::unexpect, IoFailure::LaunchFailed};
    try {
        result = io_executor_.run(claim->io_class, key, cfg_.backend_op_deadline,
                                  [backend = backend_, sub = claim->subscription]() -> int {
                                      backend->disarm(sub);
                                      return 0;
                                  });
    } catch (const std::exception& e) {
        spdlog::error("Guardian spark: submit_disarm_off_lock's own io_executor_.run() threw "
                     "({}) for key '{}' - the disarm attempt itself failed, not just the "
                     "backend call; the claim is retained for the next same-key event",
                     e.what(), key);
    }
    std::shared_ptr<KeyClaim> refill;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        const auto eit = claims_.find(key);
        if (eit == claims_.end() || eit->second.fifo.empty() || eit->second.fifo.front() != claim)
            return; // begin_stop() dropped it meanwhile
        auto& fifo = eit->second.fifo;
        if (!result && result.error() != IoFailure::Timeout && result.error() != IoFailure::Stopped) {
            // ADMISSION refusal (capacity, key, ceiling, launch, or the throw above):
            // the backend call never ran. Retain the claim at the head - never drop a
            // disarm for capacity reasons (rung 9c R5.2, closing the #3415 silent-drop
            // gap) - and count it. The next same-key event (an attach, which then
            // queues its own arm behind this claim) re-drives it; there is no redrive
            // timer in PR-1. The caller returns now: "retained" is not an outcome.
            claim->dispatch = ClaimDispatch::Queued;
            ++claim->admission_rejections;
            disarm_retained_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        if (!result && result.error() == IoFailure::Timeout) {
            // backend_op_timeouts_ counts deadline hits specifically - only
            // IoFailure::Timeout, matching attach_rule's own increment site (adversarial
            // review C3/k1). The disarm is still running on its worker and completes
            // on its own schedule; the claim is done from this caller's view.
            backend_op_timeouts_.fetch_add(1, std::memory_order_relaxed);
            claim->end = ClaimEnd::WaiterTimedOutDispatched;
            claim->outcome = std::unexpected(std::string{"disarm timed out"});
        } else if (!result) {
            // Stopped: the executor refused admission at shutdown. Dropped with a count
            // (R5.5 makes this the counted total); everything queued behind it goes
            // with it, since nothing can dispatch any more.
            claims_dropped_at_stop_.fetch_add(1, std::memory_order_relaxed);
            fail_all_claims_locked(key, "stopping", ClaimEnd::Stopped);
            claim_cv_.notify_all();
            return;
        } else {
            claim->end = ClaimEnd::DisarmDone;
            claim->outcome = 0;
        }
        fifo.pop_front();
        if (fifo.empty())
            claims_.erase(eit);
        else
            refill = try_dispatch_head_locked(key); // an arm queued behind this disarm
    }
    claim_cv_.notify_all();
    if (refill)
        dispatch_arm_off_lock(key, refill);
}

void GuardianSparkRuntime::dispatch_arm_off_lock(const std::string& key,
                                                 const std::shared_ptr<KeyClaim>& claim) {
    // The claim is the Dispatching head; nothing else can dispatch it. Build the
    // submit() call: `fn` is the bare backend call (it needs nothing from this
    // runtime - #3816); the completion callback captures self_keepalive, NOT `this`,
    // because it runs on a detached io_executor_ worker that may outlive
    // ~GuardianSparkRuntime() (the class's established off-thread capture pattern).
    // shared_from_this()'s documented bad_weak_ptr, a bad_alloc copying `spec`, or a
    // synchronous admission refusal all land in the same place: the claim never
    // launched, no callback will ever fire, so fail the head and every arm queued
    // behind it here (they were all waiting on this one backend call).
    if (claim->kind != ClaimKind::Arm) {
        // Defensive: only an Arm claim is ever handed here (the FIFO invariant puts a
        // Disarm only at the head of an otherwise-empty entry, and every refill site
        // pops the disarm first). Hand a mis-routed disarm back to the retained state
        // rather than arm a spec it does not carry.
        assert(false && "dispatch_arm_off_lock: not an Arm claim");
        std::lock_guard<std::mutex> lk{registry_mu_};
        if (claim->dispatch == ClaimDispatch::Dispatching)
            claim->dispatch = ClaimDispatch::Queued;
        return;
    }
    IoResult<void> adm{std::unexpect, IoFailure::LaunchFailed};
    try {
        auto self = shared_from_this();
        adm = io_executor_.submit(
            claim->io_class, key,
            [backend = backend_, spec = claim->spec]() -> std::expected<std::uint64_t, std::string> {
                return backend->arm(spec);
            },
            [self, key, claim](IoResult<std::expected<std::uint64_t, std::string>>&& r) {
                self->on_arm_complete(key, claim, std::move(r));
            });
    } catch (const std::exception& e) {
        try {
            spdlog::error("Guardian spark: building the arm submission for key '{}' threw ({}) - "
                          "the arm was never dispatched",
                          key, e.what());
        } catch (...) {
        }
    }
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        const auto eit = claims_.find(key);
        if (eit == claims_.end() || eit->second.fifo.empty() || eit->second.fifo.front() != claim)
            return; // the callback already ran (before submit() even returned) and
                    // erased or replaced it - never touch whatever occupies the key now
        if (adm) {
            if (claim->dispatch == ClaimDispatch::Dispatching)
                claim->dispatch = ClaimDispatch::Dispatched;
            return;
        }
        std::string reason;
        switch (adm.error()) {
        case IoFailure::Timeout:            reason = "arm timed out"; break; // unreachable: submit() has no deadline
        case IoFailure::Stopped:            reason = "stopping"; break;
        case IoFailure::CapacityExhausted:  reason = "arm capacity exhausted"; break;
        case IoFailure::AlreadyRunning:     reason = "arm already in progress for this key"; break;
        case IoFailure::LaunchFailed:       reason = "arm worker launch failed"; break;
        case IoFailure::WorkerThrew:        reason = "arm worker threw"; break; // unreachable at admission
        case IoFailure::CeilingExhausted:   reason = "arm rejected at alive-worker ceiling"; break;
        }
        fail_all_claims_locked(key, reason,
                               adm.error() == IoFailure::Stopped ? ClaimEnd::Stopped
                                                                 : ClaimEnd::AdmissionRejected);
    }
    claim_cv_.notify_all();
}

void GuardianSparkRuntime::on_arm_complete(const std::string& key,
                                           const std::shared_ptr<KeyClaim>& claim,
                                           IoResult<std::expected<std::uint64_t, std::string>>&& r) noexcept {
    // Runs on the detached io_executor_ worker (GuardianDetachedWorkerRole marked -
    // nothing here may take GuardianEngine::mtx_; registry_mu_/outbox_mu_ are fine).
    // The executor already released its quota slot and single-flight key before
    // invoking this, so the bounded compensating run() below admits normally.
    //
    // Shape (rung 9c R5.2, commit-in-callback): (1) under registry_mu_, decide the
    // outcome of the head and every sibling and perform the commits - the head stays
    // in the fifo as the key's marker throughout; (2) OFF the lock, run the
    // compensating disarm if a live subscription ended up unwanted; (3) under the
    // lock again, PUBLISH every outcome, pop the finished claims, and dispatch the
    // next head if new claims queued behind meanwhile; (4) wake waiters, fire wakers.
    // Publishing only after (2) is deliberate: no waiter can observe its outcome
    // while a subscription nobody wants is still live, which is what keeps "attach_rule
    // threw => the rollback disarm already happened" true for the caller (:2187's
    // contract) without any notify-order reasoning.
    std::optional<std::uint64_t> compensating; // a live subscription nobody adopted
    std::vector<std::shared_ptr<KeyClaim>> finished;
    std::function<void()> waker;
    std::function<void()> outbox_waker;
    bool firewalled = false;
    try {
        {
            std::unique_lock<std::mutex> lk{registry_mu_};
            const auto eit = claims_.find(key);
            const bool is_head = eit != claims_.end() && !eit->second.fifo.empty() &&
                                 eit->second.fifo.front() == claim;
            const bool armed_live = r && r->has_value();
            if (!is_head) {
                // Cannot happen by construction (only this callback pops the head) -
                // defensive: never leak the subscription, never touch a foreign entry.
                if (armed_live)
                    compensating = **r;
                if (!claim->outcome)
                    claim->outcome = std::unexpected(std::string{"arm claim orphaned"});
                claim->end = ClaimEnd::AdmissionRejected;
                lk.unlock();
                claim_drain_failures_.fetch_add(1, std::memory_order_relaxed);
            } else {
                auto& fifo = eit->second.fifo;
                // Everything currently queued is an Arm claim behind this head (a disarm
                // is only ever created on a key with no live claim - see KeyClaim).
                for (const auto& c : fifo)
                    finished.push_back(c);
                std::vector<std::shared_ptr<KeyClaim>> live;
                for (const auto& c : finished)
                    if (!c->withdrawn && !c->waiter_abandoned)
                        live.push_back(c);

                if (stopping_ || live.empty()) {
                    // Nobody is left to adopt the result: withdrawn, abandoned, or the
                    // runtime is stopping (R5.5: a late success is disarmed, never left
                    // live). No "armed" audit - nothing committed.
                    for (const auto& c : finished) {
                        release_claim_index_locked(*c);
                        if (!c->outcome)
                            c->outcome = std::unexpected(
                                std::string{stopping_ ? "stopping" : "withdrawn"});
                        if (c->end == ClaimEnd::None)
                            c->end = stopping_ ? ClaimEnd::Stopped : ClaimEnd::Withdrawn;
                    }
                    if (armed_live) {
                        compensating = **r;
                        if (claim->waiter_abandoned)
                            backend_op_late_arms_.fetch_add(1, std::memory_order_relaxed);
                    }
                } else if (!r) {
                    // The executor's own outer failure. Only WorkerThrew is reachable
                    // here (submit() has no deadline and admission refusals never reach
                    // a callback); the full map is kept for PR-5.
                    std::string reason;
                    switch (r.error()) {
                    case IoFailure::Timeout:            reason = "arm timed out"; break;
                    case IoFailure::Stopped:            reason = "stopping"; break;
                    case IoFailure::CapacityExhausted:  reason = "arm capacity exhausted"; break;
                    case IoFailure::AlreadyRunning:     reason = "arm already in progress for this key"; break;
                    case IoFailure::LaunchFailed:       reason = "arm worker launch failed"; break;
                    case IoFailure::WorkerThrew:        reason = "arm worker threw"; break;
                    case IoFailure::CeilingExhausted:   reason = "arm rejected at alive-worker ceiling"; break;
                    }
                    if (r.error() == IoFailure::Timeout)
                        backend_op_timeouts_.fetch_add(1, std::memory_order_relaxed);
                    for (const auto& c : finished) {
                        release_claim_index_locked(*c);
                        if (!c->outcome)
                            c->outcome = std::unexpected(reason);
                        if (c->end == ClaimEnd::None)
                            c->end = r.error() == IoFailure::WorkerThrew ? ClaimEnd::WorkerThrew
                                                                        : ClaimEnd::AdmissionRejected;
                    }
                } else if (!armed_live) {
                    // backend_->arm() itself refused (synchronously, on the worker) - the
                    // key genuinely could not be armed, so every sibling fails with it.
                    for (const auto& c : finished) {
                        release_claim_index_locked(*c);
                        if (!c->outcome)
                            c->outcome = std::unexpected(r->error());
                        if (c->end == ClaimEnd::None)
                            c->end = ClaimEnd::BackendRefused;
                    }
                } else {
                    // Success: commit every live claim, in FIFO order, against the ONE
                    // new subscription. `compensating` holds the subscription from this
                    // point until the first surviving claim's commit adopts it, so a
                    // throw anywhere before that (make_shared, keys_.emplace, a waker
                    // copy, the lifecycle enqueue) leaves it owned by the disarm step
                    // below, never leaked - the guard exists BEFORE the fallible work,
                    // exactly as the pre-R5.2 post-wait commit's rollback did.
                    const std::uint64_t sub = **r;
                    compensating = sub;
                    std::shared_ptr<PerKey> pk;
                    std::string adopted_by; // rule_id whose commit adopted `sub`
                    for (const auto& c : live) {
                        if (!pk) {
                            // First surviving claim (the head may itself be withdrawn):
                            // its commit is what makes keys_[key] live. Undo on throw:
                            // erase what this claim wrote and leave `compensating` set.
                            try {
                                auto fresh = std::make_shared<PerKey>();
                                fresh->spec = claim->spec; // the spec actually armed
                                fresh->subscription = sub;
                                keys_.emplace(key, fresh);
                                try {
                                    commit_new_generation_locked(c->rule_id, c->generation,
                                                                 c->guard_type, c->rule_name,
                                                                 fresh, std::move(c->rg),
                                                                 c->attach_now, waker, outbox_waker);
                                } catch (...) {
                                    rules_.erase(c->rule_id);
                                    fresh->pending_initial.erase(c->rule_id);
                                    keys_.erase(key);
                                    throw;
                                }
                                pk = fresh;
                                adopted_by = c->rule_id;
                            } catch (...) {
                                release_claim_index_locked(*c);
                                c->commit_exception = std::current_exception();
                                c->end = ClaimEnd::CommitThrew;
                                // `compensating` still holds `sub`: the remaining live
                                // claims cannot adopt a subscription whose PerKey does
                                // not exist, so they fail with a plain reason.
                                for (const auto& other : live) {
                                    if (other == c || other->outcome || other->commit_exception)
                                        continue;
                                    release_claim_index_locked(*other);
                                    other->outcome = std::unexpected(std::string{"arm commit failed"});
                                    other->end = ClaimEnd::CommitThrew;
                                }
                                break;
                            }
                            compensating.reset(); // adopted
                            c->index_held = false; // ownership passed to rules_/keys_
                            c->outcome = c->generation;
                            c->end = ClaimEnd::Committed;
                        } else {
                            // A later sibling joins the existing shared watcher - the
                            // pre-existing reuse path, one commit per claim. A throw here
                            // undoes only THIS claim's own bookkeeping; the drain continues.
                            try {
                                commit_new_generation_locked(c->rule_id, c->generation,
                                                             c->guard_type, c->rule_name, pk,
                                                             std::move(c->rg), c->attach_now,
                                                             waker, outbox_waker);
                                c->index_held = false;
                                c->outcome = c->generation;
                                c->end = ClaimEnd::Committed;
                            } catch (...) {
                                rules_.erase(c->rule_id);
                                pk->pending_initial.erase(c->rule_id);
                                release_claim_index_locked(*c);
                                c->commit_exception = std::current_exception();
                                c->end = ClaimEnd::CommitThrew;
                            }
                        }
                    }
                    // Claims that were withdrawn/abandoned while their siblings adopted.
                    for (const auto& c : finished) {
                        if (c->outcome || c->commit_exception)
                            continue;
                        release_claim_index_locked(*c);
                        c->outcome = std::unexpected(
                            std::string{c->withdrawn ? "withdrawn" : "arm timed out"});
                        if (c->end == ClaimEnd::None)
                            c->end = c->withdrawn ? ClaimEnd::Withdrawn
                                                  : ClaimEnd::WaiterTimedOutDispatched;
                    }
                }
            }
        }

        // (2) OFF the lock: the compensating disarm, BEFORE anything is published. A
        // bounded run() on this worker holds the class quota for the call (a wedged
        // disarm therefore never escapes the bulkhead into the physical ceiling) and
        // the head claim is still the key's marker, so a rearm that arrives meanwhile
        // queues behind it. Direct only when the executor is stopping (R5.5: a late
        // success is disarmed rather than left live; nothing else can run it then).
        if (compensating) {
            std::expected<int, IoFailure> d{std::unexpect, IoFailure::LaunchFailed};
            try {
                d = io_executor_.run(claim->io_class, key, cfg_.backend_op_deadline,
                                     [backend = backend_, sub = *compensating]() -> int {
                                         backend->disarm(sub);
                                         return 0;
                                     });
            } catch (...) {
            }
            if (!d) {
                if (d.error() == IoFailure::Timeout) {
                    backend_op_timeouts_.fetch_add(1, std::memory_order_relaxed);
                } else {
                    // Stopped, or refused/threw at admission: the watcher must not be
                    // left live. Direct call on this (detached, role-marked) worker.
                    try {
                        backend_->disarm(*compensating);
                    } catch (...) {
                    }
                }
            }
            compensating.reset();
        }
    } catch (...) {
        firewalled = true;
    }

    // (3) PUBLISH and pop. Reached on every path, including the firewall: a claim
    // left in the fifo with no outcome would be a Dispatched head nobody pops - #3831's
    // orphaned marker in the new shape, wedging the key until restart.
    std::shared_ptr<KeyClaim> refill;
    try {
        std::lock_guard<std::mutex> lk{registry_mu_};
        if (firewalled) {
            claim_drain_failures_.fetch_add(1, std::memory_order_relaxed);
            if (compensating) {
                try {
                    backend_->disarm(*compensating); // last resort; never leak it
                } catch (...) {
                }
                compensating.reset();
            }
        }
        const auto eit = claims_.find(key);
        if (eit != claims_.end()) {
            auto& fifo = eit->second.fifo;
            // Pop every claim this drain finished (they are a prefix of the fifo; new
            // claims that queued behind the head during (2) follow them).
            for (const auto& c : finished) {
                if (!c->outcome && !c->commit_exception) {
                    release_claim_index_locked(*c);
                    c->outcome = std::unexpected(std::string{"arm drain failed"});
                    c->end = ClaimEnd::CommitThrew;
                }
                if (!fifo.empty() && fifo.front() == c)
                    fifo.pop_front();
            }
            if (firewalled && !fifo.empty() && fifo.front() == claim) {
                // finished was never filled: the head is still here. Drop the entry.
                for (auto& c : fifo) {
                    release_claim_index_locked(*c);
                    if (!c->outcome)
                        c->outcome = std::unexpected(std::string{"arm drain failed"});
                    if (c->end == ClaimEnd::None)
                        c->end = ClaimEnd::CommitThrew;
                }
                fifo.clear();
            }
            if (fifo.empty())
                claims_.erase(eit);
            else
                refill = try_dispatch_head_locked(key);
        }
    } catch (...) {
        // A lock failure here leaves the entry as-is; the waiters' own deadlines still
        // bound them, and the count records that this path fired.
        claim_drain_failures_.fetch_add(1, std::memory_order_relaxed);
    }
    // (4) Wake + notify. Waiters were unreachable until now.
    claim_cv_.notify_all();
    try {
        if (waker)
            waker();
        if (outbox_waker)
            outbox_waker();
    } catch (...) {
    }
    if (refill)
        dispatch_arm_off_lock(key, refill);
}

std::size_t GuardianSparkRuntime::claim_queue_depth_for_test(const std::string& key) const {
    std::lock_guard<std::mutex> lk{registry_mu_};
    const auto eit = claims_.find(key);
    return eit == claims_.end() ? 0 : eit->second.fifo.size();
}

void GuardianSparkRuntime::commit_new_generation_locked(
    const std::string& rule_id, std::uint64_t gen, const char* guard_type,
    const std::string& rule_name, const std::shared_ptr<PerKey>& pk,
    std::shared_ptr<RuleGeneration> rg, std::chrono::steady_clock::time_point attach_now,
    std::function<void()>& waker, std::function<void()>& outbox_waker) {
    rules_.insert_or_assign(rule_id, std::move(rg));
    pk->pending_initial.insert_or_assign(rule_id, PendingState{attach_now, 0, false});
    // Copy the wakers (throwing std::function copies) BEFORE the lifecycle enqueue so
    // a throw here rolls back with NO audit entry yet - see the callers' own rollback
    // guards for the full reasoning.
    waker = pending_initial_waker_;
    outbox_waker = outbox_enqueue_waker_;
    enqueue_lifecycle_locked(rule_id, gen, "armed", guard_type, rule_name);
}

std::expected<std::uint64_t, std::string>
GuardianSparkRuntime::attach_rule(std::string rule_id, SparkSpec spec, RuleAssertion assertion,
                                  bool emit_compliant_edge) {
    const std::string key = spark_key(spec);
    // #2233 item 3: File/Registry/Service arm off registry_mu_; every other type
    // stays inline (see io_class_for_spark_type's doc).
    const std::optional<IoClass> io_class = io_class_for_spark_type(spec.type);
    std::function<void()> waker;
    std::function<void()> outbox_waker;
    std::uint64_t new_gen = 0;
    std::shared_ptr<KeyClaim> prior_disarm;
    // Snapshot BEFORE taking registry_mu_ (same outside-lock pattern evaluate_key uses
    // for its own now-snapshot): this is PendingState::first_seen, the M1 item (b)
    // elapsed-time demotion clock. A fresh attach always starts un-demoted regardless
    // of how long a PRIOR generation on this rule_id sat pending (detach_rule_locked
    // below drops that generation's PendingState entirely). It comes from the
    // INJECTED clock_() and is never used as the real wait deadline below.
    const auto attach_now = clock_();

    // Built once, reused by both the fast (reuse-existing-watcher / inline-type) path
    // and the claim (bounded off-lock arm) path's commit.
    const std::string rule_name = assertion.rule_name;
    const char* guard_type = guard_type_for(assertion.kind);
    auto rg = std::make_shared<RuleGeneration>();
    rg->active = true;
    rg->emit_compliant_edge = emit_compliant_edge;
    rg->assertion = std::move(assertion);
    rg->assertion.rule_id = rule_id; // keep the assertion's own rule_id authoritative

    std::uint64_t gen = 0;
    std::shared_ptr<KeyClaim> arm_claim;    // this call's own claim, once queued
    std::shared_ptr<KeyClaim> to_dispatch;  // set iff this call must dispatch it
    std::shared_ptr<KeyClaim> head_to_drive; // a retained disarm at the head to redrive first

    // #3831 (rung 9c R5.2 shape): this guard protects the claim enqueue inside the
    // locked block just below, but the work it must ALSO wrap - the off-lock dispatch
    // and the bounded wait, much further down - runs OFF both locks in a separate
    // region after that block has already closed. Function-scoped, one object spanning
    // both regions, .fn assigned HERE before registry_mu_ is even locked, so a throw
    // during the assignment (a multi-capture closure exceeding libstdc++'s
    // std::function SBO heap-allocates) has nothing to roll back yet - the original
    // defect was a guard whose .fn was assigned AFTER the mutation it protected, which
    // left the key's marker orphaned forever on a bad_alloc. arm_claim starts null and
    // is set (a noexcept pointer write) immediately after the enqueue succeeds, so fn
    // no-ops until then. Matched on POINTER identity: a same-rule_id retry that has
    // since queued a FRESH claim is a different object, so this guard can never touch
    // it (stronger than the (rule_id, generation) match the InFlightArm shape needed).
    //
    // Lock order: fn takes registry_mu_, yet it is declared while the caller has NOT
    // locked it, and it can fire while the locked block below still holds it. Safe only
    // because that block's own std::unique_lock is a NARROWER scope than this
    // function-scope guard - C++ unwind destructs the narrower scope's locals
    // (releasing registry_mu_) before continuing to unwind this one. Moving this
    // declaration back inside that block would deadlock on exactly that unwind path.
    GuardianRollback claim_rollback;
    claim_rollback.fn = [this, key, &arm_claim] {
        if (!arm_claim)
            return; // never enqueued (or not yet) - nothing to undo
        std::lock_guard<std::mutex> lk{registry_mu_};
        // Only if the claim is still live in its entry: a completed/erased claim is
        // already terminal and needs no undo.
        const auto eit = claims_.find(key);
        if (eit == claims_.end())
            return;
        bool present = false;
        for (const auto& c : eit->second.fifo)
            if (c == arm_claim) {
                present = true;
                break;
            }
        if (!present || arm_claim->outcome || arm_claim->commit_exception)
            return;
        abandon_claim_locked(key, arm_claim, stopping_);
        claim_cv_.notify_all();
    };

    {
        std::unique_lock<std::mutex> lk{registry_mu_};
        if (stopping_)
            return std::unexpected(std::string{"stopping"});

        // PR #3821 review (fjarvis, cpp-safety re-review): armed BEFORE
        // prior_disarm is even populated below, not after - fn is a std::function
        // ASSIGNMENT (a separate throwing operation from this guard's own
        // construction; a 3-capture closure exceeds libstdc++'s SBO and heap-
        // allocates), so a guard armed only once prior_disarm already held a real
        // value would itself have a bad_alloc-sized gap where the mutation was
        // real but the guard protecting it did not exist yet. Safe to install
        // this early: fn checks `if (prior_disarm)` at fire-time and correctly
        // no-ops on every exit before the assignment below actually runs.
        // Protects every return/throw between here and this locked block's normal
        // end uniformly: lk.unlock() before the off-lock submission, matching this
        // function's own established discipline. Committed only once that normal
        // end is reached. (rung 9c R5.2: the disarm claim is already queued at the
        // head of the key entry by detach_rule_locked, so a same-key rearm that
        // arrives during this unlock queues BEHIND it by construction.)
        GuardianRollback prior_disarm_rollback;
        prior_disarm_rollback.fn = [this, &prior_disarm, &lk] {
            if (prior_disarm) {
                lk.unlock();
                submit_disarm_off_lock(prior_disarm);
            }
        };

        // Fresh generation: drop any prior mapping for this rule first. This
        // rebuilds eval state from scratch on every push, identical re-push
        // included - there is no diff-skip that preserves it (matches the legacy
        // path's own tear-down-and-rebuild-every-push behavior). If a prior
        // generation existed, this already enqueued its "disarmed" lifecycle entry
        // (and, #2233 item 3, may return a disarm claim driven off-lock either
        // way: prior_disarm_rollback above fires it on an early return/throw,
        // committed=true suppresses it and the explicit call after this locked
        // block fires it instead on the normal path - exit-path-exclusive, never
        // both) - the "armed" entry below covers the new one, so ONE outbox-waker
        // firing at the end of this call covers both. A prior generation whose own
        // arm is still claimed is withdrawn in place (Case 0, generalised).
        prior_disarm = detach_rule_locked(rule_id);

        gen = ++gen_counter_;
        rg->generation = gen;

        // Gate 4 unhappy-path re-review (PR #3821 scoped governance): armed BEFORE
        // index_->add() runs, same reasoning and same fix shape as
        // prior_disarm_rollback above - a guard whose .fn is assigned only AFTER
        // the mutation it protects has a bad_alloc-sized gap during that
        // assignment itself. index_added starts false and is set true immediately
        // after index_->add() returns (a bool assignment, cannot throw), so fn
        // correctly no-ops if the assignment below never runs. Covers index_->add's
        // effect uniformly for every branch below - each branch's OWN rollback
        // (still correctly armed-before-mutation within its own branch) now
        // protects only ITS OWN additional state, not this shared one, so nothing
        // double-removes it. On the claim branches the claim's own index_held flag
        // takes over once the claim is queued (committed below), so the two never
        // both remove the mapping.
        bool index_added = false;
        GuardianRollback index_add_rollback;
        index_add_rollback.fn = [this, rule_id, &index_added] {
            if (index_added)
                index_->remove_rule(rule_id);
        };

        // rung 9c R5.2: a key that already has a claim entry (an arm in flight with
        // or without siblings, a disarm in flight, or a disarm RETAINED after an
        // admission refusal) is checked FIRST - before the 0->1 edge decides
        // anything - so this call queues behind it instead of double-arming or
        // failing fast. The old fail-fast "busy" rejection lived here (#2233 item 3);
        // it was unreachable via GuardianEngine's mtx_-serialised production callers
        // and is replaced, not removed: a second same-key call is now a QUEUED claim
        // that commits against the same subscription when the head's arm lands.
        const auto cit = claims_.find(key);
        const bool key_claimed = io_class && cit != claims_.end() && !cit->second.fifo.empty();

        const bool arm_edge = index_->add(key, rule_id); // may throw; index_added still false then
        index_added = true;
        if (key_claimed || (arm_edge && io_class)) {
            // Claim path: mark and return to the caller below WITHOUT touching
            // keys_/rules_/pending_initial/lifecycle - all deferred to the completion
            // callback's commit, so a same-key racer never sees a half-built PerKey.
            auto c = std::make_shared<KeyClaim>(); // may throw -> index_add_rollback
            c->kind = ClaimKind::Arm;
            c->key = key;
            c->io_class = *io_class;
            c->rule_id = rule_id;
            c->generation = gen;
            c->spec = spec;
            c->rg = std::move(rg);
            c->rule_name = rule_name;
            c->guard_type = guard_type;
            c->attach_now = attach_now;
            auto& entry = claims_[key];               // may throw -> index_add_rollback
            entry.fifo.push_back(c);                  // may throw -> index_add_rollback
            c->index_held = true;                     // noexcept; ownership handed over
            arm_claim = c;                            // noexcept; arms claim_rollback (#3831)
            if (key_claimed) {
                backend_op_queued_.fetch_add(1, std::memory_order_relaxed);
                // A retained (Queued, refused-before) disarm at the head is re-driven
                // by THIS call after it unlocks; a Dispatching/Dispatched head needs
                // nothing from us.
                if (entry.fifo.front() != c && entry.fifo.front()->kind == ClaimKind::Disarm &&
                    entry.fifo.front()->dispatch == ClaimDispatch::Queued)
                    head_to_drive = entry.fifo.front();
                assert(entry.fifo.front()->kind == ClaimKind::Disarm ||
                       entry.fifo.front()->kind == ClaimKind::Arm);
            } else {
                to_dispatch = try_dispatch_head_locked(key); // it is the head
            }
        } else if (arm_edge) {
            // Inline type (Interval/Startup/Disk): unchanged synchronous arm, still
            // under registry_mu_ - these are never a blocking OS watch.
            std::shared_ptr<PerKey> pk;
            std::uint64_t sub = 0;
            bool armed_here = false;
            GuardianRollback rollback;
            rollback.fn = [this, rule_id, key, &sub, &armed_here, &pk] {
                if (armed_here) {
                    keys_.erase(key);
                    backend_->disarm(sub);
                }
                rules_.erase(rule_id);
                if (pk)
                    pk->pending_initial.erase(rule_id);
            };
            auto armed = backend_->arm(spec); // may THROW -> rollback + index_add_rollback undo it
            if (!armed)
                return std::unexpected(armed.error()); // rollback + index_add_rollback undo it
            sub = *armed;
            armed_here = true;
            pk = std::make_shared<PerKey>();
            pk->spec = spec;
            pk->subscription = sub;
            keys_.emplace(key, pk);

            commit_new_generation_locked(rule_id, gen, guard_type, rule_name, pk, std::move(rg),
                                         attach_now, waker, outbox_waker);
            rollback.committed = true;
        } else {
            // An existing, COMMITTED shared watcher for this key: reaching here with
            // arm_edge==false and no claim entry means keys_ genuinely has it (a key
            // with a claim entry took the branch above, so keys_.at cannot throw here).
            // No backend call, but a throw below (map insert, or a throwing
            // waker/outbox_waker COPY) must still undo the index_->add - mirrors the
            // original unified rollback's armed_here=false shape (never disarms;
            // there is no new watcher to tear down, only this rule's own bookkeeping;
            // index_add_rollback above handles the index_->add undo).
            auto pk = keys_.at(key);
            GuardianRollback rollback;
            rollback.fn = [this, rule_id, pk] {
                rules_.erase(rule_id);
                pk->pending_initial.erase(rule_id);
            };
            commit_new_generation_locked(rule_id, gen, guard_type, rule_name, pk, std::move(rg),
                                         attach_now, waker, outbox_waker);
            rollback.committed = true;
        }
        new_gen = gen;
        index_add_rollback.committed = true;
        prior_disarm_rollback.committed = true;
    }

    // Off-lock: any watcher a superseded prior generation owed a disarm to. Its claim
    // is already at the head of its key entry, so if this redeploy kept the SAME key
    // our own arm claim is queued behind it by construction (the "disarm completes
    // before its own rearm dispatches" property R5.2 asks for) and driving it here
    // refills straight into our arm; a different key just runs the disarm first, as
    // before, so the two never race their own teardown against their own re-arm.
    if (prior_disarm)
        submit_disarm_off_lock(prior_disarm);
    else if (head_to_drive)
        submit_disarm_off_lock(head_to_drive); // a retained disarm from an earlier detach
    if (to_dispatch)
        dispatch_arm_off_lock(key, to_dispatch);

    if (!arm_claim) {
        if (waker)
            waker();
        if (outbox_waker)
            outbox_waker();
        return new_gen;
    }

    // The bounded wait for THIS call's own claim (PR-1's synchronous contract: a
    // caller - GuardianEngine::apply_rules/start_local, still holding mtx_ for its
    // whole body - waits at most cfg_.backend_op_deadline for this rule's arm to
    // resolve, PLUS, if this rule_id had a prior generation on a bounded key, up to
    // another deadline for that generation's disarm above, since the two are
    // sequential, not concurrent - a same-key redeploy is therefore up to 2x this
    // deadline, not 1x; PR-2 removes the wait). The deadline is real steady_clock
    // time captured HERE, after the prior-disarm wait, never the injected clock_()
    // snapshot above (tests inject fake clocks) and never counted from entry. Every
    // OTHER rule's attach/detach and every evaluate_key proceed freely throughout,
    // since registry_mu_ is not held here at all. The commit itself - keys_/rules_/
    // pending_initial/"armed" audit - runs in on_arm_complete on the executor
    // worker; the wait only collects its recorded outcome (or rethrows its commit
    // exception on this thread). On a deadline or stop the waiter abandons the claim
    // under registry_mu_ (a queued claim is erased, a dispatched one is left for the
    // callback to finish and disarm - #3816's late-success handling, now decided on
    // the runtime's side with the same one-mutex shape). The wakers for a claim
    // commit are fired by the callback, not here.
    const auto deadline = std::chrono::steady_clock::now() + cfg_.backend_op_deadline;
    auto outcome = wait_for_claim(key, arm_claim, deadline);
    claim_rollback.committed = true;
    return outcome;
}

void GuardianSparkRuntime::detach_rule(const std::string& rule_id) {
    std::function<void()> outbox_waker;
    std::shared_ptr<KeyClaim> work;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        work = detach_rule_locked(rule_id);
        outbox_waker = outbox_enqueue_waker_;
    }
    // #2233 item 3: off both locks - the confirmed-state mutation + "disarmed" audit
    // above are already committed regardless of what follows here.
    if (work)
        submit_disarm_off_lock(work);
    if (outbox_waker)
        outbox_waker();
}

void GuardianSparkRuntime::detach_all() {
    std::function<void()> outbox_waker;
    std::vector<std::shared_ptr<KeyClaim>> works;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        // rung 9c R5.2: a full sync replaces the active set, so a rule that is still
        // only CLAIMED (its arm in flight or queued, no rules_ entry yet) must be
        // withdrawn too - detach_rule_locked's Case 0 handles each, generalised.
        std::vector<std::string> claimed;
        for (const auto& [k, entry] : claims_)
            for (const auto& c : entry.fifo)
                if (c->kind == ClaimKind::Arm && !c->withdrawn && !c->waiter_abandoned &&
                    !c->outcome)
                    claimed.push_back(c->rule_id);
        for (const auto& rid : claimed)
            (void)detach_rule_locked(rid);
        std::vector<std::string> rule_ids;
        rule_ids.reserve(rules_.size());
        for (const auto& [rid, rg] : rules_)
            rule_ids.push_back(rid);
        for (const auto& rid : rule_ids)
            if (auto work = detach_rule_locked(rid))
                works.push_back(std::move(work));
        outbox_waker = outbox_enqueue_waker_;
    }
    // #2233 item 3: submitted sequentially, off-lock, each bounded by
    // cfg_.backend_op_deadline - full_sync teardown already tolerates this class of
    // latency (see apply_rules' full_sync branch, which counts+holds the generation
    // for the server to retry on a firewalled throw); this is the same trade,
    // bounded instead of unbounded.
    for (const auto& work : works)
        submit_disarm_off_lock(work);
    if (outbox_waker)
        outbox_waker();
}

std::shared_ptr<GuardianSparkRuntime::KeyClaim>
GuardianSparkRuntime::detach_rule_locked(const std::string& rule_id, std::string_view lifecycle_kind) {
    // rung 9c R5.2 (Case 0, generalised from #2233 item 3): rule_id belongs to a key
    // whose arm is still CLAIMED - in flight as the head, or queued behind it - so it
    // has no rules_/keys_ entry to withdraw yet. Mark the claim withdrawn and release
    // its index mapping NOW (matches the immediate-index-cleanup semantics the
    // confirmed path below already has). A queued (never dispatched) claim is erased
    // outright and its waiter woken; a dispatched one stays as the key's marker and
    // its completion skips it (a live sibling adopts the subscription, or it is
    // disarmed). No "disarmed" audit - the rule was never actually armed (same
    // "pending arm withdrawn -> no lifecycle entry" contract the confirmed path's
    // `known` gate already encodes). The search excludes withdrawn AND abandoned
    // claims so a retained stale claim can never match ahead of its live replacement.
    if (const auto key_opt = index_->key_for_rule(rule_id); key_opt) {
        if (const auto eit = claims_.find(*key_opt); eit != claims_.end()) {
            auto& fifo = eit->second.fifo;
            for (auto it = fifo.begin(); it != fifo.end(); ++it) {
                auto& c = *it;
                if (c->kind != ClaimKind::Arm || c->rule_id != rule_id || c->withdrawn ||
                    c->waiter_abandoned || c->outcome)
                    continue;
                c->withdrawn = true;
                release_claim_index_locked(*c);
                // The waiter returns "withdrawn" NOW in either state - the rule is no
                // longer wanted, so there is nothing for its caller to wait for. A
                // dispatched claim keeps its place as the key's marker and the drain
                // skips it by the `withdrawn` flag (a live sibling adopts the result, or
                // it is disarmed); a queued one is erased outright.
                c->outcome = std::unexpected(std::string{"withdrawn"});
                c->end = ClaimEnd::Withdrawn;
                if (c->dispatch == ClaimDispatch::Queued) {
                    fifo.erase(it);
                    if (fifo.empty())
                        claims_.erase(eit);
                }
                claim_cv_.notify_all(); // under the lock: a _locked helper cannot defer it
                return nullptr; // nothing to disarm yet; the claim's completion handles it
            }
        }
    }

    const auto rit = rules_.find(rule_id);
    const bool known = (rit != rules_.end());
    const std::uint64_t gen = known ? rit->second->generation : 0;
    // Capture the lifecycle metadata before rules_.erase below drops the generation.
    const std::string rule_name = known ? rit->second->assertion.rule_name : std::string{};
    const char* guard_type = known ? guard_type_for(rit->second->assertion.kind) : "";
    const auto key_opt = index_->key_for_rule(rule_id); // capture BEFORE removal
    if (known)
        rit->second->active = false; // in-flight evals will not commit
    const auto disarm_key = index_->remove_rule(rule_id);
    if (known)
        rules_.erase(rule_id);
    {
        std::lock_guard<std::mutex> ob{outbox_mu_};
        outbox_.drop_rule(rule_id); // compliance/health only - Lifecycle lives in lifecycle_log_
    }
    // #2233 item 3 / rung 9c R5.2: the confirmed-state mutation above (index_/rules_/
    // keys_) and the "disarmed" audit below are the durable commit; the actual
    // backend_->disarm() call is the CALLER's job, off-lock, by driving the DISARM
    // CLAIM queued here (submit_disarm_off_lock). Queued in THIS critical section, the
    // same one that erases keys_[key]: a same-key attach that lands in the off-lock
    // gap sees the claim and queues its arm behind it, rather than seeing "no keys_
    // entry, no claim" and dispatching an arm ahead of the teardown. Changes WHERE
    // the call runs, not whether its success is confirmed - disarm() is void and was
    // never awaited for success even in the old inline call.
    std::shared_ptr<KeyClaim> work;
    if (disarm_key) {
        const auto kit = keys_.find(*disarm_key);
        if (kit != keys_.end()) {
            if (const auto ioc = io_class_for_spark_type(kit->second->spec.type)) {
                auto c = std::make_shared<KeyClaim>();
                c->kind = ClaimKind::Disarm;
                c->key = *disarm_key;
                c->io_class = *ioc;
                c->subscription = kit->second->subscription;
                auto& entry = claims_[*disarm_key];
                // A disarm is only ever created on a key with no live claim (an arm
                // never writes keys_ until it commits, and commit erases the entry).
                assert(entry.fifo.empty());
                entry.fifo.push_back(c);
                work = c;
            } else {
                backend_->disarm(kit->second->subscription); // inline type: unchanged, synchronous
            }
            keys_.erase(kit); // the in-flight pass (if any) holds its own shared_ptr; safe
        }
    } else if (key_opt) {
        const auto kit = keys_.find(*key_opt);
        if (kit != keys_.end())
            kit->second->pending_initial.erase(rule_id);
    }
    if (known)
        enqueue_lifecycle_locked(rule_id, gen, std::string(lifecycle_kind), guard_type, rule_name);
    return work;
}

void GuardianSparkRuntime::on_subscription_lost(const std::string& key,
                                                 std::uint64_t subscription_id,
                                                 const std::string& detail) {
    // #2818: the underlying watch for `key` was torn down entirely - every rule
    // currently on it lost its enforcement, not just withdrew from it. Report each as
    // "errored" (guardian_outbox.hpp's documented vocabulary) rather than "disarmed" -
    // no immediate self-heal in this PR (Dave's call, 2026-09-06: smaller, safer diff,
    // no new blocking-retry policy).
    //
    // RECOVERY PATH, STATED PRECISELY (governance Gate 4 unhappy-path UP-4 - an
    // earlier version of this comment overclaimed "the next server-issued
    // PushRules"): a subscription dying is LOCAL to this agent and never changes the
    // server's policy generation, so server.cpp's heartbeat reconcile gate
    // (`if (agent_gen >= current) ...`, i.e. it re-pushes only when the SERVER's
    // generation has moved past what the agent last reported) is NOT triggered by
    // this event on its own. The two things that DO recover an errored rule are an
    // UNRELATED rule/policy edit bumping the server generation (whatever its cause),
    // or an agent restart (whose boot re-arm calls reconcile_rule_locked for every
    // persisted rule unconditionally). Absent either, an errored rule can sit
    // un-enforced for the life of the deployment with no proactive operator signal
    // beyond the "errored" audit entry itself - a real, undocumented-until-now
    // residual, tracked as a hardening candidate before the prefer_spark_ flip.
    std::function<void()> outbox_waker;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        if (stopping_)
            return;
        const auto kit = keys_.find(key);
        // Staleness guard: a fresh re-arm may have already superseded this
        // notification by the time it's dispatched (async queue hop) - subscription_id
        // pins it to the EXACT dead id the engine told us about, mirroring
        // evaluate_key's own shared_ptr-identity re-check for the ordinary Fired case.
        if (kit == keys_.end() || kit->second->subscription != subscription_id)
            return;
        // enterprise-readiness Gate 6: the mechanism's failure reason (SparkEvent::detail)
        // was being silently dropped entirely - unretrievable by engineering or a customer
        // reading their own journal, since the "errored" audit entry itself has no free-text
        // field for it. Logged here rather than added to the wire payload: extending the
        // Lifecycle wire event's schema is a protocol change, deliberately deferred (folded
        // into this doc's pre-PR-5 list) rather than made under a hardening round's time
        // pressure. This log line is the interim "why", for local debugging only.
        const std::vector<std::string> rule_ids = index_->rules_for(key); // copy: mutates below
        try {
            spdlog::warn("Guardian spark: key '{}' subscription {} lost ({}) - detaching {} "
                         "rule(s) as errored",
                         key, subscription_id, detail.empty() ? "no reason given" : detail,
                         rule_ids.size());
        } catch (...) {
        }
        for (const auto& rid : rule_ids)
            detach_rule_locked(rid, "errored"); // DisarmWork discarded: the guard above
                                                 // already proves this id is dead, so any
                                                 // resulting disarm() is a guaranteed,
                                                 // already-idempotent no-op
        outbox_waker = outbox_enqueue_waker_;
    }
    if (outbox_waker)
        outbox_waker();
}

void GuardianSparkRuntime::on_subscription_faulted(const std::string& key,
                                                    std::uint64_t subscription_id, bool faulted,
                                                    const std::string& detail) {
    // #2818: the watch reported itself unhealthy (or recovered) WITHOUT the key being
    // torn down - Armed still exists at the engine level, so unlike Lost this does NOT
    // touch keys_/rules_/index_. Just surfaces a Health-domain entry per active rule.
    std::vector<OutboxEntry> entries;
    std::function<void()> outbox_waker;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        if (stopping_)
            return;
        const auto kit = keys_.find(key);
        if (kit == keys_.end() || kit->second->subscription != subscription_id)
            return; // stale - same guard as on_subscription_lost
        const auto now_wall = std::chrono::system_clock::now().time_since_epoch();
        const std::int64_t ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now_wall).count();
        const std::int64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(now_wall).count();
        const std::string agent_id = agent_id_fn_ ? agent_id_fn_() : std::string{};
        for (const auto& rid : index_->rules_for(key)) {
            const auto rit = rules_.find(rid);
            if (rit == rules_.end() || !rit->second->active)
                continue;
            const auto& rg = rit->second;
            entries.push_back(OutboxEntry::health(
                rid, rg->generation, make_event_id(rid, ms, agent_id), ns,
                /*healthy=*/!faulted, faulted ? detail : std::string{},
                guard_type_for(rg->assertion.kind), rg->assertion.rule_name));
        }
        if (!entries.empty()) {
            std::lock_guard<std::mutex> ob{outbox_mu_};
            outbox_.enqueue_all(std::move(entries)); // best-effort, same posture as
                                                      // evaluate_key's own enqueue - a
                                                      // rejected (full) enqueue is dropped
            outbox_waker = outbox_enqueue_waker_;
        }
    }
    if (outbox_waker)
        outbox_waker();
}

void GuardianSparkRuntime::revalidate_subscriptions() {
    // Snapshot under registry_mu_, query health with it released (subscription_health()
    // is cheap/lock-only on a DIFFERENT mutex, but this keeps the same
    // snapshot-then-act discipline the rest of this file uses rather than nesting
    // locks). on_subscription_lost re-validates staleness itself before acting, so a
    // fresh re-arm landing between this snapshot and that call is still handled
    // correctly - no duplicated detach logic here.
    std::vector<std::pair<std::string, std::uint64_t>> snapshot;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        if (stopping_)
            return;
        snapshot.reserve(keys_.size());
        for (const auto& [key, pk] : keys_)
            snapshot.emplace_back(key, pk->subscription);
    }
    for (const auto& [key, subscription_id] : snapshot) {
        if (backend_->subscription_health(subscription_id) == SubscriptionHealth::Dead)
            on_subscription_lost(key, subscription_id, "detected dead by the poll backstop "
                                                        "(revalidate_subscriptions) - no push "
                                                        "notification ever confirmed, or one "
                                                        "was silently dropped");
    }
}

void GuardianSparkRuntime::on_event(const SparkEvent& ev) {
    switch (ev.kind) {
    case SparkEventKind::Fired:
        // The event is an invalidation HINT; evaluate_key re-reads live state.
        evaluate_key(ev.key, EvalReason::Event);
        return;
    case SparkEventKind::Lost:
        on_subscription_lost(ev.key, ev.subscription_id, ev.detail);
        return;
    case SparkEventKind::Faulted:
        on_subscription_faulted(ev.key, ev.subscription_id, /*faulted=*/true, ev.detail);
        return;
    case SparkEventKind::Recovered:
        on_subscription_faulted(ev.key, ev.subscription_id, /*faulted=*/false, ev.detail);
        return;
    }
}

void GuardianSparkRuntime::evaluate_key(const std::string& key, EvalReason reason) {
    std::shared_ptr<PerKey> pk;
    SparkSpec spec;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        if (stopping_)
            return;
        const auto kit = keys_.find(key);
        if (kit == keys_.end())
            return;
        pk = kit->second;
        spec = pk->spec;
    }

    // Serialise the whole pass (plan + read + fan-out + commit) for THIS key, so
    // read order == commit order and the freshest read commits last (no backward
    // compliance). Per-key, so sibling keys run concurrently.
    std::lock_guard<std::mutex> eval_lk{pk->eval_mu};

    const bool is_file = spec.type == SparkType::File;
    const bool is_reg = spec.type == SparkType::Registry;
    const bool is_svc = spec.type == SparkType::Service;

    // Snapshot the active generations + derive the read plan BEFORE any I/O (under
    // registry_mu_). We evaluate ONLY these generations: a rule that joins during the
    // read is not in the plan, so its value_name / hash cap was not read - evaluating
    // it against a snapshot that lacks its data would be wrong. It stays dirty in
    // pending_initial and the priority lane re-runs the key for it.
    std::vector<std::shared_ptr<RuleGeneration>> planned;
    FileReadPlan fplan;
    RegistryReadPlan rplan;
    std::string agent_id;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        if (stopping_)
            return;
        const auto kit = keys_.find(key);
        if (kit == keys_.end() || kit->second.get() != pk.get())
            return;
        std::set<std::string> reg_values; // distinct value_names (the plan's contract)
        for (const std::string& rid : index_->rules_for(key)) {
            const auto rrit = rules_.find(rid);
            if (rrit == rules_.end() || !rrit->second->active)
                continue;
            const auto& rg = rrit->second;
            planned.push_back(rg);
            if (is_file && rg->assertion.kind == AssertionKind::FileHashEquals)
                fplan.hash_cap = std::max(fplan.hash_cap, rg->assertion.max_bytes);
            if (is_reg)
                reg_values.insert(rg->assertion.value_name);
        }
        rplan.value_names.assign(reg_values.begin(), reg_values.end());
        agent_id = agent_id_fn_ ? agent_id_fn_() : std::string{}; // snapshot here, not post-read
    }
    if (planned.empty())
        return;

    // Snapshot the debounce clock BEFORE the blocking read too, so neither the clock
    // nor the agent-id provider is invoked on the detached-post-read path (a provider
    // that borrowed agent state would UAF if shutdown destroyed it during the read).
    const auto now = clock_();

    // The one blocking I/O, OUTSIDE registry_mu_, driven by the plan. Every event is
    // a hint: re-read live state rather than trust a queued payload.
    ReadResult<FileSnapshot> file_read;
    RegistryRead reg_read;
    ReadResult<ServiceRunState> svc_read;
    if (is_file)
        file_read = reader_->read_file(std::get<FileSparkParams>(spec.params), fplan);
    else if (is_reg)
        reg_read = reader_->read_registry(std::get<RegistrySparkParams>(spec.params), rplan);
    else if (is_svc)
        svc_read = reader_->read_service(std::get<ServiceSparkParams>(spec.params));
    else
        return; // non-event-driven type is never armed here

    // Commit section: IO-free, under registry_mu_ so a concurrent detach cannot
    // interleave between the eval and the enqueue (which would re-add a purged
    // entry). Commit ONLY the planned generations, and re-check each is STILL the
    // active current generation for its rule - one withdrawn or re-attached during
    // the read must drop here (its new generation gets its own pass).
    bool enqueued_any = false;
    std::function<void()> outbox_waker;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        if (stopping_)
            return;
        const auto kit = keys_.find(key);
        if (kit == keys_.end() || kit->second.get() != pk.get())
            return; // key withdrawn or re-armed under a new PerKey during the read

        for (const std::shared_ptr<RuleGeneration>& rg : planned) {
            const auto rrit = rules_.find(rg->assertion.rule_id);
            if (rrit == rules_.end() || rrit->second.get() != rg.get() || !rg->active)
                continue; // withdrawn or superseded during the read

            // copy-eval-enqueue-commit: eval mutates a COPY; commit only if what we
            // needed to buffer was accepted, else leave the eval pending for retry.
            RuleEvalState scratch = rg->eval;
            const EvalOutcome out =
                eval_rule(spec, rg->assertion, scratch, now, rg->emit_compliant_edge,
                          is_file ? &file_read : nullptr, is_reg ? &reg_read : nullptr,
                          is_svc ? &svc_read : nullptr);

            // M1 item (a): a committed repeat Unknown (edge already fired earlier in this
            // errored episode) is due a REFRESH once errored_refresh_ms has elapsed since
            // the last emission (edge or refresh) - a lost/coalesced edge must not leave
            // the server's errored view stale forever now that the edge is the sole
            // primary emission. `scratch.last_unhealthy_emit` reflects the LAST COMMITTED
            // emission (untouched by eval_rule); errored_refresh_ms == 0 disables refresh
            // entirely (edge-only, pre-F5 behaviour).
            const bool refresh_due = out.status == EvalStatus::Unhealthy && !out.unhealthy_edge &&
                                     cfg_.errored_refresh_ms > 0 &&
                                     (now - scratch.last_unhealthy_emit) >=
                                         std::chrono::milliseconds(cfg_.errored_refresh_ms);

            std::vector<OutboxEntry> entries = build_entries(*rg, out, agent_id, refresh_due);
            const bool had_entries = !entries.empty(); // captured BEFORE the move below
            bool accepted = true;
            if (had_entries) {
                std::lock_guard<std::mutex> ob{outbox_mu_};
                accepted = outbox_.enqueue_all(std::move(entries)); // both-or-neither
            }
            if (!accepted)
                continue; // outbox full: eval stays pending (nothing committed), convergence retries
            if (had_entries)
                enqueued_any = true;

            // Stamp the emission clock in the SAME scratch that is about to commit, so a
            // rejected enqueue (continue above) leaves it untouched and the refresh is
            // retried, not lost, on the next sweep - the same transactional guarantee
            // copy-eval-enqueue-commit already gives every other field here.
            if (out.status == EvalStatus::Unhealthy && (out.unhealthy_edge || refresh_due))
                scratch.last_unhealthy_emit = now;

            rg->eval = std::move(scratch); // COMMIT
            // M1: every committed repeat Unknown is counted on exactly one of these two
            // channels - REFRESHED (put on the wire) or SUPPRESSED (not) - so the
            // edge/refresh split is observable, never silent (Option-A: every loss/
            // suppression/resource-shedding channel is a counted metric).
            if (out.status == EvalStatus::Unhealthy && !out.unhealthy_edge) {
                if (refresh_due)
                    unhealthy_refreshed_.fetch_add(1, std::memory_order_relaxed);
                else
                    unhealthy_suppressed_.fetch_add(1, std::memory_order_relaxed);
            }
            // A Known verdict (Emit or steady-Silent) satisfies the initial eval; an
            // Unknown does not (it still owes a real verdict).
            if (out.status != EvalStatus::Unhealthy) {
                pk->pending_initial.erase(rg->assertion.rule_id);
            } else if (reason == EvalReason::Convergence) {
                // M1 item (b): only a COMMITTED Convergence-reason Unknown advances the
                // demotion clock - an Event-reason eval (an OS-level change notification,
                // not a poll) must not fast-demote a rule that is merely noisy, and a
                // rejected-enqueue pass (continue above) never reaches here at all.
                const auto pit = pk->pending_initial.find(rg->assertion.rule_id);
                if (pit != pk->pending_initial.end() && !pit->second.demoted) {
                    ++pit->second.unknown_sweeps;
                    const bool sweep_due = cfg_.pending_demote_sweeps > 0 &&
                                          pit->second.unknown_sweeps >= cfg_.pending_demote_sweeps;
                    const bool time_due = cfg_.pending_demote_ms > 0 &&
                                          (now - pit->second.first_seen) >=
                                              std::chrono::milliseconds(cfg_.pending_demote_ms);
                    if (sweep_due || time_due) {
                        pit->second.demoted = true;
                        priority_demoted_.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            }
        }
        if (enqueued_any)
            outbox_waker = outbox_enqueue_waker_; // copy; call after releasing registry_mu_
    }
    // Fire once for the whole pass (not per-rule/per-key concurrently - this
    // local is per-call, no cross-thread sharing) - the drain worker (rung 7.5)
    // drains everything pending regardless of how many entries accumulated.
    if (outbox_waker)
        outbox_waker();
}

EvalOutcome GuardianSparkRuntime::eval_rule(const SparkSpec& /*spec*/, const RuleAssertion& a,
                                            RuleEvalState& state,
                                            std::chrono::steady_clock::time_point now, bool edge,
                                            const ReadResult<FileSnapshot>* file,
                                            const RegistryRead* reg,
                                            const ReadResult<ServiceRunState>* svc) {
    if (file)
        return eval_file(a, *file, state, now, edge);
    if (reg) {
        // Pick THIS rule's value from the per-value_name map (the plan requested it).
        const auto it = reg->values.find(a.value_name);
        if (it == reg->values.end())
            return eval_registry(a, read_unknown<RegistrySnapshot>("value not in read plan"), state,
                                 reg->latency_us, now, edge);
        return eval_registry(a, it->second, state, reg->latency_us, now, edge);
    }
    if (svc)
        return eval_service(a, *svc, state, now, edge);
    return EvalOutcome{}; // Silent (unreachable for an armed event-driven key)
}

std::vector<OutboxEntry> GuardianSparkRuntime::build_entries(const RuleGeneration& gen,
                                                            const EvalOutcome& out,
                                                            const std::string& agent_id,
                                                            bool refresh) {
    // Wall clock for the wire timestamp + id (the steady clock used for debounce has
    // an arbitrary epoch and is not a valid observation time; system_clock::now
    // captures nothing, so it is detach-safe). registry_mu_ is held. agent_id was
    // snapshotted at pass start.
    const auto wall = std::chrono::system_clock::now().time_since_epoch();
    const std::int64_t ns = std::chrono::duration_cast<std::chrono::nanoseconds>(wall).count();
    const std::int64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(wall).count();
    const std::string& rid = gen.assertion.rule_id;
    // Health entries carry guard_type/rule_name explicitly (the compliance path carries
    // both inside out.drift). Derived from the assertion, not a spec (#2237 item 4).
    const char* gtype = guard_type_for(gen.assertion.kind);
    const std::string& rname = gen.assertion.rule_name;
    std::vector<OutboxEntry> v;
    if (out.recovered) // Unknown -> Known: clear the health stream's errored state first
        v.push_back(OutboxEntry::health(rid, gen.generation, make_event_id(rid, ms, agent_id), ns,
                                        /*healthy=*/true, {}, gtype, rname));
    if (out.status == EvalStatus::Emit)
        v.push_back(OutboxEntry::compliance(rid, gen.generation, make_event_id(rid, ms, agent_id),
                                            ns, out.drift));
    else if (out.status == EvalStatus::Unhealthy && (out.unhealthy_edge || refresh))
        // EDGE + REFRESH (M1): the first Unknown of an errored episode mints one
        // guard.unhealthy; the caller (evaluate_key) additionally sets `refresh` at
        // errored_refresh_ms cadence so a lost/coalesced edge cannot leave the server's
        // errored view stale forever - the edge is the primary emission, refresh is the
        // backstop. A repeat Unknown that is NEITHER produces NO entry here (the caller
        // counts it via unhealthy_suppressed_ instead of unhealthy_refreshed_).
        // out.health_detail is this eval's CURRENT read-error string (eval_rule refreshes
        // it on every Unknown, not just the edge), so a refresh - unlike a merely-
        // suppressed tick - re-surfaces a changed reason (EACCES -> ENODEV) on the wire at
        // errored_refresh_ms cadence, retiring the prior edge-only staleness trade.
        v.push_back(OutboxEntry::health(rid, gen.generation, make_event_id(rid, ms, agent_id), ns,
                                        /*healthy=*/false, out.health_detail, gtype, rname));
    // Silent, a suppressed repeat-Unknown, + !recovered -> empty (nothing to publish).
    return v;
}

std::string GuardianSparkRuntime::make_event_id(const std::string& rule_id, std::int64_t wall_ms,
                                                const std::string& agent_id) {
    // registry_mu_ is held by the caller; event_seq_ is guarded by it. boot_nonce_
    // makes the id restart-unique (wall_ms + seq alone are not); agent_id was
    // snapshotted at pass start (not called on the detached-post-read path).
    return agent_id + "-" + boot_nonce_ + "-" + rule_id + "-" + std::to_string(wall_ms) + "-" +
           std::to_string(++event_seq_);
}

bool GuardianSparkRuntime::enqueue_lifecycle_locked(const std::string& rule_id,
                                                    std::uint64_t generation,
                                                    const std::string& kind,
                                                    const std::string& guard_type,
                                                    const std::string& rule_name) {
    // Called from attach_rule/detach_rule_locked - never on the detached-post-
    // read path - so calling agent_id_fn_() directly (not pre-snapshotted) is
    // safe here, unlike evaluate_key's read path.
    const auto wall = std::chrono::system_clock::now().time_since_epoch(); // noexcept arithmetic
    const std::int64_t ns = std::chrono::duration_cast<std::chrono::nanoseconds>(wall).count();
    const std::int64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(wall).count();

    if (kind == "armed") {
        // ARM: every throwing op here PROPAGATES, so attach_rule's GuardianRollback undoes the
        // arm and nothing is staged (no phantom). The event_id is minted ONCE and shared by the
        // window entry + the durable record (rev-4.1 #4). The window enqueue is the LAST throwing
        // op before the caller's noexcept commit; the journal push after it is noexcept.
        const std::string agent_id = agent_id_fn_ ? agent_id_fn_() : std::string{};
        const std::string event_id = make_event_id(rule_id, ms, agent_id);
        auto entry =
            OutboxEntry::lifecycle(rule_id, generation, event_id, ns, kind, guard_type, rule_name);
        std::shared_ptr<JournalRecord> record =
            build_journal_record(rule_id, generation, event_id, ns, kind, guard_type, rule_name);
        std::lock_guard<std::mutex> ob{outbox_mu_};
        const bool accepted = lifecycle_log_.enqueue(std::move(entry)); // throwing, rolls back arm
        // #2233 item 7: a capacity-rejected lifecycle entry previously counted
        // (lifecycle_backpressure_drops(), fleet-visible via the journal heartbeat) but
        // was never itself logged - "loudly observable" per this log's own doc comment
        // meant an aggregate a human had to go check, not a line an operator would see
        // at the moment it happened. Log-once-then-count-only (n==1), mirroring
        // drain_log_unlocked's identical shape for send-side losses just below - the
        // counter, not a latch, still tracks every occurrence.
        // Firewalled: this whole line is documented (a few lines above) as the LAST
        // throwing op before the caller's noexcept commit, but spdlog::warn's own fmt
        // formatting can allocate and throw. A throw here still rolls back cleanly
        // (stage_pending_locked hasn't run yet, so attach_rule's rollback/
        // index_add_rollback undo the arm with no phantom staged record) - firewalled
        // anyway so a logging-only failure can never surprise a future reader of the
        // "last throwing op" comment above.
        if (!accepted && lifecycle_log_.backpressure_drops() == 1) {
            lifecycle_backpressure_log_fires_.fetch_add(1, std::memory_order_relaxed);
            try {
                spdlog::warn("Guardian spark: lifecycle audit log at capacity - '{}' entry for "
                            "rule '{}' dropped (further occurrences counted, not logged)",
                            kind, rule_id);
            } catch (...) {
            }
        }
        stage_pending_locked(std::move(record));                        // noexcept
        return accepted;
    }

    // DISARM: the teardown already happened, so NO throw may propagate (it would break the
    // caller mid-teardown). Firewall the WHOLE construction: agent_id, the event_id mint, the
    // OutboxEntry, and the record all allocate, and a bad_alloc in ANY of them post-teardown is
    // the reachable journal_stage_failures loss channel (rev-4.1 #5 / review B3). Then stage the
    // durable record FIRST so a best-effort window-enqueue throw cannot lose a real disarm.
    OutboxEntry entry;
    std::shared_ptr<JournalRecord> record;
    try {
        const std::string agent_id = agent_id_fn_ ? agent_id_fn_() : std::string{};
        const std::string event_id = make_event_id(rule_id, ms, agent_id);
        entry =
            OutboxEntry::lifecycle(rule_id, generation, event_id, ns, kind, guard_type, rule_name);
        record = build_journal_record(rule_id, generation, event_id, ns, kind, guard_type, rule_name);
    } catch (...) {
        journal_stage_failures_.fetch_add(1, std::memory_order_relaxed);
        return false; // nothing built, nothing to stage or enqueue
    }
    std::lock_guard<std::mutex> ob{outbox_mu_};
    stage_pending_locked(std::move(record)); // durable disarm staged first (noexcept)
    try {
        const bool accepted = lifecycle_log_.enqueue(std::move(entry)); // best-effort live window
        // #2233 item 7 (see the ARM-side twin above for the full rationale). Distinct
        // from THIS try's own catch just below: that one covers enqueue() itself
        // throwing (not a capacity rejection, which enqueue() reports via its return
        // value) - a genuinely different failure, so it must not double-log here. The
        // separate construction try/catch above (agent_id/event_id/OutboxEntry/record
        // build) already returned early on its own throw and never reaches this line.
        if (!accepted && lifecycle_log_.backpressure_drops() == 1) {
            lifecycle_backpressure_log_fires_.fetch_add(1, std::memory_order_relaxed);
            // Firewalled (see ARM-side twin): a throw here must not fall into this
            // try's own catch, which returns false and would misreport `accepted`
            // (already true) as an enqueue rejection.
            try {
                spdlog::warn("Guardian spark: lifecycle audit log at capacity - '{}' entry for "
                            "rule '{}' dropped (further occurrences counted, not logged)",
                            kind, rule_id);
            } catch (...) {
            }
        }
        return accepted;
    } catch (...) {
        return false; // window enqueue failed post-teardown; the durable record already stands
    }
}

std::shared_ptr<JournalRecord> GuardianSparkRuntime::build_journal_record(
    const std::string& rule_id, std::uint64_t generation, const std::string& event_id,
    std::int64_t enqueued_ns, const std::string& kind, const std::string& guard_type,
    const std::string& rule_name) {
    auto jr = std::make_shared<JournalRecord>(
        JournalRecord{.rule_id = rule_id, .generation = generation, .event_id = event_id,
                      .enqueued_ns = enqueued_ns, .kind = kind, .guard_type = guard_type,
                      .rule_name = rule_name});
    switch (validate_record(*jr)) {
    case JournalReject::None:
        return jr;
    case JournalReject::SkewedClock:
        journal_clock_rejected_.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    default: // EmbeddedNul / Oversized / InvalidUtf8 - a field the journal cannot carry byte-exact
        journal_field_rejected_.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }
}

void GuardianSparkRuntime::stage_pending_locked(std::shared_ptr<JournalRecord> record) noexcept {
    // #2303 K6. The noexcept below is only real because the ctor's reserve() means push_back
    // never reallocates. That is an invariant of a DIFFERENT function, so assert it here where
    // it is relied on - if a future edit drops or shrinks the reserve, a debug build trips
    // immediately instead of a release build calling std::terminate on an OOM realloc.
    assert(pending_journal_.capacity() >= kMaxPendingJournalRecords &&
           "pending_journal_ reserve is what makes stage_pending_locked's noexcept real");
    if (!record)
        return; // rejected at build - sent live, never journaled
    if (pending_journal_.size() >= kMaxPendingJournalRecords) {
        pending_journal_.erase(pending_journal_.begin()); // drop oldest; O(n) only under sustained failure
        journal_stage_dropped_.fetch_add(1, std::memory_order_relaxed);
    }
    // Reserve is fixed at construction, so this never reallocates and shared_ptr move is
    // noexcept - the push cannot throw (the enclosing noexcept documents + enforces it).
    pending_journal_.push_back(std::move(record));
}

GuardianSparkRuntime::PendingSnapshot GuardianSparkRuntime::snapshot_pending() const {
    std::lock_guard<std::mutex> ob{outbox_mu_};
    // The drop counter is read HERE, under the same lock as the snapshot. Reading it from the
    // caller just before this call left a gap in which a drop could land: it would then be
    // attributed to "after the snapshot", the erase would come up short, and a durably-written
    // record would stay staged to be persisted again under a second key. That is the safe
    // direction (a duplicate, which the server de-dupes) rather than loss - but it is the same
    // read-outside-the-lock mistake this whole mechanism exists to fix (#2345 focused review).
    return PendingSnapshot{{pending_journal_.begin(), pending_journal_.end()},
                          journal_stage_dropped_.load(std::memory_order_relaxed)};
}

void GuardianSparkRuntime::erase_persisted_prefix(std::size_t n, std::uint64_t drops_at_snapshot) {
    std::lock_guard<std::mutex> ob{outbox_mu_};
    // The prefix must be identified by IDENTITY, not by position (#2345 Gate 8b). The caller
    // snapshots under this lock, RELEASES it to do KvStore I/O, then comes back to erase what
    // it wrote. In that window stage_pending_locked can hit kMaxPendingJournalRecords and
    // drop from the FRONT - so slot 0 is no longer the record slot 0 was when the snapshot was
    // taken, and erasing n positions deletes n records of which the last few were never
    // written. That is silent, uncounted destruction of audit records, and it is worst exactly
    // when it matters most: staging only fills when persist is failing or the link is dead.
    //
    // Front-drops remove a PREFIX of the same ordered sequence, so the count of drops since the
    // snapshot is all that is needed to realign: those records are already gone, and they were
    // the oldest - i.e. the front of what was just persisted.
    const std::uint64_t dropped_since =
        journal_stage_dropped_.load(std::memory_order_relaxed) - drops_at_snapshot;
    if (dropped_since >= n)
        return; // every record we persisted has already been dropped from staging
    n -= static_cast<std::size_t>(dropped_since);
    n = std::min(n, pending_journal_.size());
    pending_journal_.erase(pending_journal_.begin(),
                           pending_journal_.begin() + static_cast<std::ptrdiff_t>(n));
}

std::size_t GuardianSparkRuntime::pending_journal_depth() const {
    std::lock_guard<std::mutex> ob{outbox_mu_};
    return pending_journal_.size();
}

GuardianSparkRuntime::PageOutcome
GuardianSparkRuntime::try_page_batch(std::vector<OutboxEntry> entries) {
    PageOutcome out;
    if (entries.empty())
        return out;
    std::lock_guard<std::mutex> ob{outbox_mu_};
    // Build the window membership set ONCE (O(window)) rather than re-scanning the window per
    // record (O(records x window)); the latter runs on the heartbeat/run-loop thread and can
    // starve heartbeats under a large backlog (review UP-12 / perf P-2).
    // Scoped: `present` holds string_views borrowed from the window's own entries. They are
    // valid here (the log's nodes are stable and nothing is erased under this lock), but the
    // enqueue loop below moves entries, so keeping a borrowed view alive across it is one edit
    // away from a use-after-free for no benefit (#2345 Gate 8 cpp-safety).
    std::unordered_set<std::string> want;
    {
    const auto present = lifecycle_log_.event_id_set();

    // Required headroom is the count of NET-NEW event_ids, not the raw batch size (#2345
    // Gate 5 CH-7). Charging the raw size is not merely pessimistic, it can wedge replay:
    // a 256-entry batch with 255 entries already in the window needs ONE slot, but reporting
    // 256 makes the worker's refill re-arm wait for 256 free slots - room the window may
    // never have while those same 255 entries are what is occupying it. The batch then never
    // pages and its one unsent record is eventually pruned: a permanent, silent audit gap
    // produced by the accounting rather than by any real shortage.
    //
    // Deduplicated, so a batch that repeats an event_id (a torn or hand-edited journal row)
    // cannot inflate the requirement past what enqueue would actually consume, nor enqueue
    // the same record twice against a membership set built before the loop.
    want.reserve(entries.size());
    for (const auto& e : entries)
        if (!present.count(e.event_id))
            want.insert(e.event_id);
    }
    if (want.empty())
        return out; // every entry is already windowed: nothing to do, and nothing is blocked

    // Headroom gate (design §5): page the batch only if its net-new records fit whole; else
    // leave it for a later pass once the window drains (never a partial page that splits a
    // batch).
    //
    // Reporting WHY nothing was added has to happen here, under the lock. A caller's own
    // pre-check can be stale by the time it gets here - a concurrent arm can consume the room
    // in between - and if that case is misread as "already a member" the caller never learns a
    // backlog is waiting and replay stalls for a whole cadence interval (#2345 Gate 3).
    if (lifecycle_log_.headroom() < want.size()) {
        out.blocked_for_headroom = true;
        out.required = want.size();
        return out;
    }
    for (auto& e : entries) {
        if (want.erase(e.event_id) == 0) // already windowed, or an intra-batch duplicate
            continue;
        if (lifecycle_log_.enqueue(std::move(e)))
            ++out.added;
    }
    return out;
}

void GuardianSparkRuntime::backfill_batch_provenance(const std::string& batch_key,
                                                     const std::vector<std::string>& event_ids,
                                                     const std::string& last_event_id) {
    if (event_ids.empty())
        return;
    const std::unordered_set<std::string> ids(event_ids.begin(), event_ids.end());
    std::lock_guard<std::mutex> ob{outbox_mu_};
    lifecycle_log_.stamp_provenance(batch_key, ids, last_event_id);
}

namespace {
// Drain one log with outbox_mu_ RELEASED across each send: copy the head under the
// lock, unlock, send (the gRPC Write - previously run UNDER outbox_mu_, so a stalled
// write blocked every evaluate_key emit / arm-disarm enqueue / heartbeat behind it -
// item 4), then re-lock and pop the head ONLY if it is still the entry we sent. A
// coalesce/drop during the unlocked window replaces or removes it; pop_front_if(event_id)
// then no-ops and the current head is handled on the next pass.
struct DrainPassLimits {
    std::size_t budget{0};                            ///< decremented per successful send
    std::chrono::steady_clock::time_point deadline{}; ///< zero-valued when unbounded
    bool has_deadline{false};
    const std::function<bool()>* should_stop{nullptr};
    /// Sends allowed to proceed even past `deadline`. The wall slice alone guarantees only
    /// that compliance gets to START, and only if the in-flight lifecycle send returns in
    /// time - so a single send slower than the whole pass budget left compliance's restored
    /// deadline permanently in the past and it shipped NOTHING, every pass, forever
    /// (#2345 Gate 4 UP-3). This converts that into a hard floor. It does NOT bypass
    /// should_stop: shutdown still wins immediately.
    std::size_t guaranteed_attempts{0};
};

template <typename Log>
std::size_t drain_log_unlocked(Log& log, std::mutex& mu,
                               const std::function<SendResult(const OutboxEntry&)>& send,
                               std::atomic<std::uint64_t>& send_exceptions,
                               DrainPassLimits& lim, bool& truncated) {
    std::size_t sent = 0;
    while (true) {
        OutboxEntry entry;
        {
            std::lock_guard<std::mutex> ob{mu};
            std::optional<OutboxEntry> front = log.front_copy();
            if (!front)
                return sent; // drained - NOT truncated, whatever the budget says
            entry = std::move(*front);
        }
        // Limits are evaluated only once an entry is known to exist, and always BEFORE the
        // send: the point is to avoid STARTING work, since an in-flight send cannot be
        // interrupted and the caller may be holding a lock across a thread join
        // (#2298 Sol review). Checking them earlier would report a drained log as truncated.
        // A guaranteed attempt overrides the DEADLINE only - never the budget, and never the
        // stop predicate.
        const bool guaranteed = lim.guaranteed_attempts > 0;
        if (lim.should_stop && *lim.should_stop && (*lim.should_stop)()) {
            truncated = true;
            return sent;
        }
        if (lim.budget == 0 ||
            (!guaranteed && lim.has_deadline &&
             std::chrono::steady_clock::now() >= lim.deadline)) {
            truncated = true;
            return sent;
        }
        if (guaranteed)
            --lim.guaranteed_attempts;
        SendResult r = SendResult::Retain;
        try {
            r = send(entry); // outbox_mu_ RELEASED here
        } catch (...) {
            // A send throw is treated as stream-down (keep the head, stop), BUT unlike a
            // Retain it can be entry-specific (an un-serializable entry jamming the head
            // forever). Count it + log the first so a permanent jam is visible, not
            // silent (Fable). The head is retained either way.
            const auto n = send_exceptions.fetch_add(1, std::memory_order_relaxed) + 1;
            if (n == 1) {
                try {
                    spdlog::error("Guardian drain: send threw (head retained; may be a "
                                  "permanently-unsendable entry). Further occurrences counted only.");
                } catch (...) {
                }
            }
            return sent;
        }
        if (r != SendResult::Sent)
            return sent; // Retain: keep the head, stop
        {
            std::lock_guard<std::mutex> ob{mu};
            log.pop_front_if(entry.event_id); // remove IFF unchanged during the unlocked send
        }
        ++sent;
        --lim.budget;
    }
}
} // namespace

std::size_t GuardianSparkRuntime::lifecycle_headroom() const {
    std::lock_guard<std::mutex> ob{outbox_mu_};
    return lifecycle_log_.headroom();
}

std::unordered_set<std::string> GuardianSparkRuntime::lifecycle_event_ids() const {
    std::lock_guard<std::mutex> ob{outbox_mu_};
    const auto present = lifecycle_log_.event_id_set(); // borrowed views, valid under the lock
    // Materialise element-by-element rather than via the iterator-range ctor (#2484).
    // The range ctor routes through libstdc++'s `_Hashtable::_S_forward_key`, which on
    // libstdc++ 13 forwards the source key type instead of converting it — so building an
    // unordered_set<string> from string_view iterators is a hard compile error there
    // (hashtable.h:890, "could not convert ... basic_string_view<char> ... to
    // basic_string<char>"). GCC 14+ accepts it, which is why only the ubuntu-24.04 canary
    // leg — the sole leg on the distro's system GCC 13 — caught it. CLAUDE.md declares
    // GCC 13+ as a supported compiler, so this must build there. Same explicit-emplace
    // idiom the sibling `want` set above already uses.
    std::unordered_set<std::string> out;
    out.reserve(present.size());
    for (const std::string_view sv : present)
        out.emplace(sv);
    return out;
}

std::size_t GuardianSparkRuntime::drain(const std::function<SendResult(const OutboxEntry&)>& send) {
    // Drain lifecycle (audit) BEFORE compliance/health so a rule's "armed" precedes its
    // first drift on the wire in the common case (stream up, both drain fully). This is
    // BEST-EFFORT ordering, NOT a hard gate: an earlier version gated compliance on the
    // lifecycle log being empty, but that let a lifecycle head that could not send (a
    // persistent send throw) block ALL compliance/health for the agent indefinitely - a
    // detection blackout, far worse than the narrow ordering blip it prevented (Gate 4
    // UP-3). Both logs now drain every pass; failure isolation beats strict ordering.
    // Residual (documented NICE): a reconnect flap between the two phases, or a concurrent
    // arm during the compliance phase, can still send a drift a pass ahead of its "armed".
    // THIS residual is sequential/next-pass in shape (phase N+1 relative to phase N) - a
    // DIFFERENT, same-pass residual exists too, see drain_bounded()'s own note below;
    // #3972 tracks the watertight fix (merge-drain by global sequence) for both.
    DrainLimits unbounded;
    return drain_bounded(send, unbounded).sent;
}

GuardianSparkRuntime::DrainOutcome
GuardianSparkRuntime::drain_bounded(const std::function<SendResult(const OutboxEntry&)>& send,
                                    const DrainLimits& limits) {
    // Production caller: GuardianOutboxDrainWorker::drain_bounded() (#3847/#3961), which
    // routes `send` through TWO INDEPENDENTLY SCHEDULED GuardianOutboxSendExecutor
    // instances (one per lane), each on its own bounded per-attempt wait and its own
    // detached worker thread. This makes a SAME-PASS cross-lane wire reordering reachable
    // that the prior single shared executor structurally prevented: a compliance/health
    // event can land on the wire between two lifecycle entries within this one call, if
    // the lifecycle lane's send is still detached past its own bounded wait while the
    // compliance/health lane's completes. Distinct from drain()'s own disclosed residual
    // above, which is sequential/next-pass, not same-pass - #3972 tracks the fix for both.
    std::lock_guard<std::mutex> dg{drain_mu_};
    DrainOutcome out;

    const bool unbounded = limits.max_entries == 0;
    const std::size_t total =
        unbounded ? std::numeric_limits<std::size_t>::max() : limits.max_entries;

    // Reserve a share for compliance/health BEFORE lifecycle runs. Draining lifecycle first
    // out of one shared budget means a busy lifecycle log can consume the entire pass and
    // compliance never runs at all - which is the detection blackout the comment above says
    // was removed for exactly that reason (Gate 4 UP-3), reintroduced in bounded form.
    // Unused lifecycle allowance rolls over below, so this costs nothing when lifecycle is
    // quiet, and the overall cap is still `total`.
    // Normalise the reserve ratio ONCE, defensively: den == 0 (disabled), num > den
    // (nonsensical), and the wall-only case where max_entries == 0 all have to land somewhere
    // explicit rather than dividing by zero or over-reserving (Sol review).
    // A ratio denominator beyond this is nonsense and only invites overflow in the wall
    // arithmetic below; treat it as "no reserve" rather than trusting the cast.
    constexpr std::size_t kMaxReserveRatio = 1'000'000;
    const std::size_t reserve_den =
        (limits.compliance_reserve_den > kMaxReserveRatio) ? 0 : limits.compliance_reserve_den;
    const std::size_t reserve_num =
        (reserve_den == 0) ? 0 : std::min(limits.compliance_reserve_num, reserve_den);

    std::size_t reserve = 0;
    if (!unbounded && reserve_den > 0) {
        reserve = total / reserve_den * reserve_num;
        if (reserve > total)
            reserve = total;
        // Integer division floors to 0 whenever total < den, which silently removes the
        // reserve and reopens the starvation this exists to prevent - with no diagnostic
        // (#2298 Gate 4 UP-8). Guarantee at least one slot whenever there is more than one
        // to give; at total == 1 there is nothing to split and lifecycle keeps first claim.
        if (reserve == 0 && total > 1 && reserve_num > 0)
            reserve = 1;
    }

    DrainPassLimits lim;
    lim.budget = total - reserve;
    lim.should_stop = limits.should_stop ? &limits.should_stop : nullptr;

    // Slice the WALL the same way the count is sliced. A single shared deadline made the
    // count reserve dead on arrival under time pressure: drain_log_unlocked checks the
    // deadline BEFORE the budget, so once lifecycle consumed the wall, compliance returned on
    // entry without ever spending a reserved slot - the Gate-4 UP-3 detection blackout reached
    // through the other limit (#2345 important-1).
    //
    // GUARANTEE, stated precisely: compliance gets an opportunity to START, provided the
    // in-flight lifecycle send returns before the full-pass deadline. It is NOT "compliance
    // gets time" - a lifecycle send begun just inside its slice can return after the full
    // deadline, and no bound here can interrupt it. You cannot have both a hard pass deadline
    // and a guaranteed compliance attempt while sends are uninterruptible (Sol review).
    const auto pass_start = std::chrono::steady_clock::now();
    if (limits.max_wall.count() > 0) {
        lim.has_deadline = true;
        // CLAMP BEFORE THE CAST. The count path clamps (min(num,den), reserve <= total) and an
        // unclamped wall path recreated the very asymmetry this round exists to remove: with a
        // pathological denominator the size_t->int64_t cast could yield a lifecycle slice
        // LONGER than the whole pass, leaving compliance's restored deadline already in the
        // past - zero compliance sends, i.e. the UP-3 detection blackout reached through a
        // sign flip. Unreachable from the sole production caller (1/2), which is exactly why
        // it needed a bound rather than an argument (#2345 Gate 2 sec-MEDIUM-1).
        std::chrono::milliseconds lifecycle_wall = limits.max_wall;
        // Gated on the WALL, not on max_entries: a {max_entries = 0, max_wall = X} config looks
        // bounded but previously received neither the count reserve (skipped by !unbounded) nor
        // a wall slice, i.e. the UP-3 blackout reachable purely by configuration
        // (#2345 Gate 3 cpp-safety).
        if (reserve_den > 0 && reserve_den <= kMaxReserveRatio) {
            // DIVIDE FIRST. Multiplying max_wall by (den - num) before dividing overflows a
            // signed 64-bit millisecond count for a large max_wall with a large denominator -
            // undefined behaviour, not merely a wrong slice. Unreachable from the sole
            // production caller, but the comment above claims a bound, so it needs to be one
            // (#2345 Gate 8 security). Dividing first costs at most (den - 1) ms of slice.
            lifecycle_wall = std::chrono::milliseconds{
                limits.max_wall.count() / static_cast<std::int64_t>(reserve_den) *
                static_cast<std::int64_t>(reserve_den - reserve_num)};
        }
        // Never longer than the pass itself, whatever the ratio said.
        // FLOOR the slice, mirroring the count reserve's floor. Without it a small max_wall
        // truncates lifecycle_wall to 0, lifecycle gets a deadline equal to pass_start and
        // ships NOTHING - the same starve-a-lane bug this round fixed for compliance, simply
        // pointed the other way (#2345 Gate 4 consistency S5). One millisecond is enough to
        // guarantee an attempt; the count budget still bounds the work.
        if (lifecycle_wall < std::chrono::milliseconds{1})
            lifecycle_wall = std::chrono::milliseconds{1};
        lim.deadline = pass_start + std::min(lifecycle_wall, limits.max_wall);
    }

    bool lifecycle_truncated = false;
    out.sent = drain_log_unlocked(lifecycle_log_, outbox_mu_, send, send_exceptions_, lim,
                                 lifecycle_truncated);
    // Hand the compliance pass its reserve PLUS whatever lifecycle did not use, and restore
    // the FULL pass deadline - lifecycle only ever held a slice of it.
    lim.budget += reserve;
    if (limits.max_wall.count() > 0)
        lim.deadline = pass_start + limits.max_wall;
    // Guarantee compliance at least one attempt even if lifecycle already overran the pass.
    // Without this the "compliance gets to start" property is conditional on the in-flight
    // lifecycle send returning in time, and a persistently slow send makes it never true.
    lim.guaranteed_attempts = (reserve > 0) ? 1 : 0;
    bool compliance_truncated = false;
    out.sent += drain_log_unlocked(outbox_, outbox_mu_, send, send_exceptions_, lim,
                                  compliance_truncated);

    // Give any STILL-unused allowance back to lifecycle. Without this the transfer is
    // one-directional and the reserve becomes a hard cap on lifecycle even when compliance
    // is completely idle - which at a small budget throttles audit delivery for no benefit.
    // Spend or drop the guaranteed attempt HERE. If the compliance log was empty the token is
    // never consumed, and carrying it into the lifecycle retry below lets lifecycle start one
    // send past the whole pass deadline - the deadline this exception exists to relax for
    // COMPLIANCE only (#2345 Gate 8 security). should_stop still bounds shutdown either way.
    lim.guaranteed_attempts = 0;
    bool lifecycle_retry_truncated = false;
    const bool retried = lifecycle_truncated && lim.budget > 0;
    if (retried)
        out.sent += drain_log_unlocked(lifecycle_log_, outbox_mu_, send, send_exceptions_, lim,
                                      lifecycle_retry_truncated);

    out.truncated =
        compliance_truncated || (retried ? lifecycle_retry_truncated : lifecycle_truncated);
    return out;
}

void GuardianSparkRuntime::begin_stop() {
    std::shared_ptr<IStateReader> reader;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        stopping_ = true;
        for (auto& [rid, rg] : rules_)
            rg->active = false;
        // rung 9c R5.2: every QUEUED (never dispatched) claim is dropped here with a
        // counted "stopping" outcome so its waiter wakes now rather than riding out
        // its deadline; a Dispatching/Dispatched head is left in place - its
        // completion callback finishes it (a late success is disarmed, R5.5). A
        // retained disarm dropped here leaks its watcher exactly as the old
        // silent Stopped drop did, now counted.
        for (auto eit = claims_.begin(); eit != claims_.end();) {
            auto& fifo = eit->second.fifo;
            for (auto it = fifo.begin(); it != fifo.end();) {
                auto& c = *it;
                if (c->dispatch == ClaimDispatch::Queued) {
                    release_claim_index_locked(*c);
                    if (!c->outcome)
                        c->outcome = std::unexpected(std::string{"stopping"});
                    if (c->end == ClaimEnd::None)
                        c->end = ClaimEnd::Stopped;
                    claims_dropped_at_stop_.fetch_add(1, std::memory_order_relaxed);
                    it = fifo.erase(it);
                } else {
                    ++it;
                }
            }
            if (fifo.empty())
                eit = claims_.erase(eit);
            else
                ++eit;
        }
        reader = reader_; // copy under the lock; call request_stop() outside it
    }
    claim_cv_.notify_all(); // after the lock: wake every claim waiter
    // request_stop() is an extensible virtual - never invoke it under registry_mu_
    // (the runtime already avoids calling copied wakers under its central lock). It
    // is contractually noexcept + nonblocking, so it is safe here even though
    // begin_stop() also runs from ~GuardianSparkRuntime().
    if (reader)
        reader->request_stop();
    // #2233 item 3: wake any attach_rule/detach_rule currently parked in a bounded
    // backend wait immediately, rather than making it ride out cfg_.backend_op_deadline.
    // NOTE this does not make GuardianEngine::stop() itself instant: stop() takes
    // GuardianEngine::mtx_ BEFORE calling begin_stop() (guardian_engine.cpp), so if
    // apply_rules() is currently the one parked in a bounded wait, stop() cannot even
    // reach this call until that wait resolves - bounded by cfg_.backend_op_deadline,
    // same as apply_rules() itself, not instant. This DOES matter for a caller that
    // already holds mtx_ across a DIFFERENT blocking section calling begin_stop()
    // directly, and for the runtime's own destructor path.
    //
    // Contained in try/catch (adversarial review C4/k2): idempotent and DOCUMENTED
    // as nonblocking, but its internal std::lock_guard is, per the standard, permitted
    // to throw std::system_error - not "non-throwing" as an earlier version of this
    // comment claimed. begin_stop() runs from ~GuardianSparkRuntime(), implicitly
    // noexcept; an escaping exception there would std::terminate the agent. Mirrors
    // GuardianStateReader::request_stop()'s identical containment of the same
    // executor's stop() call, just above.
    try {
        io_executor_.stop();
    } catch (...) {
    }
}

std::size_t GuardianSparkRuntime::armed_key_count() const {
    std::lock_guard<std::mutex> lk{registry_mu_};
    return keys_.size();
}
std::size_t GuardianSparkRuntime::rule_count() const {
    std::lock_guard<std::mutex> lk{registry_mu_};
    return rules_.size();
}
std::size_t GuardianSparkRuntime::outbox_size() const {
    std::lock_guard<std::mutex> ob{outbox_mu_};
    return outbox_.size();
}
std::uint64_t GuardianSparkRuntime::outbox_backpressure_drops() const {
    std::lock_guard<std::mutex> ob{outbox_mu_};
    return outbox_.backpressure_drops();
}
std::uint64_t GuardianSparkRuntime::lifecycle_backpressure_drops() const {
    std::lock_guard<std::mutex> ob{outbox_mu_};
    return lifecycle_log_.backpressure_drops();
}
std::optional<GuardianSparkRuntime::RuleStatusSnapshot>
GuardianSparkRuntime::status_for_rule(const std::string& rule_id) const {
    std::lock_guard<std::mutex> lk{registry_mu_};
    const auto it = rules_.find(rule_id);
    if (it == rules_.end())
        return std::nullopt;
    RuleStatusSnapshot snap;
    snap.in_unknown = it->second->eval.in_unknown;
    snap.last_compliant = it->second->eval.emit.last_compliant;
    return snap;
}
std::vector<std::string> GuardianSparkRuntime::pending_initial(const std::string& key) const {
    std::lock_guard<std::mutex> lk{registry_mu_};
    const auto kit = keys_.find(key);
    if (kit == keys_.end())
        return {};
    std::vector<std::string> out;
    out.reserve(kit->second->pending_initial.size());
    for (const auto& [rule_id, state] : kit->second->pending_initial)
        out.push_back(rule_id); // membership means "never Known" - includes demoted rules
    return out;
}

std::vector<std::string>
GuardianSparkRuntime::pending_demoted_for_test(const std::string& key) const {
    std::lock_guard<std::mutex> lk{registry_mu_};
    const auto kit = keys_.find(key);
    if (kit == keys_.end())
        return {};
    std::vector<std::string> out;
    for (const auto& [rule_id, state] : kit->second->pending_initial)
        if (state.demoted)
            out.push_back(rule_id);
    return out;
}
bool GuardianSparkRuntime::stopping() const {
    std::lock_guard<std::mutex> lk{registry_mu_};
    return stopping_;
}

std::vector<std::string> GuardianSparkRuntime::keys_for_type(SparkType type) const {
    std::lock_guard<std::mutex> lk{registry_mu_};
    std::vector<std::string> out;
    for (const auto& [key, pk] : keys_)
        if (pk->spec.type == type)
            out.push_back(key);
    return out;
}

std::vector<std::string> GuardianSparkRuntime::keys_with_pending_initial() const {
    std::lock_guard<std::mutex> lk{registry_mu_};
    std::vector<std::string> out;
    for (const auto& [key, pk] : keys_) {
        // M1 item (b): a key leaves the priority worklist only once EVERY pending rule
        // on it is demoted - a key with a mixed demoted/non-demoted pending set already
        // pays the per-key read cost for its non-demoted sibling, so excluding it would
        // silently starve that sibling's priority-lane cadence for free.
        const bool has_active_pending =
            std::any_of(pk->pending_initial.begin(), pk->pending_initial.end(),
                       [](const auto& entry) { return !entry.second.demoted; });
        if (has_active_pending)
            out.push_back(key);
    }
    return out;
}

void GuardianSparkRuntime::set_pending_initial_waker(std::function<void()> waker) {
    std::lock_guard<std::mutex> lk{registry_mu_};
    pending_initial_waker_ = std::move(waker);
}

std::function<void()> GuardianSparkRuntime::pending_initial_waker_for_test() const {
    std::lock_guard<std::mutex> lk{registry_mu_};
    return pending_initial_waker_;
}

void GuardianSparkRuntime::set_outbox_enqueue_waker(std::function<void()> waker) {
    std::lock_guard<std::mutex> lk{registry_mu_};
    outbox_enqueue_waker_ = std::move(waker);
}

std::function<void()> GuardianSparkRuntime::outbox_enqueue_waker_for_test() const {
    std::lock_guard<std::mutex> lk{registry_mu_};
    return outbox_enqueue_waker_;
}

void GuardianSparkRuntime::set_agent_id_provider(std::function<std::string()> provider) {
    std::lock_guard<std::mutex> lk{registry_mu_};
    agent_id_fn_ = std::move(provider);
}

} // namespace yuzu::agent
