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

void GuardianSparkRuntime::submit_disarm_off_lock(const DisarmWork& work) {
    // fn's own return value is discarded below - disarm() is void and was never
    // awaited for success even in the old inline call this replaces (see the
    // header doc). Only Timeout/CapacityExhausted/etc are worth counting: they
    // mean the OS watcher's fate is now genuinely unknown to us (still armed?
    // torn down mid-flight?), which the old synchronous call never risked.
    auto result =
        io_executor_.run(work.io_class, work.key, cfg_.backend_op_deadline,
                         [backend = backend_, sub = work.subscription]() -> int {
                             backend->disarm(sub);
                             return 0;
                         });
    if (!result)
        backend_op_timeouts_.fetch_add(1, std::memory_order_relaxed);
}

std::expected<std::uint64_t, std::string>
GuardianSparkRuntime::attach_rule(std::string rule_id, SparkSpec spec, RuleAssertion assertion,
                                  bool emit_compliant_edge) {
    const std::string key = spark_key(spec);
    // #2233 item 3: File/Registry/Service arm off registry_mu_, bounded; every other
    // type stays inline (see io_class_for_spark_type's doc).
    const std::optional<IoClass> io_class = io_class_for_spark_type(spec.type);
    std::function<void()> waker;
    std::function<void()> outbox_waker;
    std::uint64_t new_gen = 0;
    std::optional<DisarmWork> prior_disarm;
    // Snapshot BEFORE taking registry_mu_ (same outside-lock pattern evaluate_key uses
    // for its own now-snapshot): this is PendingState::first_seen, the M1 item (b)
    // elapsed-time demotion clock. A fresh attach always starts un-demoted regardless
    // of how long a PRIOR generation on this rule_id sat pending (detach_rule_locked
    // below drops that generation's PendingState entirely).
    const auto attach_now = clock_();

    // Built once, reused by both the fast (reuse-existing-watcher / inline-type) path
    // and the slow (bounded off-lock arm) path's post-wait commit.
    const std::string rule_name = assertion.rule_name;
    const char* guard_type = guard_type_for(assertion.kind);
    auto rg = std::make_shared<RuleGeneration>();
    rg->active = true;
    rg->emit_compliant_edge = emit_compliant_edge;
    rg->assertion = std::move(assertion);
    rg->assertion.rule_id = rule_id; // keep the assertion's own rule_id authoritative

    std::uint64_t gen = 0;
    bool need_bounded_arm = false;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        if (stopping_)
            return std::unexpected(std::string{"stopping"});

        // Fresh generation: drop any prior mapping for this rule first. This
        // rebuilds eval state from scratch on every push, identical re-push
        // included - there is no diff-skip that preserves it (matches the legacy
        // path's own tear-down-and-rebuild-every-push behavior). If a prior
        // generation existed, this already enqueued its "disarmed" lifecycle entry
        // (and, #2233 item 3, may return backend work this function submits below,
        // off-lock) - the "armed" entry below covers the new one, so ONE
        // outbox-waker firing at the end of this call covers both.
        prior_disarm = detach_rule_locked(rule_id);

        gen = ++gen_counter_;
        rg->generation = gen;

        // #2233 item 3 fail-fast: a DIFFERENT rule_id's arm is already resolving for
        // this key off-lock (unreachable via GuardianEngine's mtx_-serialised
        // production callers - start_local/apply_rules hold mtx_ for their entire
        // body, so no second attach_rule call can even start while this one's is
        // in flight; matters only for a caller that invokes this class directly
        // across threads, e.g. a test). Never wait, never double-arm: registry_mu_
        // alone used to make this impossible by construction (arm() ran inside it);
        // now that the backend call is off-lock, this closes the gap explicitly.
        if (const auto in_flight = arming_keys_.find(key); in_flight != arming_keys_.end()) {
            backend_op_busy_.fetch_add(1, std::memory_order_relaxed);
            return std::unexpected(std::string{"arm already in progress for this key"});
        }

        const bool arm_edge = index_->add(key, rule_id); // may throw; nothing mutated yet on throw
        if (arm_edge && io_class) {
            // Slow path: mark in-flight and return to the caller below WITHOUT
            // touching keys_/rules_/pending_initial/lifecycle - all deferred to the
            // post-wait commit phase, so a same-key racer's arming_keys_ check above
            // never sees a half-built PerKey.
            GuardianRollback index_rollback;
            index_rollback.fn = [this, rule_id] { index_->remove_rule(rule_id); };
            arming_keys_.emplace(key, InFlightArm{rule_id, false}); // may throw -> rollback
            index_rollback.committed = true;
            need_bounded_arm = true;
        } else if (arm_edge) {
            // Inline type (Interval/Startup/Disk): unchanged synchronous arm, still
            // under registry_mu_ - these are never a blocking OS watch.
            std::shared_ptr<PerKey> pk;
            std::uint64_t sub = 0;
            bool armed_here = false;
            GuardianRollback rollback;
            rollback.fn = [this, rule_id, key, &sub, &armed_here, &pk] {
                index_->remove_rule(rule_id);
                if (armed_here) {
                    keys_.erase(key);
                    backend_->disarm(sub);
                }
                rules_.erase(rule_id);
                if (pk)
                    pk->pending_initial.erase(rule_id);
            };
            auto armed = backend_->arm(spec); // may THROW -> rollback undoes the index add
            if (!armed)
                return std::unexpected(armed.error()); // rollback undoes the index add
            sub = *armed;
            armed_here = true;
            pk = std::make_shared<PerKey>();
            pk->spec = spec;
            pk->subscription = sub;
            keys_.emplace(key, pk);

            rules_.insert_or_assign(rule_id, std::move(rg));
            pk->pending_initial.insert_or_assign(rule_id, PendingState{attach_now, 0, false});
            waker = pending_initial_waker_;
            outbox_waker = outbox_enqueue_waker_;
            enqueue_lifecycle_locked(rule_id, gen, "armed", guard_type, rule_name);
            rollback.committed = true;
        } else {
            // An existing shared watcher for this key (armed or, #2233 item 3, itself
            // mid-arm - the arming_keys_ check above already rejected that case, so
            // reaching here with arm_edge==false means keys_ genuinely has it). No
            // backend call, but a throw below (map insert, or a throwing
            // waker/outbox_waker COPY) must still undo the index_->add - mirrors the
            // original unified rollback's armed_here=false shape (never disarms;
            // there is no new watcher to tear down, only this rule's own bookkeeping).
            auto pk = keys_.at(key);
            GuardianRollback rollback;
            rollback.fn = [this, rule_id, pk] {
                index_->remove_rule(rule_id);
                rules_.erase(rule_id);
                pk->pending_initial.erase(rule_id);
            };
            rules_.insert_or_assign(rule_id, std::move(rg));
            pk->pending_initial.insert_or_assign(rule_id, PendingState{attach_now, 0, false});
            waker = pending_initial_waker_;
            outbox_waker = outbox_enqueue_waker_;
            enqueue_lifecycle_locked(rule_id, gen, "armed", guard_type, rule_name);
            rollback.committed = true;
        }
        new_gen = gen;
    }

    // Off-lock: any watcher a superseded prior generation owed a disarm to. Fire
    // this before the new arm below so a redeploy that keeps the SAME key (rare -
    // most redeploys change the spec) does not race its own teardown against its
    // own re-arm; SparkEngine's per-type mechanism lock orders the two regardless,
    // but there is no reason to invite it.
    if (prior_disarm)
        submit_disarm_off_lock(*prior_disarm);

    if (!need_bounded_arm) {
        if (waker)
            waker();
        if (outbox_waker)
            outbox_waker();
        return new_gen;
    }

    // The actual backend arm, OFF both runtime locks, bounded by cfg_.backend_op_deadline.
    // A caller (GuardianEngine::apply_rules/start_local, still holding mtx_ for its
    // whole body) waits at most this long for THIS rule; every other rule's
    // attach/detach and every evaluate_key proceed freely in the meantime, since
    // registry_mu_ is not held here at all.
    // T = std::expected<uint64_t, string> (backend_->arm's own return type) - two
    // layers to unwrap below: the OUTER expected is io_executor_'s own bounded-wait
    // outcome (timeout/capacity/etc, IoFailure), the INNER is backend_->arm()'s own
    // synchronous refusal, exactly as returned before this call moved off-lock.
    auto io_result = io_executor_.run(*io_class, key, cfg_.backend_op_deadline,
                                      [backend = backend_, spec]() { return backend->arm(spec); });

    std::optional<DisarmWork> stale_disarm; // set below iff we must undo a LATE success
    std::expected<std::uint64_t, std::string> outcome = new_gen;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        const auto it = arming_keys_.find(key);
        const bool withdrawn = it != arming_keys_.end() && it->second.withdrawn;
        arming_keys_.erase(key); // this in-flight episode is over either way
        const bool armed_live = io_result && io_result->has_value(); // both layers succeeded

        if (stopping_ || withdrawn) {
            index_->remove_rule(rule_id); // no-op if detach already removed it (withdrawn path)
            if (armed_live) {
                // A live subscription nobody wants any more - disarm it, off-lock,
                // after this block unlocks. No "armed" audit: this generation never
                // committed (matches the existing "pending arm withdrawn -> no
                // lifecycle entry" contract - it was never armed from the runtime's
                // point of view).
                stale_disarm = DisarmWork{*io_class, key, **io_result};
            }
            outcome = std::unexpected(std::string{stopping_ ? "stopping" : "withdrawn"});
        } else if (!io_result) {
            index_->remove_rule(rule_id);
            std::string reason;
            switch (io_result.error()) {
            case IoFailure::Timeout:            reason = "arm timed out"; break;
            case IoFailure::Stopped:            reason = "stopping"; break;
            case IoFailure::CapacityExhausted:  reason = "arm capacity exhausted"; break;
            case IoFailure::AlreadyRunning:     reason = "arm already in progress for this key"; break;
            case IoFailure::LaunchFailed:       reason = "arm worker launch failed"; break;
            case IoFailure::WorkerThrew:        reason = "arm worker threw"; break;
            }
            if (io_result.error() == IoFailure::Timeout)
                backend_op_timeouts_.fetch_add(1, std::memory_order_relaxed);
            outcome = std::unexpected(reason);
        } else if (!armed_live) {
            // The bounded wait completed and backend_->arm() itself returned an
            // error (io_result->error()) - the SAME synchronous-refusal outcome the
            // old inline call could always produce, just observed after the
            // off-lock wait instead of under registry_mu_.
            index_->remove_rule(rule_id);
            outcome = std::unexpected(io_result->error());
        } else {
            // Mirrors attach_rule's fast-path rollback (same armed_here=true shape):
            // index_->add already ran in phase 1, and we now hold a live subscription
            // - a throw from here down (keys_/rules_/pending_initial insert, or a
            // throwing waker/outbox_waker COPY, exactly as the fast path's own
            // "throw AFTER arm()" test exercises) must not leave keys_/rules_/index_
            // desynced or leak the watcher. Calls backend_->disarm() synchronously,
            // still under registry_mu_ (unlike the normal off-lock disarm path) -
            // this is the SAME tradeoff the pre-#2233 code always made for this exact
            // rare unwind case (a map-insert bad_alloc or a throwing waker copy, not
            // the common path), so it does not reopen the liveness hazard this PR
            // fixes.
            const std::uint64_t sub = **io_result;
            GuardianRollback rollback;
            rollback.fn = [this, rule_id, key, sub] {
                index_->remove_rule(rule_id); // undo phase 1's index_->add
                keys_.erase(key);
                backend_->disarm(sub);
                rules_.erase(rule_id);
            };
            auto pk = std::make_shared<PerKey>();
            pk->spec = spec;
            pk->subscription = sub;
            keys_.emplace(key, pk);
            rules_.insert_or_assign(rule_id, std::move(rg));
            pk->pending_initial.insert_or_assign(rule_id, PendingState{attach_now, 0, false});
            waker = pending_initial_waker_;
            outbox_waker = outbox_enqueue_waker_;
            enqueue_lifecycle_locked(rule_id, gen, "armed", guard_type, rule_name);
            rollback.committed = true;
        }
    }
    if (stale_disarm)
        submit_disarm_off_lock(*stale_disarm);
    if (outcome) {
        if (waker)
            waker();
        if (outbox_waker)
            outbox_waker();
    }
    return outcome;
}

void GuardianSparkRuntime::detach_rule(const std::string& rule_id) {
    std::function<void()> outbox_waker;
    std::optional<DisarmWork> work;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        work = detach_rule_locked(rule_id);
        outbox_waker = outbox_enqueue_waker_;
    }
    // #2233 item 3: off both locks - the confirmed-state mutation + "disarmed" audit
    // above are already committed regardless of what follows here.
    if (work)
        submit_disarm_off_lock(*work);
    if (outbox_waker)
        outbox_waker();
}

void GuardianSparkRuntime::detach_all() {
    std::function<void()> outbox_waker;
    std::vector<DisarmWork> works;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        std::vector<std::string> rule_ids;
        rule_ids.reserve(rules_.size());
        for (const auto& [rid, rg] : rules_)
            rule_ids.push_back(rid);
        for (const auto& rid : rule_ids)
            if (auto work = detach_rule_locked(rid))
                works.push_back(std::move(*work));
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

std::optional<GuardianSparkRuntime::DisarmWork>
GuardianSparkRuntime::detach_rule_locked(const std::string& rule_id) {
    // #2233 item 3: rule_id belongs to a key whose FIRST arm is still resolving
    // off-lock (attach_rule released registry_mu_ before the backend call) - it has
    // no rules_/keys_ entry to withdraw yet. Mark the in-flight episode withdrawn so
    // its own completion abandons + disarms rather than committing a rule nobody
    // wants any more, and drop it from the index NOW (matches the immediate-index-
    // cleanup semantics the confirmed path below already has). No "disarmed" audit -
    // the rule was never actually armed (same "pending arm withdrawn -> no lifecycle
    // entry" contract the confirmed path's `known` gate already encodes).
    if (const auto key_opt = index_->key_for_rule(rule_id); key_opt) {
        if (auto it = arming_keys_.find(*key_opt);
            it != arming_keys_.end() && it->second.rule_id == rule_id) {
            it->second.withdrawn = true;
            index_->remove_rule(rule_id);
            return std::nullopt; // nothing to disarm yet; the in-flight attach's completion does
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
    // #2233 item 3: the confirmed-state mutation above (index_/rules_/keys_) and the
    // "disarmed" audit below are the durable commit; the actual backend_->disarm()
    // call is now the CALLER's job, off-lock (submit_disarm_off_lock). This changes
    // WHERE that call runs, not whether its success is confirmed - disarm() is void
    // and was never awaited for success even in the old inline call (see the header
    // doc's DisarmWork comment), so this is not a new unconfirmed-teardown gap.
    std::optional<DisarmWork> work;
    if (disarm_key) {
        const auto kit = keys_.find(*disarm_key);
        if (kit != keys_.end()) {
            if (const auto ioc = io_class_for_spark_type(kit->second->spec.type))
                work = DisarmWork{*ioc, *disarm_key, kit->second->subscription};
            else
                backend_->disarm(kit->second->subscription); // inline type: unchanged, synchronous
            keys_.erase(kit); // the in-flight pass (if any) holds its own shared_ptr; safe
        }
    } else if (key_opt) {
        const auto kit = keys_.find(*key_opt);
        if (kit != keys_.end())
            kit->second->pending_initial.erase(rule_id);
    }
    if (known)
        enqueue_lifecycle_locked(rule_id, gen, "disarmed", guard_type, rule_name);
    return work;
}

void GuardianSparkRuntime::on_event(const SparkEvent& ev) {
    // The event is an invalidation HINT; evaluate_key re-reads live state.
    evaluate_key(ev.key, EvalReason::Event);
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
        return lifecycle_log_.enqueue(std::move(entry)); // best-effort live window
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
    // The watertight fix (merge-drain by global sequence) is a tracked follow-up.
    DrainLimits unbounded;
    return drain_bounded(send, unbounded).sent;
}

GuardianSparkRuntime::DrainOutcome
GuardianSparkRuntime::drain_bounded(const std::function<SendResult(const OutboxEntry&)>& send,
                                    const DrainLimits& limits) {
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
        reader = reader_; // copy under the lock; call request_stop() outside it
    }
    // request_stop() is an extensible virtual - never invoke it under registry_mu_
    // (the runtime already avoids calling copied wakers under its central lock). It
    // is contractually noexcept + nonblocking, so it is safe here even though
    // begin_stop() also runs from ~GuardianSparkRuntime().
    if (reader)
        reader->request_stop();
    // #2233 item 3: wake any attach_rule/detach_rule currently parked in a bounded
    // backend wait immediately, rather than making it ride out cfg_.backend_op_deadline.
    // GuardianIoExecutor::stop() is idempotent, non-throwing, and safe to call from
    // ~GuardianSparkRuntime() same as request_stop() above. NOTE this does not make
    // GuardianEngine::stop() itself instant: stop() takes GuardianEngine::mtx_
    // BEFORE calling begin_stop() (guardian_engine.cpp), so if apply_rules() is
    // currently the one parked in a bounded wait, stop() cannot even reach this
    // call until that wait resolves - bounded by cfg_.backend_op_deadline, same as
    // apply_rules() itself, not instant. This DOES matter for a caller that already
    // holds mtx_ across a DIFFERENT blocking section calling begin_stop() directly,
    // and for the runtime's own destructor path.
    io_executor_.stop();
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
