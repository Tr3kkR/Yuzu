#include "guardian_spark_runtime.hpp"

#include "guardian_scope_guard.hpp" // GuardianRollback (terminate-safe rollback)
#include "spark_key_rule_index.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <cassert>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <unordered_set>
#include <utility>
#include <variant>

namespace yuzu::agent {

namespace {
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
      boot_nonce_(make_boot_nonce()), index_(std::make_unique<SparkKeyRuleIndex>()),
      outbox_(std::max(kMinOutboxCapacity, cfg.outbox_capacity)),
      lifecycle_log_(std::max(kMinOutboxCapacity, cfg.outbox_capacity)) {
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

std::expected<std::uint64_t, std::string>
GuardianSparkRuntime::attach_rule(std::string rule_id, SparkSpec spec, RuleAssertion assertion,
                                  bool emit_compliant_edge) {
    const std::string key = spark_key(spec);
    std::function<void()> waker;
    std::function<void()> outbox_waker;
    std::uint64_t new_gen = 0;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        if (stopping_)
            return std::unexpected(std::string{"stopping"});

        // Fresh generation: drop any prior mapping for this rule first. This
        // rebuilds eval state from scratch on every push, identical re-push
        // included - there is no diff-skip that preserves it (a possible future
        // optimization, not implemented; matches the legacy path's own
        // tear-down-and-rebuild-every-push behavior, so this is not a
        // regression - consistency-auditor Gate 4 finding, this PR: an earlier
        // version of this comment claimed the opposite in present tense). If a
        // prior generation existed, this already enqueued its "disarmed"
        // lifecycle entry - the "armed" entry below covers the new one, so ONE
        // outbox-waker firing at the end of this call covers both.
        detach_rule_locked(rule_id);

        const std::uint64_t gen = ++gen_counter_;
        // Capture the lifecycle metadata before `assertion` is moved into rg below;
        // the "armed" audit entry (and any prior "disarmed" from detach above) needs it.
        const std::string rule_name = assertion.rule_name;
        const char* guard_type = guard_type_for(assertion.kind);
        auto rg = std::make_shared<RuleGeneration>();
        rg->generation = gen;
        rg->active = true;
        rg->emit_compliant_edge = emit_compliant_edge;
        rg->assertion = std::move(assertion);
        rg->assertion.rule_id = rule_id; // keep the assertion's own rule_id authoritative

        // `pk`/`sub`/`armed_here` are declared BEFORE `rollback` so they outlive its
        // destructor (reverse construction order): the rollback lambda reads them by
        // reference. ONE rollback is installed BEFORE index_->add and backend_->arm, so a
        // GUARDIAN-side throw - the index add, or any map/set insertion after arm()
        // RETURNED a subscription (armed_here=true) - unwinds every Guardian-side mutation
        // and disarms that subscription. The prior code assigned the rollback only AFTER
        // arm() and per-branch, so a throwing arm() (or a throwing rollback-closure
        // assignment after the arm) leaked the subscription and left a ghost index entry
        // that corrupted a future sibling attach. Every undo is a safe no-op if its
        // mutation never ran, and GuardianRollback's destructor is terminate-safe.
        // SCOPE LIMIT (Sol B4): if backend_->arm() itself THROWS after partially mutating
        // SparkEngine (a bad_alloc inside arm_impl, no subscription returned), armed_here
        // stays false and this rollback cannot clean the engine's partial state - that is
        // a SparkEngine strong-guarantee gap tracked separately as a PR-2 flip blocker.
        // (Fable rung-7.7b M3; extends Sol rung-7.5 finding 1.)
        std::shared_ptr<PerKey> pk;
        std::uint64_t sub = 0;
        bool armed_here = false;
        GuardianRollback rollback;
        rollback.fn = [this, rule_id, key, &sub, &armed_here, &pk] {
            index_->remove_rule(rule_id); // no-op if add() never ran or threw clean
            if (armed_here) {
                // THIS attach created the watcher (0->1 edge under registry_mu_, so it is
                // the sole rule on the key): tear the new subscription + PerKey down.
                keys_.erase(key); // no-op if the new PerKey was not yet emplaced
                backend_->disarm(sub);
            }
            rules_.erase(rule_id); // no-op if not yet inserted
            if (pk)
                pk->pending_initial.erase(rule_id);
        };

        const bool arm_edge = index_->add(key, rule_id);
        if (arm_edge) {
            auto armed = backend_->arm(spec); // may THROW -> rollback undoes the index add
            if (!armed)
                return std::unexpected(armed.error()); // rollback undoes the index add
            sub = *armed;
            armed_here = true; // from here a throw also disarms the watcher
            pk = std::make_shared<PerKey>();
            pk->spec = spec;
            pk->subscription = sub;
            keys_.emplace(key, pk);
        } else {
            pk = keys_.at(key); // an existing shared watcher for this key (armed_here stays false)
        }

        rules_.insert_or_assign(rule_id, std::move(rg));
        pk->pending_initial.insert(rule_id);
        // Copy the wakers (throwing std::function copies) BEFORE the lifecycle enqueue so
        // a throw here rolls back with NO audit entry yet. The lifecycle log is
        // append-only and never purged (guardian_outbox.hpp), so a phantom "armed"
        // enqueued before a throwing waker copy would be permanent evidence of an arm
        // that actually rolled back (Sol/Fable SHOULD, rung 7.7b).
        waker = pending_initial_waker_;   // copy; call after releasing registry_mu_
        outbox_waker = outbox_enqueue_waker_;
        // Audit-on-arm (rung 7, finding 8): a successful arm - spark or legacy - must not
        // go unaudited. Failure here is counted, never rolls back the arm itself (the
        // audit trail must not compromise real detection capability); see
        // enqueue_lifecycle_locked's doc. This is the LAST potentially-throwing step, and
        // it is all-or-nothing (std::list::push_back is strong), so only the noexcept
        // commit below follows a successful enqueue.
        enqueue_lifecycle_locked(rule_id, gen, "armed", guard_type, rule_name);
        rollback.committed = true;
        new_gen = gen;
    }
    // Outside the lock (avoids a registry_mu_ -> scheduler_mu_ inversion): let the
    // convergence scheduler service the new rule's initial eval promptly, and let
    // the drain worker (rung 7.5) send the fresh armed/health/compliance entries.
    if (waker)
        waker();
    if (outbox_waker)
        outbox_waker();
    return new_gen;
}

void GuardianSparkRuntime::detach_rule(const std::string& rule_id) {
    std::function<void()> outbox_waker;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        detach_rule_locked(rule_id);
        outbox_waker = outbox_enqueue_waker_;
    }
    if (outbox_waker)
        outbox_waker();
}

void GuardianSparkRuntime::detach_all() {
    std::function<void()> outbox_waker;
    {
        std::lock_guard<std::mutex> lk{registry_mu_};
        std::vector<std::string> rule_ids;
        rule_ids.reserve(rules_.size());
        for (const auto& [rid, rg] : rules_)
            rule_ids.push_back(rid);
        for (const auto& rid : rule_ids)
            detach_rule_locked(rid);
        outbox_waker = outbox_enqueue_waker_;
    }
    if (outbox_waker)
        outbox_waker();
}

void GuardianSparkRuntime::detach_rule_locked(const std::string& rule_id) {
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
    // Disarm the shared watcher BEFORE the "disarmed" audit enqueue. enqueue_lifecycle_locked
    // allocates; in the OLD order a throw there left the watcher ARMED while the rule was
    // already gone from the index - a leaked OS watcher + keys_/index_ desync that breaks a
    // future same-key re-attach (keys_.emplace no-ops on the stale key) (Gate 2 security
    // LOW). A throw AFTER the disarm merely loses the audit entry; audit-after-teardown is
    // the correct causal order anyway.
    if (disarm_key) {
        const auto kit = keys_.find(*disarm_key);
        if (kit != keys_.end()) {
            backend_->disarm(kit->second->subscription);
            keys_.erase(kit); // the in-flight pass (if any) holds its own shared_ptr; safe
        }
    } else if (key_opt) {
        const auto kit = keys_.find(*key_opt);
        if (kit != keys_.end())
            kit->second->pending_initial.erase(rule_id);
    }
    if (known)
        enqueue_lifecycle_locked(rule_id, gen, "disarmed", guard_type, rule_name);
}

void GuardianSparkRuntime::on_event(const SparkEvent& ev) {
    // The event is an invalidation HINT; evaluate_key re-reads live state.
    evaluate_key(ev.key, EvalReason::Event);
}

void GuardianSparkRuntime::evaluate_key(const std::string& key, EvalReason /*reason*/) {
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

            std::vector<OutboxEntry> entries = build_entries(*rg, out, agent_id);
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

            rg->eval = std::move(scratch); // COMMIT
            // M1: a committed repeat Unknown (already errored, so build_entries emitted
            // nothing) is counted here so the edge-suppression is observable, never silent
            // (Option-A: every loss/suppression channel is a counted metric).
            if (out.status == EvalStatus::Unhealthy && !out.unhealthy_edge)
                unhealthy_suppressed_.fetch_add(1, std::memory_order_relaxed);
            // A Known verdict (Emit or steady-Silent) satisfies the initial eval; an
            // Unknown does not (it still owes a real verdict).
            if (out.status != EvalStatus::Unhealthy)
                pk->pending_initial.erase(rg->assertion.rule_id);
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
                                                            const std::string& agent_id) {
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
    else if (out.status == EvalStatus::Unhealthy && out.unhealthy_edge)
        // EDGE ONLY (M1): the first Unknown of an errored episode mints one guard.unhealthy.
        // A repeat Unknown while already errored produces NO entry here (the caller counts it
        // via unhealthy_suppressed_) - convergence re-evaluates a stuck rule every ~5s to catch
        // recovery, but must not re-mint a fresh health event each tick (fleet ingest flood).
        // NOTE: the emitted health_detail is this episode's FIRST read-error string; a reason
        // that changes across suppressed re-evals while still Unknown (EACCES -> ENODEV) is not
        // re-surfaced until recovery starts a new episode. Accepted trade for the flood fix.
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

std::vector<std::shared_ptr<const JournalRecord>> GuardianSparkRuntime::snapshot_pending() const {
    std::lock_guard<std::mutex> ob{outbox_mu_};
    return {pending_journal_.begin(), pending_journal_.end()};
}

void GuardianSparkRuntime::erase_persisted_prefix(std::size_t n) {
    std::lock_guard<std::mutex> ob{outbox_mu_};
    n = std::min(n, pending_journal_.size());
    pending_journal_.erase(pending_journal_.begin(),
                           pending_journal_.begin() + static_cast<std::ptrdiff_t>(n));
}

std::size_t GuardianSparkRuntime::pending_journal_depth() const {
    std::lock_guard<std::mutex> ob{outbox_mu_};
    return pending_journal_.size();
}

std::size_t GuardianSparkRuntime::try_page_batch(std::vector<OutboxEntry> entries) {
    if (entries.empty())
        return 0;
    std::lock_guard<std::mutex> ob{outbox_mu_};
    // Headroom gate (design §5): page the batch only if it fits whole; else leave it for a
    // later pass once the window drains (never a partial page that splits a batch).
    if (lifecycle_log_.headroom() < entries.size())
        return 0;
    std::size_t added = 0;
    // Build the window membership set ONCE (O(window)) rather than re-scanning the window per
    // record (O(records x window)); the latter runs on the heartbeat/run-loop thread and can
    // starve heartbeats under a large backlog (review UP-12 / perf P-2). The batch's records
    // carry distinct event_ids, so a static pre-batch set is correct here.
    const auto present = lifecycle_log_.event_id_set();
    for (auto& e : entries) {
        if (!present.count(e.event_id)) // O(1) membership: skip a re-page of an entry in the window
            if (lifecycle_log_.enqueue(std::move(e)))
                ++added;
    }
    return added;
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
template <typename Log>
std::size_t drain_log_unlocked(Log& log, std::mutex& mu,
                               const std::function<SendResult(const OutboxEntry&)>& send,
                               std::atomic<std::uint64_t>& send_exceptions) {
    std::size_t sent = 0;
    while (true) {
        OutboxEntry entry;
        {
            std::lock_guard<std::mutex> ob{mu};
            std::optional<OutboxEntry> front = log.front_copy();
            if (!front)
                return sent; // drained
            entry = std::move(*front);
        }
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
    }
}
} // namespace

std::size_t GuardianSparkRuntime::drain(const std::function<SendResult(const OutboxEntry&)>& send) {
    // Single-drainer: the send runs with outbox_mu_ released, so two concurrent drainers
    // could both peek+send the same head (duplicate delivery). drain_mu_ serialises them
    // without blocking enqueuers (they take outbox_mu_, not drain_mu_).
    std::lock_guard<std::mutex> dg{drain_mu_};
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
    std::size_t sent = drain_log_unlocked(lifecycle_log_, outbox_mu_, send, send_exceptions_);
    sent += drain_log_unlocked(outbox_, outbox_mu_, send, send_exceptions_);
    return sent;
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
    return {kit->second->pending_initial.begin(), kit->second->pending_initial.end()};
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
    for (const auto& [key, pk] : keys_)
        if (!pk->pending_initial.empty())
            out.push_back(key);
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
