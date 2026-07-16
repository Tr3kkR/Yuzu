#include "guardian_spark_runtime.hpp"

#include "spark_key_rule_index.hpp"

#include <algorithm>
#include <random>
#include <set>
#include <string>
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
      lifecycle_log_(std::max(kMinOutboxCapacity, cfg.outbox_capacity)) {}

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

        // Fresh generation: drop any prior mapping for this rule first (rung 7's
        // reconcile is what preserves eval state across an identical re-push).
        // If a prior generation existed, this already enqueued its "disarmed"
        // lifecycle entry - the "armed" entry below covers the new one, so ONE
        // outbox-waker firing at the end of this call covers both.
        detach_rule_locked(rule_id);

        const std::uint64_t gen = ++gen_counter_;
        auto rg = std::make_shared<RuleGeneration>();
        rg->generation = gen;
        rg->active = true;
        rg->emit_compliant_edge = emit_compliant_edge;
        rg->assertion = std::move(assertion);
        rg->assertion.rule_id = rule_id; // keep the assertion's own rule_id authoritative

        const bool arm_edge = index_->add(key, rule_id);
        std::shared_ptr<PerKey> pk;
        if (arm_edge) {
            auto armed = backend_->arm(spec);
            if (!armed) {
                index_->remove_rule(rule_id); // undo: an un-armed key must not linger
                return std::unexpected(armed.error());
            }
            pk = std::make_shared<PerKey>();
            pk->spec = spec;
            pk->subscription = *armed;
            keys_.emplace(key, pk);
        } else {
            pk = keys_.at(key); // an existing shared watcher for this key
        }

        rules_.insert_or_assign(rule_id, std::move(rg));
        pk->pending_initial.insert(rule_id);
        // Audit-on-arm (rung 7, finding 8): a successful arm - spark or legacy -
        // must not go unaudited. Failure here is counted, never rolls back the
        // arm itself (the audit trail must not compromise real detection
        // capability); see enqueue_lifecycle_locked's doc.
        enqueue_lifecycle_locked(rule_id, gen, "armed");
        waker = pending_initial_waker_;   // copy; call after releasing registry_mu_
        outbox_waker = outbox_enqueue_waker_;
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
    if (known)
        enqueue_lifecycle_locked(rule_id, gen, "disarmed");
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
    std::vector<OutboxEntry> v;
    if (out.recovered) // Unknown -> Known: clear the health stream's errored state first
        v.push_back(OutboxEntry::health(rid, gen.generation, make_event_id(rid, ms, agent_id), ns,
                                        /*healthy=*/true, {}));
    if (out.status == EvalStatus::Emit)
        v.push_back(OutboxEntry::compliance(rid, gen.generation, make_event_id(rid, ms, agent_id),
                                            ns, out.drift));
    else if (out.status == EvalStatus::Unhealthy)
        v.push_back(OutboxEntry::health(rid, gen.generation, make_event_id(rid, ms, agent_id), ns,
                                        /*healthy=*/false, out.health_detail));
    // Silent + !recovered -> empty (nothing to publish).
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
                                                    const std::string& kind) {
    // Called from attach_rule/detach_rule_locked - never on the detached-post-
    // read path - so calling agent_id_fn_() directly (not pre-snapshotted) is
    // safe here, unlike evaluate_key's read path.
    const auto wall = std::chrono::system_clock::now().time_since_epoch();
    const std::int64_t ns = std::chrono::duration_cast<std::chrono::nanoseconds>(wall).count();
    const std::int64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(wall).count();
    const std::string agent_id = agent_id_fn_ ? agent_id_fn_() : std::string{};
    auto entry = OutboxEntry::lifecycle(rule_id, generation, make_event_id(rule_id, ms, agent_id),
                                        ns, kind);
    std::lock_guard<std::mutex> ob{outbox_mu_};
    return lifecycle_log_.enqueue(std::move(entry));
}

std::size_t GuardianSparkRuntime::drain(const std::function<SendResult(const OutboxEntry&)>& send) {
    std::lock_guard<std::mutex> ob{outbox_mu_};
    std::size_t sent = outbox_.drain(send);
    sent += lifecycle_log_.drain(send);
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
