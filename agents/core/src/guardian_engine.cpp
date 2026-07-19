/**
 * guardian_engine.cpp — see guardian_engine.hpp.
 *
 * PR 2 scope: persistence + dispatch only. The engine speaks the wire
 * protocol from `__guard__` commands (push_rules, get_status), serialises
 * rule state into the agent's KvStore as JSON, and reports a pessimistic
 * "all rules compliant" status because no guards are running yet.
 *
 * Rule persistence layout (under KvStore namespace "__guardian__"):
 *   key="rule:<rule_id>"    — JSON blob of the rule (yaml_source + denorm fields)
 *   key="meta:policy_generation" — monotonically increasing uint64 (decimal text)
 *
 * The store is JSON, not SerializeAsString, because KvStore wraps the
 * value in sqlite3_bind_text + sqlite3_column_text — both APIs treat the
 * payload as a NUL-terminated C string and would truncate any embedded
 * null byte that proto wire-format readily produces. JSON is binary-safe
 * over those APIs and matches the storage style used by the rest of the
 * agent codebase.
 */

#include <yuzu/agent/guardian_engine.hpp>
#include <yuzu/agent/guard_file.hpp>
#include <yuzu/agent/guard_registry.hpp>
#include <yuzu/agent/guard_service.hpp>
#include <yuzu/agent/guard_systemd.hpp> // make_service_guard (platform factory)
#include <yuzu/agent/kv_store.hpp>

#include "agent.grpc.pb.h"
#include "guaranteed_state.pb.h"

// rung 7: the spark detection path GuardianEngine wires alongside legacy IGuard.
#include "guardian_convergence_scheduler.hpp"
#include "guardian_drift_event.hpp" // apply_drift_to_event (shared with the spark path)
#include "guardian_journal_heartbeat.hpp" // GuardianJournalStats (item 7 PR-Ag §8)
#include "guardian_lifecycle_journal.hpp" // durable lifecycle journal (item 7 PR-Ag)
#include "guardian_outbox_drain_worker.hpp"
#include "guardian_scope_guard.hpp" // GuardianRollback (terminate-safe rollback)
#include "guardian_spark_backend.hpp"
#include "guardian_spark_bridge.hpp" // spark_spec_from_rule, rule_assertion_from_rule, classify
#include "guardian_spark_runtime.hpp"
#include "guardian_state_reader.hpp"
#include "spark_engine.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::agent {

namespace {

namespace gpb = ::yuzu::guardian::v1;
namespace apb = ::yuzu::agent::v1;

constexpr std::string_view kKvNamespace = "__guardian__";
constexpr std::string_view kRulePrefix  = "rule:";
constexpr std::string_view kKeyGen      = "meta:policy_generation";

constexpr std::string_view kActionPushRules = "push_rules";
constexpr std::string_view kActionGetStatus = "get_status";

// The rollback guard used by wire_spark_engine() (rollback runs on EVERY exit path,
// including a catch handler's own logging throwing - Sol rung-7.5 finding 2) is now
// the shared, terminate-safe GuardianRollback (guardian_scope_guard.hpp): its cleanup
// joins threads / resets shared_ptrs and could throw during unwinding, which a plain
// noexcept ~ScopeExit would turn into std::terminate (rung 7.7b PR-1 item 3 / Sol B3).

std::string hex_encode(const std::string& bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (unsigned char c : bytes) {
        out += kHex[c >> 4];
        out += kHex[c & 0xF];
    }
    return out;
}

std::string hex_decode(std::string_view hex) {
    if (hex.size() % 2 != 0)
        return {};
    auto from_hex = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::string out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        int hi = from_hex(hex[i]);
        int lo = from_hex(hex[i + 1]);
        if (hi < 0 || lo < 0)
            return {};
        out += static_cast<char>((hi << 4) | lo);
    }
    return out;
}

nlohmann::json block_to_json(const gpb::GuardianSpecBlock& b) {
    nlohmann::json j;
    j["type"] = b.type();
    nlohmann::json params = nlohmann::json::object();
    // Iterator form (not `auto& [k,v]`): MSVC C3493s on structured bindings used
    // inside a lambda/function template context.
    for (auto it = b.params().begin(); it != b.params().end(); ++it)
        params[it->first] = it->second;
    j["params"] = params;
    return j;
}

nlohmann::json rule_to_json(const gpb::GuaranteedStateRule& r) {
    nlohmann::json j;
    j["rule_id"]          = r.rule_id();
    j["name"]             = r.name();
    j["yaml_source"]      = r.yaml_source();
    j["version"]          = static_cast<std::uint64_t>(r.version());
    j["enabled"]          = r.enabled();
    j["enforcement_mode"] = r.enforcement_mode();
    j["spark"]            = block_to_json(r.spark());
    j["assertion"]        = block_to_json(r.assertion());
    j["remediation"]      = block_to_json(r.remediation());
    if (!r.signature().empty())
        j["signature_hex"] = hex_encode(r.signature());
    return j;
}

void json_to_block(const nlohmann::json& j, gpb::GuardianSpecBlock* b) {
    if (!j.is_object() || !b) return;
    b->set_type(j.value("type", std::string{}));
    if (j.contains("params") && j["params"].is_object()) {
        const auto& p = j["params"];
        for (auto it = p.begin(); it != p.end(); ++it)
            (*b->mutable_params())[it.key()] =
                it.value().is_string() ? it.value().get<std::string>() : it.value().dump();
    }
}

bool json_to_rule(const nlohmann::json& j, gpb::GuaranteedStateRule& out) {
    if (!j.is_object()) return false;
    out.set_rule_id(j.value("rule_id", std::string{}));
    out.set_name(j.value("name", std::string{}));
    out.set_yaml_source(j.value("yaml_source", std::string{}));
    out.set_version(j.value("version", std::uint64_t{0}));
    out.set_enabled(j.value("enabled", false));
    out.set_enforcement_mode(j.value("enforcement_mode", std::string{}));
    if (j.contains("spark")) json_to_block(j["spark"], out.mutable_spark());
    if (j.contains("assertion")) json_to_block(j["assertion"], out.mutable_assertion());
    if (j.contains("remediation")) json_to_block(j["remediation"], out.mutable_remediation());
    if (j.contains("signature_hex"))
        out.set_signature(hex_decode(j["signature_hex"].get<std::string>()));
    return !out.rule_id().empty();
}

std::string make_rule_key(std::string_view rule_id) {
    std::string k(kRulePrefix);
    k.append(rule_id);
    return k;
}

} // namespace

GuardianEngine::GuardianEngine(KvStore* kv, std::string agent_id, bool prefer_spark)
    : kv_{kv}, agent_id_{std::move(agent_id)}, prefer_spark_{prefer_spark} {}

GuardianEngine::~GuardianEngine() {
    // Explicit (not = default): join the guard worker threads here via stop().
    // Workers call emit_guard_event(), which reads THIS engine's own
    // event_sink_/sink_mtx_/event_seq_ — GuardianEngine members, so they outlive
    // this join regardless of declaration order. NOTE (H4 / #1209): the sink
    // callback also reaches AgentImpl-side state (stream_write_mu_ +
    // guardian_sink_stream_); that is kept safe by AgentImpl declaring `guardian_`
    // AFTER those members (engine tears down — and joins — first) and by
    // AgentImpl::stop() joining guards before its own teardown. stop() is idempotent.
    stop();
}

std::string_view GuardianEngine::kv_namespace() {
    return kKvNamespace;
}

std::expected<void, std::string> GuardianEngine::start_local() {
    std::lock_guard lock(mtx_);
    if (started_) return {};
    // stop() is STICKY: if it already ran (e.g. a SIGTERM / service-stop arrived
    // during boot, before the reordered start_local() at rung 7.7a), do NOT
    // resurrect. Without this, stop() -> start_local() would set started_=true and
    // re-arm cached guards AFTER stop() returned, so stop() would not be truthful
    // (and at rung 7.7b, detection + buffered sends could resume post-stop).
    if (stopped_) return {};
    started_ = true;

    if (!kv_) {
        spdlog::warn("Guardian: KV store unavailable — rule cache will be in-memory only "
                     "(survives only the current process lifetime)");
        return {};
    }

    refresh_count_locked();

    if (auto raw = kv_->get(kKvNamespace, kKeyGen); raw.has_value()) {
        std::uint64_t parsed = 0;
        const auto& s = *raw;
        [[maybe_unused]] auto [_, ec] = std::from_chars(s.data(), s.data() + s.size(), parsed);
        if (ec == std::errc{})
            policy_generation_ = parsed;
    }

    // A2 (restart re-arm). A restarted agent must keep enforcing without waiting
    // for the next server push — re-arm a guard for every cached enabled rule
    // (design §4: enforce cached guards from KV pre-network). Enforcement
    // (write-back) needs no event sink, so it runs immediately; drift events
    // detected before set_event_sink() is wired are dropped (durable buffering
    // is A3). Guards re-armed by a later push replace these. Before this, a
    // restarted agent reported rules present while enforcing nothing.
    // Flush the boot re-arm's staged "armed" records to the durable journal on exit
    // (normal return or an un-firewalled throw). Same terminate-safe always-fire guard as
    // apply_rules; fires with mtx_ still held (declared after the lock).
    GuardianRollback journal_flush;
    journal_flush.fn = [this] { persist_lifecycle_journal_locked(); };

    std::size_t rearmed = 0;
    for (const auto& key : kv_->list(kKvNamespace, kRulePrefix)) {
        auto raw = kv_->get(kKvNamespace, key);
        if (!raw)
            continue;
        gpb::GuaranteedStateRule rule;
        try {
            auto parsed = nlohmann::json::parse(*raw);
            if (!json_to_rule(parsed, rule))
                continue;
        } catch (const nlohmann::json::exception&) {
            continue;
        }
        if (!rule.enabled())
            continue;
        // Arming a legacy guard spawns a std::thread (guard_{file,registry,systemd}.cpp);
        // under thread-or-handle exhaustion that ctor throws std::system_error. This
        // loop runs OUTSIDE the json try above, and start_local()'s caller does not
        // catch, so an uncaught throw here escapes run() and terminates the agent. Since
        // rung 7.7a re-armed cached guards AFTER the SparkEngine's own boot threads, an
        // exhausted host could now hit this on the still-authoritative legacy backend.
        // Degrade per-rule (LOUD error, this rule does not enforce) so the agent survives
        // to arm the rest, rather than terminating the whole process.
        try {
            if (reconcile_rule_locked(rule)) // count only rules that actually armed (either backend)
                ++rearmed;
        } catch (const std::exception& e) {
            spdlog::error("Guardian: rule '{}' failed to re-arm ({}) - NOT enforcing this rule; "
                          "agent continues with the remaining rules",
                          rule.rule_id(), e.what());
        }
    }

    spdlog::info("Guardian engine started (cached_rules={}, re-armed={}, policy_generation={})",
                 rule_count_, rearmed, policy_generation_);
    if (rearmed > 0)
        spdlog::warn("Guardian: {} guard(s) re-armed pre-network — drift remediated before the "
                     "server connection is enforced but NOT reported until reconnect (durable "
                     "event buffering is A3)",
                     rearmed);
    return {};
}

void GuardianEngine::sync_with_server() {
    std::lock_guard lock(mtx_);
    if (!started_) {
        spdlog::warn("Guardian: sync_with_server called before start_local — ignoring");
        return;
    }
    spdlog::info("Guardian engine network-connected (policy_generation={}, rules={})",
                 policy_generation_, rule_count_);
}

void GuardianEngine::stop() {
    std::lock_guard lock(mtx_);
    // Spark teardown FIRST, in this order (rung 7): (1) runtime phase 1 - fast,
    // wakes any bounded reader waiter, makes a concurrent spark event a no-op;
    // (2) the convergence scheduler - joins its lane threads, CV-interruptible
    // so this is prompt, not a multi-minute wait; (3) the drain worker - joins
    // its thread. By the time all three return, spark_runtime_ is refusing new
    // commits, so the external spark_engine_->stop() (owned by agent.cpp,
    // called separately - GuardianEngine never owns spark_engine_ itself) can
    // safely tear down the consumer afterward without racing a live commit.
    // (4) legacy guards, unchanged.
    // Signal the durable-journal paging path to stop BEFORE joining the drain worker, so a
    // concurrent off-mtx_ page (tick / reconnect) bails between batches instead of mutating a
    // post-join window (rev-4.1 #7 stop-race gate).
    if (lifecycle_journal_)
        lifecycle_journal_->request_stop();
    if (spark_runtime_)
        spark_runtime_->begin_stop();
    if (spark_scheduler_)
        spark_scheduler_->stop();
    if (spark_drain_worker_)
        spark_drain_worker_->stop();
    stop_all_guards_locked();
    // Final flush: persist any records a prior failed write left pending, before shutdown —
    // there is no maintenance tick after stop(). Bounded + circuit-broken (worst case one
    // KvStore 5 s busy-timeout). persist_lifecycle_journal_locked does not gate on stopped_,
    // so ordering it here (before stopped_) is for clarity, not correctness.
    persist_lifecycle_journal_locked();
    stopped_ = true;
    started_ = false;
}

static std::int64_t journal_now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

void GuardianEngine::persist_lifecycle_journal_locked() {
    // mtx_ held. Gated: no durable journal work unless spark is the ACTIVE backend and
    // the path is wired (rev-4.1 §7 inertness — at prefer_spark_=false a pre-populated
    // journal is neither written nor touched).
    if (!prefer_spark_ || !spark_runtime_ || !lifecycle_journal_)
        return;
    const auto pending = spark_runtime_->snapshot_pending();
    if (pending.empty())
        return;
    // snapshot released outbox_mu_; persist() does KV I/O holding NO runtime lock (so the
    // WRITE chain never nests outbox_mu_ under KvStore.mu_); erase re-takes outbox_mu_ for
    // ONLY the prefix persist() durably wrote (circuit-broken on the first failure — the
    // rest stay pending for the maintenance-tick retry, C3).
    const std::size_t written = lifecycle_journal_->persist(pending);
    if (written > 0)
        spark_runtime_->erase_persisted_prefix(written);
}

void GuardianEngine::journal_maintenance_tick() {
    std::shared_ptr<GuardianSparkRuntime> rt;
    GuardianLifecycleJournal* journal = nullptr;
    {
        // PHASE 1 (under mtx_): retry any persist a prior write left pending, so a failed
        // write self-heals on the heartbeat with NO new push/reconnect (Sol BLOCKER-4), and
        // capture the runtime + journal for the off-mtx_ phase 2. A no-op after stop().
        std::lock_guard lock(mtx_);
        if (stopped_ || !prefer_spark_)
            return;
        persist_lifecycle_journal_locked();
        rt = spark_runtime_;
        journal = lifecycle_journal_.get();
    }
    // PHASE 2 (OFF mtx_): periodic retention + replay. Bounded by the token bucket + per-pass
    // cap; page_into_window observes the component stopping_ gate, so a late page never
    // mutates the window after stop() joined the drain worker (rev-4.1 #6/#7).
    if (rt && journal) {
        journal->prune(journal_now_ms());
        journal->page_into_window(*rt, journal_now_ms());
    }
}

void GuardianEngine::page_journal() {
    std::shared_ptr<GuardianSparkRuntime> rt;
    GuardianLifecycleJournal* journal = nullptr;
    {
        std::lock_guard lock(mtx_);
        if (stopped_ || !prefer_spark_)
            return;
        rt = spark_runtime_;
        journal = lifecycle_journal_.get();
    }
    if (rt && journal)
        journal->page_into_window(*rt, journal_now_ms());
}

GuardianJournalStats GuardianEngine::journal_stats() const {
    GuardianJournalStats s;
    std::lock_guard lock(mtx_);
    if (spark_runtime_) {
        s.stage_dropped = spark_runtime_->journal_stage_dropped();
        s.stage_failures = spark_runtime_->journal_stage_failures();
        s.field_rejected = spark_runtime_->journal_field_rejected();
        s.clock_rejected = spark_runtime_->journal_clock_rejected();
        s.pending_depth = spark_runtime_->pending_journal_depth();
    }
    if (lifecycle_journal_) {
        s.batches_written = lifecycle_journal_->batches_written();
        s.write_failures = lifecycle_journal_->write_failures();
        s.key_collisions = lifecycle_journal_->key_collisions();
        s.quarantined = lifecycle_journal_->quarantined();
        s.quarantine_failures = lifecycle_journal_->quarantine_failures();
        s.batches_pruned = lifecycle_journal_->batches_pruned();
        s.prune_failures = lifecycle_journal_->prune_failures();
        s.pages = lifecycle_journal_->pages();
        s.records_paged = lifecycle_journal_->records_paged();
        s.sent_labels_written = lifecycle_journal_->sent_labels_written();
        s.evicted_sent_unacked = lifecycle_journal_->evicted_sent_unacked();
        s.evicted_without_send_evidence = lifecycle_journal_->evicted_without_send_evidence();
    }
    return s;
}

std::expected<std::size_t, std::string>
GuardianEngine::apply_rules(const gpb::GuaranteedStatePush& push) {
    std::lock_guard lock(mtx_);
    if (stopped_)
        return std::unexpected("guardian engine stopped");
    if (!kv_)
        return std::unexpected("kv store unavailable");

    // Flush staged lifecycle records to the durable journal on EVERY exit — the normal
    // return, the put_rule early return below, and any un-firewalled throw. GuardianRollback
    // is the codebase's terminate-safe scope guard; left un-committed it becomes an
    // always-fire flush whose dtor swallows a persist-during-unwind throw (records stay
    // pending for the C3 maintenance-tick retry) rather than std::terminate. Declared after
    // the lock so it fires with mtx_ STILL held (reverse-order destruction).
    GuardianRollback journal_flush;
    journal_flush.fn = [this] { persist_lifecycle_journal_locked(); };

    std::size_t applied = 0;
    std::size_t reconcile_failures = 0;
    if (push.full_sync()) {
        const int cleared = kv_->clear(kKvNamespace);
        if (cleared > 0)
            spdlog::info("Guardian: full_sync cleared {} prior rule(s)", cleared);
        // Re-persist the policy generation marker after clear() wiped everything.
        persist_generation_locked();
        // Full sync replaces the active set - tear down BOTH backends before
        // re-arming (rung 7: a spark-attached rule the new push omits must be
        // withdrawn too, not left dangling - Sol's rev-2 review). FIREWALLED like the
        // per-rule reconcile below: stop_all_guards_locked/detach_all allocate (lifecycle
        // enqueue, disarm, Key strings), and a bad_alloc here would otherwise escape
        // apply_rules onto the un-firewalled dispatch/run() thread and abort the whole
        // agent - the same #2037 class the per-rule firewall closes, on the full_sync
        // path (Gate 4 UP-1/UP-14). Count + hold the generation so the server retries,
        // then proceed to re-arm what we can.
        try {
            stop_all_guards_locked();
            if (spark_runtime_)
                spark_runtime_->detach_all();
        } catch (...) {
            ++reconcile_failures;
            arm_failures_.fetch_add(1, std::memory_order_relaxed);
            try {
                spdlog::error("Guardian: full_sync teardown threw - partial teardown, "
                              "holding generation for retry");
            } catch (...) {
            }
        }
    }

    for (const auto& rule : push.rules()) {
        if (rule.rule_id().empty()) {
            spdlog::warn("Guardian: skipping rule with empty rule_id (name={})", rule.name());
            continue;
        }
        if (!put_rule_locked(rule)) {
            return std::unexpected("failed to persist rule '" + rule.rule_id() + "'");
        }
        // Per-rule exception firewall: reconcile can throw (a spark attach OOM, a
        // backend arm that throws) and must NOT abort the whole push and escape to the
        // dispatch caller - an escaped exception on the unguarded ThreadPool task aborts
        // the whole agent (#2037). Degrade loud and continue - the posture start_local()
        // takes for a thread-exhaustion throw. catch(...) not just std::exception, and
        // the log is guarded (spdlog allocates and could itself throw under the bad_alloc
        // that triggered this). (rung 7.7b PR-1 item 3 / Sol B1 + Fable.)
        try {
            reconcile_rule_locked(rule); // step 4: arm/withdraw via the reconcile op (rung 7)
        } catch (...) {
            ++reconcile_failures;
            arm_failures_.fetch_add(1, std::memory_order_relaxed);
            try {
                spdlog::error("Guardian: reconcile threw for rule '{}' - persisted but not armed",
                              rule.rule_id());
            } catch (...) {
            }
            continue; // not counted as applied
        }
        ++applied;
    }

    // Do NOT advance the policy generation when any rule failed to arm. The server's
    // heartbeat reconcile fn re-pushes only while the agent reports a generation BEHIND
    // current (server.cpp), so advancing here would tell the server "caught up" and
    // strand the unarmed rule until restart - a silent enforcement hole on a
    // Guaranteed-State product. Holding the generation keeps the 25s heartbeat retry
    // live so a transient OOM/thread-exhaustion self-heals. (Sol B1 / Fable.) A later
    // successful push can still advance past a persistently-failing rule; arm_failures_
    // (surfaced via the heartbeat, item 9) is the durable fleet-visible signal for that.
    if (reconcile_failures == 0 && push.policy_generation() > policy_generation_) {
        policy_generation_ = push.policy_generation();
        persist_generation_locked();
    }

    refresh_count_locked();
    spdlog::info(
        "Guardian: apply_rules ok (applied={}, failed={}, full_sync={}, generation={}, total={})",
        applied, reconcile_failures, push.full_sync(), policy_generation_, rule_count_);
    return applied;
}

gpb::GuaranteedStateStatus GuardianEngine::get_status() const {
    std::lock_guard lock(mtx_);
    gpb::GuaranteedStateStatus status;
    status.set_agent_id(agent_id_);
    status.set_policy_generation(policy_generation_);
    status.set_total_rules(static_cast<std::uint32_t>(rule_count_));

    // Fail-closed status. An armed guard does NOT prove the watched value is
    // currently compliant, nor that the worker is healthy: the thread may have
    // exited after start() returned, an enforce write may be failing, or the
    // guard may have silently fallen back to read-only. `guard_healthy` is a
    // RESERVED wire field whose safe default is "unknown" (false). So until a
    // real self-test / last-remediation signal exists (deferred — see the richer
    // status-taxonomy follow-up), every rule is reported conservatively: not
    // compliant, not healthy. Under-reporting here is fail-closed; the prior
    // "armed ⇒ compliant/healthy" was the silently-deaf failure class.
    status.set_compliant_rules(0);
    status.set_drifted_rules(0);
    status.set_errored_rules(static_cast<std::uint32_t>(rule_count_));

#if defined(_WIN32)
    status.set_platform("windows");
#elif defined(__APPLE__)
    status.set_platform("macos");
#else
    status.set_platform("linux");
#endif

    if (kv_) {
        for (const auto& key : kv_->list(kKvNamespace, kRulePrefix)) {
            auto raw = kv_->get(kKvNamespace, key);
            if (!raw) continue;
            gpb::GuaranteedStateRule rule;
            try {
                auto parsed = nlohmann::json::parse(*raw);
                if (!json_to_rule(parsed, rule))
                    continue;
            } catch (const nlohmann::json::exception&) {
                continue;
            }
            auto* row = status.add_rules();
            row->set_rule_id(rule.rule_id());
            row->set_status("errored");
            row->set_guard_category("event");
            row->set_guard_healthy(false);
            row->set_notifications_total(0);
        }
    }
    return status;
}

GuardianDispatchResult GuardianEngine::dispatch(const apb::CommandRequest& cmd) {
    GuardianDispatchResult res;

    if (cmd.action() == kActionPushRules) {
        // The serialized GuaranteedStatePush rides in the `payload` bytes field, not
        // the `parameters` string map: proto3 string-map values must be valid UTF-8,
        // and raw proto bytes are not (the server's UTF-8 validator rejects the whole
        // CommandRequest before it reaches us). `bytes` is binary-safe across embedded
        // NUL bytes. The Erlang gateway preserves `payload` end-to-end: field 8 is
        // mirrored into its vendored agent.proto and it forwards the decoded request
        // straight through gpb (proven by yuzu_gw_guardian_wire_tests). Works in both
        // direct and gateway mode. See agent.proto CommandRequest.payload + G12.
        const std::string& push_bytes = cmd.payload();
        if (push_bytes.empty()) {
            res.exit_code = 1;
            res.content_type = "text";
            res.output = "missing payload (expected serialized GuaranteedStatePush)";
            return res;
        }
        gpb::GuaranteedStatePush push;
        if (!push.ParseFromString(push_bytes)) {
            res.exit_code = 2;
            res.content_type = "text";
            res.output = "failed to parse GuaranteedStatePush proto";
            return res;
        }
        auto applied = apply_rules(push);
        if (!applied) {
            res.exit_code = 3;
            res.content_type = "text";
            res.output = applied.error();
            return res;
        }
        res.exit_code = 0;
        res.content_type = "text";
        res.output = "applied=" + std::to_string(*applied) +
                     " generation=" + std::to_string(policy_generation()) +
                     " total=" + std::to_string(rule_count());
        return res;
    }

    if (cmd.action() == kActionGetStatus) {
        auto status = get_status();
        res.exit_code = 0;
        res.content_type = "proto";
        res.output = status.SerializeAsString();
        return res;
    }

    res.exit_code = 4;
    res.content_type = "text";
    res.output = "unknown __guard__ action: " + cmd.action();
    return res;
}

std::size_t GuardianEngine::rule_count() const {
    std::lock_guard lock(mtx_);
    return rule_count_;
}

std::size_t GuardianEngine::armed_guard_count() const {
    std::lock_guard lock(mtx_);
    return guards_.size();
}

std::size_t GuardianEngine::spark_armed_rule_count() const {
    std::lock_guard lock(mtx_);
    return spark_runtime_ ? spark_runtime_->rule_count() : 0;
}

std::uint64_t GuardianEngine::policy_generation() const {
    std::lock_guard lock(mtx_);
    return policy_generation_;
}

bool GuardianEngine::put_rule_locked(const gpb::GuaranteedStateRule& rule) {
    if (!kv_) return false;
    auto j = rule_to_json(rule).dump();
    return kv_->set(kKvNamespace, make_rule_key(rule.rule_id()), j);
}

void GuardianEngine::refresh_count_locked() {
    if (!kv_) {
        rule_count_ = 0;
        return;
    }
    rule_count_ = kv_->list(kKvNamespace, kRulePrefix).size();
}

void GuardianEngine::persist_generation_locked() {
    if (!kv_) return;
    kv_->set(kKvNamespace, kKeyGen, std::to_string(policy_generation_));
}

void GuardianEngine::set_event_sink(EventSink sink) {
    std::lock_guard lock(sink_mtx_);
    event_sink_ = std::move(sink);
}

void GuardianEngine::emit_guard_event(const GuardDrift& d) {
    // Snapshot the sink under sink_mtx_, then release BEFORE the (potentially
    // blocking) network send — never hold the lock across the sink call, and
    // never take mtx_ here (a guard worker can fire while apply_rules/stop hold
    // mtx_ and join this thread).
    EventSink sink;
    {
        std::lock_guard lock(sink_mtx_);
        sink = event_sink_;
    }
    if (!sink)
        return; // sink not wired yet (pre-network arm) — drop; durable buffering is A3

    const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();
    const auto seq = event_seq_.fetch_add(1, std::memory_order_relaxed);
    gpb::GuaranteedStateEvent ev;
    // event_id folds in agent_id_ because the server's events table keys on a
    // GLOBAL `event_id` PRIMARY KEY and drops on UNIQUE conflict (#1307). Without
    // agent_id, two agents drifting on the same rule in the same millisecond mint
    // an identical id (rule_id-{ms}-{seq}, seq being a per-agent counter that both
    // start at 0) → the server silently keeps one and loses the rest during a
    // fleet-wide drift wave. For any non-empty agent_id the agent_id segment
    // guarantees cross-agent distinctness regardless of clock skew; a degenerate
    // empty agent_id (pre-Register, before sync_with_server populates it) folds
    // in nothing and reverts to the old per-(rule,ms,seq) collision class — the
    // durable fix for that residual is the server-side composite key #1360. (The
    // crash/observation path landing with the DEX slice uses the same
    // {discriminator}-{agent_id}-{ms}-{seq} layout — keep them aligned.)
    ev.set_event_id(d.rule_id + "-" + agent_id_ + "-" + std::to_string(now_ms) + "-" +
                    std::to_string(seq));
    ev.set_rule_id(d.rule_id);
    ev.set_guard_category("event");
    // rule_name / guard_type / detected_value / expected_value / detection_latency_us,
    // the 4-way event_type cascade (+ remediation fields) and drift_rate are shared
    // byte-for-byte with the spark consumer's Compliance branch — set them from the
    // single apply_drift_to_event source of truth so the two producers cannot drift
    // apart (#2237 item 1). event_id, rule_id, guard_category, timestamp and platform
    // stay stamped here (idempotency- and host-specific).
    apply_drift_to_event(d, ev);
    ev.mutable_timestamp()->set_seconds(now_ms / 1000);
    // Stamp the agent's real platform (mirrors get_status) — not a hardcoded
    // "windows", which would mislabel every drift event once Linux/macOS guards land.
#if defined(_WIN32)
    ev.set_platform("windows");
#elif defined(__APPLE__)
    ev.set_platform("macos");
#else
    ev.set_platform("linux");
#endif
    sink(ev);
}

void GuardianEngine::stop_all_guards_locked() {
    for (auto& kv : guards_)
        if (kv.second) kv.second->stop();
    guards_.clear();
}

void GuardianEngine::withdraw_legacy_guard_locked(const std::string& rule_id) {
    if (auto it = guards_.find(rule_id); it != guards_.end()) {
        if (it->second)
            it->second->stop();
        guards_.erase(it);
    }
}

bool GuardianEngine::start_guard_for_rule_locked(const gpb::GuaranteedStateRule& rule) {
    // Spark dispatch. Each Spark type maps to a guard implementation, all no-op off
    // Windows for the MVP. Returns true iff a guard was actually armed (so callers
    // can count accurately).

    // Retire any guard already armed for this rule_id BEFORE validating/arming the
    // new definition below. Each branch used to do this find-stop-erase only on its
    // happy path, AFTER the type/assertion checks - so a same-id re-push whose new
    // assertion failed validation (an unsupported type, an unrecognized spark type)
    // returned false early and left the PRIOR guard running, silently enforcing a
    // stale definition the caller believes was replaced (apply_rules persists the
    // new rule to KV regardless of whether it arms). Hoisting this here means every
    // return path - early-invalid, late-failed-start, or success - starts from a
    // clean slate, so an unarmed/errored outcome is genuinely unarmed.
    withdraw_legacy_guard_locked(rule.rule_id());

    // ── file-change Spark (Change B) — realtime file watch via FileGuard ──────
    if (rule.spark().type() == "file-change") {
        const auto& fa = rule.assertion();
        const std::string atype = fa.type();
        if (atype != "file-exists" && atype != "file-hash-equals")
            return false; // unknown assertion stays unarmed (G11: errored upstream)
        auto aparam = [&fa](const char* k) -> std::string {
            auto it = fa.params().find(k);
            return it != fa.params().end() ? it->second : std::string{};
        };
        auto aparam_u64 = [&aparam](const char* k, std::uint64_t dflt) -> std::uint64_t {
            const std::string v = aparam(k);
            if (v.empty())
                return dflt;
            std::uint64_t out = dflt;
            auto [p, ec] = std::from_chars(v.data(), v.data() + v.size(), out);
            // Whole-string only: "123abc" → default, not 123 (M1 — symmetric with the
            // server validator and resilience_strategy::to_u64).
            return (ec == std::errc{} && p == v.data() + v.size()) ? out : dflt;
        };
        FileGuard::Config fcfg;
        fcfg.rule_id = rule.rule_id();
        fcfg.rule_name = rule.name();
        fcfg.path = aparam("path");
        if (atype == "file-hash-equals") {
            // Content-change detection: drift when size + SHA-256 differ from the
            // expected hash (empty → baseline captured on arm). max_bytes caps the
            // hashing-DoS; settle_ms coalesces mid-write notifications.
            fcfg.assertion = FileGuard::Assertion::HashEquals;
            fcfg.expected_hash = aparam("expected_hash");
            for (auto& c : fcfg.expected_hash) // normalise to the lowercase hex sha256_file emits
                if (c >= 'A' && c <= 'Z')
                    c = static_cast<char>(c - 'A' + 'a');
            const std::uint64_t default_max_bytes = fcfg.max_hash_bytes;
            fcfg.max_hash_bytes = aparam_u64("max_bytes", default_max_bytes);
            // A 0 cap would report every covered file as <oversize> (never hashed,
            // perpetual false "compliant"/"drift") — treat 0 as unset and keep the
            // default cap. The server rejects max_bytes:"0" at authoring; this is the
            // agent-side backstop (M1).
            if (fcfg.max_hash_bytes == 0)
                fcfg.max_hash_bytes = default_max_bytes;
            fcfg.settle_ms = aparam_u64("settle_ms", fcfg.settle_ms);
        } else {
            // file-exists: "absent" → drift when the file EXISTS; anything else
            // (default "present") → drift when the file is missing / has been deleted.
            fcfg.assertion = FileGuard::Assertion::Exists;
            fcfg.expect_present = (aparam("expected") != "absent");
        }
        // The event-debounce window shares remediation.params with the resilience
        // keys; a file guard is detection-only, so the resilience MODES do not apply
        // — only event_debounce_ms is read (single-sourced via parse_resilience_params,
        // the returned ResilienceConfig is intentionally discarded).
        const auto& frem = rule.remediation();
        auto fget = [&frem](std::string_view k) -> std::string {
            auto it = frem.params().find(std::string(k));
            return it != frem.params().end() ? it->second : std::string{};
        };
        parse_resilience_params(fget, fcfg.event_debounce_ms);
        const std::string log_path = fcfg.path;
        const std::string log_mode =
            atype == "file-hash-equals"
                ? std::string("hash-equals")
                : std::string(fcfg.expect_present ? "expect present" : "expect absent");

        auto file_sink = [this](const GuardDrift& d) { emit_guard_event(d); };
        // (prior guard for this rule_id already retired at function entry)
        auto fguard = std::make_unique<FileGuard>(std::move(fcfg), std::move(file_sink));
        if (fguard->start()) {
            guards_.emplace(rule.rule_id(), std::move(fguard));
            spdlog::info("Guardian: file guard armed for rule '{}' (path={}, {})", rule.rule_id(),
                         log_path, log_mode);
            return true;
        }
        spdlog::warn("Guardian: file guard for rule '{}' did not start (non-Windows or empty path)",
                     rule.rule_id());
        return false;
    }

    // ── service-status-change Spark (PR5) — ServiceGuard ──────────────────────
    if (rule.spark().type() == "service-status-change") {
        const auto& sa = rule.assertion();
        const std::string atype = sa.type();
        ServiceGuard::Desired desired;
        if (atype == "service-running")
            desired = ServiceGuard::Desired::Running;
        else if (atype == "service-stopped")
            desired = ServiceGuard::Desired::Stopped;
        else
            return false; // unknown/unsupported assertion stays unarmed (G11: errored upstream)
        auto aparam = [&sa](const char* k) -> std::string {
            auto it = sa.params().find(k);
            return it != sa.params().end() ? it->second : std::string{};
        };
        const bool enforce = (rule.enforcement_mode() == "enforce");
        ServiceGuard::Config cfg;
        cfg.rule_id = rule.rule_id();
        cfg.rule_name = rule.name();
        cfg.service_name = aparam("service_name");
        cfg.desired = desired;
        // "enforce" → drive the service to its desired state on drift; any other mode
        // (audit / observe) only detects and reports.
        cfg.enforce = enforce;
        const auto& srem = rule.remediation();
        auto sget = [&srem](std::string_view k) -> std::string {
            auto it = srem.params().find(std::string(k));
            return it != srem.params().end() ? it->second : std::string{};
        };
        cfg.resilience = parse_resilience_params(sget, cfg.event_debounce_ms);
        const std::string log_service = cfg.service_name; // captured before the move below

        auto service_sink = [this](const GuardDrift& d) { emit_guard_event(d); };
        // (prior guard for this rule_id already retired at function entry)
        // Platform factory: Windows SCM ServiceGuard or Linux systemd
        // SystemdServiceGuard, both IGuard. Keeps this dispatch platform-clean.
        auto sguard = make_service_guard(std::move(cfg), std::move(service_sink));
        if (sguard->start()) {
            guards_.emplace(rule.rule_id(), std::move(sguard));
            // Honest mode label: the Linux systemd guard is observe-only in v1, so an
            // enforce-authored rule observes (it logs its own downgrade too) — don't
            // claim "enforce" on a platform that won't remediate (happy-path Q4).
            const char* mode = enforce ? "enforce" : "audit";
#if defined(__linux__)
            if (enforce)
                mode = "enforce (observe-only on Linux)";
#endif
            spdlog::info("Guardian: service guard armed for rule '{}' (service={}, expect={}, mode={})",
                         rule.rule_id(), log_service,
                         desired == ServiceGuard::Desired::Running ? "running" : "stopped", mode);
            return true;
        }
        spdlog::warn("Guardian: service guard for rule '{}' did not start "
                     "(unsupported platform / no service-control backend / invalid service name)",
                     rule.rule_id());
        return false;
    }

    // ── registry-change Spark (C1/C2) — RegistryGuard ─────────────────────────
    if (rule.spark().type() != "registry-change")
        return false;
    const auto& a = rule.assertion();
    if (a.type() != "registry-value-equals")
        return false;
    auto param = [&a](const char* k) -> std::string {
        auto it = a.params().find(k);
        return it != a.params().end() ? it->second : std::string{};
    };
    const bool enforce = (rule.enforcement_mode() == "enforce");
    RegistryGuard::Config cfg;
    cfg.rule_id    = rule.rule_id();
    cfg.rule_name  = rule.name();
    cfg.hive       = param("hive");
    cfg.key        = param("key");
    cfg.value_name = param("value_name");
    cfg.value_type = param("value_type");
    cfg.expected   = param("expected");
    // "enforce" → the guard writes `expected` back on drift; any other mode
    // (audit / observe) only detects and reports.
    cfg.enforce    = enforce;

    // C3: per-rule resilience policy + debounce live in the remediation block's params
    // (design §8.5; canonical keys + parsing in resilience_strategy.hpp — the single
    // source of truth the C3b schema and C3c form must match). Absent → defaults
    // (Persist + 1s debounce), so existing rules keep their pre-C3 behaviour. The proto
    // Map .find runs INSIDE this DLL, so parse_resilience_params stays proto-free.
    const auto& rem = rule.remediation();
    auto get = [&rem](std::string_view k) -> std::string {
        auto it = rem.params().find(std::string(k));
        return it != rem.params().end() ? it->second : std::string{};
    };
    cfg.resilience = parse_resilience_params(get, cfg.event_debounce_ms);

    // Route drift through the engine rather than a captured sink copy, so a
    // guard armed before the sink is wired (A2 start_local pre-network) still
    // delivers once set_event_sink runs. emit_guard_event takes sink_mtx_ only.
    auto guard_sink = [this](const GuardDrift& d) { emit_guard_event(d); };

    // (prior guard for this rule_id already retired at function entry)
    auto guard = std::make_unique<RegistryGuard>(std::move(cfg), std::move(guard_sink));
    if (guard->start()) {
        guards_.emplace(rule.rule_id(), std::move(guard));
        spdlog::info("Guardian: registry guard armed for rule '{}' (mode={})", rule.rule_id(),
                     enforce ? "enforce" : "audit");
        return true;
    }
    spdlog::warn("Guardian: registry guard for rule '{}' did not start "
                 "(non-Windows or invalid hive)",
                 rule.rule_id());
    return false;
}

bool GuardianEngine::reconcile_rule_locked(const gpb::GuaranteedStateRule& rule) {
    if (!rule.enabled()) {
        if (spark_runtime_)
            spark_runtime_->detach_rule(rule.rule_id());
        withdraw_legacy_guard_locked(rule.rule_id());
        return false;
    }

    // VALIDATION FIRST, before any capability/preference question: an
    // authoring fault (an unrecognized spark type, a spark-type/assertion-
    // type mismatch, a missing required target param) must never be
    // mislabeled as a routine platform gap (Sol's rev-2 review flagged the
    // original ordering as backwards). A rule that fails validation is
    // withdrawn from both backends; get_status()'s existing universal
    // "errored" fail-closed behaviour already represents this correctly - no
    // separate error-reason tracking exists yet (deferred to a later rung
    // that wires status_for_rule() into a more granular get_status()).
    auto assertion = rule_assertion_from_rule(rule);
    auto spec = spark_spec_from_rule(rule);
    if (!assertion || !spec) {
        // A validation-rejected rule is withdrawn from BOTH backends with no
        // diagnostic at all otherwise - unlike every legacy arm-failure path,
        // which always spdlog::warns with the rule_id and a reason. Silent
        // withdrawal here means an operator sees a rule stop being enforced
        // (e.g. on the next restart re-arm pass) with nothing in the log to
        // explain why (sre Gate 6 finding, this PR).
        spdlog::warn("Guardian: rule '{}' failed spark validation ({}) - withdrawing from "
                     "both detection paths",
                     rule.rule_id(),
                     !assertion ? assertion.error() : "spec derivation failed for spark type '" +
                                                           rule.spark().type() + "'");
        if (spark_runtime_)
            spark_runtime_->detach_rule(rule.rule_id());
        withdraw_legacy_guard_locked(rule.rule_id());
        return false;
    }

    // spark_availability_ is set exactly once by wire_spark_engine() and never
    // changes afterward. prefer_spark_ is immutable for this object's
    // lifetime. SparkFailed and Unwired NEVER fall back to legacy - a failure
    // must be visible (errored), never silently absorbed (mutual exclusion).
    if (prefer_spark_ && (spark_availability_ == SparkAvailability::SparkFailed ||
                          spark_availability_ == SparkAvailability::Unwired)) {
        withdraw_legacy_guard_locked(rule.rule_id());
        return false;
    }

    const bool try_spark = prefer_spark_ && spark_availability_ == SparkAvailability::Available;
    if (try_spark) {
        // Capability set: registered AND functional (non-inert) mechanisms
        // only - mirrors spark_heartbeat.hpp's own inert-filtering exactly,
        // so a mechanism that started but could not bind its OS facility is
        // never misclassified as armable (Sol's rev-2 review).
        std::set<SparkType> supported;
        if (spark_engine_)
            for (const auto& [type, ms] : spark_engine_->stats_by_type())
                if (!ms.inert)
                    supported.insert(type);
        const RulePlacement placement = classify(rule.spark().type(), supported);
        if (placement == RulePlacement::Arm) {
            withdraw_legacy_guard_locked(rule.rule_id());
            auto gen = spark_runtime_->attach_rule(rule.rule_id(), std::move(*spec),
                                                   std::move(*assertion),
                                                   /*emit_compliant_edge=*/true);
            if (gen)
                return true; // armed; attach_rule already enqueued its own "armed" audit entry
            // Arm failure: errored, NEVER a fallback to legacy (mutual exclusion).
            spdlog::warn("Guardian: spark arm failed for rule '{}': {}", rule.rule_id(),
                         gen.error());
            spark_runtime_->detach_rule(rule.rule_id()); // defensive; attach_rule leaves nothing on failure
            return false;
        }
        if (placement == RulePlacement::Unrecognized) {
            // Structurally unreachable here: spec/assertion validation above
            // already rejected an unrecognized spark type before this point
            // is ever reached. Kept as an explicit branch (not folded into
            // the Unsupported fallthrough below) so a future reordering of
            // the validation step cannot silently start treating an
            // authoring fault as a routine legacy fallback.
            if (spark_runtime_)
                spark_runtime_->detach_rule(rule.rule_id());
            withdraw_legacy_guard_locked(rule.rule_id());
            return false;
        }
        // placement == Unsupported: a ROUTINE cross-platform gap (a known
        // type, no mechanism on THIS host) - legacy is the correct, expected
        // outcome here, not a failure. Falls through to the legacy arm below.
    }

    if (spark_runtime_)
        spark_runtime_->detach_rule(rule.rule_id()); // harmless no-op if never attached
    return start_guard_for_rule_locked(rule); // existing legacy path, UNCHANGED
}

void GuardianEngine::wire_spark_engine(SparkEngine* engine, bool spark_disabled_by_config,
                                       std::function<SendResult(const OutboxEntry&)> send) {
    std::lock_guard lock(mtx_);
    // stop() is STICKY (see start_local): if a stop already ran during boot, do NOT
    // start any spark machinery. Leaving spark_availability_ Unwired is correct - the
    // agent is shutting down and there is nothing to detect with.
    if (stopped_) {
        spdlog::info("Guardian: wire_spark_engine() after stop() - not wiring (shutdown in "
                     "progress); spark stays Unwired");
        return;
    }
    if (spark_availability_ != SparkAvailability::Unwired) {
        spdlog::warn("Guardian: wire_spark_engine() called more than once - ignoring (already {})",
                     spark_availability_ == SparkAvailability::Available ? "Available"
                     : spark_availability_ == SparkAvailability::SparkFailed ? "SparkFailed"
                                                                             : "SparkDisabled");
        return;
    }
    if (spark_disabled_by_config) {
        spark_availability_ = SparkAvailability::SparkDisabled;
        spdlog::info("Guardian: spark path disabled by --spark-disable - legacy IGuard is the "
                     "sole detection path");
        return;
    }
    if (!engine) {
        spark_availability_ = SparkAvailability::SparkFailed;
        spdlog::warn("Guardian: spark_engine_ failed to boot - spark path unavailable; legacy "
                     "IGuard is the sole detection path (never silently substituted)");
        return;
    }

    // All-or-nothing wiring transaction. `registered` tracks whether
    // register_consumer() succeeded, so the guard below knows whether it must
    // unregister on a LATER step's failure (scheduler/drain-worker
    // construction, which can throw - both spawn threads).
    bool registered = false;
    SparkEngine::ConsumerId consumer_id = 0;
    // Runs rollback_spark_wiring_locked() on ANY exit from this point on -
    // an early return, an exception unwinding out of the try below, or a
    // catch handler's own spdlog::warn call itself throwing - unless
    // `committed` is set at the very end of the success path. Declaring this
    // OUTSIDE the try/catch, before either branch runs, is what guarantees
    // the destructor always fires (Sol rung-7.5 review finding 2: the prior
    // explicit rollback_spark_wiring_locked() call inside each catch block
    // could be skipped if the logging call ahead of it threw).
    GuardianRollback rollback;
    rollback.fn = [this, engine, &registered, &consumer_id] {
        rollback_spark_wiring_locked(engine, registered, consumer_id);
    };
    try {
        spark_reader_ = std::make_shared<GuardianStateReader>();
        spark_backend_ = std::make_shared<GuardianSparkEngineBackend>(*engine);
        spark_runtime_ = std::make_shared<GuardianSparkRuntime>(spark_reader_, spark_backend_);
        // The durable journal is engine-owned and borrows kv_ (may be null → it durably
        // writes nothing). Constructed whenever spark is wired; persist stays gated on
        // prefer_spark_ in persist_lifecycle_journal_locked, so it is inert at 7.7a.
        lifecycle_journal_ = std::make_unique<GuardianLifecycleJournal>(kv_);

        auto id = engine->register_consumer("guardian-spark",
                                            GuardianSparkRuntime::make_handler(spark_runtime_));
        if (!id) {
            spdlog::warn("Guardian: spark consumer registration failed ({}) - spark path "
                         "unavailable",
                         id.error());
            return; // rollback's destructor cleans up (registered is still false)
        }
        consumer_id = *id;
        registered = true;
        spark_backend_->bind_consumer(consumer_id);

        spark_scheduler_ = std::make_unique<ConvergenceScheduler>(*spark_runtime_);
        // Wrap the send so that after a PAGED batch's LAST entry is delivered, its best-effort
        // sent-label is written (item 7 PR-Ag). The wrap runs on the drain-worker thread, which
        // stop() joins before teardown, so capturing `this` + lifecycle_journal_ is safe (see
        // the drain-worker doc). Live / compliance / health entries carry no batch key → no-op.
        auto journaled_send = [this, send = std::move(send)](const OutboxEntry& e) -> SendResult {
            const SendResult r = send(e);
            if (r == SendResult::Sent && e.journal_last_in_batch && !e.journal_batch_key.empty() &&
                lifecycle_journal_)
                lifecycle_journal_->mark_batch_sent(e.journal_batch_key);
            return r;
        };
        spark_drain_worker_ = std::make_unique<GuardianOutboxDrainWorker>(
            *spark_runtime_, std::move(journaled_send));
        // Start the convergence + drain machinery ONLY when spark is the ACTIVE
        // detection backend (prefer_spark_). At prefer_spark_=false (rung 7.7a: spark
        // wired but legacy authoritative) no rule ever places on spark, so the outbox
        // never fills and the convergence lanes are empty - their 5 threads would be
        // pure overhead AND would claim thread budget ahead of the still-authoritative
        // legacy backend, whose re-arm (start_local) follows wiring at boot. rung 7.7b
        // (prefer_spark_=true) starts them here. stop() calls their stop()
        // unconditionally, a no-op on an unstarted scheduler/drain. (start() may throw:
        // it spawns threads - hence the ScopeExit rollback above.)
        if (prefer_spark_) {
            spark_scheduler_->start();
            spark_drain_worker_->start();
        }

        spark_engine_ = engine;
        spark_availability_ = SparkAvailability::Available;
        rollback.committed = true;
        spdlog::info("Guardian: spark path wired and available (consumer_id={})", consumer_id);
    } catch (const std::exception& e) {
        spdlog::warn("Guardian: spark wiring failed ({}) - rolling back, spark path unavailable",
                     e.what());
    } catch (...) {
        // Belt-and-braces: nothing may terminate the agent for this
        // best-effort subsystem, even a non-std throw.
        spdlog::warn("Guardian: spark wiring failed (unknown exception) - rolling back, spark "
                     "path unavailable");
    }
}

void GuardianEngine::rollback_spark_wiring_locked(SparkEngine* engine, bool registered,
                                                  std::uint64_t consumer_id) {
    // Unwind in the reverse order construction attempted them. Each step is
    // independently null-safe, so this is correct regardless of exactly how
    // far the wiring sequence got before it threw.
    if (spark_drain_worker_)
        spark_drain_worker_->stop();
    spark_drain_worker_.reset();
    if (spark_scheduler_)
        spark_scheduler_->stop();
    spark_scheduler_.reset();
    if (spark_runtime_)
        spark_runtime_->begin_stop();
    spark_runtime_.reset();
    spark_backend_.reset();
    spark_reader_.reset();
    if (registered)
        engine->unregister_consumer(consumer_id);
    spark_engine_ = nullptr;
    spark_availability_ = SparkAvailability::SparkFailed;
}

GuardianEngine::SparkAvailability GuardianEngine::spark_availability() const {
    std::lock_guard lock(mtx_);
    return spark_availability_;
}

std::size_t GuardianEngine::active_io_workers() const {
    std::lock_guard lock(mtx_);
    return spark_reader_ ? spark_reader_->active_io_workers() : 0;
}

// #501: Test-support helper — see guardian_engine.hpp for the full rationale.
// The CommandRequest construction happens INSIDE yuzu_agent_core.dll (where
// this TU compiles). The push payload now rides in the `payload` bytes field
// (a plain string field, not a Map), so the absl::HashOf-seed split that
// motivated this helper no longer applies to the payload itself — but the
// helper still usefully parses the GuaranteedStatePush (whose nested `params`
// Map IS hashed) inside the DLL during dispatch()→apply_rules(), so keep it.
GuardianDispatchResult
guardian_dispatch_push_bytes_for_test(GuardianEngine& engine,
                                      std::string_view push_param_bytes) {
    apb::CommandRequest cmd;
    cmd.set_command_id("test-dispatch");
    cmd.set_plugin("__guard__");
    cmd.set_action(std::string{kActionPushRules});
    cmd.set_payload(std::string{push_param_bytes});
    return engine.dispatch(cmd);
}

// Test-support helper — see guardian_engine.hpp. Friend of GuardianEngine so it
// can reach the private emit_guard_event(); production drift only ever enters
// that method from a guard worker's sink lambda (see start_guard_for_rule_locked).
void guardian_emit_drift_for_test(GuardianEngine& engine, const GuardDrift& drift) {
    engine.emit_guard_event(drift);
}

} // namespace yuzu::agent
