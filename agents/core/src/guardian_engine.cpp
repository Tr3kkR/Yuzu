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

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>
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

GuardianEngine::GuardianEngine(KvStore* kv, std::string agent_id)
    : kv_{kv}, agent_id_{std::move(agent_id)} {}

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
    started_ = true;
    stopped_ = false;

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
        if (start_guard_for_rule_locked(rule)) // count only guards that actually armed
            ++rearmed;
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
    stop_all_guards_locked();
    stopped_ = true;
    started_ = false;
}

std::expected<std::size_t, std::string>
GuardianEngine::apply_rules(const gpb::GuaranteedStatePush& push) {
    std::lock_guard lock(mtx_);
    if (stopped_)
        return std::unexpected("guardian engine stopped");
    if (!kv_)
        return std::unexpected("kv store unavailable");

    if (push.full_sync()) {
        const int cleared = kv_->clear(kKvNamespace);
        if (cleared > 0)
            spdlog::info("Guardian: full_sync cleared {} prior rule(s)", cleared);
        // Re-persist the policy generation marker after clear() wiped everything.
        persist_generation_locked();
        // Full sync replaces the active set — tear down guards before re-arming.
        stop_all_guards_locked();
    }

    std::size_t applied = 0;
    for (const auto& rule : push.rules()) {
        if (rule.rule_id().empty()) {
            spdlog::warn("Guardian: skipping rule with empty rule_id (name={})", rule.name());
            continue;
        }
        if (!put_rule_locked(rule)) {
            return std::unexpected("failed to persist rule '" + rule.rule_id() + "'");
        }
        start_guard_for_rule_locked(rule); // step 4: arm the on-box guard
        ++applied;
    }

    if (push.policy_generation() > policy_generation_) {
        policy_generation_ = push.policy_generation();
        persist_generation_locked();
    }

    refresh_count_locked();
    spdlog::info("Guardian: apply_rules ok (applied={}, full_sync={}, generation={}, total={})",
                 applied, push.full_sync(), policy_generation_, rule_count_);
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
    ev.set_rule_name(d.rule_name);
    ev.set_guard_type(d.guard_type); // "registry" | "file" — set by the producing guard
    ev.set_guard_category("event");
    ev.set_detected_value(d.detected_value);
    ev.set_expected_value(d.expected_value);
    ev.set_detection_latency_us(d.detection_latency_us);
    if (d.compliant) {
        // Compliant transition (Slice B): the watched state is at / returned to
        // expected. No remediation fields — a compliant edge is never a write-back.
        // The server buckets guard.compliant + drift.remediated → compliant; the
        // guard only emits this on the edge, so steady state adds zero traffic.
        ev.set_event_type("guard.compliant");
    } else if (d.remediation_attempted) {
        ev.set_remediation_action(d.remediation_action);
        ev.set_remediation_success(d.remediation_success);
        ev.set_remediation_latency_us(d.remediation_latency_us);
        // drift.remediated = write-back restored the value; remediation.failed =
        // enforce attempted but the write did not succeed (e.g. read-only-fallback
        // key, denied ACL). Both are in the frozen taxonomy and the dashboard
        // renderer styles them; remediation.failed keeps a failed enforce visibly
        // distinct from a passive detection so the operator sees enforcement is
        // not working, not just that drift exists.
        ev.set_event_type(d.remediation_success ? "drift.remediated" : "remediation.failed");
    } else {
        ev.set_event_type("drift.detected");
    }
    // drift_rate carries the count of ADDITIONAL drift detections the agent-side
    // sink debounce collapsed into this single event over its window (H3 / #1209):
    // 0 = sole detection in its window; a high value means a competing writer was
    // churning the value and the burst was folded to keep the event store bounded.
    if (d.collapsed_count > 0)
        ev.set_drift_rate(static_cast<double>(d.collapsed_count));
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

bool GuardianEngine::start_guard_for_rule_locked(const gpb::GuaranteedStateRule& rule) {
    // Spark dispatch. Each Spark type maps to a guard implementation, all no-op off
    // Windows for the MVP. Returns true iff a guard was actually armed (so callers
    // can count accurately).

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
        if (auto it = guards_.find(rule.rule_id()); it != guards_.end()) {
            if (it->second)
                it->second->stop();
            guards_.erase(it);
        }
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
        if (auto it = guards_.find(rule.rule_id()); it != guards_.end()) {
            if (it->second)
                it->second->stop();
            guards_.erase(it);
        }
        // Platform factory: Windows SCM ServiceGuard or Linux systemd
        // SystemdServiceGuard, both IGuard. Keeps this dispatch platform-clean.
        auto sguard = make_service_guard(std::move(cfg), std::move(service_sink));
        if (sguard->start()) {
            guards_.emplace(rule.rule_id(), std::move(sguard));
            spdlog::info("Guardian: service guard armed for rule '{}' (service={}, expect={}, mode={})",
                         rule.rule_id(), log_service,
                         desired == ServiceGuard::Desired::Running ? "running" : "stopped",
                         enforce ? "enforce" : "audit");
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

    if (auto it = guards_.find(rule.rule_id()); it != guards_.end()) {
        if (it->second)
            it->second->stop();
        guards_.erase(it);
    }
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
