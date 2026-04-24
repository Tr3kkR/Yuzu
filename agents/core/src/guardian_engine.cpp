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

constexpr std::string_view kParamPush = "push";

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

nlohmann::json rule_to_json(const gpb::GuaranteedStateRule& r) {
    nlohmann::json j;
    j["rule_id"]          = r.rule_id();
    j["name"]             = r.name();
    j["yaml_source"]      = r.yaml_source();
    j["version"]          = static_cast<std::uint64_t>(r.version());
    j["enabled"]          = r.enabled();
    j["enforcement_mode"] = r.enforcement_mode();
    if (!r.signature().empty())
        j["signature_hex"] = hex_encode(r.signature());
    return j;
}

bool json_to_rule(const nlohmann::json& j, gpb::GuaranteedStateRule& out) {
    if (!j.is_object()) return false;
    out.set_rule_id(j.value("rule_id", std::string{}));
    out.set_name(j.value("name", std::string{}));
    out.set_yaml_source(j.value("yaml_source", std::string{}));
    out.set_version(j.value("version", std::uint64_t{0}));
    out.set_enabled(j.value("enabled", false));
    out.set_enforcement_mode(j.value("enforcement_mode", std::string{}));
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

GuardianEngine::~GuardianEngine() = default;

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
        auto [_, ec] = std::from_chars(s.data(), s.data() + s.size(), parsed);
        if (ec == std::errc{})
            policy_generation_ = parsed;
    }

    spdlog::info("Guardian engine started (cached_rules={}, policy_generation={})",
                 rule_count_, policy_generation_);
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

    // PR 2 has no real evaluator yet — be honest about that. Every rule is
    // reported with status="errored" because we cannot prove compliance
    // without a guard running. Dashboards then surface this as "Guardian
    // installed but inert," matching the PR 2 reality. PR 3 replaces this
    // with real per-guard health.
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
        const auto& params = cmd.parameters();
        auto it = params.find(std::string{kParamPush});
        if (it == params.end()) {
            res.exit_code = 1;
            res.content_type = "text";
            res.output = "missing 'push' parameter (expected serialized GuaranteedStatePush)";
            return res;
        }
        gpb::GuaranteedStatePush push;
        // proto map<string,string> stores the value as a std::string with
        // exact length — binary-safe across embedded NUL bytes, unlike a
        // C-string round trip.
        if (!push.ParseFromString(it->second)) {
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

// #501: Test-support helper — see guardian_engine.hpp for the full rationale.
// The CommandRequest construction and `parameters` map population happen
// INSIDE yuzu_agent_core.dll (where this TU compiles). When the test EXE
// calls this function, the map is populated and read using the same
// absl::HashOf seed (the DLL's copy of `MixingHashState::kSeed`), so
// `engine.dispatch()`'s internal `.find("push")` succeeds. If the test
// instead populates `cmd.mutable_parameters()` directly, the insert runs
// against the EXE's hash seed and the DLL's find misses the bucket.
GuardianDispatchResult
guardian_dispatch_push_bytes_for_test(GuardianEngine& engine,
                                      std::string_view push_param_bytes) {
    apb::CommandRequest cmd;
    cmd.set_command_id("test-dispatch");
    cmd.set_plugin("__guard__");
    cmd.set_action(std::string{kActionPushRules});
    // Use operator[] on the mutable Map here rather than insert({k,v}) or
    // try_emplace — any of them work equivalently because population and
    // the downstream find() both happen inside this TU (same DLL, same
    // seed). The distinction only mattered when the mutation crossed
    // modules; here it doesn't.
    (*cmd.mutable_parameters())[std::string{kParamPush}] =
        std::string{push_param_bytes};
    return engine.dispatch(cmd);
}

} // namespace yuzu::agent
