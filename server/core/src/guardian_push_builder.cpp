#include "guardian_push_builder.hpp"

#include "guardian_rule_spec.hpp" // dangerous_enforce_in_spec (H1 push backstop)
#include "mcp_jsonrpc.hpp"        // json_exceeds_depth / kMcpMaxJsonDepth (depth guard)
#include "on_behalf_guard.hpp"    // onbehalf::sanitize_for_log
#include "yuzu/metrics.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

namespace yuzu::server::guardian {

namespace {

// Rate-limits the depth-exclusion log line the same way RuntimeConfigStore's
// read-degrade sampler does (docs/observability-conventions.md's
// RuntimeConfigStore entry): the counter always increments, but the log only
// fires on the first occurrence of a new "episode" or every Nth occurrence
// within a sustained one, so a persisting poisoned row (this function runs on
// every heartbeat reconcile, for every connected agent) cannot flood the log
// for as long as it remains unfixed in the store.
constexpr std::uint64_t kExclusionLogSample = 100;
constexpr std::int64_t kExclusionEpisodeGapSecs = 60;

std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
              std::chrono::system_clock::now().time_since_epoch())
        .count();
}

struct ExclusionSampler {
    std::atomic<std::uint64_t> count{0};
    std::atomic<std::int64_t> last_ts{0};
};

bool should_log_exclusion(ExclusionSampler& s) {
    const std::int64_t now = now_secs();
    const std::int64_t prev = s.last_ts.exchange(now, std::memory_order_relaxed);
    const std::uint64_t n = s.count.fetch_add(1, std::memory_order_relaxed) + 1;
    const bool new_episode = prev == 0 || (now - prev) > kExclusionEpisodeGapSecs;
    return new_episode || (n % kExclusionLogSample) == 0;
}

// One sampler shared across all rules/agents in this process: unlike
// RuntimeConfigStore's per-call-site samplers (which exist to stop a hot call
// site masking a cold one), every exclusion here is the SAME failure shape (a
// poisoned spec_json), so a single episode clock is the right grain. The
// metric itself is not labeled per rule id (an open, unbounded set) - only by
// the fixed `reason` value below - and this sampler paces the log line for
// every excluded rule together, not per rule.
ExclusionSampler g_exclusion_sampler;

std::string to_lower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

// Canonical OS token for matching. The agent reports kAgentOs
// ("windows" | "linux" | "darwin"); rule authors write os_target "macos". Map
// darwin->macos so a macOS rule matches a Darwin agent, and lower-case so the
// match is case-insensitive. Compared for EXACT equality (not substring) so a
// short/ambiguous target like "win" cannot spuriously match "darwin" (#1209).
std::string normalize_os(std::string_view s) {
    std::string v = to_lower(s);
    if (v == "darwin")
        return "macos";
    return v;
}

// Marshal one spec block (spark / assertion / remediation) from the canonical
// spec_json into the proto. Mirrors the server's authoritative spec_json shape:
// non-string param values are dumped to their JSON text so the agent receives a
// stable string map. See docs/guardian-mvp-contract.md decisions 1-2.
void fill_block(::yuzu::guardian::v1::GuardianSpecBlock* blk, const nlohmann::json& j) {
    if (!j.is_object())
        return;
    // is_string guard, not json::value(): value() throws type_error.302 on a
    // PRESENT non-string "type", and this runs on stored spec_json at the push
    // chokepoint with no guard above it. derive_rule_spec type-checks spark.type
    // and assertion.type before persistence but NOT remediation.type, so a rule
    // authored with a non-string remediation.type (REST create, GuaranteedState:
    // Write) persists and would otherwise throw here on every fan-out — a
    // fleet-wide push DoS. A non-string type is inert (agent G11-errors an unknown
    // type), same posture as the malformed/empty-spec header-only rows (#1946).
    blk->set_type(j.contains("type") && j["type"].is_string() ? j["type"].get<std::string>()
                                                              : std::string{});
    if (j.contains("params") && j["params"].is_object()) {
        const auto& params = j["params"];
        // Iterator form, not structured bindings: MSVC C3493s on a structured
        // binding referenced inside a lambda body, and this mirrors the idiom the
        // original push lambda used.
        for (auto it = params.begin(); it != params.end(); ++it)
            (*blk->mutable_params())[it.key()] =
                it.value().is_string() ? it.value().get<std::string>() : it.value().dump();
    }
}

} // namespace

std::vector<GuaranteedStateRuleRow>
filter_deployed_members(const std::vector<GuaranteedStateRuleRow>& rules,
                        const std::unordered_set<std::string>& deployed_rule_ids) {
    std::vector<GuaranteedStateRuleRow> out;
    out.reserve(rules.size());
    for (const auto& r : rules)
        if (deployed_rule_ids.contains(r.rule_id))
            out.push_back(r);
    return out;
}

bool os_target_matches(std::string_view target, std::string_view agent_os) {
    if (target.empty())
        return true;  // rule applies to every OS
    if (agent_os.empty())
        return true;  // unknown agent OS → fail OPEN: send the rule and let the
                      // agent decide (it marks an inapplicable guard errored, G11).
                      // Failing closed here would silently drop every OS-targeted
                      // guard for an agent whose session has no os (disconnect race,
                      // partial registration) — worse than the pre-M4 send-all.
    return normalize_os(target) == normalize_os(agent_os);
}

bool guardian_guard_supported_on_platform(std::string_view agent_os, std::string_view spark_type) {
    if (agent_os.empty())
        return true;  // unknown OS — never mislabel it "not implemented"
    // normalize_os only lower-cases and maps darwin->macos — it does NOT parse
    // a verbose free-text string like "Windows 11 Pro" down to "windows".
    // agent_os is always the raw kAgentOs token, never free text, so this is a
    // non-issue in practice; a prior version of this comment claimed
    // normalize_os handled the verbose case, which was false (#4252).
    const std::string os = normalize_os(agent_os);
    if (spark_type == "service-status-change")
        // SystemdServiceGuard (guard_systemd.cpp's make_service_guard(),
        // :157-163) arms on Linux too — observe-only, enforce deliberately
        // deferred, but NOT a no-op like Registry/File are on Linux. Windows
        // ServiceGuard enforces; macOS falls to the no-op ServiceGuard stub.
        // docs/os-capability-matrix.md's "Guardian — service run-state guard"
        // row and docs/user-manual/guaranteed-state.md's Service section.
        return os == "windows" || os == "linux";
    // registry-change / file-change: RegistryGuard::start() / FileGuard::
    // start() are compiled no-ops on macOS and Linux — Windows only. Any
    // spark_type this function doesn't recognise (empty/malformed/future)
    // falls back to the same Windows-only rule, so it can never silently
    // regress Registry/File support.
    return os == "windows";
}

std::string platform_display_name(std::string_view agent_os) {
    const std::string v = normalize_os(agent_os);  // darwin->macos, lower-cased
    if (v == "windows")
        return "Windows";
    if (v == "macos")
        return "macOS";
    if (v == "linux")
        return "Linux";
    return agent_os.empty() ? std::string{"unknown"} : std::string{agent_os};
}

::yuzu::guardian::v1::GuaranteedStatePush
build_agent_push(const std::vector<GuaranteedStateRuleRow>& rules, std::string_view agent_os,
                 const std::function<bool(const std::string& scope_expr)>& in_scope,
                 bool full_sync, std::uint64_t generation, ::yuzu::MetricsRegistry* metrics) {
    ::yuzu::guardian::v1::GuaranteedStatePush push;
    push.set_full_sync(full_sync);
    push.set_policy_generation(generation);
    for (const auto& row : rules) {
        if (!row.enabled)
            continue;
        if (!os_target_matches(row.os_target, agent_os))
            continue;
        if (!row.scope_expr.empty() && in_scope && !in_scope(row.scope_expr))
            continue;

        // Depth guard on the raw stored text, before anything below interprets it
        // (including dangerous_enforce_in_spec's own parse just below, and the
        // nlohmann::json::parse further down): spec_json is stored,
        // caller-influenced text that this read path re-parses and re-dumps on
        // EVERY push/reconcile call, for EVERY rule, on ordinary fleet traffic -
        // the heartbeat reconcile call site has no operator action in the loop at
        // all. fill_block()'s params dump() is unboundedly recursive and SIGSEGVs
        // the whole process well under 1 MiB of nesting; because the poisoned row
        // persists in the store, an unguarded crash here is a crash-loop on
        // restart, not a one-time failure. Mirrors json_exceeds_depth's own
        // "never construct the deep tree" rationale (mcp_jsonrpc.hpp): this rule
        // is excluded from this agent's push in its entirety (nothing is added
        // for it, including the header) rather than partially marshalled, so a
        // single poisoned spec_json cannot block or corrupt the rest of the
        // batch. This is a structural "too deep to safely parse" rejection only -
        // it makes no judgment about the (unparsed) content, and it does not
        // change what dangerous_enforce_in_spec itself considers dangerous.
        if (!row.spec_json.empty() &&
            yuzu::server::mcp::json_exceeds_depth(row.spec_json,
                                                  yuzu::server::mcp::kMcpMaxJsonDepth)) {
            if (metrics)
                metrics
                    ->counter("yuzu_guardian_push_rule_excluded_total",
                             {{"reason", "depth_exceeded"}})
                    .increment();
            if (should_log_exclusion(g_exclusion_sampler))
                spdlog::error(
                    "Guardian push: rule {} ('{}') has spec_json nested past the depth "
                    "guard (max {}); excluding it from this push, cannot be safely parsed",
                    row.rule_id, onbehalf::sanitize_for_log(row.name, 128),
                    yuzu::server::mcp::kMcpMaxJsonDepth);
            continue;
        }

        auto* r = push.add_rules();
        r->set_rule_id(row.rule_id);
        r->set_name(row.name);
        r->set_version(static_cast<std::uint64_t>(row.version));
        r->set_enabled(row.enabled);

        // Enforce-write denylist backstop (H1): a rule can reach enforce mode via
        // create, the REST metadata-only update, OR the dashboard mode toggle — the
        // create-time validator only covers the first. This is the ONE chokepoint
        // every push funnels through, so neutralise a denylisted enforce-write here
        // regardless of how it got into the store: downgrade to audit so the guard
        // still DETECTS drift but never writes to the protected key. Authoring-time
        // rejects give the operator a clear 400; this catches legacy rows and any
        // future authoring path. See docs/guardian-mvp-contract.md §6.
        std::string mode = row.enforcement_mode;
        if (mode == "enforce") {
            if (std::string why = dangerous_enforce_in_spec(row.spec_json); !why.empty()) {
                spdlog::warn("Guardian push: rule {} ('{}') requests enforce on {} — downgrading to "
                             "audit (enforce-safety denylist, contract §6/H1)",
                             row.rule_id, row.name, why);
                mode = "audit";
            }
        }
        r->set_enforcement_mode(mode);

        if (row.spec_json.empty())
            continue;  // legacy yaml_source-only rule — header only, not enforceable
        auto spec = nlohmann::json::parse(row.spec_json, nullptr, /*allow_exceptions=*/false);
        if (!spec.is_object())
            continue;
        if (spec.contains("spark"))
            fill_block(r->mutable_spark(), spec["spark"]);
        if (spec.contains("assertion"))
            fill_block(r->mutable_assertion(), spec["assertion"]);
        if (spec.contains("remediation"))
            fill_block(r->mutable_remediation(), spec["remediation"]);
    }
    return push;
}

} // namespace yuzu::server::guardian
