#include "guardian_push_builder.hpp"

#include "guardian_rule_spec.hpp" // dangerous_enforce_key_in_spec (H1 push backstop)

#include <algorithm>
#include <cctype>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

namespace yuzu::server::guardian {

namespace {

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
    blk->set_type(j.value("type", std::string{}));
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

::yuzu::guardian::v1::GuaranteedStatePush
build_agent_push(const std::vector<GuaranteedStateRuleRow>& rules, std::string_view agent_os,
                 const std::function<bool(const std::string& scope_expr)>& in_scope,
                 bool full_sync, std::uint64_t generation) {
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
            if (std::string why = dangerous_enforce_key_in_spec(row.spec_json); !why.empty()) {
                spdlog::warn("Guardian push: rule {} ('{}') requests enforce on {} — downgrading to "
                             "audit (dangerous-key denylist, contract §6/H1)",
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
