#include "guardian_push_builder.hpp"

#include <algorithm>
#include <cctype>

#include <nlohmann/json.hpp>

namespace yuzu::server::guardian {

namespace {

std::string to_lower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
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

bool os_target_matches(std::string_view target, std::string_view agent_os) {
    if (target.empty())
        return true;  // rule applies to every OS
    if (agent_os.empty())
        return true;  // unknown agent OS → fail OPEN: send the rule and let the
                      // agent decide (it marks an inapplicable guard errored, G11).
                      // Failing closed here would silently drop every OS-targeted
                      // guard for an agent whose session has no os (disconnect race,
                      // partial registration) — worse than the pre-M4 send-all.
    return to_lower(agent_os).find(to_lower(target)) != std::string::npos;
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
        r->set_enforcement_mode(row.enforcement_mode);

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
