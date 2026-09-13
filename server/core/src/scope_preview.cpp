#include "scope_preview.hpp"

#include "scope_engine.hpp"
#include "tag_store.hpp"

#include <unordered_map>
#include <unordered_set>

namespace yuzu::server {

ScopePreviewOutcome preview_scope_targets(const std::string& expression,
                                          const nlohmann::json& agents, TagStore* tag_store) {
    auto valid = yuzu::scope::validate(expression);
    if (!valid) {
        return {.kind = ScopePreviewOutcome::Kind::kInvalidExpression,
                .detail = "Invalid scope: " + valid.error()};
    }
    auto parsed_expr = yuzu::scope::parse(expression);
    if (!parsed_expr) {
        return {.kind = ScopePreviewOutcome::Kind::kInvalidExpression,
                .detail = "Parse error: " + parsed_expr.error()};
    }

    // Preload every tag:<key> the expression references in ONE bulk query
    // before the agent loop (ADR-0050) — see this file's header comment.
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> preview_tags;
    {
        std::vector<std::string> tag_keys;
        yuzu::scope::collect_attribute_suffixes(*parsed_expr, "tag:", tag_keys);
        if (!tag_keys.empty() && tag_store != nullptr) {
            auto preload = tag_store->get_values_for_keys(tag_keys);
            if (!preload) {
                return {.kind = ScopePreviewOutcome::Kind::kTagStoreDegraded};
            }
            preview_tags = std::move(*preload);
        }
    }

    nlohmann::json matching = nlohmann::json::array();
    for (const auto& a : agents) {
        auto agent_id = a.value("agent_id", "");
        std::unordered_map<std::string, std::string> attrs;
        // Gate 8 BLOCKING fix (#2146 Batch B2 review): the DSL's canonical OS
        // attribute is "ostype" (agent_registry.cpp's real dispatch
        // resolver, docs/user-manual/scope-engine.md), not "os" - this
        // resolver populated the wrong key, so ostype=="linux" always
        // resolved unset (matched_count silently 0) and, worse,
        // ostype!="linux" resolved unset-not-equal-to-"linux" as true for
        // EVERY agent regardless of its real OS - a preview whose entire
        // purpose is "show what a real dispatch would target" silently
        // returning the wrong device set as correct.
        attrs["ostype"] = a.value("os", "");
        attrs["arch"] = a.value("arch", "");
        attrs["hostname"] = a.value("hostname", "");
        attrs["agent_version"] = a.value("agent_version", "");
        if (auto it = preview_tags.find(agent_id); it != preview_tags.end()) {
            for (const auto& [k, v] : it->second)
                attrs["tag:" + k] = v;
        }
        auto resolver = [&](std::string_view attr) -> std::string {
            auto it = attrs.find(std::string(attr));
            return it != attrs.end() ? it->second : "";
        };
        if (yuzu::scope::evaluate(*parsed_expr, resolver))
            matching.push_back(agent_id);
    }

    // Blast-radius guard: warn when scope matches many agents (G4-UHP-MCP-011)
    // — same threshold as the pre-extraction MCP tool.
    constexpr std::size_t kScopeWarnThreshold = 50;
    const bool scope_warning = matching.size() > kScopeWarnThreshold;

    nlohmann::json payload = {
        {"expression", expression},
        {"matched_count", matching.size()},
        {"matched_agents", matching},
    };
    if (scope_warning) {
        payload["warning"] = "scope matches " + std::to_string(matching.size()) + " agents (>" +
                             std::to_string(kScopeWarnThreshold) +
                             "). Phase 2 write operations targeting this scope will require "
                             "approval.";
    }
    return {.kind = ScopePreviewOutcome::Kind::kOk, .payload = std::move(payload)};
}

} // namespace yuzu::server
