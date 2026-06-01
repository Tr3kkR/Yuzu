/// @file guardian_rule_spec.cpp — see guardian_rule_spec.hpp.

#include "guardian_rule_spec.hpp"

#include "guardian_resilience_schema.hpp"

#include <nlohmann/json.hpp>

namespace yuzu::server::guardian {

RuleSpecResult derive_rule_spec(const nlohmann::json& body, const std::string& name,
                                std::int64_t version, bool enabled,
                                const std::string& enforcement_mode) {
    RuleSpecResult out;

    auto json_block = [&](const char* key) -> nlohmann::json {
        if (body.contains(key) && body[key].is_object())
            return body[key];
        return nlohmann::json::object();
    };
    nlohmann::json spark = json_block("spark");
    nlohmann::json assertion = json_block("assertion");
    nlohmann::json remediation = json_block("remediation");
    const std::string spark_type = spark.value("type", std::string{});
    const std::string assertion_type = assertion.value("type", std::string{});

    const bool any_block = !spark.empty() || !assertion.empty() || !remediation.empty();
    const bool full = !spark_type.empty() && !assertion_type.empty();

    if (!full) {
        // A body carrying a structured block but not a complete spark+assertion
        // pair is rejected, NOT silently dropped (the silent-drop trap on update).
        // A body with no structured block at all is a legacy / metadata-only path
        // the caller owns.
        if (any_block)
            out.error = ResilienceParamError{
                "a structured Guard requires both a 'spark' and an 'assertion' block "
                "(each with a 'type')",
                "include spark.type and assertion.type, or omit all structured blocks for a "
                "metadata-only update"};
        return out;
    }

    // Detect-and-alert is the MVP default remediation.
    if (remediation.empty())
        remediation = {{"type", "alert-only"}, {"params", nlohmann::json::object()}};

    // C3b: validate + canonicalise the resilience policy in remediation.params.
    if (remediation.contains("params") && remediation["params"].is_object()) {
        if (auto err = validate_and_canonicalize_resilience_params(remediation["params"])) {
            out.error = std::move(err);
            return out;
        }
    }

    nlohmann::json spec;
    spec["name"] = name;
    spec["version"] = version;
    spec["enabled"] = enabled;
    spec["enforcement_mode"] = enforcement_mode;
    spec["spark"] = spark;
    spec["assertion"] = assertion;
    spec["remediation"] = remediation;

    out.structured = true;
    // Authoritative structured form. NOTE: a structured dump, not yet
    // JCS-canonicalised — full RFC-8785 canonicalisation lands with rule signing
    // (contract G3, deferred).
    out.spec_json = spec.dump();
    // yaml_source is a generated, never-parsed human-readable rendering (decision
    // 1). JSON is a valid YAML subset, so a header-commented pretty dump is honest.
    out.yaml_source =
        "# Guardian Guard (generated rendering — authoritative form is the structured spec)\n" +
        spec.dump(2) + "\n";
    return out;
}

} // namespace yuzu::server::guardian
