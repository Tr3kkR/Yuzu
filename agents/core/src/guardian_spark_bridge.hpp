#pragma once

/**
 * guardian_spark_bridge.hpp - the Guardian-rule <-> spark vocabulary bridge
 * (ADR-0021 Stage 2 rung 2 slice 2b). Converts a GuaranteedStateRule's typed
 * blocks into the SparkSpec the SparkEngine arms.
 *
 * Source-of-truth note: the spark block carries only the type discriminator
 * ("file-change" / "service-status-change" / "registry-change"); the watch
 * TARGET (path / service_name / hive+key) lives in the ASSERTION params. This
 * mirrors exactly how the legacy guards read it in
 * start_guard_for_rule_locked() (guardian_engine.cpp) - the two paths must
 * resolve the same target or a rule would watch one thing and assert over
 * another.
 *
 * INLINE by design (not a .cpp in the DLL): a proto Map<string,string> lookup
 * must run in the SAME image that populated the map, or it hits the #501
 * abseil-seed-across-DLL hash mismatch on MSVC debug (see
 * guardian_engine.hpp's guardian_dispatch_push_bytes_for_test rationale). Inline
 * keeps populate+find co-located - the DLL both parses the wire rule and calls
 * this; a unit test both builds the rule and calls this - so neither crosses the
 * boundary.
 */

#include <yuzu/agent/spark.hpp> // SparkSpec, SparkType, *SparkParams

#include "guaranteed_state.pb.h"

#include <optional>
#include <string>
#include <utility>

namespace yuzu::agent {

namespace detail {
/// One assertion param by key, or empty. Local to this header (inline linkage).
[[nodiscard]] inline std::string
guardian_assertion_param(const yuzu::guardian::v1::GuardianSpecBlock& assertion, const char* key) {
    const auto it = assertion.params().find(key);
    return it != assertion.params().end() ? it->second : std::string{};
}
} // namespace detail

/// Build the SparkSpec that watches what `rule` asserts over. Returns nullopt
/// for an unrecognized spark type OR a recognized type whose required target
/// param is empty (no path / service_name / hive|key) - the caller treats
/// nullopt as "not armable" (an authoring error, distinct from the
/// platform-Unsupported outcome that GuardianSparkConsumer::classify reports).
[[nodiscard]] inline std::optional<SparkSpec>
spark_spec_from_rule(const yuzu::guardian::v1::GuaranteedStateRule& rule) {
    const yuzu::guardian::v1::GuardianSpecBlock& assertion = rule.assertion();
    const std::string& type = rule.spark().type();

    if (type == "file-change") {
        std::string path = detail::guardian_assertion_param(assertion, "path");
        if (path.empty()) return std::nullopt;
        return SparkSpec{SparkType::File, FileSparkParams{std::move(path)}};
    }
    if (type == "service-status-change") {
        std::string service_name = detail::guardian_assertion_param(assertion, "service_name");
        if (service_name.empty()) return std::nullopt;
        return SparkSpec{SparkType::Service, ServiceSparkParams{std::move(service_name)}};
    }
    if (type == "registry-change") {
        std::string hive = detail::guardian_assertion_param(assertion, "hive");
        std::string key = detail::guardian_assertion_param(assertion, "key");
        if (hive.empty() || key.empty()) return std::nullopt;
        return SparkSpec{SparkType::Registry, RegistrySparkParams{std::move(hive), std::move(key)}};
    }
    return std::nullopt;
}

} // namespace yuzu::agent
