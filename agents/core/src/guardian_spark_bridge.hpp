#pragma once

/**
 * guardian_spark_bridge.hpp - the Guardian-rule <-> spark vocabulary bridge
 * (ADR-0021 Stage 2 rung 2 slice 2b, extended rung 7). Converts a
 * GuaranteedStateRule's typed blocks into the SparkSpec the SparkEngine arms,
 * and classifies a rule's spark type against this host's mechanism capability.
 *
 * Source-of-truth note: the spark block carries only the type discriminator
 * ("file-change" / "service-status-change" / "registry-change"); the watch
 * TARGET (path / service_name / hive+key) lives in the ASSERTION params. This
 * mirrors exactly how the legacy guards read it in
 * start_guard_for_rule_locked() (guardian_engine.cpp) - the two paths must
 * resolve the same target or a rule would watch one thing and assert over
 * another.
 *
 * SINGLE-SOURCED token recognition (rung 7 fix): spark_type_from_token() is the
 * ONE place the three recognized spark-type strings are listed. Both
 * spark_spec_from_rule() and classify() call it, so they cannot silently drift
 * apart (previously each had its own separate copy of the same three strings -
 * an agreement that held by coincidence, not by construction). A caller that
 * already has a spark_spec_from_rule() Some result never needs classify()'s
 * Unrecognized branch - Some already proves the token was recognized - so
 * classify() exists for the cases that still need the FULL three-way split
 * (platform-capability decisions made independently of building a SparkSpec),
 * and its own unit tests document the taxonomy.
 *
 * INLINE by design (not a .cpp in the DLL): a proto Map<string,string> lookup
 * must run in the SAME image that populated the map, or it hits the #501
 * abseil-seed-across-DLL hash mismatch on MSVC debug (see
 * guardian_engine.hpp's guardian_dispatch_push_bytes_for_test rationale). Inline
 * keeps populate+find co-located - the DLL both parses the wire rule and calls
 * this; a unit test both builds the rule and calls this - so neither crosses the
 * boundary. classify() and spark_type_from_token() touch no proto Map, so this
 * constraint doesn't strictly apply to them, but they stay in this header
 * (still inline, still trivial) rather than splitting into a second file for
 * two small pure functions.
 */

#include <yuzu/agent/spark.hpp> // SparkSpec, SparkType, *SparkParams

#include "guaranteed_state.pb.h"

#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::agent {

/// The ONE place the Guardian rule spark-type tokens (the server-side
/// Guaranteed-State DSL) map to the spark vocabulary. These three are the
/// event-driven Guardian types today, matching the dispatch in
/// start_guard_for_rule_locked() (guardian_engine.cpp). A token outside this
/// set is not a platform miss - it is an authored spark type the agent does
/// not implement at all, i.e. an authoring error.
[[nodiscard]] inline std::optional<SparkType> spark_type_from_token(std::string_view token) noexcept {
    if (token == "file-change") return SparkType::File;
    if (token == "service-status-change") return SparkType::Service;
    if (token == "registry-change") return SparkType::Registry;
    return std::nullopt;
}

/// Where a Guardian rule lands when classified against the mechanisms
/// available on THIS host. The Unsupported/Unrecognized split is the whole
/// point of the platform-rejection design (ADR-0021): a cross-platform
/// Baseline reaching a host that structurally lacks the mechanism (Registry or
/// File off Windows, Service off Linux/macOS) is ROUTINE and terminal-states to
/// `unsupported`, NOT an authoring fault. Only an unknown spark type is
/// `errored`/page-worthy.
enum class RulePlacement {
    Arm,          ///< known event-driven type WITH a mechanism on this host: arm it
    Unsupported,  ///< known type, NO mechanism registered here: routine, terminal-state unsupported
    Unrecognized, ///< spark type token not understood: an authoring error (errored)
};

/// Classify a rule's spark type against the mechanisms available on this host.
/// PURE and side-effect-free. `supported` is the set of event-driven types the
/// SparkEngine has a registered, non-inert mechanism for - callers must filter
/// out any mechanism the heartbeat itself treats as inert (see
/// spark_heartbeat.hpp's inert-filtering) before passing it here, or a
/// registered-but-inert mechanism would be misclassified as armable. CRITICAL:
/// the discriminator is capability membership, NEVER the text of an arm()
/// rejection message (ADR-0021 platform-rejection) - a string match would
/// silently misfile a rejection the day the message wording changes.
[[nodiscard]] inline RulePlacement classify(std::string_view spark_type_token,
                                            const std::set<SparkType>& supported) noexcept {
    const std::optional<SparkType> type = spark_type_from_token(spark_type_token);
    if (!type) return RulePlacement::Unrecognized;
    return supported.contains(*type) ? RulePlacement::Arm : RulePlacement::Unsupported;
}

namespace detail {
/// One assertion param by key, or empty. Local to this header (inline linkage).
[[nodiscard]] inline std::string
guardian_assertion_param(const yuzu::guardian::v1::GuardianSpecBlock& assertion, const char* key) {
    const auto it = assertion.params().find(key);
    return it != assertion.params().end() ? it->second : std::string{};
}
} // namespace detail

/// Build the SparkSpec that watches what `rule` asserts over. Returns nullopt
/// for an unrecognized spark type (see spark_type_from_token) OR a recognized
/// type whose required target param is empty (no path / service_name /
/// hive|key) - the caller treats nullopt as "not armable" (an authoring error,
/// distinct from the platform-Unsupported outcome classify() reports for a
/// RECOGNIZED type this host merely lacks a mechanism for).
[[nodiscard]] inline std::optional<SparkSpec>
spark_spec_from_rule(const yuzu::guardian::v1::GuaranteedStateRule& rule) {
    const yuzu::guardian::v1::GuardianSpecBlock& assertion = rule.assertion();
    const std::optional<SparkType> type = spark_type_from_token(rule.spark().type());
    if (!type)
        return std::nullopt;

    switch (*type) {
    case SparkType::File: {
        std::string path = detail::guardian_assertion_param(assertion, "path");
        if (path.empty()) return std::nullopt;
        return SparkSpec{SparkType::File, FileSparkParams{std::move(path)}};
    }
    case SparkType::Service: {
        std::string service_name = detail::guardian_assertion_param(assertion, "service_name");
        if (service_name.empty()) return std::nullopt;
        return SparkSpec{SparkType::Service, ServiceSparkParams{std::move(service_name)}};
    }
    case SparkType::Registry: {
        std::string hive = detail::guardian_assertion_param(assertion, "hive");
        std::string key = detail::guardian_assertion_param(assertion, "key");
        if (hive.empty() || key.empty()) return std::nullopt;
        return SparkSpec{SparkType::Registry, RegistrySparkParams{std::move(hive), std::move(key)}};
    }
    default:
        return std::nullopt; // Interval/Startup/Disk are not Guardian spark types
    }
}

} // namespace yuzu::agent
