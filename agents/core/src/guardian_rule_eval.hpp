#pragma once

/**
 * guardian_rule_eval.hpp - the per-type Guardian rule evaluators for the spark
 * consumer (ADR-0021 Stage 2 rung 2 slice 2b).
 *
 * Each evaluator takes a rule's proto-free assertion, a state SNAPSHOT read once
 * per spark_key by the consumer, and the rule's mutable eval state, and returns a
 * GuardDrift to emit (or nullopt for silent). It computes `compliant` the guard's
 * way, then runs the shared decide_emit tail (guardian_emit_decider.hpp) and packs
 * the result into a GuardDrift with the legacy detected/expected token vocabulary
 * so GuardianEngine::emit_guard_event produces the SAME wire event as the legacy
 * guards (parity gate). Enforcement is NOT here - rung 2 is observe-only, so the
 * remediation fields stay default and no state is ever written.
 *
 * Proto-free (operates on RuleAssertion, extracted from the rule at arm time by
 * GuardianEngine) and platform-agnostic (the platform I/O that produces the
 * snapshot lives in the consumer's read-source seam, not here), so every branch is
 * unit-tested off-platform against synthetic snapshots.
 */

#include <yuzu/plugin.h>        // YUZU_EXPORT
#include <yuzu/agent/guard.hpp> // GuardDrift
#include <yuzu/agent/spark.hpp> // ServiceRunState

#include "guardian_emit_decider.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

namespace yuzu::agent {

/// The rule's desired-state check, proto-free (GuardianEngine extracts it from the
/// GuaranteedStateRule at arm time so the consumer never sees the proto).
enum class AssertionKind {
    FileExists,     ///< file-exists: presence vs expect_present
    FileHashEquals, ///< file-hash-equals: SHA-256 vs expected_hash (empty = baseline-on-arm)
    RegistryEquals, ///< registry-value-equals: value vs expected_value
    ServiceRunning, ///< service-running: desired Running
    ServiceStopped, ///< service-stopped: desired Stopped
};

struct RuleAssertion {
    AssertionKind kind{AssertionKind::FileExists};
    std::string rule_id;
    std::string rule_name;
    std::uint64_t debounce_ms{1000};
    // file-exists
    bool expect_present{true};
    // file-hash-equals
    std::string expected_hash; ///< lowercase hex SHA-256; empty = baseline-on-arm
    // registry-value-equals
    std::string expected_value;
};

/// File state read once per key by the consumer. Only presence/readability/size are
/// resolved cheaply; `hash` is filled when the assertion needs it (hash-equals).
struct FileSnapshot {
    bool exists{false};
    bool readable{true};  ///< false -> "<unreadable>" drift
    bool oversize{false}; ///< size over the hash cap -> "<oversize>" drift
    std::string hash;     ///< lowercase hex SHA-256 (empty when not hashed / n/a)
};

/// Registry value read once per key by the consumer.
struct RegistrySnapshot {
    bool present{false};   ///< false -> "<absent>" drift
    bool supported{true};  ///< false -> "<unsupported-type>" drift
    std::string value;     ///< G4-encoded live value string
};

/// Per-rule mutable eval state kept by the consumer, keyed by rule_id.
struct RuleEvalState {
    EmitDeciderState emit;
    std::string baseline_hash;  ///< file-hash baseline-on-arm capture
    bool baseline_set{false};
};

/// Evaluate a file rule against a snapshot. Returns a GuardDrift to emit or nullopt.
[[nodiscard]] YUZU_EXPORT std::optional<GuardDrift>
eval_file(const RuleAssertion& a, const FileSnapshot& snap, RuleEvalState& state,
          std::chrono::steady_clock::time_point now, bool emit_compliant_edge = true);

/// Evaluate a registry rule. `detection_latency_us` is the measured read time
/// (registry is the one type that records it, for parity).
[[nodiscard]] YUZU_EXPORT std::optional<GuardDrift>
eval_registry(const RuleAssertion& a, const RegistrySnapshot& snap, RuleEvalState& state,
              std::uint64_t detection_latency_us, std::chrono::steady_clock::time_point now,
              bool emit_compliant_edge = true);

/// Evaluate a service rule against the ServiceRunState the SparkEvent carried.
/// (The Service mechanism already resolved terminal state, holding transitionals,
/// and folds a deleted service into Stopped - R5, accepted.)
[[nodiscard]] YUZU_EXPORT std::optional<GuardDrift>
eval_service(const RuleAssertion& a, ServiceRunState observed, RuleEvalState& state,
             std::chrono::steady_clock::time_point now, bool emit_compliant_edge = true);

} // namespace yuzu::agent
