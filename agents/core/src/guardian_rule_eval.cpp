#include "guardian_rule_eval.hpp"

#include <yuzu/agent/guard_service.hpp> // service_is_compliant, service_state_token, ServiceState, ServiceGuard::Desired

#include <string>
#include <utility>

namespace yuzu::agent {

namespace {

/// Run the shared decide_emit tail and pack its result + the guard's
/// detected/expected tokens into a GuardDrift, or nullopt if it said stay silent.
std::optional<GuardDrift> pack(const RuleAssertion& a, const char* guard_type, bool compliant,
                               std::string detected, std::string expected, RuleEvalState& state,
                               std::chrono::steady_clock::time_point now, bool emit_compliant_edge,
                               std::uint64_t detection_latency_us) {
    const EmitResult r = decide_emit(compliant, state.emit, a.debounce_ms, now, emit_compliant_edge);
    if (r.kind == EmitKind::Silent)
        return std::nullopt;
    GuardDrift d;
    d.guard_type = guard_type;
    d.rule_id = a.rule_id;
    d.rule_name = a.rule_name;
    d.detected_value = std::move(detected);
    d.expected_value = std::move(expected);
    d.detection_latency_us = detection_latency_us;
    d.collapsed_count = r.collapsed_count;
    d.compliant = (r.kind == EmitKind::CompliantEdge);
    return d;
}

} // namespace

std::optional<GuardDrift> eval_file(const RuleAssertion& a, const FileSnapshot& snap,
                                    RuleEvalState& state, std::chrono::steady_clock::time_point now,
                                    bool emit_compliant_edge) {
    bool compliant = false;
    std::string detected;
    std::string expected;

    if (a.kind == AssertionKind::FileExists) {
        compliant = (snap.exists == a.expect_present);
        detected = snap.exists ? "<present>" : "<absent>";
        expected = a.expect_present ? "<present>" : "<absent>";
    } else { // FileHashEquals
        if (!snap.exists) {
            detected = "<absent>";
        } else if (!snap.readable) {
            detected = "<unreadable>";
        } else if (snap.oversize) {
            detected = "<oversize>";
        } else {
            // baseline-on-arm: an empty expected_hash captures the first good read as
            // the baseline and reads compliant (a guard.compliant edge).
            if (a.expected_hash.empty() && !state.baseline_set) {
                state.baseline_hash = snap.hash;
                state.baseline_set = true;
            }
            const std::string& effective =
                a.expected_hash.empty() ? state.baseline_hash : a.expected_hash;
            compliant = (snap.hash == effective);
            detected = snap.hash;
            expected = effective;
        }
        if (expected.empty()) // absent/unreadable/oversize drift: report the target hash
            expected = a.expected_hash.empty() ? state.baseline_hash : a.expected_hash;
    }
    return pack(a, "file", compliant, std::move(detected), std::move(expected), state, now,
                emit_compliant_edge, /*detection_latency_us=*/0);
}

std::optional<GuardDrift> eval_registry(const RuleAssertion& a, const RegistrySnapshot& snap,
                                        RuleEvalState& state, std::uint64_t detection_latency_us,
                                        std::chrono::steady_clock::time_point now,
                                        bool emit_compliant_edge) {
    bool compliant = false;
    std::string detected;
    if (!snap.present) {
        detected = "<absent>";
    } else if (!snap.supported) {
        detected = "<unsupported-type>";
    } else {
        compliant = (snap.value == a.expected_value);
        detected = snap.value;
    }
    return pack(a, "registry", compliant, std::move(detected), a.expected_value, state, now,
                emit_compliant_edge, detection_latency_us);
}

std::optional<GuardDrift> eval_service(const RuleAssertion& a, ServiceRunState observed,
                                       RuleEvalState& state,
                                       std::chrono::steady_clock::time_point now,
                                       bool emit_compliant_edge) {
    // ServiceRunState (spark payload) -> ServiceState (guard vocabulary). There is no
    // Absent: a deleted service folds into Stopped at the mechanism (R5, accepted -
    // the compliance verdict is identical, only detected_value differs from legacy).
    ServiceState st = ServiceState::Stopped;
    switch (observed) {
    case ServiceRunState::Running:
        st = ServiceState::Running;
        break;
    case ServiceRunState::Stopped:
        st = ServiceState::Stopped;
        break;
    case ServiceRunState::Paused:
        st = ServiceState::Paused;
        break;
    }
    const ServiceGuard::Desired want = (a.kind == AssertionKind::ServiceRunning)
                                           ? ServiceGuard::Desired::Running
                                           : ServiceGuard::Desired::Stopped;
    const bool compliant = service_is_compliant(want, st);
    std::string detected{service_state_token(st)};
    std::string expected = (want == ServiceGuard::Desired::Running) ? "running" : "stopped";
    // emit_compliant_edge default true UNIFIES the compliant-census signal across
    // platforms: legacy Windows-Service emitted it, legacy systemd did not. The caller
    // can pass false to preserve exact legacy-systemd silence (pinned in parity tests).
    return pack(a, "service", compliant, std::move(detected), std::move(expected), state, now,
                emit_compliant_edge, /*detection_latency_us=*/0);
}

} // namespace yuzu::agent
