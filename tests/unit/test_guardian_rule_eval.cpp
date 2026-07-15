// test_guardian_rule_eval.cpp - the per-type Guardian rule evaluators (ADR-0021
// rung 2 slice 2b). Synthetic snapshots + injected clock, so every branch is
// exercised off-platform. Asserts the compliant/drift verdict, the emitted
// detected/expected token vocabulary (parity), and guard_type.

#include "guardian_rule_eval.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>

using namespace yuzu::agent;

namespace {
using clock = std::chrono::steady_clock;
constexpr clock::time_point kT0{};
clock::time_point at_ms(std::uint64_t ms) { return kT0 + std::chrono::milliseconds(ms); }

RuleAssertion file_exists(bool expect_present) {
    RuleAssertion a;
    a.kind = AssertionKind::FileExists;
    a.rule_id = "r";
    a.expect_present = expect_present;
    return a;
}
RuleAssertion file_hash(const std::string& expected_hash) {
    RuleAssertion a;
    a.kind = AssertionKind::FileHashEquals;
    a.rule_id = "r";
    a.expected_hash = expected_hash;
    return a;
}
RuleAssertion registry_eq(const std::string& expected) {
    RuleAssertion a;
    a.kind = AssertionKind::RegistryEquals;
    a.rule_id = "r";
    a.expected_value = expected;
    return a;
}
} // namespace

TEST_CASE("eval_file file-exists: present-as-expected is a compliant edge", "[spark][eval]") {
    const auto a = file_exists(true);
    RuleEvalState s;
    FileSnapshot present{.exists = true};
    const auto d = eval_file(a, present, s, at_ms(0));
    REQUIRE(d.has_value());
    REQUIRE(d->guard_type == "file");
    REQUIRE(d->compliant);
    REQUIRE(d->detected_value == "<present>");
    REQUIRE(d->expected_value == "<present>");
}

TEST_CASE("eval_file file-exists: a missing file drifts", "[spark][eval]") {
    const auto a = file_exists(true);
    RuleEvalState s;
    FileSnapshot gone{.exists = false};
    const auto d = eval_file(a, gone, s, at_ms(0));
    REQUIRE(d.has_value());
    REQUIRE_FALSE(d->compliant);
    REQUIRE(d->detected_value == "<absent>");
    REQUIRE(d->expected_value == "<present>");
}

TEST_CASE("eval_file file-hash: baseline-on-arm captures + reads compliant, steady is silent",
          "[spark][eval]") {
    const auto a = file_hash(""); // empty -> baseline on arm
    RuleEvalState s;
    FileSnapshot snap{.exists = true, .hash = "abc123"};
    const auto first = eval_file(a, snap, s, at_ms(0));
    REQUIRE(first.has_value());
    REQUIRE(first->compliant);
    REQUIRE(first->detected_value == "abc123");
    REQUIRE(first->expected_value == "abc123"); // baseline == the captured hash
    REQUIRE(s.baseline_set);
    // Same hash again -> steady compliant -> silent.
    REQUIRE_FALSE(eval_file(a, snap, s, at_ms(10)).has_value());
    // A changed hash drifts against the captured baseline.
    FileSnapshot changed{.exists = true, .hash = "def456"};
    const auto drift = eval_file(a, changed, s, at_ms(20));
    REQUIRE(drift.has_value());
    REQUIRE_FALSE(drift->compliant);
    REQUIRE(drift->detected_value == "def456");
    REQUIRE(drift->expected_value == "abc123");
}

TEST_CASE("eval_file file-hash: oversize / unreadable / absent surface distinct tokens",
          "[spark][eval]") {
    const auto a = file_hash("expected");
    {
        RuleEvalState s;
        const auto d = eval_file(a, FileSnapshot{.exists = true, .oversize = true}, s, at_ms(0));
        REQUIRE(d.has_value());
        REQUIRE(d->detected_value == "<oversize>");
    }
    {
        RuleEvalState s;
        const auto d = eval_file(a, FileSnapshot{.exists = true, .readable = false}, s, at_ms(0));
        REQUIRE(d.has_value());
        REQUIRE(d->detected_value == "<unreadable>");
    }
    {
        RuleEvalState s;
        const auto d = eval_file(a, FileSnapshot{.exists = false}, s, at_ms(0));
        REQUIRE(d.has_value());
        REQUIRE(d->detected_value == "<absent>");
    }
}

TEST_CASE("eval_registry: value match is compliant; mismatch/absent/unsupported drift",
          "[spark][eval]") {
    const auto a = registry_eq("1");
    {
        RuleEvalState s;
        const auto d = eval_registry(a, RegistrySnapshot{.present = true, .value = "1"}, s, 42,
                                     at_ms(0));
        REQUIRE(d.has_value());
        REQUIRE(d->guard_type == "registry");
        REQUIRE(d->compliant);
        REQUIRE(d->detected_value == "1");
        REQUIRE(d->expected_value == "1");
        REQUIRE(d->detection_latency_us == 42);
    }
    {
        RuleEvalState s;
        const auto d =
            eval_registry(a, RegistrySnapshot{.present = true, .value = "0"}, s, 0, at_ms(0));
        REQUIRE(d.has_value());
        REQUIRE_FALSE(d->compliant);
        REQUIRE(d->detected_value == "0");
    }
    {
        RuleEvalState s;
        const auto d = eval_registry(a, RegistrySnapshot{.present = false}, s, 0, at_ms(0));
        REQUIRE(d->detected_value == "<absent>");
    }
    {
        RuleEvalState s;
        const auto d = eval_registry(
            a, RegistrySnapshot{.present = true, .supported = false}, s, 0, at_ms(0));
        REQUIRE(d->detected_value == "<unsupported-type>");
    }
}

TEST_CASE("eval_service: running/stopped verdict + tokens", "[spark][eval]") {
    {
        RuleAssertion a;
        a.kind = AssertionKind::ServiceRunning;
        a.rule_id = "r";
        RuleEvalState s;
        const auto d = eval_service(a, ServiceRunState::Running, s, at_ms(0));
        REQUIRE(d.has_value());
        REQUIRE(d->guard_type == "service");
        REQUIRE(d->compliant);
        REQUIRE(d->detected_value == "running");
        REQUIRE(d->expected_value == "running");
        // A stopped service drifts a service-running rule.
        const auto drift = eval_service(a, ServiceRunState::Stopped, s, at_ms(10));
        REQUIRE(drift.has_value());
        REQUIRE_FALSE(drift->compliant);
        REQUIRE(drift->detected_value == "stopped");
    }
    {
        RuleAssertion a;
        a.kind = AssertionKind::ServiceStopped;
        a.rule_id = "r";
        RuleEvalState s;
        // Paused drifts a service-stopped rule (paused != stopped).
        const auto d = eval_service(a, ServiceRunState::Paused, s, at_ms(0));
        REQUIRE(d.has_value());
        REQUIRE_FALSE(d->compliant);
        REQUIRE(d->detected_value == "paused");
        REQUIRE(d->expected_value == "stopped");
    }
}

TEST_CASE("eval_service: emit_compliant_edge=false keeps compliant silent (systemd parity)",
          "[spark][eval]") {
    RuleAssertion a;
    a.kind = AssertionKind::ServiceRunning;
    a.rule_id = "r";
    RuleEvalState s;
    REQUIRE_FALSE(
        eval_service(a, ServiceRunState::Running, s, at_ms(0), /*emit_compliant_edge=*/false)
            .has_value());
}
