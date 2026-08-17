// runner_status.hpp is the ONE mapping from a bounded-runner outcome to the
// ABI4 plugin->host result seam (Wave 2, ADR-3002). classify_runner_failure
// is pure (no context, no spawn), so every TerminationReason branch is
// fixture-testable here without a live subprocess.
#include <catch2/catch_test_macros.hpp>

#include <runner_status.hpp>

#include <yuzu/agent/subprocess_runner.hpp>
#include <yuzu/plugin.h>

#include <string>

using yuzu::agent::SubprocessResult;
using yuzu::agent::TerminationReason;
using yuzu::shared::classify_runner_failure;

namespace {

SubprocessResult result_with(TerminationReason reason) {
    SubprocessResult r;
    r.termination_reason = reason;
    return r;
}

} // namespace

TEST_CASE("classify_runner_failure: spawn_error -> UNAVAILABLE/PARTIAL", "[agent][runner_status]") {
    const auto s = classify_runner_failure(result_with(TerminationReason::spawn_error));
    REQUIRE(s.has_value());
    CHECK(s->status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(s->completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(std::string(s->provenance) == "subprocess_runner:spawn_error");
}

TEST_CASE("classify_runner_failure: deadline -> CONSTRAINED/PARTIAL", "[agent][runner_status]") {
    const auto s = classify_runner_failure(result_with(TerminationReason::deadline));
    REQUIRE(s.has_value());
    CHECK(s->status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(s->completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(std::string(s->provenance) == "subprocess_runner:deadline");
}

TEST_CASE("classify_runner_failure: cancelled -> CONSTRAINED/PARTIAL", "[agent][runner_status]") {
    const auto s = classify_runner_failure(result_with(TerminationReason::cancelled));
    REQUIRE(s.has_value());
    CHECK(s->status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(s->completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(std::string(s->provenance) == "subprocess_runner:cancelled");
}

TEST_CASE("classify_runner_failure: signaled -> CONSTRAINED/PARTIAL", "[agent][runner_status]") {
    const auto s = classify_runner_failure(result_with(TerminationReason::signaled));
    REQUIRE(s.has_value());
    CHECK(s->status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(s->completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(std::string(s->provenance) == "subprocess_runner:signaled");
}

TEST_CASE("classify_runner_failure: exited -> nullopt (caller owns exit-code semantics)",
         "[agent][runner_status]") {
    const auto s = classify_runner_failure(result_with(TerminationReason::exited));
    CHECK_FALSE(s.has_value());
}

TEST_CASE("classify_runner_failure: line_limit -> nullopt (clean bounded stop)",
         "[agent][runner_status]") {
    const auto s = classify_runner_failure(result_with(TerminationReason::line_limit));
    CHECK_FALSE(s.has_value());
}
