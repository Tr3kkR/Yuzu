/**
 * test_tar_capture_status.cpp -- fixture-fed tests for
 * tar_capture_status.hpp's classify_subprocess_capture(), the pure predicate
 * that decides whether a bounded-subprocess capture is complete enough to
 * diff/persist as authoritative TAR state (BR-001).
 *
 * No test here spawns a process, sleeps, or touches the network -- every
 * case feeds fixed tool_ran/timed_out/output_truncated/exit_code values
 * straight to the pure classifier, exactly the fields SubprocessResult
 * carries at runtime (agents/core/include/yuzu/agent/subprocess_runner.hpp).
 *
 * This suite exists specifically because the prior TAR test suites (BR-005)
 * exercised only parsed lines/blobs and never these SubprocessResult status
 * fields -- letting a partial-capture-persisted-as-complete bug pass the
 * whole green TAR suite. Every state SubprocessResult can report is covered
 * here: a clean complete run, spawn failure, deadline, output-cap
 * truncation, and non-zero exit -- both with the default zero_exit_required
 * policy and with it explicitly relaxed for a command whose documented
 * success path is legitimately non-zero.
 */

#include "tar_capture_status.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::tar;

TEST_CASE("classify_subprocess_capture: a clean completed run is complete", "[tar_capture_status]") {
    auto status = classify_subprocess_capture(/*tool_ran=*/true, /*timed_out=*/false,
                                              /*output_truncated=*/false, /*exit_code=*/0);
    CHECK(status.complete);
    CHECK(status.reason.empty());
}

TEST_CASE("classify_subprocess_capture: spawn failure is incomplete", "[tar_capture_status]") {
    // Mirrors SubprocessResult's own contract: tool_ran=false means exec
    // itself never positively succeeded (missing binary, not executable,
    // etc) -- termination_reason == spawn_error at the runner level.
    auto status = classify_subprocess_capture(/*tool_ran=*/false, /*timed_out=*/false,
                                              /*output_truncated=*/false, /*exit_code=*/-1);
    CHECK_FALSE(status.complete);
    CHECK(status.reason == "spawn failed");
}

TEST_CASE("classify_subprocess_capture: a deadline kill is incomplete even if the child produced output",
          "[tar_capture_status]") {
    // A killed child can still have tool_ran=true (it ran and emitted some
    // output before being killed) -- timed_out is what actually disqualifies
    // it, exactly as subprocess_runner.hpp documents callers MUST check.
    auto status = classify_subprocess_capture(/*tool_ran=*/true, /*timed_out=*/true,
                                              /*output_truncated=*/false, /*exit_code=*/-1);
    CHECK_FALSE(status.complete);
    CHECK(status.reason == "deadline exceeded");
}

TEST_CASE("classify_subprocess_capture: output-cap truncation is incomplete even on a clean exit",
          "[tar_capture_status]") {
    // The child can exit 0 and still have output_truncated=true if it wrote
    // past the byte cap before exiting -- the captured lines/output only
    // reflect what was captured before the cap, per SubprocessResult's own
    // contract, so this must not be treated as a genuine empty/short result.
    auto status = classify_subprocess_capture(/*tool_ran=*/true, /*timed_out=*/false,
                                              /*output_truncated=*/true, /*exit_code=*/0);
    CHECK_FALSE(status.complete);
    CHECK(status.reason == "output capped");
}

TEST_CASE("classify_subprocess_capture: non-zero exit is incomplete when zero-exit is required",
          "[tar_capture_status]") {
    auto status = classify_subprocess_capture(/*tool_ran=*/true, /*timed_out=*/false,
                                              /*output_truncated=*/false, /*exit_code=*/1);
    CHECK_FALSE(status.complete);
    CHECK(status.reason == "exit code 1");
}

TEST_CASE("classify_subprocess_capture: non-zero exit is tolerated when the caller opts out",
          "[tar_capture_status]") {
    // Precedent: this repo has been bitten by treating a documented
    // success-with-nonzero-exit tool (dnf check-update exits 100) as a
    // failure. No current TAR call site needs this today (systemctl,
    // launchctl, smbstatus, wevtutil, journalctl all verified/documented to
    // exit 0 on success -- see the call sites), but the escape hatch itself
    // must work correctly for the day one does.
    auto status = classify_subprocess_capture(/*tool_ran=*/true, /*timed_out=*/false,
                                              /*output_truncated=*/false, /*exit_code=*/100,
                                              /*zero_exit_required=*/false);
    CHECK(status.complete);
    CHECK(status.reason.empty());
}

TEST_CASE("classify_subprocess_capture: timed_out takes priority over a reported exit code",
          "[tar_capture_status]") {
    // A deadline-killed child never reports a real exit_code (subprocess_runner.hpp
    // leaves it at the -1 sentinel) -- but even if a future runner change ever
    // reported one alongside timed_out=true, timed_out must still win: the
    // capture is not authoritative regardless of what exit_code says.
    auto status = classify_subprocess_capture(/*tool_ran=*/true, /*timed_out=*/true,
                                              /*output_truncated=*/false, /*exit_code=*/0);
    CHECK_FALSE(status.complete);
    CHECK(status.reason == "deadline exceeded");
}
