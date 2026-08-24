/**
 * test_content_dist_exec_parsers.cpp — pure-parser coverage for
 * `content_dist`'s `execute_staged` action (content_dist_exec_parsers.hpp),
 * the decision layer around the plugin's cross-platform migration onto
 * yuzu::agent::run_bounded_subprocess (deleting the plugin's private
 * OS-specific direct-argv spawn helpers).
 *
 * Fixture-constructed yuzu::agent::SubprocessResult values only — no
 * process spawns, no OS calls, no sleeps. The runner's own spawn/reap
 * machinery is covered by test_subprocess_runner.cpp; this file pins only
 * the two pure decisions content_dist owns: which SubprocessOptions
 * `execute_staged` runs with (build_execution_options), and how a completed
 * run's SubprocessResult maps onto the status|/exit_code|/output| wire
 * lines the plugin's deleted spawn paths used to produce directly
 * (map_execution_result).
 */
#include "content_dist_exec_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cerrno>
#include <string>

using namespace yuzu::content_dist::exec;
using yuzu::agent::SubprocessResult;
using yuzu::agent::TerminationReason;

// ── build_execution_options ──────────────────────────────────────────────

TEST_CASE("build_execution_options sets the fixed deadline/merge/output-cap trio",
         "[agent][content_dist][exec]") {
    auto opts = build_execution_options(/*is_linux=*/false);
    CHECK(opts.deadline == std::chrono::seconds(30));
    CHECK(opts.merge_stderr);
    CHECK(opts.output_cap_bytes == 16u * 1024 * 1024);
}

TEST_CASE("build_execution_options enables exec_verify only when is_linux is true",
         "[agent][content_dist][exec]") {
    auto linux_opts = build_execution_options(true);
    CHECK(linux_opts.exec_verify.enabled);

    auto non_linux_opts = build_execution_options(false);
    CHECK_FALSE(non_linux_opts.exec_verify.enabled);
}

TEST_CASE("build_execution_options leaves require_root_owned false on every platform",
         "[agent][content_dist][exec]") {
    // Deliberate: the staging dir is agent-owned 0700, not root -- see the
    // header's own rationale comment. require_root_owned=true would
    // spawn_error every staged file on a rootless agent.
    CHECK_FALSE(build_execution_options(true).exec_verify.require_root_owned);
    CHECK_FALSE(build_execution_options(false).exec_verify.require_root_owned);
}

TEST_CASE("build_execution_options never sets expected_size -- that is the caller's job",
         "[agent][content_dist][exec]") {
    auto opts = build_execution_options(true);
    CHECK_FALSE(opts.exec_verify.expected_size.has_value());
}

// ── map_execution_result: exited ─────────────────────────────────────────

TEST_CASE("map_execution_result: exited with rc==0 reports status|ok", "[agent][content_dist][exec]") {
    SubprocessResult r;
    r.tool_ran = true;
    r.termination_reason = TerminationReason::exited;
    r.exit_code = 0;
    r.output = "all good\n";

    auto wire = map_execution_result(r);
    CHECK(wire.status == "ok");
    CHECK(wire.exit_code == 0);
    CHECK(wire.output == "all good\n");
}

TEST_CASE("map_execution_result: exited with nonzero rc reports status|error",
         "[agent][content_dist][exec]") {
    SubprocessResult r;
    r.tool_ran = true;
    r.termination_reason = TerminationReason::exited;
    r.exit_code = 42;
    r.output = "boom";

    auto wire = map_execution_result(r);
    CHECK(wire.status == "error");
    CHECK(wire.exit_code == 42);
    CHECK(wire.output == "boom");
}

TEST_CASE("map_execution_result: exited with empty output produces an empty output field",
         "[agent][content_dist][exec]") {
    SubprocessResult r;
    r.tool_ran = true;
    r.termination_reason = TerminationReason::exited;
    r.exit_code = 0;
    r.output = "";

    auto wire = map_execution_result(r);
    // Empty here signals the call site to omit the output| line entirely --
    // matches the deleted code's `if (!output.empty())` guard.
    CHECK(wire.output.empty());
}

// ── map_execution_result: output_truncated ───────────────────────────────

TEST_CASE("map_execution_result: output_truncated appends the truncation notice",
         "[agent][content_dist][exec]") {
    SubprocessResult r;
    r.tool_ran = true;
    r.termination_reason = TerminationReason::exited;
    r.exit_code = 0;
    r.output = "partial output";
    r.output_truncated = true;

    auto wire = map_execution_result(r);
    CHECK(wire.status == "ok");
    CHECK(wire.output == "partial output\n[output truncated at 16 MiB]");
}

// ── map_execution_result: deadline / cancelled ───────────────────────────

TEST_CASE("map_execution_result: deadline reports status|error, exit_code|-1, and a "
         "termination notice appended to captured output",
         "[agent][content_dist][exec]") {
    SubprocessResult r;
    r.tool_ran = true;
    r.termination_reason = TerminationReason::deadline;
    r.exit_code = -1;
    r.timed_out = true;
    r.output = "partial output before kill";

    auto wire = map_execution_result(r);
    CHECK(wire.status == "error");
    CHECK(wire.exit_code == -1);
    CHECK(wire.output == "partial output before kill\n[terminated: deadline exceeded]");
}

TEST_CASE("map_execution_result: cancelled maps the same way as deadline",
         "[agent][content_dist][exec]") {
    SubprocessResult r;
    r.tool_ran = true;
    r.termination_reason = TerminationReason::cancelled;
    r.exit_code = -1;
    r.timed_out = true;
    r.output = "";

    auto wire = map_execution_result(r);
    CHECK(wire.status == "error");
    CHECK(wire.exit_code == -1);
    CHECK(wire.output == "\n[terminated: deadline exceeded]");
}

TEST_CASE("map_execution_result: a pre-armed cancel that fires before exec is confirmed "
         "still reports cancelled, not spawn failed",
         "[agent][content_dist][exec]") {
    // subprocess_runner.cpp: when a pre-armed cancel (or a very tight
    // deadline) kills the child on its very first poll, tool_ran can still
    // be false (exec was never positively confirmed) while
    // termination_reason is correctly cancelled/deadline, not spawn_error.
    // deadline/cancelled MUST be checked before tool_ran or this legitimate
    // combination gets misreported as "spawn failed (errno 0: Success)".
    SubprocessResult r;
    r.tool_ran = false;
    r.termination_reason = TerminationReason::cancelled;
    r.exit_code = -1;
    r.timed_out = true;
    r.spawn_errno = 0;
    r.output = "";

    auto wire = map_execution_result(r);
    CHECK(wire.status == "error");
    CHECK(wire.exit_code == -1);
    CHECK(wire.output == "\n[terminated: deadline exceeded]");
}

TEST_CASE("map_execution_result: a pre-armed deadline kill with tool_ran==false maps the "
         "same way",
         "[agent][content_dist][exec]") {
    SubprocessResult r;
    r.tool_ran = false;
    r.termination_reason = TerminationReason::deadline;
    r.exit_code = -1;
    r.timed_out = true;
    r.spawn_errno = 0;
    r.output = "";

    auto wire = map_execution_result(r);
    CHECK(wire.status == "error");
    CHECK(wire.exit_code == -1);
    CHECK(wire.output == "\n[terminated: deadline exceeded]");
}

// ── map_execution_result: spawn_error ────────────────────────────────────

TEST_CASE("map_execution_result: spawn_error (tool_ran==false) reports the errno and strerror",
         "[agent][content_dist][exec]") {
    SubprocessResult r;
    r.tool_ran = false;
    r.termination_reason = TerminationReason::spawn_error;
    r.exit_code = -1;
    r.spawn_errno = ENOENT;

    auto wire = map_execution_result(r);
    CHECK(wire.status == "error");
    CHECK(wire.exit_code == -1);
    CHECK(wire.output.find("spawn failed (errno " + std::to_string(ENOENT) + ":") == 0);
}

TEST_CASE("map_execution_result: spawn_error from a B6 exec_verify rejection (EACCES) maps "
         "the same way as any other spawn failure",
         "[agent][content_dist][exec]") {
    SubprocessResult r;
    r.tool_ran = false;
    r.termination_reason = TerminationReason::spawn_error;
    r.exit_code = -1;
    r.spawn_errno = EACCES;

    auto wire = map_execution_result(r);
    CHECK(wire.status == "error");
    CHECK(wire.exit_code == -1);
    CHECK(wire.output.find("spawn failed (errno " + std::to_string(EACCES) + ":") == 0);
}

TEST_CASE("map_execution_result: tool_ran==false takes priority over a non-kill "
         "termination_reason",
         "[agent][content_dist][exec]") {
    // A spawn_error result should never fall into the exited branch even if
    // termination_reason were somehow left stale -- tool_ran is the
    // authoritative signal for "exec never confirmed" (subprocess_runner.hpp)
    // once deadline/cancelled (checked first -- see the two pre-armed-kill
    // test cases above) have been ruled out.
    SubprocessResult r;
    r.tool_ran = false;
    r.termination_reason = TerminationReason::exited; // deliberately inconsistent
    r.exit_code = 0;
    r.spawn_errno = ENOENT;

    auto wire = map_execution_result(r);
    CHECK(wire.status == "error");
    CHECK(wire.output.find("spawn failed") == 0);
}

// ── map_execution_result: signaled (residual case) ───────────────────────

TEST_CASE("map_execution_result: signaled reports status|error with the runner's -1 sentinel",
         "[agent][content_dist][exec]") {
    SubprocessResult r;
    r.tool_ran = true;
    r.termination_reason = TerminationReason::signaled;
    r.exit_code = -1;
    r.output = "crashed";

    auto wire = map_execution_result(r);
    CHECK(wire.status == "error");
    CHECK(wire.exit_code == -1);
    CHECK(wire.output == "crashed");
}

// ── is_shebang_payload (CDX-002) ──────────────────────────────────────────

TEST_CASE("is_shebang_payload: a genuine shebang prefix is true", "[agent][content_dist][exec]") {
    CHECK(is_shebang_payload("#!/bin/sh\n"));
    CHECK(is_shebang_payload("#!/usr/bin/env python3\n"));
}

TEST_CASE("is_shebang_payload: a bare '#' is false", "[agent][content_dist][exec]") {
    CHECK_FALSE(is_shebang_payload("#"));
}

TEST_CASE("is_shebang_payload: '#' followed by a non-'!' byte is false",
         "[agent][content_dist][exec]") {
    CHECK_FALSE(is_shebang_payload("#x"));
}

TEST_CASE("is_shebang_payload: ELF magic is false", "[agent][content_dist][exec]") {
    CHECK_FALSE(is_shebang_payload("\x7f" "ELF"));
}

TEST_CASE("is_shebang_payload: empty input is false", "[agent][content_dist][exec]") {
    CHECK_FALSE(is_shebang_payload(""));
}
