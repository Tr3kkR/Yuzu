#pragma once

// tar_capture_status.hpp -- pure predicate for whether a bounded-subprocess
// capture is complete enough to trust as an authoritative TAR snapshot.
//
// Background: run_bounded_subprocess (agents/core/include/yuzu/agent/
// subprocess_runner.hpp) distinguishes "the child ran to completion" from
// "the deadline/output cap cut it off" via SubprocessResult::{tool_ran,
// timed_out, output_truncated, exit_code}. Several TAR collectors migrated
// from popen to that runner but kept the old popen-era check (only
// `tool_ran`), so a command that hit the deadline or the output cap still
// had its (partial) lines/output parsed and diffed against the previous
// COMPLETE snapshot -- fabricating durable "stopped"/"removed" forensic
// events for every row the partial run happened not to reach, followed by
// compensating false "started"/"appeared" events once a complete run
// replaces the partial one as the new baseline. This header is the single
// place that decision is made, so it is unit-testable without spawning a
// process (tests/unit/test_tar_service.cpp, tests/unit/test_tar_mapdrive.cpp)
// and every collector site applies the identical policy.
//
// zero_exit_required defaults to true because every command this repo wraps
// through the runner today (systemctl list-units, launchctl list, smbstatus
// -b, wevtutil qe, journalctl -u ... -n) is verified or documented to exit 0
// on a normal empty-result run -- see the call sites in
// tar_service_collector.cpp / tar_mapdrive_collector.cpp for what was
// verified on a live host versus assumed from documented behaviour. A future
// command whose *documented* success path is legitimately non-zero (this
// repo has been bitten by exactly that with `dnf check-update` exiting 100)
// must pass zero_exit_required=false at its own call site rather than
// weakening this default for everyone.

#include <string>

namespace yuzu::tar {

/// Why a capture was (or was not) judged complete -- `complete` is the
/// verdict a caller acts on; `reason` is populated only when `!complete`,
/// for logging (never a fabricated verdict, never silent).
struct CaptureCompleteness {
    bool complete{false};
    std::string reason;
};

/// Pure completeness check over a bounded-subprocess result's status fields
/// (passed individually rather than as a SubprocessResult so this header
/// stays free of any dependency on agents/core, and so a test can construct
/// every combination directly). A capture is authoritative only when the
/// child actually ran, was not killed at the deadline, was not cut off by
/// the output cap, and -- unless the caller says this command's success is
/// legitimately non-zero -- exited 0.
inline CaptureCompleteness classify_subprocess_capture(bool tool_ran, bool timed_out,
                                                        bool output_truncated, int exit_code,
                                                        bool zero_exit_required = true) {
    if (!tool_ran)
        return CaptureCompleteness{.complete = false, .reason = "spawn failed"};
    if (timed_out)
        return CaptureCompleteness{.complete = false, .reason = "deadline exceeded"};
    if (output_truncated)
        return CaptureCompleteness{.complete = false, .reason = "output capped"};
    if (zero_exit_required && exit_code != 0)
        return CaptureCompleteness{.complete = false,
                                   .reason = "exit code " + std::to_string(exit_code)};
    return CaptureCompleteness{.complete = true, .reason = {}};
}

} // namespace yuzu::tar
