#pragma once

// event_logs_macos.hpp -- pure `log show` SubprocessResult -> (rows, rc)
// decision for the event_logs plugin's macOS "errors" and "query" actions
// (BR-08).
//
// event_logs_plugin.cpp's macOS branches previously checked ONLY
// result.timed_out before falling back to "result.lines.empty() -> rc-0
// none found" -- so a `log show` that never ran (missing from PATH), exited
// non-zero, or hit the internal output-truncation cap was silently reported
// as an honest empty search, indistinguishable from a genuine one.
//
// decide_log_show_output() is the single decision point both actions'
// macOS branches call: given an already-captured yuzu::agent::SubprocessResult
// plus the action's row prefix ("error"/"event") and its clean-empty message
// text, it returns the EXACT output rows to emit (already formatted in the
// plugin's existing pipe-delimited shape) and the return code -- the plugin
// shell does nothing but call this and emit what it returns.
//
// Never spawns a process -- the plugin owns the run_bounded_subprocess call
// and hands this header the already-captured result, so the decision is
// fixture-testable on every CI host without a macOS box or the real `log`
// binary.

#include <yuzu/agent/subprocess_runner.hpp>

#include <format>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::event_logs_macos {

enum class LogShowOutcome {
    ok,          // Completed normally; result.lines (possibly empty) is the
                 // whole honest picture -- callers may report rc 0.
    timed_out,   // Wall-clock deadline elapsed before `log show` finished.
    unavailable, // `log show` never ran, exited non-zero, or its captured
                 // output was truncated -- distinguishable from a genuine
                 // empty search, never folded into it.
};

// `outcome == ok` carries an empty `reason`; `timed_out`/`unavailable`
// carry the sentinel-row message text appended after any partial lines.
struct LogShowClassification {
    LogShowOutcome outcome = LogShowOutcome::ok;
    std::string_view reason;
};

inline LogShowClassification
classify_log_show_result(const yuzu::agent::SubprocessResult& result) {
    if (result.timed_out)
        return {LogShowOutcome::timed_out, "log show timed out before completing"};

    // !tool_ran means exec() itself never got off the ground (log missing
    // from PATH, etc) -- an honest "unknown", never a fabricated empty
    // search.
    if (!result.tool_ran)
        return {LogShowOutcome::unavailable, "log show did not run"};

    // log show ran and reported a real problem (bad predicate, permission
    // denial, etc) -- a nonzero exit is never silently treated as "no
    // matches".
    if (result.exit_code != 0)
        return {LogShowOutcome::unavailable, "log show exited with an error"};

    // Capture hit the internal sanity cap before log show finished --
    // whatever was collected is real, but incomplete, so it must not be
    // reported as the whole (possibly empty) picture.
    if (result.output_truncated)
        return {LogShowOutcome::unavailable, "log show output was truncated"};

    return {LogShowOutcome::ok, {}};
}

// The full row/rc decision both macOS branches emit unmodified.
struct LogShowDecision {
    std::vector<std::string> rows;
    int rc = 0;
};

// Formats one raw `log show --style compact` line into the plugin's
// "<row_prefix>|timestamp|process|message" shape (message capped at 200
// chars). Falls back to "<row_prefix>|line|-|line" when the compact
// double-space columns aren't present. Identical logic previously lived
// twice (do_errors' emit_error_line / do_query's emit_event_line) --
// row_prefix is the only thing that ever differed between them.
inline std::string format_log_show_line(std::string_view row_prefix, const std::string& line) {
    auto first_space = line.find("  ");
    if (first_space == std::string::npos)
        return std::format("{}|{}|-|{}", row_prefix, line, line);

    auto timestamp = line.substr(0, first_space);
    auto rest = line.substr(first_space + 2);
    auto second_space = rest.find("  ");
    std::string process = "-";
    std::string message = rest;
    if (second_space != std::string::npos) {
        process = rest.substr(0, second_space);
        message = rest.substr(second_space + 2);
    }
    if (message.size() > 200)
        message = message.substr(0, 200);
    return std::format("{}|{}|{}|{}", row_prefix, timestamp, process, message);
}

// The single SubprocessResult -> (rows, rc) decision for both macOS
// branches ("errors" passes row_prefix "error" + its "No error events
// found" message; "query" passes "event" + "No matching events found").
// Covers every case:
//   (a) timed_out          -> partial lines, then an honest timeout row, rc 1
//   (b) unavailable         -> partial lines, then an honest unavailable row, rc 1
//       (!tool_ran / nonzero exit_code / output_truncated)
//   (c) ok + no lines       -> the clean-empty row, rc 0
//   (d) ok + lines          -> the formatted lines, rc 0
// The plugin shell's job is reduced to calling this and emitting what it
// returns -- it makes no rows/rc decision of its own.
inline LogShowDecision decide_log_show_output(const yuzu::agent::SubprocessResult& result,
                                               std::string_view row_prefix,
                                               std::string_view empty_message) {
    LogShowDecision decision;

    auto classification = classify_log_show_result(result);
    if (classification.outcome != LogShowOutcome::ok) {
        // Never masquerade a timeout, a missing/failing `log show`, or a
        // truncated capture as an empty success: emit whatever partial
        // lines were collected, then an honest incomplete-query row in the
        // same 4-column shape.
        for (const auto& line : result.lines)
            decision.rows.push_back(format_log_show_line(row_prefix, line));
        const char* tag =
            classification.outcome == LogShowOutcome::timed_out ? "timeout" : "unavailable";
        decision.rows.push_back(
            std::format("{}|{}|-|{}", row_prefix, tag, classification.reason));
        decision.rc = 1;
        return decision;
    }

    if (result.lines.empty()) {
        decision.rows.push_back(std::format("{}|none|-|{}", row_prefix, empty_message));
        decision.rc = 0;
        return decision;
    }

    for (const auto& line : result.lines)
        decision.rows.push_back(format_log_show_line(row_prefix, line));
    decision.rc = 0;
    return decision;
}

} // namespace yuzu::event_logs_macos
