#pragma once

/// @file content_dist_exec_parsers.hpp
/// PURE decision layer for `content_dist`'s `execute_staged` action: the
/// yuzu::agent::SubprocessOptions this plugin runs every staged-file
/// invocation with, and the wire mapping of the resulting
/// yuzu::agent::SubprocessResult back onto content_dist's
/// status|/exit_code|/output| lines. No OS calls, no subprocess spawn, no
/// filesystem, no clock read — content_dist_plugin.cpp's `do_execute` is
/// the thin runner-calling shell around this header (same split as
/// firewall_parsers.hpp / content_dist_upload_parsers.hpp).
///
/// This plugin replaced its private OS-specific direct-argv spawn helpers
/// (a Windows child-process launcher and a POSIX child-process launcher)
/// with one cross-platform call to
/// yuzu::agent::run_bounded_subprocess (agents/core/src/subprocess_runner.cpp,
/// ADR-3002). The two functions below are the exact decision points a
/// reviewer needs to audit for that migration: what options the call runs
/// with, and how its result maps back onto the SAME wire lines, in the SAME
/// order, the deleted spawn paths produced.

#include <yuzu/agent/subprocess_runner.hpp>

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace yuzu::content_dist::exec {

/// True iff `first_bytes` begins with a shebang ("#!"). Pure decision only
/// -- `do_execute` reads the staged file's first two bytes itself (thin
/// shell, at the call site) and passes them here; this function never
/// touches the filesystem. Used to reject shebang-interpreted scripts
/// before the runner call on Linux: B6 exec_verify's fd-exec primitive
/// (execveat with O_CLOEXEC) closes the verified fd before the kernel's
/// binfmt_script handler gets a chance to re-open the interpreter path,
/// so a shebang script cannot run under fd-exec at all -- better to reject
/// it up front with an actionable message than let it spawn_error opaquely.
[[nodiscard]] inline bool is_shebang_payload(std::string_view first_bytes) {
    return first_bytes.size() >= 2 && first_bytes[0] == '#' && first_bytes[1] == '!';
}

/// The fixed SubprocessOptions `do_execute` runs every `execute_staged`
/// invocation with. `is_linux` is the only axis that varies the result —
/// pass `true` only on an actual Linux build (`#ifdef __linux__` at the
/// call site), never based on a runtime guess. The caller still MUST set
/// `.exec_verify.expected_size` on the returned options afterward, once the
/// staged file's hash-verified size is known: this function never touches
/// the filesystem, so it cannot know that size itself.
[[nodiscard]] inline yuzu::agent::SubprocessOptions build_execution_options(bool is_linux) {
    yuzu::agent::SubprocessOptions opts;

    // 30s: preserves the deleted Windows path's
    // WaitForSingleObject(pi.hProcess, 30000) timeout exactly. The deleted
    // POSIX path never bounded its own read/waitpid loop at all -- this is
    // a deliberate tightening to match the Windows leg's existing external
    // contract rather than a second, wider, platform-specific bound.
    opts.deadline = std::chrono::seconds(30);

    // Both deleted paths merged stderr into the SAME captured stream as
    // stdout: the Windows launcher pointed its error handle at the same
    // pipe as its output handle, and the POSIX launcher duplicated its
    // pipe's write end onto both the child's stdout and stderr file
    // descriptors. Preserve that.
    opts.merge_stderr = true;

    // The runner's own maximum (subprocess_runner.hpp clamps
    // output_cap_bytes to [1, 16*1024*1024]). The deleted paths captured
    // output UNBOUNDED (a plain 1024-byte read loop with no cap) -- 16 MiB
    // is the smallest behaviour delta a caller-configurable cap can produce
    // relative to "no cap at all".
    opts.output_cap_bytes = 16 * 1024 * 1024;

    // B6 TOCTOU-safe exec (subprocess_runner.hpp): Linux-only, and this MUST
    // stay Linux-only. macOS/BSD has no fd-exec syscall to close the
    // fstat-verify -> exec gap and FAILS CLOSED (spawn_error) if enabled
    // there; Windows verification isn't implemented and fails closed too.
    // Setting this unconditionally would make execute_staged spawn_error on
    // every single invocation on macOS and Windows.
    opts.exec_verify.enabled = is_linux;

    // DELIBERATELY false -- NOT the runner's require_root_owned=true
    // default. The staging directory (`staging_dir()` in
    // content_dist_plugin.cpp) is created agent-owned 0700, never root, so
    // on a rootless agent deployment every staged file is owned by the
    // agent's own unprivileged account. require_root_owned=true would
    // fstat-reject (spawn_error) EVERY staged file on EVERY rootless agent
    // -- execute_staged would never work at all outside a root-installed
    // agent. Integrity here does not come from file ownership; it comes
    // from `do_execute`'s MANDATORY hash re-verification against agent KV
    // (#808 -- a separate SQLite DB the staging-dir attacker can't also
    // rewrite) plus this fd-exec's own TOCTOU closure, plus the runner's
    // retained not-group/other-writable check.
    opts.exec_verify.require_root_owned = false;

    return opts;
}

/// The three status|/exit_code|/output| wire lines `do_execute` emits, in
/// that exact order. `output` already carries any truncation/termination
/// annotation this mapping adds; an empty `output` means "no output| line
/// at all" (the pre-runner code's `if (!output.empty())` guard, preserved
/// verbatim at the call site).
struct ExecutionWireResult {
    std::string status;    ///< "ok" or "error" -- content of the status| line
    int exit_code = -1;    ///< content of the exit_code| line
    std::string output;    ///< content of the output| line; empty -> line omitted
};

/// Maps a completed run_bounded_subprocess() call onto the exact
/// status|/exit_code|/output| lines the plugin's deleted OS-specific
/// spawn paths produced (content_dist_plugin.cpp, previously
/// `status|{rc==0?"ok":"error"}` / `exit_code|{rc}` / `output|{output}`),
/// for every outcome `execute_staged` can actually observe. `line_limit` is
/// excluded by construction: this plugin never sets
/// max_lines/stop_after_max_lines, so a line_limit result can never reach
/// this function.
[[nodiscard]] inline ExecutionWireResult
map_execution_result(const yuzu::agent::SubprocessResult& result) {
    // deadline/cancelled are checked BEFORE tool_ran: the runner's own
    // termination_reason priority (subprocess_runner.cpp) classifies a
    // deliberate kill by its reason EVEN IF exec was never positively
    // confirmed -- when a pre-armed cancel (or a very tight deadline) kills
    // the child on its very first poll, tool_ran can still be false (exec
    // was never confirmed) while termination_reason is correctly
    // deadline/cancelled, not spawn_error. Checking tool_ran first would
    // misreport that case as "spawn failed (errno 0: Success)" and drop the
    // deadline/cancelled reason the caller needs to pick the right retry
    // policy. A killed-at-the-boundary run may still have captured partial
    // output before the kill; report it, annotated, rather than silently
    // discarding it.
    if (result.termination_reason == yuzu::agent::TerminationReason::deadline ||
        result.termination_reason == yuzu::agent::TerminationReason::cancelled) {
        std::string output = result.output + "\n[terminated: deadline exceeded]";
        return ExecutionWireResult{"error", -1, std::move(output)};
    }

    // tool_ran == false is authoritative for "exec itself never positively
    // succeeded" -- spawn_error, covering both a missing/non-executable
    // binary and a B6 exec_verify rejection -- matching tool_ran's own
    // documented contract (subprocess_runner.hpp). Reached only once the
    // deadline/cancelled kill classification above has already been ruled
    // out.
    if (!result.tool_ran) {
        return ExecutionWireResult{
            "error", -1,
            "spawn failed (errno " + std::to_string(result.spawn_errno) + ": " +
                std::generic_category().message(result.spawn_errno) + ")"};
    }

    // The ordinary `exited` case, and the residual `signaled` case (the
    // child died of a signal it received itself -- e.g. a crash -- never
    // one the runner sent; exit_code stays the runner's -1 sentinel either
    // way per SubprocessResult's contract) both resolve the same way the
    // deleted POSIX path's `WIFEXITED(status) ? WEXITSTATUS(status) : -1`
    // already collapsed them: report whatever `exit_code` the reap
    // produced, with no extra annotation beyond a truncation notice.
    std::string output = result.output;
    if (result.output_truncated)
        output += "\n[output truncated at 16 MiB]";
    return ExecutionWireResult{result.exit_code == 0 ? "ok" : "error", result.exit_code,
                               std::move(output)};
}

} // namespace yuzu::content_dist::exec
