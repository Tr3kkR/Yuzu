#pragma once

/// @file content_dist_exec_seam.hpp
/// IMPURE integration shell for content_dist's `execute_staged` action --
/// everything `do_execute` (content_dist_plugin.cpp) does AFTER the #808 KV
/// hash re-verification gate: the Linux shebang rejection (CDX-002), the
/// caller-args safety check, the POSIX chmod, argv assembly,
/// `build_execution_options`/`run_bounded_subprocess`/`map_execution_result`
/// (content_dist_exec_parsers.hpp), and the exact wire lines the action
/// emits, in the exact order it emits them.
///
/// BR-006 (whole-branch review round 2): content_dist_plugin.cpp's `g_ctx`
/// (agent KV) is set only by the plugin's real `init()`, which the
/// LocalDispatcher test harness never calls (see
/// test_content_dist_actions.cpp's header comment for the full "no
/// legitimate way to drive a staged, hash-verified execute_staged end to
/// end" wall) -- so no unit test could previously drive a real,
/// hash-verified `execute_staged` invocation through the actual runner
/// call, leaving exactly the kind of call-site wiring defect BR-001 (POSIX
/// inherit_parent_env) turned out to be entirely uncovered by any existing
/// test. `execute_verified_payload` below is `do_execute`'s
/// post-hash-verification logic, extracted so a test can call it directly
/// against a REAL staged file -- a real chmod, a real run_bounded_subprocess
/// spawn, real result mapping -- with no plugin ABI, no KV, and no `g_ctx`
/// anywhere in the call path (test_content_dist_exec_seam.cpp). `do_execute`
/// is now a thin shell: resolve+hash-verify the staged path via KV, call
/// this, forward the returned SubprocessResult through the ABI4
/// result-status seam, and write the returned lines verbatim.
///
/// This header performs real OS I/O (filesystem, subprocess spawn) --
/// deliberately NOT part of content_dist_exec_parsers.hpp, whose whole
/// contract is "no OS calls" (see that file's own header comment). Kept as
/// its own file so the pure mapping/options layer stays trivially
/// fuzzable/golden-testable, and so this file's OS surface is opt-in for
/// whatever includes it.

#include "content_dist_exec_parsers.hpp"

#include <yuzu/agent/subprocess_runner.hpp>

#include <filesystem>
#include <format>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#ifdef _WIN32
#include <win_str.hpp> // yuzu::win::from_wide (agents/shared, #1681)
#endif

namespace yuzu::content_dist::exec {

/// Everything `execute_verified_payload` reports back to its caller, in the
/// EXACT order/text `do_execute` used to emit directly -- a caller (the
/// plugin, or a test) replays `.lines` verbatim through
/// `yuzu::CommandContext::write_output` and returns `.rc`.
struct ExecutionOutcome {
    int rc = 1;
    std::vector<std::string> lines;
    /// Set only on the ordinary run_bounded_subprocess path -- never on an
    /// early shebang/args rejection, which never reaches the runner at all.
    /// The caller still owns forwarding this through the ABI4 CC-07
    /// result-status seam (yuzu::agent::forward_runner_failure), which needs
    /// a real yuzu::CommandContext this header deliberately never touches.
    std::optional<yuzu::agent::SubprocessResult> run;
};

/// `path` MUST already be hash-verified by the caller (content_dist's #808
/// KV re-verification) -- this function never re-checks that, exactly as
/// the code it replaces never did either. `is_linux`/`is_windows` MUST come
/// from an actual `#ifdef __linux__`/`#ifdef _WIN32` at the call site, never
/// a runtime guess (mirrors build_execution_options' own contract).
[[nodiscard]] inline ExecutionOutcome
execute_verified_payload(const std::filesystem::path& path, std::string_view args, bool is_linux,
                         bool is_windows) {
    ExecutionOutcome outcome;

    if (is_linux) {
        // CDX-002: reject a shebang-interpreted script before it ever
        // reaches the runner -- B6 exec_verify's fd-exec primitive closes
        // the verified fd before the kernel's binfmt_script handler gets a
        // chance to re-open the interpreter path, so a shebang script is
        // structurally incompatible with fd-exec. Best-effort operator UX,
        // NOT a security boundary (see content_dist_plugin.cpp's original
        // comment for the full rationale, preserved verbatim there).
        std::ifstream probe{path, std::ios::binary};
        char first_bytes[2] = {};
        probe.read(first_bytes, sizeof(first_bytes));
        if (probe.gcount() == sizeof(first_bytes) &&
            is_shebang_payload(std::string_view{first_bytes, sizeof(first_bytes)})) {
            outcome.lines.push_back(
                "error|script payloads (shebang) are not supported for verified "
                "execution on Linux: the runner's fd-exec primitive is incompatible "
                "with shebang interpreters (execveat O_CLOEXEC closes the fd before "
                "binfmt_script re-opens it); stage a native executable");
            outcome.rc = 1;
            return outcome;
        }
    }

    if (!args.empty() && !is_safe_arg(args)) {
        outcome.lines.push_back(
            "error|args contain forbidden characters (shell metacharacters blocked)");
        outcome.rc = 1;
        return outcome;
    }

#ifndef _WIN32
    // Make the staged file executable -- the ONLY thing that turns a staged
    // 0644 download into something the runner can exec at all. A chmod
    // failure is not fatal here -- it is reported via a warn| line and
    // execution proceeds; the exec itself then fails honestly with its own
    // EACCES, which the runner reports through
    // termination_reason==spawn_error/spawn_errno like any other exec
    // failure, rather than this step silently papering over a permissions
    // problem.
    {
        std::error_code chmod_ec;
        std::filesystem::permissions(path, std::filesystem::perms::owner_exec,
                                     std::filesystem::perm_options::add, chmod_ec);
        if (chmod_ec) {
            outcome.lines.push_back(std::format(
                "warn|failed to set execute permission on staged file: {}", chmod_ec.message()));
        }
    }
#endif

    std::vector<std::string> argv;
#ifdef _WIN32
    // path.string() would narrow the native wide path through the active
    // ANSI code page; run_bounded_subprocess's argv is UTF-8.
    argv.push_back(yuzu::win::from_wide(path.c_str()));
#else
    argv.push_back(path.string());
#endif
    for (auto& a : split_args(args))
        argv.push_back(std::move(a));

    auto opts = build_execution_options(is_linux, is_windows);
    // B6 exec_verify.expected_size: the staged file's hash-verified size --
    // sourced here (not in build_execution_options, which never touches the
    // filesystem). A stat failure just leaves expected_size unset; the
    // other exec_verify checks still run.
    std::error_code size_ec;
    auto staged_size = std::filesystem::file_size(path, size_ec);
    if (!size_ec)
        opts.exec_verify.expected_size = static_cast<std::uint64_t>(staged_size);

    auto run = yuzu::agent::run_bounded_subprocess(argv, opts);
    auto wire = map_execution_result(run);

    outcome.lines.push_back(std::format("status|{}", wire.status));
    outcome.lines.push_back(std::format("exit_code|{}", wire.exit_code));
    if (!wire.output.empty())
        outcome.lines.push_back(std::format("output|{}", wire.output));
    outcome.rc = wire.exit_code;
    outcome.run = std::move(run);
    return outcome;
}

} // namespace yuzu::content_dist::exec
