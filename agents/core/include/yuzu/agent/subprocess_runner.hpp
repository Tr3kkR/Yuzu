#pragma once

/**
 * subprocess_runner.hpp -- agent-core bounded, fork-safe POSIX subprocess
 * runner (#2273 foundation).
 *
 * Runs a fixed argv (resolved via PATH, exec'd directly with no shell in
 * between, so no shell-quoting/injection surface) as a child in its own
 * process group, with a hard wall-clock deadline: if the child hasn't
 * exited by then, its whole process group is SIGKILLed and reaped.
 * Callers that need to end a run early (agent shutdown, an operator
 * cancel) can cooperatively request that via request_subprocess_cancel()
 * -- an in-flight run notices on its next poll and finishes the same way
 * a deadline would.
 *
 * This lives in agent-core rather than as a plugin-local header because the
 * implementation spawns a DETACHED background reaper thread when a killed
 * child can't be confirmed-reaped within a short bound (see
 * subprocess_runner.cpp). That thread's code must never live in memory that
 * can be unmapped out from under it -- which rules out a plugin .dylib/.so,
 * since agent.cpp's reconnect/shutdown paths dlclose() plugins. yuzu_agent_core_lib
 * is linked directly into the yuzu-agent executable and is never dlclose'd,
 * so a helper defined here is a genuine pinned image. Declared here, DEFINED
 * OUT-OF-LINE in subprocess_runner.cpp -- same split as LocalDispatcher
 * (local_dispatcher.hpp / .cpp) -- so the fork/exec/reap machinery compiles
 * only into that pinned image, never into an including plugin.
 *
 * POSIX only. The struct/function declarations below are visible on every
 * platform so callers compile uniformly; on Windows run_bounded_subprocess
 * is a trivial stub (see subprocess_runner.cpp) since no Windows plugin
 * calls it today.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <chrono>
#include <cstddef>
#include <string>
#include <vector>

namespace yuzu::agent {

struct SubprocessOptions {
    std::chrono::milliseconds deadline{std::chrono::milliseconds(10000)};
    std::size_t max_lines = 0; // 0 = unlimited; caps STORED lines (not raw
                                // output) so a huge invocation (e.g. `log
                                // show`) can't grow unbounded memory.
    bool merge_stderr = false; // false: child stderr -> /dev/null (matches
                                // `2>/dev/null` log-inspection CLIs). true:
                                // stderr merged into the same captured
                                // stream as stdout (codesign/plutil write
                                // their diagnostics to stderr).
    // When true AND max_lines > 0: stop reading as soon as max_lines lines
    // have been stored, kill+reap the child's process group, and report a
    // NORMAL success (timed_out=false, output_truncated=false) rather than
    // running the child to opts.deadline. For a caller that only ever wants
    // the first N lines (e.g. `log show`), this turns "N lines available in
    // a huge stream" into a clean bounded success instead of a partial
    // result that looks like a timeout/truncation. False (default) keeps
    // the previous behaviour: max_lines only caps what's stored, the runner
    // keeps draining/discarding until the child exits or the deadline hits.
    bool stop_after_max_lines = false;
};

struct SubprocessResult {
    // false IFF exec itself failed (binary missing from PATH, not
    // executable, etc). Determined by a close-on-exec exec-error pipe, NOT
    // an exit-code heuristic -- a program that legitimately returns 127
    // (e.g. `sh -c 'exit 127'`) is still tool_ran=true, exit_code==127.
    // Callers treat !tool_ran as an honest "unknown", never a fabricated
    // verdict.
    bool tool_ran = false;

    // WEXITSTATUS(status) when the child was reaped via a normal exit
    // (covers both a real exit and the internal _exit(127) taken after an
    // exec failure -- tool_ran is what tells those two apart). Left at the
    // -1 sentinel when the child was signal-killed (deadline/cancel) --
    // never a fabricated exit status for a death by signal.
    int exit_code = -1;

    // True if the wall-clock deadline elapsed OR a cancel was requested
    // before the child exited on its own. A killed child can still have
    // tool_ran=true (it ran and produced output before being killed, e.g. a
    // codesign call that emitted diagnostics) -- callers MUST check
    // timed_out before trusting exit_code/output for a pass/fail verdict.
    bool timed_out = false;

    // Captured stdout (+stderr if merge_stderr), split on '\n', blank lines
    // dropped, a trailing '\r' stripped from each line. Capped at
    // opts.max_lines when nonzero.
    std::vector<std::string> lines;

    // The same captured stream as a single blob (suitable for a
    // substring/trim style check, e.g. reading a signature-verification
    // tool's diagnostic text) -- independent of the max_lines cap on
    // `lines`, bounded only by an internal sanity cap.
    std::string output;

    // True once capture hit the internal sanity cap (currently ~1MB,
    // independent of max_lines/deadline) before the child finished. A
    // defensive memory bound against a runaway or adversarial child, not a
    // feature callers configure. When true, `output` and possibly the tail
    // of `lines` reflect only what was captured before the cap -- capture
    // stopped early, nothing here is fabricated past that point.
    bool output_truncated = false;
};

/**
 * Run `argv` (argv[0] resolved via PATH, exec'd directly -- no shell) as a
 * child in its own process group, collecting output until the child exits
 * or opts.deadline elapses / a cancel is requested, whichever first. Never
 * blocks past that bound (plus a short, bounded grace period to observe the
 * pipe close and the child reap after a kill) and never fabricates a
 * result -- an incomplete run is reported honestly via timed_out/tool_ran.
 *
 * Declared here; DEFINED OUT-OF-LINE in subprocess_runner.cpp so the
 * fork/exec/reap body compiles only into the pinned agent-core image (see
 * the header comment above).
 */
YUZU_EXPORT SubprocessResult run_bounded_subprocess(const std::vector<std::string>& argv,
                                                     const SubprocessOptions& opts);

/**
 * Process-global cooperative cancel for in-flight subprocess collection.
 * run_bounded_subprocess polls subprocess_cancel_requested() each iteration
 * of its wait loop; once true it kills and reaps the child (same bounded
 * path as a deadline) and returns promptly with timed_out=true.
 *
 * Backed by a file-local std::atomic<bool> in subprocess_runner.cpp -- a
 * single flag shared by every in-flight run in the process, not a
 * per-call/per-connection token.
 */
YUZU_EXPORT void request_subprocess_cancel(bool cancel);
YUZU_EXPORT bool subprocess_cancel_requested();

} // namespace yuzu::agent
