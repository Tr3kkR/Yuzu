// Custom Catch2 entry point for yuzu_agent_tests AND yuzu_server_tests —
// deliberately NOT Catch2WithMain (see tests/meson.build: both exes link
// catch2_nomain_dep).
//
// #1648: the Windows debug test binaries have, on rare CI runs, printed a
// clean Catch2 summary (e.g. "1 failed") and then had the OS report an
// unrelated process exit code (42), which defeats scripts/ci/flake-retry.py's
// classification (catch2_failed_cases() treats an abnormal exit as
// unclassifiable and hard-blocks the job instead of retrying a known flake).
// Printing Session::run()'s return value here, immediately before main()
// returns, bisects the bug on its next occurrence:
//   - this line prints (e.g. "returned 1") but the OS still reports 42 ->
//     the corruption happens strictly AFTER main() returns (global/static
//     destructors, DLL unload) — Catch2 and the test bodies are exonerated.
//   - this line never prints on a 42-exit run -> main() never reached the
//     fprintf, so the corruption happened DURING session.run() itself (e.g.
//     a RegistryGuard watch thread crashing mid-suite), which also explains
//     why catch2_failed_cases()'s junit re-run comes back empty/unparseable.
//
// #3507 AC1: printing the diagnostic was never enough to stop the strand -
// once a teardown-thread crash happens AFTER a green (or honestly red)
// summary, nothing in this file's control can stop the OS from reporting a
// corrupted exit code, because the corruption happens in code this file does
// not own (global/static destructors, DLL unload, a still-running detached
// worker). The fix is to never reach that code on Windows: leave immediately
// after Session::run() returns, via the same hard_exit() primitive
// main.cpp/service_win.cpp already use for the identical class of hazard
// (agents/core/src/hard_exit.hpp, ADR-0021 rung 7.6 / the F3 orphan-exit
// obligation). This is REUSE of that primitive, not a new copy — both test
// binaries already carry agents/core/src on their include path (see the
// CONSTRAINT comment on yuzu_server_tests's target in tests/meson.build), so
// server/core/src/main.cpp's "hoist to common/ on a third call site" rule is
// not triggered by this include.
//
// hard_exit.hpp documents that its `code` "should be nonzero for every
// F3/orphan-triggered call ... must never look like EXIT_SUCCESS" — that
// sentence is scoped to the F3/orphan-drain use it was written for. THIS
// call site is a different, deliberately reviewed use: a passing test run
// (result == 0) is exactly the case #3507 exists to protect, since the
// crash this bug describes happens strictly after a GREEN summary. Calling
// hard_exit(0) here on Windows is intentional, not an oversight — do not
// "fix" it to skip hard_exit on a zero result.
//
// Windows-only (#ifdef _WIN32, not a runtime check): nightly's coverage
// (-Db_coverage) and Linux ASan/UBSan/TSan legs need a normal process exit
// for their atexit dumps (gcov's .gcda write, LSan's leak report) —
// hard_exit() skips atexit entirely by design. The exit-42 hazard is a
// Windows-debug-CI phenomenon (#1648); lifting this guard to other
// platforms would silently break those legs' own instrumentation.
//
// ALSO excluded from hard_exit on Windows (governance Gate 2/3, 2026-08-28):
// nightly.yml's windows-asan leg, which DOES build and run this exact binary
// (tests/yuzu_agent_tests, -Db_sanitize=address) — an unconditional #ifdef
// _WIN32 guard would fire there too, TerminateProcess-ing before any
// static/global destructor runs and removing ASan's one window to catch a
// UAF-class race between a still-running detached worker (the exact F3
// scenario this hard_exit call exists to guard test-harness exit against)
// and normal teardown — precisely the "whole UAF class this batch targets"
// windows-asan's own job comment describes. Verified this exclusion is safe
// to make, not merely convenient: windows-asan runs `meson test` directly,
// never through flake-retry.py, so the #1648 exit-42 misclassification this
// hard_exit call exists to prevent cannot occur on that leg — excluding it
// costs this file's own stated purpose nothing. __SANITIZE_ADDRESS__ is a
// real, portable MSVC/GCC/Clang macro (confirmed already in production use
// in this exact codebase for the identical cross-toolchain sanitizer-detect
// need: tests/unit/test_helpers.hpp's kSpinScale,
// agents/core/include/yuzu/agent/guardian_engine.hpp's
// YUZU_WORKER_MUTEX_GUARD) — not a new, untested pattern.
//
// Session's own destructor (and any Catch2/system atexit handler) never
// runs on this path. Verified empirically (2026-08-27, scratch experiment
// against the vendored Catch2 3.13.0) that this is safe for what
// flake-retry.py needs: a `--reporter junit --out` file is fully written
// and well-formed, WITH the correct process exit code preserved, when the
// process calls _exit()/TerminateProcess() immediately after
// Session::run() returns — junit finalization and the PG cleanup listener's
// testRunEnded both fire INSIDE run(), not in Session's destructor.
#include "hard_exit.hpp"

#include <catch2/catch_session.hpp>

#include <cstdio>

int main(int argc, char* argv[]) {
    Catch::Session session;

    int rc = session.applyCommandLine(argc, argv);
    if (rc != 0) {
        return rc;
    }

    int result = session.run();
    std::fprintf(stderr, "[DIAG] Catch2 Session::run() returned %d (main about to return)\n",
                 result);
    std::fflush(stderr);
    std::fflush(stdout);
#if defined(_WIN32) && !defined(__SANITIZE_ADDRESS__)
    yuzu::agent::hard_exit(result); // see the #3507 AC1 comment above
#endif
    return result;
}
