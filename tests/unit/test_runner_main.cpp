// Custom Catch2 entry point for yuzu_agent_tests — deliberately NOT
// Catch2WithMain (see tests/meson.build: agent_test_exe links catch2_nomain_dep).
//
// #1648: the Windows debug agent-test binary has, on rare CI runs, printed a
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
    return result;
}
