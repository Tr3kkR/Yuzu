// test_service_binpath.cpp -- unit coverage for make_service_binpath (#1822,
// agents/core/src/service_win.hpp), the pure binPath builder used by
// --install-service / the SCM install path.
//
// Windows-only: the helper and the cases that exercise it are #ifdef _WIN32.
// On other platforms this compiles to an empty translation unit, so the file is
// listed unconditionally in tests/meson.build (matching test_win_str_utils.cpp's
// platform-gated-body convention) rather than guarded with a meson host_machine
// conditional.
//
// Pure-function tests -- no advapi32, no SCM, no live service. The dispatcher /
// control-handler state machine in service_win.cpp is exercised by the live
// Windows-rig checklist, not here (SCM-bound code isn't unit-testable in
// isolation -- see guard_service.cpp's rc=87 history for why that gap is
// deliberate, not an oversight).

#ifdef _WIN32

#include <service_win.hpp>

#include <catch2/catch_test_macros.hpp>

using yuzu::agent::win::make_service_binpath;

TEST_CASE("make_service_binpath quotes a spaceless path and appends --service",
          "[win-service]") {
    REQUIRE(make_service_binpath(L"C:\\Yuzu\\yuzu-agent.exe") ==
            L"\"C:\\Yuzu\\yuzu-agent.exe\" --service");
}

TEST_CASE("make_service_binpath quotes a path containing spaces (Program Files)",
          "[win-service]") {
    // A bare unquoted path with spaces is misparsed by the SCM as <dir> <args> --
    // the classic unquoted-service-path hazard. Only the exe path gets quoted;
    // --service stays outside the quotes as a separate argument.
    REQUIRE(make_service_binpath(L"C:\\Program Files\\Yuzu\\yuzu-agent.exe") ==
            L"\"C:\\Program Files\\Yuzu\\yuzu-agent.exe\" --service");
}

TEST_CASE("make_service_binpath suffix is exactly space-dash-dash-service", "[win-service]") {
    const std::wstring result = make_service_binpath(L"agent.exe");
    REQUIRE(result.ends_with(L"\" --service"));
    REQUIRE(result.starts_with(L"\"agent.exe"));
}

#endif // _WIN32
