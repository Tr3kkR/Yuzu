// service_win.hpp -- Windows Service Control Manager entry point for yuzu-agent.
//
// #1822: yuzu-agent.exe registered itself with the SCM (CreateServiceW, in main.cpp)
// but never implemented the SCM control protocol -- no StartServiceCtrlDispatcher /
// ServiceMain / RegisterServiceCtrlHandler / SetServiceStatus anywhere in the tree --
// so the SCM killed the process for not responding within its start timeout
// (`sc start YuzuAgent` -> error 1053). This header/cpp pair is that missing half.
//
// Windows-only by construction (#ifdef _WIN32); the header is empty elsewhere.

#pragma once

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace yuzu::agent {
class Agent; // full definition only needed in service_win.cpp
}

namespace yuzu::agent::win {

// Single source of truth for the SCM service name -- shared by the
// --install-service/--remove-service handlers in main.cpp and the ServiceMain
// dispatcher below (service_win.cpp).
constexpr wchar_t kServiceName[] = L"YuzuAgent";

// Builds the CreateServiceW / `sc config` binPath: the exe path wrapped in quotes
// (a bare unquoted path containing spaces, e.g. under "Program Files", is otherwise
// misparsed by the SCM as `<dir> <args>` -- a known unquoted-service-path hazard)
// plus the --service marker that tells this same binary to run under the SCM
// instead of as a console process. Pure and unit-testable without advapi32
// (tests/unit/test_service_binpath.cpp).
inline std::wstring make_service_binpath(std::wstring_view exe_path) {
    std::wstring result;
    result.reserve(exe_path.size() + 16);
    result += L'"';
    result += exe_path;
    result += L"\" --service";
    return result;
}

// Runs the process under the Windows Service Control Manager. Blocks for the
// lifetime of the service: StartServiceCtrlDispatcherW does not return until the
// SCM has told the service to stop and ServiceMain has returned. `factory` is
// invoked on the ServiceMain thread, after SERVICE_START_PENDING is reported, to
// construct the Agent; a null return is treated as a startup failure and reported
// to the SCM as ERROR_SERVICE_SPECIFIC_ERROR.
//
// Returns EXIT_FAILURE immediately, without blocking, if the process was not
// actually launched by the SCM (StartServiceCtrlDispatcherW fails with
// ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) -- i.e. --service was passed from an
// interactive console by mistake.
int run_service(std::move_only_function<std::unique_ptr<yuzu::agent::Agent>()> factory);

} // namespace yuzu::agent::win

#endif // _WIN32
