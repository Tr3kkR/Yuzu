/**
 * tar_service_collector.cpp -- System service enumeration for TAR plugin
 *
 * Enumerates installed services and returns them as structured ServiceInfo
 * records for diff-based change detection (state transitions).
 *
 * Platform support:
 *   Windows -- EnumServicesStatusExW (Service Control Manager)
 *   Linux   -- systemctl list-units --type=service
 *   macOS   -- launchctl list
 */

#include "tar_collectors.hpp"

#include <spdlog/spdlog.h>

#include <string>
#include <utility> // std::move
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <win_str.hpp>  // shared yuzu::win wide<->UTF-8 helpers (#1681)
#else
#include "tar_capture_status.hpp" // yuzu::tar::classify_subprocess_capture
#include "tar_service_parsers.hpp" // yuzu::tar::{parse_systemctl_list_units,parse_launchctl_list}

#include <chrono>
#include <stdexcept>

#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::run_bounded_subprocess / probe_tool_path (ADR-3002 rung 2)
#endif

namespace yuzu::tar {

// -- Windows implementation ---------------------------------------------------
#ifdef _WIN32

namespace {

// wide->UTF-8 conversion now via the shared win_str.hpp (#1681); from_wide is
// behaviour-identical to the old NUL-terminated wide_to_utf8 for valid input.
using yuzu::win::from_wide;

const char* service_state_str(DWORD state) {
    switch (state) {
    case SERVICE_STOPPED:          return "stopped";
    case SERVICE_START_PENDING:    return "start_pending";
    case SERVICE_STOP_PENDING:     return "stop_pending";
    case SERVICE_RUNNING:          return "running";
    case SERVICE_CONTINUE_PENDING: return "continue_pending";
    case SERVICE_PAUSE_PENDING:    return "pause_pending";
    case SERVICE_PAUSED:           return "paused";
    default:                       return "unknown";
    }
}

const char* startup_type_str(DWORD start_type) {
    switch (start_type) {
    case SERVICE_AUTO_START:   return "automatic";
    case SERVICE_BOOT_START:   return "boot";
    case SERVICE_DEMAND_START: return "manual";
    case SERVICE_DISABLED:     return "disabled";
    case SERVICE_SYSTEM_START: return "system";
    default:                   return "unknown";
    }
}

} // namespace

std::vector<ServiceInfo> enumerate_services() {
    std::vector<ServiceInfo> services;

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm)
        return services;

    DWORD bytes_needed = 0;
    DWORD service_count = 0;
    DWORD resume_handle = 0;

    // First call to get required buffer size
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                          SERVICE_STATE_ALL, nullptr, 0,
                          &bytes_needed, &service_count, &resume_handle, nullptr);

    std::vector<BYTE> buffer(bytes_needed);
    resume_handle = 0;

    if (!EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                               SERVICE_STATE_ALL, buffer.data(),
                               static_cast<DWORD>(buffer.size()), &bytes_needed,
                               &service_count, &resume_handle, nullptr)) {
        CloseServiceHandle(scm);
        return services;
    }

    auto* entries = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
    for (DWORD i = 0; i < service_count; ++i) {
        ServiceInfo si;
        si.name = from_wide(entries[i].lpServiceName);
        si.display_name = from_wide(entries[i].lpDisplayName);
        si.status = service_state_str(entries[i].ServiceStatusProcess.dwCurrentState);

        // Query startup type
        SC_HANDLE svc = OpenServiceW(scm, entries[i].lpServiceName, SERVICE_QUERY_CONFIG);
        if (svc) {
            DWORD config_bytes = 0;
            BOOL ok = QueryServiceConfigW(svc, nullptr, 0, &config_bytes);
            if (!ok && GetLastError() == ERROR_INSUFFICIENT_BUFFER && config_bytes > 0) {
                std::vector<BYTE> config_buf(config_bytes);
                auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config_buf.data());
                if (QueryServiceConfigW(svc, config, config_bytes, &config_bytes)) {
                    si.startup_type = startup_type_str(config->dwStartType);
                } else {
                    si.startup_type = "unknown";
                }
            } else {
                si.startup_type = "unknown";
            }
            CloseServiceHandle(svc);
        } else {
            si.startup_type = "unknown";
        }

        services.push_back(std::move(si));
    }

    CloseServiceHandle(scm);
    return services;
}

// -- Linux implementation -----------------------------------------------------
#elif defined(__linux__)

std::vector<ServiceInfo> enumerate_services() {
    // Probed over the two absolute paths systemctl actually lives at across
    // distros (mirrors the services plugin's own probe --
    // services_plugin.cpp's enumerate_services_linux precedent). Degrades
    // to empty with the existing spdlog::error when neither is present --
    // preserves today's degrade contract (previously a null pipe-open).
    auto systemctl_path = yuzu::agent::probe_tool_path({"/usr/bin/systemctl", "/bin/systemctl"});
    if (systemctl_path.empty()) {
        spdlog::error("TAR: service snapshot incomplete (systemctl not found) -- skipping diff, "
                      "retaining previous baseline");
        throw std::runtime_error("TAR: systemctl not found");
    }

    // Bounded, fork-lock-covered, shell-free argv exec (ADR-3002 rung 2): no
    // `/bin/sh -c` hop and no `timeout 10` prefix -- the runner's own
    // deadline subsumes that exactly, and stderr -> /dev/null is the
    // runner's default (merge_stderr=false, subprocess_runner.hpp:98),
    // matching the old `2>/dev/null` shell suffix. Parsing is pure
    // (tar_service_parsers.hpp), unit-testable independent of the runner.
    auto res = yuzu::agent::run_bounded_subprocess(
        {systemctl_path, "list-units", "--type=service", "--all", "--no-pager", "--no-legend"},
        yuzu::agent::SubprocessOptions{.deadline = std::chrono::seconds{10}});
    // zero_exit_required=true verified live (Docker jrei/systemd-ubuntu:22.04,
    // amd64 emulation): `systemctl list-units --type=service --all --no-legend
    // --no-pager` exits 0 both on a healthy system AND with a failed unit
    // present (`systemctl is-system-running` reporting "degraded") -- listing
    // is a query, not a health check, so a real stopped/failed service is
    // reported via its row's own status column, never via a non-zero exit.
    auto status = yuzu::tar::classify_subprocess_capture(res.tool_ran, res.timed_out,
                                                          res.output_truncated, res.exit_code);
    if (!status.complete) {
        spdlog::error("TAR: service snapshot incomplete (systemctl {}) -- skipping diff, "
                      "retaining previous baseline",
                      status.reason);
        throw std::runtime_error("TAR: systemctl capture incomplete: " + status.reason);
    }

    return parse_systemctl_list_units(res.lines);
}

// -- macOS implementation -----------------------------------------------------
#elif defined(__APPLE__)

std::vector<ServiceInfo> enumerate_services() {
    // launchctl lives at exactly one absolute path on macOS (no /usr/bin
    // alternative, unlike systemctl's cross-distro split) -- probe_tool_path
    // still verifies it exists+is executable before trusting it into
    // argv[0], same as every other runner-migrated call site, and degrades
    // to empty with the existing spdlog::error when absent (previously a
    // null pipe-open).
    auto launchctl_path = yuzu::agent::probe_tool_path({"/bin/launchctl"});
    if (launchctl_path.empty()) {
        spdlog::error("TAR: service snapshot incomplete (launchctl not found) -- skipping diff, "
                      "retaining previous baseline");
        throw std::runtime_error("TAR: launchctl not found");
    }

    // Bounded, fork-lock-covered, shell-free argv exec (ADR-3002 rung 2):
    // stderr -> /dev/null is the runner's default (merge_stderr=false,
    // subprocess_runner.hpp:98), matching the old `2>/dev/null` shell
    // suffix. Parsing (including the header-row skip) is pure
    // (tar_service_parsers.hpp), unit-testable independent of the runner.
    auto res = yuzu::agent::run_bounded_subprocess(
        {launchctl_path, "list"}, yuzu::agent::SubprocessOptions{.deadline = std::chrono::seconds{10}});
    // zero_exit_required=true verified live on this host: `launchctl list`
    // exits 0 (511 jobs listed, including third-party agents/daemons).
    auto status = yuzu::tar::classify_subprocess_capture(res.tool_ran, res.timed_out,
                                                          res.output_truncated, res.exit_code);
    if (!status.complete) {
        spdlog::error("TAR: service snapshot incomplete (launchctl {}) -- skipping diff, "
                      "retaining previous baseline",
                      status.reason);
        throw std::runtime_error("TAR: launchctl capture incomplete: " + status.reason);
    }

    return parse_launchctl_list(res.lines);
}

#else
// Unsupported platform
std::vector<ServiceInfo> enumerate_services() {
    return {};
}
#endif

} // namespace yuzu::tar
