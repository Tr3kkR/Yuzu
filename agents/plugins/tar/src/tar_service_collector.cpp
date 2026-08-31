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

#include "tar_capture_status.hpp" // yuzu::tar::{classify_subprocess_capture,IncompleteCaptureError}
#include "tar_collectors.hpp"

#include <spdlog/spdlog.h>

#include <stdexcept>
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
#include "tar_service_parsers.hpp" // yuzu::tar::{parse_systemctl_list_units,parse_launchctl_list}

#include <chrono>

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

// RAII owner for a SC_HANDLE (round 3, B3-003): both the SCM handle and each
// per-service handle are held across allocations that can throw
// (std::vector<BYTE> buffer(bytes_needed)/config_buf(config_bytes), the
// from_wide string conversions, services.push_back) -- a throwing
// allocation between a successful Open*/CloseServiceHandle used to skip the
// close entirely, leaking the handle. Same shape as this repo's other Win32
// RAII guards (processes_plugin.cpp's HandleGuard, tar_arp_collector.cpp's
// MibTableGuard, tar_mapdrive_collector.cpp's WNetEnumGuard/NetApiBufGuard).
struct ScHandleGuard {
    SC_HANDLE h{nullptr};
    explicit ScHandleGuard(SC_HANDLE hh) noexcept : h(hh) {}
    ~ScHandleGuard() {
        if (h)
            CloseServiceHandle(h);
    }
    ScHandleGuard(const ScHandleGuard&) = delete;
    ScHandleGuard& operator=(const ScHandleGuard&) = delete;
};

} // namespace

std::vector<ServiceInfo> enumerate_services() {
    std::vector<ServiceInfo> services;

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) {
        // round 3 (same shape as the Linux/macOS subprocess legs below): a
        // failed SCM open is not "zero services", it is an acquisition
        // failure -- returning an empty vector here used to be diffed
        // against the last COMPLETE service baseline as though every
        // service had stopped/been removed. Throw so collect_or_retain
        // (tar_capture_status.hpp) skips this tick's diff/state-advance
        // instead, retaining the previous baseline.
        auto rc = GetLastError();
        spdlog::error("TAR: service snapshot incomplete (OpenSCManagerW failed, rc={}) -- "
                      "skipping diff, retaining previous baseline",
                      rc);
        throw yuzu::tar::IncompleteCaptureError(
            "TAR: OpenSCManagerW failed: rc=" + std::to_string(rc));
    }
    ScHandleGuard scm_guard{scm};

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
        // Same acquisition-failure shape as the OpenSCManagerW throw above:
        // a partial/failed enumeration must not be diffed as a genuinely
        // empty service list.
        auto rc = GetLastError();
        spdlog::error("TAR: service snapshot incomplete (EnumServicesStatusExW failed, rc={}) -- "
                      "skipping diff, retaining previous baseline",
                      rc);
        throw yuzu::tar::IncompleteCaptureError(
            "TAR: EnumServicesStatusExW failed: rc=" + std::to_string(rc));
    }

    auto* entries = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
    for (DWORD i = 0; i < service_count; ++i) {
        ServiceInfo si;
        si.name = from_wide(entries[i].lpServiceName);
        si.display_name = from_wide(entries[i].lpDisplayName);
        si.status = service_state_str(entries[i].ServiceStatusProcess.dwCurrentState);

        // Query startup type. A per-service query failure degrades only
        // this one row's startup_type field to "unknown" -- the service's
        // name/status are still real and the overall snapshot is still
        // complete, so this is NOT an incomplete-capture condition (unlike
        // the SCM-wide failures above).
        ScHandleGuard svc_guard{OpenServiceW(scm, entries[i].lpServiceName, SERVICE_QUERY_CONFIG)};
        if (svc_guard.h) {
            DWORD config_bytes = 0;
            BOOL ok = QueryServiceConfigW(svc_guard.h, nullptr, 0, &config_bytes);
            if (!ok && GetLastError() == ERROR_INSUFFICIENT_BUFFER && config_bytes > 0) {
                std::vector<BYTE> config_buf(config_bytes);
                auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config_buf.data());
                if (QueryServiceConfigW(svc_guard.h, config, config_bytes, &config_bytes)) {
                    si.startup_type = startup_type_str(config->dwStartType);
                } else {
                    si.startup_type = "unknown";
                }
            } else {
                si.startup_type = "unknown";
            }
        } else {
            si.startup_type = "unknown";
        }

        services.push_back(std::move(si));
    }

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
        throw yuzu::tar::IncompleteCaptureError("TAR: systemctl not found");
    }

    // Bounded, fork-lock-covered, shell-free argv exec (ADR-3002 rung 2): no
    // `/bin/sh -c` hop and no `timeout 10` prefix -- the runner's own
    // deadline subsumes that exactly, and stderr -> /dev/null is the
    // runner's default (merge_stderr=false, subprocess_runner.hpp:98),
    // matching the old `2>/dev/null` shell suffix. Parsing is pure
    // (tar_service_parsers.hpp), unit-testable independent of the runner.
    //
    // --plain (BR-001): without it, systemctl's list-units marks a
    // failed/not-found unit with a UTF-8 "*" glyph column
    // (glyph(GLYPH_BLACK_CIRCLE), U+25CF, bytes e2 97 8f) whenever it thinks
    // stdout supports UTF-8 -- verified live (Docker
    // jrei/systemd-ubuntu:22.04, amd64 emulation, a real `failed` unit):
    // under a UTF-8 locale the row reads `\xe2\x97\x8f yzfail.service ...`,
    // which the parser's ASCII `find_first_not_of(" *")` trim does not
    // recognise, so the glyph is read as the unit name and the real row
    // shifts/collides. This process currently only ever observed the
    // locale-C ASCII `*` form (LC_ALL=C in the runner's inherited
    // environment), so the defect has not fired in production -- but that
    // correctness depended entirely on an unstated locale default, not on
    // anything this argv asserts. --plain removes the marker column
    // outright (verified live, same container: `yzfail.service ...` with no
    // leading column at all under either locale), so parsing no longer
    // depends on the runner's environment.
    auto res = yuzu::agent::run_bounded_subprocess(
        {systemctl_path, "list-units", "--type=service", "--all", "--plain", "--no-pager",
         "--no-legend"},
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
        throw yuzu::tar::IncompleteCaptureError("TAR: systemctl capture incomplete: " + status.reason);
    }

    auto parsed = parse_systemctl_list_units(res.lines);
    if (parsed.malformed) {
        // BR-service-001: a malformed row is a missing binding relative to a
        // genuinely complete table (tar_service_parsers.hpp) -- same policy
        // as the ARP leg's BR4-005. Throw rather than diff/persist the
        // surviving subset as though it were the whole service table.
        spdlog::error("TAR: service snapshot incomplete (systemctl produced a malformed row) -- "
                      "skipping diff, retaining previous baseline");
        throw yuzu::tar::IncompleteCaptureError("TAR: systemctl produced a malformed row");
    }
    return std::move(parsed.entries);
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
        throw yuzu::tar::IncompleteCaptureError("TAR: launchctl not found");
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
        throw yuzu::tar::IncompleteCaptureError("TAR: launchctl capture incomplete: " + status.reason);
    }

    auto parsed = parse_launchctl_list(res.lines);
    if (parsed.malformed) {
        // BR-service-001: same policy as the systemctl leg above.
        spdlog::error("TAR: service snapshot incomplete (launchctl produced a malformed row) -- "
                      "skipping diff, retaining previous baseline");
        throw yuzu::tar::IncompleteCaptureError("TAR: launchctl produced a malformed row");
    }
    return std::move(parsed.entries);
}

#else
// Unsupported platform
std::vector<ServiceInfo> enumerate_services() {
    return {};
}
#endif

} // namespace yuzu::tar
