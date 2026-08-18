/**
 * services_plugin.cpp — System services listing plugin for Yuzu
 *
 * Actions:
 *   "list"           — List installed services with name, display name, status, startup type.
 *   "running"        — List only running services.
 *   "set_start_mode" — Change a service's startup type (automatic, manual, disabled).
 *
 * Output is pipe-delimited via write_output():
 *   Windows: svc|name|display_name|status|startup_type
 *   Linux:   svc|name|status|description
 *   macOS:   svc|label|pid|status|startup_type
 *   set_start_mode success: status|ok\nservice|<name>\nmode|<mode>
 *   set_start_mode failure: error|<message>
 *
 * macOS startup_type (C-1.12): derived from ONE bulk `launchctl print-disabled
 * system` call joined against the enumerated labels (services_macos_launchd.hpp)
 * -- never an N+1 `launchctl print` per service. One of exactly three honest
 * values: automatic (explicitly enabled), disabled, or unknown (no override
 * recorded) -- deliberately NOT Windows' 5-state taxonomy.
 */

#include <yuzu/plugin.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <format>
#include <memory>
#include <string>
#include <string_view>
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
#pragma comment(lib, "advapi32.lib")
#else
#include <sys/wait.h>
#endif

#if defined(__linux__) || defined(__APPLE__)
#include <chrono>
#include <spdlog/spdlog.h>
#include <sudo_argv.hpp> // yuzu::shared::sudo_wrap (Decision-8 canonical privileged argv, ADR-3002)
#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::run_bounded_subprocess / probe_tool_path (K-7/CDX-07, ADR-3002 rung 2)
#endif

#ifdef __APPLE__
#include "services_macos_launchd.hpp" // pure launchctl print-disabled parser (C-1.12)
#endif

#include "services_parsers.hpp" // yuzu::services::{parse_systemctl_list_units,parse_launchctl_list,is_safe_service_name} (Wave-2 PR2.2a, ADR-3002)

namespace {

// is_safe_service_name now lives in services_parsers.hpp (yuzu::services) so
// the launchctl-list parser can share the same allowlist without depending
// on this .cpp's anonymous namespace -- pull it in unqualified so every
// existing call site here (do_set_start_mode's param check) keeps working.
using yuzu::services::is_safe_service_name;

#if defined(__linux__) || defined(__APPLE__)
// Outcome of run_tool(): the captured output PLUS the raw runner result, so
// a caller can inspect res.tool_ran/timed_out/exit_code itself (e.g.
// run_command_exit below, which reduces it to a bare exit code).
struct ToolOutcome {
    std::string output;
    yuzu::agent::SubprocessResult res;
};

// Direct-argv, shell-free replacement for the old `/bin/sh -c` hop (ADR-3002
// rung 2/review blocker: the original raw popen() here bypassed both the
// deadline and the fork lock; the shell hop that first replaced it is itself
// an unnecessary hop once every call site builds a clean argv). argv[0] is
// exec'd directly via the bounded, fork-lock-covered runner -- no shell in
// between, so no shell-quoting/injection surface. An empty/probe-miss argv
// (argv[0] empty) is reported the same way run_bounded_subprocess's own
// runtime-reject would (tool_ran=false, spawn_error) without attempting an
// OS call. The runner's own ~1 MiB sanity cap bounds a runaway/adversarial
// `systemctl`/`launchctl` output; stderr -> /dev/null is the runner's
// default (merge_stderr=false), matching the old `2>/dev/null` shell suffix.
ToolOutcome run_tool(std::vector<std::string> argv) {
    if (argv.empty() || argv.front().empty()) {
        return ToolOutcome{std::string{}, yuzu::agent::SubprocessResult{}};
    }
    auto res = yuzu::agent::run_bounded_subprocess(
        argv, yuzu::agent::SubprocessOptions{.deadline = std::chrono::seconds{20}});
    // A cut-short enumeration returns empty/partial output that parses as "0
    // services" — a silent false-negative. Warn so an operator can tell a
    // degraded enumeration from a genuinely empty one (sre-M1).
    if (res.timed_out || !res.tool_ran || res.output_truncated) {
        spdlog::warn("services: degraded run (timed_out={}, tool_ran={}, truncated={}): {}",
                     res.timed_out, res.tool_ran, res.output_truncated, argv.front());
    }
    std::string output = res.output;
    return ToolOutcome{std::move(output), std::move(res)};
}
#endif

#ifdef _WIN32

// Wide<->UTF-8 conversion now comes from the shared win_str.hpp (#1681): the old local
// wide_to_utf8 (NUL-terminated) / utf8_to_wide (explicit length) map onto from_wide /
// to_wide -- behaviour-identical for valid input.
using yuzu::win::from_wide;
using yuzu::win::to_wide;

const char* service_state_str(DWORD state) {
    switch (state) {
    case SERVICE_STOPPED:
        return "stopped";
    case SERVICE_START_PENDING:
        return "start_pending";
    case SERVICE_STOP_PENDING:
        return "stop_pending";
    case SERVICE_RUNNING:
        return "running";
    case SERVICE_CONTINUE_PENDING:
        return "continue_pending";
    case SERVICE_PAUSE_PENDING:
        return "pause_pending";
    case SERVICE_PAUSED:
        return "paused";
    default:
        return "unknown";
    }
}

const char* startup_type_str(DWORD start_type) {
    switch (start_type) {
    case SERVICE_AUTO_START:
        return "automatic";
    case SERVICE_BOOT_START:
        return "boot";
    case SERVICE_DEMAND_START:
        return "manual";
    case SERVICE_DISABLED:
        return "disabled";
    case SERVICE_SYSTEM_START:
        return "system";
    default:
        return "unknown";
    }
}

struct ServiceInfo {
    std::string name;
    std::string display_name;
    std::string status;
    std::string startup_type;
};

std::vector<ServiceInfo> enumerate_services_win(bool running_only) {
    std::vector<ServiceInfo> services;

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm)
        return services;

    DWORD bytes_needed = 0;
    DWORD service_count = 0;
    DWORD resume_handle = 0;

    // First call to get required buffer size
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                          running_only ? SERVICE_ACTIVE : SERVICE_STATE_ALL, nullptr, 0,
                          &bytes_needed, &service_count, &resume_handle, nullptr);

    std::vector<BYTE> buffer(bytes_needed);
    resume_handle = 0;

    if (!EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                               running_only ? SERVICE_ACTIVE : SERVICE_STATE_ALL, buffer.data(),
                               static_cast<DWORD>(buffer.size()), &bytes_needed, &service_count,
                               &resume_handle, nullptr)) {
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
            QueryServiceConfigW(svc, nullptr, 0, &config_bytes);
            std::vector<BYTE> config_buf(config_bytes);
            auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config_buf.data());
            if (QueryServiceConfigW(svc, config, config_bytes, &config_bytes)) {
                si.startup_type = startup_type_str(config->dwStartType);
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

#elif defined(__linux__)

using ServiceInfo = yuzu::services::SystemdUnitEntry;

std::vector<ServiceInfo> enumerate_services_linux(bool running_only) {
    // services/enumerate_services_linux#1 (docs/agent-spawn-sink-manifest.md)
    // Resolve the tool across the two absolute paths systemctl actually
    // lives at across distros (mirrors the installed sudoers grant, which
    // covers both /usr/bin/systemctl and /bin/systemctl -- see
    // scripts/install-agent-user.sh -- and the users_plugin.cpp precedent
    // for probe_tool_path's candidate-list shape).
    auto systemctl_path = yuzu::agent::probe_tool_path({"/usr/bin/systemctl", "/bin/systemctl"});

    std::vector<std::string> argv;
    if (!systemctl_path.empty()) {
        argv = {systemctl_path, "list-units", "--type=service",
                running_only ? "--state=running" : "--all", "--no-pager", "--no-legend"};
    }

    // Bounded, fork-lock-covered, shell-free argv exec (ADR-3002 rung 2): no
    // `/bin/sh -c` hop, no shell-string interpolation -- systemctl is exec'd
    // directly with each flag its own argv element. Parsing is pure
    // (services_parsers.hpp), unit-testable independent of the runner.
    return yuzu::services::parse_systemctl_list_units(run_tool(std::move(argv)).output);
}

#elif defined(__APPLE__)

struct ServiceInfo {
    std::string label;
    std::string pid;
    std::string status;
    std::string startup_type; // honest automatic|disabled|unknown (C-1.12); never Windows' 5-state taxonomy
};

// total_seen (out) receives the number of services that passed all filters
// (label allowlist + running_only) BEFORE the yuzu::services::kMaxServiceRows
// cap, so the caller can emit an honest truncation sentinel when rows were
// dropped.
std::vector<ServiceInfo> enumerate_services_macos(bool running_only, std::size_t& total_seen) {
    total_seen = 0;
    std::vector<ServiceInfo> services;

    // services/enumerate_services_macos#1 (docs/agent-spawn-sink-manifest.md)
    // launchctl lives at exactly one absolute path on macOS (no /usr/bin
    // alternative, unlike systemctl's cross-distro split) -- probe_tool_path
    // still verifies it exists+is executable before trusting it into argv[0],
    // same as every other Wave-2-migrated call site.
    auto launchctl_path = yuzu::agent::probe_tool_path({"/bin/launchctl"});

    // Bounded + fork-lock-covered, shell-free argv exec (ADR-3002 rung 2):
    // the whole `launchctl list` output is captured through the shared
    // runner, then parsed by the pure parser in services_parsers.hpp.
    std::vector<std::string> list_argv;
    if (!launchctl_path.empty()) {
        list_argv = {launchctl_path, "list"};
    }
    const std::string listing = run_tool(std::move(list_argv)).output;

    auto parsed = yuzu::services::parse_launchctl_list(listing, running_only);
    total_seen = parsed.total_seen;
    services.reserve(parsed.services.size());
    for (auto& entry : parsed.services) {
        services.push_back(ServiceInfo{std::move(entry.label), std::move(entry.pid),
                                       std::move(entry.status), /*startup_type=*/{}});
    }

    // services/enumerate_services_macos#2 (docs/agent-spawn-sink-manifest.md)
    // P15 (verified): ONE bulk `launchctl print-disabled system` call for the
    // enabled/disabled map of ALL services, joined below -- NOT an N+1
    // `launchctl print system/<label>` per service (hundreds of services would
    // mean hundreds of subprocess spawns). services_macos_launchd.hpp
    // re-validates every label (is_safe_launchd_label, same allowlist as
    // is_safe_service_name above) before trusting it as a join key, so an
    // unparseable/hostile label just yields "unknown".
    std::vector<std::string> disabled_argv;
    if (!launchctl_path.empty()) {
        disabled_argv = {launchctl_path, "print-disabled", "system"};
    }
    auto disabled_map = yuzu::services_macos::parse_print_disabled(
        run_tool(std::move(disabled_argv)).output);
    for (auto& si : services) {
        si.startup_type = yuzu::services_macos::startup_type_for(disabled_map, si.label);
    }

    return services;
}

#endif

// ── Shared helpers ──────────────────────────────────────────────────────────

/// Run argv via the bounded, fork-lock-covered runner and return its exit
/// code -- shell-free (ADR-3002 rung 2): argv[0] is exec'd directly, no
/// `/bin/sh -c` hop. stdout is drained-and-discarded by the runner (the
/// callers here only need the exit code). An empty/probe-miss argv is
/// rejected the same way run_bounded_subprocess's own runtime-reject would
/// (returns -1) without attempting an OS call. `!tool_ran` (spawn/exec
/// failure) maps to the old `popen()==nullptr`/non-WIFEXITED path: a -1
/// "unknown", never a fabricated success.
#if defined(__linux__) || defined(__APPLE__)
int run_command_exit(const std::vector<std::string>& argv) {
    if (argv.empty() || argv.front().empty())
        return -1;
    auto res = yuzu::agent::run_bounded_subprocess(
        argv, yuzu::agent::SubprocessOptions{.deadline = std::chrono::seconds{20}});
    if (!res.tool_ran || res.timed_out)
        return -1;
    return res.exit_code;
}
#endif

// ── set_start_mode — platform implementations ──────────────────────────────

#ifdef _WIN32

/// Convert a mode string ("automatic", "manual", "disabled") to a Windows
/// SERVICE_* start-type constant.  Returns 0xFFFFFFFF on invalid input.
DWORD mode_to_start_type(std::string_view mode) {
    if (mode == "automatic")
        return SERVICE_AUTO_START;
    if (mode == "manual")
        return SERVICE_DEMAND_START;
    if (mode == "disabled")
        return SERVICE_DISABLED;
    return 0xFFFFFFFF;
}

int do_set_start_mode_win(yuzu::CommandContext& ctx, std::string_view name, std::string_view mode) {
    DWORD start_type = mode_to_start_type(mode);
    if (start_type == 0xFFFFFFFF) {
        ctx.write_output(std::format("error|invalid mode '{}': must be automatic, manual, or disabled", mode));
        return 1;
    }

    auto wide_name = to_wide(name);

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        ctx.write_output(
            std::format("error|failed to open Service Control Manager (err={})", GetLastError()));
        return 1;
    }

    SC_HANDLE svc = OpenServiceW(scm, wide_name.c_str(), SERVICE_CHANGE_CONFIG);
    if (!svc) {
        DWORD err = GetLastError();
        CloseServiceHandle(scm);
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            ctx.write_output(std::format("error|service '{}' not found", name));
        } else if (err == ERROR_ACCESS_DENIED) {
            ctx.write_output(std::format("error|access denied changing service '{}'", name));
        } else {
            ctx.write_output(std::format("error|failed to open service '{}' (err={})", name, err));
        }
        return 1;
    }

    BOOL ok = ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, start_type, SERVICE_NO_CHANGE, nullptr,
                                   nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    DWORD err = GetLastError();
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    if (!ok) {
        ctx.write_output(
            std::format("error|ChangeServiceConfig failed for '{}' (err={})", name, err));
        return 1;
    }

    ctx.write_output("status|ok");
    ctx.write_output(std::format("service|{}", name));
    ctx.write_output(std::format("mode|{}", mode));
    return 0;
}

#elif defined(__linux__)

int do_set_start_mode_linux(yuzu::CommandContext& ctx, std::string_view name,
                            std::string_view mode) {
    auto systemctl_path = yuzu::agent::probe_tool_path({"/usr/bin/systemctl", "/bin/systemctl"});
    if (systemctl_path.empty()) {
        ctx.write_output("error|systemctl not found on this system");
        return 1;
    }

    // services/set_start_mode_linux#1 (docs/agent-spawn-sink-manifest.md)
    // Privileged mutation, Decision-8 canonical form (ADR-3002, sudo_argv.hpp):
    // these four call sites (enable/disable/mask/unmask) previously ran
    // completely UNWRAPPED -- no sudo at all -- even though
    // scripts/install-agent-user.sh installs exactly this grant for a
    // privilege-dropped agent:
    //   /usr/bin/systemctl enable *,  /usr/bin/systemctl disable *
    //   /usr/bin/systemctl mask *,    /usr/bin/systemctl unmask *
    //   (and the /bin/systemctl twin)
    // A non-root agent's systemctl enable/disable/mask/unmask on a SYSTEM
    // unit requires root, so the unwrapped call failed outright for every
    // non-root agent -- the grant existed and was never used. sudo_wrap
    // builds the exact `sudo -n -- <tool> <args>` argv shape that grant
    // matches (a no-op when already root). The systemctl-side "--" keeps the
    // original safety property: is_safe_service_name allows a LEADING '-' in
    // `name` (needed for e.g. "-foo"-shaped unit names to reach the
    // pipe-delimited protocol unmangled), so without "--" a crafted name
    // could still be parsed as a systemctl flag even though there is no
    // shell involved.
    //
    // Mode -> systemctl verb:
    //   automatic -> enable  (starts at boot)
    //   manual    -> disable (available but not started at boot)
    //   disabled  -> mask    (cannot be started at all)
    std::vector<std::string> argv;
    if (mode == "automatic") {
        argv = yuzu::shared::sudo_wrap({systemctl_path, "enable", "--", std::string(name)});
    } else if (mode == "manual") {
        // If the service was previously masked, unmask it first so disable
        // works. Best-effort, same as before: its exit code is intentionally
        // not checked (a service that was never masked has nothing to
        // unmask, and the following disable is the actual mode change).
        run_command_exit(
            yuzu::shared::sudo_wrap({systemctl_path, "unmask", "--", std::string(name)}));
        argv = yuzu::shared::sudo_wrap({systemctl_path, "disable", "--", std::string(name)});
    } else if (mode == "disabled") {
        argv = yuzu::shared::sudo_wrap({systemctl_path, "mask", "--", std::string(name)});
    } else {
        ctx.write_output(
            std::format("error|invalid mode '{}': must be automatic, manual, or disabled", mode));
        return 1;
    }

    int rc = run_command_exit(argv);
    if (rc != 0) {
        ctx.write_output(
            std::format("error|systemctl command failed for '{}' (exit={})", name, rc));
        return 1;
    }

    ctx.write_output("status|ok");
    ctx.write_output(std::format("service|{}", name));
    ctx.write_output(std::format("mode|{}", mode));
    return 0;
}

#elif defined(__APPLE__)

int do_set_start_mode_macos(yuzu::CommandContext& ctx, std::string_view name,
                            std::string_view mode) {
    // launchctl enable/disable operates on service targets.
    // We target the system domain: system/<label>.
    //
    // launchd has no third "manual" (start-on-demand-only) state -- it is a
    // binary enabled/disabled, which is exactly why "list"/"running" only
    // ever report startup_type as automatic|disabled|unknown (C-1.12, see
    // file header). Silently mapping "manual" onto "disabled" here while
    // echoing back the requested "manual" mode would report a value that a
    // subsequent "list" can never confirm (BR-03: state-changing action
    // reporting a mode the platform cannot actually represent). Reject it
    // honestly instead of misrepresenting the effective state.
    auto launchctl_path = yuzu::agent::probe_tool_path({"/bin/launchctl"});
    if (launchctl_path.empty()) {
        ctx.write_output("error|launchctl not found on this system");
        return 1;
    }

    // services/set_start_mode_macos#1 (docs/agent-spawn-sink-manifest.md)
    // Privileged mutation, Decision-8 canonical form (ADR-3002, sudo_argv.hpp):
    // these two call sites (enable/disable) previously ran completely
    // UNWRAPPED -- no sudo at all -- even though
    // scripts/install-agent-user.sh installs exactly this grant for a
    // privilege-dropped agent: `/bin/launchctl enable system/*` and
    // `/bin/launchctl disable system/*`. A non-root agent's launchctl
    // enable/disable on the system domain requires root, so the unwrapped
    // call failed outright for every non-root agent -- the grant existed and
    // was never used. sudo_wrap builds the exact `sudo -n -- <tool> <args>`
    // argv shape that grant matches (a no-op when already root). No
    // systemctl-style "--" is needed here: "system/<name>" is never itself
    // leading-hyphen (it always starts with the literal "system/" prefix),
    // so launchctl can never mistake it for a flag regardless of what `name`
    // contains.
    std::vector<std::string> argv;
    if (mode == "automatic") {
        argv = yuzu::shared::sudo_wrap(
            {launchctl_path, "enable", std::format("system/{}", name)});
    } else if (mode == "disabled") {
        argv = yuzu::shared::sudo_wrap(
            {launchctl_path, "disable", std::format("system/{}", name)});
    } else if (mode == "manual") {
        ctx.write_output(
            "error|mode 'manual' is not supported on macOS: launchd has no manual/auto "
            "distinction, only enabled (automatic) and disabled -- use 'automatic' or "
            "'disabled'");
        return 1;
    } else {
        ctx.write_output(
            std::format("error|invalid mode '{}': must be automatic, manual, or disabled", mode));
        return 1;
    }

    int rc = run_command_exit(argv);
    if (rc != 0) {
        ctx.write_output(
            std::format("error|launchctl command failed for '{}' (exit={})", name, rc));
        return 1;
    }

    ctx.write_output("status|ok");
    ctx.write_output(std::format("service|{}", name));
    ctx.write_output(std::format("mode|{}", mode));
    return 0;
}

#endif

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// windows: EnumServicesStatusExW/QueryServiceConfigW/ChangeServiceConfigW --
// native Win32 Service Control Manager API throughout, rung 1.
// linux: systemctl (list-units / enable|disable|mask|unmask) via
// run_bounded_subprocess(argv, ...) -- shell-free, direct argv[0] exec, no
// `/bin/sh -c` hop -- rung 2 (ADR-3002) for every action: the read-only
// list-units enumeration and enable/disable/mask/unmask (the latter now
// sudo_wrap'd, matching the installed sudoers grant) alike. Previously rung
// 3 (governed shell) throughout -- this migration removed the shell hop
// entirely, it did not merely add sudo.
// macos: launchctl (list, print-disabled, enable|disable) via the same
// shell-free runner path -- rung 2, same as linux above; the macOS
// startup_type leg specifically is the bulk `launchctl print-disabled
// system` parse in services_macos_launchd.hpp.
const YuzuActionDescriptor kActionDescriptors[] = {
    {"list",
     /* linux   = */ {YUZU_SUPPORT_SUPPORTED, 2, "runner argv 'systemctl list-units'", nullptr},
     /* macos   = */ {YUZU_SUPPORT_SUPPORTED, 2, "runner argv 'launchctl list'", nullptr},
     /* windows = */ {YUZU_SUPPORT_SUPPORTED, 1, "win32_service_api", nullptr}},
    {"running",
     /* linux   = */ {YUZU_SUPPORT_SUPPORTED, 2, "runner argv 'systemctl list-units'", nullptr},
     /* macos   = */ {YUZU_SUPPORT_SUPPORTED, 2, "runner argv 'launchctl list'", nullptr},
     /* windows = */ {YUZU_SUPPORT_SUPPORTED, 1, "win32_service_api", nullptr}},
    {"set_start_mode",
     /* linux   = */
     {YUZU_SUPPORT_SUPPORTED, 2, "runner argv 'sudo -n -- systemctl enable|disable|mask|unmask'",
      nullptr},
     /* macos   = */
     {YUZU_SUPPORT_SUPPORTED, 2, "runner argv 'sudo -n -- launchctl enable|disable'", nullptr},
     /* windows = */ {YUZU_SUPPORT_SUPPORTED, 1, "win32_service_api", nullptr}},
};

} // namespace

class ServicesPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "services"; }
    std::string_view version() const noexcept override { return "0.2.0"; }
    std::string_view description() const noexcept override {
        return "System services — enumerate, query, and configure service startup types";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"list", "running", "set_start_mode", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (action == "list") {
            return do_list(ctx, false);
        }
        if (action == "running") {
            return do_list(ctx, true);
        }
        if (action == "set_start_mode") {
            return do_set_start_mode(ctx, params);
        }

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
    int do_set_start_mode(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto name = params.get("name");
        auto mode = params.get("mode");

        if (name.empty()) {
            ctx.write_output("error|missing required parameter: name");
            return 1;
        }
        if (mode.empty()) {
            ctx.write_output("error|missing required parameter: mode");
            return 1;
        }
        if (!is_safe_service_name(name)) {
            ctx.write_output("error|invalid service name: only alphanumeric, hyphens, "
                             "underscores, dots, and @ are allowed");
            return 1;
        }
        if (mode != "automatic" && mode != "manual" && mode != "disabled") {
            ctx.write_output(
                std::format("error|invalid mode '{}': must be automatic, manual, or disabled",
                            mode));
            return 1;
        }

#ifdef _WIN32
        return do_set_start_mode_win(ctx, name, mode);
#elif defined(__linux__)
        return do_set_start_mode_linux(ctx, name, mode);
#elif defined(__APPLE__)
        return do_set_start_mode_macos(ctx, name, mode);
#else
        ctx.write_output("error|unsupported platform");
        return 1;
#endif
    }

    int do_list(yuzu::CommandContext& ctx, bool running_only) {
#ifdef _WIN32
        auto services = enumerate_services_win(running_only);
        for (const auto& s : services) {
            ctx.write_output(
                std::format("svc|{}|{}|{}|{}", s.name, s.display_name, s.status, s.startup_type));
        }
#elif defined(__linux__)
        auto services = enumerate_services_linux(running_only);
        for (const auto& s : services) {
            ctx.write_output(std::format("svc|{}|{}|{}", s.name, s.status, s.description));
        }
#elif defined(__APPLE__)
        std::size_t total_seen = 0;
        auto services = enumerate_services_macos(running_only, total_seen);
        for (const auto& s : services) {
            ctx.write_output(
                std::format("svc|{}|{}|{}|{}", s.label, s.pid, s.status, s.startup_type));
        }
        if (total_seen > yuzu::services::kMaxServiceRows) {
            // Honest truncation sentinel: more services qualified than the row
            // cap kept, so the list above is incomplete. "__truncated__" in the
            // label slot cannot collide with a real (allowlisted) launchd label,
            // and total_seen rides in the status slot.
            ctx.write_output(std::format("svc|__truncated__|-|{}|-", total_seen));
        }
#else
        ctx.write_output("error|unsupported platform");
        return 1;
#endif
        return 0;
    }
};

YUZU_PLUGIN_EXPORT(ServicesPlugin)
