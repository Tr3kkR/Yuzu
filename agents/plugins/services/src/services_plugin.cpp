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

#ifdef __APPLE__
#include "services_macos_launchd.hpp" // pure launchctl print-disabled parser (C-1.12)
#endif

namespace {

// Forward-declared: defined below in the shared-helpers section, but the
// macOS enumerate function (further down, same anonymous namespace) needs to
// guard every launchctl label against the same allowlist before trusting it
// into the pipe-delimited protocol -- see is_safe_service_name's definition
// for the allowed character set.
bool is_safe_service_name(std::string_view name);

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

struct ServiceInfo {
    std::string name;
    std::string status;
    std::string description;
};

std::vector<ServiceInfo> enumerate_services_linux(bool running_only) {
    std::vector<ServiceInfo> services;
    const char* cmd =
        running_only
            ? "systemctl list-units --type=service --state=running --no-pager --no-legend "
              "2>/dev/null"
            : "systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null";

    FILE* pipe = popen(cmd, "r");
    if (!pipe)
        return services;

    std::array<char, 1024> buf{};
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        std::string line{buf.data()};
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
            line.pop_back();
        }
        if (line.empty())
            continue;

        // systemctl output: UNIT LOAD ACTIVE SUB DESCRIPTION...
        // Trim leading whitespace and bullet
        auto start = line.find_first_not_of(" *");
        if (start == std::string::npos)
            continue;
        line = line.substr(start);

        ServiceInfo si;
        // Parse columns by whitespace
        size_t pos = 0;
        auto next_token = [&]() -> std::string {
            auto s = line.find_first_not_of(' ', pos);
            if (s == std::string::npos)
                return {};
            auto e = line.find(' ', s);
            if (e == std::string::npos)
                e = line.size();
            pos = e;
            return line.substr(s, e - s);
        };

        si.name = next_token();   // UNIT
        next_token();             // LOAD
        next_token();             // ACTIVE
        si.status = next_token(); // SUB
        // Remainder is description
        auto desc_start = line.find_first_not_of(' ', pos);
        if (desc_start != std::string::npos) {
            si.description = line.substr(desc_start);
        }

        services.push_back(std::move(si));
    }
    pclose(pipe);
    return services;
}

#elif defined(__APPLE__)

struct ServiceInfo {
    std::string label;
    std::string pid;
    std::string status;
    std::string startup_type; // honest automatic|disabled|unknown (C-1.12); never Windows' 5-state taxonomy
};

// Defensive row cap (mirrors the C-8 row_cap precedent in licensing_wmi.hpp):
// real macOS systems run in the low hundreds of launchd services, so this
// bounds worst-case memory/output size without affecting normal enumeration.
// Rows beyond the cap are still drained from the `launchctl list` pipe (so
// the child process never blocks writing into a full pipe) -- just not kept.
constexpr std::size_t kMaxServiceRows = 512;

// Read the full stdout of a command via popen into a string, bounded so a
// runaway/adversarial `launchctl print-disabled` can't grow this unbounded.
// Pure I/O helper (not part of services_macos_launchd.hpp, which stays
// popen-free) -- reused nowhere else, kept file-local like run_command_exit.
std::string slurp_command_output(const char* cmd) {
    std::string out;
    std::unique_ptr<FILE, int (*)(FILE*)> pipe{popen(cmd, "r"), &pclose};
    if (!pipe)
        return out;
    static constexpr std::size_t kMaxOutputBytes = 2 * 1024 * 1024; // 2 MiB sanity cap
    std::array<char, 4096> buf{};
    size_t n;
    while ((n = fread(buf.data(), 1, buf.size(), pipe.get())) > 0) {
        if (out.size() < kMaxOutputBytes) {
            out.append(buf.data(), std::min(n, kMaxOutputBytes - out.size()));
        }
    }
    return out;
}

// total_seen (out) receives the number of services that passed all filters
// (label allowlist + running_only) BEFORE the kMaxServiceRows cap, so the
// caller can emit an honest truncation sentinel when rows were dropped.
std::vector<ServiceInfo> enumerate_services_macos(bool running_only, std::size_t& total_seen) {
    total_seen = 0;
    std::vector<ServiceInfo> services;
    FILE* pipe = popen("launchctl list 2>/dev/null", "r");
    if (!pipe)
        return services;

    std::array<char, 1024> buf{};
    // Skip header
    if (fgets(buf.data(), static_cast<int>(buf.size()), pipe) == nullptr) {
        pclose(pipe);
        return services;
    }

    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        std::string line{buf.data()};
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
            line.pop_back();
        }
        if (line.empty())
            continue;

        // Format: PID\tStatus\tLabel
        ServiceInfo si;
        size_t pos = 0;
        auto next_field = [&]() -> std::string {
            auto tab = line.find('\t', pos);
            std::string field;
            if (tab == std::string::npos) {
                field = line.substr(pos);
                pos = line.size();
            } else {
                field = line.substr(pos, tab - pos);
                pos = tab + 1;
            }
            return field;
        };

        si.pid = next_field();
        si.status = next_field();
        si.label = next_field();

        // Guard the label before it is ever trusted into the pipe-delimited
        // protocol or used as a startup_type_for() join key -- an unsafe
        // label (e.g. containing '|') would otherwise corrupt the field
        // boundaries write_output() emits below. Same allowlist as
        // is_safe_launchd_label in services_macos_launchd.hpp.
        if (!is_safe_service_name(si.label))
            continue;

        if (running_only && si.pid == "-")
            continue;

        // Count every qualifying service BEFORE the cap so the caller can tell
        // a truncated inventory from a complete one.
        ++total_seen;

        // Row cap: keep draining the pipe (loop continues) but stop storing
        // once the cap is hit, so the child never blocks on a full pipe.
        if (services.size() < kMaxServiceRows) {
            services.push_back(std::move(si));
        }
    }
    pclose(pipe);

    // P15 (verified): ONE bulk `launchctl print-disabled system` call for the
    // enabled/disabled map of ALL services, joined below -- NOT an N+1
    // `launchctl print system/<label>` per service (hundreds of services would
    // mean hundreds of subprocess spawns). services_macos_launchd.hpp
    // re-validates every label (is_safe_launchd_label, same allowlist as
    // is_safe_service_name above) before trusting it as a join key, so an
    // unparseable/hostile label just yields "unknown".
    auto disabled_map = yuzu::services_macos::parse_print_disabled(
        slurp_command_output("launchctl print-disabled system 2>/dev/null"));
    for (auto& si : services) {
        si.startup_type = yuzu::services_macos::startup_type_for(disabled_map, si.label);
    }

    return services;
}

#endif

// ── Shared helpers ──────────────────────────────────────────────────────────

/// Validate a service name to prevent command injection.
/// Allows alphanumeric, hyphens, underscores, dots, and '@' (for systemd
/// template instances like getty@tty1.service).
bool is_safe_service_name(std::string_view name) {
    if (name.empty() || name.size() > 256)
        return false;
    for (char c : name) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_' && c != '.' &&
            c != '@') {
            return false;
        }
    }
    return true;
}

/// Run a command via popen and return its exit code.
/// Drains stdout so the child process doesn't block on a full pipe.
#if defined(__linux__) || defined(__APPLE__)
int run_command_exit(const char* cmd) {
    FILE* pipe = popen(cmd, "r");
    if (!pipe)
        return -1;
    std::array<char, 256> buf{};
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
    }
    int raw = pclose(pipe);
    // pclose returns the wait status; extract the actual exit code
    if (WIFEXITED(raw))
        return WEXITSTATUS(raw);
    return -1;
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
    // Build the systemctl command based on mode:
    //   automatic -> enable  (starts at boot)
    //   manual    -> disable (available but not started at boot)
    //   disabled  -> mask    (cannot be started at all)
    std::string cmd;
    if (mode == "automatic") {
        cmd = std::format("systemctl enable -- {} 2>&1", name);
    } else if (mode == "manual") {
        // If the service was previously masked, unmask it first so disable works
        auto unmask_cmd = std::format("systemctl unmask -- {} 2>/dev/null", name);
        run_command_exit(unmask_cmd.c_str());
        cmd = std::format("systemctl disable -- {} 2>&1", name);
    } else if (mode == "disabled") {
        cmd = std::format("systemctl mask -- {} 2>&1", name);
    } else {
        ctx.write_output(
            std::format("error|invalid mode '{}': must be automatic, manual, or disabled", mode));
        return 1;
    }

    int rc = run_command_exit(cmd.c_str());
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
    std::string cmd;
    if (mode == "automatic") {
        cmd = std::format("launchctl enable system/{} 2>&1", name);
    } else if (mode == "disabled") {
        cmd = std::format("launchctl disable system/{} 2>&1", name);
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

    int rc = run_command_exit(cmd.c_str());
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
        if (total_seen > kMaxServiceRows) {
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
