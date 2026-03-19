/**
 * services_plugin.cpp — System services listing plugin for Yuzu
 *
 * Actions:
 *   "list"    — List installed services with name, display name, status, startup type.
 *   "running" — List only running services.
 *
 * Output is pipe-delimited via write_output():
 *   Windows: svc|name|display_name|status|startup_type
 *   Linux:   svc|name|status|description
 *   macOS:   svc|label|pid|status
 */

#include <yuzu/plugin.hpp>

#include <array>
#include <cstdio>
#include <format>
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
#pragma comment(lib, "advapi32.lib")
#endif

namespace {

#ifdef _WIN32

std::string wide_to_utf8(const wchar_t* wstr) {
    if (!wstr || !*wstr)
        return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0)
        return {};
    std::string result(static_cast<size_t>(len - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, result.data(), len, nullptr, nullptr);
    return result;
}

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
        si.name = wide_to_utf8(entries[i].lpServiceName);
        si.display_name = wide_to_utf8(entries[i].lpDisplayName);
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
};

std::vector<ServiceInfo> enumerate_services_macos(bool running_only) {
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

        if (running_only && si.pid == "-")
            continue;

        services.push_back(std::move(si));
    }
    pclose(pipe);
    return services;
}

#endif

} // namespace

class ServicesPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "services"; }
    std::string_view version() const noexcept override { return "0.1.0"; }
    std::string_view description() const noexcept override {
        return "System services listing — enumerate installed and running services";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"list", "running", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        if (action == "list") {
            return do_list(ctx, false);
        }
        if (action == "running") {
            return do_list(ctx, true);
        }

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
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
        auto services = enumerate_services_macos(running_only);
        for (const auto& s : services) {
            ctx.write_output(std::format("svc|{}|{}|{}", s.label, s.pid, s.status));
        }
#else
        ctx.write_output("error|unsupported platform");
        return 1;
#endif
        return 0;
    }
};

YUZU_PLUGIN_EXPORT(ServicesPlugin)
