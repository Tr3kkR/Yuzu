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

#include <array>
#include <cstdio>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace yuzu::tar {

// -- Windows implementation ---------------------------------------------------
#ifdef _WIN32

namespace {

// Intentionally duplicated for build isolation — see process_enum.cpp for canonical implementation
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
        si.name = wide_to_utf8(entries[i].lpServiceName);
        si.display_name = wide_to_utf8(entries[i].lpDisplayName);
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
    std::vector<ServiceInfo> services;
    FILE* pipe = popen(
        "timeout 10 systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null", "r");
    if (!pipe) {
        spdlog::error("TAR: failed to run systemctl for service enumeration (popen returned null)");
        return services;
    }

    std::array<char, 1024> buf{};
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        std::string line{buf.data()};
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
            line.pop_back();
        if (line.empty())
            continue;

        // Trim leading whitespace and bullet
        auto start = line.find_first_not_of(" *");
        if (start == std::string::npos)
            continue;
        line = line.substr(start);

        ServiceInfo si;
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

        si.name = next_token();     // UNIT
        next_token();               // LOAD
        next_token();               // ACTIVE
        si.status = next_token();   // SUB
        // Remainder is description
        auto desc_start = line.find_first_not_of(' ', pos);
        if (desc_start != std::string::npos)
            si.display_name = line.substr(desc_start);

        si.startup_type = "unknown";
        services.push_back(std::move(si));
    }
    pclose(pipe);
    return services;
}

// -- macOS implementation -----------------------------------------------------
#elif defined(__APPLE__)

std::vector<ServiceInfo> enumerate_services() {
    std::vector<ServiceInfo> services;
    FILE* pipe = popen("launchctl list 2>/dev/null", "r");
    if (!pipe) {
        spdlog::error("TAR: failed to run launchctl for service enumeration (popen returned null)");
        return services;
    }

    std::array<char, 1024> buf{};
    // Skip header line
    if (fgets(buf.data(), static_cast<int>(buf.size()), pipe) == nullptr) {
        pclose(pipe);
        return services;
    }

    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        std::string line{buf.data()};
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
            line.pop_back();
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

        auto pid_str = next_field();
        next_field(); // status code
        si.name = next_field();

        si.status = (pid_str != "-" && !pid_str.empty()) ? "running" : "stopped";
        // macOS launchctl list does not provide startup type; 'unknown' is correct
        si.startup_type = "unknown";
        services.push_back(std::move(si));
    }
    pclose(pipe);
    return services;
}

#else
// Unsupported platform
std::vector<ServiceInfo> enumerate_services() {
    return {};
}
#endif

} // namespace yuzu::tar
