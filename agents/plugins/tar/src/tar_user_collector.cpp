/**
 * tar_user_collector.cpp -- User session enumeration for TAR plugin
 *
 * Enumerates active user sessions and returns them as structured
 * UserSession records for diff-based change detection (login/logout).
 *
 * Platform support:
 *   Windows -- WTSEnumerateSessionsW + WTSQuerySessionInformationW
 *   Linux   -- /var/run/utmp (struct utmp)
 *   macOS   -- who command output
 */

#include "tar_collectors.hpp"

#include <spdlog/spdlog.h>

#include <array>
#include <cstdio>
#include <sstream>
#include <string>
#include <vector>

#ifdef __linux__
#include <utmp.h>
#endif

#ifdef __APPLE__
#include <utmpx.h>
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wtsapi32.h>
#endif

namespace yuzu::tar {

// -- Windows implementation ---------------------------------------------------
#ifdef _WIN32

namespace {

std::string wide_to_utf8_user(const wchar_t* wstr) {
    if (!wstr || !*wstr)
        return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0)
        return {};
    std::string result(static_cast<size_t>(len - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, result.data(), len, nullptr, nullptr);
    return result;
}

} // namespace

std::vector<UserSession> enumerate_users() {
    std::vector<UserSession> sessions;

    WTS_SESSION_INFOW* wts_sessions = nullptr;
    DWORD count = 0;
    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &wts_sessions, &count))
        return sessions;

    for (DWORD i = 0; i < count; ++i) {
        if (wts_sessions[i].State != WTSActive && wts_sessions[i].State != WTSDisconnected)
            continue;

        LPWSTR user_buf = nullptr;
        DWORD user_len = 0;
        LPWSTR domain_buf = nullptr;
        DWORD domain_len = 0;

        WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, wts_sessions[i].SessionId,
                                    WTSUserName, &user_buf, &user_len);
        WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, wts_sessions[i].SessionId,
                                    WTSDomainName, &domain_buf, &domain_len);

        auto user = wide_to_utf8_user(user_buf);
        auto domain = wide_to_utf8_user(domain_buf);

        if (user_buf)
            WTSFreeMemory(user_buf);
        if (domain_buf)
            WTSFreeMemory(domain_buf);

        if (user.empty())
            continue;

        UserSession us;
        us.user = user;
        us.domain = domain.empty() ? "local" : domain;
        us.session_id = std::to_string(wts_sessions[i].SessionId);

        // Determine logon type from session name
        auto station_name = wide_to_utf8_user(wts_sessions[i].pWinStationName);
        if (station_name.find("RDP") != std::string::npos ||
            station_name.find("rdp") != std::string::npos) {
            us.logon_type = "remote";
        } else {
            us.logon_type = "interactive";
        }

        sessions.push_back(std::move(us));
    }
    WTSFreeMemory(wts_sessions);
    return sessions;
}

// -- Linux implementation -----------------------------------------------------
#elif defined(__linux__)

std::vector<UserSession> enumerate_users() {
    std::vector<UserSession> sessions;

    setutent();
    struct utmp* entry = nullptr;
    while ((entry = getutent()) != nullptr) {
        if (entry->ut_type != USER_PROCESS)
            continue;

        UserSession us;
        us.user = std::string(entry->ut_user);
        us.session_id = std::string(entry->ut_line);

        std::string host(entry->ut_host);
        us.domain = host.empty() ? "local" : host;

        // Determine logon type from tty name
        std::string line_str(entry->ut_line);
        us.logon_type = line_str.starts_with("pts/") ? "remote" : "interactive";

        sessions.push_back(std::move(us));
    }
    endutent();
    return sessions;
}

// -- macOS implementation -----------------------------------------------------
#elif defined(__APPLE__)

std::vector<UserSession> enumerate_users() {
    std::vector<UserSession> sessions;

    // Use utmpx API instead of parsing `who` output for reliable field extraction
    setutxent();
    struct utmpx* entry = nullptr;
    while ((entry = getutxent()) != nullptr) {
        if (entry->ut_type != USER_PROCESS)
            continue;

        UserSession us;
        us.user = std::string(entry->ut_user);
        us.session_id = std::string(entry->ut_line);

        std::string host(entry->ut_host);
        us.domain = host.empty() ? "local" : host;

        // Determine logon type from tty name
        std::string line_str(entry->ut_line);
        us.logon_type = line_str.starts_with("ttys") ? "remote" : "interactive";

        sessions.push_back(std::move(us));
    }
    endutxent();
    return sessions;
}

#else
// Unsupported platform
std::vector<UserSession> enumerate_users() {
    return {};
}
#endif

} // namespace yuzu::tar
