/**
 * users_plugin.cpp — User accounts plugin for Yuzu
 *
 * Actions:
 *   "logged_on"       — Lists currently logged-on users.
 *   "sessions"        — Lists active interactive sessions.
 *   "local_users"     — Enumerates local user accounts.
 *   "local_admins"    — Lists members of the local Administrators group.
 *   "group_members"   — Lists members of a specified local group.
 *   "primary_user"    — Identifies the primary user (most frequent login).
 *   "session_history" — Shows historical login/logout session records.
 *
 * Output is pipe-delimited, one record per line via write_output():
 *   key|field1|field2|...
 */

#include <yuzu/plugin.hpp>

#include <array>
#include <cstdio>
#include <format>
#include <map>
#include <sstream>
#include <string>
#include <string_view>

#if defined(__linux__)
#include <ctime>
#include <fstream>
#include <grp.h>
#include <pwd.h>
#include <shadow.h>
#include <utmp.h>
#endif

#if defined(__APPLE__)
#include <ctime>
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <lm.h>
#include <wtsapi32.h>
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "netapi32.lib")
#endif

namespace {

// ── input validation ──────────────────────────────────────────────────────

/// Validate that a string contains only safe characters for use in shell commands.
/// Allows: [a-zA-Z0-9._-] — rejects anything with shell metacharacters.
bool is_safe_identifier(std::string_view s) {
    if (s.empty())
        return false;
    for (char c : s) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '.' || c == '_' || c == '-')) {
            return false;
        }
    }
    return true;
}

// ── subprocess helper (all platforms) ──────────────────────────────────────

std::string run_command(const char* cmd) {
    std::string result;
    std::array<char, 256> buf{};
#ifdef _WIN32
    FILE* pipe = _popen(cmd, "r");
#else
    FILE* pipe = popen(cmd, "r");
#endif
    if (!pipe)
        return result;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        result += buf.data();
    }
#ifdef _WIN32
    _pclose(pipe);
#else
    pclose(pipe);
#endif
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
    }
    return result;
}

#ifdef _WIN32
// Convert a wide string to UTF-8
std::string wide_to_utf8(const wchar_t* ws) {
    if (!ws || !*ws)
        return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, ws, -1, nullptr, 0, nullptr, nullptr);
    std::string result(len > 0 ? len - 1 : 0, '\0');
    if (len > 0) {
        WideCharToMultiByte(CP_UTF8, 0, ws, -1, result.data(), len, nullptr, nullptr);
    }
    return result;
}

// Format a Windows FILETIME as "YYYY-MM-DD HH:MM:SS" or "Never" if zero
std::string format_filetime(DWORD low, DWORD high) {
    if (low == 0 && high == 0)
        return "Never";
    FILETIME ft;
    ft.dwLowDateTime = low;
    ft.dwHighDateTime = high;
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);
    return std::format("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", st.wYear, st.wMonth, st.wDay,
                       st.wHour, st.wMinute, st.wSecond);
}
#endif

// ── logged_on action ──────────────────────────────────────────────────────

int do_logged_on(yuzu::CommandContext& ctx) {
#ifdef __linux__
    // Read utmp for logged-on users
    setutent();
    struct utmp* entry;
    while ((entry = getutent()) != nullptr) {
        if (entry->ut_type == USER_PROCESS) {
            std::string user(entry->ut_user);
            std::string host(entry->ut_host);
            std::string line(entry->ut_line);
            // Determine logon type from tty name
            std::string logon_type = "console";
            if (line.starts_with("pts/"))
                logon_type = "remote";
            std::string session_id = line;
            ctx.write_output(std::format("user|{}|{}|{}|{}", user, host.empty() ? "local" : host,
                                         logon_type, session_id));
        }
    }
    endutent();

#elif defined(__APPLE__)
    auto who_out = run_command("who 2>/dev/null");
    if (!who_out.empty()) {
        std::istringstream ss(who_out);
        std::string line;
        while (std::getline(ss, line)) {
            // Format: username  tty  date time (host)
            std::istringstream ls(line);
            std::string user, tty;
            ls >> user >> tty;
            std::string logon_type = "console";
            if (tty.starts_with("ttys"))
                logon_type = "remote";
            // Extract host if present (in parentheses at end)
            std::string domain = "local";
            auto paren = line.rfind('(');
            if (paren != std::string::npos) {
                auto end = line.rfind(')');
                if (end != std::string::npos && end > paren) {
                    domain = line.substr(paren + 1, end - paren - 1);
                }
            }
            ctx.write_output(std::format("user|{}|{}|{}|{}", user, domain, logon_type, tty));
        }
    }

#elif defined(_WIN32)
    WTS_SESSION_INFOW* sessions = nullptr;
    DWORD count = 0;
    if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count)) {
        for (DWORD i = 0; i < count; ++i) {
            if (sessions[i].State != WTSActive && sessions[i].State != WTSDisconnected)
                continue;

            LPWSTR user_buf = nullptr;
            DWORD user_len = 0;
            LPWSTR domain_buf = nullptr;
            DWORD domain_len = 0;

            WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessions[i].SessionId,
                                        WTSUserName, &user_buf, &user_len);
            WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessions[i].SessionId,
                                        WTSDomainName, &domain_buf, &domain_len);

            auto user = wide_to_utf8(user_buf);
            auto domain = wide_to_utf8(domain_buf);

            if (user_buf)
                WTSFreeMemory(user_buf);
            if (domain_buf)
                WTSFreeMemory(domain_buf);

            if (user.empty())
                continue;

            std::string logon_type = "console";
            auto session_name = wide_to_utf8(sessions[i].pWinStationName);
            if (session_name.find("RDP") != std::string::npos ||
                session_name.find("rdp") != std::string::npos) {
                logon_type = "RDP";
            }

            ctx.write_output(std::format("user|{}|{}|{}|{}", user,
                                         domain.empty() ? "local" : domain, logon_type,
                                         sessions[i].SessionId));
        }
        WTSFreeMemory(sessions);
    }
#endif
    return 0;
}

// ── sessions action ───────────────────────────────────────────────────────

int do_sessions(yuzu::CommandContext& ctx) {
#ifdef __linux__
    // Use 'w' command for session info with idle times
    auto w_out = run_command("w -h 2>/dev/null");
    if (!w_out.empty()) {
        std::istringstream ss(w_out);
        std::string line;
        while (std::getline(ss, line)) {
            // Fields: USER TTY FROM LOGIN@ IDLE JCPU PCPU WHAT
            std::istringstream ls(line);
            std::string user, tty, from, login, idle;
            ls >> user >> tty >> from >> login >> idle;
            std::string state = "Active";
            // Parse idle time to seconds (format: "1:23" or "1.00s" or "1days")
            std::string idle_seconds = idle;
            ctx.write_output(std::format("session|{}|{}|{}|{}|{}", tty, user, state,
                                         from.empty() ? "-" : from, idle));
        }
    }

#elif defined(__APPLE__)
    auto w_out = run_command("w -h 2>/dev/null");
    if (!w_out.empty()) {
        std::istringstream ss(w_out);
        std::string line;
        while (std::getline(ss, line)) {
            std::istringstream ls(line);
            std::string user, tty, from, login, idle;
            ls >> user >> tty >> from >> login >> idle;
            ctx.write_output(std::format("session|{}|{}|Active|{}|{}", tty, user,
                                         from.empty() ? "-" : from, idle));
        }
    }

#elif defined(_WIN32)
    WTS_SESSION_INFOW* sessions = nullptr;
    DWORD count = 0;
    if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count)) {
        for (DWORD i = 0; i < count; ++i) {
            LPWSTR user_buf = nullptr;
            DWORD user_len = 0;
            WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessions[i].SessionId,
                                        WTSUserName, &user_buf, &user_len);
            auto user = wide_to_utf8(user_buf);
            if (user_buf)
                WTSFreeMemory(user_buf);

            if (user.empty())
                continue;

            const char* state = "unknown";
            switch (sessions[i].State) {
            case WTSActive:
                state = "Active";
                break;
            case WTSConnected:
                state = "Connected";
                break;
            case WTSDisconnected:
                state = "Disconnected";
                break;
            case WTSIdle:
                state = "Idle";
                break;
            case WTSListen:
                state = "Listen";
                break;
            default:
                state = "Other";
                break;
            }

            // Get client name for RDP sessions
            LPWSTR client_buf = nullptr;
            DWORD client_len = 0;
            WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessions[i].SessionId,
                                        WTSClientName, &client_buf, &client_len);
            auto client = wide_to_utf8(client_buf);
            if (client_buf)
                WTSFreeMemory(client_buf);

            // Get idle time
            WTSINFOEXW* info_buf = nullptr;
            DWORD info_len = 0;
            long long idle_secs = 0;
            if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessions[i].SessionId,
                                            WTSSessionInfo, reinterpret_cast<LPWSTR*>(&info_buf),
                                            &info_len) &&
                info_buf) {
                // IdleTime is a LARGE_INTEGER representing 100-nanosecond intervals
                // But WTSINFOEXA has different layout; use CurrentTime - LastInputTime
                // For simplicity, report 0 for active sessions
                WTSFreeMemory(info_buf);
            }

            ctx.write_output(std::format("session|{}|{}|{}|{}|{}", sessions[i].SessionId, user,
                                         state, client.empty() ? "-" : client, idle_secs));
        }
        WTSFreeMemory(sessions);
    }
#endif
    return 0;
}

// ── local_users action ────────────────────────────────────────────────────

int do_local_users(yuzu::CommandContext& ctx) {
#ifdef __linux__
    std::ifstream passwd("/etc/passwd");
    if (!passwd) {
        ctx.write_output("local_user|error|false|Never|Cannot read /etc/passwd");
        return 1;
    }
    std::string line;
    while (std::getline(passwd, line)) {
        // Format: username:x:uid:gid:description:home:shell
        std::istringstream ls(line);
        std::string user, x, uid_s, gid_s, desc, home, shell;
        std::getline(ls, user, ':');
        std::getline(ls, x, ':');
        std::getline(ls, uid_s, ':');
        std::getline(ls, gid_s, ':');
        std::getline(ls, desc, ':');
        std::getline(ls, home, ':');
        std::getline(ls, shell, ':');

        int uid = 0;
        try {
            uid = std::stoi(uid_s);
        } catch (...) {}

        // Skip system accounts (uid < 1000, except root)
        if (uid != 0 && uid < 1000)
            continue;
        // Skip nologin/false shell accounts
        bool enabled = true;
        if (shell.find("nologin") != std::string::npos ||
            shell.find("/false") != std::string::npos) {
            enabled = false;
        }

        // Try to get last login from lastlog
        std::string last_logon = "unknown";
        auto lastlog_out =
            run_command(std::format("lastlog -u {} 2>/dev/null | tail -1", user).c_str());
        if (!lastlog_out.empty() && lastlog_out.find("Never") != std::string::npos) {
            last_logon = "Never";
        } else if (!lastlog_out.empty()) {
            // Extract the date portion (after Username and Port columns)
            auto from_pos = lastlog_out.find("**");
            if (from_pos == std::string::npos) {
                // Try to extract date after the port field
                last_logon = lastlog_out;
            }
        }

        ctx.write_output(std::format("local_user|{}|{}|{}|{}", user, enabled ? "true" : "false",
                                     last_logon, desc.empty() ? "-" : desc));
    }

#elif defined(__APPLE__)
    auto dscl_out = run_command("dscl . -list /Users UniqueID 2>/dev/null");
    if (!dscl_out.empty()) {
        std::istringstream ss(dscl_out);
        std::string line;
        while (std::getline(ss, line)) {
            std::istringstream ls(line);
            std::string user, uid_s;
            ls >> user >> uid_s;
            int uid = 0;
            try {
                uid = std::stoi(uid_s);
            } catch (...) {}
            // Skip system accounts
            if (uid < 500 && user != "root")
                continue;
            if (user.starts_with("_"))
                continue;

            // Validate username before using in shell commands
            if (!is_safe_identifier(user))
                continue;

            // Check if account is enabled
            auto shell = run_command(
                std::format("dscl . -read /Users/{} UserShell 2>/dev/null", user).c_str());
            // Extract second field (the shell path) without piping to awk
            bool enabled = true;
            {
                auto sp = shell.find(' ');
                if (sp != std::string::npos) {
                    auto shell_path = shell.substr(sp + 1);
                    while (!shell_path.empty() && shell_path.front() == ' ')
                        shell_path.erase(shell_path.begin());
                    enabled = shell_path.find("false") == std::string::npos &&
                              shell_path.find("nologin") == std::string::npos;
                }
            }

            auto desc_raw = run_command(
                std::format("dscl . -read /Users/{} RealName 2>/dev/null", user).c_str());
            // Extract real name: skip first line ("RealName:"), trim leading space
            std::string desc;
            {
                auto nl = desc_raw.find('\n');
                if (nl != std::string::npos) {
                    desc = desc_raw.substr(nl + 1);
                    while (!desc.empty() && desc.front() == ' ')
                        desc.erase(desc.begin());
                } else {
                    // Single-line: strip "RealName: " prefix
                    auto colon2 = desc_raw.find(':');
                    if (colon2 != std::string::npos) {
                        desc = desc_raw.substr(colon2 + 1);
                        while (!desc.empty() && desc.front() == ' ')
                            desc.erase(desc.begin());
                    }
                }
            }

            ctx.write_output(std::format("local_user|{}|{}|unknown|{}", user,
                                         enabled ? "true" : "false", desc.empty() ? "-" : desc));
        }
    }

#elif defined(_WIN32)
    LPUSER_INFO_2 buf = nullptr;
    DWORD entries_read = 0;
    DWORD total_entries = 0;
    DWORD resume = 0;
    NET_API_STATUS status;

    do {
        status = NetUserEnum(nullptr, 2, FILTER_NORMAL_ACCOUNT, reinterpret_cast<LPBYTE*>(&buf),
                             MAX_PREFERRED_LENGTH, &entries_read, &total_entries, &resume);

        if (status == NERR_Success || status == ERROR_MORE_DATA) {
            for (DWORD i = 0; i < entries_read; ++i) {
                auto& u = buf[i];
                auto name = wide_to_utf8(u.usri2_name);
                bool enabled = !(u.usri2_flags & UF_ACCOUNTDISABLE);
                auto comment = wide_to_utf8(u.usri2_comment);

                // Format last logon
                std::string last_logon = "Never";
                if (u.usri2_last_logon != 0) {
                    time_t t = static_cast<time_t>(u.usri2_last_logon);
                    struct tm tm_buf{};
                    localtime_s(&tm_buf, &t);
                    char time_str[64]{};
                    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);
                    last_logon = time_str;
                }

                ctx.write_output(std::format("local_user|{}|{}|{}|{}", name,
                                             enabled ? "true" : "false", last_logon,
                                             comment.empty() ? "-" : comment));
            }
            NetApiBufferFree(buf);
            buf = nullptr;
        }
    } while (status == ERROR_MORE_DATA);
#endif
    return 0;
}

// ── local_admins action ───────────────────────────────────────────────────

int do_local_admins(yuzu::CommandContext& ctx) {
#ifdef __linux__
    // Check sudo and wheel groups
    for (const char* group_name : {"sudo", "wheel"}) {
        struct group* grp = getgrnam(group_name);
        if (!grp)
            continue;
        for (char** member = grp->gr_mem; *member; ++member) {
            ctx.write_output(std::format("admin|{}|user|{}", *member, group_name));
        }
    }
    // Also check root (uid 0) in /etc/passwd
    struct passwd* pw = getpwuid(0);
    if (pw) {
        ctx.write_output(std::format("admin|{}|user|root", pw->pw_name));
    }

#elif defined(__APPLE__)
    auto admin_out = run_command("dscl . -read /Groups/admin GroupMembership 2>/dev/null");
    if (!admin_out.empty()) {
        // Format: GroupMembership: user1 user2 user3
        auto colon = admin_out.find(':');
        if (colon != std::string::npos) {
            auto members = admin_out.substr(colon + 1);
            std::istringstream ss(members);
            std::string member;
            while (ss >> member) {
                ctx.write_output(std::format("admin|{}|user|admin", member));
            }
        }
    }

#elif defined(_WIN32)
    LPLOCALGROUP_MEMBERS_INFO_2 buf = nullptr;
    DWORD entries_read = 0;
    DWORD total_entries = 0;
    DWORD_PTR resume = 0;

    NET_API_STATUS status =
        NetLocalGroupGetMembers(nullptr, L"Administrators", 2, reinterpret_cast<LPBYTE*>(&buf),
                                MAX_PREFERRED_LENGTH, &entries_read, &total_entries, &resume);

    if (status == NERR_Success) {
        for (DWORD i = 0; i < entries_read; ++i) {
            auto& m = buf[i];
            auto name = wide_to_utf8(m.lgrmi2_domainandname);

            const char* type_str = "unknown";
            switch (m.lgrmi2_sidusage) {
            case SidTypeUser:
                type_str = "user";
                break;
            case SidTypeGroup:
                type_str = "group";
                break;
            case SidTypeWellKnownGroup:
                type_str = "well_known_group";
                break;
            case SidTypeAlias:
                type_str = "alias";
                break;
            default:
                break;
            }

            // Split domain\name
            std::string domain = "local";
            std::string member_name = name;
            auto backslash = name.find('\\');
            if (backslash != std::string::npos) {
                domain = name.substr(0, backslash);
                member_name = name.substr(backslash + 1);
            }

            ctx.write_output(std::format("admin|{}|{}|{}", member_name, type_str, domain));
        }
        NetApiBufferFree(buf);
    }
#endif
    return 0;
}

// ── group_members action ──────────────────────────────────────────────────

int do_group_members(yuzu::CommandContext& ctx, yuzu::Params params) {
    auto group_name = params.get("group");
    if (group_name.empty()) {
        ctx.write_output("group_member|error|Missing required parameter: group");
        return 1;
    }

    // Validate group_name to prevent command injection on platforms that use shell commands
    if (!is_safe_identifier(group_name)) {
        ctx.write_output(std::format("group_member|error|Invalid group name: {}", group_name));
        return 1;
    }

#ifdef __linux__
    struct group* grp = getgrnam(std::string(group_name).c_str());
    if (!grp) {
        ctx.write_output(std::format("group_member|error|Group not found: {}", group_name));
        return 1;
    }
    for (char** member = grp->gr_mem; *member; ++member) {
        ctx.write_output(std::format("group_member|{}|{}|user", *member, group_name));
    }

    // Also check if any user has this as their primary group (GID match)
    std::ifstream passwd("/etc/passwd");
    if (passwd) {
        std::string line;
        while (std::getline(passwd, line)) {
            std::istringstream ls(line);
            std::string user, x, uid_s, gid_s;
            std::getline(ls, user, ':');
            std::getline(ls, x, ':');
            std::getline(ls, uid_s, ':');
            std::getline(ls, gid_s, ':');
            int gid = 0;
            try {
                gid = std::stoi(gid_s);
            } catch (...) {}
            if (gid == static_cast<int>(grp->gr_gid)) {
                // Check if already listed as explicit member
                bool already_listed = false;
                for (char** member = grp->gr_mem; *member; ++member) {
                    if (user == *member) {
                        already_listed = true;
                        break;
                    }
                }
                if (!already_listed) {
                    ctx.write_output(
                        std::format("group_member|{}|{}|primary_group", user, group_name));
                }
            }
        }
    }

#elif defined(__APPLE__)
    auto dscl_out = run_command(
        std::format("dscl . -read /Groups/{} GroupMembership 2>/dev/null", group_name).c_str());
    if (!dscl_out.empty()) {
        auto colon = dscl_out.find(':');
        if (colon != std::string::npos) {
            auto members_str = dscl_out.substr(colon + 1);
            std::istringstream ss(members_str);
            std::string member;
            while (ss >> member) {
                ctx.write_output(
                    std::format("group_member|{}|{}|user", member, group_name));
            }
        }
    } else {
        ctx.write_output(std::format("group_member|error|Group not found: {}", group_name));
        return 1;
    }

#elif defined(_WIN32)
    // Convert group name to wide string
    std::wstring wgroup(group_name.begin(), group_name.end());

    LPLOCALGROUP_MEMBERS_INFO_2 buf = nullptr;
    DWORD entries_read = 0;
    DWORD total_entries = 0;
    DWORD_PTR resume = 0;

    NET_API_STATUS status = NetLocalGroupGetMembers(
        nullptr, wgroup.c_str(), 2, reinterpret_cast<LPBYTE*>(&buf), MAX_PREFERRED_LENGTH,
        &entries_read, &total_entries, &resume);

    if (status == NERR_Success || status == ERROR_MORE_DATA) {
        for (DWORD i = 0; i < entries_read; ++i) {
            auto& m = buf[i];
            auto name = wide_to_utf8(m.lgrmi2_domainandname);

            const char* type_str = "unknown";
            switch (m.lgrmi2_sidusage) {
            case SidTypeUser:
                type_str = "user";
                break;
            case SidTypeGroup:
                type_str = "group";
                break;
            case SidTypeWellKnownGroup:
                type_str = "well_known_group";
                break;
            case SidTypeAlias:
                type_str = "alias";
                break;
            default:
                break;
            }

            // Split domain\name
            std::string member_name = name;
            auto backslash = name.find('\\');
            if (backslash != std::string::npos) {
                member_name = name.substr(backslash + 1);
            }

            ctx.write_output(
                std::format("group_member|{}|{}|{}", member_name, group_name, type_str));
        }
        NetApiBufferFree(buf);
    } else if (status == NERR_GroupNotFound || status == ERROR_NO_SUCH_ALIAS) {
        ctx.write_output(std::format("group_member|error|Group not found: {}", group_name));
        return 1;
    } else {
        ctx.write_output(std::format("group_member|error|Failed to query group: {}", group_name));
        return 1;
    }
#endif
    return 0;
}

// ── primary_user action ──────────────────────────────────────────────────

int do_primary_user(yuzu::CommandContext& ctx) {
#ifdef __linux__
    // Parse 'last' output to find most-frequent interactive login
    auto last_out = run_command("last -F 2>/dev/null | head -200");
    if (!last_out.empty()) {
        std::map<std::string, int> login_counts;
        std::istringstream ss(last_out);
        std::string line;
        while (std::getline(ss, line)) {
            if (line.empty() || line.starts_with("reboot") || line.starts_with("wtmp"))
                continue;
            std::istringstream ls(line);
            std::string user;
            ls >> user;
            if (user.empty() || user == "reboot" || user == "wtmp")
                continue;
            login_counts[user]++;
        }

        // Find the user with most logins
        std::string primary;
        int max_count = 0;
        for (const auto& [user, count] : login_counts) {
            if (count > max_count) {
                max_count = count;
                primary = user;
            }
        }

        if (!primary.empty()) {
            ctx.write_output(std::format("primary_user|{}|{}|last", primary, max_count));
        } else {
            ctx.write_output("primary_user|unknown|0|no login records");
        }
    } else {
        ctx.write_output("primary_user|unknown|0|last command failed");
    }

#elif defined(__APPLE__)
    // macOS: use 'last' command similarly
    auto last_out = run_command("last 2>/dev/null | head -200");
    if (!last_out.empty()) {
        std::map<std::string, int> login_counts;
        std::istringstream ss(last_out);
        std::string line;
        while (std::getline(ss, line)) {
            if (line.empty() || line.starts_with("reboot") || line.starts_with("wtmp") ||
                line.starts_with("shutdown"))
                continue;
            std::istringstream ls(line);
            std::string user;
            ls >> user;
            if (user.empty() || user == "reboot" || user == "wtmp" || user == "shutdown")
                continue;
            login_counts[user]++;
        }

        std::string primary;
        int max_count = 0;
        for (const auto& [user, count] : login_counts) {
            if (count > max_count) {
                max_count = count;
                primary = user;
            }
        }

        if (!primary.empty()) {
            ctx.write_output(std::format("primary_user|{}|{}|last", primary, max_count));
        } else {
            ctx.write_output("primary_user|unknown|0|no login records");
        }
    } else {
        ctx.write_output("primary_user|unknown|0|last command failed");
    }

#elif defined(_WIN32)
    // Windows: query Security Event Log for logon events (Event ID 4624)
    // Use wevtutil to extract recent logon events
    auto evt_out = run_command(
        "wevtutil qe Security /q:\"*[System[EventID=4624]]\" /c:200 /f:text /rd:true 2>&1");
    if (!evt_out.empty() && evt_out.find("Access is denied") == std::string::npos) {
        std::map<std::string, int> login_counts;
        std::istringstream ss(evt_out);
        std::string line;
        while (std::getline(ss, line)) {
            // Look for "Account Name:" lines (skip the first one per event, which is machine$)
            auto start = line.find_first_not_of(" \t");
            if (start == std::string::npos)
                continue;
            auto trimmed = line.substr(start);
            if (trimmed.starts_with("Account Name:")) {
                auto name = trimmed.substr(13);
                auto name_start = name.find_first_not_of(" \t");
                if (name_start != std::string::npos) {
                    name = name.substr(name_start);
                    // Skip machine accounts (ending with $)
                    if (!name.empty() && name.back() != '$' && name != "-" && name != "SYSTEM") {
                        login_counts[name]++;
                    }
                }
            }
        }

        std::string primary;
        int max_count = 0;
        for (const auto& [user, count] : login_counts) {
            if (count > max_count) {
                max_count = count;
                primary = user;
            }
        }

        if (!primary.empty()) {
            ctx.write_output(
                std::format("primary_user|{}|{}|event_log_4624", primary, max_count));
        } else {
            ctx.write_output("primary_user|unknown|0|no logon events found");
        }
    } else {
        // Fallback: check user profiles in registry
        auto reg_out = run_command(
            "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows "
            "NT\\CurrentVersion\\ProfileList\" /s 2>&1");
        if (!reg_out.empty()) {
            std::string last_user;
            std::istringstream ss(reg_out);
            std::string line;
            while (std::getline(ss, line)) {
                auto start = line.find_first_not_of(" \t");
                if (start == std::string::npos)
                    continue;
                auto trimmed = line.substr(start);
                if (trimmed.find("ProfileImagePath") != std::string::npos) {
                    auto users_pos = trimmed.find("\\Users\\");
                    if (users_pos != std::string::npos) {
                        last_user = trimmed.substr(users_pos + 7);
                        // Trim trailing whitespace
                        while (!last_user.empty() &&
                               (last_user.back() == '\r' || last_user.back() == ' '))
                            last_user.pop_back();
                    }
                }
            }
            if (!last_user.empty()) {
                ctx.write_output(
                    std::format("primary_user|{}|0|profile_list", last_user));
            } else {
                ctx.write_output("primary_user|unknown|0|no profiles found");
            }
        } else {
            ctx.write_output("primary_user|unknown|0|cannot query event log or registry");
        }
    }
#endif
    return 0;
}

// ── session_history action ───────────────────────────────────────────────

int do_session_history(yuzu::CommandContext& ctx, yuzu::Params params) {
    auto count_param = params.get("count", "50");
    int count = 50;
    try {
        count = std::stoi(std::string(count_param));
        if (count < 1 || count > 500)
            count = 50;
    } catch (...) {
        count = 50;
    }

#ifdef __linux__
    auto last_out =
        run_command(std::format("last -F -n {} 2>/dev/null", count).c_str());
    if (!last_out.empty()) {
        std::istringstream ss(last_out);
        std::string line;
        while (std::getline(ss, line)) {
            if (line.empty() || line.starts_with("wtmp"))
                continue;
            // Parse 'last' output: USER TTY HOST LOGIN_TIME - LOGOUT_TIME (DURATION)
            std::istringstream ls(line);
            std::string user, tty, source;
            ls >> user >> tty >> source;
            if (user.empty() || user == "wtmp")
                continue;

            // The rest of the line contains timestamps and duration
            std::string rest;
            std::getline(ls, rest);
            auto start = rest.find_first_not_of(" \t");
            if (start != std::string::npos)
                rest = rest.substr(start);

            // Determine if still logged in
            std::string status = "completed";
            if (rest.find("still logged in") != std::string::npos)
                status = "active";
            else if (rest.find("crash") != std::string::npos)
                status = "crash";

            std::string logon_type = "console";
            if (tty.starts_with("pts/"))
                logon_type = "remote";
            else if (user == "reboot")
                logon_type = "system";

            ctx.write_output(std::format("session_history|{}|{}|{}|{}|{}|{}", user, tty, source,
                                         logon_type, status, rest.empty() ? "-" : rest));
        }
    } else {
        ctx.write_output("session_history|error|last command failed");
    }

#elif defined(__APPLE__)
    auto last_out =
        run_command(std::format("last -n {} 2>/dev/null", count).c_str());
    if (!last_out.empty()) {
        std::istringstream ss(last_out);
        std::string line;
        while (std::getline(ss, line)) {
            if (line.empty() || line.starts_with("wtmp"))
                continue;
            std::istringstream ls(line);
            std::string user, tty, source;
            ls >> user >> tty >> source;
            if (user.empty() || user == "wtmp")
                continue;

            std::string rest;
            std::getline(ls, rest);
            auto start = rest.find_first_not_of(" \t");
            if (start != std::string::npos)
                rest = rest.substr(start);

            std::string status = "completed";
            if (rest.find("still logged in") != std::string::npos)
                status = "active";
            else if (rest.find("crash") != std::string::npos)
                status = "crash";

            std::string logon_type = "console";
            if (tty.starts_with("ttys"))
                logon_type = "remote";
            else if (user == "reboot" || user == "shutdown")
                logon_type = "system";

            ctx.write_output(std::format("session_history|{}|{}|{}|{}|{}|{}", user, tty, source,
                                         logon_type, status, rest.empty() ? "-" : rest));
        }
    } else {
        ctx.write_output("session_history|error|last command failed");
    }

#elif defined(_WIN32)
    // Query Windows Security Event Log for logon (4624) and logoff (4634) events
    auto logon_out = run_command(
        std::format(
            "wevtutil qe Security /q:\"*[System[(EventID=4624 or EventID=4634)]]\" /c:{} "
            "/f:text /rd:true 2>&1",
            count)
            .c_str());

    if (!logon_out.empty() && logon_out.find("Access is denied") == std::string::npos) {
        std::istringstream ss(logon_out);
        std::string line;
        std::string current_event_id;
        std::string current_time;
        std::string current_user;
        std::string current_logon_type;
        std::string current_source;
        int account_name_count = 0; // Track which "Account Name" we're on

        while (std::getline(ss, line)) {
            auto start = line.find_first_not_of(" \t");
            if (start == std::string::npos)
                continue;
            auto trimmed = line.substr(start);

            if (trimmed.starts_with("Event[")) {
                // New event — emit previous if we have data
                if (!current_user.empty() && current_user != "-" &&
                    current_user != "SYSTEM" && !current_user.empty() &&
                    current_user.back() != '$') {
                    std::string event_type =
                        (current_event_id == "4624") ? "logon" : "logoff";
                    ctx.write_output(std::format("session_history|{}|{}|{}|{}|{}|{}", current_user,
                                                 event_type, current_logon_type,
                                                 current_source.empty() ? "-" : current_source,
                                                 current_time.empty() ? "-" : current_time,
                                                 current_event_id));
                }
                current_event_id.clear();
                current_time.clear();
                current_user.clear();
                current_logon_type.clear();
                current_source.clear();
                account_name_count = 0;
            }

            if (trimmed.starts_with("Date:")) {
                current_time = trimmed.substr(5);
                auto ts = current_time.find_first_not_of(" \t");
                if (ts != std::string::npos)
                    current_time = current_time.substr(ts);
            } else if (trimmed.starts_with("Event ID:")) {
                current_event_id = trimmed.substr(9);
                auto ts = current_event_id.find_first_not_of(" \t");
                if (ts != std::string::npos)
                    current_event_id = current_event_id.substr(ts);
            } else if (trimmed.starts_with("Account Name:")) {
                account_name_count++;
                // Second Account Name in 4624 events is the actual user
                if (account_name_count == 2 || current_event_id == "4634") {
                    current_user = trimmed.substr(13);
                    auto ts = current_user.find_first_not_of(" \t");
                    if (ts != std::string::npos)
                        current_user = current_user.substr(ts);
                }
            } else if (trimmed.starts_with("Logon Type:")) {
                auto val = trimmed.substr(11);
                auto ts = val.find_first_not_of(" \t");
                if (ts != std::string::npos)
                    val = val.substr(ts);
                // Map logon type numbers to names
                if (val == "2")
                    current_logon_type = "interactive";
                else if (val == "3")
                    current_logon_type = "network";
                else if (val == "4")
                    current_logon_type = "batch";
                else if (val == "5")
                    current_logon_type = "service";
                else if (val == "7")
                    current_logon_type = "unlock";
                else if (val == "8")
                    current_logon_type = "network_cleartext";
                else if (val == "9")
                    current_logon_type = "new_credentials";
                else if (val == "10")
                    current_logon_type = "remote_interactive";
                else if (val == "11")
                    current_logon_type = "cached_interactive";
                else
                    current_logon_type = val;
            } else if (trimmed.starts_with("Source Network Address:")) {
                current_source = trimmed.substr(23);
                auto ts = current_source.find_first_not_of(" \t");
                if (ts != std::string::npos)
                    current_source = current_source.substr(ts);
            }
        }

        // Emit last event
        if (!current_user.empty() && current_user != "-" && current_user != "SYSTEM" &&
            current_user.back() != '$') {
            std::string event_type = (current_event_id == "4624") ? "logon" : "logoff";
            ctx.write_output(std::format("session_history|{}|{}|{}|{}|{}|{}", current_user,
                                         event_type, current_logon_type,
                                         current_source.empty() ? "-" : current_source,
                                         current_time.empty() ? "-" : current_time,
                                         current_event_id));
        }
    } else {
        ctx.write_output("session_history|error|Cannot access Security event log (requires "
                         "elevated privileges)");
    }
#endif
    return 0;
}

} // namespace

class UsersPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "users"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Reports logged-on users, sessions, local accounts, admin group members, "
               "group membership, primary user, and session history";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"logged_on",    "sessions",        "local_users",
                                     "local_admins", "group_members",   "primary_user",
                                     "session_history", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params params) override {
        if (action == "logged_on")
            return do_logged_on(ctx);
        if (action == "sessions")
            return do_sessions(ctx);
        if (action == "local_users")
            return do_local_users(ctx);
        if (action == "local_admins")
            return do_local_admins(ctx);
        if (action == "group_members")
            return do_group_members(ctx, params);
        if (action == "primary_user")
            return do_primary_user(ctx);
        if (action == "session_history")
            return do_session_history(ctx, params);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(UsersPlugin)
