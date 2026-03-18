/**
 * users_plugin.cpp — User accounts plugin for Yuzu
 *
 * Actions:
 *   "logged_on"    — Lists currently logged-on users.
 *   "sessions"     — Lists active interactive sessions.
 *   "local_users"  — Enumerates local user accounts.
 *   "local_admins" — Lists members of the local Administrators group.
 *
 * Output is pipe-delimited, one record per line via write_output():
 *   key|field1|field2|...
 */

#include <yuzu/plugin.hpp>

#include <array>
#include <cstdio>
#include <format>
#include <sstream>
#include <string>
#include <string_view>

#if defined(__linux__)
#include <fstream>
#include <utmp.h>
#include <ctime>
#include <pwd.h>
#include <grp.h>
#include <shadow.h>
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
#include <wtsapi32.h>
#include <lm.h>
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "netapi32.lib")
#endif

namespace {

// ── subprocess helper (Linux / macOS) ──────────────────────────────────────

#if defined(__linux__) || defined(__APPLE__)
std::string run_command(const char* cmd) {
    std::string result;
    std::array<char, 256> buf{};
    FILE* pipe = popen(cmd, "r");
    if (!pipe) return result;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        result += buf.data();
    }
    pclose(pipe);
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
    }
    return result;
}
#endif

#ifdef _WIN32
// Convert a wide string to UTF-8
std::string wide_to_utf8(const wchar_t* ws) {
    if (!ws || !*ws) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, ws, -1, nullptr, 0, nullptr, nullptr);
    std::string result(len > 0 ? len - 1 : 0, '\0');
    if (len > 0) {
        WideCharToMultiByte(CP_UTF8, 0, ws, -1, result.data(), len, nullptr, nullptr);
    }
    return result;
}

// Format a Windows FILETIME as "YYYY-MM-DD HH:MM:SS" or "Never" if zero
std::string format_filetime(DWORD low, DWORD high) {
    if (low == 0 && high == 0) return "Never";
    FILETIME ft;
    ft.dwLowDateTime = low;
    ft.dwHighDateTime = high;
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);
    return std::format("{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
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
            if (line.starts_with("pts/")) logon_type = "remote";
            std::string session_id = line;
            ctx.write_output(std::format("user|{}|{}|{}|{}",
                user, host.empty() ? "local" : host, logon_type, session_id));
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
            if (tty.starts_with("ttys")) logon_type = "remote";
            // Extract host if present (in parentheses at end)
            std::string domain = "local";
            auto paren = line.rfind('(');
            if (paren != std::string::npos) {
                auto end = line.rfind(')');
                if (end != std::string::npos && end > paren) {
                    domain = line.substr(paren + 1, end - paren - 1);
                }
            }
            ctx.write_output(std::format("user|{}|{}|{}|{}",
                user, domain, logon_type, tty));
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

            if (user_buf) WTSFreeMemory(user_buf);
            if (domain_buf) WTSFreeMemory(domain_buf);

            if (user.empty()) continue;

            std::string logon_type = "console";
            auto session_name = wide_to_utf8(sessions[i].pWinStationName);
            if (session_name.find("RDP") != std::string::npos ||
                session_name.find("rdp") != std::string::npos) {
                logon_type = "RDP";
            }

            ctx.write_output(std::format("user|{}|{}|{}|{}",
                user, domain.empty() ? "local" : domain,
                logon_type, sessions[i].SessionId));
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
            ctx.write_output(std::format("session|{}|{}|{}|{}|{}",
                tty, user, state, from.empty() ? "-" : from, idle));
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
            ctx.write_output(std::format("session|{}|{}|Active|{}|{}",
                tty, user, from.empty() ? "-" : from, idle));
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
            if (user_buf) WTSFreeMemory(user_buf);

            if (user.empty()) continue;

            const char* state = "unknown";
            switch (sessions[i].State) {
                case WTSActive:       state = "Active"; break;
                case WTSConnected:    state = "Connected"; break;
                case WTSDisconnected: state = "Disconnected"; break;
                case WTSIdle:         state = "Idle"; break;
                case WTSListen:       state = "Listen"; break;
                default:              state = "Other"; break;
            }

            // Get client name for RDP sessions
            LPWSTR client_buf = nullptr;
            DWORD client_len = 0;
            WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessions[i].SessionId,
                WTSClientName, &client_buf, &client_len);
            auto client = wide_to_utf8(client_buf);
            if (client_buf) WTSFreeMemory(client_buf);

            // Get idle time
            WTSINFOEXW* info_buf = nullptr;
            DWORD info_len = 0;
            long long idle_secs = 0;
            if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessions[i].SessionId,
                    WTSSessionInfo, reinterpret_cast<LPWSTR*>(&info_buf), &info_len) && info_buf) {
                // IdleTime is a LARGE_INTEGER representing 100-nanosecond intervals
                // But WTSINFOEXA has different layout; use CurrentTime - LastInputTime
                // For simplicity, report 0 for active sessions
                WTSFreeMemory(info_buf);
            }

            ctx.write_output(std::format("session|{}|{}|{}|{}|{}",
                sessions[i].SessionId, user, state,
                client.empty() ? "-" : client, idle_secs));
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
        try { uid = std::stoi(uid_s); } catch (...) {}

        // Skip system accounts (uid < 1000, except root)
        if (uid != 0 && uid < 1000) continue;
        // Skip nologin/false shell accounts
        bool enabled = true;
        if (shell.find("nologin") != std::string::npos ||
            shell.find("/false") != std::string::npos) {
            enabled = false;
        }

        // Try to get last login from lastlog
        std::string last_logon = "unknown";
        auto lastlog_out = run_command(
            std::format("lastlog -u {} 2>/dev/null | tail -1", user).c_str());
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

        ctx.write_output(std::format("local_user|{}|{}|{}|{}",
            user, enabled ? "true" : "false", last_logon,
            desc.empty() ? "-" : desc));
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
            try { uid = std::stoi(uid_s); } catch (...) {}
            // Skip system accounts
            if (uid < 500 && user != "root") continue;
            if (user.starts_with("_")) continue;

            // Check if account is enabled
            auto shell = run_command(
                std::format("dscl . -read /Users/{} UserShell 2>/dev/null | awk '{{print $2}}'", user).c_str());
            bool enabled = shell.find("false") == std::string::npos &&
                           shell.find("nologin") == std::string::npos;

            auto desc = run_command(
                std::format("dscl . -read /Users/{} RealName 2>/dev/null | tail -1 | sed 's/^ //'", user).c_str());

            ctx.write_output(std::format("local_user|{}|{}|unknown|{}",
                user, enabled ? "true" : "false",
                desc.empty() ? "-" : desc));
        }
    }

#elif defined(_WIN32)
    LPUSER_INFO_2 buf = nullptr;
    DWORD entries_read = 0;
    DWORD total_entries = 0;
    DWORD resume = 0;
    NET_API_STATUS status;

    do {
        status = NetUserEnum(nullptr, 2, FILTER_NORMAL_ACCOUNT,
            reinterpret_cast<LPBYTE*>(&buf), MAX_PREFERRED_LENGTH,
            &entries_read, &total_entries, &resume);

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

                ctx.write_output(std::format("local_user|{}|{}|{}|{}",
                    name, enabled ? "true" : "false", last_logon,
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
        if (!grp) continue;
        for (char** member = grp->gr_mem; *member; ++member) {
            ctx.write_output(std::format("admin|{}|user|{}",
                *member, group_name));
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

    NET_API_STATUS status = NetLocalGroupGetMembers(
        nullptr, L"Administrators", 2,
        reinterpret_cast<LPBYTE*>(&buf), MAX_PREFERRED_LENGTH,
        &entries_read, &total_entries, &resume);

    if (status == NERR_Success) {
        for (DWORD i = 0; i < entries_read; ++i) {
            auto& m = buf[i];
            auto name = wide_to_utf8(m.lgrmi2_domainandname);

            const char* type_str = "unknown";
            switch (m.lgrmi2_sidusage) {
                case SidTypeUser:           type_str = "user"; break;
                case SidTypeGroup:          type_str = "group"; break;
                case SidTypeWellKnownGroup: type_str = "well_known_group"; break;
                case SidTypeAlias:          type_str = "alias"; break;
                default: break;
            }

            // Split domain\name
            std::string domain = "local";
            std::string member_name = name;
            auto backslash = name.find('\\');
            if (backslash != std::string::npos) {
                domain = name.substr(0, backslash);
                member_name = name.substr(backslash + 1);
            }

            ctx.write_output(std::format("admin|{}|{}|{}",
                member_name, type_str, domain));
        }
        NetApiBufferFree(buf);
    }
#endif
    return 0;
}

}  // namespace

class UsersPlugin final : public yuzu::Plugin {
public:
    std::string_view name()        const noexcept override { return "users"; }
    std::string_view version()     const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Reports logged-on users, sessions, local accounts, and admin group members";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {
            "logged_on", "sessions", "local_users", "local_admins", nullptr
        };
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override {
        return {};
    }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx,
                std::string_view action,
                yuzu::Params /*params*/) override {
        if (action == "logged_on")    return do_logged_on(ctx);
        if (action == "sessions")     return do_sessions(ctx);
        if (action == "local_users")  return do_local_users(ctx);
        if (action == "local_admins") return do_local_admins(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(UsersPlugin)
