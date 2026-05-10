/**
 * windows_updates_plugin.cpp — Windows updates / package updates plugin for Yuzu
 *
 * Actions:
 *   "installed"          — List recently installed updates/packages.
 *   "missing"            — List available updates/packages that can be installed.
 *   "pending_reboot"     — Detect if the endpoint requires a reboot after updates.
 *   "patch_connectivity" — Test connectivity to patch/update servers (DNS, TCP, HTTPS).
 *
 * Output is pipe-delimited, one record per line via write_output():
 *   update|kb_id|description|date
 *   package|name|version
 *   available|title|severity
 *   source_name|true/false|detail          (per-check rows)
 *   reboot_required|true/false|reasons    (summary row)
 *   target|url|dns_ok|bool|dns_ms|N|...   (connectivity results)
 */

#include <yuzu/plugin.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
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
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <arpa/inet.h>
#endif

namespace {

// ── subprocess helpers ─────────────────────────────────────────────────────

#if defined(__linux__) || defined(__APPLE__)
std::string run_command(const char* cmd) {
    std::string result;
    std::array<char, 256> buf{};
    FILE* pipe = popen(cmd, "r");
    if (!pipe)
        return result;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        result += buf.data();
    }
    pclose(pipe);
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
        result.pop_back();
    return result;
}
#endif

std::vector<std::string> run_command_lines(const char* cmd) {
    std::vector<std::string> lines;
    std::array<char, 512> buf{};
#ifdef _WIN32
    FILE* pipe = _popen(cmd, "r");
#else
    FILE* pipe = popen(cmd, "r");
#endif
    if (!pipe)
        return lines;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        std::string line(buf.data());
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
            line.pop_back();
        if (!line.empty())
            lines.push_back(std::move(line));
    }
#ifdef _WIN32
    _pclose(pipe);
#else
    pclose(pipe);
#endif
    return lines;
}

// ── installed action ───────────────────────────────────────────────────────

int do_installed(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    auto lines = run_command_lines(
        "powershell -NoProfile -Command \""
        "Get-HotFix | Select-Object HotFixID,Description,InstalledOn "
        "| Sort-Object InstalledOn -Descending "
        "| Select-Object -First 50 "
        "| ForEach-Object { $_.HotFixID + '|' + $_.Description + '|' + $_.InstalledOn }"
        "\"");
    if (lines.empty()) {
        ctx.write_output("update|none|No updates found|-");
        return 0;
    }
    for (const auto& line : lines) {
        ctx.write_output(std::format("update|{}", line));
    }

#elif defined(__linux__)
    // Try rpm first, then apt
    auto lines = run_command_lines("rpm -qa --last 2>/dev/null | head -50");
    if (!lines.empty()) {
        for (const auto& line : lines) {
            // Format: "package-name  date"
            auto sep = line.find("  ");
            if (sep != std::string::npos) {
                ctx.write_output(
                    std::format("package|{}|{}", line.substr(0, sep), line.substr(sep + 2)));
            } else {
                ctx.write_output(std::format("package|{}|-", line));
            }
        }
    } else {
        lines = run_command_lines("apt list --installed 2>/dev/null | head -50");
        if (lines.empty()) {
            ctx.write_output("package|none|No packages found");
            return 0;
        }
        for (const auto& line : lines) {
            // Skip the "Listing..." header
            if (line.starts_with("Listing"))
                continue;
            // Format: "name/repo version arch [status]"
            auto slash = line.find('/');
            auto space = line.find(' ');
            if (slash != std::string::npos && space != std::string::npos) {
                auto name = line.substr(0, slash);
                auto version = line.substr(space + 1);
                auto ver_end = version.find(' ');
                if (ver_end != std::string::npos)
                    version = version.substr(0, ver_end);
                ctx.write_output(std::format("package|{}|{}", name, version));
            } else {
                ctx.write_output(std::format("package|{}|-", line));
            }
        }
    }

#elif defined(__APPLE__)
    auto lines = run_command_lines("system_profiler SPInstallHistoryDataType 2>/dev/null "
                                   "| grep -E '^ {4}\\w|Install Date:' | head -100");
    if (lines.empty()) {
        ctx.write_output("update|none|No update history found");
        return 0;
    }
    std::string current_name;
    for (const auto& line : lines) {
        auto trimmed = line;
        auto start = trimmed.find_first_not_of(" \t");
        if (start != std::string::npos)
            trimmed = trimmed.substr(start);

        if (trimmed.starts_with("Install Date:")) {
            auto date = trimmed.substr(14);
            auto ds = date.find_first_not_of(" ");
            if (ds != std::string::npos)
                date = date.substr(ds);
            if (!current_name.empty()) {
                ctx.write_output(std::format("update|{}|{}", current_name, date));
            }
            current_name.clear();
        } else if (!trimmed.empty() && trimmed.back() == ':') {
            current_name = trimmed.substr(0, trimmed.size() - 1);
        }
    }
    if (!current_name.empty()) {
        ctx.write_output(std::format("update|{}|-", current_name));
    }

#else
    ctx.write_output("error|platform not supported");
#endif
    return 0;
}

// ── missing action ─────────────────────────────────────────────────────────

int do_missing(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    auto lines = run_command_lines(
        "powershell -NoProfile -Command \""
        "$s = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher(); "
        "$r = $s.Search('IsInstalled=0'); "
        "foreach ($u in $r.Updates) { $u.Title + '|' + $u.MsrcSeverity }"
        "\"");
    if (lines.empty()) {
        ctx.write_output("available|none|No pending updates");
        return 0;
    }
    for (const auto& line : lines) {
        ctx.write_output(std::format("available|{}", line));
    }

#elif defined(__linux__)
    auto lines = run_command_lines("apt list --upgradable 2>/dev/null");
    bool found = false;
    if (!lines.empty()) {
        for (const auto& line : lines) {
            if (line.starts_with("Listing"))
                continue;
            // Format: "name/repo version arch [upgradable from: old_ver]"
            auto slash = line.find('/');
            auto space = line.find(' ');
            if (slash != std::string::npos && space != std::string::npos) {
                auto name = line.substr(0, slash);
                auto rest = line.substr(space + 1);
                auto ver_end = rest.find(' ');
                auto version = (ver_end != std::string::npos) ? rest.substr(0, ver_end) : rest;
                ctx.write_output(std::format("available|{}|{}", name, version));
                found = true;
            }
        }
    }
    if (!found) {
        lines = run_command_lines("yum check-update 2>/dev/null | grep -v '^$'");
        for (const auto& line : lines) {
            if (line.starts_with("Loaded") || line.starts_with("Loading"))
                continue;
            ctx.write_output(std::format("available|{}", line));
            found = true;
        }
    }
    if (!found) {
        ctx.write_output("available|none|System is up to date");
    }

#elif defined(__APPLE__)
    auto lines = run_command_lines("softwareupdate -l 2>/dev/null");
    if (lines.empty()) {
        ctx.write_output("available|none|No updates available");
        return 0;
    }
    for (const auto& line : lines) {
        auto trimmed = line;
        auto start = trimmed.find_first_not_of(" \t*");
        if (start != std::string::npos)
            trimmed = trimmed.substr(start);
        if (trimmed.empty() || trimmed.starts_with("Software Update"))
            continue;
        if (trimmed.starts_with("Finding") || trimmed.starts_with("No new"))
            continue;
        ctx.write_output(std::format("available|{}", trimmed));
    }

#else
    ctx.write_output("error|platform not supported");
#endif
    return 0;
}

// ── pending reboot action ─────────────────────────────────────────────────

int do_pending_reboot(yuzu::CommandContext& ctx) {
    std::vector<std::string> reasons;

#ifdef _WIN32
    // Check 1: Windows Update RebootRequired registry key
    {
        HKEY hkey = nullptr;
        bool found = (RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            R"(SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired)",
            0, KEY_READ, &hkey) == ERROR_SUCCESS);
        if (found) {
            RegCloseKey(hkey);
            reasons.push_back("windows_update_reboot");
        }
        ctx.write_output(std::format("windows_update_reboot|{}|{}",
                                     found ? "true" : "false",
                                     found ? "Registry key exists" : ""));
    }

    // Check 2: Component Based Servicing RebootPending
    {
        HKEY hkey = nullptr;
        bool found = (RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            R"(SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending)",
            0, KEY_READ, &hkey) == ERROR_SUCCESS);
        if (found) {
            RegCloseKey(hkey);
            reasons.push_back("cbs_reboot");
        }
        ctx.write_output(std::format("cbs_reboot|{}|{}",
                                     found ? "true" : "false",
                                     found ? "Registry key exists" : ""));
    }

    // Check 3: Pending file rename operations
    {
        HKEY hkey = nullptr;
        bool found = false;
        if (RegOpenKeyExA(
                HKEY_LOCAL_MACHINE,
                R"(SYSTEM\CurrentControlSet\Control\Session Manager)",
                0, KEY_READ, &hkey) == ERROR_SUCCESS) {
            DWORD size = 0;
            if (RegQueryValueExA(hkey, "PendingFileRenameOperations", nullptr,
                                 nullptr, nullptr, &size) == ERROR_SUCCESS && size > 0) {
                found = true;
                reasons.push_back("pending_file_rename");
            }
            RegCloseKey(hkey);
        }
        ctx.write_output(std::format("pending_file_rename|{}|{}",
                                     found ? "true" : "false",
                                     found ? "Non-empty value" : ""));
    }

#elif defined(__linux__)
    // Check 1: /var/run/reboot-required (Debian/Ubuntu)
    {
        std::error_code ec;
        bool found = std::filesystem::exists("/var/run/reboot-required", ec);
        if (found)
            reasons.push_back("reboot_required_file");
        ctx.write_output(std::format("reboot_required_file|{}|{}",
                                     found ? "true" : "false",
                                     found ? "/var/run/reboot-required exists" : ""));
    }

    // Check 2: Running kernel vs installed kernel mismatch
    {
        bool found = false;
        auto running = run_command("uname -r");
        // Use ls -t (sort by mtime) instead of sort -V for portability (busybox/Alpine)
        auto latest = run_command("ls -t /boot/vmlinuz-* 2>/dev/null | head -1");
        if (!latest.empty()) {
            // Strip "vmlinuz-" prefix and path
            auto pos = latest.rfind("vmlinuz-");
            if (pos != std::string::npos) {
                auto installed = latest.substr(pos + 8);
                if (!running.empty() && !installed.empty() && running != installed) {
                    found = true;
                    reasons.push_back("kernel_mismatch");
                }
                ctx.write_output(std::format("kernel_mismatch|{}|running={} installed={}",
                                             found ? "true" : "false", running, installed));
            }
        }
        if (latest.empty()) {
            // Fallback: needs-restarting (RHEL/CentOS/Fedora)
            auto output = run_command("needs-restarting -r 2>&1");
            bool needs = output.find("Reboot is required") != std::string::npos;
            if (needs) {
                found = true;
                reasons.push_back("needs_restarting");
            }
            ctx.write_output(std::format("needs_restarting|{}|{}",
                                         needs ? "true" : "false",
                                         needs ? "needs-restarting reports reboot required" : ""));
        }
    }

#elif defined(__APPLE__)
    // Check: softwareupdate -l output containing "restart"
    // NOTE: softwareupdate -l contacts Apple servers and may take 30-120s.
    // run_command() uses popen() with no timeout — may block on headless/offline Macs.
    // TODO: Consider timeout wrapper or checking /Library/Updates/ for cached state.
    {
        bool found = false;
        auto lines = run_command_lines("softwareupdate -l 2>/dev/null");
        for (const auto& line : lines) {
            // Case-insensitive search for "restart"
            std::string lower = line;
            for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (lower.find("restart") != std::string::npos) {
                found = true;
                reasons.push_back("softwareupdate_restart");
                break;
            }
        }
        ctx.write_output(std::format("softwareupdate_restart|{}|{}",
                                     found ? "true" : "false",
                                     found ? "Update requires restart" : ""));
    }

#else
    ctx.write_output("error|false|platform not supported");
    return 0;
#endif

    // Summary line
    bool any = !reasons.empty();
    std::string reason_str;
    for (size_t i = 0; i < reasons.size(); ++i) {
        if (i > 0) reason_str += ',';
        reason_str += reasons[i];
    }
    ctx.write_output(std::format("reboot_required|{}|{}",
                                 any ? "true" : "false", reason_str));
    return 0;
}

// ── connectivity helpers ──────────────────────────────────────────────────

struct ConnTarget {
    std::string url;
    std::string host;
    int port{443};
    std::string path;
    bool use_tls{true};
};

ConnTarget parse_url(const std::string& url) {
    ConnTarget t;
    t.url = url;
    std::string_view sv = url;
    if (sv.starts_with("https://")) {
        sv.remove_prefix(8); t.use_tls = true; t.port = 443;
    } else if (sv.starts_with("http://")) {
        sv.remove_prefix(7); t.use_tls = false; t.port = 80;
    }
    auto slash = sv.find('/');
    auto host_part = sv.substr(0, slash);
    t.path = (slash != std::string_view::npos) ? std::string(sv.substr(slash)) : "/";
    auto colon = host_part.find(':');
    if (colon != std::string_view::npos) {
        t.host = std::string(host_part.substr(0, colon));
        try { t.port = std::stoi(std::string(host_part.substr(colon + 1))); } catch (...) {}
    } else {
        t.host = std::string(host_part);
    }
    return t;
}

struct DnsResult {
    bool ok{false};
    std::string ip;
    int64_t ms{-1};
    std::string error;
};

DnsResult test_dns(const std::string& host) {
    DnsResult r;
    auto start = std::chrono::steady_clock::now();
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int rc = getaddrinfo(host.c_str(), nullptr, &hints, &res);
    auto elapsed = std::chrono::steady_clock::now() - start;
    r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    if (rc != 0) {
        r.error = "name resolution failed";
        return r;
    }
    r.ok = true;
    char buf[64]{};
    if (res->ai_family == AF_INET) {
        inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr, buf, sizeof(buf));
    } else if (res->ai_family == AF_INET6) {
        inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6*>(res->ai_addr)->sin6_addr, buf, sizeof(buf));
    }
    r.ip = buf;
    freeaddrinfo(res);
    return r;
}

struct TcpResult {
    bool ok{false};
    int64_t ms{-1};
    std::string error;
};

TcpResult test_tcp(const std::string& host, int port, int timeout_s) {
    TcpResult r;
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    auto port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0) {
        r.error = "dns failed";
        return r;
    }

    auto start = std::chrono::steady_clock::now();

#ifdef _WIN32
    SOCKET sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == INVALID_SOCKET) { freeaddrinfo(res); r.error = "socket failed"; return r; }
    unsigned long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
    connect(sock, res->ai_addr, static_cast<int>(res->ai_addrlen));
    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(sock, &writefds);
    timeval tv;
    tv.tv_sec = timeout_s;
    tv.tv_usec = 0;
    int sel = select(0, nullptr, &writefds, nullptr, &tv);
    auto elapsed = std::chrono::steady_clock::now() - start;
    r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    if (sel > 0) {
        int err = 0;
        int err_len = sizeof(err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &err_len);
        r.ok = (err == 0);
        if (!r.ok) r.error = "connection refused";
    } else {
        r.error = (sel == 0) ? "timeout" : "select failed";
    }
    closesocket(sock);
#else
    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) { freeaddrinfo(res); r.error = "socket failed"; return r; }
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    connect(sock, res->ai_addr, res->ai_addrlen);
    struct pollfd pfd{sock, POLLOUT, 0};
    int sel = poll(&pfd, 1, timeout_s * 1000);
    auto elapsed = std::chrono::steady_clock::now() - start;
    r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    if (sel > 0) {
        int err = 0;
        socklen_t err_len = sizeof(err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &err_len);
        r.ok = (err == 0);
        if (!r.ok) r.error = "connection refused";
    } else {
        r.error = (sel == 0) ? "timeout" : "poll failed";
    }
    close(sock);
#endif

    freeaddrinfo(res);
    return r;
}

std::vector<std::string> get_default_patch_targets() {
    std::vector<std::string> targets;
#ifdef _WIN32
    targets.push_back("https://windowsupdate.microsoft.com");
    targets.push_back("https://update.microsoft.com");
    targets.push_back("https://download.windowsupdate.com");
    // Check for WSUS URL in registry
    HKEY hkey = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            R"(SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate)",
            0, KEY_READ, &hkey) == ERROR_SUCCESS) {
        char buf[512]{};
        DWORD buf_size = sizeof(buf);
        if (RegQueryValueExA(hkey, "WUServer", nullptr, nullptr,
                              reinterpret_cast<LPBYTE>(buf), &buf_size) == ERROR_SUCCESS) {
            std::string wsus(buf);
            if (!wsus.empty()) targets.push_back(wsus);
        }
        RegCloseKey(hkey);
    }
#elif defined(__linux__)
    // Try to read apt sources.list for repository URLs
    auto parse_apt_sources = [&](const std::string& path) {
        std::ifstream f(path);
        if (!f) return;
        std::string line;
        while (std::getline(f, line)) {
            if (line.empty() || line[0] == '#') continue;
            // deb http://... or deb-src http://...
            auto http_pos = line.find("http");
            if (http_pos != std::string::npos) {
                auto end = line.find(' ', http_pos);
                auto url = line.substr(http_pos, end == std::string::npos ? std::string::npos : end - http_pos);
                // Extract just the host URL (drop the path for connectivity test)
                auto parsed = parse_url(url);
                auto base = std::string(parsed.use_tls ? "https://" : "http://") + parsed.host;
                if (std::find(targets.begin(), targets.end(), base) == targets.end())
                    targets.push_back(base);
            }
        }
    };
    parse_apt_sources("/etc/apt/sources.list");
    // Check sources.list.d
    namespace fs = std::filesystem;
    std::error_code ec;
    for (auto& entry : fs::directory_iterator("/etc/apt/sources.list.d", ec)) {
        if (entry.path().extension() == ".list")
            parse_apt_sources(entry.path().string());
    }
    if (targets.empty()) {
        targets.push_back("https://archive.ubuntu.com");
        targets.push_back("https://security.ubuntu.com");
    }
#elif defined(__APPLE__)
    targets.push_back("https://swscan.apple.com");
    targets.push_back("https://swdist.apple.com");
#endif
    return targets;
}

int do_patch_connectivity(yuzu::CommandContext& ctx, yuzu::Params params) {
    auto targets_str = params.get("targets");
    int timeout_s = 10;
    auto timeout_str = params.get("timeout_seconds", "10");
    try { timeout_s = std::stoi(std::string{timeout_str}); } catch (...) {}
    if (timeout_s < 1) timeout_s = 1;
    if (timeout_s > 60) timeout_s = 60;

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    std::vector<std::string> targets;
    if (targets_str.empty()) {
        targets = get_default_patch_targets();
    } else {
        // Split on comma
        std::string s{targets_str};
        size_t pos = 0;
        while (pos < s.size()) {
            auto comma = s.find(',', pos);
            auto token = s.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos);
            // Trim whitespace
            auto start = token.find_first_not_of(" \t");
            if (start != std::string::npos) {
                auto end = token.find_last_not_of(" \t");
                targets.push_back(token.substr(start, end - start + 1));
            }
            if (comma == std::string::npos) break;
            pos = comma + 1;
        }
    }

    int reachable = 0;
    int failed = 0;

    for (const auto& url : targets) {
        auto target = parse_url(url);

        // DNS test
        auto dns = test_dns(target.host);
        ctx.write_output(std::format("target|{}|dns_ok|{}|dns_ms|{}|ip|{}",
            url, dns.ok ? "true" : "false", dns.ms,
            dns.ok ? dns.ip : dns.error));

        if (!dns.ok) { ++failed; continue; }

        // TCP test
        auto tcp = test_tcp(target.host, target.port, timeout_s);
        ctx.write_output(std::format("target|{}|tcp_ok|{}|tcp_ms|{}",
            url, tcp.ok ? "true" : "false", tcp.ms));

        if (!tcp.ok) {
            ctx.write_output(std::format("target|{}|tcp_error|{}", url, tcp.error));
            ++failed;
            continue;
        }

        ++reachable;
    }

    ctx.write_output(std::format("summary|targets_tested|{}|targets_reachable|{}|targets_failed|{}",
        targets.size(), reachable, failed));

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}

} // namespace

class WindowsUpdatesPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "windows_updates"; }
    std::string_view version() const noexcept override { return "1.1.0"; }
    std::string_view description() const noexcept override {
        return "Updates/packages: installed, available, pending-reboot, patch connectivity";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"installed", "missing", "pending_reboot",
                                     "patch_connectivity", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params params) override {
        if (action == "installed")
            return do_installed(ctx);
        if (action == "missing")
            return do_missing(ctx);
        if (action == "pending_reboot")
            return do_pending_reboot(ctx);
        if (action == "patch_connectivity")
            return do_patch_connectivity(ctx, params);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(WindowsUpdatesPlugin)
