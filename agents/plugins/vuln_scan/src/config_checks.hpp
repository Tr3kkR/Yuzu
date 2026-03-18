#pragma once

#include <array>
#include <cstdio>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

#if defined(__linux__) || defined(__APPLE__)
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace yuzu::vuln {

struct ConfigCheckResult {
    std::string_view severity;
    std::string_view title;
    std::string detail;
    bool passed;
};

// ── Subprocess helper (Linux / macOS) ──────────────────────────────────────

#if defined(__linux__) || defined(__APPLE__)
namespace detail {

inline std::string run_cmd(const char* cmd) {
    std::string result;
    std::array<char, 256> buf{};
    FILE* pipe = popen(cmd, "r");
    if (!pipe)
        return result;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        result += buf.data();
    }
    pclose(pipe);
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
    }
    return result;
}

inline bool file_contains(const char* path, std::string_view needle) {
    std::ifstream f(path);
    if (!f.is_open())
        return false;
    std::string line;
    while (std::getline(f, line)) {
        // Skip comment lines
        auto pos = line.find_first_not_of(" \t");
        if (pos != std::string::npos && line[pos] == '#')
            continue;
        if (line.find(needle) != std::string::npos)
            return true;
    }
    return false;
}

inline std::string read_proc_value(const char* path) {
    std::ifstream f(path);
    if (!f.is_open())
        return {};
    std::string val;
    std::getline(f, val);
    return val;
}

} // namespace detail
#endif

// ── Windows config checks ──────────────────────────────────────────────────

#ifdef _WIN32
namespace detail {

inline std::string read_registry_string(HKEY root, const char* subkey, const char* value_name) {
    HKEY hkey{};
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hkey) != ERROR_SUCCESS)
        return {};
    char buf[512]{};
    DWORD size = sizeof(buf);
    DWORD type = 0;
    std::string result;
    if (RegQueryValueExA(hkey, value_name, nullptr, &type, reinterpret_cast<LPBYTE>(buf), &size) ==
        ERROR_SUCCESS) {
        if ((type == REG_SZ || type == REG_EXPAND_SZ) && size > 0) {
            result.assign(buf, size - 1);
        }
    }
    RegCloseKey(hkey);
    return result;
}

inline DWORD read_registry_dword(HKEY root, const char* subkey, const char* value_name,
                                 DWORD default_val) {
    HKEY hkey{};
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hkey) != ERROR_SUCCESS)
        return default_val;
    DWORD val = 0;
    DWORD size = sizeof(val);
    DWORD type = 0;
    DWORD result = default_val;
    if (RegQueryValueExA(hkey, value_name, nullptr, &type, reinterpret_cast<LPBYTE>(&val), &size) ==
        ERROR_SUCCESS) {
        if (type == REG_DWORD)
            result = val;
    }
    RegCloseKey(hkey);
    return result;
}

} // namespace detail

inline std::vector<ConfigCheckResult> run_windows_checks() {
    std::vector<ConfigCheckResult> results;

    // UAC enabled
    {
        auto val = detail::read_registry_dword(
            HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "EnableLUA", 0);
        results.push_back(
            {val == 1 ? "INFO" : "HIGH", "UAC (User Account Control)",
             val == 1 ? "Enabled" : "Disabled - system is vulnerable to privilege escalation",
             val == 1});
    }

    // SMBv1 disabled
    {
        auto val = detail::read_registry_dword(
            HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
            "SMB1", 1); // default is enabled if key missing
        results.push_back(
            {val == 0 ? "INFO" : "CRITICAL", "SMBv1 Protocol",
             val == 0 ? "Disabled" : "Enabled - vulnerable to EternalBlue/WannaCry (MS17-010)",
             val == 0});
    }

    // Auto-logon disabled
    {
        auto val = detail::read_registry_string(
            HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            "AutoAdminLogon");
        bool disabled = val.empty() || val == "0";
        results.push_back(
            {disabled ? "INFO" : "HIGH", "Auto-Logon",
             disabled ? "Disabled" : "Enabled - credentials stored in plaintext in registry",
             disabled});
    }

    // RDP Network Level Authentication
    {
        auto val = detail::read_registry_dword(
            HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
            "UserAuthentication", 0);
        auto rdp_enabled = detail::read_registry_dword(
            HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
            "fDenyTSConnections", 1);
        if (rdp_enabled == 0) { // RDP is enabled
            results.push_back(
                {val == 1 ? "INFO" : "HIGH", "RDP Network Level Authentication",
                 val == 1 ? "Enabled" : "Disabled - RDP is exposed without pre-authentication",
                 val == 1});
        }
    }

    // Windows Defender real-time protection
    {
        auto val = detail::read_registry_dword(
            HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
            "DisableRealtimeMonitoring", 0);
        results.push_back({val == 0 ? "INFO" : "HIGH", "Windows Defender Real-Time Protection",
                           val == 0 ? "Enabled" : "Disabled - no real-time malware protection",
                           val == 0});
    }

    // Firewall profiles
    {
        static const char* kProfiles[] = {"DomainProfile", "StandardProfile", "PublicProfile"};
        static const char* kNames[] = {"Domain", "Private", "Public"};
        for (int i = 0; i < 3; ++i) {
            auto subkey = std::string("SYSTEM\\CurrentControlSet\\Services\\"
                                      "SharedAccess\\Parameters\\FirewallPolicy\\") +
                          kProfiles[i];
            auto val = detail::read_registry_dword(HKEY_LOCAL_MACHINE, subkey.c_str(),
                                                   "EnableFirewall", 0);
            results.push_back(
                {val == 1 ? "INFO" : "HIGH", "Windows Firewall",
                 std::string(kNames[i]) + " profile: " + (val == 1 ? "Enabled" : "Disabled"),
                 val == 1});
        }
    }

    return results;
}
#endif

// ── Linux config checks ───────────────────────────────────────────────────

#ifdef __linux__
inline std::vector<ConfigCheckResult> run_linux_checks() {
    std::vector<ConfigCheckResult> results;

    // SSH: PermitRootLogin
    {
        bool root_login = detail::file_contains("/etc/ssh/sshd_config", "PermitRootLogin yes");
        bool no_root = detail::file_contains("/etc/ssh/sshd_config", "PermitRootLogin no");
        // If explicit "no" found, it's secure. If "yes" found, it's insecure.
        // If neither, default depends on distro but flag as warning.
        if (no_root) {
            results.push_back({"INFO", "SSH Root Login", "PermitRootLogin is set to no", true});
        } else if (root_login) {
            results.push_back(
                {"HIGH", "SSH Root Login",
                 "PermitRootLogin is set to yes - direct root access via SSH is enabled", false});
        } else {
            results.push_back(
                {"MEDIUM", "SSH Root Login",
                 "PermitRootLogin not explicitly set - may default to prohibit-password", false});
        }
    }

    // SSH: PasswordAuthentication
    {
        bool pw_yes = detail::file_contains("/etc/ssh/sshd_config", "PasswordAuthentication yes");
        bool pw_no = detail::file_contains("/etc/ssh/sshd_config", "PasswordAuthentication no");
        if (pw_no) {
            results.push_back(
                {"INFO", "SSH Password Authentication", "Disabled - key-based auth only", true});
        } else if (pw_yes) {
            results.push_back({"MEDIUM", "SSH Password Authentication",
                               "Enabled - consider using key-based authentication only", false});
        }
    }

    // ASLR
    {
        auto val = detail::read_proc_value("/proc/sys/kernel/randomize_va_space");
        bool ok = !val.empty() && val[0] == '2';
        results.push_back({ok ? "INFO" : "HIGH", "ASLR (Address Space Layout Randomization)",
                           ok ? "Full randomization enabled (value=2)"
                              : "Not fully enabled (value=" + val + ") - should be 2",
                           ok});
    }

    // Core dumps restricted
    {
        auto val = detail::read_proc_value("/proc/sys/fs/suid_dumpable");
        bool ok = !val.empty() && val[0] == '0';
        results.push_back(
            {ok ? "INFO" : "MEDIUM", "SUID Core Dumps",
             ok ? "Restricted (suid_dumpable=0)"
                : "Not restricted (suid_dumpable=" + val + ") - SUID programs may dump core",
             ok});
    }

    // /tmp mounted noexec
    {
        std::ifstream mounts("/proc/mounts");
        bool found_tmp = false;
        bool has_noexec = false;
        if (mounts.is_open()) {
            std::string line;
            while (std::getline(mounts, line)) {
                if (line.find(" /tmp ") != std::string::npos) {
                    found_tmp = true;
                    has_noexec = line.find("noexec") != std::string::npos;
                    break;
                }
            }
        }
        if (found_tmp) {
            results.push_back(
                {has_noexec ? "INFO" : "MEDIUM", "/tmp noexec",
                 has_noexec ? "/tmp is mounted with noexec"
                            : "/tmp is not mounted with noexec - executables can run from /tmp",
                 has_noexec});
        }
    }

    // Firewall (iptables/nftables)
    {
        auto ipt = detail::run_cmd("iptables -L -n 2>/dev/null | wc -l");
        auto nft = detail::run_cmd("nft list ruleset 2>/dev/null | wc -l");
        auto ufw = detail::run_cmd("ufw status 2>/dev/null | head -1");

        bool has_rules = false;
        std::string detail_str;

        if (ufw.find("active") != std::string::npos) {
            has_rules = true;
            detail_str = "UFW firewall is active";
        } else {
            int ipt_lines = 0, nft_lines = 0;
            try {
                ipt_lines = std::stoi(ipt);
            } catch (...) {}
            try {
                nft_lines = std::stoi(nft);
            } catch (...) {}
            // iptables -L with no rules still shows ~8 lines (headers)
            has_rules = ipt_lines > 10 || nft_lines > 0;
            if (has_rules) {
                detail_str = "Firewall rules detected";
            } else {
                detail_str = "No firewall rules detected - host may be unprotected";
            }
        }

        results.push_back({has_rules ? "INFO" : "HIGH", "Firewall", detail_str, has_rules});
    }

    // World-writable directories in PATH
    // Uses stat() directly instead of shell commands to avoid injection.
    {
        const char* path_env = std::getenv("PATH");
        std::vector<std::string> writable;
        if (path_env) {
            std::istringstream ss(path_env);
            std::string dir;
            while (std::getline(ss, dir, ':')) {
                if (dir.empty())
                    continue;
                struct stat st{};
                if (stat(dir.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
                    // Check if world-writable (other-write bit)
                    if (st.st_mode & S_IWOTH) {
                        writable.push_back(dir);
                    }
                }
            }
        }
        if (!writable.empty()) {
            std::string dirs;
            for (const auto& d : writable) {
                if (!dirs.empty())
                    dirs += ", ";
                dirs += d;
            }
            results.push_back({"HIGH", "World-Writable PATH Directories",
                               "World-writable directories found in PATH: " + dirs, false});
        }
    }

    return results;
}
#endif

// ── macOS config checks ───────────────────────────────────────────────────

#ifdef __APPLE__
inline std::vector<ConfigCheckResult> run_macos_checks() {
    std::vector<ConfigCheckResult> results;

    // Gatekeeper
    {
        auto out = detail::run_cmd("spctl --status 2>&1");
        bool enabled = out.find("enabled") != std::string::npos;
        results.push_back({enabled ? "INFO" : "HIGH", "Gatekeeper",
                           enabled ? "Enabled - only verified apps can run"
                                   : "Disabled - unsigned apps can run without restriction",
                           enabled});
    }

    // FileVault
    {
        auto out = detail::run_cmd("fdesetup status 2>&1");
        bool on = out.find("On") != std::string::npos;
        results.push_back({on ? "INFO" : "HIGH", "FileVault Disk Encryption",
                           on ? "Enabled" : "Disabled - disk is not encrypted", on});
    }

    // SIP (System Integrity Protection)
    {
        auto out = detail::run_cmd("csrutil status 2>&1");
        bool enabled = out.find("enabled") != std::string::npos;
        results.push_back({enabled ? "INFO" : "CRITICAL", "System Integrity Protection (SIP)",
                           enabled ? "Enabled" : "Disabled - system files are unprotected",
                           enabled});
    }

    // Firewall
    {
        auto out = detail::run_cmd(
            "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>&1");
        bool enabled = out.find("enabled") != std::string::npos;
        results.push_back({enabled ? "INFO" : "MEDIUM", "Application Firewall",
                           enabled ? "Enabled" : "Disabled", enabled});
    }

    // Remote Login (SSH)
    {
        auto out = detail::run_cmd("systemsetup -getremotelogin 2>&1");
        bool off = out.find("Off") != std::string::npos;
        results.push_back({off ? "INFO" : "MEDIUM", "Remote Login (SSH)",
                           off ? "Disabled" : "Enabled - SSH access is open", off});
    }

    // Automatic updates
    {
        auto out = detail::run_cmd("defaults read /Library/Preferences/com.apple.SoftwareUpdate "
                                   "AutomaticCheckEnabled 2>&1");
        bool enabled = out.find("1") != std::string::npos;
        results.push_back({enabled ? "INFO" : "MEDIUM", "Automatic Software Updates",
                           enabled ? "Enabled" : "Disabled - system may miss security patches",
                           enabled});
    }

    return results;
}
#endif

// ── Cross-platform checks ─────────────────────────────────────────────────

inline std::vector<ConfigCheckResult> run_cross_platform_checks() {
    std::vector<ConfigCheckResult> results;

#if defined(__linux__) || defined(__APPLE__)
    // Check for common risky ports listening on all interfaces
    auto listeners = detail::run_cmd("ss -tlnH 2>/dev/null || netstat -tlnp 2>/dev/null");
    if (!listeners.empty()) {
        static constexpr struct {
            int port;
            const char* name;
            const char* risk;
        } kRiskyPorts[] = {
            {21, "FTP", "Unencrypted file transfer"},
            {23, "Telnet", "Unencrypted remote access"},
            {445, "SMB", "File sharing - common attack vector"},
            {3389, "RDP", "Remote desktop - frequent brute force target"},
            {5900, "VNC", "Remote desktop - often unencrypted"},
        };

        for (const auto& rp : kRiskyPorts) {
            auto port_str = ":" + std::to_string(rp.port) + " ";
            auto any_bind = "0.0.0.0:" + std::to_string(rp.port);
            auto any6_bind = ":::" + std::to_string(rp.port);
            if (listeners.find(any_bind) != std::string::npos ||
                listeners.find(any6_bind) != std::string::npos) {
                results.push_back({"HIGH", "Open Port",
                                   std::string(rp.name) + " (port " + std::to_string(rp.port) +
                                       ") listening on all interfaces - " + rp.risk,
                                   false});
            }
        }
    }
#endif

#ifdef _WIN32
    // On Windows, check common risky ports via netstat
    // (simplified — real implementation would parse netstat output)
    // For now, skipped since Windows firewall check covers this area
#endif

    return results;
}

// ── Run all platform checks ───────────────────────────────────────────────

inline std::vector<ConfigCheckResult> run_all_config_checks() {
    std::vector<ConfigCheckResult> results;

#ifdef _WIN32
    auto win = run_windows_checks();
    results.insert(results.end(), win.begin(), win.end());
#elif defined(__linux__)
    auto lin = run_linux_checks();
    results.insert(results.end(), lin.begin(), lin.end());
#elif defined(__APPLE__)
    auto mac = run_macos_checks();
    results.insert(results.end(), mac.begin(), mac.end());
#endif

    auto cross = run_cross_platform_checks();
    results.insert(results.end(), cross.begin(), cross.end());

    return results;
}

} // namespace yuzu::vuln
