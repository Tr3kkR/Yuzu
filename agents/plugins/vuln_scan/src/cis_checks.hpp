#pragma once
#include "config_checks.hpp"
#include <string>
#include <vector>

namespace yuzu::vuln {

struct CisCheckResult {
    std::string check_id;    // e.g. "CIS-LIN-1.4.1"
    std::string level;       // "1" or "2"
    std::string title;
    std::string status;      // "PASS" or "FAIL"
    std::string expected;
    std::string actual;
    std::string severity;    // CRITICAL / HIGH / MEDIUM / LOW / INFO
    std::string remediation;
};

// ── Windows CIS Level 1 ────────────────────────────────────────────────────

#ifdef _WIN32

inline std::vector<CisCheckResult> run_windows_cis_l1() {
    std::vector<CisCheckResult> r;

    // CIS WIN 1.1 — UAC enabled
    {
        auto val = detail::read_registry_dword(
            HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "EnableLUA", 0);
        bool pass = val == 1;
        r.push_back({"CIS-WIN-1.1", "1",
                     "Ensure User Account Control (UAC) is enabled",
                     pass ? "PASS" : "FAIL", "1 (enabled)", std::to_string(val),
                     pass ? "INFO" : "CRITICAL",
                     "Set HKLM\\...\\Policies\\System\\EnableLUA = 1"});
    }

    // CIS WIN 1.2 — SMBv1 disabled
    {
        auto val = detail::read_registry_dword(
            HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
            "SMB1", 1);
        bool pass = val == 0;
        r.push_back({"CIS-WIN-1.2", "1",
                     "Ensure SMBv1 protocol is disabled",
                     pass ? "PASS" : "FAIL", "0 (disabled)", std::to_string(val),
                     pass ? "INFO" : "CRITICAL",
                     "Set-SmbServerConfiguration -EnableSMB1Protocol $false"});
    }

    // CIS WIN 1.3 — Auto-logon disabled
    {
        auto val = detail::read_registry_string(
            HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            "AutoAdminLogon");
        bool pass = val.empty() || val == "0";
        r.push_back({"CIS-WIN-1.3", "1",
                     "Ensure AutoAdminLogon is disabled",
                     pass ? "PASS" : "FAIL", "0 (disabled)", val.empty() ? "0" : val,
                     pass ? "INFO" : "HIGH",
                     "Set HKLM\\...\\Winlogon\\AutoAdminLogon = 0"});
    }

    // CIS WIN 1.4 — Windows Defender real-time protection
    {
        auto val = detail::read_registry_dword(
            HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
            "DisableRealtimeMonitoring", 0);
        bool pass = val == 0;
        r.push_back({"CIS-WIN-1.4", "1",
                     "Ensure Windows Defender real-time protection is enabled",
                     pass ? "PASS" : "FAIL", "0 (not disabled)", std::to_string(val),
                     pass ? "INFO" : "HIGH",
                     "Enable via Windows Security > Virus & threat protection"});
    }

    // CIS WIN 1.5 — RDP Network Level Authentication
    {
        auto rdp_disabled = detail::read_registry_dword(
            HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
            "fDenyTSConnections", 1);
        if (rdp_disabled == 0) {
            auto nla = detail::read_registry_dword(
                HKEY_LOCAL_MACHINE,
                "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
                "UserAuthentication", 0);
            bool pass = nla == 1;
            r.push_back({"CIS-WIN-1.5", "1",
                         "Ensure RDP uses Network Level Authentication",
                         pass ? "PASS" : "FAIL", "1 (NLA required)", std::to_string(nla),
                         pass ? "INFO" : "HIGH",
                         "Set via Group Policy: Require NLA for Remote Desktop connections"});
        }
    }

    // CIS WIN 1.6 — Firewall: Domain profile
    {
        auto val = detail::read_registry_dword(
            HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters"
            "\\FirewallPolicy\\DomainProfile",
            "EnableFirewall", 0);
        bool pass = val == 1;
        r.push_back({"CIS-WIN-1.6", "1",
                     "Ensure Windows Firewall is enabled for Domain profile",
                     pass ? "PASS" : "FAIL", "1 (enabled)", std::to_string(val),
                     pass ? "INFO" : "HIGH",
                     "netsh advfirewall set domainprofile state on"});
    }

    // CIS WIN 1.7 — Firewall: Private profile
    {
        auto val = detail::read_registry_dword(
            HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters"
            "\\FirewallPolicy\\StandardProfile",
            "EnableFirewall", 0);
        bool pass = val == 1;
        r.push_back({"CIS-WIN-1.7", "1",
                     "Ensure Windows Firewall is enabled for Private profile",
                     pass ? "PASS" : "FAIL", "1 (enabled)", std::to_string(val),
                     pass ? "INFO" : "HIGH",
                     "netsh advfirewall set privateprofile state on"});
    }

    // CIS WIN 1.8 — Firewall: Public profile
    {
        auto val = detail::read_registry_dword(
            HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters"
            "\\FirewallPolicy\\PublicProfile",
            "EnableFirewall", 0);
        bool pass = val == 1;
        r.push_back({"CIS-WIN-1.8", "1",
                     "Ensure Windows Firewall is enabled for Public profile",
                     pass ? "PASS" : "FAIL", "1 (enabled)", std::to_string(val),
                     pass ? "INFO" : "CRITICAL",
                     "netsh advfirewall set publicprofile state on"});
    }

    return r;
}
#endif // _WIN32

// ── Linux CIS Level 1 ─────────────────────────────────────────────────────

#ifdef __linux__

inline std::vector<CisCheckResult> run_linux_cis_l1() {
    std::vector<CisCheckResult> r;

    // CIS LIN 1.4.1 — ASLR enabled (randomize_va_space = 2)
    {
        auto val = detail::read_proc_value("/proc/sys/kernel/randomize_va_space");
        bool pass = !val.empty() && val[0] == '2';
        r.push_back({"CIS-LIN-1.4.1", "1",
                     "Ensure address space layout randomization (ASLR) is enabled",
                     pass ? "PASS" : "FAIL", "2", val.empty() ? "unknown" : val,
                     pass ? "INFO" : "HIGH",
                     "Set kernel.randomize_va_space = 2 in /etc/sysctl.conf"});
    }

    // CIS LIN 1.4.2 — Core dumps restricted (suid_dumpable = 0)
    {
        auto val = detail::read_proc_value("/proc/sys/fs/suid_dumpable");
        bool pass = !val.empty() && val[0] == '0';
        r.push_back({"CIS-LIN-1.4.2", "1",
                     "Ensure core dumps are restricted",
                     pass ? "PASS" : "FAIL", "0", val.empty() ? "unknown" : val,
                     pass ? "INFO" : "MEDIUM",
                     "Set fs.suid_dumpable = 0 in /etc/sysctl.conf"});
    }

    // CIS LIN 3.1.1 — IP forwarding disabled
    {
        auto val = detail::read_proc_value("/proc/sys/net/ipv4/ip_forward");
        bool pass = !val.empty() && val[0] == '0';
        r.push_back({"CIS-LIN-3.1.1", "1",
                     "Ensure IP forwarding is disabled",
                     pass ? "PASS" : "FAIL", "0", val.empty() ? "unknown" : val,
                     pass ? "INFO" : "MEDIUM",
                     "Set net.ipv4.ip_forward = 0 in /etc/sysctl.conf"});
    }

    // CIS LIN 3.2.1 — Source route packets rejected
    {
        auto val = detail::read_proc_value("/proc/sys/net/ipv4/conf/all/accept_source_route");
        bool pass = !val.empty() && val[0] == '0';
        r.push_back({"CIS-LIN-3.2.1", "1",
                     "Ensure source routed packets are not accepted",
                     pass ? "PASS" : "FAIL", "0", val.empty() ? "unknown" : val,
                     pass ? "INFO" : "MEDIUM",
                     "Set net.ipv4.conf.all.accept_source_route = 0 in /etc/sysctl.conf"});
    }

    // CIS LIN 3.2.2 — ICMP redirects not accepted
    {
        auto val = detail::read_proc_value("/proc/sys/net/ipv4/conf/all/accept_redirects");
        bool pass = !val.empty() && val[0] == '0';
        r.push_back({"CIS-LIN-3.2.2", "1",
                     "Ensure ICMP redirects are not accepted",
                     pass ? "PASS" : "FAIL", "0", val.empty() ? "unknown" : val,
                     pass ? "INFO" : "MEDIUM",
                     "Set net.ipv4.conf.all.accept_redirects = 0 in /etc/sysctl.conf"});
    }

    // CIS LIN 3.3.1 — TCP SYN cookies enabled
    {
        auto val = detail::read_proc_value("/proc/sys/net/ipv4/tcp_syncookies");
        bool pass = !val.empty() && val[0] == '1';
        r.push_back({"CIS-LIN-3.3.1", "1",
                     "Ensure TCP SYN cookies are enabled",
                     pass ? "PASS" : "FAIL", "1", val.empty() ? "unknown" : val,
                     pass ? "INFO" : "MEDIUM",
                     "Set net.ipv4.tcp_syncookies = 1 in /etc/sysctl.conf"});
    }

    // CIS LIN 5.2.4 — SSH PermitRootLogin disabled
    {
        bool root_yes = detail::file_contains("/etc/ssh/sshd_config", "PermitRootLogin yes");
        bool root_no  = detail::file_contains("/etc/ssh/sshd_config", "PermitRootLogin no");
        bool pass = root_no && !root_yes;
        std::string actual = root_yes ? "yes" : root_no ? "no" : "default";
        r.push_back({"CIS-LIN-5.2.4", "1",
                     "Ensure SSH PermitRootLogin is set to no",
                     pass ? "PASS" : "FAIL", "no", actual,
                     pass ? "INFO" : "HIGH",
                     "Set 'PermitRootLogin no' in /etc/ssh/sshd_config"});
    }

    // CIS LIN 5.2.5 — SSH PermitEmptyPasswords disabled
    {
        bool empty_pw = detail::file_contains("/etc/ssh/sshd_config", "PermitEmptyPasswords yes");
        r.push_back({"CIS-LIN-5.2.5", "1",
                     "Ensure SSH PermitEmptyPasswords is disabled",
                     !empty_pw ? "PASS" : "FAIL", "no", empty_pw ? "yes" : "no",
                     !empty_pw ? "INFO" : "CRITICAL",
                     "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config"});
    }

    // CIS LIN 5.2.6 — SSH IgnoreRhosts enabled
    {
        bool ignore = detail::file_contains("/etc/ssh/sshd_config", "IgnoreRhosts yes");
        r.push_back({"CIS-LIN-5.2.6", "1",
                     "Ensure SSH IgnoreRhosts is enabled",
                     ignore ? "PASS" : "FAIL", "yes", ignore ? "yes" : "not set",
                     ignore ? "INFO" : "MEDIUM",
                     "Set 'IgnoreRhosts yes' in /etc/ssh/sshd_config"});
    }

    // CIS LIN 5.2.7 — SSH LogLevel INFO or VERBOSE
    {
        bool info_set = detail::file_contains("/etc/ssh/sshd_config", "LogLevel INFO") ||
                        detail::file_contains("/etc/ssh/sshd_config", "LogLevel VERBOSE");
        r.push_back({"CIS-LIN-5.2.7", "1",
                     "Ensure SSH LogLevel is appropriate",
                     info_set ? "PASS" : "FAIL", "INFO or VERBOSE", info_set ? "set" : "not set",
                     info_set ? "INFO" : "MEDIUM",
                     "Set 'LogLevel INFO' in /etc/ssh/sshd_config"});
    }

    // CIS LIN 5.2.8 — SSH HostbasedAuthentication disabled
    {
        bool host_based = detail::file_contains("/etc/ssh/sshd_config", "HostbasedAuthentication yes");
        r.push_back({"CIS-LIN-5.2.8", "1",
                     "Ensure SSH HostbasedAuthentication is disabled",
                     !host_based ? "PASS" : "FAIL", "no", host_based ? "yes" : "no",
                     !host_based ? "INFO" : "HIGH",
                     "Set 'HostbasedAuthentication no' in /etc/ssh/sshd_config"});
    }

    // CIS LIN 5.2.9 — SSH Protocol version 2 only
    {
        bool proto1 = detail::file_contains("/etc/ssh/sshd_config", "Protocol 1");
        r.push_back({"CIS-LIN-5.2.9", "1",
                     "Ensure SSH uses Protocol 2 only",
                     !proto1 ? "PASS" : "FAIL", "2 (implicit)", proto1 ? "1 present" : "2 only",
                     !proto1 ? "INFO" : "CRITICAL",
                     "Remove 'Protocol 1' from /etc/ssh/sshd_config"});
    }

    // CIS LIN 6.1.1 — /tmp mounted noexec
    {
        std::ifstream mounts("/proc/mounts");
        bool found = false, noexec = false;
        if (mounts.is_open()) {
            std::string line;
            while (std::getline(mounts, line)) {
                if (line.find(" /tmp ") != std::string::npos) {
                    found = true;
                    noexec = line.find("noexec") != std::string::npos;
                    break;
                }
            }
        }
        if (found) {
            r.push_back({"CIS-LIN-6.1.1", "1",
                         "Ensure /tmp is mounted with noexec option",
                         noexec ? "PASS" : "FAIL", "noexec", noexec ? "noexec" : "exec",
                         noexec ? "INFO" : "MEDIUM",
                         "Add noexec to /tmp mount options in /etc/fstab"});
        }
    }

    return r;
}
#endif // __linux__

// ── macOS CIS Level 1 ─────────────────────────────────────────────────────

#ifdef __APPLE__

inline std::vector<CisCheckResult> run_macos_cis_l1() {
    std::vector<CisCheckResult> r;

    // CIS MAC 1.1 — System Integrity Protection enabled
    {
        auto out = detail::run_cmd("csrutil status 2>&1");
        bool pass = out.find("enabled") != std::string::npos;
        r.push_back({"CIS-MAC-1.1", "1",
                     "Ensure System Integrity Protection (SIP) is enabled",
                     pass ? "PASS" : "FAIL", "enabled", pass ? "enabled" : "disabled",
                     pass ? "INFO" : "CRITICAL",
                     "Boot to Recovery Mode and run: csrutil enable"});
    }

    // CIS MAC 1.2 — FileVault enabled
    {
        auto out = detail::run_cmd("fdesetup status 2>&1");
        bool pass = out.find("On") != std::string::npos;
        r.push_back({"CIS-MAC-1.2", "1",
                     "Ensure FileVault disk encryption is enabled",
                     pass ? "PASS" : "FAIL", "On", pass ? "On" : "Off",
                     pass ? "INFO" : "HIGH",
                     "Enable via System Settings > Privacy & Security > FileVault"});
    }

    // CIS MAC 1.3 — Gatekeeper enabled
    {
        auto out = detail::run_cmd("spctl --status 2>&1");
        bool pass = out.find("enabled") != std::string::npos;
        r.push_back({"CIS-MAC-1.3", "1",
                     "Ensure Gatekeeper is enabled",
                     pass ? "PASS" : "FAIL", "enabled", pass ? "enabled" : "disabled",
                     pass ? "INFO" : "HIGH",
                     "sudo spctl --master-enable"});
    }

    // CIS MAC 1.4 — Application Firewall enabled
    {
        auto out = detail::run_cmd(
            "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>&1");
        bool pass = out.find("enabled") != std::string::npos;
        r.push_back({"CIS-MAC-1.4", "1",
                     "Ensure Application Firewall is enabled",
                     pass ? "PASS" : "FAIL", "enabled", pass ? "enabled" : "disabled",
                     pass ? "INFO" : "HIGH",
                     "/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"});
    }

    // CIS MAC 1.5 — Automatic updates enabled
    {
        auto out = detail::run_cmd(
            "defaults read /Library/Preferences/com.apple.SoftwareUpdate "
            "AutomaticCheckEnabled 2>/dev/null");
        bool pass = out.find("1") != std::string::npos;
        r.push_back({"CIS-MAC-1.5", "1",
                     "Ensure automatic software updates are enabled",
                     pass ? "PASS" : "FAIL", "1 (enabled)", pass ? "1" : "0",
                     pass ? "INFO" : "MEDIUM",
                     "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate "
                     "AutomaticCheckEnabled -bool TRUE"});
    }

    // CIS MAC 1.6 — Remote Login (SSH) disabled unless needed
    {
        auto out = detail::run_cmd("systemsetup -getremotelogin 2>&1");
        bool off = out.find("Off") != std::string::npos;
        r.push_back({"CIS-MAC-1.6", "1",
                     "Ensure Remote Login (SSH) is disabled if not required",
                     off ? "PASS" : "FAIL", "Off", off ? "Off" : "On",
                     off ? "INFO" : "MEDIUM",
                     "sudo systemsetup -setremotelogin off"});
    }

    // CIS MAC 1.7 — Screen sharing disabled
    {
        auto out = detail::run_cmd(
            "defaults read /var/db/launchd.db/com.apple.launchd/overrides.plist "
            "com.apple.screensharing 2>/dev/null | grep -c Disabled");
        bool pass = out.find("1") != std::string::npos;
        r.push_back({"CIS-MAC-1.7", "1",
                     "Ensure Screen Sharing is disabled",
                     pass ? "PASS" : "FAIL", "Disabled", pass ? "Disabled" : "may be enabled",
                     pass ? "INFO" : "MEDIUM",
                     "Disable via System Settings > Sharing > Screen Sharing"});
    }

    return r;
}
#endif // __APPLE__

// ── Run all CIS checks for the current platform ───────────────────────────

inline std::vector<CisCheckResult> run_all_cis_checks() {
    std::vector<CisCheckResult> results;
#ifdef _WIN32
    auto w = run_windows_cis_l1();
    results.insert(results.end(), w.begin(), w.end());
#elif defined(__linux__)
    auto l = run_linux_cis_l1();
    results.insert(results.end(), l.begin(), l.end());
#elif defined(__APPLE__)
    auto m = run_macos_cis_l1();
    results.insert(results.end(), m.begin(), m.end());
#endif
    return results;
}

} // namespace yuzu::vuln
