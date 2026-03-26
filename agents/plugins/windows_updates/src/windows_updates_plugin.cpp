/**
 * windows_updates_plugin.cpp — Windows updates / package updates plugin for Yuzu
 *
 * Actions:
 *   "installed"      — List recently installed updates/packages.
 *   "missing"        — List available updates/packages that can be installed.
 *   "pending_reboot" — Detect if the endpoint requires a reboot after updates.
 *
 * Output is pipe-delimited, one record per line via write_output():
 *   update|kb_id|description|date
 *   package|name|version
 *   available|title|severity
 *   source_name|true/false|detail          (per-check rows)
 *   reboot_required|true/false|reasons    (summary row)
 */

#include <yuzu/plugin.hpp>

#include <array>
#include <cstdio>
#include <filesystem>
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
#endif

namespace {

// ── subprocess helpers ─────────────────────────────────────────────────────

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
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
        result.pop_back();
    return result;
}

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
        auto latest = run_command("ls /boot/vmlinuz-* 2>/dev/null | sort -V | tail -1");
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
    ctx.write_output("error|platform not supported");
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

} // namespace

class WindowsUpdatesPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "windows_updates"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Lists installed, available, and pending-reboot OS updates/packages";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"installed", "missing", "pending_reboot", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        if (action == "installed")
            return do_installed(ctx);
        if (action == "missing")
            return do_missing(ctx);
        if (action == "pending_reboot")
            return do_pending_reboot(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(WindowsUpdatesPlugin)
