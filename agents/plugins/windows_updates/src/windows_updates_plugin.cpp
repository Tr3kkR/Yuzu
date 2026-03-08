/**
 * windows_updates_plugin.cpp — Windows updates / package updates plugin for Yuzu
 *
 * Actions:
 *   "installed" — List recently installed updates/packages.
 *   "missing"   — List available updates/packages that can be installed.
 *
 * Output is pipe-delimited, one record per line via write_output():
 *   update|kb_id|description|date
 *   package|name|version
 *   available|title|severity
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
    if (!pipe) return result;
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
    if (!pipe) return lines;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        std::string line(buf.data());
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
            line.pop_back();
        if (!line.empty()) lines.push_back(std::move(line));
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
                ctx.write_output(std::format("package|{}|{}", line.substr(0, sep), line.substr(sep + 2)));
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
            if (line.starts_with("Listing")) continue;
            // Format: "name/repo version arch [status]"
            auto slash = line.find('/');
            auto space = line.find(' ');
            if (slash != std::string::npos && space != std::string::npos) {
                auto name = line.substr(0, slash);
                auto version = line.substr(space + 1);
                auto ver_end = version.find(' ');
                if (ver_end != std::string::npos) version = version.substr(0, ver_end);
                ctx.write_output(std::format("package|{}|{}", name, version));
            } else {
                ctx.write_output(std::format("package|{}|-", line));
            }
        }
    }

#elif defined(__APPLE__)
    auto lines = run_command_lines(
        "system_profiler SPInstallHistoryDataType 2>/dev/null "
        "| grep -E '^ {4}\\w|Install Date:' | head -100");
    if (lines.empty()) {
        ctx.write_output("update|none|No update history found");
        return 0;
    }
    std::string current_name;
    for (const auto& line : lines) {
        auto trimmed = line;
        auto start = trimmed.find_first_not_of(" \t");
        if (start != std::string::npos) trimmed = trimmed.substr(start);

        if (trimmed.starts_with("Install Date:")) {
            auto date = trimmed.substr(14);
            auto ds = date.find_first_not_of(" ");
            if (ds != std::string::npos) date = date.substr(ds);
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
            if (line.starts_with("Listing")) continue;
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
            if (line.starts_with("Loaded") || line.starts_with("Loading")) continue;
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
        if (start != std::string::npos) trimmed = trimmed.substr(start);
        if (trimmed.empty() || trimmed.starts_with("Software Update")) continue;
        if (trimmed.starts_with("Finding") || trimmed.starts_with("No new")) continue;
        ctx.write_output(std::format("available|{}", trimmed));
    }

#else
    ctx.write_output("error|platform not supported");
#endif
    return 0;
}

}  // namespace

class WindowsUpdatesPlugin final : public yuzu::Plugin {
public:
    std::string_view name()        const noexcept override { return "windows_updates"; }
    std::string_view version()     const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Lists installed and available OS updates/packages";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {
            "installed", "missing", nullptr
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
        if (action == "installed") return do_installed(ctx);
        if (action == "missing")   return do_missing(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(WindowsUpdatesPlugin)
