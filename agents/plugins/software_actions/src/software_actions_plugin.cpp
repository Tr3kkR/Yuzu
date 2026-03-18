/**
 * software_actions_plugin.cpp — Software upgrade info plugin for Yuzu
 *
 * Actions:
 *   "list_upgradable" — List packages/apps that can be upgraded (read-only).
 *   "installed_count" — Quick count of installed packages/apps.
 *
 * Output is pipe-delimited, one record per line via write_output():
 *   upgradable|name|current|available
 *   count|N
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

// ── list_upgradable action ─────────────────────────────────────────────────

int do_list_upgradable(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    // Use winget to list upgradable packages
    auto lines = run_command_lines("winget upgrade --accept-source-agreements 2>nul");
    if (lines.empty()) {
        ctx.write_output("upgradable|none|-|-");
        return 0;
    }
    // winget output has header lines, then a separator line of dashes,
    // then data rows. Find the separator to know where data starts.
    bool in_data = false;
    bool found_any = false;
    for (const auto& line : lines) {
        if (!in_data) {
            // Look for the separator line (all dashes/spaces)
            bool is_sep = !line.empty();
            for (char ch : line) {
                if (ch != '-' && ch != ' ') {
                    is_sep = false;
                    break;
                }
            }
            if (is_sep && line.size() > 10) {
                in_data = true;
            }
            continue;
        }
        // Skip footer lines (e.g. "N upgrades available")
        if (line.find("upgrade") != std::string::npos &&
            line.find("available") != std::string::npos) {
            continue;
        }
        if (line.empty())
            continue;

        // Parse columns — winget uses fixed-width columns.
        // We'll just output the whole line if we can't parse well.
        // Typical format: "Name            Id              Version  Available"
        // Split on multiple spaces
        std::vector<std::string> parts;
        std::string current;
        int spaces = 0;
        for (char ch : line) {
            if (ch == ' ') {
                spaces++;
                if (spaces >= 2 && !current.empty()) {
                    parts.push_back(current);
                    current.clear();
                    spaces = 0;
                }
            } else {
                if (spaces > 0 && spaces < 2) {
                    current += std::string(static_cast<size_t>(spaces), ' ');
                }
                spaces = 0;
                current += ch;
            }
        }
        if (!current.empty())
            parts.push_back(current);

        if (parts.size() >= 4) {
            ctx.write_output(std::format("upgradable|{}|{}|{}", parts[0], parts[2], parts[3]));
            found_any = true;
        } else if (parts.size() >= 2) {
            ctx.write_output(std::format("upgradable|{}|-|-", parts[0]));
            found_any = true;
        }
    }
    if (!found_any) {
        ctx.write_output("upgradable|none|System is up to date|-");
    }

#elif defined(__linux__)
    // Try apt first
    auto lines = run_command_lines("apt list --upgradable 2>/dev/null");
    bool found = false;
    for (const auto& line : lines) {
        if (line.starts_with("Listing"))
            continue;
        // Format: "name/repo new_ver arch [upgradable from: old_ver]"
        auto slash = line.find('/');
        auto space = line.find(' ');
        if (slash != std::string::npos && space != std::string::npos) {
            auto name = line.substr(0, slash);
            auto rest = line.substr(space + 1);
            auto ver_end = rest.find(' ');
            auto new_ver = (ver_end != std::string::npos) ? rest.substr(0, ver_end) : rest;
            // Try to extract old version from "[upgradable from: X.Y.Z]"
            std::string old_ver = "-";
            auto from_pos = rest.find("from: ");
            if (from_pos != std::string::npos) {
                old_ver = rest.substr(from_pos + 6);
                auto bracket = old_ver.find(']');
                if (bracket != std::string::npos)
                    old_ver = old_ver.substr(0, bracket);
            }
            ctx.write_output(std::format("upgradable|{}|{}|{}", name, old_ver, new_ver));
            found = true;
        }
    }
    if (!found) {
        // Try yum
        lines = run_command_lines("yum check-update 2>/dev/null | grep -v '^$'");
        for (const auto& line : lines) {
            if (line.starts_with("Loaded") || line.starts_with("Loading"))
                continue;
            if (line.starts_with("Last metadata"))
                continue;
            // Format: "package.arch  new_version  repo"
            std::string name, version, repo;
            size_t pos = 0;
            // Find first whitespace
            while (pos < line.size() && line[pos] != ' ' && line[pos] != '\t')
                pos++;
            name = line.substr(0, pos);
            while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t'))
                pos++;
            auto ver_start = pos;
            while (pos < line.size() && line[pos] != ' ' && line[pos] != '\t')
                pos++;
            version = line.substr(ver_start, pos - ver_start);
            if (!name.empty()) {
                ctx.write_output(std::format("upgradable|{}|-|{}", name, version));
                found = true;
            }
        }
    }
    if (!found) {
        ctx.write_output("upgradable|none|System is up to date|-");
    }

#elif defined(__APPLE__)
    auto lines = run_command_lines("softwareupdate -l 2>/dev/null");
    bool found = false;
    for (const auto& line : lines) {
        auto trimmed = line;
        auto start = trimmed.find_first_not_of(" \t*");
        if (start != std::string::npos)
            trimmed = trimmed.substr(start);
        if (trimmed.empty())
            continue;
        if (trimmed.starts_with("Software Update") || trimmed.starts_with("Finding") ||
            trimmed.starts_with("No new"))
            continue;
        // Lines starting with "Label:" or containing version info
        if (trimmed.find("Label:") != std::string::npos) {
            auto label = trimmed.substr(trimmed.find(':') + 2);
            ctx.write_output(std::format("upgradable|{}|-|-", label));
            found = true;
        } else if (!trimmed.starts_with("Title:") && !trimmed.starts_with("Size:") &&
                   !trimmed.starts_with("Recommended:") && !trimmed.starts_with("Action:")) {
            ctx.write_output(std::format("upgradable|{}|-|-", trimmed));
            found = true;
        }
    }
    if (!found) {
        ctx.write_output("upgradable|none|System is up to date|-");
    }

#else
    ctx.write_output("error|platform not supported");
#endif
    return 0;
}

// ── installed_count action ─────────────────────────────────────────────────

int do_installed_count(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    auto result = run_command("powershell -NoProfile -Command \""
                              "(Get-ItemProperty "
                              "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' "
                              "-ErrorAction SilentlyContinue).Count\"");
    if (result.empty()) {
        ctx.write_output("count|0");
    } else {
        // Trim whitespace
        while (!result.empty() && (result.back() == ' ' || result.back() == '\t'))
            result.pop_back();
        ctx.write_output(std::format("count|{}", result));
    }

#elif defined(__linux__)
    // Try dpkg first, then rpm
    auto result = run_command("dpkg --list 2>/dev/null | grep '^ii' | wc -l");
    if (!result.empty() && result != "0") {
        while (!result.empty() && result.front() == ' ')
            result.erase(result.begin());
        ctx.write_output(std::format("count|{}", result));
    } else {
        result = run_command("rpm -qa 2>/dev/null | wc -l");
        while (!result.empty() && result.front() == ' ')
            result.erase(result.begin());
        ctx.write_output(std::format("count|{}", result.empty() ? "0" : result));
    }

#elif defined(__APPLE__)
    auto result = run_command("pkgutil --pkgs 2>/dev/null | wc -l");
    while (!result.empty() && result.front() == ' ')
        result.erase(result.begin());
    ctx.write_output(std::format("count|{}", result.empty() ? "0" : result));

#else
    ctx.write_output("error|platform not supported");
#endif
    return 0;
}

} // namespace

class SoftwareActionsPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "software_actions"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Lists upgradable packages and counts installed software";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"list_upgradable", "installed_count", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        if (action == "list_upgradable")
            return do_list_upgradable(ctx);
        if (action == "installed_count")
            return do_installed_count(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(SoftwareActionsPlugin)
