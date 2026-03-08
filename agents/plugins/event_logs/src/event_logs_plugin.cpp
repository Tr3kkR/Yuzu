/**
 * event_logs_plugin.cpp — Event log viewer plugin for Yuzu
 *
 * Actions:
 *   "errors" — Recent error events from a specified log.
 *              Params: log (optional, default "System"),
 *                      hours (optional, default "24").
 *   "query"  — Search events by keyword.
 *              Params: log (required), filter (required),
 *                      count (optional, default "50").
 *
 * Output is pipe-delimited, one record per line via write_output():
 *   error|timestamp|event_id|source|message
 *   event|timestamp|level|event_id|source|message
 */

#include <yuzu/plugin.hpp>

#include <algorithm>
#include <array>
#include <cctype>
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

// ── input sanitization ────────────────────────────────────────────────────

// Only allow alphanumeric, spaces, dots, hyphens, underscores, and slashes
// for log names and filter strings to prevent injection.
std::string sanitize_input(std::string_view input) {
    std::string out;
    out.reserve(input.size());
    for (char ch : input) {
        if (std::isalnum(static_cast<unsigned char>(ch)) ||
            ch == ' ' || ch == '.' || ch == '-' || ch == '_' || ch == '/') {
            out += ch;
        }
    }
    return out;
}

// ── errors action ──────────────────────────────────────────────────────────

int do_errors(yuzu::CommandContext& ctx, yuzu::Params params) {
    auto log_name = sanitize_input(params.get("log"));
    if (log_name.empty()) log_name = "System";

    auto hours_str = std::string(params.get("hours"));
    if (hours_str.empty()) hours_str = "24";
    // Validate hours is numeric
    int hours = 24;
    try { hours = std::stoi(hours_str); } catch (...) { hours = 24; }
    if (hours < 1) hours = 1;
    if (hours > 720) hours = 720;

#ifdef _WIN32
    auto cmd = std::format(
        "powershell -NoProfile -Command \""
        "Get-WinEvent -FilterHashtable @{{LogName='{}';Level=2;"
        "StartTime=(Get-Date).AddHours(-{})}} -MaxEvents 100 "
        "-ErrorAction SilentlyContinue | ForEach-Object {{ "
        "$_.TimeCreated.ToString('o') + '|' + $_.Id + '|' + "
        "$_.ProviderName + '|' + "
        "($_.Message -replace '[\\r\\n]+',' ').Substring(0,"
        "[Math]::Min(200,$_.Message.Length)) }}\"",
        log_name, hours);
    auto lines = run_command_lines(cmd.c_str());
    if (lines.empty()) {
        ctx.write_output("error|none|No error events found|-|-");
        return 0;
    }
    for (const auto& line : lines) {
        ctx.write_output(std::format("error|{}", line));
    }

#elif defined(__linux__)
    auto cmd = std::format(
        "journalctl -p err --since \"{} hours ago\" -n 100 --no-pager -o short-iso 2>/dev/null",
        hours);
    auto lines = run_command_lines(cmd.c_str());
    if (lines.empty()) {
        ctx.write_output("error|none|-|No error events found");
        return 0;
    }
    for (const auto& line : lines) {
        // journalctl short-iso format: "YYYY-MM-DDTHH:MM:SS+ZZZZ hostname unit[pid]: message"
        auto first_space = line.find(' ');
        if (first_space == std::string::npos) {
            ctx.write_output(std::format("error|{}|-|{}", line, line));
            continue;
        }
        auto timestamp = line.substr(0, first_space);
        auto rest = line.substr(first_space + 1);
        // Skip hostname
        auto second_space = rest.find(' ');
        if (second_space != std::string::npos) {
            rest = rest.substr(second_space + 1);
        }
        // Split on ': ' for unit and message
        auto colon = rest.find(": ");
        if (colon != std::string::npos) {
            auto unit = rest.substr(0, colon);
            auto message = rest.substr(colon + 2);
            if (message.size() > 200) message = message.substr(0, 200);
            ctx.write_output(std::format("error|{}|{}|{}", timestamp, unit, message));
        } else {
            ctx.write_output(std::format("error|{}|-|{}", timestamp, rest));
        }
    }

#elif defined(__APPLE__)
    auto cmd = std::format(
        "log show --predicate 'messageType == error' --last {}h "
        "--style compact 2>/dev/null | head -100",
        hours);
    auto lines = run_command_lines(cmd.c_str());
    if (lines.empty()) {
        ctx.write_output("error|none|-|No error events found");
        return 0;
    }
    for (const auto& line : lines) {
        // Compact format: "timestamp  process[pid]  message"
        auto first_space = line.find("  ");
        if (first_space == std::string::npos) {
            ctx.write_output(std::format("error|{}|-|{}", line, line));
            continue;
        }
        auto timestamp = line.substr(0, first_space);
        auto rest = line.substr(first_space + 2);
        auto second_space = rest.find("  ");
        std::string process = "-";
        std::string message = rest;
        if (second_space != std::string::npos) {
            process = rest.substr(0, second_space);
            message = rest.substr(second_space + 2);
        }
        if (message.size() > 200) message = message.substr(0, 200);
        ctx.write_output(std::format("error|{}|{}|{}", timestamp, process, message));
    }

#else
    ctx.write_output("error|platform not supported|-|-");
#endif
    return 0;
}

// ── query action ───────────────────────────────────────────────────────────

int do_query(yuzu::CommandContext& ctx, yuzu::Params params) {
    auto log_name = sanitize_input(params.get("log"));
    if (log_name.empty()) {
        ctx.write_output("error|'log' parameter is required");
        return 1;
    }

    auto filter = sanitize_input(params.get("filter"));
    if (filter.empty()) {
        ctx.write_output("error|'filter' parameter is required");
        return 1;
    }

    auto count_str = std::string(params.get("count"));
    if (count_str.empty()) count_str = "50";
    int count = 50;
    try { count = std::stoi(count_str); } catch (...) { count = 50; }
    if (count < 1) count = 1;
    if (count > 500) count = 500;

#ifdef _WIN32
    auto cmd = std::format(
        "powershell -NoProfile -Command \""
        "Get-WinEvent -LogName '{}' -MaxEvents {} "
        "-ErrorAction SilentlyContinue | Where-Object {{ $_.Message -like '*{}*' }} "
        "| ForEach-Object {{ "
        "$_.TimeCreated.ToString('o') + '|' + $_.LevelDisplayName + '|' + "
        "$_.Id + '|' + $_.ProviderName + '|' + "
        "($_.Message -replace '[\\r\\n]+',' ').Substring(0,"
        "[Math]::Min(200,$_.Message.Length)) }}\"",
        log_name, count, filter);
    auto lines = run_command_lines(cmd.c_str());
    if (lines.empty()) {
        ctx.write_output("event|none|-|-|-|No matching events found");
        return 0;
    }
    for (const auto& line : lines) {
        ctx.write_output(std::format("event|{}", line));
    }

#elif defined(__linux__)
    auto cmd = std::format(
        "journalctl --grep=\"{}\" -n {} --no-pager -o short-iso 2>/dev/null",
        filter, count);
    auto lines = run_command_lines(cmd.c_str());
    if (lines.empty()) {
        ctx.write_output("event|none|-|No matching events found");
        return 0;
    }
    for (const auto& line : lines) {
        auto first_space = line.find(' ');
        if (first_space == std::string::npos) {
            ctx.write_output(std::format("event|{}|-|{}", line, line));
            continue;
        }
        auto timestamp = line.substr(0, first_space);
        auto rest = line.substr(first_space + 1);
        auto second_space = rest.find(' ');
        if (second_space != std::string::npos) {
            rest = rest.substr(second_space + 1);
        }
        auto colon = rest.find(": ");
        if (colon != std::string::npos) {
            auto unit = rest.substr(0, colon);
            auto message = rest.substr(colon + 2);
            if (message.size() > 200) message = message.substr(0, 200);
            ctx.write_output(std::format("event|{}|{}|{}", timestamp, unit, message));
        } else {
            ctx.write_output(std::format("event|{}|-|{}", timestamp, rest));
        }
    }

#elif defined(__APPLE__)
    auto cmd = std::format(
        "log show --predicate 'eventMessage contains \"{}\"' --last 24h "
        "--style compact 2>/dev/null | head -{}",
        filter, count);
    auto lines = run_command_lines(cmd.c_str());
    if (lines.empty()) {
        ctx.write_output("event|none|-|No matching events found");
        return 0;
    }
    for (const auto& line : lines) {
        auto first_space = line.find("  ");
        if (first_space == std::string::npos) {
            ctx.write_output(std::format("event|{}|-|{}", line, line));
            continue;
        }
        auto timestamp = line.substr(0, first_space);
        auto rest = line.substr(first_space + 2);
        auto second_space = rest.find("  ");
        std::string process = "-";
        std::string message = rest;
        if (second_space != std::string::npos) {
            process = rest.substr(0, second_space);
            message = rest.substr(second_space + 2);
        }
        if (message.size() > 200) message = message.substr(0, 200);
        ctx.write_output(std::format("event|{}|{}|{}", timestamp, process, message));
    }

#else
    ctx.write_output("error|platform not supported");
#endif
    return 0;
}

}  // namespace

class EventLogsPlugin final : public yuzu::Plugin {
public:
    std::string_view name()        const noexcept override { return "event_logs"; }
    std::string_view version()     const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Queries system event logs for errors and filtered events";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {
            "errors", "query", nullptr
        };
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override {
        return {};
    }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx,
                std::string_view action,
                yuzu::Params params) override {
        if (action == "errors") return do_errors(ctx, params);
        if (action == "query")  return do_query(ctx, params);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(EventLogsPlugin)
