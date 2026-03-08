/**
 * script_exec_plugin.cpp — Script/command execution plugin for Yuzu
 *
 * Actions:
 *   "exec"       — Execute a command and stream stdout.
 *                   Params: command (required), timeout (optional, default "300").
 *   "powershell" — Run a PowerShell script (Windows only).
 *                   Params: script (required), timeout (optional, default "300").
 *   "bash"       — Run a bash script (Linux/macOS only).
 *                   Params: script (required), timeout (optional, default "300").
 *
 * Output is pipe-delimited, streamed per line via write_output():
 *   stdout|line_content
 *   exit_code|N
 *   status|ok/error/timeout
 */

#include <yuzu/plugin.hpp>

#include <array>
#include <chrono>
#include <cstdio>
#include <format>
#include <string>
#include <string_view>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <csignal>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {

// ── helper: parse timeout ──────────────────────────────────────────────────

int parse_timeout(yuzu::Params& params) {
    auto t = std::string(params.get("timeout"));
    if (t.empty()) return 300;
    int val = 300;
    try { val = std::stoi(t); } catch (...) { val = 300; }
    if (val < 1) val = 1;
    if (val > 3600) val = 3600;
    return val;
}

// ── core execution with streaming output ───────────────────────────────────

int run_and_stream(yuzu::CommandContext& ctx, const std::string& cmd, int timeout_secs) {
    auto start = std::chrono::steady_clock::now();

#ifdef _WIN32
    FILE* pipe = _popen(cmd.c_str(), "r");
#else
    FILE* pipe = popen(cmd.c_str(), "r");
#endif
    if (!pipe) {
        ctx.write_output("status|error");
        ctx.write_output("exit_code|-1");
        return 1;
    }

    std::array<char, 512> buf{};
    bool timed_out = false;

    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        // Check timeout
        auto elapsed = std::chrono::steady_clock::now() - start;
        if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() >= timeout_secs) {
            timed_out = true;
            break;
        }

        std::string line(buf.data());
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
            line.pop_back();
        ctx.write_output(std::format("stdout|{}", line));
    }

#ifdef _WIN32
    int exit_code = _pclose(pipe);
#else
    int raw = pclose(pipe);
    int exit_code = WIFEXITED(raw) ? WEXITSTATUS(raw) : -1;
#endif

    if (timed_out) {
        ctx.write_output("status|timeout");
        ctx.write_output(std::format("exit_code|{}", exit_code));
        return 1;
    }

    ctx.write_output(std::format("exit_code|{}", exit_code));
    ctx.write_output(exit_code == 0 ? "status|ok" : "status|error");
    return exit_code == 0 ? 0 : 1;
}

// ── exec action ────────────────────────────────────────────────────────────

int do_exec(yuzu::CommandContext& ctx, yuzu::Params params) {
    auto command = std::string(params.get("command"));
    if (command.empty()) {
        ctx.write_output("error|'command' parameter is required");
        return 1;
    }

    int timeout = parse_timeout(params);

    return run_and_stream(ctx, command, timeout);
}

// ── powershell action ──────────────────────────────────────────────────────

int do_powershell(yuzu::CommandContext& ctx, yuzu::Params params) {
#ifndef _WIN32
    ctx.write_output("error|powershell action is Windows-only");
    ctx.write_output("status|error");
    return 1;
#else
    auto script = std::string(params.get("script"));
    if (script.empty()) {
        ctx.write_output("error|'script' parameter is required");
        return 1;
    }

    int timeout = parse_timeout(params);

    // Escape double quotes in the script for the command line
    std::string escaped;
    escaped.reserve(script.size());
    for (char ch : script) {
        if (ch == '"') {
            escaped += "\\\"";
        } else {
            escaped += ch;
        }
    }

    auto cmd = std::format(
        "powershell.exe -NoProfile -NonInteractive -Command \"{}\"", escaped);

    return run_and_stream(ctx, cmd, timeout);
#endif
}

// ── bash action ────────────────────────────────────────────────────────────

int do_bash(yuzu::CommandContext& ctx, yuzu::Params params) {
#ifdef _WIN32
    ctx.write_output("error|bash action is not available on Windows");
    ctx.write_output("status|error");
    return 1;
#else
    auto script = std::string(params.get("script"));
    if (script.empty()) {
        ctx.write_output("error|'script' parameter is required");
        return 1;
    }

    int timeout = parse_timeout(params);

    // Escape single quotes in the script for bash -c '...'
    std::string escaped;
    escaped.reserve(script.size());
    for (char ch : script) {
        if (ch == '\'') {
            escaped += "'\\''";
        } else {
            escaped += ch;
        }
    }

    auto cmd = std::format("/bin/bash -c '{}'", escaped);

    return run_and_stream(ctx, cmd, timeout);
#endif
}

}  // namespace

class ScriptExecPlugin final : public yuzu::Plugin {
public:
    std::string_view name()        const noexcept override { return "script_exec"; }
    std::string_view version()     const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Executes commands and scripts with streaming output";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {
            "exec", "powershell", "bash", nullptr
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
        if (action == "exec")       return do_exec(ctx, params);
        if (action == "powershell") return do_powershell(ctx, params);
        if (action == "bash")       return do_bash(ctx, params);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(ScriptExecPlugin)
