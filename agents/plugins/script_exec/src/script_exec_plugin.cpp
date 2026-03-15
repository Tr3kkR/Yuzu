/**
 * script_exec_plugin.cpp — Script/command execution plugin for Yuzu
 *
 * Actions:
 *   "exec"       — Execute a command with arguments (no shell interpretation).
 *                   Params: command (required — program path),
 *                           args (optional — space-separated arguments),
 *                           timeout (optional, default "300").
 *   "powershell" — Run a PowerShell script (Windows only).
 *                   Params: script (required), timeout (optional, default "300").
 *   "bash"       — Run a bash script (Linux/macOS only).
 *                   Params: script (required), timeout (optional, default "300").
 *
 * Security: This plugin is admin-only — the server enforces role checks
 * before dispatching commands to this plugin.
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
#include <cstring>
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
#include <wincrypt.h>
#pragma comment(lib, "Crypt32.lib")
#else
#include <csignal>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
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

// ── Stream output from a file descriptor/handle with timeout ────────────

#ifdef _WIN32

int stream_from_handle(yuzu::CommandContext& ctx, HANDLE read_handle,
                       HANDLE proc_handle, int timeout_secs) {
    auto start = std::chrono::steady_clock::now();
    bool timed_out = false;

    std::string line_buf;
    std::array<char, 512> buf{};

    while (true) {
        auto elapsed = std::chrono::steady_clock::now() - start;
        if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() >= timeout_secs) {
            timed_out = true;
            TerminateProcess(proc_handle, 1);
            break;
        }

        DWORD avail = 0;
        if (!PeekNamedPipe(read_handle, nullptr, 0, nullptr, &avail, nullptr) || avail == 0) {
            // Check if process is still alive
            if (WaitForSingleObject(proc_handle, 10) != WAIT_TIMEOUT) break;
            continue;
        }

        DWORD bytes_read = 0;
        if (!ReadFile(read_handle, buf.data(), static_cast<DWORD>(buf.size() - 1),
                      &bytes_read, nullptr) || bytes_read == 0) {
            break;
        }

        for (DWORD i = 0; i < bytes_read; ++i) {
            if (buf[i] == '\n') {
                while (!line_buf.empty() && line_buf.back() == '\r')
                    line_buf.pop_back();
                ctx.write_output(std::format("stdout|{}", line_buf));
                line_buf.clear();
            } else {
                line_buf += buf[i];
            }
        }
    }

    // Flush remaining
    if (!line_buf.empty()) {
        while (!line_buf.empty() && (line_buf.back() == '\r' || line_buf.back() == '\n'))
            line_buf.pop_back();
        if (!line_buf.empty())
            ctx.write_output(std::format("stdout|{}", line_buf));
    }

    DWORD exit_code = 0;
    GetExitCodeProcess(proc_handle, &exit_code);

    ctx.write_output(std::format("exit_code|{}", static_cast<int>(exit_code)));
    if (timed_out) {
        ctx.write_output("status|timeout");
        return 1;
    }
    ctx.write_output(exit_code == 0 ? "status|ok" : "status|error");
    return exit_code == 0 ? 0 : 1;
}

int run_process_win(yuzu::CommandContext& ctx, const std::string& cmd_line, int timeout_secs) {
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;

    HANDLE stdout_read = nullptr;
    HANDLE stdout_write = nullptr;
    if (!CreatePipe(&stdout_read, &stdout_write, &sa, 0)) {
        ctx.write_output("status|error");
        ctx.write_output("exit_code|-1");
        return 1;
    }
    SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.hStdOutput = stdout_write;
    si.hStdError = stdout_write;
    si.dwFlags |= STARTF_USESTDHANDLES;

    PROCESS_INFORMATION pi{};

    // CreateProcessA needs a mutable buffer
    std::vector<char> cmd_buf(cmd_line.begin(), cmd_line.end());
    cmd_buf.push_back('\0');

    if (!CreateProcessA(nullptr, cmd_buf.data(), nullptr, nullptr,
                        TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(stdout_read);
        CloseHandle(stdout_write);
        ctx.write_output("status|error");
        ctx.write_output("exit_code|-1");
        return 1;
    }

    CloseHandle(stdout_write);  // Close write end in parent

    int result = stream_from_handle(ctx, stdout_read, pi.hProcess, timeout_secs);

    CloseHandle(stdout_read);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return result;
}

#else  // POSIX

int run_process_posix(yuzu::CommandContext& ctx,
                      const std::vector<std::string>& argv,
                      int timeout_secs) {
    int pipe_fd[2];
    if (pipe(pipe_fd) != 0) {
        ctx.write_output("status|error");
        ctx.write_output("exit_code|-1");
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        ctx.write_output("status|error");
        ctx.write_output("exit_code|-1");
        return 1;
    }

    if (pid == 0) {
        // Child
        close(pipe_fd[0]);
        dup2(pipe_fd[1], STDOUT_FILENO);
        dup2(pipe_fd[1], STDERR_FILENO);
        close(pipe_fd[1]);

        // Build argv for execvp
        std::vector<const char*> c_argv;
        for (const auto& arg : argv) {
            c_argv.push_back(arg.c_str());
        }
        c_argv.push_back(nullptr);

        execvp(c_argv[0], const_cast<char* const*>(c_argv.data()));
        _exit(127);  // exec failed
    }

    // Parent
    close(pipe_fd[1]);

    // Set read end to non-blocking
    int flags = fcntl(pipe_fd[0], F_GETFL, 0);
    fcntl(pipe_fd[0], F_SETFL, flags | O_NONBLOCK);

    auto start = std::chrono::steady_clock::now();
    bool timed_out = false;
    std::string line_buf;
    std::array<char, 512> buf{};

    while (true) {
        auto elapsed = std::chrono::steady_clock::now() - start;
        if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() >= timeout_secs) {
            timed_out = true;
            kill(pid, SIGKILL);
            break;
        }

        auto n = read(pipe_fd[0], buf.data(), buf.size());
        if (n > 0) {
            for (ssize_t i = 0; i < n; ++i) {
                if (buf[i] == '\n') {
                    while (!line_buf.empty() && line_buf.back() == '\r')
                        line_buf.pop_back();
                    ctx.write_output(std::format("stdout|{}", line_buf));
                    line_buf.clear();
                } else {
                    line_buf += buf[i];
                }
            }
        } else if (n == 0) {
            break;  // EOF
        } else {
            // EAGAIN — no data yet, brief sleep
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct timespec ts = {0, 10'000'000};  // 10ms
                nanosleep(&ts, nullptr);
                continue;
            }
            break;  // Real error
        }
    }

    close(pipe_fd[0]);

    // Flush remaining
    if (!line_buf.empty()) {
        while (!line_buf.empty() && (line_buf.back() == '\r' || line_buf.back() == '\n'))
            line_buf.pop_back();
        if (!line_buf.empty())
            ctx.write_output(std::format("stdout|{}", line_buf));
    }

    int status = 0;
    waitpid(pid, &status, 0);
    int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

    ctx.write_output(std::format("exit_code|{}", exit_code));
    if (timed_out) {
        ctx.write_output("status|timeout");
        return 1;
    }
    ctx.write_output(exit_code == 0 ? "status|ok" : "status|error");
    return exit_code == 0 ? 0 : 1;
}

#endif

// ── Split a string into arguments (simple whitespace split) ────────────

std::vector<std::string> split_args(std::string_view s) {
    std::vector<std::string> result;
    std::string current;
    bool in_quote = false;
    char quote_char = 0;

    for (size_t i = 0; i < s.size(); ++i) {
        char ch = s[i];
        if (in_quote) {
            if (ch == quote_char) {
                in_quote = false;
            } else {
                current += ch;
            }
        } else if (ch == '"' || ch == '\'') {
            in_quote = true;
            quote_char = ch;
        } else if (ch == ' ' || ch == '\t') {
            if (!current.empty()) {
                result.push_back(std::move(current));
                current.clear();
            }
        } else {
            current += ch;
        }
    }
    if (!current.empty()) {
        result.push_back(std::move(current));
    }
    return result;
}

// ── exec action ────────────────────────────────────────────────────────────

int do_exec(yuzu::CommandContext& ctx, yuzu::Params params) {
    auto command = std::string(params.get("command"));
    if (command.empty()) {
        ctx.write_output("error|'command' parameter is required");
        return 1;
    }

    auto args_str = std::string(params.get("args"));
    int timeout = parse_timeout(params);

#ifdef _WIN32
    // On Windows, build a command line string for CreateProcess
    // The program path and args are kept separate — no shell interpretation
    std::string cmd_line = command;
    if (!args_str.empty()) {
        cmd_line += " " + args_str;
    }
    return run_process_win(ctx, cmd_line, timeout);
#else
    // On POSIX, use execvp with an argv array — no shell interpretation
    std::vector<std::string> argv;
    argv.push_back(command);
    if (!args_str.empty()) {
        auto extra = split_args(args_str);
        argv.insert(argv.end(), extra.begin(), extra.end());
    }
    return run_process_posix(ctx, argv, timeout);
#endif
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

    // Use -EncodedCommand with Base64-encoded UTF-16LE to avoid all escaping issues.
    // This prevents any shell metacharacter injection.
    std::vector<uint8_t> utf16le;
    utf16le.reserve(script.size() * 2);
    for (char ch : script) {
        utf16le.push_back(static_cast<uint8_t>(ch));
        utf16le.push_back(0);  // High byte (ASCII → UTF-16LE)
    }

    // Base64 encode
    DWORD b64_len = 0;
    CryptBinaryToStringA(utf16le.data(), static_cast<DWORD>(utf16le.size()),
                         CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                         nullptr, &b64_len);
    std::string b64(b64_len, '\0');
    CryptBinaryToStringA(utf16le.data(), static_cast<DWORD>(utf16le.size()),
                         CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                         b64.data(), &b64_len);
    b64.resize(b64_len);

    auto cmd_line = std::format(
        "powershell.exe -NoProfile -NonInteractive -EncodedCommand {}", b64);

    return run_process_win(ctx, cmd_line, timeout);
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

    // Pass script as a single argument to bash -c via execvp (no shell expansion)
    std::vector<std::string> argv = {"/bin/bash", "-c", script};
    return run_process_posix(ctx, argv, timeout);
#endif
}

}  // namespace

class ScriptExecPlugin final : public yuzu::Plugin {
public:
    std::string_view name()        const noexcept override { return "script_exec"; }
    std::string_view version()     const noexcept override { return "1.1.0"; }
    std::string_view description() const noexcept override {
        return "Executes commands and scripts with streaming output (admin-only)";
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
