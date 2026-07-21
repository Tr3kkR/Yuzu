/**
 * network_actions_plugin.cpp — Network action plugin for Yuzu
 *
 * Actions:
 *   "flush_dns" — Flush the DNS resolver cache.
 *   "ping"      — Ping a host (params: host, count).
 *
 * Output is pipe-delimited via write_output().
 */

#include <yuzu/plugin.hpp>

#include <array>
#include <cctype>
#include <cstdio>
#include <format>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>

#if defined(__APPLE__)
#include <sys/wait.h> // WIFEXITED / WEXITSTATUS for honest flush_dns status
#include <unistd.h>   // geteuid() — EUID-aware sudo prefix
#endif

namespace {

#if defined(_WIN32) || defined(__linux__)
// Fire-and-report-output command runner used by the Windows/Linux flush_dns
// branches. Guarded to those platforms: the macOS branch uses
// run_command_status below (which also captures the exit code), so on Darwin
// this function has no caller and would trip -Wunused-function at warning_level=3.
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
#endif

#if defined(__APPLE__)
// EUID-aware sudo prefix (see docs/agent-privilege-model.md; mirrors
// quarantine_plugin.cpp's sudo_prefix). The macOS agent's production
// LaunchDaemon runs as root → empty prefix (no useless round-trip). The
// documented unprivileged `_yuzu` dev account instead relies on the NOPASSWD
// grants installed by scripts/install-agent-user.sh, so it must invoke the
// privileged binaries through `sudo -n` — the `-n` fails fast with a clear
// error if the grant is missing, rather than hanging on a password prompt the
// daemon cannot answer. EUID cannot change during the agent's lifetime, so the
// result is computed once.
const char* sudo_prefix() {
    static const char* prefix = (geteuid() == 0) ? "" : "sudo -n ";
    return prefix;
}

// Run a command and return the child's exit status (0 = success, non-zero =
// failure, -1 = spawn/abnormal), filling `out` with captured stdout+stderr. The
// plain run_command above discards the exit code, so macOS flush_dns used to
// report a blind status|ok even when the flush actually failed. macOS is the
// only caller, so this is guarded to avoid an unused-function warning elsewhere.
//
// The FILE* is held by an RAII owner so an exception thrown by the read loop
// (string growth → bad_alloc) still closes the pipe and reaps the child
// (docs/cpp-conventions.md resource-ownership rule; precedent
// dex_macos_collector.cpp). On the normal path ownership is reclaimed via
// release() so pclose's status can be read.
int run_command_status(const std::string& cmd, std::string& out) {
    out.clear();
    std::unique_ptr<FILE, decltype(&::pclose)> pipe(::popen(cmd.c_str(), "r"), &::pclose);
    if (!pipe)
        return -1;
    std::array<char, 256> buf{};
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe.get())) {
        out += buf.data();
    }
    int status = ::pclose(pipe.release());
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r'))
        out.pop_back();
    if (status == -1)
        return -1;
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return -1; // killed by signal / abnormal
}
#endif

bool is_safe_host(std::string_view host) {
    if (host.empty() || host.size() > 253)
        return false;
    for (char c : host) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '-' && c != ':') {
            return false;
        }
    }
    return true;
}

} // namespace

class NetworkActionsPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "network_actions"; }
    std::string_view version() const noexcept override { return "0.1.0"; }
    std::string_view description() const noexcept override {
        return "Network actions — DNS flush and ping";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"flush_dns", "ping", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }
    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {

        if (action == "flush_dns") {
#ifdef _WIN32
            auto output = run_command("ipconfig /flushdns");
            ctx.write_output("status|ok");
            ctx.write_output(std::format("output|{}", output));
            return 0;
#elif defined(__linux__)
            auto output = run_command("resolvectl flush-caches 2>/dev/null || "
                                      "systemd-resolve --flush-caches 2>/dev/null || true");
            ctx.write_output("status|ok");
            ctx.write_output(std::format("output|{}", output));
            return 0;
#elif defined(__APPLE__)
            // A real macOS DNS flush is two steps: dscacheutil clears the
            // dscacheutil-visible cache, and the SIGHUP to mDNSResponder is what
            // actually resets the resolver — dscacheutil -flushcache alone is
            // insufficient on modern macOS. Both need root: the production
            // LaunchDaemon runs as root (empty prefix), while the documented
            // unprivileged _yuzu dev account reaches them through the `sudo -n`
            // NOPASSWD grants that install-agent-user.sh installs for exactly
            // these two commands. Absolute paths per the PATH-injection
            // discipline. Report status from the real exit codes, never a blind
            // status|ok.
            const std::string sudo = sudo_prefix();
            std::string out1, out2;
            int rc1 = run_command_status(sudo + "/usr/bin/dscacheutil -flushcache 2>&1", out1);
            int rc2 = run_command_status(sudo + "/usr/bin/killall -HUP mDNSResponder 2>&1", out2);
            bool ok = (rc1 == 0) && (rc2 == 0);
            ctx.write_output(std::format("status|{}", ok ? "ok" : "error"));
            ctx.write_output(
                std::format("output|dscacheutil rc={} mDNSResponder rc={}", rc1, rc2));
            if (!ok) {
                // Surface the captured command output (e.g. "sudo: a password is
                // required" when the _yuzu grant is missing) so a failed flush is
                // diagnosable. Collapse newlines/pipes to preserve the
                // pipe-delimited, one-line-per-record output protocol.
                auto flatten = [](std::string s) {
                    for (char& c : s)
                        if (c == '\n' || c == '\r' || c == '|')
                            c = ' ';
                    return s;
                };
                if (!out1.empty())
                    ctx.write_output(std::format("detail|dscacheutil: {}", flatten(out1)));
                if (!out2.empty())
                    ctx.write_output(std::format("detail|mDNSResponder: {}", flatten(out2)));
            }
            return ok ? 0 : 1;
#else
            // Previously reported status|ok on unsupported platforms — a lie.
            ctx.write_output("status|error");
            ctx.write_output("output|unsupported platform");
            return 1;
#endif
        }

        if (action == "ping") {
            auto host = params.get("host");
            if (host.empty()) {
                ctx.write_output("error|missing required parameter: host");
                return 1;
            }
            if (!is_safe_host(host)) {
                ctx.write_output("error|invalid host characters");
                return 1;
            }

            auto count = params.get("count", "4");
            // Validate count is numeric
            for (char c : count) {
                if (!std::isdigit(static_cast<unsigned char>(c))) {
                    ctx.write_output("error|count must be numeric");
                    return 1;
                }
            }

#ifdef _WIN32
            auto cmd = std::format("ping -n {} {}", count, host);
#else
            auto cmd = std::format("ping -c {} {}", count, host);
#endif
            std::string result;
            std::array<char, 256> buf{};
            int exit_code = 0;
#ifdef _WIN32
            FILE* pipe = _popen(cmd.c_str(), "r");
#else
            FILE* pipe = popen(cmd.c_str(), "r");
#endif
            if (!pipe) {
                ctx.write_output("error|failed to execute ping");
                return 1;
            }
            while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
                std::string line(buf.data());
                while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
                    line.pop_back();
                if (!line.empty()) {
                    ctx.write_output(std::format("output|{}", line));
                }
            }
#ifdef _WIN32
            exit_code = _pclose(pipe);
#else
            exit_code = pclose(pipe);
#endif
            return exit_code;
        }

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(NetworkActionsPlugin)
