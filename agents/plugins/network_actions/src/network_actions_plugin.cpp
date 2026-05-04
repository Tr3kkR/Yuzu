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
#include <sstream>
#include <string>
#include <string_view>

namespace {

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
#elif defined(__linux__)
            auto output = run_command("resolvectl flush-caches 2>/dev/null || "
                                      "systemd-resolve --flush-caches 2>/dev/null || true");
#elif defined(__APPLE__)
            auto output = run_command("dscacheutil -flushcache");
#else
            std::string output = "unsupported platform";
#endif
            ctx.write_output("status|ok");
            ctx.write_output(std::format("output|{}", output));
            return 0;
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
