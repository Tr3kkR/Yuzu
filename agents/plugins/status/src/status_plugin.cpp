/**
 * status_plugin.cpp - Agent status plugin for Yuzu
 *
 * Actions:
 *   "version"    - Returns agent version, build number, and git commit hash.
 *   "info"       - Returns platform OS, architecture, and hostname.
 *   "health"     - Returns uptime, current timestamp, and memory RSS.
 *   "plugins"    - Returns list of installed plugins with version/description.
 *   "connection" - Returns server address, TLS status, debug mode, verbose.
 *   "config"     - Returns full agent configuration.
 *
 * Output is pipe-delimited, one field per line via write_output():
 *   key|value
 */

#include <yuzu/plugin.hpp>
#include <yuzu/version.hpp>

#include <charconv>
#include <chrono>
#include <format>
#include <string>
#include <string_view>

#if defined(__linux__) || defined(__APPLE__)
#include <sys/utsname.h>
#include <unistd.h>
#endif

#ifdef __linux__
#include <fstream>
#endif

#ifdef __APPLE__
#include <mach/mach.h>
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <psapi.h>
#include <windows.h>
#endif

namespace {

// version action

int do_version(yuzu::CommandContext& ctx) {
    ctx.write_output(std::format("version|{}", yuzu::kFullVersionString));
    ctx.write_output(std::format("build_number|{}", yuzu::kBuildNumber));
    ctx.write_output(std::format("git_commit|{}", yuzu::kGitCommitHash));
    return 0;
}

// info action

int do_info(yuzu::CommandContext& ctx) {
#if defined(__linux__) || defined(__APPLE__)
    struct utsname uts{};
    if (uname(&uts) == 0) {
        ctx.write_output(std::format("os|{}", uts.sysname));
        ctx.write_output(std::format("arch|{}", uts.machine));
    }

    char hostname[256]{};
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        ctx.write_output(std::format("hostname|{}", hostname));
    }

#elif defined(_WIN32)
    ctx.write_output("os|Windows");

    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);
    const char* arch = "unknown";
    switch (si.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64:
        arch = "x86_64";
        break;
    case PROCESSOR_ARCHITECTURE_ARM64:
        arch = "aarch64";
        break;
    case PROCESSOR_ARCHITECTURE_INTEL:
        arch = "x86";
        break;
    case PROCESSOR_ARCHITECTURE_ARM:
        arch = "arm";
        break;
    }
    ctx.write_output(std::format("arch|{}", arch));

    char hostname[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD size = sizeof(hostname);
    if (GetComputerNameA(hostname, &size)) {
        ctx.write_output(std::format("hostname|{}", hostname));
    }

#else
    ctx.write_output("error|platform not supported for info");
    return 1;
#endif
    return 0;
}

// health helpers

long long get_memory_rss_kb() {
#ifdef __linux__
    std::ifstream status("/proc/self/status");
    if (!status)
        return -1;

    std::string line;
    while (std::getline(status, line)) {
        if (line.starts_with("VmRSS:")) {
            long long kb = 0;
            auto pos = line.find_first_of("0123456789");
            if (pos != std::string::npos) {
                auto [ptr, ec] = std::from_chars(line.data() + pos, line.data() + line.size(), kb);
                if (ec == std::errc{})
                    return kb;
            }
            break;
        }
    }
    return -1;

#elif defined(__APPLE__)
    mach_task_basic_info_data_t info{};
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, reinterpret_cast<task_info_t>(&info),
                  &count) == KERN_SUCCESS) {
        return static_cast<long long>(info.resident_size / 1024);
    }
    return -1;

#elif defined(_WIN32)
    PROCESS_MEMORY_COUNTERS pmc{};
    pmc.cb = sizeof(pmc);
    if (K32GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return static_cast<long long>(pmc.WorkingSetSize / 1024);
    }
    return -1;

#else
    return -1;
#endif
}

} // namespace

class StatusPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "status"; }
    std::string_view version() const noexcept override { return yuzu::kVersionString; }
    std::string_view description() const noexcept override {
        return "Reports agent version, system info, health, modules, connection, switch, and "
               "config";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"version",    "info",   "health", "plugins", "modules",
                                     "connection", "switch", "config", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override {
        init_time_ = std::chrono::steady_clock::now();
        // Store the raw YuzuPluginContext* for live config reads during
        // execute(). The C++ PluginContext wrapper is a stack local in the
        // init trampoline, but the underlying YuzuPluginContext* points to
        // the agent's PluginContextImpl which lives for the agent's lifetime.
        // The plugin list is populated after all init() calls complete, so we
        // read it live when actions are invoked rather than caching here.
        raw_plugin_ctx_ = ctx.raw();
        return {};
    }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        if (action == "version")
            return do_version(ctx);
        if (action == "info")
            return do_info(ctx);
        if (action == "health")
            return do_health(ctx);
        if (action == "plugins")
            return do_plugins(ctx);
        if (action == "modules")
            return do_modules(ctx);
        if (action == "connection")
            return do_connection(ctx);
        if (action == "switch")
            return do_switch(ctx);
        if (action == "config")
            return do_config(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
    std::chrono::steady_clock::time_point init_time_{};
    YuzuPluginContext* raw_plugin_ctx_{nullptr};

    std::string_view cfg(std::string_view key) const {
        if (!raw_plugin_ctx_)
            return {};
        const char* val = yuzu_ctx_get_config(raw_plugin_ctx_, std::string{key}.c_str());
        return val ? std::string_view{val} : std::string_view{};
    }

    // plugins action

    int do_plugins(yuzu::CommandContext& ctx) {
        auto count_sv = cfg("agent.plugins.count");
        if (count_sv.empty()) {
            ctx.write_output("plugins_count|0");
            return 0;
        }

        int count = 0;
        std::from_chars(count_sv.data(), count_sv.data() + count_sv.size(), count);
        ctx.write_output(std::format("plugins_count|{}", count));

        for (int i = 0; i < count; ++i) {
            auto prefix = std::format("agent.plugins.{}", i);
            auto pname = cfg(prefix + ".name");
            auto pver = cfg(prefix + ".version");
            auto pdesc = cfg(prefix + ".description");
            ctx.write_output(std::format("plugin|{}|{}|{}", pname, pver, pdesc));
        }

        return 0;
    }

    // connection action

    int do_connection(yuzu::CommandContext& ctx) {
        ctx.write_output(std::format("server_address|{}", cfg("agent.server_address")));

        auto tls = cfg("agent.tls_enabled");
        ctx.write_output(std::format("tls_enabled|{}", tls));
        ctx.write_output(std::format("encrypted|{}", tls == "false" ? "false" : "true"));

        ctx.write_output(std::format("debug_mode|{}", cfg("agent.debug_mode")));
        ctx.write_output(std::format("verbose_logging|{}", cfg("agent.verbose_logging")));
        ctx.write_output(std::format("log_level|{}", cfg("agent.log_level")));

        return 0;
    }

    int do_modules(yuzu::CommandContext& ctx) {
        auto count_sv = cfg("agent.modules.count");
        if (count_sv.empty()) {
            ctx.write_output("modules_count|0");
            return 0;
        }

        int count = 0;
        std::from_chars(count_sv.data(), count_sv.data() + count_sv.size(), count);
        ctx.write_output(std::format("modules_count|{}", count));

        for (int i = 0; i < count; ++i) {
            auto prefix = std::format("agent.modules.{}", i);
            auto name = cfg(prefix + ".name");
            auto version = cfg(prefix + ".version");
            auto status = cfg(prefix + ".status");
            ctx.write_output(std::format("module|{}|{}|{}", name, version, status));

            auto description = cfg(prefix + ".description");
            if (!description.empty()) {
                ctx.write_output(std::format("module_description|{}|{}", name, description));
            }
        }

        return 0;
    }

    int do_switch(yuzu::CommandContext& ctx) {
        ctx.write_output(std::format("switch_address|{}", cfg("agent.server_address")));
        ctx.write_output(std::format("session_id|{}", cfg("agent.session_id")));
        ctx.write_output(std::format("connected_since|{}", cfg("agent.connected_since")));
        ctx.write_output(std::format("reconnect_count|{}", cfg("agent.reconnect_count")));
        return 0;
    }

    // config action

    int do_config(yuzu::CommandContext& ctx) {
        ctx.write_output(std::format("agent_id|{}", cfg("agent.id")));
        ctx.write_output(std::format("agent_version|{}", cfg("agent.version")));
        ctx.write_output(std::format("build_number|{}", cfg("agent.build_number")));
        ctx.write_output(std::format("git_commit|{}", cfg("agent.git_commit")));
        ctx.write_output(std::format("server_address|{}", cfg("agent.server_address")));
        ctx.write_output(std::format("tls_enabled|{}", cfg("agent.tls_enabled")));
        ctx.write_output(std::format("heartbeat_interval|{}", cfg("agent.heartbeat_interval")));
        ctx.write_output(std::format("plugin_dir|{}", cfg("agent.plugin_dir")));
        ctx.write_output(std::format("data_dir|{}", cfg("agent.data_dir")));
        ctx.write_output(std::format("log_level|{}", cfg("agent.log_level")));
        ctx.write_output(std::format("debug_mode|{}", cfg("agent.debug_mode")));
        ctx.write_output(std::format("verbose_logging|{}", cfg("agent.verbose_logging")));
        return 0;
    }

    // health action

    int do_health(yuzu::CommandContext& ctx) {
        auto now = std::chrono::steady_clock::now();
        auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - init_time_).count();
        ctx.write_output(std::format("uptime_seconds|{}", uptime));

        auto sys_now = std::chrono::system_clock::now();
        auto epoch_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(sys_now.time_since_epoch())
                .count();
        ctx.write_output(std::format("timestamp_epoch_ms|{}", epoch_ms));

        auto rss = get_memory_rss_kb();
        if (rss >= 0) {
            ctx.write_output(std::format("memory_rss_kb|{}", rss));
        }

        return 0;
    }
};

YUZU_PLUGIN_EXPORT(StatusPlugin)
