/**
 * status_plugin.cpp — Agent status plugin for Yuzu
 *
 * Actions:
 *   "version" — Returns agent version, build number, and git commit hash.
 *   "info"    — Returns platform OS, architecture, and hostname.
 *   "health"  — Returns uptime, current timestamp, and memory RSS.
 *
 * Output is pipe-delimited, one field per line via write_output():
 *   key|value
 */

#include <yuzu/plugin.hpp>
#include <yuzu/version.hpp>

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
#include <windows.h>
#include <psapi.h>
#endif

namespace {

// ── version action ──────────────────────────────────────────────────────────

int do_version(yuzu::CommandContext& ctx) {
    ctx.write_output(std::format("version|{}", yuzu::kFullVersionString));
    ctx.write_output(std::format("build_number|{}", yuzu::kBuildNumber));
    ctx.write_output(std::format("git_commit|{}", yuzu::kGitCommitHash));
    return 0;
}

// ── info action ─────────────────────────────────────────────────────────────

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
        case PROCESSOR_ARCHITECTURE_AMD64: arch = "x86_64"; break;
        case PROCESSOR_ARCHITECTURE_ARM64: arch = "aarch64"; break;
        case PROCESSOR_ARCHITECTURE_INTEL: arch = "x86"; break;
        case PROCESSOR_ARCHITECTURE_ARM:   arch = "arm"; break;
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

// ── health action ───────────────────────────────────────────────────────────

long long get_memory_rss_kb() {
#ifdef __linux__
    std::ifstream status("/proc/self/status");
    if (!status) return -1;

    std::string line;
    while (std::getline(status, line)) {
        if (line.starts_with("VmRSS:")) {
            // Format: "VmRSS:    12345 kB"
            long long kb = 0;
            auto pos = line.find_first_of("0123456789");
            if (pos != std::string::npos) {
                auto [ptr, ec] = std::from_chars(
                    line.data() + pos,
                    line.data() + line.size(),
                    kb);
                if (ec == std::errc{}) return kb;
            }
            break;
        }
    }
    return -1;

#elif defined(__APPLE__)
    mach_task_basic_info_data_t info{};
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                  reinterpret_cast<task_info_t>(&info), &count) == KERN_SUCCESS) {
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

}  // namespace

class StatusPlugin final : public yuzu::Plugin {
public:
    std::string_view name()        const noexcept override { return "status"; }
    std::string_view version()     const noexcept override { return yuzu::kVersionString; }
    std::string_view description() const noexcept override {
        return "Reports agent version, system info, and health metrics";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"version", "info", "health", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override {
        init_time_ = std::chrono::steady_clock::now();
        return {};
    }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx,
                std::string_view action,
                yuzu::Params /*params*/) override {
        if (action == "version") return do_version(ctx);
        if (action == "info")    return do_info(ctx);
        if (action == "health")  return do_health(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
    std::chrono::steady_clock::time_point init_time_{};

    int do_health(yuzu::CommandContext& ctx) {
        auto now = std::chrono::steady_clock::now();
        auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
            now - init_time_).count();
        ctx.write_output(std::format("uptime_seconds|{}", uptime));

        auto sys_now = std::chrono::system_clock::now();
        auto epoch_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            sys_now.time_since_epoch()).count();
        ctx.write_output(std::format("timestamp_epoch_ms|{}", epoch_ms));

        auto rss = get_memory_rss_kb();
        if (rss >= 0) {
            ctx.write_output(std::format("memory_rss_kb|{}", rss));
        }

        return 0;
    }
};

YUZU_PLUGIN_EXPORT(StatusPlugin)
