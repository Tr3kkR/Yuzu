#pragma once

/// process_health.hpp — Cross-platform server process health sampler.
///
/// Provides CPU usage (percent), RSS, and VSS for the current process.
/// Thread-safe: sample() may be called from multiple threads concurrently.

#include <chrono>
#include <cmath>
#include <cstdint>
#include <mutex>

#ifdef __linux__
#include <fstream>
#include <string>
#include <unistd.h>
#elif defined(__APPLE__)
#include <mach/mach.h>
#include <sys/resource.h>
#elif defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <psapi.h>
#endif

namespace yuzu::server::detail {

struct ProcessHealth {
    double cpu_percent{0.0};
    int64_t memory_rss_bytes{0};
    int64_t memory_vss_bytes{0};
};

class ProcessHealthSampler {
public:
    ProcessHealthSampler() {
        // Capture initial snapshot
        std::lock_guard lock(mu_);
        prev_wall_ = std::chrono::steady_clock::now();
        prev_cpu_seconds_ = read_cpu_seconds();
    }

    ProcessHealth sample() {
        std::lock_guard lock(mu_);
        ProcessHealth h;

        // CPU delta
        auto now = std::chrono::steady_clock::now();
        double cpu_now = read_cpu_seconds();
        double wall_delta = std::chrono::duration<double>(now - prev_wall_).count();

        if (wall_delta > 0.01) {
            double cpu_delta = cpu_now - prev_cpu_seconds_;
            h.cpu_percent = (cpu_delta / wall_delta) * 100.0;
            // Clamp: negative or non-finite values become 0
            if (h.cpu_percent < 0.0 || !std::isfinite(h.cpu_percent))
                h.cpu_percent = 0.0;
            prev_wall_ = now;
            prev_cpu_seconds_ = cpu_now;
        }

        // Memory
        read_memory(h.memory_rss_bytes, h.memory_vss_bytes);
        return h;
    }

private:
    std::mutex mu_;
    std::chrono::steady_clock::time_point prev_wall_;
    double prev_cpu_seconds_{0.0};

    static double read_cpu_seconds() {
#ifdef __linux__
        std::ifstream stat("/proc/self/stat");
        if (!stat)
            return 0.0;
        std::string token;
        // Skip fields 1 (pid) and 2 (comm — may contain spaces, enclosed in parens)
        stat >> token; // pid
        // Read until closing ')'
        char c = 0;
        while (stat.get(c) && c != ')') {}
        // Fields 3..13 are single tokens we skip (state, ppid, pgrp, session, tty, etc.)
        for (int i = 3; i <= 13; ++i)
            stat >> token;
        // Fields 14 (utime) and 15 (stime) are in clock ticks
        long long utime = 0, stime = 0;
        stat >> utime >> stime;
        static long ticks_per_sec = sysconf(_SC_CLK_TCK);
        if (ticks_per_sec <= 0)
            ticks_per_sec = 100;
        return static_cast<double>(utime + stime) / static_cast<double>(ticks_per_sec);

#elif defined(__APPLE__)
        struct rusage ru {};
        if (getrusage(RUSAGE_SELF, &ru) != 0)
            return 0.0;
        double user = static_cast<double>(ru.ru_utime.tv_sec) +
                      static_cast<double>(ru.ru_utime.tv_usec) / 1e6;
        double sys = static_cast<double>(ru.ru_stime.tv_sec) +
                     static_cast<double>(ru.ru_stime.tv_usec) / 1e6;
        return user + sys;

#elif defined(_WIN32)
        FILETIME ct, et, kt, ut;
        if (!GetProcessTimes(GetCurrentProcess(), &ct, &et, &kt, &ut))
            return 0.0;
        auto to_seconds = [](const FILETIME& ft) -> double {
            ULARGE_INTEGER li;
            li.LowPart = ft.dwLowDateTime;
            li.HighPart = ft.dwHighDateTime;
            return static_cast<double>(li.QuadPart) / 1e7; // 100ns units
        };
        return to_seconds(kt) + to_seconds(ut);

#else
        return 0.0;
#endif
    }

    static void read_memory(int64_t& rss_bytes, int64_t& vss_bytes) {
#ifdef __linux__
        std::ifstream status("/proc/self/status");
        if (!status)
            return;
        std::string line;
        while (std::getline(status, line)) {
            auto parse_kb = [&](const char* prefix, int64_t& out) {
                if (line.starts_with(prefix)) {
                    auto pos = line.find_first_of("0123456789");
                    if (pos != std::string::npos) {
                        long long kb = 0;
                        auto [ptr, ec] = std::from_chars(
                            line.data() + pos, line.data() + line.size(), kb);
                        if (ec == std::errc{})
                            out = kb * 1024;
                    }
                }
            };
            parse_kb("VmRSS:", rss_bytes);
            parse_kb("VmSize:", vss_bytes);
        }

#elif defined(__APPLE__)
        mach_task_basic_info_data_t info{};
        mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
        if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                      reinterpret_cast<task_info_t>(&info), &count) == KERN_SUCCESS) {
            rss_bytes = static_cast<int64_t>(info.resident_size);
            vss_bytes = static_cast<int64_t>(info.virtual_size);
        }

#elif defined(_WIN32)
        PROCESS_MEMORY_COUNTERS pmc{};
        pmc.cb = sizeof(pmc);
        if (K32GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
            rss_bytes = static_cast<int64_t>(pmc.WorkingSetSize);
            vss_bytes = static_cast<int64_t>(pmc.PagefileUsage);
        }

#else
        (void)rss_bytes;
        (void)vss_bytes;
#endif
    }
};

} // namespace yuzu::server::detail
