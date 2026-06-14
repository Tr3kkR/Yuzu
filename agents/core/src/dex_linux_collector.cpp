/**
 * dex_linux_collector.cpp — Linux server DEX collector (Guardian DEX).
 *
 * Linux servers have no event-driven OS signal bus the way Windows does
 * (EvtSubscribe), so the whole Linux DEX observer is a slow-cadence poll loop —
 * the dex_win_poll WinStatePoller shape, except it IS the ISignalObserver (there
 * is no event engine for it to ride alongside). v1 (PR3, the tracer-bullet slice)
 * reads /proc + statvfs and REUSES the existing cross-platform breach + poll-latch
 * + observation builders, so a Linux server lights up the same
 * perf.cpu_sustained / perf.memory_pressure / storage.low buckets as Windows and
 * macOS with ZERO server change (the macOS-collector parity playbook). journald
 * reliability signals (OOM, unit-failure) and os.uptime are the next slices.
 *
 * The pure /proc parsing lives in dex_linux_proc.{hpp,cpp} (tested off-Linux); the
 * statvfs read + the poll thread are the only Linux-only mechanism and live here
 * behind #if defined(__linux__) — an empty TU elsewhere, the dex_macos_collector
 * pattern. proto-free by design (the dex_observer.hpp rationale).
 */

#include <yuzu/agent/dex_observer.hpp>

#if defined(__linux__)

#include "dex_linux_proc.hpp"
#include "dex_perf_breach.hpp" // breach_update, kCpuBreach/kMemoryBreach, *_observation
#include "dex_win_poll.hpp"    // DiskLevel, low_disk_observation, latch_should_emit

#include <sys/statvfs.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <fstream>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>

#include <spdlog/spdlog.h>

namespace yuzu::agent {
namespace {

std::int64_t now_unix() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Read a small /proc pseudo-file whole. /proc/stat, /proc/meminfo and
// /proc/mounts report size 0 but stream their content; they are a few KiB at most
// and must be read in one shot (the parsers expect a complete snapshot).
std::optional<std::string> read_proc_file(const char* path) {
    std::ifstream f(path);
    if (!f.is_open())
        return std::nullopt;
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str(); // possibly empty/partial — the pure parser validates and bails
}

/// The Linux DEX observer: a single owned poll thread (the WinStatePoller
/// lifetime — stop() joins it, the sink is set before the thread starts and
/// cleared after the join, so no callback can outlive the object). All signals
/// reuse the existing pure decision + observation builders, so a Linux server is
/// observed identically to Windows/macOS in the same /dex buckets.
class LinuxDexObserver final : public ISignalObserver {
public:
    ~LinuxDexObserver() override { stop(); }

    bool start(SignalSink sink, std::function<void()> /*on_error*/) override {
        // A poll loop has no async "subscription error" the way EvtSubscribe does,
        // so on_error is accepted for interface parity and never called.
        if (thread_.joinable())
            return true; // already armed (idempotent)
        sink_ = std::move(sink);
        stopping_ = false;
        thread_ = std::thread([this] { run(); });
        spdlog::info("dex_observer(linux): armed — /proc perf + storage poll");
        return true;
    }

    void stop() override {
        {
            std::lock_guard lk(mu_);
            stopping_ = true;
        }
        cv_.notify_all();
        if (thread_.joinable())
            thread_.join();
        sink_ = nullptr;
    }

    int armed_channels() const override { return thread_.joinable() ? 1 : 0; }

private:
    void run() {
        // First poll 60 s after arm (never at-arm — arm-time work delays agent
        // startup), then each source keeps its own cadence. Mirrors WinStatePoller.
        {
            const std::int64_t now = now_unix();
            last_perf_poll_ = now - win::kPerfSampleIntervalSeconds + kFirstPollDelaySeconds;
            last_disk_poll_ = now - kDiskIntervalSeconds + kFirstPollDelaySeconds;
        }
        for (;;) {
            const std::int64_t next = std::min(last_perf_poll_ + win::kPerfSampleIntervalSeconds,
                                               last_disk_poll_ + kDiskIntervalSeconds);
            const auto wait_s =
                std::chrono::seconds(std::max(next - now_unix(), std::int64_t{1}));
            {
                std::unique_lock lk(mu_);
                if (cv_.wait_for(lk, wait_s, [this] { return stopping_; }))
                    return; // stop() requested
            }
            const std::int64_t now = now_unix();
            if (now - last_perf_poll_ >= win::kPerfSampleIntervalSeconds) {
                last_perf_poll_ = now;
                poll_perf();
            }
            if (now - last_disk_poll_ >= kDiskIntervalSeconds) {
                last_disk_poll_ = now;
                poll_disks();
            }
        }
    }

    // Sustained CPU + commit-charge breaches via the SAME hysteresis + builders as
    // Windows (dex_perf_breach). CPU needs two readings for the busy% delta; the
    // first poll (and any unreadable one) only re-baselines — breach_update treats
    // the invalid sample as a gap (the latch holds, no re-fire). Emission is
    // bounded by the sustain/recover windows, so no rate cap is needed.
    void poll_perf() {
        bool cpu_valid = false;
        double cpu_pct = 0.0;
        if (const auto stat = read_proc_file("/proc/stat")) {
            const lnx::CpuJiffies cur = lnx::parse_proc_stat(*stat);
            if (const auto pct = lnx::cpu_busy_pct(prev_cpu_, cur)) {
                cpu_pct = *pct;
                cpu_valid = true;
            }
            prev_cpu_ = cur; // baseline the next interval (even if this one was invalid)
        } else {
            prev_cpu_ = lnx::CpuJiffies{}; // unreadable — drop the baseline
        }
        if (const auto avg = win::breach_update(cpu_breach_, cpu_pct, cpu_valid, win::kCpuBreach))
            emit(win::cpu_sustained_observation(*avg));

        // Commit charge vs commit limit — Linux's direct analogue of the Windows
        // commit/limit signal, so memory_pressure_observation's "commit charge …
        // of limit" wording is correct, not relabelled.
        bool mem_valid = false;
        double mem_pct = 0.0;
        if (const auto mem = read_proc_file("/proc/meminfo")) {
            if (const auto pct = lnx::parse_commit_pct(*mem)) {
                mem_pct = *pct;
                mem_valid = true;
            }
        }
        if (const auto avg =
                win::breach_update(mem_breach_, mem_pct, mem_valid, win::kMemoryBreach))
            emit(win::memory_pressure_observation(*avg));
    }

    // Poll-and-latch storage.low over real local filesystems, via the SAME pure
    // decision functions as Windows. parse_storage_mounts whitelists block-backed
    // fstypes (so no squashfs/snap "100% by design" noise and no statvfs() on a
    // potentially-hung network mount), and a failed statvfs leaves the level
    // invalid → low_disk_observation nullopt → the latch neither emits nor clears
    // (UP-5: a transient read failure must not re-fire). Paths with octal-escaped
    // characters (\040) are statvfs'd as-is and simply skipped if that fails — a
    // rare, safe omission for v1.
    void poll_disks() {
        const auto mounts = read_proc_file("/proc/mounts");
        if (!mounts)
            return;
        for (const auto& m : lnx::parse_storage_mounts(*mounts)) {
            win::DiskLevel level;
            struct statvfs vfs{};
            if (::statvfs(m.path.c_str(), &vfs) == 0 && vfs.f_blocks > 0) {
                const std::uint64_t bs = vfs.f_frsize ? vfs.f_frsize : vfs.f_bsize;
                level.valid = true;
                level.total_bytes = static_cast<std::uint64_t>(vfs.f_blocks) * bs;
                // f_bavail = blocks free to unprivileged users (the "disk is full"
                // signal), not f_bfree which includes the root-reserved slack.
                level.free_bytes = static_cast<std::uint64_t>(vfs.f_bavail) * bs;
            }
            const auto obs = win::low_disk_observation(level, m.path);
            bool& reported = disk_low_reported_[m.path];
            if (win::latch_should_emit(obs.has_value(), level.valid, reported))
                emit(*obs);
        }
    }

    // Stamp platform + delivery time centrally (an empty platform would vanish from
    // the by-OS panel; "linux" is the render token, matching dex_routes os_label).
    void emit(SignalObservation obs) {
        obs.platform = "linux";
        obs.timestamp_unix = now_unix();
        spdlog::info("dex_observer(linux): observed {} subject='{}' reason={}", obs.obs_type,
                     obs.subject, obs.reason);
        try {
            sink_(obs);
        } catch (...) {
            // The sink does a network write — a failure must not kill the poll thread.
        }
    }

    static constexpr std::int64_t kFirstPollDelaySeconds = 60;
    static constexpr std::int64_t kDiskIntervalSeconds = 600; // 10 min (the WinStatePoller cadence)

    std::mutex mu_;
    std::condition_variable cv_;
    bool stopping_ = false;
    std::thread thread_;
    SignalSink sink_; // set before the thread starts, cleared after join — stable in run()
    std::int64_t last_perf_poll_ = 0;
    std::int64_t last_disk_poll_ = 0;
    lnx::CpuJiffies prev_cpu_;                               // valid=false until the first read
    win::BreachState cpu_breach_, mem_breach_;              // sustained-breach latches
    std::unordered_map<std::string, bool> disk_low_reported_; // per-mount storage.low latch
};

} // namespace

std::unique_ptr<ISignalObserver> make_linux_dex_observer() {
    return std::make_unique<LinuxDexObserver>();
}

} // namespace yuzu::agent

#endif // __linux__
