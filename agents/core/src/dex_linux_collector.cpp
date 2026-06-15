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
 * reliability signals (unit-failure, coredump crashes, OOM-kills) ride the same
 * poll loop via dex_linux_journal; os.uptime is a later slice.
 *
 * The pure /proc parsing lives in dex_linux_proc.{hpp,cpp} (tested off-Linux); the
 * statvfs read + the poll thread are the only Linux-only mechanism and live here
 * behind #if defined(__linux__) — an empty TU elsewhere, the dex_macos_collector
 * pattern. proto-free by design (the dex_observer.hpp rationale).
 */

#include <yuzu/agent/dex_observer.hpp>

#if defined(__linux__)

#include "dex_linux_journal.hpp" // parse_journal_line, kMsgId* (journald → DEX)
#include "dex_linux_proc.hpp"
#include "dex_linux_storage.hpp"  // storage_low_observation — the non-PII subject chokepoint
#include "dex_macos_signals.hpp"  // uptime_observation (shared cross-platform os.uptime_report)
#include "dex_perf_breach.hpp"    // breach_update, kCpuBreach/kMemoryBreach, *_observation
#include "dex_win_poll.hpp"       // DiskLevel, latch_should_emit

#include <sys/statvfs.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include <spdlog/spdlog.h>

namespace yuzu::agent {
namespace {

std::int64_t now_unix() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Monotonic seconds for the poll CADENCE only — immune to wall-clock steps (NTP
// step-back, VM snapshot-resume) that would otherwise stall the loop until the old
// stamp is re-passed (Gate-4 UP-12). The emitted observation timestamp still uses
// now_unix() (wall clock) — that one must reflect real time, not uptime.
std::int64_t steady_now() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::steady_clock::now().time_since_epoch())
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
    if (ss.fail() || f.bad()) // empty / errored read — treat as unreadable (review MEDIUM)
        return std::nullopt;
    return ss.str();
}

// RAII for a popen() pipe — pclose on every exit path (the macOS poll_oslog
// pattern). The journalctl command is built from internal constants + the
// journald-generated cursor, never operator input, so there is no shell-injection
// surface.
struct PcloseDeleter {
    void operator()(std::FILE* f) const {
        if (f)
            ::pclose(f);
    }
};
using PipeHandle = std::unique_ptr<std::FILE, PcloseDeleter>;

PipeHandle open_pipe(const std::string& cmd) { return PipeHandle(::popen(cmd.c_str(), "r")); }

// Read one newline-terminated line from a pipe into `out` (newline stripped);
// false at EOF. Accumulates across fgets chunks so a long JSON line is not split.
bool read_pipe_line(std::FILE* f, std::string& out) {
    out.clear();
    char buf[16384];
    while (std::fgets(buf, sizeof(buf), f)) {
        out += buf;
        if (!out.empty() && out.back() == '\n') {
            out.pop_back();
            if (!out.empty() && out.back() == '\r')
                out.pop_back();
            return true;
        }
    }
    return !out.empty(); // a final line with no trailing newline
}

/// The Linux DEX observer: a single owned poll thread (the WinStatePoller
/// lifetime — stop() joins it, the sink is set before the thread starts and
/// cleared after the join, so no callback can outlive the object). All signals
/// reuse the existing pure decision + observation builders, so a Linux server is
/// observed identically to Windows/macOS in the same /dex buckets.
class LinuxDexObserver final : public ISignalObserver {
public:
    ~LinuxDexObserver() override { stop(); }

    bool start(SignalSink sink, std::function<void()> on_error) override {
        if (thread_.joinable())
            return true; // already armed (idempotent)
        sink_ = std::move(sink);
        on_error_ = std::move(on_error); // fired at runtime if /proc becomes unreadable (HIGH-3)
        stopping_ = false;
        thread_ = std::thread([this] { run(); });
        spdlog::info("dex_observer(linux): armed — /proc perf + storage + journald + uptime poll");
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
        on_error_ = nullptr;
    }

    int armed_channels() const override { return thread_.joinable() ? 1 : 0; }

private:
    void run() {
        // First poll 60 s after arm (never at-arm — arm-time work delays agent
        // startup), then each source keeps its own cadence. Mirrors WinStatePoller.
        {
            const std::int64_t now = steady_now();
            last_perf_poll_ = now - win::kPerfSampleIntervalSeconds + kFirstPollDelaySeconds;
            last_disk_poll_ = now - kDiskIntervalSeconds + kFirstPollDelaySeconds;
            last_journald_poll_ = now - kJournaldIntervalSeconds + kFirstPollDelaySeconds;
            last_uptime_poll_ = now - kUptimeIntervalSeconds + kFirstPollDelaySeconds;
        }
        for (;;) {
            const std::int64_t next = std::min({last_perf_poll_ + win::kPerfSampleIntervalSeconds,
                                                last_disk_poll_ + kDiskIntervalSeconds,
                                                last_journald_poll_ + kJournaldIntervalSeconds,
                                                last_uptime_poll_ + kUptimeIntervalSeconds});
            const auto wait_s =
                std::chrono::seconds(std::max(next - steady_now(), std::int64_t{1}));
            {
                std::unique_lock lk(mu_);
                if (cv_.wait_for(lk, wait_s, [this] { return stopping_; }))
                    return; // stop() requested
            }
            const std::int64_t now = steady_now();
            // A poll must NEVER unwind out of this thread (the file invariant): an
            // allocation failure — most likely exactly when measuring memory pressure —
            // would otherwise std::terminate the whole agent. Catch-and-continue keeps
            // the thread alive (so the observer is not silently dead); the next tick
            // re-baselines. (Bounding statvfs against a hung block device is a separate,
            // tracked follow-up — a D-state stall throws nothing to catch here.)
            try {
                if (now - last_perf_poll_ >= win::kPerfSampleIntervalSeconds) {
                    last_perf_poll_ = now;
                    poll_perf();
                }
                if (now - last_disk_poll_ >= kDiskIntervalSeconds) {
                    last_disk_poll_ = now;
                    poll_disks();
                }
                if (now - last_journald_poll_ >= kJournaldIntervalSeconds) {
                    last_journald_poll_ = now;
                    poll_journald();
                }
                if (now - last_uptime_poll_ >= kUptimeIntervalSeconds) {
                    last_uptime_poll_ = now;
                    poll_uptime();
                }
            } catch (const std::exception& e) {
                spdlog::warn("dex_observer(linux): poll iteration failed, continuing: {}",
                             e.what());
            } catch (...) {
                spdlog::warn("dex_observer(linux): poll iteration failed (unknown), continuing");
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
            proc_stat_fail_streak_ = 0; // a good read clears the disarm streak
        } else {
            prev_cpu_ = lnx::CpuJiffies{}; // unreadable — drop the baseline
            // Flag the observer unhealthy only after PERSISTENT failure. The Windows
            // on_error fires on terminal subscription death; a Linux /proc/stat read miss
            // is usually TRANSIENT (a momentary EMFILE, a brief seccomp/mount-ns blip),
            // and the poll thread re-baselines and resumes next tick — so a single miss
            // must NOT latch armed=0 (that produced fleet-wide false-disarm alerts, sre
            // Gate-6). Disarm only after kProcFailDisarmThreshold consecutive misses.
            // (on_error is one-way today; recovery-to-armed is a tracked follow-up.)
            if (++proc_stat_fail_streak_ >= kProcFailDisarmThreshold && on_error_)
                on_error_();
        }
        if (const auto avg = win::breach_update(cpu_breach_, cpu_pct, cpu_valid, win::kCpuBreach))
            emit(win::cpu_sustained_observation(*avg));

        // Commit charge vs commit limit — Linux's direct analogue of the Windows
        // commit/limit signal, so memory_pressure_observation's "commit charge …
        // of limit" wording is correct, not relabelled. SKIPPED under
        // vm.overcommit_memory=1 ("always"): there CommitLimit is advisory and
        // Committed_AS routinely exceeds it on healthy DB/Redis/HPC hosts, so the
        // ratio would false-positive-storm (Gate-4 UP-7). A read failure leaves the
        // signal enabled (fail-safe toward keeping it). Modes 0/2 keep it meaningful.
        bool mem_valid = false;
        double mem_pct = 0.0;
        const auto oc = read_proc_file("/proc/sys/vm/overcommit_memory");
        if (!(oc && lnx::overcommit_is_always(*oc))) {
            if (const auto mem = read_proc_file("/proc/meminfo")) {
                if (const auto pct = lnx::parse_commit_pct(*mem)) {
                    mem_pct = *pct;
                    mem_valid = true;
                }
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
        std::unordered_set<std::string> current;
        for (const auto& m : lnx::parse_storage_mounts(*mounts)) {
            // Latch identity is the backing DEVICE (the dedup key + the subject source),
            // NOT the mount path: keying by path would re-fire a duplicate storage.low for
            // the same device if it is remounted at a different path (UP-8, Gate-4).
            current.insert(m.device);
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
            // Single chokepoint: subject = the backing-device basename, NEVER the mount
            // path (a path carries usernames / tenant / project names — DEX edge-privacy,
            // dex-signal-catalog.md §"Privacy / works-council contract"). m.path is used
            // ONLY for the local statvfs() above; it is never passed to the observation, so
            // it cannot be emitted, serialized, or logged. The [dex][privacy] test guards
            // this exact call.
            const auto obs = lnx::storage_low_observation(m, level);
            bool& reported = disk_low_reported_[m.device];
            if (win::latch_should_emit(obs.has_value(), level.valid, reported))
                emit(*obs);
        }
        // Drop latch entries for devices that have gone away, so the map stays bounded
        // by the live device count, not every device ever seen (review MEDIUM).
        std::erase_if(disk_low_reported_,
                      [&](const auto& kv) { return !current.contains(kv.first); });
    }

    // Poll the systemd journal for new reliability events. The first poll baselines
    // the cursor at the journal tail (no history replay, and no events from the
    // first interval after arm); then each poll reads strictly after it (journalctl
    // --after-cursor is exclusive → no boundary de-dup). MESSAGE_ID matching yields
    // one canonical entry per failure; the `+ _TRANSPORT=kernel` group carries the
    // OOM line (no stable MESSAGE_ID) and is parsed-and-mostly-dropped. No libsystemd:
    // journalctl is a runtime shell-out; on a non-systemd host the shell-out simply
    // yields no output (popen still succeeds via /bin/sh, so the cursor never
    // baselines) and the source quietly no-ops. The cursor advances only after a clean
    // read, so a throw mid-loop re-polls the same window next tick.
    void poll_journald() {
        // Evict debounce entries older than the window FIRST, every cycle: a stamp past
        // the window can no longer suppress anything, so it is pure bloat. This is the
        // age-keyed analogue of poll_disks()'s std::erase_if on disk_low_reported_ —
        // journal events are transient (no live set to diff against), so the bound is
        // time, not a current-set intersection. Keeps journal_dedup_ sized by the
        // trailing-window event count, NOT daemon uptime (sre/consistency Gate-4/6).
        const std::int64_t mono = steady_now();
        std::erase_if(journal_dedup_,
                      [&](const auto& kv) { return mono - kv.second >= kJournaldDebounceSeconds; });
        if (journal_cursor_.empty()) {
            if (const PipeHandle p = open_pipe("journalctl -o json -n 1 --no-pager 2>/dev/null")) {
                std::string line;
                while (read_pipe_line(p.get(), line))
                    if (auto c = lnx::parse_journal_line(line).cursor; !c.empty())
                        journal_cursor_ = std::move(c);
            }
            return; // baselined (or journal unreadable) — emit nothing this tick
        }
        if (journal_cursor_.find('\'') != std::string::npos) {
            journal_cursor_.clear(); // defensive: a cursor never contains a quote — re-baseline
            return;
        }
        const std::string cmd = "journalctl --after-cursor='" + journal_cursor_ +
                                "' -o json --no-pager MESSAGE_ID=" +
                                std::string(lnx::kMsgIdCoredump) +
                                " MESSAGE_ID=" + std::string(lnx::kMsgIdUnitFailed) +
                                " MESSAGE_ID=" + std::string(lnx::kMsgIdUnitResult) +
                                " + _TRANSPORT=kernel 2>/dev/null";
        const PipeHandle pipe = open_pipe(cmd);
        if (!pipe) {
            spdlog::warn("dex_observer(linux): popen(journalctl) failed — journald poll skipped");
            return;
        }
        std::string newest = journal_cursor_;
        std::string line;
        while (read_pipe_line(pipe.get(), line)) {
            lnx::JournalLine jl = lnx::parse_journal_line(line);
            if (!jl.cursor.empty())
                newest = std::move(jl.cursor); // journalctl is chronological → last wins
            if (jl.obs)
                emit_journal(std::move(*jl.obs));
        }
        journal_cursor_ = std::move(newest);
    }

    // Journald-sourced emit with a per-(obs_type, subject) debounce: a flapping unit
    // (Restart= loop) or a crash-looping process collapses to one observation per
    // window instead of flooding the wire. The /proc sources are latch-bounded and
    // skip this.
    void emit_journal(SignalObservation obs) {
        const std::string key = obs.obs_type + "|" + obs.subject;
        // steady_now(): the debounce is a TIMER, not an emitted timestamp. now_unix()
        // here let a backward wall-clock step (NTP correction, VM snapshot-resume) make
        // (now - stamp) negative → < window → a real re-failure silently suppressed for
        // the step's duration (sre Gate-6). Monotonic time cannot step back. The emitted
        // observation's timestamp_unix (in emit()) stays wall-clock — that one is a real
        // time, not a timer.
        const std::int64_t now = steady_now();
        if (const auto it = journal_dedup_.find(key);
            it != journal_dedup_.end() && now - it->second < kJournaldDebounceSeconds)
            return; // within the debounce window — collapse
        journal_dedup_[key] = now;
        emit(std::move(obs));
    }

    // os.uptime_report — the cross-platform uptime/reboot heartbeat (the Windows
    // EventLog 6013 / macOS sysctl-boottime equivalent). Interval-gated (hourly,
    // trendable) and timer-driven, not at-arm. /proc/uptime is unprivileged; boot
    // time = now - uptime, fed to the SAME builder macOS uses so the observation is
    // identical across OSes (parity). Bounded by the cadence — no debounce needed.
    void poll_uptime() {
        const auto txt = read_proc_file("/proc/uptime");
        if (!txt)
            return;
        const auto up = lnx::parse_proc_uptime(*txt);
        if (!up)
            return;
        const std::int64_t now = now_unix();
        if (auto obs = macos::uptime_observation(now - static_cast<std::int64_t>(*up), now))
            emit(std::move(*obs));
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
    static constexpr std::int64_t kDiskIntervalSeconds = 600;     // 10 min (the WinStatePoller cadence)
    static constexpr std::int64_t kJournaldIntervalSeconds = 60;  // reliability events want low latency
    static constexpr std::int64_t kJournaldDebounceSeconds = 300; // collapse a flapping unit/process
    static constexpr std::int64_t kUptimeIntervalSeconds = 3600;  // hourly uptime/reboot heartbeat
    static constexpr int kProcFailDisarmThreshold = 3; // consecutive /proc/stat misses before disarm

    std::mutex mu_;
    std::condition_variable cv_;
    bool stopping_ = false;
    std::thread thread_;
    SignalSink sink_; // set before the thread starts, cleared after join — stable in run()
    std::function<void()> on_error_; // disarms dex_health_ after persistent /proc failure (HIGH-3)
    std::int64_t last_perf_poll_ = 0;
    std::int64_t last_disk_poll_ = 0;
    std::int64_t last_journald_poll_ = 0;
    std::int64_t last_uptime_poll_ = 0;
    int proc_stat_fail_streak_ = 0;                          // consecutive /proc/stat read misses
    lnx::CpuJiffies prev_cpu_;                               // valid=false until the first read
    win::BreachState cpu_breach_, mem_breach_;              // sustained-breach latches
    std::unordered_map<std::string, bool> disk_low_reported_; // per-device storage.low latch
    std::string journal_cursor_;                              // "" until baselined at the journal tail
    std::unordered_map<std::string, std::int64_t> journal_dedup_; // (type|subject) → last journald emit
};

} // namespace

std::unique_ptr<ISignalObserver> make_linux_dex_observer() {
    return std::make_unique<LinuxDexObserver>();
}

} // namespace yuzu::agent

#endif // __linux__
