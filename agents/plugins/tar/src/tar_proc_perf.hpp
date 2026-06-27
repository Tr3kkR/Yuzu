#pragma once

/**
 * tar_proc_perf.hpp — top-N per-process resource sampling for the TAR edge
 * warehouse (BRD A2, docs/dex-brd-coverage.md rows 22/27).
 *
 * Rides the same 30 s collect_perf tick as the A1 device sampler (no new
 * thread, no new trigger): one system-wide process snapshot in, the top-N
 * APPLICATIONS by CPU and by working set out, aggregated by image name
 * (12 chrome.exe processes = one "chrome.exe" row with instances=12 — the
 * BRD asks for app-specific consumption, not per-PID noise; per-PID detail
 * stays on the process_live event trail). Raw rows stay ON-DEVICE
 * (ADR-0004); the hourly tier carries per-app avg/max for trend queries.
 *
 * Windows source — deliberately NOT PDH, NOT WMI: ONE
 * NtQuerySystemInformation(SystemProcessInformation) call returns every
 * process's image name, PID, create time, kernel+user CPU time, and working
 * set, with no per-process handles. CPU% needs two snapshots; the previous
 * one is held in plugin memory keyed by (pid, create_time) so PID reuse never
 * miscounts. Linux (/proc/[pid]/stat) and macOS (proc_pid_rusage) are
 * kPlanned.
 *
 * Version (DEX app-perf-over-time): the per-app `version` is the BOUNDED,
 * deliberate exception to the handle-free posture. SystemProcessInformation
 * carries the image NAME but not its full path, and a file version lives in
 * the on-disk image — so after top-N selection ONLY (<= 2N apps/tick) we
 * OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) the representative instance,
 * resolve its path, and read the version resource. Per-process failure
 * (ACCESS_DENIED on a protected process, no version resource, PID reuse)
 * isolates to version="" and never aborts the tick; a (pid, create_time)
 * cache resolves each process once at first sighting (the version nearest
 * launch — least disk-staleness, ~zero steady-state handle cost). Off-Windows
 * the resolver is a no-op (version stays "").
 *
 * Privacy: only image NAMES + the on-disk file VERSION are recorded — never
 * command lines (the stronger default; cmdlines can carry secrets) and never
 * the image PATH (it can carry a user profile dir). The operator's TAR
 * redaction patterns are additionally applied to the name, so a process an
 * operator redacted from the event trail never appears here either. The
 * whole source sits behind its own `procperf_enabled` toggle
 * (works-council: per-app visibility can be disabled while device-level
 * sampling stays on).
 *
 * The derivation + top-N selection is PURE (derive_proc_samples), as is the
 * shared version normalization (yuzu::util::format_file_version /
 * normalize_ffi_version in <yuzu/version_string.hpp>) — both unit-tested on
 * every host; read_proc_counters() and resolve_proc_versions() are the impure
 * Windows shells.
 */

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::tar {

/// One process's raw counters at an instant. `cpu_100ns` is CUMULATIVE
/// kernel+user time since process start; `ws_bytes` is instantaneous.
/// (pid, create_time_100ns) is the identity key — PID alone is reused.
struct ProcCounter {
    std::uint32_t pid{0};
    std::int64_t create_time_100ns{0};
    std::uint64_t cpu_100ns{0};
    std::uint64_t ws_bytes{0};
    std::string name; ///< image name, UTF-8 (no path, no cmdline)
};

/// One system-wide snapshot.
struct ProcSnapshot {
    bool valid{false};
    std::int64_t ts_epoch{0};
    int ncores{0}; ///< logical processors — the CPU%% denominator
    std::vector<ProcCounter> procs;
};

/// One derived per-APPLICATION sample (aggregated across same-name
/// processes). `cpu_pct` is the app's share of TOTAL machine capacity
/// (all cores — one saturated core on an 8-core box reads 12.5, matching
/// the device sampler's denominator and Task Manager).
struct ProcPerfSample {
    std::string name;
    std::string version; ///< on-disk file version "a.b.c.d"; "" until resolved / off-Windows
    int instances{0};
    double cpu_pct{0.0};
    std::int64_t ws_bytes{0}; ///< summed working set across instances
    /// The largest-working-set instance, used as the representative for version
    /// resolution. create_time guards against PID reuse between snapshot and
    /// resolution. Set by derive_proc_samples; read by resolve_proc_versions.
    std::uint32_t rep_pid{0};
    std::int64_t rep_create_time_100ns{0};
};

/// Top-N size per dimension. The recorded set is the UNION of the top N by
/// CPU and the top N by working set (<= 2N rows per tick) — a memory hog
/// that's CPU-idle stays visible and vice versa.
inline constexpr int kProcTopN = 10;

/// PURE: derive the per-app top-N from two snapshots. Empty when either
/// snapshot is invalid, elapsed <= 0, or ncores <= 0. A process absent from
/// `prev` (new, or PID reused — different create_time) contributes 0 CPU
/// this interval (it baselines; its working set still counts). A CPU
/// counter regression saturates to 0, never wraps. Names matching a
/// redaction pattern are skipped entirely.
std::vector<ProcPerfSample> derive_proc_samples(const ProcSnapshot& prev,
                                                const ProcSnapshot& cur,
                                                const std::vector<std::string>& redaction);

/// Impure shell: snapshot the current per-process counters. valid=false off
/// Windows until the Linux/macOS collectors land (registry: kPlanned).
ProcSnapshot read_proc_counters();

/// PURE: the (pid, create_time) identity key — PID alone is reused by the OS.
/// Shared by the CPU-baseline lookup and the version cache so both agree.
std::uint64_t proc_identity(std::uint32_t pid, std::int64_t create_time_100ns);

// Version formatting/normalization is shared with the crash-side extractor and
// the server projection — see <yuzu/version_string.hpp> (format_file_version /
// normalize_ffi_version / canon_version), so all three producers of the
// (name, version) identity emit byte-identical canonical strings.

/// Impure shell: annotate each sample's `version` from its representative
/// process (Windows OpenProcess + file-version resource read). `cache` maps a
/// (pid, create_time) identity → version so a process resolves once while it
/// stays in the top-N; the cache is rewritten to this tick's live set on each
/// call (bounded to <= 2N entries). Per-process failure isolates to
/// version="". No-op off Windows (versions stay "").
void resolve_proc_versions(std::vector<ProcPerfSample>& samples,
                           std::unordered_map<std::uint64_t, std::string>& cache);

} // namespace yuzu::tar
