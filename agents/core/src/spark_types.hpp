#pragma once

/**
 * spark_types.hpp — internal per-type spark logic, shared between the
 * SparkEngine's timer wheel and the unit tests.
 *
 * Each timer-scheduled spark type owns a small `*_process_due` function in its
 * own translation unit (spark_interval.cpp / spark_startup.cpp /
 * spark_disk.cpp): given the spec's params and the spark's mutable per-arm
 * state, decide whether to emit and when to run next. The functions are PURE
 * apart from the injected disk reader — no engine, no threads — so every
 * emission edge is unit-testable without arming anything (the guard_systemd
 * `systemd_decide_emit` pattern).
 *
 * Event-driven mechanisms (file / registry / service) do not process on the
 * wheel and land in later PRs with their own internals.
 */

#include <yuzu/plugin.h>      // YUZU_EXPORT
#include <yuzu/agent/spark.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>

namespace yuzu::agent {

/// What a `*_process_due` call decided for one due tick.
struct SparkFireDecision {
    bool emit{false};
    SparkData data{};
    /// Next wheel deadline; nullopt = one-shot complete (never scheduled again).
    std::optional<std::chrono::steady_clock::time_point> reschedule;
};

// ── interval ──────────────────────────────────────────────────────────────────

/// Interval tick: always emits, reschedules one interval out. `interval_ms` is
/// the engine-floored effective cadence (flooring happens once at arm, not here).
[[nodiscard]] YUZU_EXPORT SparkFireDecision
interval_process_due(std::uint64_t interval_ms, std::chrono::steady_clock::time_point now);

// ── startup ───────────────────────────────────────────────────────────────────

/// Startup tick: emits exactly once, never reschedules.
[[nodiscard]] YUZU_EXPORT SparkFireDecision startup_process_due();

// ── disk ──────────────────────────────────────────────────────────────────────

/// True when a VALID reading is in the bad state: used% >= threshold OR
/// free < min_free_bytes (min_free_bytes == 0 disables the floor). An invalid
/// or zero-total reading is NEVER bad — a failed reading must not read as a
/// full disk (the dex_win_poll convention). Integer arithmetic; no float.
[[nodiscard]] YUZU_EXPORT bool disk_reading_is_bad(const DiskReading& reading,
                                                   std::uint32_t used_pct_threshold,
                                                   std::uint64_t min_free_bytes);

/// Poll-and-latch transition decision. `latched` is the per-arm latch state,
/// updated in place. Returns Breach exactly on the transition INTO bad (then
/// suppresses while bad persists), Recovery exactly when a VALID reading shows
/// healthy after a breach (re-arms), nullopt otherwise. An INVALID reading
/// never changes the latch and never emits — a transient read failure must not
/// clear the latch and re-fire (gov UP-5, ported from dex_win_poll's
/// latch_should_emit and extended with the recovery edge for Reflex episodes).
[[nodiscard]] YUZU_EXPORT std::optional<DiskEdge>
disk_latch_transition(const DiskReading& reading, std::uint32_t used_pct_threshold,
                      std::uint64_t min_free_bytes, bool& latched);

/// Platform capacity read for `path` (std::filesystem::space). Never throws;
/// failure → `valid == false`.
[[nodiscard]] YUZU_EXPORT DiskReading read_disk_level(const std::string& path);

using DiskReaderFn = std::function<DiskReading(const std::string& path)>;

/// Disk tick: read via `reader`, run the latch, emit on an edge with the
/// reading + edge attached, reschedule one poll out. `poll_ms` is the
/// engine-floored effective cadence.
[[nodiscard]] YUZU_EXPORT SparkFireDecision
disk_process_due(const DiskSparkParams& params, std::uint64_t poll_ms, bool& latched,
                 const DiskReaderFn& reader, std::chrono::steady_clock::time_point now);

} // namespace yuzu::agent
