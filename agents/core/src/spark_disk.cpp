/**
 * spark_disk.cpp — the disk threshold spark type (see spark_types.hpp).
 *
 * Poll-and-latch on a volume's capacity: emit exactly on the transition INTO
 * the bad state (Breach), suppress while it persists, and emit Recovery
 * exactly when a VALID reading shows healthy again. An invalid reading never
 * moves the latch in either direction (gov UP-5 — a transient read failure
 * must not clear the latch and re-fire, and must never read as a full disk).
 *
 * The decision logic is a port of dex_win_poll.hpp's latch_should_emit +
 * low_disk_observation thresholds (>= 90% used OR < 5 GiB free by default,
 * kept identical to the shipped macOS/Windows DEX collectors so Stage 4's
 * re-homed DEX consumer reads the same fleet-wide), extended with the recovery
 * edge that Reflex episodes need (breach opens an episode, recovery closes it
 * — ADR-0021 Decision 4 / Stage 3). The platform read is std::filesystem::space
 * so the spark is cross-platform from day one; the DEX enumerate-fixed-volumes
 * sweep stays with the DEX consumer until Stage 4 re-homes it.
 */

#include "spark_types.hpp"

#include <filesystem>
#include <system_error>

namespace yuzu::agent {

bool disk_reading_is_bad(const DiskReading& reading, std::uint32_t used_pct_threshold,
                         std::uint64_t min_free_bytes) {
    // An invalid or zero-size reading is never bad — a failed reading must not
    // read as a full disk (dex_win_poll convention).
    if (!reading.valid || reading.total_bytes == 0)
        return false;
    const std::uint64_t used =
        reading.total_bytes > reading.free_bytes ? reading.total_bytes - reading.free_bytes : 0;
    // used/total >= threshold/100, in integers. total_bytes * 100 cannot
    // overflow u64 for any real volume (would need ~180 EB).
    if (used * 100 >= static_cast<std::uint64_t>(used_pct_threshold) * reading.total_bytes)
        return true;
    return min_free_bytes > 0 && reading.free_bytes < min_free_bytes;
}

std::optional<DiskEdge> disk_latch_transition(const DiskReading& reading,
                                              std::uint32_t used_pct_threshold,
                                              std::uint64_t min_free_bytes, bool& latched) {
    // UP-5: an invalid reading keeps the latch exactly as it is — no breach
    // (can't prove bad), no recovery (can't prove healthy).
    if (!reading.valid)
        return std::nullopt;
    const bool bad = disk_reading_is_bad(reading, used_pct_threshold, min_free_bytes);
    if (bad && !latched) {
        latched = true;
        return DiskEdge::Breach;
    }
    if (!bad && latched) {
        latched = false;
        return DiskEdge::Recovery;
    }
    return std::nullopt;
}

DiskReading read_disk_level(const std::string& path) {
    DiskReading r;
    std::error_code ec;
    const std::filesystem::space_info si = std::filesystem::space(path, ec);
    if (ec)
        return r; // valid == false
    // capacity/free can be -1 (uintmax_t max) on failure per the standard.
    if (si.capacity == static_cast<std::uintmax_t>(-1) || si.free == static_cast<std::uintmax_t>(-1))
        return r;
    r.valid = true;
    r.total_bytes = static_cast<std::uint64_t>(si.capacity);
    // `free` (total free space, ~ Win32 lpTotalNumberOfFreeBytes) rather than
    // `available` (caller-quota-restricted, ~ lpFreeBytesAvailable): the
    // shipped DEX collector (dex_win_poll.cpp) reads total free, and the
    // header comment's parity claim ("same thresholds so fleet dashboards
    // read the same on both platforms") only holds if this spark matches that
    // convention exactly — `available` would cross the threshold sooner
    // (root-reserved / quota headroom) and silently drift Stage 4's parity.
    r.free_bytes = static_cast<std::uint64_t>(si.free);
    return r;
}

SparkFireDecision disk_process_due(const DiskSparkParams& params, std::uint64_t poll_ms,
                                   bool& latched, const DiskReaderFn& reader,
                                   std::chrono::steady_clock::time_point now) {
    SparkFireDecision d;
    d.reschedule = now + std::chrono::milliseconds(poll_ms);
    const DiskReading reading = reader ? reader(params.path) : read_disk_level(params.path);
    const std::optional<DiskEdge> edge =
        disk_latch_transition(reading, params.used_pct_threshold, params.min_free_bytes, latched);
    if (!edge)
        return d;
    d.emit = true;
    d.data = DiskSparkData{reading, *edge};
    return d;
}

} // namespace yuzu::agent
