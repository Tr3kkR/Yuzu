#pragma once

/**
 * dex_rate_limiter.hpp — per-obs_type hourly emit cap for DEX signal collectors.
 *
 * "Be kind to the network": a storming signal type (a crash-looping process, a
 * flapping unit, an OOM cascade) must not flood the wire. Each obs_type carries a
 * `max_per_hour` in the signal catalogue (dex_signal_catalog); this is the shared,
 * PURE, platform-agnostic limiter that enforces it at a collector's emit()
 * chokepoint. The Linux collector wires it today; the Windows observer reads the
 * catalogue cap inline and the macOS collector still carries a bespoke cap table —
 * unifying all three onto this limiter is a tracked follow-up (do NOT fold that in
 * here).
 *
 * PURE + logging-free: the limiter classifies an observation as Emit / Drop /
 * DropAndWarn and tells the caller when a drop is the FIRST of its clock-hour (so
 * the caller logs exactly one warning per type per hour) — but it does no I/O
 * itself, so it is unit-tested off-target with no spdlog and no journalctl.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>

namespace yuzu::agent {

/// The per-hour emit cap for `obs_type`: the FIRST catalogue SignalSpec whose
/// obs_type matches → its `max_per_hour`; 60 (the SignalSpec default) when the
/// type is not catalogued — e.g. the Linux poll-derived perf.*/storage.low types,
/// which are already bounded by their hysteresis/latch and never approach 60.
/// PURE — a scan of the static catalogue, no state. (`service.crashed` appears
/// under two provider spellings with the same cap, so first-match is unambiguous.)
YUZU_EXPORT int dex_obs_cap_per_hour(std::string_view obs_type);

/// What the caller should do with an observation the limiter just classified.
enum class RateDecision {
    Emit,        ///< under the cap this hour — send it
    Drop,        ///< over the cap this hour — drop silently (already warned)
    DropAndWarn, ///< over the cap, and the FIRST drop this hour — drop + log one warning
};

/// Per-(obs_type) hourly cap. Hour bucket = timestamp_unix / 3600 (WALL clock —
/// the cap is "per clock hour", matching the macOS collector). On a new hour the
/// count resets and the warned flag clears (one warning per type per hour at
/// most). The map is bounded by the number of distinct obs_types (small, fixed),
/// never by event volume. Single-threaded by contract (called only from the
/// owning collector's poll thread) — no internal locking.
class YUZU_EXPORT DexRateLimiter {
public:
    /// Classify one observation: `obs_type` selects the bucket + cap,
    /// `timestamp_unix` selects the hour. Exactly `cap` observations return Emit
    /// per (obs_type, hour); the rest Drop (the first one DropAndWarn). The cap is
    /// resolved once per (obs_type, hour) and cached, so a storm does not re-scan
    /// the catalogue per dropped event.
    RateDecision check(const std::string& obs_type, std::int64_t timestamp_unix);

private:
    struct Bucket {
        std::int64_t hour = -1; ///< timestamp_unix/3600 of the current window
        int count = 0;          ///< emits this hour (saturates at cap — no overflow under a storm)
        int cap = 60;           ///< cached cap for this obs_type (resolved on window reset)
        bool warned = false;    ///< a drop already logged this hour
    };
    std::unordered_map<std::string, Bucket> buckets_;
};

} // namespace yuzu::agent
