#pragma once

/**
 * dex_macos_iokit.hpp — pure macOS hardware-health DEX extractors (Hardware heading).
 *
 * The Hardware & storage heading is the one empty heading the unified log does
 * NOT cover well; IOKit/system tools do, unprivileged. These pure parsers map the
 * output of two unprivileged commands onto the OS-neutral SignalObservation shape,
 * reusing existing Windows obs_types (zero server change):
 *   - `diskutil info <disk>`        → `disk.smart_failure` (SMART status != Verified)
 *   - `system_profiler SPPowerDataType` → `hw.error` (battery condition / capacity)
 *
 * Battery health has NO Windows like-for-like (the Windows catalogue has no
 * battery signal) — it is the macOS-native Hardware signal; it rides the generic
 * `hw.error` obs_type (Hardware group, "Hardware error" label) with subject =
 * "battery" so it renders correctly without a server change.
 *
 * These are STATE, not events — the collector polls on a slow cadence and emits
 * only on a transition to a bad state (poll-and-diff lives in the engine). Pure +
 * framework-free so the parsing is unit-tested on every host against captured
 * real command output.
 */

#include <yuzu/plugin.h>                     // YUZU_EXPORT
#include <yuzu/agent/dex_signal_catalog.hpp> // SignalObservation

#include <optional>
#include <string>

namespace yuzu::agent::macos {

/// SMART status text out of `diskutil info <disk>` ("Verified" / "Failing" /
/// "Not Supported" / ""). Pure string scan.
YUZU_EXPORT std::string parse_smart_status(const std::string& diskutil_output);

/// `disk.smart_failure` observation when SMART indicates failure. nullopt for
/// healthy ("Verified") or no-SMART ("Not Supported"/"Not Mapped" — e.g. an NVMe
/// behind USB) so a missing SMART capability never reads as a failure.
YUZU_EXPORT std::optional<SignalObservation> smart_observation(const std::string& status,
                                                               const std::string& disk);

/// Battery health out of `system_profiler SPPowerDataType`.
struct BatteryHealth {
    bool valid{false};       ///< false = no battery (desktop) — never emit
    std::string condition;   ///< "Normal" / "Replace Soon" / "Service Battery" / …
    int max_capacity_pct{0}; ///< "Maximum Capacity: 92%" → 92 (0 = absent)
    int cycle_count{0};
};

YUZU_EXPORT BatteryHealth parse_battery_health(const std::string& sp_power_output);

/// `hw.error` (subject="battery") observation when the battery is degraded — bad
/// condition or maximum capacity below 80%. nullopt for a healthy battery or a
/// machine with no battery.
YUZU_EXPORT std::optional<SignalObservation> battery_observation(const BatteryHealth& health);

// ── Resource-pressure signals (faster cadence than battery/SMART) ────────────
// These map the employee-felt "my machine is full / slow / hot" states.

/// Disk usage out of the last line of `df -k <mount>` — the capacity % and the
/// available KB (parsed positionally: the first `\d+%` token is capacity, the
/// token before it is available). `valid=false` if no data line is found.
struct DiskUsage {
    bool valid{false};
    int capacity_pct{0};
    long long available_kb{0};
};
YUZU_EXPORT DiskUsage parse_disk_usage(const std::string& df_output);

/// `storage.low` observation when a volume is nearly full (capacity >= 90% OR
/// available < 5 GiB) — the single highest employee-felt storage signal. macOS-
/// specific obs_type (no Windows catalogue equivalent); registered in the server
/// `dex_signal_groups()` Hardware & storage group with label "Disk nearly full".
YUZU_EXPORT std::optional<SignalObservation> disk_observation(const DiskUsage& usage,
                                                              const std::string& volume);

/// `hw.cpu_throttled` observation when `pmset -g therm` reports a CPU speed cap
/// (`CPU_Speed_Limit` < 100). nullopt when no thermal warning is recorded.
YUZU_EXPORT std::optional<SignalObservation> thermal_observation(const std::string& pmset_therm_output);

/// `memory.exhausted` observation when `memory_pressure -Q` reports free memory
/// below 10% — a low-memory *warning* that complements the jetsam *kill* signal.
/// nullopt when memory is healthy.
YUZU_EXPORT std::optional<SignalObservation> memory_pressure_observation(const std::string& mp_output);

} // namespace yuzu::agent::macos
