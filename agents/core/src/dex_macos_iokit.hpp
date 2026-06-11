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

} // namespace yuzu::agent::macos
