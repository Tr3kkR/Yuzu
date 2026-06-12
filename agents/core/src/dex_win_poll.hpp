#pragma once

/**
 * dex_win_poll.hpp — Windows state-poll DEX signals (Hardware & storage heading).
 *
 * The Windows DEX engine is event-driven (EvtSubscribe) — right for failures the
 * OS *logs*, blind to bad *states* the OS never logs: a volume filling up and a
 * battery wearing out produce no Event Log record. This module is the Windows
 * analogue of the macOS IOKit poll (dex_macos_iokit): a slow-cadence poll that
 * emits only on the transition INTO a bad state (latch on, suppress while it
 * persists, re-arm on recovery). BRD rows 20–21 (docs/dex-brd-coverage.md, D1).
 *
 * Signals (both already in the server display catalogue — zero server change):
 *   - `storage.low`          — fixed volume >= 90% full or < 5 GiB free (the
 *                              macOS collector's thresholds, kept identical so
 *                              fleet dashboards read the same on both platforms)
 *   - `hw.error` ("battery") — full-charge capacity below 80% of design via
 *                              IOCTL_BATTERY (mirrors the macOS battery signal)
 *
 * The decision functions are pure and unit-tested on every host; the Win32
 * mechanism (GetDiskFreeSpaceExW, SetupDi + battery IOCTLs, the poll thread)
 * lives behind make_win_state_poller() in the _WIN32 section of the .cpp.
 * windows.h-free and proto-free by design (the dex_observer.hpp rationale).
 */

#include <yuzu/plugin.h>               // YUZU_EXPORT
#include <yuzu/agent/dex_observer.hpp> // SignalSink, SignalObservation

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace yuzu::agent::win {

/// Free/total bytes for one fixed volume (GetDiskFreeSpaceExW reading).
struct DiskLevel {
    bool valid{false};
    std::uint64_t total_bytes{0};
    std::uint64_t free_bytes{0};
};

/// `storage.low` observation when the volume is nearly full (>= 90% used OR
/// < 5 GiB free). nullopt for a healthy, unreadable, or zero-size volume — a
/// failed reading must never read as a full disk.
YUZU_EXPORT std::optional<SignalObservation> low_disk_observation(const DiskLevel& level,
                                                                  const std::string& volume);

/// Battery health out of IOCTL_BATTERY_QUERY_INFORMATION (BATTERY_INFORMATION).
/// Units may be relative (BATTERY_CAPACITY_RELATIVE) — the full/design *ratio*
/// is meaningful either way; absolute values are never surfaced.
struct BatteryHealth {
    bool valid{false};                      ///< false = no battery (desktop) — never emit
    std::uint32_t designed_capacity{0};     ///< BATTERY_INFORMATION.DesignedCapacity
    std::uint32_t full_charged_capacity{0}; ///< BATTERY_INFORMATION.FullChargedCapacity
    std::uint32_t cycle_count{0};           ///< BATTERY_INFORMATION.CycleCount
};

/// `hw.error` (subject="battery") observation when full-charge capacity is below
/// 80% of design — same threshold and rendering as the macOS battery signal.
/// nullopt for healthy, no battery, or designed_capacity == 0 (no ratio — a
/// missing reading must never read as a failure).
YUZU_EXPORT std::optional<SignalObservation> battery_observation(const BatteryHealth& health);

/// Poll-and-latch transition decision (pure, unit-tested). `reported` is the
/// per-subject latch state, updated in place. Returns true exactly on the
/// transition INTO a bad state (emit once), suppresses while it persists, and
/// re-arms ONLY when a VALID reading shows healthy — a transient read failure
/// (`reading_valid == false`) must not clear the latch and re-fire (gov UP-5).
/// Disk callers pass `reading_valid = true` (unreadable volumes are skipped
/// before the latch); battery passes the reading's validity.
YUZU_EXPORT bool latch_should_emit(bool currently_bad, bool reading_valid, bool& reported);

/// A running state poll. start() launches the poll thread (disk every 10 min,
/// battery hourly; first poll on the first 60 s tick — timer-driven, never
/// at-arm, the macOS lesson); stop() joins it. Single-owner; the Windows DEX
/// observer owns one alongside its event subscriptions.
class IStatePoller {
public:
    virtual ~IStatePoller() = default;
    virtual void start(SignalSink sink) = 0;
    virtual void stop() = 0;
};

/// Factory: the Win32 poll mechanism on Windows, a no-op elsewhere (this TU
/// compiles on every platform so the pure decision functions stay testable).
YUZU_EXPORT std::unique_ptr<IStatePoller> make_win_state_poller();

} // namespace yuzu::agent::win
