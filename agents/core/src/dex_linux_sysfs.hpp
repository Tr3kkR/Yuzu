#pragma once

/**
 * dex_linux_sysfs.hpp — pure parsers for the Linux /sys DEX signals (Guardian DEX).
 *
 * The Linux DEX collector reads a few `/sys` counters on its slow poll cadence and
 * latches a DEX observation on a transition into a bad state — the storage.low
 * poll-and-latch shape. Today: CPU thermal throttling
 * (`/sys/devices/system/cpu/cpuN/thermal_throttle/core_throttle_count`, a monotonic
 * count of throttling episodes) → `hw.cpu_throttled`. The `/sys` globbing + summing
 * is the impure shell in dex_linux_collector.cpp (Linux-only); the value parse is
 * pure and unit-tested on every host.
 *
 * Namespace `lnx` (a sibling of dex_linux_proc). Parsers NEVER throw.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace yuzu::agent::lnx {

/// Per-CPU `core_throttle_count` snapshot (cpuN -> count).
using ThrottleCounts = std::unordered_map<std::string, std::uint64_t>;

/// PURE: parse a `/sys` throttle counter file — a bare decimal with a trailing
/// newline ("42\n"). Takes the first whitespace-delimited token (so the trailing
/// newline is tolerated, unlike a strict whole-string parse) and requires it to be
/// a plain unsigned integer. nullopt on anything else (empty / non-numeric).
YUZU_EXPORT std::optional<std::uint64_t> parse_throttle_count(std::string_view content);

/// PURE: true iff some CPU present in BOTH snapshots had its core_throttle_count
/// INCREASE. A core that appeared since `prev` (re-online) or disappeared (offline) is
/// NOT compared — so CPU hotplug / SMT toggle / the kernel's counter-reset-on-re-online
/// cannot fabricate a throttle (a single summed counter could not tell those apart, the
/// Gate-8 defect). This is the throttling-edge detector behind hw.cpu_throttled; the
/// collector wraps it in the storage.low poll-and-latch so it fires once per episode.
YUZU_EXPORT bool throttle_increased(const ThrottleCounts& prev, const ThrottleCounts& cur);

} // namespace yuzu::agent::lnx
