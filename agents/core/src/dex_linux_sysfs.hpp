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
#include <string_view>

namespace yuzu::agent::lnx {

/// PURE: parse a `/sys` throttle counter file — a bare decimal with a trailing
/// newline ("42\n"). Takes the first whitespace-delimited token (so the trailing
/// newline is tolerated, unlike a strict whole-string parse) and requires it to be
/// a plain unsigned integer. nullopt on anything else (empty / non-numeric).
YUZU_EXPORT std::optional<std::uint64_t> parse_throttle_count(std::string_view content);

} // namespace yuzu::agent::lnx
