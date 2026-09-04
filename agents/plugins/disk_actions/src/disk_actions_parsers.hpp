/**
 * disk_actions_parsers.hpp — the PURE decision layer for disk_actions.
 *
 * Everything here is a free function over plain data: no OS calls, no I/O, no
 * logging, no platform headers. That is the repo's standing test-efficiency
 * discipline (testable logic — parsing, decisions, formatting — lives in a
 * pure `*_parsers.hpp`; the OS interaction lives in a shell the unit suites
 * never run), and it is the sibling shape `filesystem_posture_parsers.hpp`
 * already establishes.
 *
 * WHY THIS FILE EXISTS AT ALL. The first revision of this plugin had the NVMe
 * log decode and the health classification buried in an anonymous namespace
 * inside `disk_actions_win.cpp` — a `#if defined(_WIN32)` TU. Nothing could
 * reach them: no test on any platform could assert that byte offset 5 is
 * "percentage used", or that critical-warning bit 0 means a failing drive.
 * Both external functional reviewers independently reported that the whole
 * Windows health path had no discriminating test and would stay green if the
 * offsets or the bitmask meaning silently changed. They were right, and the
 * fix is structural rather than another assertion bolted onto a shape test:
 * the decisions move HERE, where every platform's unit suite can exercise them
 * against fixtures.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace yuzu::disk_actions {

/// The subset of the NVMe SMART / Health Information log page this plugin
/// reports. Plain data — the decode below is the only thing that fills it.
struct NvmeHealth {
    std::uint8_t critical_warning{0};
    std::uint8_t available_spare{0};   ///< percent remaining
    std::uint8_t percentage_used{0};   ///< percent of rated endurance consumed
};

/// Byte offsets within NVMe log page 0x02, from the NVMe specification. Named
/// rather than inlined so a test can assert the MEANING of each offset instead
/// of duplicating a magic number the implementation could drift away from.
inline constexpr std::size_t kNvmeCriticalWarningOffset = 0;
inline constexpr std::size_t kNvmeAvailableSpareOffset = 3;
inline constexpr std::size_t kNvmePercentageUsedOffset = 5;

/// The smallest prefix of the log page this decode needs. The real page is 512
/// bytes; requiring only the prefix keeps a short-but-sufficient reply usable
/// while still refusing one that cannot contain the fields.
inline constexpr std::size_t kNvmeHealthMinBytes = kNvmePercentageUsedOffset + 1;

/// Decode the health fields from an NVMe log-page 0x02 payload.
///
/// Returns nullopt when the payload is too short to contain them — a device
/// that answered with less than it promised is a failure to report, never a
/// zeroed-out "healthy" reading. This is the bounds check that keeps
/// firmware-shaped data from being read past its end.
[[nodiscard]] inline std::optional<NvmeHealth>
decode_nvme_health(std::span<const std::byte> page) noexcept {
    if (page.size() < kNvmeHealthMinBytes) return std::nullopt;
    return NvmeHealth{
        static_cast<std::uint8_t>(page[kNvmeCriticalWarningOffset]),
        static_cast<std::uint8_t>(page[kNvmeAvailableSpareOffset]),
        static_cast<std::uint8_t>(page[kNvmePercentageUsedOffset]),
    };
}

/// NVMe critical-warning bits this plugin acts on, from the specification.
/// Bit 0 (spare below threshold) and bit 2 (reliability degraded) are the two
/// an operator must act on; the rest are real warnings the plugin does not
/// individually interpret.
inline constexpr std::uint8_t kNvmeWarnSpareBelowThreshold = 0x01;
inline constexpr std::uint8_t kNvmeWarnTemperature = 0x02;
inline constexpr std::uint8_t kNvmeWarnReliabilityDegraded = 0x04;
inline constexpr std::uint8_t kNvmeWarnReadOnly = 0x08;
inline constexpr std::uint8_t kNvmeWarnVolatileMemoryBackupFailed = 0x10;

/// Health classes, as a pure value. Deliberately duplicated from the row-layer
/// `Health` enum in disk_actions_legs.hpp rather than shared, so this header
/// stays free of the plugin SDK and can be unit-tested with no plugin context
/// at all. `disk_actions_legs.hpp` owns the emitted token vocabulary; this
/// owns the DECISION.
enum class NvmeVerdict { Ok, Warning, Failing };

/// Map a critical-warning bitmask to a verdict.
///
/// An UNRECOGNISED bit still yields `Warning`, never `Ok`: a warning this code
/// does not understand is still a warning, and treating an unknown bit as
/// healthy is the failure mode that makes a fleet health view lie. Only an
/// entirely clear bitmask is `Ok`.
[[nodiscard]] inline constexpr NvmeVerdict nvme_verdict(std::uint8_t critical_warning) noexcept {
    if (critical_warning & (kNvmeWarnSpareBelowThreshold | kNvmeWarnReliabilityDegraded))
        return NvmeVerdict::Failing;
    if (critical_warning != 0) return NvmeVerdict::Warning;
    return NvmeVerdict::Ok;
}

/// The whole-disk name for a partition, by string shape only.
///
/// DELIBERATELY NOT USED BY THE macOS LEG, and kept here with that warning
/// attached. On APFS the string answer is WRONG: `/` lives on disk3s1s1 whose
/// name-derived whole disk is disk3, but disk3 is a SYNTHESIZED container
/// whose physical store is disk0s2 on the real drive disk0. The macOS leg
/// therefore walks the IOKit provider chain instead. This function exists so
/// the distinction is testable and documented rather than tribal: a test pins
/// that the string shortcut and the provider walk disagree on exactly this
/// case, which is what stops the defect being reintroduced as a "simplification".
[[nodiscard]] inline std::string_view name_derived_whole_disk(std::string_view bsd) noexcept {
    // "disk0s2" -> "disk0"; anything without a slice suffix is unchanged.
    if (bsd.size() < 5 || bsd.substr(0, 4) != "disk") return bsd;
    const auto s = bsd.find('s', 4);
    return s == std::string_view::npos ? bsd : bsd.substr(0, s);
}

} // namespace yuzu::disk_actions
