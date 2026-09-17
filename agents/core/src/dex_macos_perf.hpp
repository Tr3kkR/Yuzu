#pragma once

/**
 * dex_macos_perf.hpp — pure math + macOS perf readers for the DEX perf primitives
 * (Guardian DEX perf.* breach trio, TAR device/app perf — consumed starting C2/C4).
 *
 * The macOS analogue of dex_linux_proc.hpp: every derivation (busy%, await-ms,
 * pressure%, used-bytes) is PURE — no syscalls, no platform guards — so it is
 * unit-tested on every host exactly like the Linux /proc arithmetic. Only the
 * six `read_*` functions touch the kernel (host_statistics/host_statistics64,
 * IOKit's IOBlockStorageDriver "Statistics" dictionaries, sysctlbyname) and are
 * `#if defined(__APPLE__)`, with an all-invalid stub on every other platform —
 * the net_quality_sampler.cpp / dex_linux_proc.cpp shape.
 *
 * Nothing in this file is wired into any collector yet (C0 goal: primitives
 * only). C2 (TAR device perf) and C4 (Guardian perf.* breach trio) are the
 * first consumers.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <cstdint>
#include <optional>

namespace yuzu::agent::macos {

/// PURE, saturating: convert `t` mach-absolute-time ticks to 100ns units, given the
/// host's mach_timebase_info (numer/denom — ticks-to-nanoseconds is `t*numer/denom`;
/// this then divides by 100 for the wire's 100ns unit, matching ProcCounter::cpu_100ns
/// in tar_proc_perf.hpp, C3's consumer). Saturates at UINT64_MAX rather than wrapping
/// on overflow — a malformed/extreme input must not silently underreport. `denom==0`
/// (a corrupt timebase) returns 0, never divides by zero.
YUZU_EXPORT std::uint64_t mach_abs_to_100ns(std::uint64_t t, std::uint32_t numer,
                                            std::uint32_t denom) noexcept;

} // namespace yuzu::agent::macos
