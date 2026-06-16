/// @file linux_tcp_info.hpp
/// Portable, ABI-pinned view of the Linux kernel's `struct tcp_info`.
///
/// Why this exists: the field set in glibc's `<netinet/tcp.h>` lags the kernel
/// uapi `<linux/tcp.h>`. On glibc 2.39 (the canonical Ubuntu 24.04 / gcc-13
/// toolchain) `struct tcp_info` has `tcpi_lost`, `tcpi_rtt`, `tcpi_rttvar`,
/// `tcpi_total_retrans`, `tcpi_ca_state` — but NOT `tcpi_segs_out`, which the
/// netlink INET_DIAG collectors read as a retransmit-rate denominator. We can't
/// just add `<linux/tcp.h>`: it defines `struct tcp_info` too, and the two
/// definitions collide in any TU that also pulls in `<netinet/tcp.h>` (needed
/// for `TCP_ESTABLISHED`).
///
/// The fix is to stop depending on the libc struct layout at all. The kernel
/// writes a well-known, append-only ABI into the INET_DIAG_INFO attribute;
/// `LinuxTcpInfo` mirrors that ABI's prefix up to `tcpi_segs_out`, and every
/// field offset is pinned by `static_assert`. memcpy the netlink payload into a
/// `LinuxTcpInfo` (NOT a cast — RTA_DATA is only 4-byte aligned), copying at most
/// `sizeof(LinuxTcpInfo)` (the kernel struct is longer; the prefix is stable).
///
/// If a future kernel/compiler ever lays this out differently, the asserts fail
/// the build LOUDLY rather than reading a garbage offset silently — the exact
/// failure mode that let the glibc-2.39 gap ship green from newer-glibc rigs.

#ifndef YUZU_AGENT_LINUX_TCP_INFO_HPP
#define YUZU_AGENT_LINUX_TCP_INFO_HPP

#include <cstddef> // offsetof
#include <cstdint>
#include <type_traits>

namespace yuzu::agent {

/// Append-only prefix of the kernel uapi `struct tcp_info` (include/uapi/linux/
/// tcp.h), through `tcpi_segs_out`. Field names match the kernel's so call sites
/// read identically to the old `struct tcp_info` access. The first eight bytes
/// pack the kernel's bitfields into plain bytes — we never read them, so we keep
/// them opaque rather than re-deriving the `:4`/`:1` layout.
struct LinuxTcpInfo {
    std::uint8_t tcpi_state;
    std::uint8_t tcpi_ca_state;
    std::uint8_t tcpi_retransmits;
    std::uint8_t tcpi_probes;
    std::uint8_t tcpi_backoff;
    std::uint8_t tcpi_options;
    std::uint8_t tcpi_wscale;     // snd_wscale:4 | rcv_wscale:4 (opaque)
    std::uint8_t tcpi_app_limited; // delivery_rate_app_limited:1 | fastopen_client_fail:2 (opaque)

    std::uint32_t tcpi_rto;
    std::uint32_t tcpi_ato;
    std::uint32_t tcpi_snd_mss;
    std::uint32_t tcpi_rcv_mss;

    std::uint32_t tcpi_unacked;
    std::uint32_t tcpi_sacked;
    std::uint32_t tcpi_lost;
    std::uint32_t tcpi_retrans;
    std::uint32_t tcpi_fackets;

    std::uint32_t tcpi_last_data_sent;
    std::uint32_t tcpi_last_ack_sent;
    std::uint32_t tcpi_last_data_recv;
    std::uint32_t tcpi_last_ack_recv;

    std::uint32_t tcpi_pmtu;
    std::uint32_t tcpi_rcv_ssthresh;
    std::uint32_t tcpi_rtt;
    std::uint32_t tcpi_rttvar;
    std::uint32_t tcpi_snd_ssthresh;
    std::uint32_t tcpi_snd_cwnd;
    std::uint32_t tcpi_advmss;
    std::uint32_t tcpi_reordering;

    std::uint32_t tcpi_rcv_rtt;
    std::uint32_t tcpi_rcv_space;

    std::uint32_t tcpi_total_retrans;

    std::uint64_t tcpi_pacing_rate;
    std::uint64_t tcpi_max_pacing_rate;
    std::uint64_t tcpi_bytes_acked;
    std::uint64_t tcpi_bytes_received;
    std::uint32_t tcpi_segs_out;
};

// Kernel ABI offsets (ground-truthed against the uapi layout on glibc 2.39).
// Any compiler that pads differently trips these at build time.
static_assert(offsetof(LinuxTcpInfo, tcpi_ca_state) == 1, "tcpi_ca_state offset drift");
static_assert(offsetof(LinuxTcpInfo, tcpi_lost) == 32, "tcpi_lost offset drift");
static_assert(offsetof(LinuxTcpInfo, tcpi_rtt) == 68, "tcpi_rtt offset drift");
static_assert(offsetof(LinuxTcpInfo, tcpi_rttvar) == 72, "tcpi_rttvar offset drift");
static_assert(offsetof(LinuxTcpInfo, tcpi_total_retrans) == 100, "tcpi_total_retrans offset drift");
static_assert(offsetof(LinuxTcpInfo, tcpi_segs_out) == 136, "tcpi_segs_out offset drift");

// The whole design is "memcpy the netlink payload into a LinuxTcpInfo" — that is
// only defined if the type is trivially copyable. Pin it so a future field that
// breaks triviality fails the build, not a sanitizer at runtime.
static_assert(std::is_trivially_copyable_v<LinuxTcpInfo>,
              "LinuxTcpInfo must stay trivially copyable for the memcpy decode");
// offsetof (used above and at every read site) is only fully defined for a
// standard-layout type. Pin it so a future private section / base / mixed-access
// change fails the build rather than making every offsetof conditionally UB.
static_assert(std::is_standard_layout_v<LinuxTcpInfo>,
              "LinuxTcpInfo must stay standard-layout for offsetof to be defined");

} // namespace yuzu::agent

#endif // YUZU_AGENT_LINUX_TCP_INFO_HPP
