#pragma once

/// @file net_quality_sampler.hpp
/// Device-level NETWORK-QUALITY sampler for the heartbeat (slice 4a of the
/// /network dashboard). The agent has no /metrics endpoint, so these thin,
/// fixed-cardinality facts are the ONLY channel by which the fleet network
/// gauges + the /network Overview cards exist (mirrors the yuzu.perf_* path).
///
/// Linux: per-connection smoothed RTT + retransmits via netlink SOCK_DIAG /
/// INET_DIAG (the same interface `ss -ti` uses — no packet capture, no
/// elevation: a non-root agent sees system TCP_INFO), rolled up to a device
/// p50 RTT + aggregate retransmit ratio; throughput from /proc/net/dev deltas.
/// Off Linux the sampler returns an all-invalid sample (Windows is the
/// ESTATS-vs-ETW spike; macOS later) so no tags ship — absent, never zero.
///
/// THE EDGE SHIPS FACTS, NEVER A VERDICT. `degraded` is a measured device fact
/// (RTT/retransmit over a documented threshold), used by the server only as the
/// co-occurrence population — NOT a causal attribution. Per-destination /
/// per-app detail stays OFF the heartbeat (warehouse tier, a later slice) — this
/// device-aggregate is no more sensitive than the existing perf tags.

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>
#include <vector>

namespace yuzu::agent::netq {

/// Interface byte counters for the throughput delta (kept across heartbeats).
struct NetCounters {
    bool valid{false};
    uint64_t rx_bytes{0};
    uint64_t tx_bytes{0};
    std::chrono::steady_clock::time_point at{};
};

/// The thin device-level sample shipped on the heartbeat. Each metric carries
/// its own validity — a domain whose read failed is OMITTED, never shipped as 0.
struct NetQualitySample {
    bool rtt_valid{false};
    double rtt_p50_ms{0.0};
    bool retrans_valid{false};
    double retrans_pct{0.0}; ///< lifetime retransmit ratio across active TCP conns
    bool throughput_valid{false};
    double throughput_bps{0.0}; ///< device rx+tx bytes/s, non-loopback
    bool degraded{false};       ///< measured fact (RTT/retransmit over threshold), not a verdict
};

/// Degraded thresholds — a MEASURED-FACT heuristic ("this device's network
/// looks degraded right now"), the co-occurrence population, NOT a verdict.
inline constexpr double kNetDegradedRttMs = 150.0;
inline constexpr double kNetDegradedRetransPct = 5.0;

/// Read current non-loopback interface byte counters (Linux: /proc/net/dev).
/// Returns invalid off Linux or on read failure.
NetCounters read_net_counters();

/// Produce the heartbeat sample: a one-shot INET_DIAG dump for rtt/retrans (no
/// delta needed) + throughput from prev/cur counters. `prev` invalid (first
/// heartbeat) → throughput omitted this cycle. Off Linux → all-invalid.
NetQualitySample sample_net_quality(const NetCounters& prev, const NetCounters& cur);

// ── Pure helpers (header-inline so they link into tests without DLL export,
//    matching the dex_perf_breach pattern) ───────────────────────────────────

/// Median of a value list (middle element). Empty → nullopt.
inline std::optional<double> median(std::vector<double> v) {
    if (v.empty())
        return std::nullopt;
    std::sort(v.begin(), v.end());
    return v[v.size() / 2]; // deterministic; robust to the RTT outliers `ss` shows
}

/// Throughput in bytes/s from two counter reads. nullopt unless both valid and
/// the interval is positive; counter wrap (cur < prev) yields nullopt, not a
/// negative/huge rate.
inline std::optional<double> throughput_bps(const NetCounters& prev, const NetCounters& cur) {
    if (!prev.valid || !cur.valid)
        return std::nullopt;
    if (cur.rx_bytes < prev.rx_bytes || cur.tx_bytes < prev.tx_bytes)
        return std::nullopt; // counter wrap/reset — drop the sample, never a bogus rate
    const double secs = std::chrono::duration<double>(cur.at - prev.at).count();
    if (secs <= 0.0)
        return std::nullopt;
    const double bytes =
        static_cast<double>((cur.rx_bytes - prev.rx_bytes) + (cur.tx_bytes - prev.tx_bytes));
    return bytes / secs;
}

/// The degraded fact from the validated rollups (shared by the sampler + tests).
inline bool is_degraded(bool rtt_valid, double rtt_p50_ms, bool retrans_valid,
                        double retrans_pct) {
    return (rtt_valid && rtt_p50_ms > kNetDegradedRttMs) ||
           (retrans_valid && retrans_pct > kNetDegradedRetransPct);
}

} // namespace yuzu::agent::netq
