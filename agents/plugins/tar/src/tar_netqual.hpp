#pragma once

/**
 * tar_netqual.hpp — pure, cross-platform helpers for the per-connection TCP
 * quality (netqual) warehouse tier of the /network dashboard (BRD Workstream E).
 *
 * The platform collector (Linux: netlink INET_DIAG TCP_INFO, in
 * tar_network_collector.cpp) yields raw TcpQualitySample records carrying the
 * RAW remote address. These header-inline helpers turn those into persistable
 * NetQualRow records:
 *   - remote_bucket()      — classify the destination into a coarse, privacy-safe
 *                            CLASS so the raw address never reaches the warehouse;
 *   - select_netqual_rows()— apply the bucket + a per-tick top-N cap that keeps
 *                            the MOST-DEGRADED connections first.
 *
 * Both are pure (no I/O, no platform headers) so they compile + unit-test on
 * every host, matching the net_quality_sampler header-inline-helpers pattern.
 *
 * SIGNAL DISCIPLINE (see NetQualRow in tar_db.hpp): `lost` is the CURRENT-loss
 * gauge (tcpi_lost) and the only field that moves with current conditions;
 * `retrans`/`segs_out` are lifetime-cumulative CONTEXT only — never build a
 * "current loss" signal from their ratio (it is diluted by historical clean
 * segments, which is exactly why the device-aggregate signal was disproven).
 */

#include "tar_db.hpp" // NetQualRow

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace yuzu::tar {

/// Raw per-connection TCP quality observation from the platform collector.
/// Carries the RAW remote address — it is the INPUT to select_netqual_rows,
/// which buckets it away. The raw address MUST NOT be persisted: only
/// remote_bucket leaves the builder.
struct TcpQualitySample {
    std::string proto;        ///< tcp, tcp6
    std::string remote_addr;  ///< raw — bucketed by the builder, never stored
    std::string process_name; ///< owning process image name (may be kernel-truncated)
    int64_t rtt_us{0};        ///< smoothed RTT (tcpi_rtt)
    int64_t rtt_var_us{0};    ///< RTT variance / jitter (tcpi_rttvar)
    int64_t lost{0};          ///< CURRENT lost segments (tcpi_lost) — instantaneous degraded driver
    int64_t retrans{0};       ///< lifetime retransmits (tcpi_total_retrans) — context
    int64_t segs_out{0};      ///< lifetime segments out (tcpi_segs_out) — context
    int64_t ca_state{0};      ///< tcpi_ca_state (0=Open..4=Loss) — holds across a recovery episode
};

/// Default per-tick top-N connection cap. The real cardinality bound (the
/// warehouse can't explode on a box opening thousands of connections); the
/// schema's row-count retention is the storage backstop behind it.
inline constexpr std::size_t kNetQualTopN = 50;

/// Classify a remote address into a coarse, privacy-safe destination CLASS:
/// "loopback" | "private" | "public" | "unknown". String-prefix only (no socket
/// headers) so it is header-safe and testable cross-platform. VPN-ness is
/// interface-derived, not address-derived, so it is deliberately NOT a class
/// here — a later slice that has interface context can add it.
inline std::string remote_bucket(const std::string& addr) {
    if (addr.empty() || addr == "*")
        return "unknown";

    // IPv6 (any colon).
    if (addr.find(':') != std::string::npos) {
        if (addr == "::1")
            return "loopback";
        // IPv4-mapped (::ffff:a.b.c.d) — classify by the embedded v4 so an
        // internal dual-stack peer isn't mislabelled "public". inet_ntop emits
        // lowercase, but accept either case defensively.
        if (addr.starts_with("::ffff:") || addr.starts_with("::FFFF:"))
            return remote_bucket(addr.substr(7));
        // link-local fe80::/10 (fe80–febf) and unique-local fc00::/7 (fc/fd).
        if (addr.starts_with("fe8") || addr.starts_with("fe9") ||
            addr.starts_with("fea") || addr.starts_with("feb") ||
            addr.starts_with("fc") || addr.starts_with("fd"))
            return "private";
        return "public";
    }

    // IPv4.
    if (addr.starts_with("127."))
        return "loopback";
    if (addr.starts_with("10.") || addr.starts_with("192.168.") ||
        addr.starts_with("169.254.")) // RFC1918 + link-local
        return "private";
    // Ranges keyed on the 2nd octet: 172.16–31 (RFC1918 /12) and
    // 100.64–127 (RFC6598 carrier-grade NAT shared space — internal, not public).
    const auto second_octet = [&](int lo, int hi) -> bool {
        const auto d1 = addr.find('.');
        const auto d2 = addr.find('.', d1 + 1);
        if (d2 == std::string::npos || d2 <= d1 + 1)
            return false;
        int oct = 0;
        for (auto i = d1 + 1; i < d2; ++i) {
            if (addr[i] < '0' || addr[i] > '9')
                return false;
            oct = oct * 10 + (addr[i] - '0');
        }
        return oct >= lo && oct <= hi;
    };
    if (addr.starts_with("172.") && second_octet(16, 31))
        return "private";
    if (addr.starts_with("100.") && second_octet(64, 127))
        return "private";
    return "public";
}

/// PURE: turn raw quality samples into persistable rows. Applies the privacy
/// bucket (DROPS the raw address) and a per-tick top-N cap that keeps the
/// MOST-DEGRADED connections first — highest current loss, then most active
/// (segs_out) — so a losing connection is never dropped in favour of an idle
/// one. `cap == 0` means no cap. Order within the cap is degraded-first.
inline std::vector<NetQualRow> select_netqual_rows(const std::vector<TcpQualitySample>& samples,
                                                   int64_t ts, int64_t snapshot_id,
                                                   std::size_t cap) {
    std::vector<const TcpQualitySample*> ordered;
    ordered.reserve(samples.size());
    for (const auto& s : samples)
        ordered.push_back(&s);
    std::stable_sort(ordered.begin(), ordered.end(),
                     [](const TcpQualitySample* a, const TcpQualitySample* b) {
                         if (a->lost != b->lost)
                             return a->lost > b->lost;       // current loss first
                         return a->segs_out > b->segs_out;   // then most active
                     });
    if (cap > 0 && ordered.size() > cap)
        ordered.resize(cap);

    std::vector<NetQualRow> rows;
    rows.reserve(ordered.size());
    for (const auto* s : ordered) {
        NetQualRow r;
        r.ts = ts;
        r.snapshot_id = snapshot_id;
        r.proto = s->proto;
        r.remote_bucket = remote_bucket(s->remote_addr); // privacy: raw addr dropped here
        r.process_name = s->process_name;
        r.rtt_us = s->rtt_us;
        r.rtt_var_us = s->rtt_var_us;
        r.lost = s->lost;
        r.retrans = s->retrans;
        r.segs_out = s->segs_out;
        r.ca_state = s->ca_state;
        rows.push_back(std::move(r));
    }
    return rows;
}

} // namespace yuzu::tar
