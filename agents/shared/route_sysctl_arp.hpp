/**
 * route_sysctl_arp.hpp — macOS ARP table via the routing socket sysctl
 * (Wave-2 PR2.1, WP-C). Darwin-only (#ifdef __APPLE__-gated); consumer:
 * discovery's `scan_subnet` get_arp_table(). Replaces the old `arp -a`
 * subprocess call with the native mechanism `arp -a` itself reads from —
 * the kernel routing table filtered to link-layer ("llinfo") entries.
 *
 * Two clearly separated halves:
 *   fetch_rt_flags_llinfo()  — impure: size-then-fill
 *       sysctl({CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO}).
 *   parse_rt_flags_llinfo()  — pure: walks the returned rt_msghdr chain and
 *       decodes each record's trailing sockaddr_inarp (RTA_DST) and
 *       sockaddr_dl (RTA_GATEWAY) into an ArpRecord. Never trusts the blob:
 *       every length it reads is bounds-checked against the buffer before
 *       the corresponding bytes are dereferenced, and any malformed record
 *       (zero or undersized rtm_msglen, a record that would run past the
 *       buffer end, a sockaddr whose sa_len overruns its record) stops the
 *       walk and returns whatever was parsed so far rather than looping or
 *       reading out of bounds.
 *
 * A record without a resolved 6-byte link-layer address (sdl_alen != 6 —
 * e.g. an in-flight ARP probe) is skipped, same selectivity as the old
 * `arp -a` parser dropping "(incomplete)" rows.
 */
#pragma once

#ifdef __APPLE__

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#include <spdlog/spdlog.h>

namespace yuzu::shared {

struct ArpRecord {
    std::string ip;
    std::string mac;
};

// ── impure half: raw sysctl fetch ────────────────────────────────────────

/**
 * Fetch the raw NET_RT_FLAGS/RTF_LLINFO routing-socket buffer — the same
 * data `arp -a` reads. Size-then-fill sysctl(2); no popen/exec. Empty
 * vector on any failure (including a zero-sized table).
 */
inline std::vector<unsigned char> fetch_rt_flags_llinfo() {
    int mib[6] = {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO};
    std::size_t needed = 0;
    if (::sysctl(mib, 6, nullptr, &needed, nullptr, 0) != 0 || needed == 0) {
        spdlog::warn("discovery arp (macOS): sysctl NET_RT_FLAGS size query failed");
        return {};
    }

    std::vector<unsigned char> buf(needed);
    if (::sysctl(mib, 6, buf.data(), &needed, nullptr, 0) != 0) {
        spdlog::warn("discovery arp (macOS): sysctl NET_RT_FLAGS fill query failed");
        return {};
    }
    buf.resize(needed);
    return buf;
}

namespace detail {

inline std::string mac_to_string(const unsigned char* addr) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(17);
    for (int i = 0; i < 6; ++i) {
        if (i)
            out += ':';
        out += kHex[addr[i] >> 4];
        out += kHex[addr[i] & 0x0F];
    }
    return out;
}

} // namespace detail

// ── pure half: walk the rt_msghdr chain ──────────────────────────────────

/**
 * Parse a NET_RT_FLAGS/RTF_LLINFO blob into {ip, mac} records. Pure —
 * no I/O. Never trusts rtm_msglen or any sockaddr's sa_len: every step is
 * bounds-checked against `blob`'s actual size before it is dereferenced,
 * and the walk stops (returning what it has) rather than looping or
 * reading past the end on a malformed record.
 */
inline std::vector<ArpRecord> parse_rt_flags_llinfo(std::span<const unsigned char> blob) {
    std::vector<ArpRecord> out;
    std::size_t off = 0;

    while (off + sizeof(rt_msghdr) <= blob.size()) {
        rt_msghdr hdr{};
        std::memcpy(&hdr, blob.data() + off, sizeof(hdr));

        if (hdr.rtm_msglen == 0)
            break; // malformed — would spin forever advancing by zero
        if (hdr.rtm_msglen < sizeof(rt_msghdr))
            break; // malformed — shorter than its own fixed header
        if (off + hdr.rtm_msglen > blob.size())
            break; // record claims more bytes than the buffer has left

        const unsigned char* rec_end = blob.data() + off + hdr.rtm_msglen;
        const unsigned char* p = blob.data() + off + sizeof(rt_msghdr);

        std::string ip;
        std::string mac;

        for (int i = 0; i < RTAX_MAX && p < rec_end; ++i) {
            if (!(hdr.rtm_addrs & (1 << i)))
                continue;

            const std::size_t remaining = static_cast<std::size_t>(rec_end - p);
            if (remaining < 2)
                break; // not enough bytes left for sa_len + sa_family

            // Read the two-byte sockaddr prefix straight from the blob —
            // no alignment requirement for byte access, unlike casting `p`
            // to a typed sockaddr pointer and dereferencing through it.
            const unsigned char sa_len = p[0];
            const unsigned char sa_family = p[1];
            const std::size_t entry_len = sa_len ? sa_len : sizeof(long);
            if (remaining < entry_len)
                break; // this sockaddr claims more than the record has left

            if (i == RTAX_DST && sa_family == AF_INET &&
                sa_len >= sizeof(struct sockaddr_inarp)) {
                // memcpy into an aligned local before touching any typed
                // field — never dereference a struct through an unaligned
                // raw pointer into the blob.
                struct sockaddr_inarp sin{};
                std::memcpy(&sin, p, sizeof(sin));
                char buf4[INET_ADDRSTRLEN]{};
                if (::inet_ntop(AF_INET, &sin.sin_addr, buf4, sizeof(buf4)))
                    ip = buf4;
            } else if (i == RTAX_GATEWAY && sa_family == AF_LINK &&
                       sa_len >= offsetof(struct sockaddr_dl, sdl_data)) {
                struct sockaddr_dl sdl{};
                std::memcpy(&sdl, p, std::min<std::size_t>(sa_len, sizeof(sdl)));
                const std::size_t needed =
                    offsetof(struct sockaddr_dl, sdl_data) +
                    static_cast<std::size_t>(sdl.sdl_nlen) + static_cast<std::size_t>(sdl.sdl_alen);
                if (sdl.sdl_alen == 6 && sa_len >= needed) {
                    // The MAC bytes themselves are read directly from the
                    // raw blob (unsigned char* — no alignment requirement),
                    // not from the (possibly truncated) local copy.
                    mac = detail::mac_to_string(
                        p + offsetof(struct sockaddr_dl, sdl_data) + sdl.sdl_nlen);
                }
            }

            // Advance to the next sockaddr in the chain, word-rounded per
            // the BSD routing-socket ROUNDUP convention. The rounded
            // advance must itself still fit in the record — a sockaddr
            // whose unrounded length fits but whose rounded length doesn't
            // must not push `p` past `rec_end`.
            std::size_t adv = entry_len;
            adv = (adv + sizeof(long) - 1) & ~(sizeof(long) - 1);
            if (adv > remaining)
                break;
            p += adv;
        }

        if (!ip.empty() && !mac.empty())
            out.push_back(ArpRecord{std::move(ip), std::move(mac)});

        off += hdr.rtm_msglen;
    }

    return out;
}

} // namespace yuzu::shared

#endif // __APPLE__
