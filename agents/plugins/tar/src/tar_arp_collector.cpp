// tar_arp_collector.cpp — host ARP / neighbour-table enumeration for the TAR
// `arp` capture source (ADR-0015). The impure platform shell only: the snapshot
// is diffed in tar_diff.cpp (compute_arp_events) and persisted in tar_db.cpp
// (insert_arp_events). Follows the core capture-source pattern (no per-source
// header; types + decls in tar_collectors.hpp) — see docs/tar-implementer.md
// "Adding a capture source".
//
// Windows: GetIpNetTable2(AF_UNSPEC) over the kernel ARP + IPv6 neighbour cache.
// Linux: reads /proc/net/arp, parsed by tar_arp_parsers.hpp's
// parse_proc_net_arp(). macOS: reuses agents/shared/route_sysctl_arp.hpp's
// NET_RT_FLAGS/RTF_LLINFO sysctl fetch + parse (the same native mechanism
// discovery's scan_subnet already uses), mapped onto ArpEntry by this
// header's arp_entry_from_route_record(). Both non-Windows legs are
// log-and-degrade on failure/truncation, matching the Windows leg's own
// warn-and-return-empty / rate-limited cap-warn contract.

#include "tar_arp_parsers.hpp"
#include "tar_collectors.hpp"

#include <spdlog/spdlog.h>

#include <atomic> // rate-limited truncation warn
#include <format>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681)
#include <netioapi.h> // GetIpNetTable2 / MIB_IPNET_ROW2 / ConvertInterfaceLuidToAlias
#elif defined(__APPLE__)
#include <route_sysctl_arp.hpp> // agents/shared — fetch_rt_flags_llinfo / parse_rt_flags_llinfo
#include <span>
#else
#include <fstream> // /proc/net/arp read
#include <sstream>
#endif

namespace yuzu::tar {

#ifdef _WIN32

namespace {

std::string mac_to_string(const UCHAR* addr, ULONG len) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    if (len == 0)
        return out; // incomplete entry — no hardware address yet
    out.reserve(len * 3 - 1);
    for (ULONG i = 0; i < len; ++i) {
        if (i)
            out += ':';
        out += kHex[addr[i] >> 4];
        out += kHex[addr[i] & 0x0F];
    }
    return out;
}

std::string sockaddr_inet_to_string(const SOCKADDR_INET& a) {
    char buf[INET6_ADDRSTRLEN]{};
    if (a.si_family == AF_INET)
        inet_ntop(AF_INET, const_cast<IN_ADDR*>(&a.Ipv4.sin_addr), buf, sizeof(buf));
    else if (a.si_family == AF_INET6)
        inet_ntop(AF_INET6, const_cast<IN6_ADDR*>(&a.Ipv6.sin6_addr), buf, sizeof(buf));
    return buf;
}

// Map the Win32 NL_NEIGHBOR_STATE onto the published entry_type tokens
// (dynamic / static / incomplete / other) — see the ADR's $ARP_Live schema.
std::string entry_type_for_state(NL_NEIGHBOR_STATE st) {
    switch (st) {
    case NlnsPermanent:
        return "static";
    case NlnsReachable:
    case NlnsStale:
    case NlnsDelay:
    case NlnsProbe:
        return "dynamic";
    case NlnsIncomplete:
    case NlnsUnreachable:
        return "incomplete";
    default:
        return "other";
    }
}

std::string iface_alias(const NET_LUID& luid, NET_IFINDEX idx) {
    wchar_t alias[IF_MAX_STRING_SIZE + 1]{};
    if (ConvertInterfaceLuidToAlias(&luid, alias, IF_MAX_STRING_SIZE + 1) == NO_ERROR) {
        // (#1681) internal buffer -> shared -1 convert; keep the if<N> fallback for the
        // (unreachable) empty-conversion case to stay byte-identical to the pre-de-dup code.
        if (auto a = yuzu::win::from_wide(alias); !a.empty())
            return a;
    }
    return std::format("if{}", static_cast<unsigned long>(idx));
}

} // namespace

std::vector<ArpEntry> enumerate_arp() {
    std::vector<ArpEntry> out;

    PMIB_IPNET_TABLE2 table = nullptr;
    DWORD rc = GetIpNetTable2(AF_UNSPEC, &table);
    if (rc != NO_ERROR || table == nullptr) {
        if (rc != NO_ERROR)
            spdlog::warn("TAR arp: GetIpNetTable2 failed (rc={})", rc);
        return out;
    }

    out.reserve(table->NumEntries);
    bool truncated = false;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const MIB_IPNET_ROW2& row = table->Table[i];
        ArpEntry e;
        e.iface = iface_alias(row.InterfaceLuid, row.InterfaceIndex);
        e.ip_address = sockaddr_inet_to_string(row.Address);
        e.mac_address = mac_to_string(row.PhysicalAddress, row.PhysicalAddressLength);
        e.entry_type = entry_type_for_state(row.State);
        if (e.ip_address.empty())
            continue; // address failed to format — skip defensively
        out.push_back(std::move(e));

        if (out.size() >= kArpEntryCap) {
            truncated = true;
            break;
        }
    }

    FreeMibTable(table);
    // Rate-limit the truncation warn (UP-7): once when it begins, suppressed until
    // the table drops back under the cap.
    static std::atomic<bool> s_arp_cap_warned{false};
    if (truncated) {
        if (!s_arp_cap_warned.exchange(true))
            spdlog::warn("TAR arp: entry cap {} reached — truncating (repeats suppressed until it "
                         "clears)",
                         kArpEntryCap);
    } else {
        s_arp_cap_warned.store(false);
    }
    return out;
}

#elif defined(__APPLE__) // macOS: reuse agents/shared/route_sysctl_arp.hpp

std::vector<ArpEntry> enumerate_arp() {
    std::vector<ArpEntry> out;

    const auto fetch = yuzu::shared::fetch_rt_flags_llinfo();
    if (!fetch.ok) {
        // ok=false is a FAILED sysctl read, not an empty table — same
        // distinction the Windows leg's GetIpNetTable2 failure warn above
        // preserves; collapsing it to {} silently would report the failure
        // as a quiet, empty ARP table.
        spdlog::warn("TAR arp: NET_RT_FLAGS sysctl failed");
        return out;
    }

    const auto parsed = yuzu::shared::parse_rt_flags_llinfo(std::span{fetch.blob});

    // Rate-limit the partial-table warn, same pattern as the Windows leg's
    // cap warn below: once when it begins, suppressed until a subsequent
    // read comes back whole.
    static std::atomic<bool> s_arp_parse_truncated_warned{false};
    if (parsed.truncated) {
        if (!s_arp_parse_truncated_warned.exchange(true))
            spdlog::warn("TAR arp: NET_RT_FLAGS read returned a partial table (repeats "
                         "suppressed until it clears)");
    } else {
        s_arp_parse_truncated_warned.store(false);
    }

    out.reserve(parsed.records.size());
    bool cap_hit = false;
    for (const auto& rec : parsed.records) {
        if (out.size() >= kArpEntryCap) {
            cap_hit = true;
            break;
        }
        out.push_back(arp_entry_from_route_record(rec));
    }

    static std::atomic<bool> s_arp_cap_warned{false};
    if (cap_hit) {
        if (!s_arp_cap_warned.exchange(true))
            spdlog::warn("TAR arp: entry cap {} reached — truncating (repeats suppressed until it "
                         "clears)",
                         kArpEntryCap);
    } else {
        s_arp_cap_warned.store(false);
    }

    // The partial table (if any) is still returned — an ARP table is a SET,
    // and the neighbours that DID parse are individually true; the operator
    // learns about the gap via the warn above, not via a silently smaller
    // "complete-looking" result.
    return out;
}

#else // Linux: /proc/net/arp

std::vector<ArpEntry> enumerate_arp() {
    std::ifstream f("/proc/net/arp");
    if (!f) {
        // Parity with the Windows leg's GetIpNetTable2 failure warn above:
        // a read failure is reported, not silently returned as {} looking
        // like a genuinely empty table.
        spdlog::warn("TAR arp: failed to read /proc/net/arp");
        return {};
    }
    std::ostringstream buf;
    buf << f.rdbuf();

    const auto parsed = parse_proc_net_arp(buf.str(), kArpEntryCap);

    // Rate-limit the cap-truncation warn (UP-7), exactly mirroring the
    // Windows leg's s_arp_cap_warned pattern above: once when it begins,
    // reset once a subsequent read comes back under the cap.
    static std::atomic<bool> s_arp_cap_warned{false};
    if (parsed.truncated) {
        if (!s_arp_cap_warned.exchange(true))
            spdlog::warn("TAR arp: entry cap {} reached — truncating (repeats suppressed until it "
                         "clears)",
                         kArpEntryCap);
    } else {
        s_arp_cap_warned.store(false);
    }

    return parsed.entries;
}

#endif

} // namespace yuzu::tar
