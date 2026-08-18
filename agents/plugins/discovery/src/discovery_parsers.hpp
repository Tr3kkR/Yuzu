/**
 * discovery_parsers.hpp — pure ARP-data parsing/formatting for discovery
 * (Wave-2 PR2.1, WP-C). Portable and header-only: this file and its test
 * TU (test_discovery_parsers.cpp) carry no platform guard and run on every
 * leg. Two consumers in discovery_plugin.cpp: parse_proc_net_arp() on the
 * Linux leg, and format_mac48() on the Windows leg.
 *
 * Kernel format (`net/ipv4/arp.c:arp_seq_show`):
 *   IP address       HW type     Flags       HW address            Mask     Device
 *   192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
 *
 * `Flags` is a hex bitmask; ATF_COM (0x2) marks a resolved ("complete")
 * entry — an in-flight probe lacks that bit and reports an unresolved
 * (usually all-zero) HW address. Both are dropped here, matching the
 * selectivity the old `arp -n` subprocess parser had (it dropped
 * "(incomplete)" rows and required HWtype "ether").
 */
#pragma once

#include <cerrno>
#include <cstdlib>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::discovery {

struct ArpEntry {
    std::string ip;
    std::string mac;
};

/**
 * Format 6 raw bytes as lowercase colon-separated hex ("aa:bb:cc:dd:ee:ff") —
 * the canonical MAC shape every leg of this plugin emits, so a Windows
 * neighbour row and a Linux /proc row are indistinguishable downstream.
 *
 * `addr` must point to at least 6 readable bytes; callers check the platform's
 * own length field first (Windows: MIB_IPNET_ROW2::PhysicalAddressLength).
 *
 * Exists as a pure function because the Windows leg previously formatted MACs
 * with snprintf, which docs/cpp-conventions.md lists under "Forbidden in new
 * code" (printf-family calls). Being portable, it is also compiled and tested
 * on every leg, so the one piece of the Windows ARP path that can be verified
 * off-Windows is verified.
 */
inline std::string format_mac48(const unsigned char* addr) {
    static constexpr char kHex[] = "0123456789abcdef";
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

/**
 * Parse the text of /proc/net/arp into resolved {ip, mac} entries. Pure —
 * no ifstream, no I/O. Tolerates CRLF line endings, ragged/collapsed
 * whitespace, short lines (skipped rather than throwing), and a missing
 * header line (the header is detected by its literal leading "IP" token,
 * so a header-less capture's first data row is never mistaken for one).
 */
inline std::vector<ArpEntry> parse_proc_net_arp(std::string_view text) {
    std::vector<ArpEntry> out;

    std::istringstream stream{std::string{text}};
    std::string line;
    bool first_line = true;

    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back(); // tolerate CRLF captures

        if (first_line) {
            first_line = false;
            std::istringstream probe{line};
            std::string first_tok;
            if (probe >> first_tok && first_tok == "IP")
                continue; // the kernel header always starts with "IP address"
        }

        std::istringstream lss{line};
        std::string ip, hwtype, flags_str, mac, mask, device;
        if (!(lss >> ip >> hwtype >> flags_str >> mac >> mask >> device))
            continue; // short/ragged/blank/truncated line — skip, don't crash

        if (hwtype != "0x1")
            continue; // Ethernet only — preserve the old `arp -n` parser's
                      // hwtype "ether" selectivity (ARPHRD_ETHER == 0x1)

        char* end = nullptr;
        errno = 0;
        const unsigned long flags = std::strtoul(flags_str.c_str(), &end, 16);
        constexpr unsigned long kAtfCom = 0x2;
        if (errno == ERANGE || end == flags_str.c_str() || *end != '\0' || !(flags & kAtfCom))
            continue; // incomplete/unresolved/overflowing entry — no complete bit set

        if (mac.empty() || mac == "00:00:00:00:00:00")
            continue;

        out.push_back(ArpEntry{std::move(ip), std::move(mac)});
    }

    return out;
}

} // namespace yuzu::discovery
