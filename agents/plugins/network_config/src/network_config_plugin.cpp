/**
 * network_config_plugin.cpp — Network configuration plugin for Yuzu
 *
 * Actions:
 *   "adapters"     — Lists network adapters with MAC, speed, status.
 *   "ip_addresses" — Lists assigned IP addresses with subnet and gateway.
 *   "dns_servers"  — Lists configured DNS servers per adapter.
 *   "proxy"        — Returns system proxy configuration.
 *   "dns_cache"    — Returns the DNS resolver cache (Windows, Linux).
 *   "arp"          — Returns the host ARP / neighbour table:
 *                    arp|iface|ip|mac|type.
 *
 * Output is pipe-delimited via write_output().
 */

#include <yuzu/plugin.hpp>

#include <algorithm>
#include <array>
#include <cstdio>
#include <format>
#include <sstream>
#include <string>
#include <string_view>

#include "network_config_parsers.hpp"

#if defined(__linux__) || defined(__APPLE__)
#include <spdlog/spdlog.h>
#endif

#if defined(__linux__)
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iterator> // std::make_move_iterator
#include <map>
#include <span>
#include <vector>

#include <arpa/inet.h>
#include <linux/if.h> // IFF_UP -- see network_config_parsers.hpp's own include comment
#include <linux/if_addr.h> // struct ifaddrmsg -- named directly in fetch_addr_dump()'s request
#include <linux/if_link.h> // struct ifinfomsg -- named directly in fetch_link_dump()'s request
#include <linux/netlink.h>
#include <linux/rtnetlink.h> // struct rtmsg / RTM_GET* / NLM_F_* -- named directly below
#include <sys/socket.h>
#include <unistd.h>

#include <yuzu/agent/runner_status.hpp>     // classify_runner_failure / forward_runner_failure
#include <yuzu/agent/scoped_fd.hpp>         // ScopedFd -- RAII netlink socket owner
#include <yuzu/agent/subprocess_runner.hpp> // run_bounded_subprocess / probe_tool_path (dns_cache argv legs only)
#endif

#if defined(__APPLE__)
// SIOCGIFMEDIA is a native BSD socket ioctl (libc + kernel headers only, no
// framework link) used to read a real adapter link speed for do_adapters().
#include <net/if.h>
#include <net/if_dl.h>  // sockaddr_dl -- getifaddrs' AF_LINK entries (adapters MAC)
#include <net/if_media.h>
#include <net/route.h>  // NET_RT_DUMP / RTF_GATEWAY -- default-route sysctl (ip_addresses)
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <cstddef> // offsetof
#include <cstring>
#include <ifaddrs.h>
#include <map>
#include <netinet/in.h>
#include <span>
#include <vector>

#include "route_sysctl_arp.hpp" // yuzu::shared::{fetch,parse}_rt_flags_llinfo -- reused as-is (arp leg)

#include <yuzu/agent/scoped_cfref.hpp> // ScopedCFRef -- RAII CF object owner (dns_servers/proxy)

#if defined(YUZU_HAVE_SYSTEMCONFIGURATION)
#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>
#endif
#endif

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
#include <win_str.hpp>  // shared yuzu::win wide<->UTF-8 helpers (#1681)
#include <iphlpapi.h>
#include <netioapi.h> // GetIpNetTable2 / MIB_IPNET_ROW2 / ConvertInterfaceLuidToAlias (arp)
#include <winhttp.h>
#include <vector>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#endif

namespace {

#if defined(__APPLE__)
// Real link speed via SIOCGIFMEDIA (a single ioctl on a throwaway datagram
// socket — no framework). Only Ethernet media subtypes are decoded to a
// numeric Mbps; Wi-Fi, virtual interfaces, or an ioctl failure/inactive link
// report the honest 0 (unknown) rather than a fabricated number.
int mac_link_speed_mbps(const std::string& name) {
    // Non-copyable scope owner for the throwaway datagram socket (RAII —
    // no manual close() on any exit path, including future early returns).
    struct SocketGuard {
        int fd;
        explicit SocketGuard(int f) : fd(f) {}
        ~SocketGuard() {
            if (fd >= 0)
                ::close(fd);
        }
        SocketGuard(const SocketGuard&) = delete;
        SocketGuard& operator=(const SocketGuard&) = delete;
    };

    SocketGuard socket_guard{::socket(AF_INET, SOCK_DGRAM, 0)};
    if (socket_guard.fd < 0)
        return 0;
    struct ifmediareq ifmr {};
    std::snprintf(ifmr.ifm_name, sizeof(ifmr.ifm_name), "%s", name.c_str());
    const int rc = ::ioctl(socket_guard.fd, SIOCGIFMEDIA, &ifmr);
    if (rc != 0)
        return 0;
    if (!(ifmr.ifm_status & IFM_AVALID) || !(ifmr.ifm_status & IFM_ACTIVE))
        return 0;
    if (IFM_TYPE(ifmr.ifm_active) != IFM_ETHER)
        return 0;
    // Every Ethernet subtype whose Mbps figure is documented directly by the
    // Darwin if_media.h constant name is grouped here — the ioctl already
    // paid for the lookup, so decoding the rest of the speed-explicit
    // subtypes is a constant-time win. Genuinely speed-ambiguous types
    // (IFM_OTHER, IFM_AUTO, HomePNA, etc.) fall through to the honest 0.
    switch (IFM_SUBTYPE(ifmr.ifm_active)) {
    case IFM_10_T:
        return 10;
    case IFM_100_TX:
    case IFM_100_T4:
    case IFM_100_T2:
    case IFM_100_T:
        return 100;
    case IFM_1000_T:
    case IFM_1000_SX:
    case IFM_1000_LX:
    case IFM_1000_CX:
    case IFM_1000_CX_SGMII:
    case IFM_1000_KX:
        return 1000;
    case IFM_2500_T:
    case IFM_2500_SX:
    case IFM_2500_KX:
    case IFM_2500_X:
        return 2500;
    case IFM_5000_T:
    case IFM_5000_KR:
    case IFM_5000_KR_S:
    case IFM_5000_KR1:
        return 5000;
    case IFM_10G_T:
    case IFM_10G_SR:
    case IFM_10G_LR:
    case IFM_10G_CX4:
    case IFM_10G_KX4:
    case IFM_10G_KR:
    case IFM_10G_CR1:
    case IFM_10G_ER:
    case IFM_10G_TWINAX:
    case IFM_10G_TWINAX_LONG:
    case IFM_10G_LRM:
    case IFM_10G_AOC:
        return 10000;
    case IFM_20G_KR2:
        return 20000;
    case IFM_25G_CR:
    case IFM_25G_KR:
    case IFM_25G_SR:
    case IFM_25G_LR:
    case IFM_25G_T:
    case IFM_25G_CR_S:
    case IFM_25G_CR1:
    case IFM_25G_KR_S:
    case IFM_25G_KR1:
    case IFM_25G_ACC:
    case IFM_25G_AOC:
        return 25000;
    case IFM_40G_CR4:
    case IFM_40G_SR4:
    case IFM_40G_LR4:
    case IFM_40G_KR4:
    case IFM_40G_XLPPI:
    case IFM_40G_XLAUI:
    case IFM_40G_ER4:
        return 40000;
    case IFM_50G_CR2:
    case IFM_50G_KR2:
    case IFM_50G_SR:
    case IFM_50G_LR:
    case IFM_50G_FR:
    case IFM_50G_CP:
    case IFM_50G_KR_PAM4:
        return 50000;
    case IFM_56G_R4:
        return 56000;
    case IFM_100G_CR4:
    case IFM_100G_SR4:
    case IFM_100G_KR4:
    case IFM_100G_LR4:
    case IFM_100G_CP2:
    case IFM_100G_SR2:
    case IFM_100G_DR:
    case IFM_100G_KR2_PAM4:
    case IFM_100G_CAUI2:
    case IFM_100G_CAUI4:
    case IFM_100G_AUI2:
    case IFM_100G_AUI4:
    case IFM_100G_CR_PAM4:
    case IFM_100G_KR_PAM4:
        return 100000;
    default:
        return 0; // unrecognised subtype — honest unknown, never fabricated
    }
}

// Default-route gateway via the PF_ROUTE sysctl dump (NET_RT_DUMP/AF_INET),
// replacing the old `route -n get default | grep gateway` shell pipe. The
// impure sysctl fetch stays here; the bounds-checked walk lives in
// network_config_parsers.hpp's parse_default_route_dump().
std::string mac_default_gateway() {
    int mib[6] = {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0};
    std::size_t needed = 0;
    if (::sysctl(mib, 6, nullptr, &needed, nullptr, 0) != 0 || needed == 0)
        return "-";
    std::vector<unsigned char> buf(needed);
    if (::sysctl(mib, 6, buf.data(), &needed, nullptr, 0) != 0)
        return "-";
    buf.resize(needed);
    auto parsed = yuzu::network_config::parse_default_route_dump(buf);
    if (parsed.truncated)
        spdlog::warn("network_config: PF_ROUTE default-route dump was truncated");
    return parsed.found ? parsed.gateway : "-";
}

#if defined(YUZU_HAVE_SYSTEMCONFIGURATION)
// One SCDynamicStore session per call — cheap, no persistent state, no
// change-notification callback registered (dns_servers/proxy only ever read
// a point-in-time snapshot).
yuzu::agent::ScopedCFRef<SCDynamicStoreRef> open_dynamic_store() {
    return yuzu::agent::ScopedCFRef<SCDynamicStoreRef>(
        SCDynamicStoreCreate(kCFAllocatorDefault, CFSTR("com.yuzu.agent.network_config"), nullptr,
                             nullptr));
}

std::string cfstring_to_utf8(CFStringRef s) {
    if (!s)
        return {};
    const CFIndex len = CFStringGetLength(s);
    if (len == 0)
        return {};
    const CFIndex max_size = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
    std::string buf(static_cast<std::size_t>(max_size), '\0');
    if (!CFStringGetCString(s, buf.data(), max_size, kCFStringEncodingUTF8))
        return {};
    buf.resize(std::strlen(buf.c_str()));
    return buf;
}
#endif // YUZU_HAVE_SYSTEMCONFIGURATION
#endif // __APPLE__

#ifdef _WIN32
// Format a MAC address from a byte array
std::string format_mac(const BYTE* addr, DWORD len) {
    if (len < 6)
        return "-";
    return std::format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", addr[0], addr[1], addr[2],
                       addr[3], addr[4], addr[5]);
}

// wide->UTF-8 conversion now via the shared win_str.hpp (#1681); from_wide is
// behaviour-identical to the old NUL-terminated wide_to_utf8 for valid input.
using yuzu::win::from_wide;

// Convert a SOCKADDR to a string
std::string sockaddr_to_string(LPSOCKADDR sa) {
    char buf[128]{};
    if (sa->sa_family == AF_INET) {
        auto* v4 = reinterpret_cast<sockaddr_in*>(sa);
        inet_ntop(AF_INET, &v4->sin_addr, buf, sizeof(buf));
    } else if (sa->sa_family == AF_INET6) {
        auto* v6 = reinterpret_cast<sockaddr_in6*>(sa);
        inet_ntop(AF_INET6, &v6->sin6_addr, buf, sizeof(buf));
    }
    return buf;
}
#endif

#if defined(__linux__)

// ── rtnetlink dump helpers (adapters/ip_addresses legs) ──────────────────
//
// Thin impure shells: own the socket/send/recv mechanics only. Every byte
// of decode logic lives in network_config_parsers.hpp's pure, span-based
// parse_rtnetlink_*_chunk() functions -- these loops just hand each
// recvmsg() buffer to the decoder and accumulate its records.

constexpr std::size_t kNetlinkRecvBufSize = 16384; // matches net_quality_sampler.cpp's convention

yuzu::agent::ScopedFd open_rtnetlink_socket() {
    return yuzu::agent::ScopedFd{::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)};
}

struct LinkDumpResult {
    std::vector<yuzu::network_config::RtLinkRecord> records;
    bool ok = false; // true iff the dump completed (NLMSG_DONE) without error/truncation
};

LinkDumpResult fetch_link_dump() {
    LinkDumpResult result;
    auto fd = open_rtnetlink_socket();
    if (!fd)
        return result;

    constexpr std::uint32_t kSeq = 1;
    struct {
        struct nlmsghdr nlh;
        struct ifinfomsg ifi;
    } req{};
    req.nlh.nlmsg_len = sizeof(req);
    req.nlh.nlmsg_type = RTM_GETLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = kSeq;
    req.ifi.ifi_family = AF_UNSPEC;

    struct sockaddr_nl sa {};
    sa.nl_family = AF_NETLINK;
    struct iovec iov {&req, sizeof(req)};
    struct msghdr m {};
    m.msg_name = &sa;
    m.msg_namelen = sizeof(sa);
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    if (::sendmsg(fd.get(), &m, 0) <= 0)
        return result;

    alignas(NLMSG_ALIGNTO) unsigned char buf[kNetlinkRecvBufSize];
    bool truncated = false;
    for (;;) {
        struct sockaddr_nl rsa {};
        struct iovec riov {buf, sizeof(buf)};
        struct msghdr rm {};
        rm.msg_name = &rsa;
        rm.msg_namelen = sizeof(rsa);
        rm.msg_iov = &riov;
        rm.msg_iovlen = 1;
        ssize_t n;
        do {
            n = ::recvmsg(fd.get(), &rm, 0);
        } while (n < 0 && errno == EINTR);
        if (n <= 0)
            return result; // ok stays false — an honest incomplete read

        auto chunk = yuzu::network_config::parse_rtnetlink_link_chunk(
            std::span<const unsigned char>(buf, static_cast<std::size_t>(n)), kSeq);
        result.records.insert(result.records.end(), std::make_move_iterator(chunk.records.begin()),
                              std::make_move_iterator(chunk.records.end()));
        if (chunk.truncated)
            truncated = true;
        if (chunk.error)
            return result;
        if (chunk.done) {
            result.ok = !truncated;
            return result;
        }
    }
}

struct AddrDumpResult {
    std::vector<yuzu::network_config::RtAddrRecord> records;
    bool ok = false;
};

AddrDumpResult fetch_addr_dump() {
    AddrDumpResult result;
    auto fd = open_rtnetlink_socket();
    if (!fd)
        return result;

    constexpr std::uint32_t kSeq = 2;
    struct {
        struct nlmsghdr nlh;
        struct ifaddrmsg ifa;
    } req{};
    req.nlh.nlmsg_len = sizeof(req);
    req.nlh.nlmsg_type = RTM_GETADDR;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = kSeq;
    req.ifa.ifa_family = AF_UNSPEC;

    struct sockaddr_nl sa {};
    sa.nl_family = AF_NETLINK;
    struct iovec iov {&req, sizeof(req)};
    struct msghdr m {};
    m.msg_name = &sa;
    m.msg_namelen = sizeof(sa);
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    if (::sendmsg(fd.get(), &m, 0) <= 0)
        return result;

    alignas(NLMSG_ALIGNTO) unsigned char buf[kNetlinkRecvBufSize];
    bool truncated = false;
    for (;;) {
        struct sockaddr_nl rsa {};
        struct iovec riov {buf, sizeof(buf)};
        struct msghdr rm {};
        rm.msg_name = &rsa;
        rm.msg_namelen = sizeof(rsa);
        rm.msg_iov = &riov;
        rm.msg_iovlen = 1;
        ssize_t n;
        do {
            n = ::recvmsg(fd.get(), &rm, 0);
        } while (n < 0 && errno == EINTR);
        if (n <= 0)
            return result;

        auto chunk = yuzu::network_config::parse_rtnetlink_addr_chunk(
            std::span<const unsigned char>(buf, static_cast<std::size_t>(n)), kSeq);
        result.records.insert(result.records.end(), std::make_move_iterator(chunk.records.begin()),
                              std::make_move_iterator(chunk.records.end()));
        if (chunk.truncated)
            truncated = true;
        if (chunk.error)
            return result;
        if (chunk.done) {
            result.ok = !truncated;
            return result;
        }
    }
}

struct RouteDumpResult {
    std::vector<yuzu::network_config::RtRouteRecord> records;
    bool ok = false;
};

RouteDumpResult fetch_default_route_dump() {
    RouteDumpResult result;
    auto fd = open_rtnetlink_socket();
    if (!fd)
        return result;

    constexpr std::uint32_t kSeq = 3;
    struct {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
    } req{};
    req.nlh.nlmsg_len = sizeof(req);
    req.nlh.nlmsg_type = RTM_GETROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = kSeq;
    req.rtm.rtm_family = AF_INET;

    struct sockaddr_nl sa {};
    sa.nl_family = AF_NETLINK;
    struct iovec iov {&req, sizeof(req)};
    struct msghdr m {};
    m.msg_name = &sa;
    m.msg_namelen = sizeof(sa);
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    if (::sendmsg(fd.get(), &m, 0) <= 0)
        return result;

    alignas(NLMSG_ALIGNTO) unsigned char buf[kNetlinkRecvBufSize];
    bool truncated = false;
    for (;;) {
        struct sockaddr_nl rsa {};
        struct iovec riov {buf, sizeof(buf)};
        struct msghdr rm {};
        rm.msg_name = &rsa;
        rm.msg_namelen = sizeof(rsa);
        rm.msg_iov = &riov;
        rm.msg_iovlen = 1;
        ssize_t n;
        do {
            n = ::recvmsg(fd.get(), &rm, 0);
        } while (n < 0 && errno == EINTR);
        if (n <= 0)
            return result;

        auto chunk = yuzu::network_config::parse_rtnetlink_route_chunk(
            std::span<const unsigned char>(buf, static_cast<std::size_t>(n)), kSeq);
        result.records.insert(result.records.end(), std::make_move_iterator(chunk.records.begin()),
                              std::make_move_iterator(chunk.records.end()));
        if (chunk.truncated)
            truncated = true;
        if (chunk.error)
            return result;
        if (chunk.done) {
            result.ok = !truncated;
            return result;
        }
    }
}

#endif // __linux__

// ── adapters action ───────────────────────────────────────────────────────

int do_adapters(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    ULONG buf_size = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &buf_size);
    if (buf_size == 0) {
        ctx.write_output("adapter|No adapters found|-|0|unknown");
        return 0;
    }

    std::vector<BYTE> buffer(buf_size);
    auto* adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, adapters, &buf_size) !=
        NO_ERROR) {
        ctx.write_output("adapter|Error enumerating adapters|-|0|unknown");
        return 1;
    }

    for (auto* a = adapters; a; a = a->Next) {
        // Skip loopback and tunnel adapters
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;
        if (a->IfType == IF_TYPE_TUNNEL)
            continue;

        auto name = from_wide(a->FriendlyName);
        auto mac = format_mac(a->PhysicalAddress, a->PhysicalAddressLength);
        auto speed_mbps = a->TransmitLinkSpeed / 1'000'000;
        const char* status = (a->OperStatus == IfOperStatusUp) ? "up" : "down";

        ctx.write_output(std::format("adapter|{}|{}|{}|{}", name, mac, speed_mbps, status));
    }

#elif defined(__linux__)
    auto links = fetch_link_dump();
    for (const auto& rec : links.records) {
        if (rec.name.empty() || rec.name == "lo")
            continue;

        // Speed via sysfs (native file read, unrelated to the rtnetlink
        // dump above) — unchanged from the pre-migration implementation.
        std::string speed = "0";
        std::ifstream speed_file("/sys/class/net/" + rec.name + "/speed");
        if (speed_file) {
            std::getline(speed_file, speed);
            if (speed.empty() || speed[0] == '-')
                speed = "0";
        }

        const std::string mac = rec.mac.empty() ? "-" : rec.mac;
        ctx.write_output(
            std::format("adapter|{}|{}|{}|{}", rec.name, mac, speed, rec.up ? "up" : "down"));
    }
    if (!links.ok) {
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "network_config:rtnetlink_link_dump_incomplete");
    }

#elif defined(__APPLE__)
    struct ifaddrs* head = nullptr;
    if (::getifaddrs(&head) != 0) {
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "network_config:getifaddrs_failed");
        return 0;
    }

    // getifaddrs() returns one entry per (interface, address-family) pair —
    // collapse to one row per interface name, in first-seen order, matching
    // the old ifconfig-parse's per-adapter grouping.
    std::vector<std::string> order;
    std::map<std::string, std::string> mac_by_name;
    std::map<std::string, bool> up_by_name;
    for (auto* p = head; p != nullptr; p = p->ifa_next) {
        if (!p->ifa_name)
            continue;
        const std::string name = p->ifa_name;
        if (name == "lo0")
            continue;
        if (std::find(order.begin(), order.end(), name) == order.end())
            order.push_back(name);
        const bool up = (p->ifa_flags & IFF_UP) != 0;
        auto up_it = up_by_name.find(name);
        up_by_name[name] = (up_it != up_by_name.end()) ? (up_it->second || up) : up;

        if (p->ifa_addr && p->ifa_addr->sa_family == AF_LINK) {
            // sockaddr_dl's real on-wire size (sa_len) routinely exceeds
            // sizeof(struct sockaddr_dl): sdl_data is a fixed 12-byte
            // placeholder array that only reliably holds the NAME; the
            // trailing link-layer address bytes can land past it for a
            // longer interface name. Same discipline as
            // route_sysctl_arp.hpp's RTAX_GATEWAY handling: memcpy only the
            // small fixed-offset header fields (sdl_nlen/sdl_alen) into a
            // local struct for a safe read, then read the MAC bytes
            // directly from the ORIGINAL buffer at their bounds-checked
            // offset — never from the (possibly truncated) local copy.
            const auto* raw = reinterpret_cast<const unsigned char*>(p->ifa_addr);
            const auto sa_len = static_cast<std::size_t>(p->ifa_addr->sa_len);
            struct sockaddr_dl sdl {};
            std::memcpy(&sdl, raw, std::min(sizeof(sdl), sa_len));
            const std::size_t needed = offsetof(struct sockaddr_dl, sdl_data) +
                                       static_cast<std::size_t>(sdl.sdl_nlen) +
                                       static_cast<std::size_t>(sdl.sdl_alen);
            if (sdl.sdl_alen == 6 && sa_len >= needed) {
                unsigned char mac[6];
                std::memcpy(mac, raw + offsetof(struct sockaddr_dl, sdl_data) + sdl.sdl_nlen, 6);
                mac_by_name[name] = yuzu::network_config::format_mac(mac, 6);
            }
        }
    }
    ::freeifaddrs(head);

    for (const auto& name : order) {
        auto mac_it = mac_by_name.find(name);
        const std::string mac =
            (mac_it != mac_by_name.end() && !mac_it->second.empty()) ? mac_it->second : "-";
        ctx.write_output(std::format("adapter|{}|{}|{}|{}", name, mac, mac_link_speed_mbps(name),
                                     up_by_name[name] ? "up" : "down"));
    }
#endif
    return 0;
}

// ── ip_addresses action ───────────────────────────────────────────────────

int do_ip_addresses(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    ULONG buf_size = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS, nullptr, nullptr, &buf_size);
    if (buf_size == 0)
        return 0;

    std::vector<BYTE> buffer(buf_size);
    auto* adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS, nullptr, adapters, &buf_size) !=
        NO_ERROR) {
        return 1;
    }

    for (auto* a = adapters; a; a = a->Next) {
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;
        if (a->IfType == IF_TYPE_TUNNEL)
            continue;

        auto adapter_name = from_wide(a->FriendlyName);

        // Collect first gateway
        std::string gateway = "-";
        for (auto* gw = a->FirstGatewayAddress; gw; gw = gw->Next) {
            auto addr = sockaddr_to_string(gw->Address.lpSockaddr);
            if (!addr.empty()) {
                gateway = addr;
                break;
            }
        }

        // List unicast addresses
        for (auto* ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
            auto addr = sockaddr_to_string(ua->Address.lpSockaddr);
            if (addr.empty())
                continue;
            ctx.write_output(
                std::format("ip|{}|{}|{}|{}", adapter_name, addr, ua->OnLinkPrefixLength, gateway));
        }
    }

#elif defined(__linux__)
    auto links = fetch_link_dump();
    std::map<int, std::string> name_by_index;
    for (const auto& r : links.records)
        name_by_index[r.index] = r.name;

    auto route = fetch_default_route_dump();
    std::string default_gw = "-";
    if (!route.records.empty())
        default_gw = route.records.front().gateway;

    auto addrs = fetch_addr_dump();
    for (const auto& rec : addrs.records) {
        std::string name = !rec.label.empty() ? rec.label : std::string{};
        if (name.empty()) {
            auto it = name_by_index.find(rec.index);
            name = (it != name_by_index.end()) ? it->second : std::format("if{}", rec.index);
        }
        if (name == "lo")
            continue;
        ctx.write_output(std::format("ip|{}|{}|{}|{}", name, rec.address,
                                     static_cast<unsigned int>(rec.prefix_len), default_gw));
    }
    if (!links.ok || !addrs.ok || !route.ok) {
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "network_config:rtnetlink_dump_incomplete");
    }

#elif defined(__APPLE__)
    const std::string default_gw = mac_default_gateway();

    struct ifaddrs* head = nullptr;
    if (::getifaddrs(&head) != 0) {
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "network_config:getifaddrs_failed");
        return 0;
    }

    char text_buf[INET6_ADDRSTRLEN];
    for (auto* p = head; p != nullptr; p = p->ifa_next) {
        if (!p->ifa_name || !p->ifa_addr)
            continue;
        const std::string name = p->ifa_name;
        if (name == "lo0")
            continue;

        if (p->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in sin {};
            std::memcpy(&sin, p->ifa_addr, sizeof(sin));
            if (!::inet_ntop(AF_INET, &sin.sin_addr, text_buf, sizeof(text_buf)))
                continue;
            unsigned int prefix = 0;
            if (p->ifa_netmask) {
                struct sockaddr_in mask {};
                std::memcpy(&mask, p->ifa_netmask, sizeof(mask));
                std::uint32_t m = ntohl(mask.sin_addr.s_addr);
                while (m & 0x80000000u) {
                    ++prefix;
                    m <<= 1;
                }
            }
            ctx.write_output(std::format("ip|{}|{}|{}|{}", name, text_buf, prefix, default_gw));
        } else if (p->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 sin6 {};
            std::memcpy(&sin6, p->ifa_addr,
                       std::min(sizeof(sin6), static_cast<std::size_t>(p->ifa_addr->sa_len)));
            if (!::inet_ntop(AF_INET6, &sin6.sin6_addr, text_buf, sizeof(text_buf)))
                continue;
            unsigned int prefix = 0;
            if (p->ifa_netmask) {
                struct sockaddr_in6 mask6 {};
                std::memcpy(&mask6, p->ifa_netmask,
                           std::min(sizeof(mask6),
                                    static_cast<std::size_t>(p->ifa_netmask->sa_len)));
                for (unsigned char byte : mask6.sin6_addr.s6_addr) {
                    while (byte & 0x80) {
                        ++prefix;
                        byte <<= 1;
                    }
                }
            }
            std::string addr = text_buf;
            const auto pct = addr.find('%');
            if (pct != std::string::npos)
                addr = addr.substr(0, pct);
            ctx.write_output(std::format("ip|{}|{}|{}|{}", name, addr, prefix, default_gw));
        }
    }
    ::freeifaddrs(head);
#endif
    return 0;
}

// ── dns_servers action ────────────────────────────────────────────────────

int do_dns_servers(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    ULONG buf_size = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &buf_size);
    if (buf_size == 0)
        return 0;

    std::vector<BYTE> buffer(buf_size);
    auto* adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, adapters, &buf_size) !=
        NO_ERROR) {
        return 1;
    }

    for (auto* a = adapters; a; a = a->Next) {
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;
        if (a->IfType == IF_TYPE_TUNNEL)
            continue;

        auto adapter_name = from_wide(a->FriendlyName);

        for (auto* dns = a->FirstDnsServerAddress; dns; dns = dns->Next) {
            auto addr = sockaddr_to_string(dns->Address.lpSockaddr);
            if (addr.empty())
                continue;
            auto family = dns->Address.lpSockaddr->sa_family;
            const char* type = (family == AF_INET6) ? "IPv6" : "IPv4";
            ctx.write_output(std::format("dns|{}|{}|{}", adapter_name, addr, type));
        }
    }

#elif defined(__linux__)
    std::ifstream resolv("/etc/resolv.conf");
    if (resolv) {
        std::string line;
        while (std::getline(resolv, line)) {
            if (line.starts_with("nameserver ")) {
                auto server = line.substr(11);
                auto type = (server.find(':') != std::string::npos) ? "IPv6" : "IPv4";
                ctx.write_output(std::format("dns|system|{}|{}", server, type));
            }
        }
    }

#elif defined(__APPLE__)
#if defined(YUZU_HAVE_SYSTEMCONFIGURATION)
    auto store = open_dynamic_store();
    if (store) {
        yuzu::agent::ScopedCFRef<CFDictionaryRef> dns_dict(static_cast<CFDictionaryRef>(
            SCDynamicStoreCopyValue(store.get(), CFSTR("State:/Network/Global/DNS"))));
        if (dns_dict) {
            auto* servers = static_cast<CFArrayRef>(
                CFDictionaryGetValue(dns_dict.get(), CFSTR("ServerAddresses")));
            if (servers) {
                const CFIndex count = CFArrayGetCount(servers);
                for (CFIndex i = 0; i < count; ++i) {
                    auto* item = static_cast<CFStringRef>(CFArrayGetValueAtIndex(servers, i));
                    auto server = cfstring_to_utf8(item);
                    if (server.empty())
                        continue;
                    auto type = (server.find(':') != std::string::npos) ? "IPv6" : "IPv4";
                    ctx.write_output(std::format("dns|system|{}|{}", server, type));
                }
            }
        }
    }
#else
    // Compiled without SystemConfiguration -- honest gap, no fabricated list.
    ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                          "network_config:no_systemconfiguration");
#endif
#endif
    return 0;
}

// ── proxy action ──────────────────────────────────────────────────────────

int do_proxy(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxy_cfg{};
    if (WinHttpGetIEProxyConfigForCurrentUser(&proxy_cfg)) {
        if (proxy_cfg.lpszAutoConfigUrl) {
            ctx.write_output(std::format("proxy_type|pac"));
            ctx.write_output(
                std::format("proxy_address|{}", from_wide(proxy_cfg.lpszAutoConfigUrl)));
            GlobalFree(proxy_cfg.lpszAutoConfigUrl);
        }
        if (proxy_cfg.lpszProxy) {
            auto proxy = from_wide(proxy_cfg.lpszProxy);
            ctx.write_output(std::format("proxy_type|http"));
            ctx.write_output(std::format("proxy_address|{}", proxy));
            GlobalFree(proxy_cfg.lpszProxy);
        }
        if (proxy_cfg.lpszProxyBypass) {
            ctx.write_output(std::format("bypass|{}", from_wide(proxy_cfg.lpszProxyBypass)));
            GlobalFree(proxy_cfg.lpszProxyBypass);
        }
        if (!proxy_cfg.lpszAutoConfigUrl && !proxy_cfg.lpszProxy) {
            if (proxy_cfg.fAutoDetect) {
                ctx.write_output("proxy_type|auto_detect");
            } else {
                ctx.write_output("proxy_type|none");
            }
        }
    } else {
        ctx.write_output("proxy_type|none");
    }

#elif defined(__linux__)
    bool found = false;
    for (const char* var : {"http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy",
                            "ALL_PROXY", "no_proxy", "NO_PROXY"}) {
        const char* val = std::getenv(var);
        if (val && *val) {
            if (std::string_view(var).find("no_proxy") != std::string_view::npos ||
                std::string_view(var).find("NO_PROXY") != std::string_view::npos) {
                ctx.write_output(std::format("bypass|{}", val));
            } else {
                ctx.write_output(std::format("proxy_type|{}", var));
                ctx.write_output(std::format("proxy_address|{}", val));
            }
            found = true;
        }
    }
    if (!found) {
        ctx.write_output("proxy_type|none");
    }

#elif defined(__APPLE__)
#if defined(YUZU_HAVE_SYSTEMCONFIGURATION)
    // SCDynamicStoreCopyProxies covers every network service, not only
    // Wi-Fi -- a disclosed behavior improvement over the old
    // `networksetup -getwebproxy Wi-Fi` / `-getautoproxyurl Wi-Fi` pair,
    // which only ever inspected one interface.
    yuzu::agent::ScopedCFRef<CFDictionaryRef> proxies(SCDynamicStoreCopyProxies(nullptr));
    bool emitted = false;
    if (proxies) {
        auto get_bool = [&](CFStringRef key) -> bool {
            const void* v = CFDictionaryGetValue(proxies.get(), key);
            if (!v)
                return false;
            if (CFGetTypeID(v) == CFBooleanGetTypeID())
                return CFBooleanGetValue(static_cast<CFBooleanRef>(v));
            if (CFGetTypeID(v) == CFNumberGetTypeID()) {
                int val = 0;
                CFNumberGetValue(static_cast<CFNumberRef>(v), kCFNumberIntType, &val);
                return val != 0;
            }
            return false;
        };
        auto get_string = [&](CFStringRef key) -> std::string {
            const void* v = CFDictionaryGetValue(proxies.get(), key);
            if (!v || CFGetTypeID(v) != CFStringGetTypeID())
                return {};
            return cfstring_to_utf8(static_cast<CFStringRef>(v));
        };
        auto get_int = [&](CFStringRef key) -> int {
            const void* v = CFDictionaryGetValue(proxies.get(), key);
            if (!v || CFGetTypeID(v) != CFNumberGetTypeID())
                return 0;
            int val = 0;
            CFNumberGetValue(static_cast<CFNumberRef>(v), kCFNumberIntType, &val);
            return val;
        };

        // PAC first, matching the old auto-proxy branch's priority.
        if (get_bool(kSCPropNetProxiesProxyAutoConfigEnable)) {
            auto url = get_string(kSCPropNetProxiesProxyAutoConfigURLString);
            if (!url.empty()) {
                ctx.write_output("proxy_type|pac");
                ctx.write_output(std::format("proxy_address|{}", url));
                emitted = true;
            }
        }
        if (!emitted && get_bool(kSCPropNetProxiesHTTPEnable)) {
            auto host = get_string(kSCPropNetProxiesHTTPProxy);
            const int port = get_int(kSCPropNetProxiesHTTPPort);
            if (!host.empty()) {
                ctx.write_output("proxy_type|http");
                ctx.write_output(std::format("proxy_address|{}:{}", host, port));
                emitted = true;
            }
        }

        auto* bypass_list = static_cast<CFArrayRef>(
            CFDictionaryGetValue(proxies.get(), kSCPropNetProxiesExceptionsList));
        if (bypass_list) {
            const CFIndex count = CFArrayGetCount(bypass_list);
            std::string joined;
            for (CFIndex i = 0; i < count; ++i) {
                auto* item = static_cast<CFStringRef>(CFArrayGetValueAtIndex(bypass_list, i));
                auto s = cfstring_to_utf8(item);
                if (s.empty())
                    continue;
                if (!joined.empty())
                    joined += ',';
                joined += s;
            }
            if (!joined.empty())
                ctx.write_output(std::format("bypass|{}", joined));
        }
    }
    if (!emitted)
        ctx.write_output("proxy_type|none");
#else
    ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                          "network_config:no_systemconfiguration");
    ctx.write_output("proxy_type|none");
#endif
#endif
    return 0;
}

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// Windows reads every leg through native, in-process Win32 APIs (rung 1).
// Linux reads adapters/ip_addresses via rtnetlink (RTM_GETLINK/RTM_GETADDR/
// RTM_GETROUTE, AF_NETLINK SOCK_RAW), dns_servers/proxy via direct file/env
// reads, and arp via a native /proc/net/arp read — all rung 1. dns_cache on
// Linux is the one remaining spawn site, now a direct argv invocation of
// `resolvectl`/`systemd-resolve` (no shell), rung 2. macOS reads
// adapters/ip_addresses via getifaddrs + SIOCGIFMEDIA/PF_ROUTE sysctl,
// dns_servers/proxy via SCDynamicStore, and arp via the PF_ROUTE
// NET_RT_FLAGS/RTF_LLINFO sysctl (agents/shared/route_sysctl_arp.hpp) —
// all rung 1, zero `/bin/sh` occurrences anywhere in this plugin. macOS
// dns_cache stays a permanent OS capability gap (see do_dns_cache's own
// comment): dscacheutil -cachedump was gutted upstream and there is nothing
// left to shell out to.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "adapters",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "rtnetlink (RTM_GETLINK)", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "getifaddrs + SIOCGIFMEDIA", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "GetAdaptersAddresses", nullptr},
    },
    {
        /* .action      = */ "ip_addresses",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "rtnetlink (RTM_GETADDR/RTM_GETROUTE)", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "getifaddrs + PF_ROUTE sysctl", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "GetAdaptersAddresses", nullptr},
    },
    {
        /* .action      = */ "dns_servers",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "/etc/resolv.conf read", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "SCDynamicStore", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "GetAdaptersAddresses", nullptr},
    },
    {
        /* .action      = */ "proxy",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "environment variables", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "SCDynamicStoreCopyProxies", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "WinHttpGetIEProxyConfigForCurrentUser", nullptr},
    },
    {
        /* .action      = */ "dns_cache",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 2, "resolvectl via direct-argv runner",
         "falls back to systemd-resolve statistics, or reports unavailable, when resolvectl is "
         "absent"},
        // macOS: no shell-out is even attempted — dscacheutil -cachedump was
        // gutted upstream and can only fail, a permanent OS capability gap
        // (do_dns_cache's own comment), never a transient failure.
        /* .macos_leg   = */ {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "DnsGetCacheDataTable (dnsapi.dll)", nullptr},
    },
    {
        /* .action      = */ "arp",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 1, "/proc/net/arp", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "PF_ROUTE sysctl RTF_LLINFO", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 1, "GetIpNetTable2", nullptr},
    },
};

} // namespace

class NetworkConfigPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "network_config"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Reports network adapter configuration, IP addresses, DNS servers, and proxy "
               "settings";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"adapters", "ip_addresses", "dns_servers", "proxy",
                                     "dns_cache", "arp",         nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        if (action == "adapters")
            return do_adapters(ctx);
        if (action == "ip_addresses")
            return do_ip_addresses(ctx);
        if (action == "dns_servers")
            return do_dns_servers(ctx);
        if (action == "proxy")
            return do_proxy(ctx);
        if (action == "dns_cache")
            return do_dns_cache(ctx);
        if (action == "arp")
            return do_arp(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
    // arp|iface|ip|mac|type — the host ARP / IPv6-neighbour table. Windows reads the
    // kernel neighbour cache via GetIpNetTable2(AF_UNSPEC); Linux reads /proc/net/arp
    // natively; macOS reads the PF_ROUTE NET_RT_FLAGS/RTF_LLINFO sysctl via
    // agents/shared/route_sysctl_arp.hpp, reused as-is. Mirrors the proven
    // enumeration in tar_arp_collector.cpp (reimplemented here — the TAR plugin
    // internals aren't linked into network_config).
    static int do_arp(yuzu::CommandContext& ctx) {
#ifdef _WIN32
        // Cap entries so a large/forged neighbour cache can't produce an unbounded
        // response (mirrors the TAR collector's kArpEntryCap posture).
        constexpr ULONG kArpEntryCap = 20000;

        auto state_to_type = [](NL_NEIGHBOR_STATE st) -> const char* {
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
        };
        auto mac_string = [](const UCHAR* addr, ULONG len) -> std::string {
            if (len == 0)
                return "-"; // incomplete entry — no hardware address yet
            std::string out;
            static const char* kHex = "0123456789abcdef";
            for (ULONG i = 0; i < len; ++i) {
                if (i)
                    out += ':';
                out += kHex[addr[i] >> 4];
                out += kHex[addr[i] & 0x0F];
            }
            return out;
        };
        auto ip_string = [](const SOCKADDR_INET& a) -> std::string {
            char buf[INET6_ADDRSTRLEN]{};
            if (a.si_family == AF_INET)
                inet_ntop(AF_INET, const_cast<IN_ADDR*>(&a.Ipv4.sin_addr), buf, sizeof(buf));
            else if (a.si_family == AF_INET6)
                inet_ntop(AF_INET6, const_cast<IN6_ADDR*>(&a.Ipv6.sin6_addr), buf, sizeof(buf));
            return buf;
        };
        auto iface_name = [](const NET_LUID& luid, NET_IFINDEX idx) -> std::string {
            wchar_t alias[IF_MAX_STRING_SIZE + 1]{};
            if (ConvertInterfaceLuidToAlias(&luid, alias, IF_MAX_STRING_SIZE + 1) == NO_ERROR)
                return from_wide(alias);
            return std::format("if{}", static_cast<unsigned long>(idx));
        };

        PMIB_IPNET_TABLE2 table = nullptr;
        DWORD rc = GetIpNetTable2(AF_UNSPEC, &table);
        if (rc != NO_ERROR || table == nullptr) {
            ctx.write_output(std::format("error|GetIpNetTable2 failed (rc={})", rc));
            return 1;
        }
        // RAII owner: FreeMibTable runs on every scope exit, including an exception
        // thrown by std::format / write_output between here and the end of the loop
        // (a manual FreeMibTable would leak the kernel table on that path).
        // Non-copyable: a copy would duplicate `t` and both destructors would call
        // FreeMibTable on the same kernel table pointer (double-free). Mirrors
        // SocketGuard above (~:91-100).
        struct MibTableGuard {
            PMIB_IPNET_TABLE2 t;
            explicit MibTableGuard(PMIB_IPNET_TABLE2 tbl) : t(tbl) {}
            ~MibTableGuard() { if (t) FreeMibTable(t); }
            MibTableGuard(const MibTableGuard&) = delete;
            MibTableGuard& operator=(const MibTableGuard&) = delete;
        } table_guard{table};
        ULONG emitted = 0;
        for (ULONG i = 0; i < table->NumEntries && emitted < kArpEntryCap; ++i) {
            const MIB_IPNET_ROW2& row = table->Table[i];
            std::string ip = ip_string(row.Address);
            if (ip.empty())
                continue; // address failed to format — skip defensively
            ctx.write_output(std::format(
                "arp|{}|{}|{}|{}", iface_name(row.InterfaceLuid, row.InterfaceIndex), ip,
                mac_string(row.PhysicalAddress, row.PhysicalAddressLength),
                state_to_type(row.State)));
            ++emitted;
        }
        return 0; // ~MibTableGuard frees the table on every path

#elif defined(__linux__)
        std::ifstream in("/proc/net/arp");
        if (!in) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "network_config:proc_net_arp_unreadable");
            ctx.write_output("arp|not_available");
            return 0;
        }
        std::ostringstream contents;
        contents << in.rdbuf();
        if (in.bad()) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "network_config:proc_net_arp_read_error");
            ctx.write_output("arp|not_available");
            return 0;
        }
        for (const auto& e : yuzu::network_config::parse_proc_net_arp(contents.str())) {
            ctx.write_output(std::format("arp|{}|{}|{}|{}", e.iface, e.ip, e.mac, e.type));
        }
        return 0;

#elif defined(__APPLE__)
        auto fetched = yuzu::shared::fetch_rt_flags_llinfo();
        if (!fetched.ok) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "network_config:pf_route_arp_sysctl_failed");
            ctx.write_output("arp|not_available");
            return 0;
        }
        auto parsed = yuzu::shared::parse_rt_flags_llinfo(fetched.blob);
        if (parsed.truncated) {
            ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "network_config:pf_route_arp_truncated");
        }
        // route_sysctl_arp.hpp's ArpRecord carries only {ip, mac} — no
        // interface index and no static/dynamic distinction (RTF_LLINFO
        // mixes both without differentiating). Reused as-is (owned by an
        // earlier package); iface/type are honestly reported as unknown ("-")
        // rather than guessed.
        for (const auto& rec : parsed.records) {
            ctx.write_output(std::format("arp|-|{}|{}|-", rec.ip, rec.mac));
        }
        return 0;

#else
        // Honest sentinel, not an error: no ARP mechanism on this platform.
        ctx.write_output("arp|not_available");
        return 0;
#endif
    }

    static int do_dns_cache(yuzu::CommandContext& ctx) {
#ifdef _WIN32
        // Dynamically load DnsGetCacheDataTable from dnsapi.dll
        using DNS_CACHE_ENTRY = struct _DNS_CACHE_ENTRY {
            struct _DNS_CACHE_ENTRY* pNext;
            PWSTR pszName;
            WORD wType;
            WORD wDataLength;
            DWORD dwFlags;
        };
        using DnsGetCacheDataTableFn = BOOL(WINAPI*)(DNS_CACHE_ENTRY*);

        auto hDnsApi = LoadLibraryA("dnsapi.dll");
        if (!hDnsApi) {
            ctx.write_output("dns_cache|not_available|dnsapi.dll not found");
            return 0;
        }

        auto pFunc = reinterpret_cast<DnsGetCacheDataTableFn>(
            GetProcAddress(hDnsApi, "DnsGetCacheDataTable"));
        if (!pFunc) {
            FreeLibrary(hDnsApi);
            ctx.write_output("dns_cache|not_available|DnsGetCacheDataTable not found");
            return 0;
        }

        DNS_CACHE_ENTRY root{};
        if (pFunc(&root)) {
            int count = 0;
            for (auto* entry = root.pNext; entry; entry = entry->pNext) {
                if (entry->pszName) {
                    auto name = from_wide(entry->pszName);
                    // wType: 1=A, 28=AAAA, 5=CNAME, etc.
                    const char* type = "unknown";
                    switch (entry->wType) {
                    case 1:
                        type = "A";
                        break;
                    case 28:
                        type = "AAAA";
                        break;
                    case 5:
                        type = "CNAME";
                        break;
                    case 12:
                        type = "PTR";
                        break;
                    case 15:
                        type = "MX";
                        break;
                    case 33:
                        type = "SRV";
                        break;
                    }
                    ctx.write_output(std::format("cache_entry|{}|{}|0|", name, type));
                    ++count;
                }
            }
            if (count == 0) {
                ctx.write_output("dns_cache|empty");
            }
        } else {
            ctx.write_output("dns_cache|not_available|query failed");
        }
        FreeLibrary(hDnsApi);

#elif defined(__linux__)
        // Direct argv via the bounded runner (ADR-3002 rung 2) — no `/bin/sh
        // -c`, argv[0] resolved by probe_tool_path so a missing binary is
        // caught BEFORE exec rather than sniffed from captured text.
        auto resolvectl_path =
            yuzu::agent::probe_tool_path({"/usr/bin/resolvectl", "/bin/resolvectl"});
        if (!resolvectl_path.empty()) {
            auto res = yuzu::agent::run_bounded_subprocess(
                {resolvectl_path, "cache"},
                yuzu::agent::SubprocessOptions{.deadline = std::chrono::seconds{15}});
            if (yuzu::agent::forward_runner_failure(ctx, res))
                return 0; // status already set — an honest CONSTRAINED/UNAVAILABLE, not silence
            if (res.tool_ran && res.exit_code == 0) {
                for (const auto& line :
                    yuzu::network_config::parse_resolvectl_cache_lines(res.output)) {
                    ctx.write_output(std::format("cache_entry|{}", line));
                }
                return 0;
            }
            // resolvectl ran but exited nonzero (e.g. no systemd-resolved
            // running) — fall through to the systemd-resolve statistics
            // fallback, same behaviour as the pre-migration shell-out.
        }

        auto systemd_resolve_path =
            yuzu::agent::probe_tool_path({"/usr/bin/systemd-resolve", "/bin/systemd-resolve"});
        if (!systemd_resolve_path.empty()) {
            auto res = yuzu::agent::run_bounded_subprocess(
                {systemd_resolve_path, "--statistics"},
                yuzu::agent::SubprocessOptions{.deadline = std::chrono::seconds{15}});
            if (yuzu::agent::forward_runner_failure(ctx, res))
                return 0;
            if (res.tool_ran && res.exit_code == 0) {
                auto lines = yuzu::network_config::parse_systemd_resolve_stats_lines(res.output);
                if (!lines.empty()) {
                    for (const auto& line : lines)
                        ctx.write_output(std::format("dns_stats|{}", line));
                    return 0;
                }
            }
        }

        ctx.write_output("dns_cache|not_available|no systemd-resolved");

#elif defined(__APPLE__)
        // macOS does not expose resolver-cache CONTENTS to userspace. dscacheutil
        // -cachedump was gutted years ago: on macOS 26 it prints "Unable to get
        // details from the cache node" to stderr and exits 0 (see darwin-compat).
        // So there is nothing to shell out to — it can only ever fail. This is a
        // permanent OS capability gap, not a transient failure, so report it as
        // such rather than the ambiguous not_available (which invites a pointless
        // retry and reads like a query that might succeed next time).
        ctx.write_output("dns_cache|unsupported|macOS does not expose DNS resolver cache contents");
#endif
        return 0;
    }
};

YUZU_PLUGIN_EXPORT(NetworkConfigPlugin)
