/**
 * discovery_plugin.cpp — Network device discovery plugin for Yuzu
 *
 * Actions:
 *   "scan_subnet" — ARP scan + ping sweep of a subnet to find hosts.
 *
 * Output is pipe-delimited via write_output():
 *   host|ip_address|mac_address|hostname|managed
 *
 * Platform support (zero spawn sites, all native/rung 1):
 *   Windows — GetIpNetTable2 ARP read + IcmpSendEcho ping sweep.
 *   Linux   — /proc/net/arp read + unprivileged SOCK_DGRAM ICMP ping sweep
 *             (net.ipv4.ping_group_range-gated; see the honest-degrade
 *             branch in do_scan_subnet for the CONSTRAINED/UNAVAILABLE
 *             fallback when the kernel refuses the socket).
 *   macOS   — sysctl NET_RT_FLAGS/RTF_LLINFO ARP read + SOCK_DGRAM ICMP
 *             ping sweep.
 *
 * Input validation: the subnet parameter is validated as a CIDR block —
 * digits, dots and a single slash only (is_valid_cidr), then re-parsed into
 * octets and a prefix length. There is no longer a shell to inject into (the
 * action spawns nothing at all); the validation is retained because every
 * downstream step — host enumeration, inet_pton, the ICMP destination — is
 * entitled to assume a well-formed dotted quad.
 */

#include <yuzu/plugin.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <format>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
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
#include <netioapi.h> // GetIpNetTable2 / MIB_IPNET_ROW2 (tar_arp_collector.cpp precedent)
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#endif

#include "icmp_probe.hpp" // yuzu::shared::IcmpSession — shared unprivileged ping sweep

#include "discovery_scan_plan.hpp" // pure sweep bounds + honest-degrade decisions

#ifdef __linux__
#include "discovery_parsers.hpp" // yuzu::discovery::parse_proc_net_arp — pure /proc/net/arp parser
#endif

#ifdef __APPLE__
#include "route_sysctl_arp.hpp" // yuzu::shared::{fetch,parse}_rt_flags_llinfo — sysctl ARP read
#endif

namespace {

// ── Input sanitization ────────────────────────────────────────────────────────

/**
 * Validate that a string looks like a CIDR subnet (e.g., "192.168.1.0/24").
 * Only allows digits, dots, and slash.
 */
bool is_valid_cidr(std::string_view s) {
    if (s.empty() || s.size() > 18) return false;
    int dots = 0, slashes = 0;
    for (char c : s) {
        if (c >= '0' && c <= '9') continue;
        if (c == '.') { ++dots; continue; }
        if (c == '/') { ++slashes; continue; }
        return false; // invalid character
    }
    return dots == 3 && slashes == 1;
}

/**
 * Parse subnet into base IP and prefix length.
 * Returns false if invalid.
 */
bool parse_cidr(std::string_view cidr, uint32_t& base_ip, int& prefix_len) {
    auto slash_pos = cidr.find('/');
    if (slash_pos == std::string_view::npos) return false;

    auto ip_str = cidr.substr(0, slash_pos);
    auto prefix_str = cidr.substr(slash_pos + 1);

    // Parse prefix length
    prefix_len = 0;
    [[maybe_unused]] auto [ptr, ec] = std::from_chars(prefix_str.data(),
                                      prefix_str.data() + prefix_str.size(),
                                      prefix_len);
    if (ec != std::errc{} || prefix_len < 8 || prefix_len > 30)
        return false;

    // Parse IP octets
    uint8_t octets[4]{};
    int octet_idx = 0;
    size_t start = 0;
    std::string ip{ip_str};
    for (size_t i = 0; i <= ip.size() && octet_idx < 4; ++i) {
        if (i == ip.size() || ip[i] == '.') {
            int val = 0;
            [[maybe_unused]] auto [p, e] = std::from_chars(ip.data() + start, ip.data() + i, val);
            if (e != std::errc{} || val < 0 || val > 255) return false;
            octets[octet_idx++] = static_cast<uint8_t>(val);
            start = i + 1;
        }
    }
    if (octet_idx != 4) return false;

    base_ip = (static_cast<uint32_t>(octets[0]) << 24) |
              (static_cast<uint32_t>(octets[1]) << 16) |
              (static_cast<uint32_t>(octets[2]) << 8) |
              static_cast<uint32_t>(octets[3]);

    return true;
}

/**
 * Convert a 32-bit IP to dotted-quad string.
 */
std::string ip_to_string(uint32_t ip) {
    return std::format("{}.{}.{}.{}",
                       (ip >> 24) & 0xFF,
                       (ip >> 16) & 0xFF,
                       (ip >> 8) & 0xFF,
                       ip & 0xFF);
}

/**
 * Generate all host IPs in a CIDR range (excludes network and broadcast).
 */
std::vector<std::string> enumerate_hosts(uint32_t base_ip, int prefix_len) {
    std::vector<std::string> result;
    uint32_t mask = 0xFFFFFFFF << (32 - prefix_len);
    uint32_t network = base_ip & mask;
    uint32_t broadcast = network | ~mask;

    // Limit to /24 (254 hosts) to prevent DoS from scanning overly large subnets
    if (prefix_len < 24) return result;

    for (uint32_t ip = network + 1; ip < broadcast; ++ip) {
        result.push_back(ip_to_string(ip));
    }
    return result;
}

struct ArpEntry {
    std::string ip;
    std::string mac;
};

// ── ARP table parsing ─────────────────────────────────────────────────────

#ifdef _WIN32

/**
 * Read the Windows ARP table via GetIpNetTable2(AF_INET) — the neighbour
 * cache, native (no popen). FreeMibTable is called on every exit path.
 */
std::vector<ArpEntry> get_arp_table() {
    std::vector<ArpEntry> entries;

    PMIB_IPNET_TABLE2 table = nullptr;
    DWORD rc = GetIpNetTable2(AF_INET, &table);
    // RAII: FreeMibTable runs on every exit path below, early returns
    // included, without needing to remember to call it manually.
    std::unique_ptr<MIB_IPNET_TABLE2, decltype(&FreeMibTable)> table_owner{
        table, &FreeMibTable};
    if (rc != NO_ERROR || table == nullptr)
        return entries;

    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const MIB_IPNET_ROW2& row = table->Table[i];

        // Accept resolved/reachable states only, equivalent to the old
        // MIB_IPNET_TYPE_DYNAMIC|MIB_IPNET_TYPE_STATIC filter.
        switch (row.State) {
        case NlnsReachable:
        case NlnsStale:
        case NlnsDelay:
        case NlnsProbe:
        case NlnsPermanent:
            break;
        default:
            continue;
        }

        if (row.PhysicalAddressLength < 6)
            continue;

        char ip[INET_ADDRSTRLEN]{};
        if (!inet_ntop(AF_INET, const_cast<IN_ADDR*>(&row.Address.Ipv4.sin_addr), ip, sizeof(ip)))
            continue;

        char mac[18]{};
        snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 row.PhysicalAddress[0], row.PhysicalAddress[1], row.PhysicalAddress[2],
                 row.PhysicalAddress[3], row.PhysicalAddress[4], row.PhysicalAddress[5]);

        entries.push_back({ip, mac});
    }

    return entries;
}

#elif defined(__APPLE__)

/**
 * Read the macOS ARP table via the routing socket sysctl
 * (route_sysctl_arp.hpp) — the same data `arp -a` reads, native (no popen).
 */
std::vector<ArpEntry> get_arp_table() {
    std::vector<ArpEntry> entries;
    auto blob = yuzu::shared::fetch_rt_flags_llinfo();
    for (auto& rec : yuzu::shared::parse_rt_flags_llinfo(blob))
        entries.push_back({std::move(rec.ip), std::move(rec.mac)});
    return entries;
}

#elif defined(__linux__)

/**
 * Read the Linux ARP table from /proc/net/arp (discovery_parsers.hpp) —
 * native, no `arp -n` subprocess.
 */
std::vector<ArpEntry> get_arp_table() {
    std::vector<ArpEntry> entries;
    std::ifstream in("/proc/net/arp");
    if (!in)
        return entries;

    std::ostringstream contents;
    contents << in.rdbuf();

    for (auto& e : yuzu::discovery::parse_proc_net_arp(contents.str()))
        entries.push_back({std::move(e.ip), std::move(e.mac)});
    return entries;
}

#else

std::vector<ArpEntry> get_arp_table() {
    return {};
}

#endif

// ── Hostname resolution ───────────────────────────────────────────────────

std::string resolve_hostname(const std::string& ip) {
#ifdef _WIN32
    // Use getnameinfo
    struct sockaddr_in sa{};
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
    char host[NI_MAXHOST]{};
    if (getnameinfo(reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa),
                    host, sizeof(host), nullptr, 0, NI_NAMEREQD) == 0) {
        return host;
    }
#else
    // Use getaddrinfo reverse lookup
    struct sockaddr_in sa{};
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
    char host[1025]{};
    if (getnameinfo(reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa),
                    host, sizeof(host), nullptr, 0, NI_NAMEREQD) == 0) {
        return host;
    }
#endif
    return {};
}

// ── Ping sweep ────────────────────────────────────────────────────────────

/**
 * Sample one host over the shared ICMP session. Builds the destination
 * address from the (already-validated, dotted-quad) IP string and delegates
 * to yuzu::shared::IcmpSession::sample — no subprocess, no per-host socket.
 */
#ifdef _WIN32
std::optional<double> icmp_sample(yuzu::shared::IcmpSession& session, const std::string& ip,
                                  int timeout_ms) {
    struct in_addr addr{};
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1)
        return std::nullopt;
    return session.sample(addr.S_un.S_addr, timeout_ms);
}
#else
std::optional<double> icmp_sample(yuzu::shared::IcmpSession& session, const std::string& ip,
                                  int timeout_ms) {
    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip.c_str(), &sin.sin_addr) != 1)
        return std::nullopt;
    return session.sample(sin, timeout_ms);
}
#endif

/**
 * Ping a single host over the shared session with a short timeout.
 * Returns true if the host responds.
 */
bool ping_host(yuzu::shared::IcmpSession& session, const std::string& ip, int timeout_ms) {
    return icmp_sample(session, ip, timeout_ms).has_value();
}

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// scan_subnet combines an ARP-table read with an ICMP ping sweep, all
// native now (zero spawn sites, rung 1 on every platform): Windows reads
// GetIpNetTable2 and pings via IcmpSendEcho; macOS reads the routing socket
// (sysctl NET_RT_FLAGS/RTF_LLINFO) and pings via an unprivileged SOCK_DGRAM
// ICMP socket; Linux reads /proc/net/arp and pings the same way, but the
// ICMP socket depends on net.ipv4.ping_group_range admitting the agent's
// gid — see do_scan_subnet's honest-degrade branch for the CONSTRAINED /
// UNAVAILABLE fallback this leg documents.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "scan_subnet",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "/proc/net/arp + unprivileged SOCK_DGRAM ICMP",
         "the ICMP sweep needs net.ipv4.ping_group_range to admit the agent's gid; "
         "ARP-only results with a CONSTRAINED/PARTIAL status otherwise, or "
         "UNAVAILABLE/PARTIAL when the ICMP socket cannot be created at all. netlink "
         "RTM_GETNEIGH is a recorded future promotion over /proc/net/arp"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "sysctl NET_RT_FLAGS/RTF_LLINFO + SOCK_DGRAM ICMP", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "GetIpNetTable2 + IcmpSendEcho", nullptr},
    },
};

} // namespace

class DiscoveryPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "discovery"; }
    std::string_view version() const noexcept override { return "0.1.0"; }
    std::string_view description() const noexcept override {
        return "Network device discovery — ARP scan and ping sweep";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"scan_subnet", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override {
        return {};
    }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params params) override {
        if (action == "scan_subnet")
            return do_scan_subnet(ctx, params);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
    int do_scan_subnet(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto subnet = params.get("subnet");
        auto timeout_str = params.get("timeout_ms", "1000");

        if (subnet.empty()) {
            ctx.write_output("status|error|missing required parameter: subnet");
            return 1;
        }

        if (!is_valid_cidr(subnet)) {
            ctx.write_output("status|error|invalid CIDR subnet format (e.g., 192.168.1.0/24)");
            return 1;
        }

        int timeout_ms = 1000;
        if (!timeout_str.empty()) {
            std::from_chars(timeout_str.data(),
                            timeout_str.data() + timeout_str.size(),
                            timeout_ms);
        }
        if (timeout_ms < 100) timeout_ms = 100;
        if (timeout_ms > 10000) timeout_ms = 10000;

        uint32_t base_ip = 0;
        int prefix_len = 0;
        if (!parse_cidr(subnet, base_ip, prefix_len)) {
            ctx.write_output("status|error|failed to parse CIDR subnet");
            return 1;
        }

        auto hosts = enumerate_hosts(base_ip, prefix_len);
        if (hosts.empty()) {
            ctx.write_output("status|error|subnet too large (max /24) or no valid hosts");
            return 1;
        }

        ctx.report_progress(5);

        // Overall scan timeout: abort after 300 seconds and return partial results
        constexpr int kScanTimeoutSeconds = 300;
        auto scan_start = std::chrono::steady_clock::now();
        bool timed_out = false;

        // Step 1: Get current ARP table (fast, pre-populated entries)
        auto arp_entries = get_arp_table();
        std::set<std::string> arp_ips;
        std::map<std::string, std::string> ip_to_mac;
        for (const auto& entry : arp_entries) {
            arp_ips.insert(entry.ip);
            ip_to_mac[entry.ip] = entry.mac;
        }

        ctx.report_progress(10);

        // Step 2: Ping sweep to discover hosts not in ARP table
        // The ping will populate the ARP table for responding hosts
        int total = static_cast<int>(hosts.size());
        int done = 0;
        std::set<std::string> alive_ips;

        // ONE ICMP session per scan (never per host — a /24 must not open
        // 254 sockets). Each probe gets a short per-host budget, capped
        // independently of the caller's timeout_ms so the sweep stays finite;
        // both bounds are decided by discovery_scan_plan.hpp (tested there).
        yuzu::shared::IcmpSession session;
        const int probe_timeout_ms = yuzu::discovery::probe_budget_ms(timeout_ms);
        const auto availability =
            yuzu::discovery::classify_icmp_session(session.ok(), session.permitted);

        if (const auto degrade = yuzu::discovery::degrade_for(availability); degrade.has_report) {
            // HONEST DEGRADE — resolved before any probe is attempted. Never
            // probe through an invalid session; fall back to the ARP-derived
            // host set, warn once, and stamp the ABI4 result so a machine
            // consumer cannot read a dead network as a successful empty scan.
            // Denied (Linux net.ipv4.ping_group_range refusing the
            // unprivileged SOCK_DGRAM ICMP socket) and Unavailable
            // (EMFILE/ENFILE/ENOMEM, or IcmpCreateFile failing on Windows)
            // carry distinct statuses and reason tags.
            ctx.write_output(std::format("status|warning|{}", degrade.report.message));
            ctx.set_result_status(degrade.report.status, degrade.report.completeness,
                                  degrade.report.reason);
            // Confine the degrade fallback to the requested subnet — never
            // surface unrelated cached ARP neighbors (other subnets,
            // multicast/broadcast entries) as scan results.
            for (const auto& ip : yuzu::discovery::arp_hosts_in_subnet(hosts, arp_ips))
                alive_ips.insert(ip);
        } else {
            for (const auto& ip : hosts) {
                // Check overall scan timeout
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - scan_start).count();
                if (elapsed >= kScanTimeoutSeconds) {
                    timed_out = true;
                    ctx.write_output(std::format("status|warning|scan timed out after {}s, "
                                                 "returning partial results ({}/{})",
                                                 elapsed, done, total));
                    break;
                }

                // If already in ARP table, it's alive
                if (arp_ips.count(ip)) {
                    alive_ips.insert(ip);
                } else {
                    // Ping it
                    if (ping_host(session, ip, probe_timeout_ms)) {
                        alive_ips.insert(ip);
                    }
                }

                ++done;
                int progress = 10 + (done * 80 / total);
                if (done % 10 == 0 || done == total) {
                    ctx.report_progress(progress);
                }

                // Progress reporting every 50 hosts
                if (done % 50 == 0) {
                    ctx.write_output(std::format("progress|scanned {} of {} hosts, "
                                                 "{} alive so far",
                                                 done, total, alive_ips.size()));
                }
            }
        }

        // A sweep cut short by its own deadline is PARTIAL, not a clean scan.
        // The warning line above says so to a human; this says so to the ABI4
        // result seam, which is what a machine consumer reads — without it a
        // scan that stopped at host 40 of 254 is indistinguishable from a
        // complete one. Not set on the degrade path above, which has already
        // reported its own (more specific) status.
        if (timed_out) {
            const auto t = yuzu::discovery::timeout_degrade();
            ctx.set_result_status(t.status, t.completeness, t.reason);
        }

        // Step 3: Re-read ARP table after ping sweep to get MACs
        auto fresh_arp = get_arp_table();
        for (const auto& entry : fresh_arp) {
            ip_to_mac[entry.ip] = entry.mac;
        }

        ctx.report_progress(95);

        // Step 4: Output results
        int found = 0;
        for (const auto& ip : alive_ips) {
            std::string mac = ip_to_mac.count(ip) ? ip_to_mac[ip] : "unknown";
            std::string hostname = resolve_hostname(ip);
            if (hostname.empty()) hostname = "unknown";
            // managed status is always "unknown" from the agent side —
            // the server will correlate with known agent IPs
            ctx.write_output(std::format("host|{}|{}|{}|unknown", ip, mac, hostname));
            ++found;
        }

        ctx.write_output(std::format("scan_complete|{}|{}", found, total));
        ctx.report_progress(100);
        return 0;
    }
};

YUZU_PLUGIN_EXPORT(DiscoveryPlugin)
