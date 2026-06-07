/**
 * discovery_plugin.cpp — Network device discovery plugin for Yuzu
 *
 * Actions:
 *   "scan_subnet" — ARP scan + ping sweep of a subnet to find hosts.
 *
 * Output is pipe-delimited via write_output():
 *   host|ip_address|mac_address|hostname|managed
 *
 * Platform support:
 *   Windows — arp -a parsing + ping sweep via subprocess
 *   Linux   — arp -n parsing + ping sweep via subprocess
 *   macOS   — arp -a parsing + ping sweep via subprocess
 *
 * Input validation: subnet parameter is validated as a CIDR block.
 * Only alphanumeric, dots, slashes, and colons are allowed to prevent
 * command injection.
 */

#include <yuzu/plugin.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <format>
#include <map>
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
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
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

// ── subprocess helper ──────────────────────────────────────────────────────

std::string run_command(const char* cmd) {
    std::string result;
    std::array<char, 256> buf{};
#ifdef _WIN32
    FILE* pipe = _popen(cmd, "r");
#else
    FILE* pipe = popen(cmd, "r");
#endif
    if (!pipe) return result;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        result += buf.data();
    }
#ifdef _WIN32
    _pclose(pipe);
#else
    pclose(pipe);
#endif
    return result;
}

struct ArpEntry {
    std::string ip;
    std::string mac;
};

// ── ARP table parsing ─────────────────────────────────────────────────────

#ifdef _WIN32

/**
 * Parse Windows ARP table. Windows `arp -a` output format:
 *   Interface: 192.168.1.100 --- 0xb
 *     Internet Address      Physical Address      Type
 *     192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
 */
std::vector<ArpEntry> get_arp_table() {
    std::vector<ArpEntry> entries;

    // Use Win32 API for reliable ARP table access
    DWORD size = 0;
    GetIpNetTable(nullptr, &size, FALSE);
    if (size == 0) return entries;

    std::vector<BYTE> buffer(size);
    if (GetIpNetTable(reinterpret_cast<MIB_IPNETTABLE*>(buffer.data()),
                      &size, FALSE) != NO_ERROR)
        return entries;

    auto* table = reinterpret_cast<MIB_IPNETTABLE*>(buffer.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        auto& row = table->table[i];
        // Only dynamic and static entries
        if (row.dwType != MIB_IPNET_TYPE_DYNAMIC && row.dwType != MIB_IPNET_TYPE_STATIC)
            continue;

        struct in_addr addr{};
        addr.S_un.S_addr = static_cast<ULONG>(row.dwAddr);
        char ip[INET_ADDRSTRLEN]{};
        inet_ntop(AF_INET, &addr, ip, sizeof(ip));

        // Format MAC address
        if (row.dwPhysAddrLen >= 6) {
            char mac[18]{};
            snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                     row.bPhysAddr[0], row.bPhysAddr[1], row.bPhysAddr[2],
                     row.bPhysAddr[3], row.bPhysAddr[4], row.bPhysAddr[5]);
            entries.push_back({ip, mac});
        }
    }
    return entries;
}

#elif defined(__APPLE__)

/**
 * Parse macOS ARP table. macOS `arp -a` output format:
 *   ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
 */
std::vector<ArpEntry> get_arp_table() {
    std::vector<ArpEntry> entries;
    std::string output = run_command("arp -a 2>/dev/null");
    std::istringstream iss(output);
    std::string line;

    while (std::getline(iss, line)) {
        // Find IP in parentheses
        auto paren_start = line.find('(');
        auto paren_end = line.find(')');
        if (paren_start == std::string::npos || paren_end == std::string::npos)
            continue;

        std::string ip = line.substr(paren_start + 1, paren_end - paren_start - 1);

        // Find MAC after " at "
        auto at_pos = line.find(" at ");
        if (at_pos == std::string::npos) continue;
        auto mac_start = at_pos + 4;
        auto mac_end = line.find(' ', mac_start);
        if (mac_end == std::string::npos) mac_end = line.size();
        std::string mac = line.substr(mac_start, mac_end - mac_start);

        if (mac != "(incomplete)" && !mac.empty())
            entries.push_back({ip, mac});
    }
    return entries;
}

#elif defined(__linux__)

/**
 * Parse Linux ARP table. Linux `arp -n` output format:
 *   Address         HWtype  HWaddress           Flags Mask  Iface
 *   192.168.1.1     ether   aa:bb:cc:dd:ee:ff   C           eth0
 */
std::vector<ArpEntry> get_arp_table() {
    std::vector<ArpEntry> entries;
    std::string output = run_command("arp -n 2>/dev/null");
    std::istringstream iss(output);
    std::string line;

    // Skip header
    std::getline(iss, line);

    while (std::getline(iss, line)) {
        std::istringstream lss(line);
        std::string ip, hwtype, mac;
        if (!(lss >> ip >> hwtype >> mac)) continue;
        if (mac != "(incomplete)" && !mac.empty() && hwtype == "ether")
            entries.push_back({ip, mac});
    }
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
 * Ping a single host with a short timeout.
 * Returns true if the host responds.
 */
bool ping_host(const std::string& ip, int timeout_ms) {
#ifdef _WIN32
    std::string cmd = std::format("ping -n 1 -w {} {} >NUL 2>NUL", timeout_ms, ip);
    return system(cmd.c_str()) == 0;
#elif defined(__APPLE__)
    int timeout_sec = std::max(1, timeout_ms / 1000);
    std::string cmd = std::format("ping -c 1 -t {} {} >/dev/null 2>&1", timeout_sec, ip);
    return system(cmd.c_str()) == 0;
#else
    int timeout_sec = std::max(1, timeout_ms / 1000);
    std::string cmd = std::format("ping -c 1 -W {} {} >/dev/null 2>&1", timeout_sec, ip);
    return system(cmd.c_str()) == 0;
#endif
}

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
                if (ping_host(ip, timeout_ms)) {
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
