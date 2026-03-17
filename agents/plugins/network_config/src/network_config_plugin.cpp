/**
 * network_config_plugin.cpp — Network configuration plugin for Yuzu
 *
 * Actions:
 *   "adapters"     — Lists network adapters with MAC, speed, status.
 *   "ip_addresses" — Lists assigned IP addresses with subnet and gateway.
 *   "dns_servers"  — Lists configured DNS servers per adapter.
 *   "proxy"        — Returns system proxy configuration.
 *
 * Output is pipe-delimited via write_output().
 */

#include <yuzu/plugin.hpp>

#include <array>
#include <cstdio>
#include <format>
#include <sstream>
#include <string>
#include <string_view>

#if defined(__linux__)
#include <cstdlib>
#include <fstream>
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
#include <iphlpapi.h>
#include <winhttp.h>
#include <vector>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#endif

namespace {

// ── subprocess helper (Linux / macOS) ──────────────────────────────────────

#if defined(__linux__) || defined(__APPLE__)
std::string run_command(const char* cmd) {
    std::string result;
    std::array<char, 256> buf{};
    FILE* pipe = popen(cmd, "r");
    if (!pipe) return result;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        result += buf.data();
    }
    pclose(pipe);
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
    }
    return result;
}
#endif

#ifdef _WIN32
// Format a MAC address from a byte array
std::string format_mac(const BYTE* addr, DWORD len) {
    if (len < 6) return "-";
    return std::format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

// Convert wide string to UTF-8
std::string wide_to_utf8(const wchar_t* ws) {
    if (!ws || !*ws) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, ws, -1, nullptr, 0, nullptr, nullptr);
    std::string result(len > 0 ? len - 1 : 0, '\0');
    if (len > 0) {
        WideCharToMultiByte(CP_UTF8, 0, ws, -1, result.data(), len, nullptr, nullptr);
    }
    return result;
}

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
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, adapters, &buf_size) != NO_ERROR) {
        ctx.write_output("adapter|Error enumerating adapters|-|0|unknown");
        return 1;
    }

    for (auto* a = adapters; a; a = a->Next) {
        // Skip loopback and tunnel adapters
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        if (a->IfType == IF_TYPE_TUNNEL) continue;

        auto name = wide_to_utf8(a->FriendlyName);
        auto mac = format_mac(a->PhysicalAddress, a->PhysicalAddressLength);
        auto speed_mbps = a->TransmitLinkSpeed / 1'000'000;
        const char* status = (a->OperStatus == IfOperStatusUp) ? "up" : "down";

        ctx.write_output(std::format("adapter|{}|{}|{}|{}",
            name, mac, speed_mbps, status));
    }

#elif defined(__linux__)
    auto ip_out = run_command("ip -o link show 2>/dev/null");
    if (!ip_out.empty()) {
        std::istringstream ss(ip_out);
        std::string line;
        while (std::getline(ss, line)) {
            // Format: "2: eth0: <BROADCAST,...> mtu 1500 ... state UP ... link/ether aa:bb:cc:dd:ee:ff ..."
            // Extract name
            auto colon1 = line.find(':');
            if (colon1 == std::string::npos) continue;
            auto colon2 = line.find(':', colon1 + 1);
            if (colon2 == std::string::npos) continue;
            auto name = line.substr(colon1 + 2, colon2 - colon1 - 2);

            // Skip loopback
            if (name == "lo") continue;

            // Extract state
            std::string status = "unknown";
            auto state_pos = line.find("state ");
            if (state_pos != std::string::npos) {
                auto start = state_pos + 6;
                auto end = line.find(' ', start);
                status = line.substr(start, end - start);
                // Normalize
                if (status == "UP") status = "up";
                else if (status == "DOWN") status = "down";
                else status = "down";
            }

            // Extract MAC
            std::string mac = "-";
            auto ether_pos = line.find("link/ether ");
            if (ether_pos != std::string::npos) {
                auto start = ether_pos + 11;
                auto end = line.find(' ', start);
                mac = line.substr(start, end - start);
            }

            // Get speed from sysfs
            std::string speed = "0";
            std::ifstream speed_file("/sys/class/net/" + name + "/speed");
            if (speed_file) {
                std::getline(speed_file, speed);
                if (speed.empty() || speed[0] == '-') speed = "0";
            }

            ctx.write_output(std::format("adapter|{}|{}|{}|{}",
                name, mac, speed, status));
        }
    }

#elif defined(__APPLE__)
    auto ifconfig = run_command("ifconfig -a 2>/dev/null");
    if (!ifconfig.empty()) {
        std::istringstream ss(ifconfig);
        std::string line;
        std::string current_name;
        std::string mac = "-";
        std::string status = "down";
        bool first = true;
        while (std::getline(ss, line)) {
            if (!line.empty() && line[0] != '\t' && line[0] != ' ') {
                // New adapter — emit previous
                if (!first && !current_name.empty()) {
                    ctx.write_output(std::format("adapter|{}|{}|0|{}",
                        current_name, mac, status));
                }
                first = false;
                auto colon = line.find(':');
                current_name = (colon != std::string::npos) ? line.substr(0, colon) : line;
                mac = "-";
                status = "down";
                if (line.find("status: active") != std::string::npos ||
                    line.find("UP") != std::string::npos) {
                    status = "up";
                }
            } else {
                // Trim
                auto start = line.find_first_not_of(" \t");
                if (start == std::string::npos) continue;
                auto trimmed = line.substr(start);
                if (trimmed.starts_with("ether ")) {
                    mac = trimmed.substr(6, 17);
                }
                if (trimmed.find("status: active") != std::string::npos) {
                    status = "up";
                }
            }
        }
        if (!current_name.empty()) {
            ctx.write_output(std::format("adapter|{}|{}|0|{}",
                current_name, mac, status));
        }
    }
#endif
    return 0;
}

// ── ip_addresses action ───────────────────────────────────────────────────

int do_ip_addresses(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    ULONG buf_size = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS, nullptr, nullptr, &buf_size);
    if (buf_size == 0) return 0;

    std::vector<BYTE> buffer(buf_size);
    auto* adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS, nullptr, adapters, &buf_size) != NO_ERROR) {
        return 1;
    }

    for (auto* a = adapters; a; a = a->Next) {
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        if (a->IfType == IF_TYPE_TUNNEL) continue;

        auto adapter_name = wide_to_utf8(a->FriendlyName);

        // Collect first gateway
        std::string gateway = "-";
        for (auto* gw = a->FirstGatewayAddress; gw; gw = gw->Next) {
            auto addr = sockaddr_to_string(gw->Address.lpSockaddr);
            if (!addr.empty()) { gateway = addr; break; }
        }

        // List unicast addresses
        for (auto* ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
            auto addr = sockaddr_to_string(ua->Address.lpSockaddr);
            if (addr.empty()) continue;
            ctx.write_output(std::format("ip|{}|{}|{}|{}",
                adapter_name, addr, ua->OnLinkPrefixLength, gateway));
        }
    }

#elif defined(__linux__)
    auto ip_out = run_command("ip -o addr show 2>/dev/null");
    if (!ip_out.empty()) {
        // Get default gateway
        auto gw_out = run_command("ip route show default 2>/dev/null");
        std::string default_gw = "-";
        if (!gw_out.empty()) {
            auto via = gw_out.find("via ");
            if (via != std::string::npos) {
                auto start = via + 4;
                auto end = gw_out.find(' ', start);
                default_gw = gw_out.substr(start, end - start);
            }
        }

        std::istringstream ss(ip_out);
        std::string line;
        while (std::getline(ss, line)) {
            // Format: "2: eth0    inet 192.168.1.100/24 ..."
            std::istringstream ls(line);
            std::string idx, name, family, addr_cidr;
            ls >> idx >> name >> family >> addr_cidr;
            if (family != "inet" && family != "inet6") continue;
            if (name == "lo") continue;

            // Split addr/prefix
            auto slash = addr_cidr.find('/');
            std::string addr = addr_cidr;
            std::string prefix = "0";
            if (slash != std::string::npos) {
                addr = addr_cidr.substr(0, slash);
                prefix = addr_cidr.substr(slash + 1);
            }

            ctx.write_output(std::format("ip|{}|{}|{}|{}",
                name, addr, prefix, default_gw));
        }
    }

#elif defined(__APPLE__)
    auto ifconfig = run_command("ifconfig 2>/dev/null");
    auto gw_out = run_command("route -n get default 2>/dev/null | grep gateway");
    std::string default_gw = "-";
    if (!gw_out.empty()) {
        auto colon = gw_out.find(':');
        if (colon != std::string::npos) {
            auto start = gw_out.find_first_not_of(" \t", colon + 1);
            if (start != std::string::npos) default_gw = gw_out.substr(start);
        }
    }

    if (!ifconfig.empty()) {
        std::istringstream ss(ifconfig);
        std::string line;
        std::string current_adapter;
        while (std::getline(ss, line)) {
            if (!line.empty() && line[0] != '\t' && line[0] != ' ') {
                auto colon = line.find(':');
                current_adapter = (colon != std::string::npos) ? line.substr(0, colon) : line;
            } else if (current_adapter != "lo0") {
                auto start = line.find_first_not_of(" \t");
                if (start == std::string::npos) continue;
                auto trimmed = line.substr(start);
                if (trimmed.starts_with("inet ")) {
                    std::istringstream ls(trimmed);
                    std::string kw, addr, mask_kw, mask;
                    ls >> kw >> addr >> mask_kw >> mask;
                    ctx.write_output(std::format("ip|{}|{}|{}|{}",
                        current_adapter, addr, mask, default_gw));
                } else if (trimmed.starts_with("inet6 ")) {
                    std::istringstream ls(trimmed);
                    std::string kw, addr, prefix_kw, prefix;
                    ls >> kw >> addr >> prefix_kw >> prefix;
                    // Remove %scope from addr
                    auto pct = addr.find('%');
                    if (pct != std::string::npos) addr = addr.substr(0, pct);
                    ctx.write_output(std::format("ip|{}|{}|{}|{}",
                        current_adapter, addr, prefix, default_gw));
                }
            }
        }
    }
#endif
    return 0;
}

// ── dns_servers action ────────────────────────────────────────────────────

int do_dns_servers(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    ULONG buf_size = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &buf_size);
    if (buf_size == 0) return 0;

    std::vector<BYTE> buffer(buf_size);
    auto* adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, adapters, &buf_size) != NO_ERROR) {
        return 1;
    }

    for (auto* a = adapters; a; a = a->Next) {
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        if (a->IfType == IF_TYPE_TUNNEL) continue;

        auto adapter_name = wide_to_utf8(a->FriendlyName);

        for (auto* dns = a->FirstDnsServerAddress; dns; dns = dns->Next) {
            auto addr = sockaddr_to_string(dns->Address.lpSockaddr);
            if (addr.empty()) continue;
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
    auto dns_out = run_command("scutil --dns 2>/dev/null | grep 'nameserver\\[' | awk '{print $3}'");
    if (!dns_out.empty()) {
        std::istringstream ss(dns_out);
        std::string server;
        while (std::getline(ss, server)) {
            if (server.empty()) continue;
            auto type = (server.find(':') != std::string::npos) ? "IPv6" : "IPv4";
            ctx.write_output(std::format("dns|system|{}|{}", server, type));
        }
    }
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
            ctx.write_output(std::format("proxy_address|{}", wide_to_utf8(proxy_cfg.lpszAutoConfigUrl)));
            GlobalFree(proxy_cfg.lpszAutoConfigUrl);
        }
        if (proxy_cfg.lpszProxy) {
            auto proxy = wide_to_utf8(proxy_cfg.lpszProxy);
            ctx.write_output(std::format("proxy_type|http"));
            ctx.write_output(std::format("proxy_address|{}", proxy));
            GlobalFree(proxy_cfg.lpszProxy);
        }
        if (proxy_cfg.lpszProxyBypass) {
            ctx.write_output(std::format("bypass|{}", wide_to_utf8(proxy_cfg.lpszProxyBypass)));
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
    for (const char* var : {"http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY",
                            "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY"}) {
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
    auto http_proxy = run_command("networksetup -getwebproxy Wi-Fi 2>/dev/null");
    if (!http_proxy.empty() && http_proxy.find("Enabled: Yes") != std::string::npos) {
        // Extract server and port
        std::istringstream ss(http_proxy);
        std::string line;
        std::string server, port;
        while (std::getline(ss, line)) {
            if (line.starts_with("Server: ")) server = line.substr(8);
            if (line.starts_with("Port: ")) port = line.substr(6);
        }
        ctx.write_output("proxy_type|http");
        ctx.write_output(std::format("proxy_address|{}:{}", server, port));
    } else {
        auto auto_proxy = run_command("networksetup -getautoproxyurl Wi-Fi 2>/dev/null");
        if (!auto_proxy.empty() && auto_proxy.find("Enabled: Yes") != std::string::npos) {
            std::istringstream ss(auto_proxy);
            std::string line;
            while (std::getline(ss, line)) {
                if (line.starts_with("URL: ")) {
                    ctx.write_output("proxy_type|pac");
                    ctx.write_output(std::format("proxy_address|{}", line.substr(5)));
                    break;
                }
            }
        } else {
            ctx.write_output("proxy_type|none");
        }
    }
#endif
    return 0;
}

}  // namespace

class NetworkConfigPlugin final : public yuzu::Plugin {
public:
    std::string_view name()        const noexcept override { return "network_config"; }
    std::string_view version()     const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Reports network adapter configuration, IP addresses, DNS servers, and proxy settings";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {
            "adapters", "ip_addresses", "dns_servers", "proxy", "dns_cache", nullptr
        };
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override {
        return {};
    }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx,
                std::string_view action,
                yuzu::Params /*params*/) override {
        if (action == "adapters")     return do_adapters(ctx);
        if (action == "ip_addresses") return do_ip_addresses(ctx);
        if (action == "dns_servers")  return do_dns_servers(ctx);
        if (action == "proxy")        return do_proxy(ctx);
        if (action == "dns_cache")    return do_dns_cache(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
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
                    auto name = wide_to_utf8(entry->pszName);
                    // wType: 1=A, 28=AAAA, 5=CNAME, etc.
                    const char* type = "unknown";
                    switch (entry->wType) {
                        case 1:  type = "A"; break;
                        case 28: type = "AAAA"; break;
                        case 5:  type = "CNAME"; break;
                        case 12: type = "PTR"; break;
                        case 15: type = "MX"; break;
                        case 33: type = "SRV"; break;
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
        auto result = run_command("resolvectl cache 2>/dev/null");
        if (!result.empty() && result.find("not found") == std::string::npos) {
            std::istringstream ss(result);
            std::string line;
            while (std::getline(ss, line)) {
                if (!line.empty()) {
                    ctx.write_output(std::format("cache_entry|{}", line));
                }
            }
        } else {
            // Fallback: try systemd-resolve --statistics
            auto stats = run_command("systemd-resolve --statistics 2>/dev/null");
            if (!stats.empty()) {
                std::istringstream ss(stats);
                std::string line;
                while (std::getline(ss, line)) {
                    auto trimmed = line;
                    auto start = trimmed.find_first_not_of(" \t");
                    if (start != std::string::npos) trimmed = trimmed.substr(start);
                    if (trimmed.starts_with("Current Cache Size:") ||
                        trimmed.starts_with("Cache Hits:") ||
                        trimmed.starts_with("Cache Misses:")) {
                        ctx.write_output(std::format("dns_stats|{}", trimmed));
                    }
                }
            } else {
                ctx.write_output("dns_cache|not_available|no systemd-resolved");
            }
        }

#elif defined(__APPLE__)
        auto result = run_command("dscacheutil -cachedump -entries 2>/dev/null");
        if (!result.empty()) {
            std::istringstream ss(result);
            std::string line;
            while (std::getline(ss, line)) {
                if (!line.empty()) {
                    ctx.write_output(std::format("cache_entry|{}", line));
                }
            }
        } else {
            ctx.write_output("dns_cache|not_available");
        }
#endif
        return 0;
    }
};

YUZU_PLUGIN_EXPORT(NetworkConfigPlugin)
