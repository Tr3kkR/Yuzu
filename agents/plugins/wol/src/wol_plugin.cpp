/**
 * wol_plugin.cpp — Wake-on-LAN plugin for Yuzu
 *
 * Actions:
 *   "wake"  — Sends a Wake-on-LAN magic packet to a specified MAC address.
 *             The magic packet is a UDP broadcast containing 6 bytes of 0xFF
 *             followed by the target MAC address repeated 16 times.
 *   "check" — Pings a host to verify it responded to a WoL wake.
 *
 * Output is pipe-delimited, one record per line via write_output():
 *   key|field1|field2|...
 *
 * Platform implementations:
 *   Windows: Winsock2 UDP broadcast (ws2_32)
 *   Linux:   POSIX UDP sockets
 *   macOS:   POSIX UDP sockets
 */

#include <yuzu/plugin.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <format>
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
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {

// ── subprocess helper (all platforms) ──────────────────────────────────────

std::string run_command(const char* cmd) {
    std::string result;
    std::array<char, 256> buf{};
#ifdef _WIN32
    FILE* pipe = _popen(cmd, "r");
#else
    FILE* pipe = popen(cmd, "r");
#endif
    if (!pipe)
        return result;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        result += buf.data();
    }
#ifdef _WIN32
    _pclose(pipe);
#else
    pclose(pipe);
#endif
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
    }
    return result;
}

// ── MAC address parsing ────────────────────────────────────────────────────

/// Returns true if c is a valid hexadecimal digit.
bool is_hex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/// Convert a hex digit to its numeric value (0-15). Caller must ensure is_hex(c).
unsigned int hex_val(char c) {
    if (c >= '0' && c <= '9')
        return static_cast<unsigned int>(c - '0');
    if (c >= 'a' && c <= 'f')
        return static_cast<unsigned int>(c - 'a' + 10);
    return static_cast<unsigned int>(c - 'A' + 10);
}

// Parse a MAC address string (AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF)
// into 6 bytes. Returns false on invalid format.
// Validates every position explicitly: HH<sep>HH<sep>HH<sep>HH<sep>HH<sep>HH
// where H is [0-9a-fA-F] and <sep> is ':' or '-' (must be consistent).
bool parse_mac(std::string_view mac_str, uint8_t out[6]) {
    // Must be exactly 17 characters: 6 pairs of 2 hex digits separated by 5 separators
    if (mac_str.size() != 17)
        return false;

    // Determine separator from position 2 — must be ':' or '-'
    char sep = mac_str[2];
    if (sep != ':' && sep != '-')
        return false;

    // Validate each of the 17 positions explicitly
    // Positions 0,1   = hex pair (byte 0)
    // Position  2     = separator
    // Positions 3,4   = hex pair (byte 1)
    // Position  5     = separator
    // Positions 6,7   = hex pair (byte 2)
    // Position  8     = separator
    // Positions 9,10  = hex pair (byte 3)
    // Position  11    = separator
    // Positions 12,13 = hex pair (byte 4)
    // Position  14    = separator
    // Positions 15,16 = hex pair (byte 5)
    for (int i = 0; i < 6; ++i) {
        int base = i * 3;
        char hi = mac_str[base];
        char lo = mac_str[base + 1];

        // Both characters must be valid hex digits
        if (!is_hex(hi) || !is_hex(lo))
            return false;

        // Check separator at the expected position (except after last byte)
        if (i < 5) {
            if (mac_str[base + 2] != sep)
                return false;
        }

        out[i] = static_cast<uint8_t>((hex_val(hi) << 4) | hex_val(lo));
    }
    return true;
}

// ── build magic packet ─────────────────────────────────────────────────────

// Build a 102-byte WoL magic packet: 6 bytes of 0xFF followed by the
// target MAC address repeated 16 times.
std::vector<uint8_t> build_magic_packet(const uint8_t mac[6]) {
    std::vector<uint8_t> packet(102);

    // 6 bytes of 0xFF
    std::memset(packet.data(), 0xFF, 6);

    // 16 repetitions of the MAC address
    for (int i = 0; i < 16; ++i) {
        std::memcpy(packet.data() + 6 + (i * 6), mac, 6);
    }

    return packet;
}

// ── L11: RAII wrapper for Winsock lifecycle ─────────────────────────────────

#ifdef _WIN32
struct WinsockGuard {
    bool ok{false};
    WinsockGuard() {
        WSADATA wsa_data;
        ok = (WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0);
    }
    ~WinsockGuard() {
        if (ok) WSACleanup();
    }
    WinsockGuard(const WinsockGuard&) = delete;
    WinsockGuard& operator=(const WinsockGuard&) = delete;
};

struct SocketGuard {
    SOCKET sock{INVALID_SOCKET};
    explicit SocketGuard(SOCKET s) : sock(s) {}
    ~SocketGuard() {
        if (sock != INVALID_SOCKET) closesocket(sock);
    }
    SocketGuard(const SocketGuard&) = delete;
    SocketGuard& operator=(const SocketGuard&) = delete;
    explicit operator bool() const { return sock != INVALID_SOCKET; }
    SOCKET get() const { return sock; }
};
#endif

// ── wake action ────────────────────────────────────────────────────────────

int do_wake(yuzu::CommandContext& ctx, yuzu::Params params) {
    auto mac_param = params.get("mac");
    if (mac_param.empty()) {
        ctx.write_output("wake|error|Missing required parameter: mac");
        return 1;
    }

    // Parse MAC address
    uint8_t mac[6]{};
    if (!parse_mac(mac_param, mac)) {
        ctx.write_output(std::format("wake|error|Invalid MAC address format: {}", mac_param));
        return 1;
    }

    // Optional port (default 9 — standard WoL port)
    auto port_param = params.get("port", "9");
    int port = 9;
    try {
        port = std::stoi(std::string(port_param));
        if (port < 1 || port > 65535)
            port = 9;
    } catch (...) {
        port = 9;
    }

    // Build magic packet
    auto packet = build_magic_packet(mac);

#ifdef _WIN32
    // L11: RAII wrappers ensure cleanup on all exit paths
    WinsockGuard wsa;
    if (!wsa.ok) {
        ctx.write_output("wake|error|WSAStartup failed");
        return 1;
    }

    SocketGuard sg(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
    if (!sg) {
        ctx.write_output("wake|error|Failed to create UDP socket");
        return 1;
    }
    auto sock = sg.get();
#else
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ctx.write_output("wake|error|Failed to create UDP socket");
        return 1;
    }
#endif

    // Enable broadcast
    int broadcast_enable = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST,
               reinterpret_cast<const char*>(&broadcast_enable), sizeof(broadcast_enable));

    // Set up broadcast destination
    struct sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(static_cast<uint16_t>(port));
    dest.sin_addr.s_addr = INADDR_BROADCAST; // 255.255.255.255

    // Send the magic packet
    auto sent = sendto(sock, reinterpret_cast<const char*>(packet.data()),
                       static_cast<int>(packet.size()), 0,
                       reinterpret_cast<struct sockaddr*>(&dest), sizeof(dest));

#ifndef _WIN32
    close(sock);
#endif
    // On Windows, SocketGuard and WinsockGuard destructors handle cleanup

    if (sent < 0) {
        ctx.write_output(std::format("wake|error|Failed to send magic packet to {}", mac_param));
        return 1;
    }

    ctx.write_output(std::format(
        "wake|success|Magic packet sent to {}|port {}|{} bytes", mac_param, port, sent));
    return 0;
}

// ── check action ───────────────────────────────────────────────────────────

int do_check(yuzu::CommandContext& ctx, yuzu::Params params) {
    auto host = params.get("host");
    if (host.empty()) {
        ctx.write_output("check|error|Missing required parameter: host");
        return 1;
    }

    // Validate host to prevent command injection
    // Only allow alphanumeric, dots, hyphens, colons (for IPv6)
    for (char c : host) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '.' || c == '-' || c == ':')) {
            ctx.write_output(std::format("check|error|Invalid host: {}", host));
            return 1;
        }
    }

    auto count_param = params.get("count", "3");
    int count = 3;
    try {
        count = std::stoi(std::string(count_param));
        if (count < 1 || count > 10)
            count = 3;
    } catch (...) {
        count = 3;
    }

    // Build ping command
    std::string cmd;
#ifdef _WIN32
    cmd = std::format("ping -n {} -w 2000 {} 2>&1", count, host);
#else
    cmd = std::format("ping -c {} -W 2 {} 2>&1", count, host);
#endif

    auto ping_out = run_command(cmd.c_str());

    // Determine if host is reachable
    bool reachable = false;
    if (!ping_out.empty()) {
#ifdef _WIN32
        // Windows: look for "Reply from" or "TTL="
        reachable = ping_out.find("Reply from") != std::string::npos ||
                    ping_out.find("TTL=") != std::string::npos;
#else
        // Unix: look for "bytes from" or "time="
        reachable = ping_out.find("bytes from") != std::string::npos ||
                    ping_out.find("time=") != std::string::npos;
#endif
    }

    ctx.write_output(std::format("check|{}|{}|{}", host, reachable ? "reachable" : "unreachable",
                                 count));

    // Output the raw ping result line by line
    std::istringstream ss(ping_out);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty()) {
            ctx.write_output(std::format("ping_line|{}", line));
        }
    }

    return 0;
}

} // namespace

class WolPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "wol"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Sends Wake-on-LAN magic packets and checks host reachability";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"wake", "check", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params params) override {
        if (action == "wake")
            return do_wake(ctx, params);
        if (action == "check")
            return do_check(ctx, params);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(WolPlugin)
