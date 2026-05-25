#include "cidr_match.hpp"

#include <array>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h> // must precede windows.h (which ws2tcpip.h pulls in)
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace yuzu::server::detail {
namespace {

// Parse a decimal prefix length in [0, max_bits] without throwing. Returns -1 on
// any malformed input (empty, >3 digits, non-digit, leading '+', out of range).
int parse_prefix_len(std::string_view s, int max_bits) {
    if (s.empty() || s.size() > 3)
        return -1;
    int val = 0;
    for (char c : s) {
        if (c < '0' || c > '9')
            return -1;
        val = val * 10 + (c - '0');
    }
    if (val > max_bits)
        return -1;
    return val;
}

// Compare the first `prefix_len` bits of two equal-length byte arrays.
bool prefix_equal(const unsigned char* a, const unsigned char* b, int prefix_len, int total_bits) {
    if (prefix_len < 0 || prefix_len > total_bits)
        return false;
    const int full_bytes = prefix_len / 8;
    const int rem_bits = prefix_len % 8;
    if (full_bytes && std::memcmp(a, b, static_cast<std::size_t>(full_bytes)) != 0)
        return false;
    if (rem_bits) {
        const auto mask = static_cast<unsigned char>(0xFFu << (8 - rem_bits));
        if ((a[full_bytes] & mask) != (b[full_bytes] & mask))
            return false;
    }
    return true;
}

} // namespace

bool ip_in_cidr(std::string_view cidr, std::string_view ip) {
    if (cidr.empty() || ip.empty())
        return false;

    const auto slash = cidr.find('/');
    const std::string net_str(slash == std::string_view::npos ? cidr : cidr.substr(0, slash));
    const std::string ip_str(ip);

    // The network's address family dictates which family `ip` must be: try IPv4
    // first, then IPv6. A cross-family pair falls through to false.
    std::array<unsigned char, 4> net4{}, ip4{};
    if (inet_pton(AF_INET, net_str.c_str(), net4.data()) == 1) {
        if (inet_pton(AF_INET, ip_str.c_str(), ip4.data()) != 1)
            return false;
        const int prefix =
            (slash == std::string_view::npos) ? 32 : parse_prefix_len(cidr.substr(slash + 1), 32);
        return prefix_equal(net4.data(), ip4.data(), prefix, 32);
    }

    std::array<unsigned char, 16> net6{}, ip6{};
    if (inet_pton(AF_INET6, net_str.c_str(), net6.data()) == 1) {
        if (inet_pton(AF_INET6, ip_str.c_str(), ip6.data()) != 1)
            return false;
        const int prefix =
            (slash == std::string_view::npos) ? 128 : parse_prefix_len(cidr.substr(slash + 1), 128);
        return prefix_equal(net6.data(), ip6.data(), prefix, 128);
    }

    return false; // net_str parsed as neither family
}

bool ips_share_trusted_cidr(const std::vector<std::string>& cidrs, std::string_view a,
                            std::string_view b) {
    if (a.empty() || b.empty())
        return false;
    for (const auto& cidr : cidrs) {
        if (ip_in_cidr(cidr, a) && ip_in_cidr(cidr, b))
            return true;
    }
    return false;
}

} // namespace yuzu::server::detail
