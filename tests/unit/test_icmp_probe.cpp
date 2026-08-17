// icmp_probe.hpp is wave-0 shared infrastructure (discovery's ping sweep,
// wol's `check` action, both Wave-2 packages not yet in this branch) -- this
// TU covers the pure/host-testable surface reachable without a live network
// hop: the RFC-1071 checksum, numeric-literal address resolution (no DNS
// round-trip -- getaddrinfo on a numeric IP or "" resolves entirely
// in-process), and IcmpSession construction succeeding unprivileged on this
// host (matching the live proof already captured in
// ~/.claude/wave2-prestage/shared/icmp_live.cpp).
#include <catch2/catch_test_macros.hpp>

#include <icmp_probe.hpp>

#include <cstring>

using namespace yuzu::shared;

TEST_CASE("icmp_checksum: all-zero packet checksums to 0xFFFF (RFC 1071 identity)",
          "[agent][icmp_probe]") {
    unsigned char pkt[8] = {0};
    CHECK(icmp_checksum(pkt, sizeof(pkt)) == 0xFFFF);
}

TEST_CASE("icmp_checksum: a known byte pattern matches the hand-computed RFC 1071 sum",
          "[agent][icmp_probe]") {
    // Two 16-bit words: 0x0001 + 0xF203 = 0xF204; one's-complement -> 0x0DFB.
    unsigned char pkt[4] = {0x00, 0x01, 0xF2, 0x03};
    CHECK(icmp_checksum(pkt, sizeof(pkt)) == 0x0DFB);
}

TEST_CASE("icmp_checksum: an odd-length buffer pads the trailing byte high, not low",
          "[agent][icmp_probe]") {
    // A single 0xFF byte is summed as 0xFF00 (padded as the HIGH byte per
    // RFC 1071), not 0x00FF -- carry-fold to one's complement of 0xFF00.
    unsigned char pkt[1] = {0xFF};
    CHECK(icmp_checksum(pkt, sizeof(pkt)) == static_cast<std::uint16_t>(~0xFF00));
}

TEST_CASE("resolve_first: a numeric IPv4 literal resolves without any DNS round-trip",
          "[agent][icmp_probe]") {
    auto r = resolve_first("127.0.0.1", AF_INET);
    REQUIRE(r.has_value());
    CHECK(r->family == AF_INET);
    CHECK(r->addr_len == sizeof(sockaddr_in));
    const auto* sin = reinterpret_cast<const sockaddr_in*>(&r->addr);
    CHECK(sin->sin_family == AF_INET);
    unsigned char expected[4] = {127, 0, 0, 1};
    CHECK(std::memcmp(&sin->sin_addr, expected, 4) == 0);
}

TEST_CASE("resolve_first: a numeric IPv6 literal resolves without any DNS round-trip",
          "[agent][icmp_probe]") {
    auto r = resolve_first("::1", AF_INET6);
    REQUIRE(r.has_value());
    CHECK(r->family == AF_INET6);
    CHECK(r->addr_len == sizeof(sockaddr_in6));
}

TEST_CASE("resolve_first: an empty target fails immediately (EAI_NONAME, no network I/O)",
          "[agent][icmp_probe]") {
    auto r = resolve_first("", AF_INET);
    CHECK_FALSE(r.has_value());
}

TEST_CASE("set_port: writes the port in network byte order for both address families",
          "[agent][icmp_probe]") {
    auto v4 = resolve_first("127.0.0.1", AF_INET);
    REQUIRE(v4.has_value());
    set_port(*v4, 8080);
    const auto* sin = reinterpret_cast<const sockaddr_in*>(&v4->addr);
    CHECK(sin->sin_port == htons(8080));

    auto v6 = resolve_first("::1", AF_INET6);
    REQUIRE(v6.has_value());
    set_port(*v6, 443);
    const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(&v6->addr);
    CHECK(sin6->sin6_port == htons(443));
}

TEST_CASE("IcmpSession: constructs an unprivileged, usable session on this host",
          "[agent][icmp_probe]") {
    // Matches the live proof already captured pre-authoring (unprivileged
    // echo to 127.0.0.1, RTT 0.15ms, no entitlement) -- this asserts the
    // session construction succeeds and reports itself permitted, without
    // repeating the live-network round-trip in the unit suite.
    IcmpSession session;
    CHECK(session.ok());
    CHECK(session.permitted);
}
