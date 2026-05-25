/**
 * test_cidr_match.cpp — unit coverage for the #1128 NAT-aware binding's CIDR
 * containment helpers (server/core/src/cidr_match.{hpp,cpp}).
 *
 * These back the trusted-NAT-CIDR relaxation: a direct-connect agent whose
 * Register and Subscribe source IPs both fall inside an operator-declared
 * multi-egress range is tolerated instead of rejected. The security contract is
 * symmetric: an IP pair that does NOT share a configured range must NOT be
 * tolerated (the #826 stolen-session guard stays intact), and a malformed CIDR
 * or IP must never widen the match.
 */

#include "cidr_match.hpp"

#include <catch2/catch_test_macros.hpp>

using yuzu::server::detail::ip_in_cidr;
using yuzu::server::detail::ips_share_trusted_cidr;

TEST_CASE("ip_in_cidr: IPv4 containment", "[cidr][issue1128]") {
    CHECK(ip_in_cidr("10.0.0.0/8", "10.1.2.3"));
    CHECK(ip_in_cidr("10.0.0.0/8", "10.255.255.255"));
    CHECK_FALSE(ip_in_cidr("10.0.0.0/8", "11.0.0.1"));

    CHECK(ip_in_cidr("203.0.113.0/24", "203.0.113.7"));
    CHECK(ip_in_cidr("203.0.113.0/24", "203.0.113.255"));
    CHECK_FALSE(ip_in_cidr("203.0.113.0/24", "203.0.114.1")); // adjacent /24

    // /32 = exact host, and a bare address means an implicit /32.
    CHECK(ip_in_cidr("192.168.1.5/32", "192.168.1.5"));
    CHECK_FALSE(ip_in_cidr("192.168.1.5/32", "192.168.1.6"));
    CHECK(ip_in_cidr("192.168.1.5", "192.168.1.5"));
    CHECK_FALSE(ip_in_cidr("192.168.1.5", "192.168.1.6"));

    // /0 matches everything in-family.
    CHECK(ip_in_cidr("0.0.0.0/0", "8.8.8.8"));
}

TEST_CASE("ip_in_cidr: IPv6 containment", "[cidr][issue1128]") {
    CHECK(ip_in_cidr("2001:db8::/32", "2001:db8::1"));
    CHECK(ip_in_cidr("2001:db8::/32", "2001:db8:ffff::abcd"));
    CHECK_FALSE(ip_in_cidr("2001:db8::/32", "2001:db9::1"));

    CHECK(ip_in_cidr("fe80::/10", "fe80::1"));
    CHECK_FALSE(ip_in_cidr("fe80::/10", "fec0::1"));

    // /128 exact + bare implicit /128. Case-insensitive (inet_pton canonicalizes).
    CHECK(ip_in_cidr("2001:db8::dead:beef/128", "2001:db8::DEAD:BEEF"));
    CHECK(ip_in_cidr("2001:db8::1", "2001:DB8::1"));
    CHECK(ip_in_cidr("::/0", "2606:4700::1"));
}

TEST_CASE("ip_in_cidr: cross-family pairs never match", "[cidr][issue1128]") {
    CHECK_FALSE(ip_in_cidr("10.0.0.0/8", "2001:db8::1"));     // v6 ip, v4 cidr
    CHECK_FALSE(ip_in_cidr("2001:db8::/32", "10.1.2.3"));     // v4 ip, v6 cidr
    CHECK_FALSE(ip_in_cidr("::/0", "8.8.8.8"));               // v4 ip, v6 catch-all
    CHECK_FALSE(ip_in_cidr("0.0.0.0/0", "2001:db8::1"));      // v6 ip, v4 catch-all
}

TEST_CASE("ip_in_cidr: malformed inputs are false, never throw", "[cidr][issue1128]") {
    CHECK_FALSE(ip_in_cidr("", "10.0.0.1"));
    CHECK_FALSE(ip_in_cidr("10.0.0.0/8", ""));
    CHECK_FALSE(ip_in_cidr("not-a-cidr", "10.0.0.1"));
    CHECK_FALSE(ip_in_cidr("10.0.0.0/8", "not-an-ip"));
    CHECK_FALSE(ip_in_cidr("10.0.0.0/33", "10.0.0.1"));  // prefix > 32
    CHECK_FALSE(ip_in_cidr("2001:db8::/129", "2001:db8::1")); // prefix > 128
    CHECK_FALSE(ip_in_cidr("10.0.0.0/abc", "10.0.0.1")); // non-numeric prefix
    CHECK_FALSE(ip_in_cidr("10.0.0.0/", "10.0.0.1"));    // empty prefix
    CHECK_FALSE(ip_in_cidr("10.0.0.0/9999", "10.0.0.1")); // overflow-ish prefix
}

TEST_CASE("ips_share_trusted_cidr: both endpoints must share one range",
          "[cidr][issue1128]") {
    const std::vector<std::string> cidrs{"203.0.113.0/24", "198.51.100.0/24", "2001:db8::/32"};

    // Legit multi-egress: two different IPs in the SAME declared range → tolerated.
    CHECK(ips_share_trusted_cidr(cidrs, "203.0.113.7", "203.0.113.200"));
    CHECK(ips_share_trusted_cidr(cidrs, "2001:db8::1", "2001:db8:dead::beef"));

    // Stolen-session replay analogue: one in range, one outside → NOT tolerated.
    CHECK_FALSE(ips_share_trusted_cidr(cidrs, "203.0.113.7", "8.8.8.8"));
    // Each IP is in a DIFFERENT trusted range — not the same one → NOT tolerated.
    CHECK_FALSE(ips_share_trusted_cidr(cidrs, "203.0.113.7", "198.51.100.7"));
    // Neither in range.
    CHECK_FALSE(ips_share_trusted_cidr(cidrs, "8.8.8.8", "1.1.1.1"));
}

TEST_CASE("ips_share_trusted_cidr: empty list or empty IP is false",
          "[cidr][issue1128]") {
    CHECK_FALSE(ips_share_trusted_cidr({}, "203.0.113.7", "203.0.113.8"));
    const std::vector<std::string> cidrs{"203.0.113.0/24"};
    CHECK_FALSE(ips_share_trusted_cidr(cidrs, "", "203.0.113.8"));
    CHECK_FALSE(ips_share_trusted_cidr(cidrs, "203.0.113.7", ""));
}
