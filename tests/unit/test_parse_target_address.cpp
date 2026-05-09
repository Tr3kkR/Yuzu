// SPDX-License-Identifier: Apache-2.0
//
// tests/unit/test_parse_target_address.cpp
//
// Pure-function tests for the agent-side target-address parser introduced
// by #376 PR 1c-3. Covers the 10+ rejection paths and the IPv4/IPv6
// happy paths. Pinning the rejection contract here is what governance
// QE-1 required before this round was mergeable: the parser is a
// security perimeter (operator-edited cfg) and its `noexcept` envelope
// must hold across every branch.
//
// Sibling parser: server.cpp parse_listen_address (server-side bind
// parser; strips IPv6 brackets, allows port==0). Both will collapse
// into a single transport-library helper in #376 PR 1c-6 — at that
// point this file moves into the transport test suite.

#include <yuzu/agent/detail/parse_target_address.hpp>
#include <yuzu/transport/transport.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>

using yuzu::agent::detail::parse_target_address;

namespace {

bool rejects(std::string_view s) noexcept {
    return !parse_target_address(s).has_value();
}

} // namespace

TEST_CASE("parse_target_address: valid IPv4", "[agent][parse_target_address]") {
    auto e = parse_target_address("server.example.com:50051");
    REQUIRE(e.has_value());
    CHECK(e->host == "server.example.com");
    CHECK(e->port == 50051);
}

TEST_CASE("parse_target_address: valid bare IPv4 literal", "[agent][parse_target_address]") {
    auto e = parse_target_address("192.0.2.1:50051");
    REQUIRE(e.has_value());
    CHECK(e->host == "192.0.2.1");
    CHECK(e->port == 50051);
}

TEST_CASE("parse_target_address: valid IPv6 with brackets", "[agent][parse_target_address][ipv6]") {
    auto e = parse_target_address("[::1]:50051");
    REQUIRE(e.has_value());
    // Brackets are RETAINED in host so the gRPC backend's `host + ":" + port`
    // construction yields a valid address literal. This is intentional.
    CHECK(e->host == "[::1]");
    CHECK(e->port == 50051);
}

TEST_CASE("parse_target_address: valid IPv6 full form", "[agent][parse_target_address][ipv6]") {
    auto e = parse_target_address("[2001:db8::1]:443");
    REQUIRE(e.has_value());
    CHECK(e->host == "[2001:db8::1]");
    CHECK(e->port == 443);
}

TEST_CASE("parse_target_address: port at lower boundary (1) accepted",
          "[agent][parse_target_address][bounds]") {
    auto e = parse_target_address("h:1");
    REQUIRE(e.has_value());
    CHECK(e->port == 1);
}

TEST_CASE("parse_target_address: port at upper boundary (65535) accepted",
          "[agent][parse_target_address][bounds]") {
    auto e = parse_target_address("h:65535");
    REQUIRE(e.has_value());
    CHECK(e->port == 65535);
}

TEST_CASE("parse_target_address: leading-zero port accepted (canonical 50051)",
          "[agent][parse_target_address][bounds]") {
    // std::from_chars accepts leading zeros for unsigned without complaint.
    auto e = parse_target_address("h:0050051");
    REQUIRE(e.has_value());
    CHECK(e->port == 50051);
}

TEST_CASE("parse_target_address: rejects empty input", "[agent][parse_target_address][reject]") {
    CHECK(rejects(""));
}

TEST_CASE("parse_target_address: rejects port == 0",
          "[agent][parse_target_address][reject][bounds]") {
    // Client targets cannot point at an ephemeral port; sibling
    // parse_listen_address allows port==0 for server bind.
    CHECK(rejects("h:0"));
    CHECK(rejects("[::1]:0"));
}

TEST_CASE("parse_target_address: rejects port > 65535",
          "[agent][parse_target_address][reject][bounds]") {
    CHECK(rejects("h:65536"));
    CHECK(rejects("h:99999"));
    CHECK(rejects("h:4294967295")); // UINT32_MAX
}

TEST_CASE("parse_target_address: rejects port overflow uint32",
          "[agent][parse_target_address][reject][bounds]") {
    // std::from_chars returns errc::result_out_of_range for >UINT32_MAX,
    // which our predicate treats as failure.
    CHECK(rejects("h:99999999999"));
}

TEST_CASE("parse_target_address: rejects missing colon", "[agent][parse_target_address][reject]") {
    CHECK(rejects("server.example.com"));
    CHECK(rejects("hostonly"));
}

TEST_CASE("parse_target_address: rejects empty host", "[agent][parse_target_address][reject]") {
    CHECK(rejects(":50051"));
}

TEST_CASE("parse_target_address: rejects empty port", "[agent][parse_target_address][reject]") {
    CHECK(rejects("server.example.com:"));
    CHECK(rejects("h:"));
}

TEST_CASE("parse_target_address: rejects non-numeric port",
          "[agent][parse_target_address][reject]") {
    CHECK(rejects("h:abc"));
    CHECK(rejects("h:50a"));
    CHECK(rejects("h:5 0"));
    CHECK(rejects("h:0x50"));
}

TEST_CASE("parse_target_address: rejects port with trailing junk",
          "[agent][parse_target_address][reject]") {
    // from_chars consumes only the digits; if any chars remain, the
    // ptr != last predicate fails and the parser rejects.
    CHECK(rejects("h:50051x"));
    CHECK(rejects("h:50051 "));
    CHECK(rejects("h:50051\n"));
}

TEST_CASE("parse_target_address: rejects negative port", "[agent][parse_target_address][reject]") {
    // from_chars on uint32_t does not accept '-'; treated as non-numeric.
    CHECK(rejects("h:-1"));
}

TEST_CASE("parse_target_address: rejects IPv6 missing closing bracket",
          "[agent][parse_target_address][reject][ipv6]") {
    CHECK(rejects("[::1:50051"));
    CHECK(rejects("[::1"));
}

TEST_CASE("parse_target_address: rejects IPv6 with no port",
          "[agent][parse_target_address][reject][ipv6]") {
    CHECK(rejects("[::1]"));
}

TEST_CASE("parse_target_address: rejects IPv6 missing colon after bracket",
          "[agent][parse_target_address][reject][ipv6]") {
    CHECK(rejects("[::1]50051"));
    CHECK(rejects("[::1]x:50051"));
}

TEST_CASE("parse_target_address: rejects NUL byte injection",
          "[agent][parse_target_address][reject][security]") {
    using namespace std::literals;
    // Embedded NUL inside the port — from_chars treats it as a non-digit
    // and the parser rejects on `ptr != last`.
    CHECK(rejects("h:500\x0051"sv));
    // Embedded NUL inside the host token — for non-bracketed input we
    // accept this verbatim because string_view is byte-safe and gRPC's
    // resolver will reject downstream. Document the choice rather than
    // assert a behaviour the parser does not enforce.
}

TEST_CASE("parse_target_address: noexcept envelope holds across rejection paths",
          "[agent][parse_target_address][contract]") {
    // Compile-time check: the function signature is noexcept.
    static_assert(noexcept(parse_target_address(std::string_view{})),
                  "parse_target_address MUST remain noexcept (governance "
                  "contract; agent treats startup OOM as fatal)");
}
