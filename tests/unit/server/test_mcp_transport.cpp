/**
 * test_mcp_transport.cpp — MCP Streamable HTTP transport pre-check helpers
 * (ADR-1005 Decision 15, track 2f). Pure predicates, no httplib/auth deps.
 * Covers the CH-9 (Origin) pure core + protocol-version negotiation clamp.
 */

#include "mcp_transport.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::server::mcp::transport;

TEST_CASE("MCP transport: protocol version support set", "[mcp][transport]") {
    CHECK(protocol_version_supported("2025-03-26"));
    CHECK(protocol_version_supported("2025-06-18"));
    CHECK_FALSE(protocol_version_supported("2024-11-05")); // older, unsupported
    CHECK_FALSE(protocol_version_supported("9999-99-99"));
    CHECK_FALSE(protocol_version_supported("")); // absent is the caller's concern, not "supported"
    CHECK(kProtocolDefault == "2025-03-26");
}

TEST_CASE("MCP transport: Origin allowlist (CH-9 pure core)", "[mcp][transport]") {
    SECTION("absent Origin is always allowed (credential-gated endpoint)") {
        CHECK(origin_allowed("", {}));                             // empty allowlist
        CHECK(origin_allowed("", {"https://ui.example.com"}));     // populated allowlist
    }
    SECTION("empty allowlist rejects ANY present Origin (secure default)") {
        CHECK_FALSE(origin_allowed("https://ui.example.com", {}));
        CHECK_FALSE(origin_allowed("http://localhost:8080", {}));
    }
    SECTION("present Origin must match an allowlist entry exactly") {
        const std::vector<std::string> allow{"https://ui.example.com", "http://localhost:8080"};
        CHECK(origin_allowed("https://ui.example.com", allow));
        CHECK(origin_allowed("http://localhost:8080", allow));
        // scheme / host / port mismatches all reject — no heuristics
        CHECK_FALSE(origin_allowed("http://ui.example.com", allow));   // scheme
        CHECK_FALSE(origin_allowed("https://evil.example.com", allow)); // host
        CHECK_FALSE(origin_allowed("http://localhost:9090", allow));    // port
        CHECK_FALSE(origin_allowed("https://ui.example.com/", allow));  // trailing slash ≠ exact
    }
}

TEST_CASE("MCP transport: Accept opts into SSE (case-insensitive)", "[mcp][transport]") {
    CHECK(accept_wants_sse("text/event-stream"));
    CHECK(accept_wants_sse("application/json, text/event-stream"));
    CHECK(accept_wants_sse("TEXT/EVENT-STREAM"));
    CHECK(accept_wants_sse("application/json,Text/Event-Stream;q=0.9"));
    CHECK_FALSE(accept_wants_sse("application/json"));
    CHECK_FALSE(accept_wants_sse(""));
    CHECK_FALSE(accept_wants_sse("text/event")); // partial, not the full media type
}
