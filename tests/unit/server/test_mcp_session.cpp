/**
 * test_mcp_session.cpp — McpSessionRegistry (ADR-0022 Decision 15, track 2f).
 *
 * Covers the security-critical session invariants: 128-bit CSPRNG ids, the
 * principal-bound / no-cross-principal-oracle rule (CH-8), reject-not-evict cap
 * semantics (15(j)), idle-TTL expiry via an injected clock, and DELETE reuse.
 * Session fixation (a client-supplied id is never adopted) is a wiring property
 * verified in test_mcp_server.cpp — the registry exposes no id-ingest API.
 */

#include "mcp_session.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <set>
#include <string>
#include <thread>
#include <vector>

using yuzu::server::mcp::McpSessionRegistry;
using Validate = McpSessionRegistry::ValidateResult;

TEST_CASE("MCP session: mint yields unique 128-bit lowercase-hex ids", "[mcp][session]") {
    McpSessionRegistry reg({.per_principal_cap = 100, .global_cap = 1000});
    std::set<std::string> ids;
    for (int i = 0; i < 50; ++i) {
        auto r = reg.mint("alice");
        REQUIRE(r.ok);
        CHECK(r.session_id.size() == 32); // 16 bytes → 32 hex chars = 128-bit
        CHECK(ids.insert(r.session_id).second == true); // never a duplicate
        for (char c : r.session_id) {
            CHECK(((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')));
        }
    }
    CHECK(reg.active_count() == 50);
}

TEST_CASE("MCP session: validate is principal-bound, no cross-principal oracle (CH-8)",
          "[mcp][session]") {
    McpSessionRegistry reg;
    auto a = reg.mint("alice");
    REQUIRE(a.ok);

    CHECK(reg.validate_and_touch(a.session_id, "alice") == Validate::kValid);
    // alice's valid id under bob's identity ≡ a never-existed id (no oracle)
    CHECK(reg.validate_and_touch(a.session_id, "bob") == Validate::kUnknown);
    CHECK(reg.validate_and_touch(std::string(32, 'a'), "bob") == Validate::kUnknown);
    // bob's probe neither consumed nor leaked alice's session
    CHECK(reg.validate_and_touch(a.session_id, "alice") == Validate::kValid);
}

TEST_CASE("MCP session: idle TTL expires; touch slides the window", "[mcp][session]") {
    std::chrono::steady_clock::time_point clk{};
    McpSessionRegistry reg(
        {.per_principal_cap = 8, .global_cap = 64, .idle_ttl = std::chrono::seconds{30}},
        [&clk]() { return clk; });

    auto a = reg.mint("alice");
    REQUIRE(a.ok);

    clk += std::chrono::seconds{20};
    CHECK(reg.validate_and_touch(a.session_id, "alice") == Validate::kValid); // touch → last_seen=20
    clk += std::chrono::seconds{20};                                          // 20s < 30s idle
    CHECK(reg.validate_and_touch(a.session_id, "alice") == Validate::kValid);
    clk += std::chrono::seconds{31}; // now idle > 30s
    CHECK(reg.validate_and_touch(a.session_id, "alice") == Validate::kUnknown);
    CHECK(reg.active_count() == 0); // gc'd on the failing validate
}

TEST_CASE("MCP session: per-principal cap REJECTS, never evicts a live session (15(j))",
          "[mcp][session]") {
    McpSessionRegistry reg(
        {.per_principal_cap = 2, .global_cap = 64, .idle_ttl = std::chrono::hours{1}});
    auto a1 = reg.mint("alice");
    auto a2 = reg.mint("alice");
    REQUIRE(a1.ok);
    REQUIRE(a2.ok);

    auto a3 = reg.mint("alice");
    CHECK_FALSE(a3.ok);
    CHECK(a3.reject_reason == "per_principal_cap");
    CHECK(a3.session_id.empty());

    // The two live sessions SURVIVE — the cap did not evict to make room.
    CHECK(reg.validate_and_touch(a1.session_id, "alice") == Validate::kValid);
    CHECK(reg.validate_and_touch(a2.session_id, "alice") == Validate::kValid);
    // A different principal is unaffected by alice's cap.
    CHECK(reg.mint("bob").ok);
}

TEST_CASE("MCP session: global cap rejects", "[mcp][session]") {
    McpSessionRegistry reg(
        {.per_principal_cap = 10, .global_cap = 2, .idle_ttl = std::chrono::hours{1}});
    CHECK(reg.mint("alice").ok);
    CHECK(reg.mint("bob").ok);
    auto third = reg.mint("carol");
    CHECK_FALSE(third.ok);
    CHECK(third.reject_reason == "global_cap");
}

TEST_CASE("MCP session: terminate is principal-bound; reuse 404s", "[mcp][session]") {
    McpSessionRegistry reg;
    auto a = reg.mint("alice");
    REQUIRE(a.ok);

    CHECK_FALSE(reg.terminate(a.session_id, "bob")); // foreign principal cannot delete
    CHECK(reg.validate_and_touch(a.session_id, "alice") == Validate::kValid); // still alive

    CHECK(reg.terminate(a.session_id, "alice")); // owner deletes
    CHECK(reg.validate_and_touch(a.session_id, "alice") == Validate::kUnknown); // gone
    CHECK_FALSE(reg.terminate(a.session_id, "alice")); // double-delete is a no-op
    CHECK(reg.active_count() == 0);
}

TEST_CASE("MCP session: concurrent access is race-free (TSan regression net)", "[mcp][session]") {
    // The registry claims thread-safety (httplib dispatches across workers). This
    // hammers mint/validate_and_touch/terminate/gc from many threads so TSan/ASan
    // catch a future method that forgets the lock (governance cpp-safety-SHOULD).
    // No socket/httplib → no #438 TSan-acceptor hazard.
    McpSessionRegistry reg({.per_principal_cap = 1000, .global_cap = 100000});
    constexpr int kThreads = 8;
    constexpr int kOpsPerThread = 400;
    // Catch2 assertion macros are NOT multithread-safe, so worker threads only
    // accumulate into atomics; every CHECK runs after join (cpp-safety SAFE-RE-S2).
    std::atomic<int> minted{0};
    std::atomic<int> own_invalid{0}; // a thread's own just-minted session read back != kValid
    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&reg, &minted, &own_invalid, t] {
            const std::string principal = "p" + std::to_string(t);
            std::vector<std::string> mine;
            for (int i = 0; i < kOpsPerThread; ++i) {
                auto m = reg.mint(principal);
                if (m.ok) {
                    ++minted;
                    if (reg.validate_and_touch(m.session_id, principal) != Validate::kValid) {
                        ++own_invalid; // must stay 0 — asserted after join
                    }
                    mine.push_back(m.session_id);
                }
                if (!mine.empty() && (i % 3 == 0)) {
                    reg.terminate(mine.back(), principal);
                    mine.pop_back();
                }
                // foreign / unknown probes must never crash or leak across threads
                (void)reg.validate_and_touch(std::string(32, 'e'), "intruder");
                if (i % 7 == 0) {
                    reg.gc();
                }
            }
        });
    }
    for (auto& th : threads) {
        th.join();
    }
    CHECK(minted.load() > 0);
    CHECK(own_invalid.load() == 0); // no thread ever failed to read back its own session
    CHECK(reg.active_count() <= static_cast<std::size_t>(kThreads * kOpsPerThread));
}

TEST_CASE("MCP session: idle GC reclaims cap room on mint", "[mcp][session]") {
    std::chrono::steady_clock::time_point clk{};
    McpSessionRegistry reg(
        {.per_principal_cap = 1, .global_cap = 8, .idle_ttl = std::chrono::seconds{30}},
        [&clk]() { return clk; });

    auto a1 = reg.mint("alice");
    REQUIRE(a1.ok);
    CHECK_FALSE(reg.mint("alice").ok); // cap 1 hit while a1 is live

    clk += std::chrono::seconds{31};   // a1 idles out
    auto a2 = reg.mint("alice");        // mint's opportunistic GC frees a1's slot
    CHECK(a2.ok);
    CHECK(reg.active_count() == 1);
}
