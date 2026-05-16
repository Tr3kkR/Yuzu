/**
 * test_auth.cpp — Unit tests for yuzu::server::auth::AuthManager
 *
 * Covers: crypto primitives, password auth, sessions, user CRUD,
 *         enrollment tokens, pending agents, config persistence.
 */

#include <yuzu/server/auth.hpp>

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::server::auth;

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Create an AuthManager configured to use a per-test config file.
///
/// Previously this used a hardcoded shared `yuzu_test_auth` directory and a
/// process-wide cleanup_guard, which meant any two tests running in the same
/// process saw each other's state via the on-disk file even though they
/// thought they had a clean AuthManager. Migrated to the canonical helper —
/// every call gets its own unique path so tests are independent.
/// (governance qe-B2; flake-class #473.)
static std::unique_ptr<AuthManager> make_temp_auth() {
    auto mgr = std::make_unique<AuthManager>();
    auto cfg = yuzu::test::unique_temp_path("yuzu-test-auth-");
    cfg += ".cfg";
    fs::create_directories(cfg.parent_path());
    fs::remove(cfg);
    mgr->load_config(cfg);
    return mgr;
}

// ── Crypto Primitives ────────────────────────────────────────────────────────

TEST_CASE("bytes_to_hex produces lowercase hex", "[auth][crypto]") {
    std::vector<uint8_t> data = {0x00, 0xFF, 0xAB, 0x12};
    auto hex = AuthManager::bytes_to_hex(data);
    REQUIRE(hex == "00ffab12");
}

TEST_CASE("hex_to_bytes roundtrip", "[auth][crypto]") {
    std::vector<uint8_t> original = {0xDE, 0xAD, 0xBE, 0xEF};
    auto hex = AuthManager::bytes_to_hex(original);
    auto roundtripped = AuthManager::hex_to_bytes(hex);
    REQUIRE(roundtripped == original);
}

TEST_CASE("hex_to_bytes with empty string", "[auth][crypto]") {
    auto result = AuthManager::hex_to_bytes("");
    REQUIRE(result.empty());
}

TEST_CASE("sha256_hex known vector", "[auth][crypto]") {
    // SHA-256 of empty string
    auto hash = AuthManager::sha256_hex("");
    REQUIRE(hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST_CASE("sha256_hex known vector: hello", "[auth][crypto]") {
    auto hash = AuthManager::sha256_hex("hello");
    REQUIRE(hash == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
}

TEST_CASE("random_bytes returns requested size", "[auth][crypto]") {
    auto bytes = AuthManager::random_bytes(32);
    REQUIRE(bytes.size() == 32);
}

TEST_CASE("random_bytes produces unique outputs", "[auth][crypto]") {
    auto a = AuthManager::random_bytes(16);
    auto b = AuthManager::random_bytes(16);
    REQUIRE(a != b);
}

TEST_CASE("constant_time_compare: equal strings", "[auth][crypto]") {
    REQUIRE(AuthManager::constant_time_compare("abc", "abc"));
}

TEST_CASE("constant_time_compare: unequal strings", "[auth][crypto]") {
    REQUIRE_FALSE(AuthManager::constant_time_compare("abc", "def"));
}

TEST_CASE("constant_time_compare: different lengths", "[auth][crypto]") {
    REQUIRE_FALSE(AuthManager::constant_time_compare("abc", "abcd"));
}

TEST_CASE("pbkdf2_sha256 produces consistent output", "[auth][crypto]") {
    std::vector<uint8_t> salt = {0x01, 0x02, 0x03, 0x04};
    auto h1 = AuthManager::pbkdf2_sha256("password", salt, 1000);
    auto h2 = AuthManager::pbkdf2_sha256("password", salt, 1000);
    REQUIRE(h1 == h2);
    REQUIRE_FALSE(h1.empty());
}

TEST_CASE("pbkdf2_sha256 different passwords differ", "[auth][crypto]") {
    std::vector<uint8_t> salt = {0x01, 0x02, 0x03, 0x04};
    auto h1 = AuthManager::pbkdf2_sha256("password1", salt, 1000);
    auto h2 = AuthManager::pbkdf2_sha256("password2", salt, 1000);
    REQUIRE(h1 != h2);
}

// ── Role / Status Conversions ────────────────────────────────────────────────

TEST_CASE("role_to_string", "[auth][role]") {
    REQUIRE(role_to_string(Role::admin) == "admin");
    REQUIRE(role_to_string(Role::user) == "user");
}

TEST_CASE("string_to_role", "[auth][role]") {
    REQUIRE(string_to_role("admin") == Role::admin);
    REQUIRE(string_to_role("user") == Role::user);
    REQUIRE(string_to_role("unknown") == Role::user); // default
}

TEST_CASE("pending_status_to_string", "[auth][role]") {
    REQUIRE(pending_status_to_string(PendingStatus::pending) == "pending");
    REQUIRE(pending_status_to_string(PendingStatus::approved) == "approved");
    REQUIRE(pending_status_to_string(PendingStatus::denied) == "denied");
}

// ── User Management ──────────────────────────────────────────────────────────

TEST_CASE("has_users returns false initially", "[auth][user]") {
    auto mgr = make_temp_auth();
    REQUIRE_FALSE(mgr->has_users());
}

TEST_CASE("upsert_user + list_users", "[auth][user]") {
    auto mgr = make_temp_auth();
    REQUIRE(mgr->upsert_user("alice", "password12345", Role::admin));
    REQUIRE(mgr->has_users());

    auto users = mgr->list_users();
    REQUIRE(users.size() == 1);
    REQUIRE(users[0].username == "alice");
    REQUIRE(users[0].role == Role::admin);
}

TEST_CASE("remove_user", "[auth][user]") {
    auto mgr = make_temp_auth();
    mgr->upsert_user("alice", "password1234", Role::admin);
    REQUIRE(mgr->remove_user("alice"));
    REQUIRE_FALSE(mgr->has_users());
}

TEST_CASE("remove_user returns false for nonexistent user", "[auth][user]") {
    auto mgr = make_temp_auth();
    REQUIRE_FALSE(mgr->remove_user("nonexistent"));
}

// ── Authentication ───────────────────────────────────────────────────────────

TEST_CASE("authenticate succeeds with correct password", "[auth][session]") {
    auto mgr = make_temp_auth();
    mgr->upsert_user("alice", "secret123456", Role::admin);

    auto token = mgr->authenticate("alice", "secret123456");
    REQUIRE(token.has_value());
    REQUIRE_FALSE(token->empty());
}

TEST_CASE("authenticate fails with wrong password", "[auth][session]") {
    auto mgr = make_temp_auth();
    mgr->upsert_user("alice", "secret123456", Role::admin);

    auto token = mgr->authenticate("alice", "wrong");
    REQUIRE_FALSE(token.has_value());
}

TEST_CASE("authenticate fails for unknown user", "[auth][session]") {
    auto mgr = make_temp_auth();
    auto token = mgr->authenticate("nobody", "password1234");
    REQUIRE_FALSE(token.has_value());
}

TEST_CASE("validate_session returns correct user info", "[auth][session]") {
    auto mgr = make_temp_auth();
    mgr->upsert_user("alice", "secret123456", Role::admin);

    auto token = mgr->authenticate("alice", "secret123456");
    REQUIRE(token.has_value());

    auto session = mgr->validate_session(*token);
    REQUIRE(session.has_value());
    REQUIRE(session->username == "alice");
    REQUIRE(session->role == Role::admin);
}

TEST_CASE("invalidate_session destroys session", "[auth][session]") {
    auto mgr = make_temp_auth();
    mgr->upsert_user("alice", "secret123456", Role::admin);

    auto token = mgr->authenticate("alice", "secret123456");
    REQUIRE(token.has_value());

    mgr->invalidate_session(*token);
    REQUIRE_FALSE(mgr->validate_session(*token).has_value());
}

TEST_CASE("validate_session fails for garbage token", "[auth][session]") {
    auto mgr = make_temp_auth();
    REQUIRE_FALSE(mgr->validate_session("not-a-real-token").has_value());
}

TEST_CASE("validate_session rejects overly-long tokens (DoS protection #630)", "[auth][session]") {
    auto mgr = make_temp_auth();
    mgr->upsert_user("testuser", "secret123456", Role::admin); // min 12 chars

    // Get a valid token via normal auth flow
    auto valid_token = mgr->authenticate("testuser", "secret123456");
    REQUIRE(valid_token.has_value());
    REQUIRE(valid_token->size() == 64); // Should be exactly 64 hex chars

    // 65 chars — should be rejected
    std::string too_long_65 = *valid_token + "x";
    REQUIRE_FALSE(mgr->validate_session(too_long_65).has_value());

    // 128 chars — should be rejected
    REQUIRE_FALSE(mgr->validate_session(std::string(128, 'a')).has_value());

    // 1000 chars — should be rejected (DoS attempt)
    REQUIRE_FALSE(mgr->validate_session(std::string(1000, 'b')).has_value());
}

// ── Enrollment Tokens ────────────────────────────────────────────────────────

TEST_CASE("create and validate enrollment token", "[auth][enrollment]") {
    auto mgr = make_temp_auth();
    auto raw = mgr->create_enrollment_token("test", 0, std::chrono::hours(1));
    REQUIRE_FALSE(raw.empty());
    REQUIRE(mgr->validate_enrollment_token(raw));
}

TEST_CASE("validate fails with wrong token", "[auth][enrollment]") {
    auto mgr = make_temp_auth();
    mgr->create_enrollment_token("test", 0, std::chrono::hours(1));
    REQUIRE_FALSE(mgr->validate_enrollment_token("definitely-wrong-token"));
}

TEST_CASE("validate fails after revocation", "[auth][enrollment]") {
    auto mgr = make_temp_auth();
    auto raw = mgr->create_enrollment_token("test", 0, std::chrono::hours(1));

    auto tokens = mgr->list_enrollment_tokens();
    REQUIRE(tokens.size() == 1);
    REQUIRE(mgr->revoke_enrollment_token(tokens[0].token_id));
    REQUIRE_FALSE(mgr->validate_enrollment_token(raw));
}

TEST_CASE("max_uses enforcement", "[auth][enrollment]") {
    auto mgr = make_temp_auth();
    auto raw = mgr->create_enrollment_token("once", 1, std::chrono::hours(1));

    REQUIRE(mgr->validate_enrollment_token(raw));       // first use
    REQUIRE_FALSE(mgr->validate_enrollment_token(raw)); // exhausted
}

TEST_CASE("batch token creation", "[auth][enrollment]") {
    auto mgr = make_temp_auth();
    auto batch = mgr->create_enrollment_tokens_batch("batch", 5, 10, std::chrono::hours(1));
    REQUIRE(batch.size() == 5);

    // All tokens should be distinct
    for (size_t i = 0; i < batch.size(); ++i) {
        for (size_t j = i + 1; j < batch.size(); ++j) {
            REQUIRE(batch[i] != batch[j]);
        }
    }
}

TEST_CASE("list_enrollment_tokens", "[auth][enrollment]") {
    auto mgr = make_temp_auth();
    mgr->create_enrollment_token("alpha", 0, std::chrono::hours(1));
    mgr->create_enrollment_token("beta", 0, std::chrono::hours(1));

    auto tokens = mgr->list_enrollment_tokens();
    REQUIRE(tokens.size() == 2);
}

// ── Enrollment Token — Atomic Consume (W1.4 / #827) ─────────────────────────
//
// `consume_enrollment_token` is the new atomic-claim entry point. The legacy
// `validate_enrollment_token` is now a thin wrapper. The race-loss case is
// the primary defence against the #827 attack (two Register RPCs presenting
// the same one-time enrollment token simultaneously, both passing the
// pre-W1.4 check-then-increment race window).

TEST_CASE("consume_enrollment_token returns claim on success", "[auth][enrollment][atomic]") {
    auto mgr = make_temp_auth();
    auto raw = mgr->create_enrollment_token("first-use", 5, std::chrono::hours(1));

    auto claim = mgr->consume_enrollment_token(raw, "agent-A");
    REQUIRE(claim.has_value());
    CHECK(claim->use_count_after == 1);
    CHECK(claim->max_uses == 5);
    CHECK_FALSE(claim->single_use);
    CHECK_FALSE(claim->token_id.empty());

    // Second consume from a different agent also wins — multi-use token.
    auto claim2 = mgr->consume_enrollment_token(raw, "agent-B");
    REQUIRE(claim2.has_value());
    CHECK(claim2->use_count_after == 2);

    // last_consumer_for_token_hash returns the most-recent consumer.
    auto hash = AuthManager::sha256_hex(raw);
    CHECK(mgr->last_consumer_for_token_hash(hash) == "agent-B");
}

TEST_CASE("consume_enrollment_token: not_found on unknown token", "[auth][enrollment][atomic]") {
    auto mgr = make_temp_auth();
    mgr->create_enrollment_token("decoy", 1, std::chrono::hours(1));

    auto claim = mgr->consume_enrollment_token("never-issued-token", "agent-X");
    REQUIRE_FALSE(claim.has_value());
    CHECK(claim.error() == EnrollmentTokenError::not_found);
}

TEST_CASE("consume_enrollment_token: revoked variant", "[auth][enrollment][atomic]") {
    auto mgr = make_temp_auth();
    auto raw = mgr->create_enrollment_token("revoke-me", 0, std::chrono::hours(1));
    auto tokens = mgr->list_enrollment_tokens();
    REQUIRE(tokens.size() == 1);
    REQUIRE(mgr->revoke_enrollment_token(tokens[0].token_id));

    auto claim = mgr->consume_enrollment_token(raw, "agent-X");
    REQUIRE_FALSE(claim.has_value());
    CHECK(claim.error() == EnrollmentTokenError::revoked);
}

TEST_CASE("consume_enrollment_token: expired variant", "[auth][enrollment][atomic]") {
    auto mgr = make_temp_auth();
    // Negative TTL == expired-on-creation. The implementation treats ttl==0
    // as "never expires" via time_point::max(); a 1-second TTL with a sleep
    // would race the test clock — so we cover expired via the revoked
    // branch above and rely on the implementation correctness here. To
    // assert the variant mapping we re-use the in-memory mutation pattern
    // by issuing a token with a 1-tick TTL and racing past it.
    auto raw = mgr->create_enrollment_token("expire", 0, std::chrono::seconds(1));
    std::this_thread::sleep_for(std::chrono::seconds(2));
    auto claim = mgr->consume_enrollment_token(raw, "agent-X");
    REQUIRE_FALSE(claim.has_value());
    CHECK(claim.error() == EnrollmentTokenError::expired);
}

TEST_CASE("consume_enrollment_token: already_consumed after exhaustion",
          "[auth][enrollment][atomic]") {
    auto mgr = make_temp_auth();
    auto raw = mgr->create_enrollment_token("once", 1, std::chrono::hours(1));

    // First call wins.
    auto first = mgr->consume_enrollment_token(raw, "agent-A");
    REQUIRE(first.has_value());
    CHECK(first->single_use);
    CHECK(first->use_count_after == 1);

    // Second call (after first has landed) sees already_consumed.
    auto second = mgr->consume_enrollment_token(raw, "agent-B");
    REQUIRE_FALSE(second.has_value());
    CHECK(second.error() == EnrollmentTokenError::already_consumed);

    // last_consumer_for_token_hash names the winner so the lost-race audit
    // detail in agent_service_impl can stamp `already_consumed_by=agent-A`.
    auto hash = AuthManager::sha256_hex(raw);
    CHECK(mgr->last_consumer_for_token_hash(hash) == "agent-A");
}

TEST_CASE("consume_enrollment_token: invalid_input on empty token", "[auth][enrollment][atomic]") {
    auto mgr = make_temp_auth();
    auto claim = mgr->consume_enrollment_token("", "agent-X");
    REQUIRE_FALSE(claim.has_value());
    CHECK(claim.error() == EnrollmentTokenError::invalid_input);
}

TEST_CASE("consume_enrollment_token: invalid_input on oversize token",
          "[auth][enrollment][atomic]") {
    auto mgr = make_temp_auth();
    // 257 chars — one byte over the kMaxEnrollmentTokenLength bound. The
    // defence-in-depth length check in consume_enrollment_token rejects
    // before SHA-256 runs, so it shouldn't matter whether a token of
    // matching shape was ever issued; we don't create one to make the
    // intent clear.
    std::string oversize(kMaxEnrollmentTokenLength + 1, 'A');
    auto claim = mgr->consume_enrollment_token(oversize, "agent-X");
    REQUIRE_FALSE(claim.has_value());
    CHECK(claim.error() == EnrollmentTokenError::invalid_input);
}

TEST_CASE("consume_enrollment_token: concurrent claim — exactly one winner",
          "[auth][enrollment][atomic][race]") {
    // The canonical #827 race-test. N threads try to consume the same
    // single-use enrollment token simultaneously. The pre-W1.4 behaviour
    // (validate-then-increment with the lock released between) allowed
    // multiple winners; the W1.4 atomic-claim guarantees exactly one.
    //
    // We don't use std::barrier here (not yet C++20-ubiquitous on the CI
    // matrix per the cross-compiler doc) — instead we follow the
    // ConcurrencyManager race-test pattern (#1031): spin up all threads
    // and let them race for the lock. With kThreads >> 1 the
    // contention is real even without an explicit synchronisation point.
    auto mgr = make_temp_auth();
    auto raw = mgr->create_enrollment_token("one-shot", 1, std::chrono::hours(1));

    constexpr int kThreads = 64;
    std::atomic<int> winners{0};
    std::atomic<int> race_losers{0};
    std::atomic<int> other_rejections{0};
    std::vector<std::thread> threads;
    threads.reserve(kThreads);

    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&, i] {
            std::string agent_id = "agent-" + std::to_string(i);
            auto result = mgr->consume_enrollment_token(raw, agent_id);
            if (result.has_value()) {
                winners.fetch_add(1, std::memory_order_relaxed);
            } else if (result.error() == EnrollmentTokenError::already_consumed) {
                race_losers.fetch_add(1, std::memory_order_relaxed);
            } else {
                other_rejections.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }
    for (auto& t : threads)
        t.join();

    // Exactly one thread won the race. Everyone else saw already_consumed.
    // No "other" variant should fire — the token exists, isn't revoked,
    // isn't expired; the only way to fail is to lose the race.
    CHECK(winners.load() == 1);
    CHECK(race_losers.load() == kThreads - 1);
    CHECK(other_rejections.load() == 0);

    // The store-side use_count matches the winner count.
    auto tokens = mgr->list_enrollment_tokens();
    REQUIRE(tokens.size() == 1);
    CHECK(tokens[0].use_count == 1);
    CHECK_FALSE(tokens[0].last_consumed_by_agent_id.empty());
}

TEST_CASE("consume_enrollment_token: concurrent claim on N-use token — exactly N winners",
          "[auth][enrollment][atomic][race]") {
    // Generalisation of the previous test. With max_uses == 3, exactly 3
    // threads win and the rest see already_consumed. This exercises the
    // `use_count >= max_uses` branch under contention rather than the
    // single-use special case.
    auto mgr = make_temp_auth();
    auto raw = mgr->create_enrollment_token("three-uses", 3, std::chrono::hours(1));

    constexpr int kThreads = 32;
    constexpr int kMaxUses = 3;
    std::atomic<int> winners{0};
    std::atomic<int> race_losers{0};
    std::vector<std::thread> threads;
    threads.reserve(kThreads);

    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&, i] {
            std::string agent_id = "agent-" + std::to_string(i);
            auto result = mgr->consume_enrollment_token(raw, agent_id);
            if (result.has_value()) {
                winners.fetch_add(1, std::memory_order_relaxed);
            } else if (result.error() == EnrollmentTokenError::already_consumed) {
                race_losers.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }
    for (auto& t : threads)
        t.join();

    CHECK(winners.load() == kMaxUses);
    CHECK(race_losers.load() == kThreads - kMaxUses);

    auto tokens = mgr->list_enrollment_tokens();
    REQUIRE(tokens.size() == 1);
    CHECK(tokens[0].use_count == kMaxUses);
}

TEST_CASE("validate_enrollment_token still works (legacy wrapper)", "[auth][enrollment][atomic]") {
    // The legacy bool API must keep working — pre-W1.4 callers (tests,
    // batch deployments) still call through this surface. It delegates to
    // consume_enrollment_token with an empty consuming_agent_id.
    auto mgr = make_temp_auth();
    auto raw = mgr->create_enrollment_token("legacy", 1, std::chrono::hours(1));

    CHECK(mgr->validate_enrollment_token(raw));
    CHECK_FALSE(mgr->validate_enrollment_token(raw));
}

// ── Pending Agents ───────────────────────────────────────────────────────────

TEST_CASE("pending agent lifecycle", "[auth][pending]") {
    auto mgr = make_temp_auth();
    mgr->add_pending_agent("agent-1", "host1", "linux", "x86_64", "0.1.0");

    auto status = mgr->get_pending_status("agent-1");
    REQUIRE(status.has_value());
    REQUIRE(*status == PendingStatus::pending);

    REQUIRE(mgr->approve_pending_agent("agent-1"));
    status = mgr->get_pending_status("agent-1");
    REQUIRE(status.has_value());
    REQUIRE(*status == PendingStatus::approved);
}

TEST_CASE("deny pending agent", "[auth][pending]") {
    auto mgr = make_temp_auth();
    mgr->add_pending_agent("agent-2", "host2", "windows", "x86_64", "0.1.0");

    REQUIRE(mgr->deny_pending_agent("agent-2"));
    auto status = mgr->get_pending_status("agent-2");
    REQUIRE(status.has_value());
    REQUIRE(*status == PendingStatus::denied);
}

TEST_CASE("remove pending agent", "[auth][pending]") {
    auto mgr = make_temp_auth();
    mgr->add_pending_agent("agent-3", "host3", "linux", "arm64", "0.1.0");
    REQUIRE(mgr->remove_pending_agent("agent-3"));
    REQUIRE_FALSE(mgr->get_pending_status("agent-3").has_value());
}

TEST_CASE("list_pending_agents", "[auth][pending]") {
    auto mgr = make_temp_auth();
    mgr->add_pending_agent("a1", "h1", "linux", "x86_64", "0.1.0");
    mgr->add_pending_agent("a2", "h2", "windows", "x86_64", "0.1.0");

    auto agents = mgr->list_pending_agents();
    REQUIRE(agents.size() == 2);
}

// ── Config Persistence ───────────────────────────────────────────────────────

TEST_CASE("save and reload config preserves users", "[auth][config]") {
    auto tmp = yuzu::test::unique_temp_path("yuzu-test-auth-roundtrip-");
    tmp += ".cfg";
    fs::create_directories(tmp.parent_path());
    fs::remove(tmp);

    {
        AuthManager mgr;
        mgr.load_config(tmp);
        mgr.upsert_user("alice", "password1pass", Role::admin);
        mgr.upsert_user("bob", "password2pass", Role::user);
        REQUIRE(mgr.save_config());
    }

    {
        AuthManager mgr;
        REQUIRE(mgr.load_config(tmp));
        auto users = mgr.list_users();
        REQUIRE(users.size() == 2);

        // Verify we can still authenticate
        REQUIRE(mgr.authenticate("alice", "password1pass").has_value());
        REQUIRE(mgr.authenticate("bob", "password2pass").has_value());
    }

    fs::remove(tmp);
}
