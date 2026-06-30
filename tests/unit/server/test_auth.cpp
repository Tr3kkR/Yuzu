/**
 * test_auth.cpp — Unit tests for yuzu::server::auth::AuthManager
 *
 * Covers: crypto primitives, password auth, sessions, user CRUD,
 *         enrollment tokens, pending agents, config persistence.
 */

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <filesystem>
#include <fstream>
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

// ── Idle (inactivity) session timeout — SOC 2 CC6.3 ──────────────────────────
// The window is a real steady_clock interval, so these use a short (1-2s)
// window + sleeps and are tagged [slow] (excludable with ~[slow]), matching the
// account-lockout expiry test.

TEST_CASE("idle timeout disabled by default: a session survives inactivity",
          "[auth][session][idle][slow]") {
    auto mgr = make_temp_auth();
    mgr->upsert_user("alice", "secret123456", Role::admin);
    auto token = mgr->authenticate("alice", "secret123456");
    REQUIRE(token.has_value());
    // session_inactivity_ defaults to 0 (disabled) — a pause does not
    // invalidate the session (only the absolute 8h lifetime applies).
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    CHECK(mgr->validate_session(*token).has_value());
}

TEST_CASE("idle timeout invalidates and evicts an inactive session",
          "[auth][session][idle][slow]") {
    auto mgr = make_temp_auth();
    mgr->set_session_inactivity(std::chrono::seconds(1));
    mgr->upsert_user("alice", "secret123456", Role::admin);
    auto token = mgr->authenticate("alice", "secret123456");
    REQUIRE(token.has_value());
    CHECK(mgr->validate_session(*token).has_value()); // active immediately

    // Idle past the 1s window (1.6s for calendar-second margin / runner I/O).
    std::this_thread::sleep_for(std::chrono::milliseconds(1600));
    CHECK_FALSE(mgr->validate_session(*token).has_value());
    // Evicted, not merely rejected — a replayed cookie cannot be re-touched
    // back to life; a second check is still nullopt.
    CHECK_FALSE(mgr->validate_session(*token).has_value());
}

TEST_CASE("idle timeout slides forward on activity (active session stays alive)",
          "[auth][session][idle][slow]") {
    auto mgr = make_temp_auth();
    mgr->set_session_inactivity(std::chrono::seconds(2));
    mgr->upsert_user("alice", "secret123456", Role::admin);
    auto token = mgr->authenticate("alice", "secret123456");
    REQUIRE(token.has_value());

    // Validate every 0.7s for ~3.5s total. Each touch is within the 2s window,
    // so the session lives well past the original 2s-from-creation mark — the
    // window slides on every authenticated request.
    for (int i = 0; i < 5; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(700));
        REQUIRE(mgr->validate_session(*token).has_value());
    }
    // Stop touching it; after > 2s idle it expires.
    std::this_thread::sleep_for(std::chrono::milliseconds(2400));
    CHECK_FALSE(mgr->validate_session(*token).has_value());
}

TEST_CASE("AuthDB::touch_session_activity is a best-effort mirror", "[auth][session][authdb]") {
    auto dir = yuzu::test::unique_temp_path("yuzu-touch-");
    fs::create_directories(dir);
    yuzu::server::AuthDB db(dir, /*cleanup_interval_secs=*/0); // no reaper thread
    REQUIRE(db.initialize().has_value());

    auto token = db.create_session("alice", Role::admin);
    REQUIRE(token.has_value());
    // Touching an existing row succeeds.
    CHECK(db.touch_session_activity(*token).has_value());
    // Best-effort: a no-match UPDATE is still success (the in-memory map is the
    // authoritative idle path; this durable mirror is fire-and-forget).
    CHECK(db.touch_session_activity("deadbeefdeadbeef").has_value());

    std::error_code ec;
    fs::remove_all(dir, ec);
}

TEST_CASE("invalidate_user_sessions wipes every session for a user (multi-token)",
          "[auth][session][invalidate_user_sessions]") {
    auto mgr = make_temp_auth();
    mgr->upsert_user("alice", "secret123456", Role::admin);
    mgr->upsert_user("bob", "secret123456", Role::user);

    // Three concurrent alice sessions (different browsers/devices)
    // and one bob session.
    auto a1 = mgr->authenticate("alice", "secret123456");
    auto a2 = mgr->authenticate("alice", "secret123456");
    auto a3 = mgr->authenticate("alice", "secret123456");
    auto b1 = mgr->authenticate("bob", "secret123456");
    REQUIRE(a1);
    REQUIRE(a2);
    REQUIRE(a3);
    REQUIRE(b1);

    auto result = mgr->invalidate_user_sessions("alice");
    // All three alice sessions wiped.
    REQUIRE(result.count == 3);
    // db_persisted is true when AuthDB is configured and the DELETE
    // succeeds; legacy config-file-only path also reports true.
    REQUIRE(result.db_persisted);

    // bob's session unaffected.
    REQUIRE(mgr->validate_session(*b1).has_value());
    // Every alice token rejected.
    REQUIRE_FALSE(mgr->validate_session(*a1).has_value());
    REQUIRE_FALSE(mgr->validate_session(*a2).has_value());
    REQUIRE_FALSE(mgr->validate_session(*a3).has_value());
}

TEST_CASE("invalidate_user_sessions returns 0 for unknown user",
          "[auth][session][invalidate_user_sessions]") {
    auto mgr = make_temp_auth();
    mgr->upsert_user("alice", "secret123456", Role::admin);
    auto a = mgr->authenticate("alice", "secret123456");
    REQUIRE(a);

    auto result = mgr->invalidate_user_sessions("ghost");
    REQUIRE(result.count == 0);
    REQUIRE(result.db_persisted);

    // Existing alice session still valid.
    REQUIRE(mgr->validate_session(*a).has_value());
}

TEST_CASE("invalidate_user_sessions is idempotent",
          "[auth][session][invalidate_user_sessions][idempotent]") {
    auto mgr = make_temp_auth();
    mgr->upsert_user("alice", "secret123456", Role::admin);
    auto a1 = mgr->authenticate("alice", "secret123456");
    REQUIRE(a1);

    auto first = mgr->invalidate_user_sessions("alice");
    REQUIRE(first.count == 1);

    auto second = mgr->invalidate_user_sessions("alice");
    REQUIRE(second.count == 0);
    REQUIRE(second.db_persisted);
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

TEST_CASE("max_uses enforcement via consume", "[auth][enrollment]") {
    // W1.4 R2 / UP-H2: validate_enrollment_token is now read-only and no
    // longer burns a use. Exhaustion still works — but it must be tested
    // through consume_enrollment_token, which is what the gRPC handlers
    // call. validate is the observability probe, not the consume path.
    auto mgr = make_temp_auth();
    auto raw = mgr->create_enrollment_token("once", 1, std::chrono::hours(1));

    auto first = mgr->consume_enrollment_token(raw, "agent-1");
    REQUIRE(first.has_value());
    auto second = mgr->consume_enrollment_token(raw, "agent-2");
    REQUIRE_FALSE(second.has_value());
    CHECK(second.error() == EnrollmentTokenError::already_consumed);
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

TEST_CASE("validate_enrollment_token is read-only — does NOT burn a use",
          "[auth][enrollment][atomic][r2-up-h2]") {
    // W1.4 R2 / UP-H2: the wrapper used to silently delegate to consume_,
    // so two consecutive validates on a max_uses=1 token would burn the
    // token. That was a semantic break with the function name. Restored
    // to true read-only — N validates leave use_count untouched, and the
    // subsequent consume still wins.
    auto mgr = make_temp_auth();
    auto raw = mgr->create_enrollment_token("readonly", 1, std::chrono::hours(1));

    // Five validates, no state change.
    for (int i = 0; i < 5; ++i) {
        CHECK(mgr->validate_enrollment_token(raw));
    }
    auto tokens = mgr->list_enrollment_tokens();
    REQUIRE(tokens.size() == 1);
    CHECK(tokens[0].use_count == 0);

    // Consume still wins because validates did not burn the use.
    auto claim = mgr->consume_enrollment_token(raw, "agent-1");
    REQUIRE(claim.has_value());
    CHECK(claim->use_count_after == 1);

    // After exhaustion, validate reports false (read-only check still
    // catches the exhausted state).
    CHECK_FALSE(mgr->validate_enrollment_token(raw));
}

TEST_CASE("validate_enrollment_token: revoked / expired / not-found return false",
          "[auth][enrollment][atomic][r2-up-h2]") {
    auto mgr = make_temp_auth();
    // not_found
    CHECK_FALSE(mgr->validate_enrollment_token("never-issued"));
    // empty / oversize (length-bound)
    CHECK_FALSE(mgr->validate_enrollment_token(""));
    std::string oversize(kMaxEnrollmentTokenLength + 1, 'A');
    CHECK_FALSE(mgr->validate_enrollment_token(oversize));
    // revoked
    auto raw = mgr->create_enrollment_token("to-revoke", 0, std::chrono::hours(1));
    CHECK(mgr->validate_enrollment_token(raw));
    auto tokens = mgr->list_enrollment_tokens();
    REQUIRE(tokens.size() == 1);
    REQUIRE(mgr->revoke_enrollment_token(tokens[0].token_id));
    CHECK_FALSE(mgr->validate_enrollment_token(raw));
}

TEST_CASE("consume_enrollment_token persists state to disk (UP-C1 crash-replay)",
          "[auth][enrollment][atomic][r2-up-c1]") {
    // W1.4 R2 / UP-C1: the PR1 implementation atomically claimed in
    // memory but did NOT persist the use_count change before returning.
    // A server SIGKILL between consume and any later save_tokens() call
    // (revoke, create, manager destruction) would leave on-disk
    // use_count=0 and let the token replay on the next boot.
    //
    // Test the crash by NOT cleanly destructing the first manager. We
    // instantiate manager A, create+consume a token, then construct a
    // brand-new manager B against the same cfg path. If save_tokens()
    // landed inside consume_, B's load_tokens() sees use_count=1 and
    // a subsequent consume on B fails with already_consumed.
    // The on-disk enrollment-tokens.cfg lives next to the user cfg
    // (state_dir() defaults to cfg parent). Other tests share
    // temp_directory_path(); to keep this test isolated we give it its
    // own unique subdirectory so the load_tokens() call in mgr_b only
    // sees the rows mgr_a wrote.
    auto dir = yuzu::test::unique_temp_path("yuzu-test-auth-crashreplay-");
    fs::create_directories(dir);
    auto cfg = dir / "users.cfg";

    // load_config short-circuits if the users cfg file is missing — but the
    // enrollment-tokens.cfg load lives in load_tokens(), which is called
    // unconditionally after the user-load loop. Touch an empty cfg so
    // load_config follows through to load_tokens() in both phases.
    { std::ofstream(cfg) << "# Version: 1\n"; }

    std::string raw;
    {
        AuthManager mgr_a;
        mgr_a.load_config(cfg);
        raw = mgr_a.create_enrollment_token("crash-replay", 1, std::chrono::hours(1));
        auto claim = mgr_a.consume_enrollment_token(raw, "agent-pre-crash");
        REQUIRE(claim.has_value());
        // SIMULATE CRASH: drop mgr_a without an explicit save call.
        // The save inside consume_ is what we're proving works.
    }

    // Fresh manager rebuilds in-memory state from disk only.
    AuthManager mgr_b;
    mgr_b.load_config(cfg);
    auto tokens = mgr_b.list_enrollment_tokens();
    REQUIRE(tokens.size() == 1);
    CHECK(tokens[0].use_count == 1);

    // Replay attempt fails on the fresh instance — token is exhausted.
    auto replay = mgr_b.consume_enrollment_token(raw, "agent-post-crash");
    REQUIRE_FALSE(replay.has_value());
    CHECK(replay.error() == EnrollmentTokenError::already_consumed);

    // Cleanup
    std::error_code ec;
    fs::remove_all(dir, ec);
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
