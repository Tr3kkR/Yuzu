/**
 * test_auth.cpp — Unit tests for yuzu::server::auth::AuthManager
 *
 * Covers: crypto primitives, password auth, sessions, user CRUD,
 *         enrollment tokens, pending agents, config persistence.
 */

#include <yuzu/server/auth.hpp>

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <memory>
#include <string>

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
