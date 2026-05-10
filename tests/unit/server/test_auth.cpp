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

// These two probes exercise the AuthManager + AuthDB integration path, which
// had zero existing coverage. Filed alongside #947 — they confirm that the
// authenticate() → validate_session() round-trip survives a server restart
// against a populated data dir and a regenerated config file. If the #947
// regression ever reappears at the unit level, one of these will fail first.

TEST_CASE("authenticate+validate with AuthDB attached, clean dir",
          "[auth][session][regression-947]") {
    auto data_dir = yuzu::test::unique_temp_path("yuzu-947-clean-");
    fs::create_directories(data_dir);

    auto auth_db = std::make_unique<yuzu::server::AuthDB>(data_dir);
    auto db_init = auth_db->initialize();
    REQUIRE(db_init.has_value());

    auto cfg = data_dir / "yuzu-server.cfg";
    AuthManager mgr;
    mgr.load_config(cfg);
    mgr.set_data_dir(data_dir);

    REQUIRE(mgr.upsert_user("alice", "secret123456", Role::admin));
    auto seed = auth_db->upsert_user("alice", mgr.list_users().front().hash_hex,
                                     mgr.list_users().front().salt_hex, Role::admin);
    REQUIRE(seed.has_value());

    mgr.set_auth_db(auth_db.get());

    auto token = mgr.authenticate("alice", "secret123456");
    REQUIRE(token.has_value());

    auto session = mgr.validate_session(*token);
    REQUIRE(session.has_value());
    REQUIRE(session->username == "alice");
}

TEST_CASE("authenticate+validate with AuthDB attached, stale dir (restart)",
          "[auth][session][regression-947]") {
    auto data_dir = yuzu::test::unique_temp_path("yuzu-947-stale-");
    fs::create_directories(data_dir);
    auto cfg = data_dir / "yuzu-server.cfg";

    // ── Run 1: populate auth.db + cfg, authenticate once, abandon. ─────
    {
        auto auth_db = std::make_unique<yuzu::server::AuthDB>(data_dir);
        REQUIRE(auth_db->initialize().has_value());

        AuthManager mgr1;
        mgr1.load_config(cfg);
        mgr1.set_data_dir(data_dir);
        REQUIRE(mgr1.upsert_user("alice", "secret123456", Role::admin));
        auto entry = mgr1.list_users().front();
        REQUIRE(
            auth_db->upsert_user("alice", entry.hash_hex, entry.salt_hex, Role::admin).has_value());
        mgr1.set_auth_db(auth_db.get());

        auto first = mgr1.authenticate("alice", "secret123456");
        REQUIRE(first.has_value());
        // session lives in mgr1.sessions_ only; it dies with mgr1.
    }

    // ── Run 2: same data_dir (stale auth.db survives), but the cfg gets
    // regenerated with a FRESH PBKDF2 salt — exactly what the UAT does
    // on each invocation. The OLD hash/salt remains in auth.db. ────────
    {
        fs::remove(cfg); // regenerate cfg from scratch

        auto auth_db = std::make_unique<yuzu::server::AuthDB>(data_dir);
        REQUIRE(auth_db->initialize().has_value());

        AuthManager mgr2;
        mgr2.load_config(cfg);
        mgr2.set_data_dir(data_dir);
        // Fresh upsert → new salt, new hash. cfg now disagrees with auth.db.
        REQUIRE(mgr2.upsert_user("alice", "secret123456", Role::admin));
        // Note: we do NOT re-seed auth.db here. main.cpp's seed path only
        // fires when auth.db is empty (`users_result->empty()`), so on
        // stale dirs the old DB row survives untouched.
        mgr2.set_auth_db(auth_db.get());

        auto token = mgr2.authenticate("alice", "secret123456");
        REQUIRE(token.has_value()); // step 2: login OK
        auto session = mgr2.validate_session(*token);
        REQUIRE(session.has_value()); // step 3: BUG claim is this fails
        REQUIRE(session->username == "alice");
    }
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
