/**
 * test_api_token_store.cpp — Unit tests for API token authentication store
 */

#include "api_token_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <string>
#include <thread>

using namespace yuzu::server;

namespace {

// Per-instance unique path so tests are safe to run under parallel
// meson test --num-processes N. The prior hardcoded path collided
// between concurrent test cases.
struct TempDb {
    std::filesystem::path path;
    TempDb()
        : path(std::filesystem::temp_directory_path() /
               ("test_api_tokens-" +
                std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id()) ^
                               static_cast<size_t>(std::chrono::steady_clock::now()
                                                       .time_since_epoch()
                                                       .count())) +
                ".db")) {
        std::filesystem::remove(path);
    }
    ~TempDb() { std::filesystem::remove(path); }
};

} // namespace

TEST_CASE("ApiTokenStore: create and validate token", "[token][crud]") {
    TempDb tmp;
    ApiTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    auto result = store.create_token("Test Token", "admin");
    REQUIRE(result.has_value());
    CHECK(result->starts_with("yuzu_"));
    CHECK(result->size() == 37); // "yuzu_" + 32 chars

    auto validated = store.validate_token(*result);
    REQUIRE(validated.has_value());
    CHECK(validated->name == "Test Token");
    CHECK(validated->principal_id == "admin");
    CHECK(validated->created_at > 0);
}

TEST_CASE("ApiTokenStore: invalid token rejected", "[token][auth]") {
    TempDb tmp;
    ApiTokenStore store(tmp.path);

    auto validated = store.validate_token("yuzu_invalid_token_123456789012");
    CHECK(!validated.has_value());
}

TEST_CASE("ApiTokenStore: empty token rejected", "[token][auth]") {
    TempDb tmp;
    ApiTokenStore store(tmp.path);

    auto validated = store.validate_token("");
    CHECK(!validated.has_value());
}

TEST_CASE("ApiTokenStore: revoked token rejected", "[token][auth]") {
    TempDb tmp;
    ApiTokenStore store(tmp.path);

    auto raw = store.create_token("Revocable", "admin");
    REQUIRE(raw.has_value());

    // Validate before revocation
    auto valid1 = store.validate_token(*raw);
    REQUIRE(valid1.has_value());

    // Revoke
    bool revoked = store.revoke_token(valid1->token_id);
    CHECK(revoked);

    // Validate after revocation
    auto valid2 = store.validate_token(*raw);
    CHECK(!valid2.has_value());
}

TEST_CASE("ApiTokenStore: expired token rejected", "[token][auth]") {
    TempDb tmp;
    ApiTokenStore store(tmp.path);

    // Create token that expired 1 second ago
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    auto raw = store.create_token("Expired", "admin", now - 1);
    REQUIRE(raw.has_value());

    auto validated = store.validate_token(*raw);
    CHECK(!validated.has_value());
}

TEST_CASE("ApiTokenStore: list tokens", "[token][crud]") {
    TempDb tmp;
    ApiTokenStore store(tmp.path);

    store.create_token("Token A", "alice");
    store.create_token("Token B", "alice");
    store.create_token("Token C", "bob");

    auto all = store.list_tokens();
    CHECK(all.size() == 3);

    auto alice_tokens = store.list_tokens("alice");
    CHECK(alice_tokens.size() == 2);

    auto bob_tokens = store.list_tokens("bob");
    CHECK(bob_tokens.size() == 1);

    // Token hashes should never be exposed in listings
    for (const auto& t : all)
        CHECK(t.token_hash.empty());
}

TEST_CASE("ApiTokenStore: delete token", "[token][crud]") {
    TempDb tmp;
    ApiTokenStore store(tmp.path);

    auto raw = store.create_token("Deletable", "admin");
    REQUIRE(raw.has_value());

    auto valid = store.validate_token(*raw);
    REQUIRE(valid.has_value());

    bool deleted = store.delete_token(valid->token_id);
    CHECK(deleted);

    auto after = store.validate_token(*raw);
    CHECK(!after.has_value());

    auto list = store.list_tokens();
    CHECK(list.empty());
}

TEST_CASE("ApiTokenStore: last_used_at updated on validation", "[token][auth]") {
    TempDb tmp;
    ApiTokenStore store(tmp.path);

    auto raw = store.create_token("Usage", "admin");
    REQUIRE(raw.has_value());

    auto before = store.list_tokens();
    REQUIRE(before.size() == 1);
    CHECK(before[0].last_used_at == 0);

    store.validate_token(*raw);

    auto after = store.list_tokens();
    REQUIRE(after.size() == 1);
    CHECK(after[0].last_used_at > 0);
}

TEST_CASE("ApiTokenStore: empty name rejected", "[token][crud]") {
    TempDb tmp;
    ApiTokenStore store(tmp.path);

    auto result = store.create_token("", "admin");
    CHECK(!result.has_value());
}

TEST_CASE("ApiTokenStore: revoke nonexistent token", "[token][crud]") {
    TempDb tmp;
    ApiTokenStore store(tmp.path);

    bool revoked = store.revoke_token("nonexistent");
    CHECK(!revoked);
}

// ── get_token: metadata lookup for owner-scoped revoke (#222) ────────────────

TEST_CASE("ApiTokenStore: get_token returns metadata for ownership check",
          "[token][crud][owner]") {
    TempDb tmp;
    ApiTokenStore store(tmp.path);

    auto raw = store.create_token("Alice's token", "alice");
    REQUIRE(raw.has_value());
    auto listing = store.list_tokens("alice");
    REQUIRE(listing.size() == 1);
    auto token_id = listing[0].token_id;

    auto looked_up = store.get_token(token_id);
    REQUIRE(looked_up.has_value());
    CHECK(looked_up->token_id == token_id);
    CHECK(looked_up->principal_id == "alice");
    CHECK(looked_up->name == "Alice's token");
    CHECK(looked_up->revoked == false);
    // The raw hash must never surface through metadata lookups.
    CHECK(looked_up->token_hash.empty());
}

TEST_CASE("ApiTokenStore: get_token returns nullopt for unknown id",
          "[token][crud][owner]") {
    TempDb tmp;
    ApiTokenStore store(tmp.path);

    CHECK(!store.get_token("does-not-exist").has_value());
    CHECK(!store.get_token("").has_value());
}

TEST_CASE("ApiTokenStore: get_token distinguishes owners for IDOR defense",
          "[token][crud][owner]") {
    // This test encodes the core invariant that the REST DELETE handler
    // relies on to close #222: looking up a token by id must surface the
    // owning principal_id so the handler can reject cross-user revokes.
    TempDb tmp;
    ApiTokenStore store(tmp.path);

    REQUIRE(store.create_token("alice-key", "alice").has_value());
    REQUIRE(store.create_token("bob-key", "bob").has_value());

    auto alice_tokens = store.list_tokens("alice");
    auto bob_tokens = store.list_tokens("bob");
    REQUIRE(alice_tokens.size() == 1);
    REQUIRE(bob_tokens.size() == 1);

    auto alice_looked_up = store.get_token(alice_tokens[0].token_id);
    auto bob_looked_up = store.get_token(bob_tokens[0].token_id);
    REQUIRE(alice_looked_up.has_value());
    REQUIRE(bob_looked_up.has_value());
    CHECK(alice_looked_up->principal_id == "alice");
    CHECK(bob_looked_up->principal_id == "bob");
    CHECK(alice_looked_up->principal_id != bob_looked_up->principal_id);
}
