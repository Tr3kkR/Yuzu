/**
 * test_device_token_store.cpp — Unit tests for DeviceTokenStore
 *
 * Covers: create, validate, revoke, list, expiration, scoping,
 * and last_used_at tracking.
 */

#include "device_token_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <string>

using namespace yuzu::server;

namespace {

struct TempDb {
    std::filesystem::path path;
    TempDb() : path(std::filesystem::temp_directory_path() / "test_device_tokens.db") {
        std::filesystem::remove(path);
    }
    ~TempDb() { std::filesystem::remove(path); }
};

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

} // namespace

// ============================================================================
// Create and Validate
// ============================================================================

TEST_CASE("DeviceTokenStore: create and validate round-trip", "[device_token][crud]") {
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    auto result = store.create_token("Test Token", "admin", "", "", 0);
    REQUIRE(result.has_value());

    auto validated = store.validate_token(*result);
    REQUIRE(validated.has_value());
    CHECK(validated->name == "Test Token");
    CHECK(validated->principal_id == "admin");
    CHECK(validated->created_at > 0);
    CHECK(!validated->revoked);
}

TEST_CASE("DeviceTokenStore: token starts with ydt_ prefix", "[device_token][format]") {
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    auto result = store.create_token("Prefixed Token", "admin", "", "", 0);
    REQUIRE(result.has_value());
    CHECK(result->starts_with("ydt_"));
    CHECK(result->size() == 68); // "ydt_" (4) + 64 hex chars
}

TEST_CASE("DeviceTokenStore: invalid token rejected", "[device_token][auth]") {
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    auto validated = store.validate_token("ydt_this_is_not_a_valid_token_abcdef0123456789");
    CHECK(!validated.has_value());
}

TEST_CASE("DeviceTokenStore: empty token rejected", "[device_token][auth]") {
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    auto validated = store.validate_token("");
    CHECK(!validated.has_value());
}

TEST_CASE("DeviceTokenStore: expired token rejected", "[device_token][auth]") {
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    // Create token that already expired (expires_at = 1 second since epoch)
    auto result = store.create_token("Expired Token", "admin", "", "", 1);
    REQUIRE(result.has_value());

    auto validated = store.validate_token(*result);
    CHECK(!validated.has_value());
}

TEST_CASE("DeviceTokenStore: revoked token rejected", "[device_token][auth]") {
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    auto raw = store.create_token("Revocable", "admin", "", "", 0);
    REQUIRE(raw.has_value());

    // Validate before revocation
    auto valid1 = store.validate_token(*raw);
    REQUIRE(valid1.has_value());

    // Revoke by token_id
    bool revoked = store.revoke_token(valid1->token_id);
    CHECK(revoked);

    // Validate after revocation should fail
    auto valid2 = store.validate_token(*raw);
    CHECK(!valid2.has_value());
}

// ============================================================================
// List
// ============================================================================

TEST_CASE("DeviceTokenStore: list tokens", "[device_token][crud]") {
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    store.create_token("Token A", "alice", "", "", 0);
    store.create_token("Token B", "alice", "", "", 0);
    store.create_token("Token C", "bob", "", "", 0);

    auto all = store.list_tokens();
    CHECK(all.size() == 3);
}

TEST_CASE("DeviceTokenStore: list tokens with principal_id filter", "[device_token][crud]") {
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    store.create_token("Token A", "alice", "", "", 0);
    store.create_token("Token B", "alice", "", "", 0);
    store.create_token("Token C", "bob", "", "", 0);

    auto alice_tokens = store.list_tokens("alice");
    CHECK(alice_tokens.size() == 2);
    for (const auto& t : alice_tokens)
        CHECK(t.principal_id == "alice");

    auto bob_tokens = store.list_tokens("bob");
    CHECK(bob_tokens.size() == 1);
    CHECK(bob_tokens[0].principal_id == "bob");
}

// ============================================================================
// Revoke edge cases
// ============================================================================

TEST_CASE("DeviceTokenStore: revoke non-existent returns false", "[device_token][crud]") {
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    bool revoked = store.revoke_token("nonexistent-token-id");
    CHECK(!revoked);
}

// ============================================================================
// Validate updates last_used_at
// ============================================================================

TEST_CASE("DeviceTokenStore: validate updates last_used_at", "[device_token][auth]") {
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    auto raw = store.create_token("Usage Token", "admin", "", "", 0);
    REQUIRE(raw.has_value());

    // Before validation, last_used_at should be 0
    auto before = store.list_tokens();
    REQUIRE(before.size() == 1);
    CHECK(before[0].last_used_at == 0);

    // Validate the token (triggers last_used_at update)
    auto validated = store.validate_token(*raw);
    REQUIRE(validated.has_value());

    // After validation, last_used_at should be updated
    auto after = store.list_tokens();
    REQUIRE(after.size() == 1);
    CHECK(after[0].last_used_at > 0);
}

// ============================================================================
// Scope fields
// ============================================================================

TEST_CASE("DeviceTokenStore: device scope stored correctly", "[device_token][scope]") {
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    auto result = store.create_token("Scoped Token", "admin", "device-42", "", 0);
    REQUIRE(result.has_value());

    auto validated = store.validate_token(*result);
    REQUIRE(validated.has_value());
    CHECK(validated->device_id == "device-42");
    CHECK(validated->definition_id.empty());
}

TEST_CASE("DeviceTokenStore: definition scope stored correctly", "[device_token][scope]") {
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    auto result = store.create_token("Def Scoped Token", "admin", "", "get-os-info", 0);
    REQUIRE(result.has_value());

    auto validated = store.validate_token(*result);
    REQUIRE(validated.has_value());
    CHECK(validated->device_id.empty());
    CHECK(validated->definition_id == "get-os-info");
}

TEST_CASE("DeviceTokenStore: both scopes stored correctly", "[device_token][scope]") {
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    auto result =
        store.create_token("Dual Scoped Token", "admin", "device-99", "restart-service", 0);
    REQUIRE(result.has_value());

    auto validated = store.validate_token(*result);
    REQUIRE(validated.has_value());
    CHECK(validated->device_id == "device-99");
    CHECK(validated->definition_id == "restart-service");
}

// ============================================================================
// Expiration edge cases
// ============================================================================

TEST_CASE("DeviceTokenStore: non-expiring token (expires_at=0) is valid", "[device_token][auth]") {
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    auto result = store.create_token("Perpetual Token", "admin", "", "", 0);
    REQUIRE(result.has_value());

    auto validated = store.validate_token(*result);
    REQUIRE(validated.has_value());
    CHECK(validated->expires_at == 0);
}

TEST_CASE("DeviceTokenStore: future expiry token is valid", "[device_token][auth]") {
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    auto future = now_epoch() + 86400 * 365; // 1 year from now
    auto result = store.create_token("Future Token", "admin", "", "", future);
    REQUIRE(result.has_value());

    auto validated = store.validate_token(*result);
    REQUIRE(validated.has_value());
    CHECK(validated->expires_at == future);
}
