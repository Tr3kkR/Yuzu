/**
 * test_device_token_store.cpp — Unit tests for DeviceTokenStore
 *
 * Covers: create, validate, revoke, list, expiration, scoping,
 * and last_used_at tracking.
 */

#include "device_token_store.hpp"
#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <set>
#include <string>

using namespace yuzu::server;

namespace {

// Adopts the shared TempDbFile RAII to dodge flake #473 — the previous
// fixed-name temp path collided under parallel Catch2 runs (also see CLAUDE.md
// "Test conventions — shared helpers").
struct TempDb {
    yuzu::test::TempDbFile file{std::string_view{"test_device_tokens-"}};
    const std::filesystem::path& path = file.path;
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

    // Any-device token (device_id="") accepts any presenter — empty presenter
    // works for the round-trip case.
    auto validated = store.validate_token(*result, "");
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

    auto validated = store.validate_token("ydt_this_is_not_a_valid_token_abcdef0123456789", "");
    REQUIRE(!validated.has_value());
    CHECK(validated.error() == DeviceTokenValidateError::not_found);
}

TEST_CASE("DeviceTokenStore: empty token rejected", "[device_token][auth]") {
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    auto validated = store.validate_token("", "");
    REQUIRE(!validated.has_value());
    CHECK(validated.error() == DeviceTokenValidateError::invalid_input);
}

TEST_CASE("DeviceTokenStore: expired token rejected", "[device_token][auth]") {
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    // Create token that already expired (expires_at = 1 second since epoch)
    auto result = store.create_token("Expired Token", "admin", "", "", 1);
    REQUIRE(result.has_value());

    auto validated = store.validate_token(*result, "");
    REQUIRE(!validated.has_value());
    CHECK(validated.error() == DeviceTokenValidateError::expired);
}

TEST_CASE("DeviceTokenStore: revoked token rejected", "[device_token][auth]") {
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    auto raw = store.create_token("Revocable", "admin", "", "", 0);
    REQUIRE(raw.has_value());

    // Validate before revocation
    auto valid1 = store.validate_token(*raw, "");
    REQUIRE(valid1.has_value());

    // Revoke by token_id
    bool revoked = store.revoke_token(valid1->token_id);
    CHECK(revoked);

    // Validate after revocation should fail
    auto valid2 = store.validate_token(*raw, "");
    REQUIRE(!valid2.has_value());
    CHECK(valid2.error() == DeviceTokenValidateError::revoked);
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
    auto validated = store.validate_token(*raw, "");
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

    // Bound to device-42 — must present matching agent_id.
    auto validated = store.validate_token(*result, "device-42");
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

    // device_id is empty -> any-device token, presenter can be empty.
    auto validated = store.validate_token(*result, "");
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

    auto validated = store.validate_token(*result, "device-99");
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

    auto validated = store.validate_token(*result, "");
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

    auto validated = store.validate_token(*result, "");
    REQUIRE(validated.has_value());
    CHECK(validated->expires_at == future);
}

// ============================================================================
// Binding enforcement (#824) — token presenter MUST equal token subject
// ============================================================================

TEST_CASE("DeviceTokenStore: device-bound token accepted from matching presenter",
          "[device_token][binding]") {
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    auto raw = store.create_token("Bound", "admin", "device-A", "", 0);
    REQUIRE(raw.has_value());

    auto ok = store.validate_token(*raw, "device-A");
    REQUIRE(ok.has_value());
    CHECK(ok->device_id == "device-A");
}

TEST_CASE("DeviceTokenStore: device-bound token rejected from different presenter",
          "[device_token][binding]") {
    // Core #824 case: token issued for device A is presented by device B.
    // The hash matches and the row is found, but binding enforcement must
    // reject with the typed binding_mismatch error so the handler can emit
    // the right audit row.
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    auto raw = store.create_token("Bound", "admin", "device-A", "", 0);
    REQUIRE(raw.has_value());

    auto bad = store.validate_token(*raw, "device-B");
    REQUIRE(!bad.has_value());
    CHECK(bad.error() == DeviceTokenValidateError::binding_mismatch);
}

TEST_CASE("DeviceTokenStore: device-bound token rejected when presenter empty",
          "[device_token][binding]") {
    // Empty presenter on a bound token is also a mismatch — passing "" is
    // not a back-door to skip the check. Callers that genuinely have no
    // agent identity (early bootstrap) should only ever encounter any-device
    // tokens (device_id="").
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    auto raw = store.create_token("Bound", "admin", "device-A", "", 0);
    REQUIRE(raw.has_value());

    auto bad = store.validate_token(*raw, "");
    REQUIRE(!bad.has_value());
    CHECK(bad.error() == DeviceTokenValidateError::binding_mismatch);
}

TEST_CASE("DeviceTokenStore: any-device token (device_id empty) accepts any presenter",
          "[device_token][binding]") {
    // Org-wide / bootstrap any-device tokens (device_id="") accept any
    // presenter. These are an org policy choice — the binding check still
    // structurally cannot fail because there is no subject to bind to. The
    // caller still owns the outer principal check.
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    auto raw = store.create_token("AnyDevice", "admin", "", "", 0);
    REQUIRE(raw.has_value());

    auto a = store.validate_token(*raw, "device-A");
    REQUIRE(a.has_value());
    auto b = store.validate_token(*raw, "device-B");
    REQUIRE(b.has_value());
    auto e = store.validate_token(*raw, "");
    REQUIRE(e.has_value());
}

TEST_CASE("DeviceTokenStore: binding_mismatch precedes neither expired nor revoked",
          "[device_token][binding]") {
    // Ordering invariant: not_found / revoked / expired are checked before
    // binding_mismatch because (a) revoked/expired tokens MUST always be
    // rejected even if the right presenter shows up, and (b) returning
    // binding_mismatch for a revoked token would leak that the hash exists.
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    // Expired token bound to device-A
    auto raw = store.create_token("ExpiredBound", "admin", "device-A", "", 1);
    REQUIRE(raw.has_value());

    // Even with the right presenter, expired wins
    auto exp_ok = store.validate_token(*raw, "device-A");
    REQUIRE(!exp_ok.has_value());
    CHECK(exp_ok.error() == DeviceTokenValidateError::expired);
    auto exp_bad = store.validate_token(*raw, "device-B");
    REQUIRE(!exp_bad.has_value());
    CHECK(exp_bad.error() == DeviceTokenValidateError::expired);
}

// ============================================================================
// CSPRNG contract (#801) — replaces std::mt19937_64 with OpenSSL/BCrypt CSPRNG
// ============================================================================

TEST_CASE("DeviceTokenStore: consecutive tokens differ", "[device_token][csprng]") {
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    auto a = store.create_token("A", "admin", "", "", 0);
    auto b = store.create_token("B", "admin", "", "", 0);
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    CHECK(*a != *b);
}

TEST_CASE("DeviceTokenStore: 256 consecutive tokens are all unique", "[device_token][csprng]") {
    // 256 bits of entropy per token; the chance of a real-world collision in
    // any feasible sample is negligible. Any duplicate here is a CSPRNG
    // correctness failure (e.g. mt19937 regression).
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    std::set<std::string> seen;
    for (int i = 0; i < 256; ++i) {
        auto r = store.create_token("bulk", "admin", "", "", 0);
        REQUIRE(r.has_value());
        CHECK(seen.insert(*r).second);
    }
    CHECK(seen.size() == 256);
}

TEST_CASE("DeviceTokenStore: token shape — 'ydt_' + 64 lowercase hex chars",
          "[device_token][csprng][format]") {
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    auto r = store.create_token("Shape", "admin", "", "", 0);
    REQUIRE(r.has_value());
    REQUIRE(r->size() == 68);
    CHECK(r->starts_with("ydt_"));
    for (std::size_t i = 4; i < r->size(); ++i) {
        char c = (*r)[i];
        CHECK(((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')));
    }
}
