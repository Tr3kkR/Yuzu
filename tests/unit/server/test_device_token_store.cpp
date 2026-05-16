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

    auto result = store.create_token("Test Token", "admin", "device-RT", "", 0);
    REQUIRE(result.has_value());

    // Round-trip requires an explicitly bound token now that any-device
    // tokens (empty device_id) are rejected as unbound_legacy (W1.2 R2).
    auto validated = store.validate_token(*result, "device-RT");
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
    CHECK(validated.error().error == DeviceTokenValidateError::not_found);
    // not_found row has no context — token_id / bound_* must be empty
    // so the audit row can't leak that the hash matched anything.
    CHECK(validated.error().token_id.empty());
    CHECK(validated.error().bound_device_id.empty());
    CHECK(validated.error().bound_principal_id.empty());
}

TEST_CASE("DeviceTokenStore: empty token rejected", "[device_token][auth]") {
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    auto validated = store.validate_token("", "");
    REQUIRE(!validated.has_value());
    CHECK(validated.error().error == DeviceTokenValidateError::invalid_input);
    CHECK(validated.error().token_id.empty());
}

TEST_CASE("DeviceTokenStore: expired token rejected", "[device_token][auth]") {
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    // Create token that already expired (expires_at = 1 second since epoch).
    // Bound to a real device so the failure mode is purely "expired" and not
    // unbound_legacy (which must precede binding but follow expired).
    auto result = store.create_token("Expired Token", "admin", "device-X", "", 1);
    REQUIRE(result.has_value());

    auto validated = store.validate_token(*result, "device-X");
    REQUIRE(!validated.has_value());
    CHECK(validated.error().error == DeviceTokenValidateError::expired);
    // #1053: rich-rejection context — `expired` populates bound_device_id +
    // bound_principal_id so the audit row can record what was being attempted
    // without a second SELECT.
    CHECK(!validated.error().token_id.empty());
    CHECK(validated.error().bound_device_id == "device-X");
    CHECK(validated.error().bound_principal_id == "admin");
}

TEST_CASE("DeviceTokenStore: revoked token rejected", "[device_token][auth]") {
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    auto raw = store.create_token("Revocable", "admin", "device-R", "", 0);
    REQUIRE(raw.has_value());

    // Validate before revocation
    auto valid1 = store.validate_token(*raw, "device-R");
    REQUIRE(valid1.has_value());

    // Revoke by token_id
    bool revoked = store.revoke_token(valid1->token_id);
    CHECK(revoked);

    // Validate after revocation should fail
    auto valid2 = store.validate_token(*raw, "device-R");
    REQUIRE(!valid2.has_value());
    CHECK(valid2.error().error == DeviceTokenValidateError::revoked);
    // #1053: revoked also carries full bound context — auditor needs to
    // see WHICH token was being replayed-after-revoke.
    CHECK(valid2.error().bound_device_id == "device-R");
    CHECK(valid2.error().bound_principal_id == "admin");
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

    auto raw = store.create_token("Usage Token", "admin", "device-U", "", 0);
    REQUIRE(raw.has_value());

    // Before validation, last_used_at should be 0
    auto before = store.list_tokens();
    REQUIRE(before.size() == 1);
    CHECK(before[0].last_used_at == 0);

    // Validate the token (triggers last_used_at update)
    auto validated = store.validate_token(*raw, "device-U");
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

    // Bind to a device so we can validate; the assertion is that definition
    // scope is recorded independently of device scope. (Pre-W1.2-R2 this used
    // an empty device_id, which is now rejected as unbound_legacy.)
    auto result = store.create_token("Def Scoped Token", "admin", "device-D", "get-os-info", 0);
    REQUIRE(result.has_value());

    auto validated = store.validate_token(*result, "device-D");
    REQUIRE(validated.has_value());
    CHECK(validated->device_id == "device-D");
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

    auto result = store.create_token("Perpetual Token", "admin", "device-P", "", 0);
    REQUIRE(result.has_value());

    auto validated = store.validate_token(*result, "device-P");
    REQUIRE(validated.has_value());
    CHECK(validated->expires_at == 0);
}

TEST_CASE("DeviceTokenStore: future expiry token is valid", "[device_token][auth]") {
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    auto future = now_epoch() + 86400 * 365; // 1 year from now
    auto result = store.create_token("Future Token", "admin", "device-F", "", future);
    REQUIRE(result.has_value());

    auto validated = store.validate_token(*result, "device-F");
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
    CHECK(bad.error().error == DeviceTokenValidateError::binding_mismatch);
    // #1053: binding_mismatch is THE high-signal rejection — `bound_device_id`
    // + `bound_principal_id` must be set so the audit row can record
    // "presenter=device-B bound=device-A bound_principal=admin" without
    // a second SELECT (which would create a timing oracle).
    CHECK(bad.error().bound_device_id == "device-A");
    CHECK(bad.error().bound_principal_id == "admin");
    CHECK(!bad.error().token_id.empty());
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
    CHECK(bad.error().error == DeviceTokenValidateError::binding_mismatch);
    CHECK(bad.error().bound_device_id == "device-A");
    CHECK(bad.error().bound_principal_id == "admin");
}

TEST_CASE(
    "DeviceTokenStore: validate_token rejects unbound legacy token with unbound_legacy variant",
    "[device_token][binding]") {
    // W1.2 R2 HIGH-1/HIGH-2: a token created with empty device_id (the
    // pre-#824 default) is a back-door — the old `if (!device_id.empty() && ...)`
    // would short-circuit and accept any presenter. The new contract refuses
    // to validate such rows loudly with unbound_legacy, regardless of presenter.
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    auto raw = store.create_token("LegacyAny", "admin", "", "", 0);
    REQUIRE(raw.has_value());

    // Empty presenter — historical caller pattern.
    auto e = store.validate_token(*raw, "");
    REQUIRE(!e.has_value());
    CHECK(e.error().error == DeviceTokenValidateError::unbound_legacy);
    // #1053: unbound_legacy explicitly leaves bound_device_id empty (the
    // row literally has no binding — propagating "" would mislead the
    // auditor). bound_principal_id IS propagated so the operator can find
    // which admin issued the legacy token and rotate it.
    CHECK(e.error().bound_device_id.empty());
    CHECK(e.error().bound_principal_id == "admin");
    CHECK(!e.error().token_id.empty());

    // Any non-empty presenter is equally rejected — confirms the
    // empty-comparison short-circuit is closed.
    auto a = store.validate_token(*raw, "device-A");
    REQUIRE(!a.has_value());
    CHECK(a.error().error == DeviceTokenValidateError::unbound_legacy);

    auto b = store.validate_token(*raw, "device-B");
    REQUIRE(!b.has_value());
    CHECK(b.error().error == DeviceTokenValidateError::unbound_legacy);
}

TEST_CASE("DeviceTokenStore: validate_token unbound_legacy precedes binding_mismatch and follows "
          "expired",
          "[device_token][binding]") {
    // Ordering invariant: not_found → revoked → expired → unbound_legacy →
    // binding_mismatch. unbound_legacy comes AFTER expired (so an expired
    // legacy token reports expired, not unbound_legacy) and BEFORE
    // binding_mismatch (so an unbound row never reaches the binding check
    // and thus can never accidentally pass via the empty-comparison
    // short-circuit).
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    // (a) expired beats unbound_legacy: expired token with empty device_id
    auto expired_raw = store.create_token("ExpiredLegacy", "admin", "", "", 1);
    REQUIRE(expired_raw.has_value());
    auto exp = store.validate_token(*expired_raw, "anything");
    REQUIRE(!exp.has_value());
    CHECK(exp.error().error == DeviceTokenValidateError::expired);

    // (b) unbound_legacy beats binding_mismatch: a row with empty device_id
    // never falls through to the binding check, so even a non-matching
    // presenter reports unbound_legacy (not binding_mismatch).
    auto legacy_raw = store.create_token("Legacy", "admin", "", "", 0);
    REQUIRE(legacy_raw.has_value());
    auto leg = store.validate_token(*legacy_raw, "device-X");
    REQUIRE(!leg.has_value());
    CHECK(leg.error().error == DeviceTokenValidateError::unbound_legacy);
}

TEST_CASE("DeviceTokenStore: binding_mismatch precedes neither expired nor revoked",
          "[device_token][binding]") {
    // Full ordering invariant: not_found / revoked / expired / unbound_legacy
    // all precede binding_mismatch. revoked/expired MUST always be rejected
    // even if the right presenter shows up, and returning binding_mismatch
    // for a revoked or expired token would leak that the hash exists (worse
    // disclosure than a generic not_found).
    TempDb tmp;
    DeviceTokenStore store(tmp.path);
    REQUIRE(store.is_open());

    // Expired token bound to device-A
    auto raw = store.create_token("ExpiredBound", "admin", "device-A", "", 1);
    REQUIRE(raw.has_value());

    // Even with the right presenter, expired wins
    auto exp_ok = store.validate_token(*raw, "device-A");
    REQUIRE(!exp_ok.has_value());
    CHECK(exp_ok.error().error == DeviceTokenValidateError::expired);
    auto exp_bad = store.validate_token(*raw, "device-B");
    REQUIRE(!exp_bad.has_value());
    CHECK(exp_bad.error().error == DeviceTokenValidateError::expired);
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
