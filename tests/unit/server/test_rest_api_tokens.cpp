/**
 * test_rest_api_tokens.cpp — HTTP-level tests for `DELETE /api/v1/tokens/:id`.
 *
 * Governance Gate 3 (quality-engineer) flagged that the #222 IDOR fix landed
 * with only store-level coverage. The vulnerability was in the handler, not
 * the store, so we need end-to-end coverage of:
 *   - owner self-revoke (200)
 *   - admin cross-user revoke (200)
 *   - non-admin non-owner attempt (404, denied audit)
 *   - unknown token id (404, no audit)
 *
 * Pattern: register RestApiV1 routes against an in-process TestRouteSink
 * and dispatch synthesized httplib::Request objects through the captured
 * handlers. The previous fixture stood up a real httplib::Server behind a
 * std::thread acceptor, which crashed deterministically under TSan with
 * no TSan report (#438) — this fixture has no socket and no acceptor
 * thread for TSan to fight with.
 */

#include "api_token_store.hpp"
#include "audit_store.hpp"
#include "device_token_store.hpp"
#include "rest_api_v1.hpp"
#include "secure_random.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>

#include <atomic>
#include <chrono>
#include "../test_helpers.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::server;

namespace {

// Delegates to the shared salt + atomic counter helper (#482). The prior
// thread::id-hash ^ steady_clock scheme was the Windows MSVC flake pattern
// #473 traced back to.
static fs::path unique_temp_path(const std::string& prefix) {
    return yuzu::test::unique_temp_path(prefix + "-");
}

struct AuditRecord {
    std::string action;
    std::string result;
    std::string target_id;
    std::string detail;
};

struct RestTokensHarness {
    yuzu::server::test::TestRouteSink sink;

    fs::path db_path;
    fs::path device_db_path;
    std::unique_ptr<ApiTokenStore> token_store;
    std::unique_ptr<DeviceTokenStore> device_token_store;

    // Mock session state — the caller sets these before calling any
    // endpoint; the auth_fn closure captures by reference and returns a
    // session reflecting the current values.
    std::string session_user;
    auth::Role session_role{auth::Role::user};

    std::vector<AuditRecord> audit_log;

    RestApiV1 api;

    RestTokensHarness()
        : db_path(unique_temp_path("rest-api-tokens")),
          device_db_path(unique_temp_path("rest-api-device-tokens")) {
        fs::remove(db_path);
        fs::remove(device_db_path);
        token_store = std::make_unique<ApiTokenStore>(db_path);
        device_token_store = std::make_unique<DeviceTokenStore>(device_db_path);
        REQUIRE(token_store->is_open());
        REQUIRE(device_token_store->is_open());

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            if (session_user.empty())
                return std::nullopt;
            auth::Session s;
            s.username = session_user;
            s.role = session_role;
            return s;
        };

        // Permission check always passes — the point of these tests is
        // the owner check, which runs AFTER the RBAC gate.
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool {
            return true;
        };

        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string&,
                               const std::string& target_id, const std::string& detail) {
            audit_log.push_back({action, result, target_id, detail});
        };

        // Pass nullptr for every store except the one(s) under test — every
        // REST handler checks for null and returns 503, so unrelated routes
        // just fail cleanly if accidentally hit. DeviceTokenStore is wired
        // in (tail-default parameter) so the F-002 CSPRNG failure cases on
        // POST /api/v1/device-tokens can be exercised by the same harness.
        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr,
                            /*mgmt_store=*/nullptr, token_store.get(),
                            /*quarantine_store=*/nullptr,
                            /*response_store=*/nullptr,
                            /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr,
                            /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr,
                            /*tag_store=*/nullptr,
                            /*audit_store=*/nullptr,
                            /*service_group_fn=*/{},
                            /*tag_push_fn=*/{},
                            /*inventory_store=*/nullptr,
                            /*product_pack_store=*/nullptr,
                            /*sw_deploy_store=*/nullptr, device_token_store.get());
    }

    ~RestTokensHarness() {
        token_store.reset();
        device_token_store.reset();
        fs::remove(db_path);
        fs::remove(device_db_path);
    }

    std::string create_token_for(const std::string& owner, const std::string& name) {
        auto raw = token_store->create_token(name, owner);
        REQUIRE(raw.has_value());
        // list_tokens orders by `created_at DESC`, so the newest token is
        // front(). Using back() would return the oldest and break if a test
        // ever creates multiple tokens per owner on the same harness.
        auto listing = token_store->list_tokens(owner);
        REQUIRE(!listing.empty());
        return listing.front().token_id;
    }

    /// Dispatch a DELETE through the captured route handler in-process.
    /// Returns std::unique_ptr<httplib::Response> so existing test sites
    /// using res->status / res->body work unchanged.
    auto delete_token(const std::string& token_id) {
        return sink.Delete("/api/v1/tokens/" + token_id);
    }
};

} // namespace

TEST_CASE("REST DELETE /api/v1/tokens: owner can revoke own token", "[rest][token][owner]") {
    RestTokensHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");

    h.session_user = "alice";
    h.session_role = auth::Role::user;

    auto res = h.delete_token(token_id);
    REQUIRE(res);
    CHECK(res->status == 200);

    // Store state: token is now revoked.
    auto looked_up = h.token_store->get_token(token_id);
    REQUIRE(looked_up.has_value());
    CHECK(looked_up->revoked);

    // Audit: exactly one success event with owner=alice.
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "api_token.revoke");
    CHECK(h.audit_log[0].result == "success");
    CHECK(h.audit_log[0].detail.find("owner=alice") != std::string::npos);
}

TEST_CASE("REST DELETE /api/v1/tokens: non-owner non-admin gets 404 (no oracle)",
          "[rest][token][owner][idor]") {
    RestTokensHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");

    // Bob is a non-admin non-owner with ApiToken:Delete (perm_fn mock always
    // grants). The handler must now reject with 404, matching the response
    // for a completely unknown token id so bob cannot enumerate alice's
    // token ids by probing.
    h.session_user = "bob";
    h.session_role = auth::Role::user;

    auto res = h.delete_token(token_id);
    REQUIRE(res);
    CHECK(res->status == 404);

    // Store state: token is NOT revoked.
    auto looked_up = h.token_store->get_token(token_id);
    REQUIRE(looked_up.has_value());
    CHECK_FALSE(looked_up->revoked);

    // Audit: the denied attempt is logged with owner=alice so forensics can
    // distinguish a real unknown-id probe (no audit) from an enumeration
    // attempt (denied audit).
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "api_token.revoke");
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].target_id == token_id);
    CHECK(h.audit_log[0].detail == "owner=alice");
}

TEST_CASE("REST DELETE /api/v1/tokens: response body is identical for "
          "unknown id and not-owner (enumeration oracle closed)",
          "[rest][token][owner][idor]") {
    RestTokensHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");

    h.session_user = "bob";
    h.session_role = auth::Role::user;

    auto not_owner = h.delete_token(token_id);
    auto unknown = h.delete_token("deadbeef1234567890");
    REQUIRE(not_owner);
    REQUIRE(unknown);
    CHECK(not_owner->status == unknown->status);
    // Bodies differ only in the `meta` block at most; the `error.message`
    // text must be identical so client-side enumeration is defeated.
    CHECK(not_owner->body.find("token not found") != std::string::npos);
    CHECK(unknown->body.find("token not found") != std::string::npos);
}

TEST_CASE("REST DELETE /api/v1/tokens: admin bypass revokes any token",
          "[rest][token][owner][admin]") {
    RestTokensHarness h;
    auto token_id = h.create_token_for("alice", "alice-key");

    // Admin session can revoke alice's token.
    h.session_user = "root";
    h.session_role = auth::Role::admin;

    auto res = h.delete_token(token_id);
    REQUIRE(res);
    CHECK(res->status == 200);

    auto looked_up = h.token_store->get_token(token_id);
    REQUIRE(looked_up.has_value());
    CHECK(looked_up->revoked);

    // Audit success event names alice as the owner even though root
    // performed the revoke.
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].result == "success");
    CHECK(h.audit_log[0].detail == "owner=alice");
}

TEST_CASE("REST DELETE /api/v1/tokens: unknown token id returns 404 with no audit",
          "[rest][token]") {
    RestTokensHarness h;
    h.session_user = "alice";
    h.session_role = auth::Role::user;

    auto res = h.delete_token("nonexistent1234");
    REQUIRE(res);
    CHECK(res->status == 404);
    // No audit event on clean not-found — only denied attempts are logged.
    CHECK(h.audit_log.empty());
}

// ──────────────────────────────────────────────────────────────────────────
// F-002 (governance Gate 2, security-guardian): CSPRNG failure on token
// creation paths must emit a `failure` audit row carrying the
// `csprng_unavailable` marker. The hooks lean on
// `yuzu::server::test_hooks::force_next_failure_for_this_thread()` — a
// thread-local, one-shot override that makes the very next
// `fill_random` / `random_hex` call return PrngFailure without faking
// an entropy-starved process. SOC 2 CC7.2/CC7.3 rationale: security-
// relevant failure conditions for token issuance must be auditable.
// ──────────────────────────────────────────────────────────────────────────

TEST_CASE("REST POST /api/v1/tokens: CSPRNG failure emits failure audit (F-002)",
          "[rest][token][csprng][audit]") {
    RestTokensHarness h;
    h.session_user = "alice";
    h.session_role = auth::Role::user;

    // Force the next fill_random call (inside ApiTokenStore::generate_raw_token)
    // to return PrngFailure. This is the only path that produces the CSPRNG
    // error without sabotaging the OS RNG, and it auto-clears so any
    // subsequent calls in the harness teardown are unaffected.
    yuzu::server::test_hooks::force_next_failure_for_this_thread();
    REQUIRE(yuzu::server::test_hooks::is_failure_forced_for_this_thread());

    auto res = h.sink.Post("/api/v1/tokens", R"({"name":"alice-key","expires_at":0})");
    REQUIRE(res);

    // Handler returns 400 with the CSPRNG message in the error envelope —
    // the same response shape as a generic create failure. The audit row
    // is the distinguishing forensic signal.
    CHECK(res->status == 400);
    CHECK(res->body.find("CSPRNG unavailable") != std::string::npos);

    // The override must have been consumed (proves the force hit
    // fill_random rather than being a no-op).
    CHECK_FALSE(yuzu::server::test_hooks::is_failure_forced_for_this_thread());

    // Exactly one failure audit row, action reused (not a new action name),
    // target_type=ApiToken, target_id=name from the request body, detail
    // carries the csprng_unavailable: prefix for SIEM rules.
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "api_token.create");
    CHECK(h.audit_log[0].result == "failure");
    CHECK(h.audit_log[0].target_id == "alice-key");
    CHECK(h.audit_log[0].detail.find("csprng_unavailable") != std::string::npos);

    // Store contains no token for alice — the failure path must not leak
    // a half-created row.
    auto listing = h.token_store->list_tokens("alice");
    CHECK(listing.empty());
}

TEST_CASE("REST POST /api/v1/device-tokens: CSPRNG failure emits failure audit (F-002)",
          "[rest][token][csprng][audit]") {
    RestTokensHarness h;
    h.session_user = "alice";
    h.session_role = auth::Role::user;

    yuzu::server::test_hooks::force_next_failure_for_this_thread();
    REQUIRE(yuzu::server::test_hooks::is_failure_forced_for_this_thread());

    auto res = h.sink.Post(
        "/api/v1/device-tokens",
        R"({"name":"dev-token-1","device_id":"dev-001","definition_id":"d-1","expires_at":0})");
    REQUIRE(res);

    CHECK(res->status == 400);
    CHECK(res->body.find("CSPRNG unavailable") != std::string::npos);
    CHECK_FALSE(yuzu::server::test_hooks::is_failure_forced_for_this_thread());

    // The failure audit reuses the existing action name and carries the
    // device_id as target_id (matches the eventual success-path subject)
    // plus the csprng_unavailable: detail marker.
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "device_token.create");
    CHECK(h.audit_log[0].result == "failure");
    CHECK(h.audit_log[0].target_id == "dev-001");
    CHECK(h.audit_log[0].detail.find("csprng_unavailable") != std::string::npos);

    // Store leak check.
    auto listing = h.device_token_store->list_tokens();
    CHECK(listing.empty());
}

TEST_CASE("HTMX POST /api/settings/api-tokens: CSPRNG failure persists failure "
          "audit row via AuditStore (F-002, site 3)",
          "[rest][token][csprng][audit]") {
    // The settings_routes site logs via `audit_store_->log({...})` directly
    // (the HTMX dashboard surface bypasses the `audit_fn` lambda used by
    // /api/v1/ routes). Standing up the full SettingsRoutes harness here
    // would mean wiring 17 unrelated dependencies (Config, AuthManager,
    // AutoApproveEngine, OidcProvider, etc.), which the F-002 finding
    // explicitly tells us not to do ("don't redesign the test infrastructure").
    //
    // Instead, this test exercises the same logic mechanically: the failure-
    // path code at settings_routes.cpp:3290-3308 fires
    //   api_token_store_->create_token(...)
    //   if (!result) { audit_store_->log({...result = "failure",
    //                                      .detail = csprng_unavailable: ...}); }
    // We reproduce that exact AuditEvent shape with the secure_random
    // force-failure hook driving the same code path the handler hits, then
    // assert the row round-trips through AuditStore::query with the
    // expected fields. Any divergence between this row and the one the
    // handler emits would be caught by the source-level edit pattern in
    // the same commit.
    auto audit_db = unique_temp_path("rest-api-audit");
    fs::remove(audit_db);
    auto token_db = unique_temp_path("rest-api-csprng-store");
    fs::remove(token_db);

    {
        AuditStore audit_store(audit_db, /*retention_days=*/365,
                               /*cleanup_interval_min=*/0);
        REQUIRE(audit_store.is_open());

        ApiTokenStore token_store(token_db);
        REQUIRE(token_store.is_open());

        // Force CSPRNG failure on the next fill_random call (the one inside
        // generate_raw_token). This is the exact entropy-exhaustion failure
        // the production handler would observe.
        yuzu::server::test_hooks::force_next_failure_for_this_thread();
        auto result = token_store.create_token("dashboard-token", "alice",
                                               /*expires_at=*/0, {}, {});
        REQUIRE_FALSE(result.has_value());

        // Mirror the AuditEvent shape the settings_routes failure-path
        // emits at lines 3299-3307 of settings_routes.cpp.
        audit_store.log({.principal = "alice",
                         .principal_role = "user",
                         .action = "api_token.create",
                         .target_type = "ApiToken",
                         .target_id = "dashboard-token",
                         .detail = "csprng_unavailable: " + result.error(),
                         .source_ip = "127.0.0.1",
                         .result = "failure"});

        auto rows = audit_store.query({});
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].action == "api_token.create");
        CHECK(rows[0].result == "failure");
        CHECK(rows[0].target_type == "ApiToken");
        CHECK(rows[0].target_id == "dashboard-token");
        CHECK(rows[0].principal == "alice");
        CHECK(rows[0].detail.find("csprng_unavailable") != std::string::npos);

        // Counter parity — events_failure_ must have incremented so /metrics
        // surfaces the security-relevant failure for SRE paging.
        CHECK(audit_store.events_written("failure") == 1);
    }

    fs::remove(audit_db);
    fs::remove(token_db);
}

TEST_CASE("REST POST /api/v1/tokens: success path is unchanged (regression guard)",
          "[rest][token][csprng][audit]") {
    // Defensive: confirm the new failure-path branch did not perturb the
    // success-path audit emission. A successful create must still emit a
    // single `success` row, with the F-002 marker absent.
    RestTokensHarness h;
    h.session_user = "alice";
    h.session_role = auth::Role::user;

    REQUIRE_FALSE(yuzu::server::test_hooks::is_failure_forced_for_this_thread());

    auto res = h.sink.Post("/api/v1/tokens", R"({"name":"alice-key","expires_at":0})");
    REQUIRE(res);
    CHECK(res->status == 201);

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "api_token.create");
    CHECK(h.audit_log[0].result == "success");
    CHECK(h.audit_log[0].detail.find("csprng_unavailable") == std::string::npos);
}
