/**
 * test_auth_routes.cpp — Unit tests for AuthRoutes session resolution and audit
 * event construction.
 *
 * Regression coverage for the audit-trail bug where AuthRoutes::make_audit_event
 * resolved the principal from session cookies only, leaving `principal=""` on
 * every audit row written by an API-token-authenticated request (REST automation
 * and every MCP tool call). The fix extracted resolve_session(req), used by
 * require_auth, make_audit_event, and emit_event alike. These tests lock that
 * helper's three-branch contract (cookie / Bearer / X-Yuzu-Token) so future
 * refactors cannot silently re-introduce the gap.
 */

#include "auth_routes.hpp"

#include "analytics_event_store.hpp"
#include "api_token_store.hpp"
#include "oidc_provider.hpp"
#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <httplib.h>

#include <atomic>
#include <filesystem>
#include <memory>
#include <shared_mutex>
#include <string>

namespace fs = std::filesystem;
using namespace yuzu::server;

namespace {

/// Holds every store + ref AuthRoutes needs so the test body stays compact.
/// Stores that the methods under test do not dereference (RbacStore,
/// ManagementGroupStore, TagStore, AuditStore) are passed as nullptr to keep
/// setup minimal — see auth_routes.cpp:289-344 for the read set.
struct AuthRoutesFixture {
    Config cfg{};
    auth::AuthManager auth_mgr{};
    fs::path tmp_dir;
    std::unique_ptr<ApiTokenStore> api_tokens;
    std::unique_ptr<AnalyticsEventStore> analytics;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;  // empty
    std::unique_ptr<AuthRoutes> ar;

    AuthRoutesFixture() {
        // Per-fixture unique tmp dir so concurrent Catch2 runs (`-j`) cannot
        // race on shared SQLite files. PID alone is not enough — every test
        // case in the same process shares it.
        static std::atomic<unsigned> seq{0};
        tmp_dir = fs::temp_directory_path() /
                  ("yuzu_auth_routes_test_" + std::to_string(::getpid()) + "_" +
                   std::to_string(seq.fetch_add(1)));
        fs::create_directories(tmp_dir);
        api_tokens = std::make_unique<ApiTokenStore>(tmp_dir / "api_tokens.db");
        analytics = std::make_unique<AnalyticsEventStore>(tmp_dir / "analytics.db");
        REQUIRE(api_tokens->is_open());
        REQUIRE(analytics->is_open());

        // Register a known user so synthesize_token_session resolves a real role.
        REQUIRE(auth_mgr.upsert_user("test_user", "test_password", auth::Role::admin));

        ar = std::make_unique<AuthRoutes>(
            cfg, auth_mgr,
            /*rbac_store=*/nullptr,
            api_tokens.get(),
            /*audit_store=*/nullptr,
            /*mgmt_group_store=*/nullptr,
            /*tag_store=*/nullptr,
            analytics.get(),
            oidc_mu, oidc_provider);
    }

    ~AuthRoutesFixture() {
        std::error_code ec;
        // Drop stores before removing the directory so SQLite handles close cleanly.
        ar.reset();
        analytics.reset();
        api_tokens.reset();
        fs::remove_all(tmp_dir, ec);
    }

    std::string mint_token() {
        auto raw = api_tokens->create_token("unit-test", "test_user");
        REQUIRE(raw.has_value());
        return *raw;
    }
};

httplib::Request request_with_header(const std::string& name, const std::string& value) {
    httplib::Request req;
    req.headers.emplace(name, value);
    return req;
}

}  // namespace

TEST_CASE("AuthRoutes::resolve_session — Bearer token populates principal",
          "[auth_routes]") {
    AuthRoutesFixture fix;
    auto raw = fix.mint_token();
    auto req = request_with_header("Authorization", "Bearer " + raw);

    auto session = fix.ar->resolve_session(req);
    REQUIRE(session.has_value());
    CHECK(session->username == "test_user");
    CHECK(session->mcp_tier.empty());
}

TEST_CASE("AuthRoutes::resolve_session — X-Yuzu-Token populates principal",
          "[auth_routes]") {
    AuthRoutesFixture fix;
    auto raw = fix.mint_token();
    auto req = request_with_header("X-Yuzu-Token", raw);

    auto session = fix.ar->resolve_session(req);
    REQUIRE(session.has_value());
    CHECK(session->username == "test_user");
}

TEST_CASE("AuthRoutes::resolve_session — session cookie populates principal",
          "[auth_routes]") {
    AuthRoutesFixture fix;
    auto cookie = fix.auth_mgr.authenticate("test_user", "test_password");
    REQUIRE(cookie.has_value());
    auto req = request_with_header("Cookie", "yuzu_session=" + *cookie);

    auto session = fix.ar->resolve_session(req);
    REQUIRE(session.has_value());
    CHECK(session->username == "test_user");
}

TEST_CASE("AuthRoutes::resolve_session — no auth returns nullopt",
          "[auth_routes]") {
    AuthRoutesFixture fix;
    httplib::Request req;
    auto session = fix.ar->resolve_session(req);
    CHECK_FALSE(session.has_value());
}

TEST_CASE("AuthRoutes::make_audit_event — populates principal from Bearer token "
          "(regression: mcp.* audit rows had empty principal)",
          "[auth_routes][audit]") {
    AuthRoutesFixture fix;
    auto raw = fix.mint_token();
    auto req = request_with_header("Authorization", "Bearer " + raw);

    auto event = fix.ar->make_audit_event(req, "mcp.list_agents", "success");
    CHECK(event.action == "mcp.list_agents");
    CHECK(event.result == "success");
    CHECK(event.principal == "test_user");
    CHECK(event.principal_role == "admin");
}

TEST_CASE("AuthRoutes::make_audit_event — populates principal from X-Yuzu-Token",
          "[auth_routes][audit]") {
    AuthRoutesFixture fix;
    auto raw = fix.mint_token();
    auto req = request_with_header("X-Yuzu-Token", raw);

    auto event = fix.ar->make_audit_event(req, "rest.api.call", "success");
    CHECK(event.principal == "test_user");
    CHECK(event.principal_role == "admin");
}

TEST_CASE("AuthRoutes::make_audit_event — populates principal from session cookie",
          "[auth_routes][audit]") {
    AuthRoutesFixture fix;
    auto cookie = fix.auth_mgr.authenticate("test_user", "test_password");
    REQUIRE(cookie.has_value());
    auto req = request_with_header("Cookie", "yuzu_session=" + *cookie);

    auto event = fix.ar->make_audit_event(req, "dashboard.action", "success");
    CHECK(event.principal == "test_user");
    CHECK(event.principal_role == "admin");
    CHECK(event.session_id == *cookie);
}

TEST_CASE("AuthRoutes::make_audit_event — empty principal when no auth present",
          "[auth_routes][audit]") {
    AuthRoutesFixture fix;
    httplib::Request req;
    auto event = fix.ar->make_audit_event(req, "anonymous", "success");
    CHECK(event.principal.empty());
    CHECK(event.principal_role.empty());
}

TEST_CASE("AuthRoutes::emit_event — analytics event records principal from "
          "Bearer token (regression: same shape as audit_event bug)",
          "[auth_routes][analytics]") {
    AuthRoutesFixture fix;
    auto raw = fix.mint_token();
    auto req = request_with_header("Authorization", "Bearer " + raw);

    fix.ar->emit_event("test.event", req);

    // Drain the buffer (the in-memory store flushes on demand via query_recent).
    auto events = fix.analytics->query_recent(10);
    REQUIRE_FALSE(events.empty());
    bool found = false;
    for (const auto& e : events) {
        if (e.event_type == "test.event") {
            CHECK(e.principal == "test_user");
            CHECK(e.principal_role == "admin");
            found = true;
            break;
        }
    }
    CHECK(found);
}

// ---------------------------------------------------------------------------
// require_admin scope-enforcement tests (#520)
// ---------------------------------------------------------------------------

TEST_CASE("AuthRoutes::require_admin — service-scoped token from admin is rejected",
          "[auth_routes][scope]") {
    AuthRoutesFixture fix;
    // Mint a token scoped to "finance-svc"; creator is an admin.
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("scoped", "test_user",
                                            now + 3600, "finance-svc", "");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool ok = fix.ar->require_admin(req, res);
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
    CHECK(res.body.find("service-scoped tokens cannot perform admin operations") !=
          std::string::npos);
}

TEST_CASE("AuthRoutes::require_admin — MCP token from admin is rejected",
          "[auth_routes][scope]") {
    AuthRoutesFixture fix;
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-tok", "test_user",
                                            now + 3600, "", "readonly");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool ok = fix.ar->require_admin(req, res);
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
    CHECK(res.body.find("MCP tokens cannot perform admin operations") != std::string::npos);
}

TEST_CASE("AuthRoutes::require_admin — unscoped admin token is accepted (regression guard)",
          "[auth_routes][scope]") {
    AuthRoutesFixture fix;
    auto raw = fix.api_tokens->create_token("plain", "test_user");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool ok = fix.ar->require_admin(req, res);
    CHECK(ok);
    CHECK(res.status != 403);
}

// ---------------------------------------------------------------------------
// require_permission MCP-tier enforcement tests (#520 — Claude review F1)
// ---------------------------------------------------------------------------

TEST_CASE("AuthRoutes::require_permission — MCP token rejected when RBAC disabled",
          "[auth_routes][scope]") {
    AuthRoutesFixture fix;
    // Fixture has rbac_store=nullptr, so RBAC is disabled.
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-rp", "test_user",
                                            now + 3600, "", "readonly");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool ok = fix.ar->require_permission(req, res, "Agent", "Execute");
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
    CHECK(res.body.find("MCP tokens require RBAC to be enabled") != std::string::npos);
}

// ---------------------------------------------------------------------------
// require_scoped_permission MCP-tier enforcement tests (#520 — Claude review F2)
// ---------------------------------------------------------------------------

TEST_CASE("AuthRoutes::require_scoped_permission — MCP token rejected when RBAC disabled",
          "[auth_routes][scope]") {
    AuthRoutesFixture fix;
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-rsp", "test_user",
                                            now + 3600, "", "readonly");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool ok = fix.ar->require_scoped_permission(req, res, "Agent", "Read", "agent-1");
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
    CHECK(res.body.find("MCP tokens require RBAC to be enabled") != std::string::npos);
}

// ---------------------------------------------------------------------------
// Bearer token length guard tests (#630 — Claude review F4/F6)
// ---------------------------------------------------------------------------

TEST_CASE("AuthRoutes::require_auth — oversized Bearer token is rejected (DoS protection #630)",
          "[auth_routes][dos]") {
    AuthRoutesFixture fix;
    std::string big_token(1000, 'a');
    auto req = request_with_header("Authorization", "Bearer " + big_token);
    httplib::Response res;

    auto session = fix.ar->require_auth(req, res);
    CHECK_FALSE(session.has_value());
    CHECK(res.status == 401); // Rejected before reaching ApiTokenStore
}

TEST_CASE("AuthRoutes::require_auth — oversized X-Yuzu-Token is rejected (DoS protection #630)",
          "[auth_routes][dos]") {
    AuthRoutesFixture fix;
    std::string big_token(1000, 'b');
    auto req = request_with_header("X-Yuzu-Token", big_token);
    httplib::Response res;

    auto session = fix.ar->require_auth(req, res);
    CHECK_FALSE(session.has_value());
    CHECK(res.status == 401);
}
