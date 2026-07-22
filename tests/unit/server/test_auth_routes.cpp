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
#include "test_api_token_pg_helper.hpp" // ApiTokenStorePg — PR 4.1 PG port
#include "oidc_provider.hpp"
#include "pg/pg_raii.hpp" // PgConn/PgResult — the CH-4 saboteur's second connection
#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <httplib.h>
#include <libpq-fe.h>
#include <sqlite3.h>
#include <nlohmann/json.hpp>

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
    // ApiTokenStore ported to Postgres (PR 4.1) — clones an ephemeral database
    // via the shared ApiTokenStorePg helper. Constructing this fixture now
    // SKIPs the current TEST_CASE when YUZU_TEST_POSTGRES_DSN is unset, and
    // FAILs when it is set but broken (same posture as every other [pg] test).
    yuzu::test::ApiTokenStorePg api_tokens;
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
        analytics = std::make_unique<AnalyticsEventStore>(tmp_dir / "analytics.db");
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
    CHECK(event.principal_class == "agent"); // bearer token (ADR-1005 Phase 3a)
}

TEST_CASE("AuthRoutes::make_audit_event — populates principal from X-Yuzu-Token",
          "[auth_routes][audit]") {
    AuthRoutesFixture fix;
    auto raw = fix.mint_token();
    auto req = request_with_header("X-Yuzu-Token", raw);

    auto event = fix.ar->make_audit_event(req, "rest.api.call", "success");
    CHECK(event.principal == "test_user");
    CHECK(event.principal_role == "admin");
    CHECK(event.principal_class == "agent"); // X-Yuzu-Token (ADR-1005 Phase 3a)
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
    CHECK(event.principal_class == "human"); // session cookie (ADR-1005 Phase 3a)
}

TEST_CASE("AuthRoutes::make_audit_event — empty principal when no auth present",
          "[auth_routes][audit]") {
    AuthRoutesFixture fix;
    httplib::Request req;
    auto event = fix.ar->make_audit_event(req, "anonymous", "success");
    CHECK(event.principal.empty());
    CHECK(event.principal_role.empty());
    CHECK(event.principal_class == "none"); // no credential (ADR-1005 Phase 3a)
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
          "[auth_routes][scope][mcp]") {
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
    // #1470: the require_admin denial now emits the unified A4 envelope with a
    // correlation_id echoed on the header. require_admin gates a whole route,
    // not a securable:operation, so there is deliberately NO `permission` field.
    auto j = nlohmann::json::parse(res.body);
    CHECK(j["error"]["code"].get<int>() == 403);
    CHECK_FALSE(j["error"]["correlation_id"].get<std::string>().empty());
    CHECK(j["error"].contains("retry_after_ms")); // A4: always present (null here)
    CHECK_FALSE(j["error"].contains("permission"));
    CHECK(j["meta"]["api_version"].get<std::string>() == "v1");
    CHECK(res.get_header_value("X-Correlation-Id") ==
          j["error"]["correlation_id"].get<std::string>());
}

TEST_CASE("AuthRoutes::require_admin — MCP token from admin is rejected",
          "[auth_routes][scope][mcp]") {
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
          "[auth_routes][scope][mcp]") {
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
// require_permission MCP-tier enforcement tests (#520)
// The tier (readonly/operator/supervised) is the primary boundary; the creator's
// actual role is the secondary RBAC boundary. RBAC-disabled deployments still work.
// ---------------------------------------------------------------------------

TEST_CASE("AuthRoutes::require_permission — readonly MCP tier blocks Execute regardless of RBAC",
          "[auth_routes][scope][mcp]") {
    AuthRoutesFixture fix;
    // Fixture has rbac_store=nullptr (RBAC disabled). test_user is admin.
    // Tier enforcement must fire regardless of RBAC state.
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-rp", "test_user",
                                            now + 3600, "", "readonly");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool ok = fix.ar->require_permission(req, res, "Execution", "Execute");
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
    CHECK(res.body.find("MCP token tier does not allow Execution:Execute") != std::string::npos);
    // #1470: require_permission's MCP-tier denial now emits the unified A4
    // envelope — a correlation_id (echoed on the header) and the structured
    // securable_type:operation permission field (kPermissionDenied §A4).
    auto j = nlohmann::json::parse(res.body);
    CHECK(j["error"]["code"].get<int>() == 403);
    CHECK_FALSE(j["error"]["correlation_id"].get<std::string>().empty());
    CHECK(j["error"]["permission"].get<std::string>() == "Execution:Execute");
    CHECK(j["error"].contains("retry_after_ms"));
    CHECK(j["meta"]["api_version"].get<std::string>() == "v1");
    CHECK(res.get_header_value("X-Correlation-Id") ==
          j["error"]["correlation_id"].get<std::string>());
}

TEST_CASE("AuthRoutes::require_permission — readonly MCP tier allows Read without RBAC",
          "[auth_routes][scope][mcp]") {
    AuthRoutesFixture fix;
    // readonly tier permits Read; creator is admin; RBAC disabled → should pass.
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-rp2", "test_user",
                                            now + 3600, "", "readonly");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool ok = fix.ar->require_permission(req, res, "Infrastructure", "Read");
    CHECK(ok);
}

// ---------------------------------------------------------------------------
// require_scoped_permission MCP-tier enforcement tests (#520)
// ---------------------------------------------------------------------------

TEST_CASE("AuthRoutes::require_scoped_permission — operator MCP tier allows Execute without RBAC",
          "[auth_routes][scope][mcp]") {
    AuthRoutesFixture fix;
    // operator tier permits Execution:Execute; creator is admin; RBAC disabled → pass.
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-rsp", "test_user",
                                            now + 3600, "", "operator");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool ok = fix.ar->require_scoped_permission(req, res, "Execution", "Execute", "agent-1");
    CHECK(ok);
}

TEST_CASE("AuthRoutes::require_scoped_permission — readonly MCP tier blocks Execute",
          "[auth_routes][scope][mcp]") {
    AuthRoutesFixture fix;
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-rsp2", "test_user",
                                            now + 3600, "", "readonly");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool ok = fix.ar->require_scoped_permission(req, res, "Execution", "Execute", "agent-1");
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
    CHECK(res.body.find("MCP token tier does not allow Execution:Execute") != std::string::npos);
    // #1549 review MEDIUM: the scoped-gate denial now carries the A4 envelope —
    // a correlation_id and a structured securable_type:operation permission field.
    auto j = nlohmann::json::parse(res.body);
    CHECK(j["error"]["code"].get<int>() == 403);
    CHECK_FALSE(j["error"]["correlation_id"].get<std::string>().empty());
    CHECK(j["error"]["permission"].get<std::string>() == "Execution:Execute");
    CHECK(j["meta"]["api_version"].get<std::string>() == "v1");
    // The body's correlation_id is echoed on the X-Correlation-Id header so a caller
    // can correlate without parsing the body.
    CHECK(res.get_header_value("X-Correlation-Id") ==
          j["error"]["correlation_id"].get<std::string>());
}

// ---------------------------------------------------------------------------
// supervised-tier approval enforcement on REST transport (sec-H1 / CH-1)
// The MCP server DENIES supervised+destructive ops (kTierDenied) because Phase 2
// re-dispatch is not built — it deliberately does NOT return kApprovalRequired,
// which the A4 contract reserves for a pollable approval (approval_id +
// status_url) it cannot honestly produce. The REST transport must mirror that
// denial — a supervised MCP token must not bypass the approval gate by switching
// endpoints.
// ---------------------------------------------------------------------------

TEST_CASE("AuthRoutes::require_permission — supervised MCP token blocked from approval-gated Execute",
          "[auth_routes][scope][mcp]") {
    AuthRoutesFixture fix;
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-sup-rp", "test_user",
                                            now + 3600, "", "supervised");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    req.path = "/api/v1/executions"; // a REST (non-MCP) transport
    httplib::Response res;

    // tier_allows("supervised", Execution, Execute) → true
    // requires_approval("supervised", Execution, Execute) → true
    // → on a REST transport the approval gate is enforced here so an MCP token
    //   cannot bypass the ticket flow by switching endpoints (#520).
    bool ok = fix.ar->require_permission(req, res, "Execution", "Execute");
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
    CHECK(res.body.find("approval") != std::string::npos);
}

// Complement of the above: on the MCP JSON-RPC transport (`/mcp/v1/`) the C8 gate
// in mcp_server.cpp is the authoritative approval gate (ticket-then-recall, #289),
// so require_permission must NOT re-deny an approval-gated op here — otherwise the
// recall consumes the ticket then dies at the auth layer. This is the exact
// integration bug the UAT smoke caught (the MCP unit harness mocks perm_fn).
TEST_CASE("AuthRoutes::require_permission — approval gate is skipped on the MCP transport",
          "[auth_routes][scope][mcp]") {
    AuthRoutesFixture fix;
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-sup-mcp", "test_user",
                                            now + 3600, "", "supervised");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    req.path = "/mcp/v1/"; // the MCP transport — C8 governs approval
    httplib::Response res;

    // Same (supervised, Execution:Execute) that the REST case above denies — here
    // the approval denial must NOT fire. RBAC is permissive in this fixture (the
    // "allows Read" case returns true), so this passes through to true.
    bool ok = fix.ar->require_permission(req, res, "Execution", "Execute");
    CHECK(ok);
    CHECK(res.body.find("approval") == std::string::npos); // the approval gate did not fire
}

// PR #1796 review C2: quarantine is Security:Execute on BOTH transports. The
// kToolSecurity mapping and requires_approval("supervised","Security","Execute")
// move together (see the invariant note above kToolSecurity in mcp_server.cpp),
// so the REST POST/DELETE /api/v1/quarantine routes — which gate on
// perm_fn("Security","Execute") — are mirror-denied here for a supervised token.
// Before the fix the mapping said Security:Write while the routes checked
// Execute, so requires_approval() was false for the REST pair and a supervised
// MCP token could quarantine (and release) via REST with NO approval (#520).
TEST_CASE("AuthRoutes::require_permission — supervised token mirror-denied on REST quarantine POST",
          "[auth_routes][scope][mcp][quarantine]") {
    AuthRoutesFixture fix;
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-sup-quar-post", "test_user",
                                            now + 3600, "", "supervised");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    req.method = "POST";
    req.path = "/api/v1/quarantine"; // the exact route the REST quarantine gate runs on
    httplib::Response res;

    // tier_allows("supervised", Security, Execute) → true
    // requires_approval("supervised", Security, Execute) → true (the C2 rule)
    // → non-MCP transport ⇒ the approval mirror-denial fires (#520).
    bool ok = fix.ar->require_permission(req, res, "Security", "Execute");
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
    CHECK(res.body.find("approval") != std::string::npos);
}

TEST_CASE("AuthRoutes::require_permission — supervised token mirror-denied on REST quarantine DELETE",
          "[auth_routes][scope][mcp][quarantine]") {
    AuthRoutesFixture fix;
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-sup-quar-del", "test_user",
                                            now + 3600, "", "supervised");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    req.method = "DELETE";
    req.path = "/api/v1/quarantine/agent-1"; // release route — same Security:Execute gate
    httplib::Response res;

    bool ok = fix.ar->require_permission(req, res, "Security", "Execute");
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
    CHECK(res.body.find("approval") != std::string::npos);
}

TEST_CASE("AuthRoutes::require_scoped_permission — supervised MCP token blocked from approval-gated Delete",
          "[auth_routes][scope][mcp]") {
    AuthRoutesFixture fix;
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-sup-rsp", "test_user",
                                            now + 3600, "", "supervised");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool ok = fix.ar->require_scoped_permission(req, res, "Tag", "Delete", "agent-1");
    CHECK_FALSE(ok);
    CHECK(res.status == 403);
    CHECK(res.body.find("approval") != std::string::npos);
}

TEST_CASE("AuthRoutes::require_permission — supervised MCP token allows Read (not approval-gated)",
          "[auth_routes][scope][mcp]") {
    AuthRoutesFixture fix;
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    auto raw = fix.api_tokens->create_token("mcp-sup-read", "test_user",
                                            now + 3600, "", "supervised");
    REQUIRE(raw.has_value());
    auto req = request_with_header("Authorization", "Bearer " + *raw);
    httplib::Response res;

    bool ok = fix.ar->require_permission(req, res, "Infrastructure", "Read");
    CHECK(ok);
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

// ---------------------------------------------------------------------------
// AuthRoutes::url_decode — malformed percent-sequence safety (H-A)
//
// Prior to this fix, AuthRoutes::url_decode called std::stoul on any two
// characters that followed a '%', throwing std::invalid_argument for non-hex
// sequences such as "%GH" or a bare "%" and causing a 500 on form-encoded
// POST handlers (login, MFA, SAML ACS).
// ---------------------------------------------------------------------------

TEST_CASE("AuthRoutes::url_decode — valid percent-encoded sequences decode correctly",
          "[auth_routes][url_decode]") {
    CHECK(AuthRoutes::url_decode("hello%20world") == "hello world");
    CHECK(AuthRoutes::url_decode("%26")            == "&");
    CHECK(AuthRoutes::url_decode("%3D")            == "=");
    CHECK(AuthRoutes::url_decode("%41")            == "A"); // 0x41 = 'A'
    CHECK(AuthRoutes::url_decode("key%3Dvalue")    == "key=value");
}

TEST_CASE("AuthRoutes::url_decode — plus sign decoded to space", "[auth_routes][url_decode]") {
    CHECK(AuthRoutes::url_decode("hello+world") == "hello world");
}

TEST_CASE("AuthRoutes::url_decode — bare percent passed through literally (H-A)",
          "[auth_routes][url_decode]") {
    // A bare '%' at end of string — no two chars follow → emit literally.
    CHECK(AuthRoutes::url_decode("%")        == "%");
    CHECK(AuthRoutes::url_decode("test%")    == "test%");
}

TEST_CASE("AuthRoutes::url_decode — single hex digit after percent passed through (H-A)",
          "[auth_routes][url_decode]") {
    // '%' followed by exactly one char (truncated) → emit literally.
    CHECK(AuthRoutes::url_decode("%2")       == "%2");
    CHECK(AuthRoutes::url_decode("abc%2")    == "abc%2");
}

TEST_CASE("AuthRoutes::url_decode — non-hex chars after percent passed through (H-A)",
          "[auth_routes][url_decode]") {
    // '%GH' — 'G' is not a hex digit in the first nibble → emit '%' literally.
    CHECK(AuthRoutes::url_decode("%GH")      == "%GH");
    // '%1G' — second nibble non-hex.
    CHECK(AuthRoutes::url_decode("%1G")      == "%1G");
    // Mid-string malformed, rest is plain text.
    CHECK(AuthRoutes::url_decode("a%GHb")    == "a%GHb");
}

TEST_CASE("AuthRoutes::url_decode — mixed valid and malformed sequences (H-A)",
          "[auth_routes][url_decode]") {
    // The malformed '%GH' is passed through; the valid '%41' decodes to 'A'.
    CHECK(AuthRoutes::url_decode("%GH%41")   == "%GHA");
    CHECK(AuthRoutes::url_decode("ok%41")    == "okA");
}

// ── revalidate_stream: the tri-state a HELD-OPEN stream needs ────────────────
//
// This is the production implementation of ADR-1005 Decision 15(c)/(i) — the code
// that decides, every heartbeat tick, whether a live MCP SSE stream keeps running.
// The distinction it draws is the whole point: a REVOKED credential must cut the
// stream on the spot, while an auth store that merely cannot be REACHED must not cut
// every stream on the fleet at the same instant (chaos CH-4).

TEST_CASE("revalidate_stream: a live token for the stream's principal is valid",
          "[auth][stream][ch4]") {
    AuthRoutesFixture f;
    const auto token = f.mint_token();
    auto req = request_with_header("Authorization", "Bearer " + token);
    CHECK(f.ar->revalidate_stream(req, "test_user") == auth::CredentialCheck::kValid);
}

TEST_CASE("revalidate_stream: a revoked token DEFINITIVELY ends the stream",
          "[auth][stream][ch4]") {
    AuthRoutesFixture f;
    const auto token = f.mint_token();
    auto live = f.api_tokens->validate_token(token);
    REQUIRE(live.has_value());
    REQUIRE(f.api_tokens->revoke_token(live->token_id));

    auto req = request_with_header("Authorization", "Bearer " + token);
    // kRevoked, NOT kIndeterminate: an indeterminate answer would buy the revoked
    // credential a full grace window of extra life on a live stream.
    CHECK(f.ar->revalidate_stream(req, "test_user") == auth::CredentialCheck::kRevoked);
}

TEST_CASE("revalidate_stream: a valid token for ANOTHER principal is not authority",
          "[auth][stream][ch4]") {
    AuthRoutesFixture f;
    const auto token = f.mint_token(); // belongs to test_user
    auto req = request_with_header("Authorization", "Bearer " + token);
    // The stream carries test_user's messages. A credential that authenticates as
    // somebody else does not entitle the holder to keep reading them.
    CHECK(f.ar->revalidate_stream(req, "someone_else") == auth::CredentialCheck::kRevoked);
}

TEST_CASE("revalidate_stream: no credential at all is a definitive no", "[auth][stream][ch4]") {
    AuthRoutesFixture f;
    httplib::Request bare;
    CHECK(f.ar->revalidate_stream(bare, "test_user") == auth::CredentialCheck::kRevoked);
}

TEST_CASE("revalidate_stream: a dead cookie FALLS THROUGH to a live token",
          "[auth][stream][ch4]") {
    // The invariant: a stream lives iff a fresh request with these headers would still
    // authenticate as this principal — so this must mirror resolve_session's
    // fall-through exactly. An earlier version returned kRevoked as soon as the cookie
    // failed, which killed a perfectly good token-authenticated stream every 3 s (in a
    // reconnect loop) whenever the client also carried a stale cookie from a browser
    // jar or a cookie-injecting proxy.
    AuthRoutesFixture f;
    const auto token = f.mint_token();
    httplib::Request req;
    req.set_header("Cookie", "yuzu_session=dead-and-gone");
    req.set_header("Authorization", "Bearer " + token);
    CHECK(f.ar->revalidate_stream(req, "test_user") == auth::CredentialCheck::kValid);
}

TEST_CASE("revalidate_stream: X-Yuzu-Token is honoured alongside a dead Bearer",
          "[auth][stream][ch4]") {
    AuthRoutesFixture f;
    const auto token = f.mint_token();
    httplib::Request req;
    req.set_header("Authorization", "Bearer yuzu_not_a_real_token_000000000000");
    req.set_header("X-Yuzu-Token", token);
    CHECK(f.ar->revalidate_stream(req, "test_user") == auth::CredentialCheck::kValid);
}

TEST_CASE("revalidate_stream: an unreachable token store is INDETERMINATE, not revoked",
          "[auth][stream][ch4]") {
    // CH-4's second half. If the store cannot answer, we do not KNOW the credential is
    // gone — and treating "cannot tell" as "revoked" would cut every stream on the
    // fleet the moment the auth store hiccupped. The pump rides out a bounded grace
    // window on kIndeterminate instead.
    AuthRoutesFixture f;
    const auto token = f.mint_token();
    auto req = request_with_header("Authorization", "Bearer " + token);
    // NOTE: deliberately do NOT validate the token first — a successful validation
    // would populate the 60 s token cache, and the cached answer would sail straight
    // past the broken store, testing nothing.

    // Break the store underneath the token, from a SECOND connection — no test-only
    // hook on the production store, and this is what a real corruption/ops accident
    // looks like from the reader's side: the query it needs will not run.
    {
        yuzu::server::pg::PgConn saboteur{PQconnectdb(f.api_tokens.dsn().c_str())};
        REQUIRE(PQstatus(saboteur.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult r{
            PQexec(saboteur.get(), "DROP TABLE api_token_store.api_tokens")};
        REQUIRE(r.ok());
    }

    CHECK(f.ar->revalidate_stream(req, "test_user") == auth::CredentialCheck::kIndeterminate);
}
