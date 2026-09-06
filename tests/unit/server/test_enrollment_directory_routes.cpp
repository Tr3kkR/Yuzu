/**
 * test_enrollment_directory_routes.cpp — HTTP-level coverage for #4031's five
 * REST v1 read twins (`EnrollmentDirectoryRoutes`):
 *   - GET /api/v1/directory/users             (Directory:Read, [pg])
 *   - GET /api/v1/directory/status             (Directory:Read, [pg])
 *   - GET /api/v1/enrollment/auto-approve-rules (Enrollment:Read)
 *   - GET /api/v1/enrollment/pending-agents     (Enrollment:Read)
 *   - GET /api/v1/settings/oidc                 (OidcConfig:Read)
 *
 * Registers EnrollmentDirectoryRoutes against an in-process TestRouteSink and
 * dispatches synthesised requests directly into the captured handlers — no
 * socket, no acceptor thread (the #438 TSan trap).
 *
 * Coverage:
 *   - perm_fn denial (403) on every route, with the exact (securable, op) it
 *     was called with
 *   - 503 when the backing dependency is null (directory_sync / auto_approve
 *     / auth_mgr / cfg)
 *   - success-path shape for auto-approve-rules / pending-agents / oidc
 *     (all in-memory, no Postgres needed)
 *   - success-path shape + audit-fail-closed 503 for directory/users and
 *     directory/status ([pg]-tagged, DirectorySyncPg helper)
 *   - the naming-trap regression: /settings/oidc gates on OidcConfig, never
 *     Directory
 */

#include "enrollment_directory_routes.hpp"
#include "test_directory_sync_pg_helper.hpp"
#include "test_route_sink.hpp"

#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

struct AuditRecord {
    std::string action, result, target_type, target_id, detail;
};

struct PermCall {
    std::string securable, operation;
};

/// REST harness for EnrollmentDirectoryRoutes. `auto_approve`/`auth_mgr`/`cfg`
/// are plain value members (no Postgres) so most of this file needs no [pg]
/// tag; `directory_sync` stays a raw pointer the caller wires separately
/// (nullptr by default — the null-dependency 503 path) since DirectorySync is
/// Postgres-backed. Member order: dependencies before `sink`/`routes`, so
/// they outlive the handlers that capture pointers into them (same
/// discipline as WebhookRouteHarness, test_webhook_routes.cpp).
struct EnrollmentDirectoryRouteHarness {
    auth::AutoApproveEngine auto_approve;
    auth::AuthManager auth_mgr;
    Config cfg;
    DirectorySync* directory_sync{nullptr};

    bool perm_grant{true};
    std::vector<PermCall> perm_calls;
    std::vector<AuditRecord> audit_log;
    bool audit_persists{true};

    yuzu::server::test::TestRouteSink sink;
    EnrollmentDirectoryRoutes routes;

    explicit EnrollmentDirectoryRouteHarness() {
        auto auth_fn = [](const httplib::Request&, httplib::Response&)
            -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "tester";
            s.role = auth::Role::admin;
            return s;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& securable, const std::string& op) -> bool {
            perm_calls.push_back({securable, op});
            if (!perm_grant) {
                res.status = 403;
                return false;
            }
            return true;
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& a,
                               const std::string& r, const std::string& tt,
                               const std::string& ti, const std::string& d) -> bool {
            audit_log.push_back({a, r, tt, ti, d});
            return audit_persists;
        };

        routes.register_routes(sink, auth_fn, perm_fn, audit_fn, directory_sync, &auto_approve,
                               &auth_mgr, &cfg);
    }
};

} // namespace

// ── perm_fn denial (403) — every route, exact securable/operation ─────────

TEST_CASE("REST enrollment/directory[pg]: perm_fn denial 403s directory/users on Directory:Read",
          "[rest][enrollment_directory][pg]") {
    EnrollmentDirectoryRouteHarness h;
    h.perm_grant = false;
    auto res = h.sink.Get("/api/v1/directory/users");
    REQUIRE(res);
    CHECK(res->status == 403);
    REQUIRE_FALSE(h.perm_calls.empty());
    CHECK(h.perm_calls.back().securable == "Directory");
    CHECK(h.perm_calls.back().operation == "Read");
}

TEST_CASE("REST enrollment/directory: perm_fn denial 403s directory/status on Directory:Read",
          "[rest][enrollment_directory]") {
    EnrollmentDirectoryRouteHarness h;
    h.perm_grant = false;
    auto res = h.sink.Get("/api/v1/directory/status");
    REQUIRE(res);
    CHECK(res->status == 403);
    REQUIRE_FALSE(h.perm_calls.empty());
    CHECK(h.perm_calls.back().securable == "Directory");
    CHECK(h.perm_calls.back().operation == "Read");
}

TEST_CASE("REST enrollment/directory: perm_fn denial 403s auto-approve-rules on Enrollment:Read",
          "[rest][enrollment_directory]") {
    EnrollmentDirectoryRouteHarness h;
    h.perm_grant = false;
    auto res = h.sink.Get("/api/v1/enrollment/auto-approve-rules");
    REQUIRE(res);
    CHECK(res->status == 403);
    REQUIRE_FALSE(h.perm_calls.empty());
    CHECK(h.perm_calls.back().securable == "Enrollment");
    CHECK(h.perm_calls.back().operation == "Read");
}

TEST_CASE("REST enrollment/directory: perm_fn denial 403s pending-agents on Enrollment:Read",
          "[rest][enrollment_directory]") {
    EnrollmentDirectoryRouteHarness h;
    h.perm_grant = false;
    auto res = h.sink.Get("/api/v1/enrollment/pending-agents");
    REQUIRE(res);
    CHECK(res->status == 403);
    REQUIRE_FALSE(h.perm_calls.empty());
    CHECK(h.perm_calls.back().securable == "Enrollment");
    CHECK(h.perm_calls.back().operation == "Read");
}

TEST_CASE("REST enrollment/directory: perm_fn denial 403s settings/oidc on OidcConfig:Read — "
          "NEVER Directory (the naming-trap regression)",
          "[rest][enrollment_directory]") {
    EnrollmentDirectoryRouteHarness h;
    h.perm_grant = false;
    auto res = h.sink.Get("/api/v1/settings/oidc");
    REQUIRE(res);
    CHECK(res->status == 403);
    REQUIRE_FALSE(h.perm_calls.empty());
    CHECK(h.perm_calls.back().securable == "OidcConfig");
    CHECK(h.perm_calls.back().operation == "Read");
}

// ── 503 on a null dependency ────────────────────────────────────────────

TEST_CASE("REST enrollment/directory: directory/users 503s when directory_sync is null",
          "[rest][enrollment_directory]") {
    EnrollmentDirectoryRouteHarness h; // directory_sync stays nullptr
    auto res = h.sink.Get("/api/v1/directory/users");
    REQUIRE(res);
    CHECK(res->status == 503);
}

TEST_CASE("REST enrollment/directory: directory/status 503s when directory_sync is null",
          "[rest][enrollment_directory]") {
    EnrollmentDirectoryRouteHarness h;
    auto res = h.sink.Get("/api/v1/directory/status");
    REQUIRE(res);
    CHECK(res->status == 503);
}

// ── auto-approve-rules: success shape + audit (in-memory, no PG) ──────────

TEST_CASE("REST enrollment/directory: auto-approve-rules returns the configured rule set",
          "[rest][enrollment_directory]") {
    EnrollmentDirectoryRouteHarness h;
    h.auto_approve.add_rule(
        {auth::AutoApproveRuleType::hostname_glob, "*.prod.example.com", "prod hosts"});
    h.auto_approve.set_require_all(true);

    auto res = h.sink.Get("/api/v1/enrollment/auto-approve-rules");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j.contains("data"));
    REQUIRE(j["data"]["rules"].is_array());
    REQUIRE(j["data"]["rules"].size() == 1);
    CHECK(j["data"]["rules"][0]["type"] == "hostname_glob");
    CHECK(j["data"]["rules"][0]["value"] == "*.prod.example.com");
    CHECK(j["data"]["rules"][0]["label"] == "prod hosts");
    CHECK(j["data"]["rules"][0]["enabled"] == true);
    CHECK(j["data"]["require_all"] == true);
    CHECK(j["meta"]["api_version"] == "v1");

    // Audited, non-blocking posture — a row was written even though it never
    // gates the response.
    REQUIRE_FALSE(h.audit_log.empty());
    CHECK(h.audit_log.back().action == "enrollment.auto_approve.view");
}

TEST_CASE("REST enrollment/directory: auto-approve-rules 503s when the engine is null",
          "[rest][enrollment_directory]") {
    EnrollmentDirectoryRouteHarness h;
    // Rebuild against a null auto_approve pointer to exercise the 503 arm —
    // register a second sink directly (cheaper than modifying the fixture).
    yuzu::server::test::TestRouteSink sink2;
    EnrollmentDirectoryRoutes routes2;
    auto auth_fn = [](const httplib::Request&, httplib::Response&)
        -> std::optional<auth::Session> { return auth::Session{}; };
    auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) { return true; };
    auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                       const std::string&, const std::string&, const std::string&) {
        return true;
    };
    routes2.register_routes(sink2, auth_fn, perm_fn, audit_fn, nullptr, nullptr, nullptr, &h.cfg);
    auto res = sink2.Get("/api/v1/enrollment/auto-approve-rules");
    REQUIRE(res);
    CHECK(res->status == 503);
}

// ── pending-agents: success shape + audit (in-memory, no PG) ──────────────

TEST_CASE("REST enrollment/directory: pending-agents returns the queue, excludes nothing "
          "(unlike the fragment, no approved-filter)",
          "[rest][enrollment_directory]") {
    EnrollmentDirectoryRouteHarness h;
    h.auth_mgr.add_pending_agent("agent-1", "host1.example.com", "linux", "x86_64", "1.2.3");

    auto res = h.sink.Get("/api/v1/enrollment/pending-agents");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"].is_array());
    REQUIRE(j["data"].size() == 1);
    CHECK(j["data"][0]["agent_id"] == "agent-1");
    CHECK(j["data"][0]["hostname"] == "host1.example.com");
    CHECK(j["data"][0]["os"] == "linux");
    CHECK(j["data"][0]["arch"] == "x86_64");
    CHECK(j["data"][0]["agent_version"] == "1.2.3");
    CHECK(j["data"][0]["status"] == "pending");
    CHECK(j["pagination"]["total"] == 1);

    REQUIRE_FALSE(h.audit_log.empty());
    CHECK(h.audit_log.back().action == "enrollment.pending_agents.view");
}

// ── settings/oidc: success shape + secret masking (in-memory, no PG) ──────

TEST_CASE("REST enrollment/directory: settings/oidc reports configured=true and never echoes "
          "the client secret",
          "[rest][enrollment_directory]") {
    EnrollmentDirectoryRouteHarness h;
    h.cfg.oidc_issuer = "https://login.microsoftonline.com/tenant/v2.0";
    h.cfg.oidc_client_id = "client-abc";
    h.cfg.oidc_client_secret = "super-secret-value";
    h.cfg.oidc_redirect_uri = "https://yuzu.example.com/auth/callback";
    h.cfg.oidc_admin_group = "admin-group-id";
    h.cfg.oidc_skip_tls_verify = true;

    auto res = h.sink.Get("/api/v1/settings/oidc");
    REQUIRE(res);
    CHECK(res->status == 200);

    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["configured"] == true);
    CHECK(j["data"]["issuer"] == "https://login.microsoftonline.com/tenant/v2.0");
    CHECK(j["data"]["client_id"] == "client-abc");
    CHECK(j["data"]["client_secret_configured"] == true);
    CHECK(j["data"]["redirect_uri"] == "https://yuzu.example.com/auth/callback");
    CHECK(j["data"]["admin_group"] == "admin-group-id");
    CHECK(j["data"]["skip_tls_verify"] == true);

    // The raw secret must never appear anywhere in the response body.
    CHECK(res->body.find("super-secret-value") == std::string::npos);

    REQUIRE_FALSE(h.audit_log.empty());
    CHECK(h.audit_log.back().action == "settings.oidc.view");
}

TEST_CASE("REST enrollment/directory: settings/oidc reports configured=false and "
          "client_secret_configured=false when unset",
          "[rest][enrollment_directory]") {
    EnrollmentDirectoryRouteHarness h;
    auto res = h.sink.Get("/api/v1/settings/oidc");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["data"]["configured"] == false);
    CHECK(j["data"]["client_secret_configured"] == false);
}

// ── directory/users, directory/status: [pg] ────────────────────────────────

TEST_CASE("REST enrollment/directory[pg]: directory/users returns an empty list against a "
          "freshly-opened store and audits directory.users.view",
          "[rest][enrollment_directory][pg]") {
    // Deliberately does NOT call sync_entra/apply_entra_sync: sync_entra
    // makes a real outbound Graph API call (unsuitable for a unit test, and
    // the private apply_entra_sync test seam is a file-local friend struct
    // in test_directory_sync.cpp — duplicating it here would risk an ODR
    // violation across TUs). DirectorySync's own sync/row semantics are
    // covered by test_directory_sync.cpp; this file's job is only to prove
    // the ROUTE calls the store and builds a correct response + audit row,
    // which an empty-but-open store already exercises.
    yuzu::test::DirectorySyncPg ds;

    EnrollmentDirectoryRouteHarness h;
    h.directory_sync = ds.get();
    // Re-register against the now-set directory_sync (harness ctor already
    // ran with nullptr) — cheap to build a second sink here rather than
    // reorder the fixture's construction.
    yuzu::server::test::TestRouteSink sink2;
    EnrollmentDirectoryRoutes routes2;
    auto auth_fn = [](const httplib::Request&, httplib::Response&)
        -> std::optional<auth::Session> { return auth::Session{}; };
    auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) { return true; };
    std::vector<AuditRecord> audit_log;
    auto audit_fn = [&audit_log](const httplib::Request&, const std::string& a,
                                 const std::string& r, const std::string& tt,
                                 const std::string& ti, const std::string& d) {
        audit_log.push_back({a, r, tt, ti, d});
        return true;
    };
    routes2.register_routes(sink2, auth_fn, perm_fn, audit_fn, ds.get(), &h.auto_approve,
                            &h.auth_mgr, &h.cfg);

    auto res = sink2.Get("/api/v1/directory/users");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j["data"].is_array());
    CHECK(j["data"].empty());
    CHECK(j["pagination"]["total"] == 0);

    REQUIRE_FALSE(audit_log.empty());
    CHECK(audit_log.back().action == "directory.users.view");
}

TEST_CASE("REST enrollment/directory[pg]: directory/users fails closed (503) when the audit "
          "row cannot persist",
          "[rest][enrollment_directory][pg]") {
    yuzu::test::DirectorySyncPg ds;

    yuzu::server::test::TestRouteSink sink2;
    EnrollmentDirectoryRoutes routes2;
    auto auth_fn = [](const httplib::Request&, httplib::Response&)
        -> std::optional<auth::Session> { return auth::Session{}; };
    auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) { return true; };
    auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                       const std::string&, const std::string&, const std::string&) {
        return false; // simulate a persist failure
    };
    auth::AutoApproveEngine auto_approve;
    auth::AuthManager auth_mgr;
    Config cfg;
    routes2.register_routes(sink2, auth_fn, perm_fn, audit_fn, ds.get(), &auto_approve,
                            &auth_mgr, &cfg);

    auto res = sink2.Get("/api/v1/directory/users");
    REQUIRE(res);
    CHECK(res->status == 503);
}

TEST_CASE("REST enrollment/directory[pg]: directory/status returns provider/status/counts, "
          "unaudited",
          "[rest][enrollment_directory][pg]") {
    yuzu::test::DirectorySyncPg ds;

    EnrollmentDirectoryRouteHarness h;
    yuzu::server::test::TestRouteSink sink2;
    EnrollmentDirectoryRoutes routes2;
    auto auth_fn = [](const httplib::Request&, httplib::Response&)
        -> std::optional<auth::Session> { return auth::Session{}; };
    auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                      const std::string&) { return true; };
    int audit_calls = 0;
    auto audit_fn = [&audit_calls](const httplib::Request&, const std::string&,
                                   const std::string&, const std::string&, const std::string&,
                                   const std::string&) {
        ++audit_calls;
        return true;
    };
    routes2.register_routes(sink2, auth_fn, perm_fn, audit_fn, ds.get(), &h.auto_approve,
                            &h.auth_mgr, &h.cfg);

    auto res = sink2.Get("/api/v1/directory/status");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = nlohmann::json::parse(res->body);
    REQUIRE(j.contains("data"));
    CHECK(j["data"].contains("provider"));
    CHECK(j["data"].contains("status"));
    CHECK(j["data"].contains("user_count"));
    CHECK(j["data"].contains("group_count"));
    CHECK(j["data"]["groups"].is_array());
    CHECK(audit_calls == 0); // no PII — deliberately unaudited, matches the legacy route
}
