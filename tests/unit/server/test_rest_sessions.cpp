/**
 * test_rest_sessions.cpp — HTTP-level tests for session revocation REST.
 *
 * Covers `DELETE /api/v1/sessions?username=<name>` (admin force-logout) and
 * `DELETE /api/v1/sessions/me` (self-revoke). The DB primitive
 * `AuthDB::invalidate_all_sessions()` and the in-memory counterpart
 * `AuthManager::invalidate_user_sessions()` already had unit coverage; this
 * file pins the REST surface (auth gate, audit action selection, query
 * parameter validation, idempotency).
 *
 * Pattern: TestRouteSink + a stub session-revoke callback that records
 * (username, count) tuples. We do not stand up a real AuthManager / AuthDB
 * because the goal is the REST handler's logic, not the dual-write.
 */

#include "rest_api_v1.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>

#include <string>
#include <utility>
#include <vector>

using namespace yuzu::server;

namespace {

struct AuditRecord {
    std::string action;
    std::string result;
    std::string target_id;
    std::string detail;
};

struct RestSessionsHarness {
    yuzu::server::test::TestRouteSink sink;

    // Mock session state. The auth_fn closure captures by reference and
    // returns a session reflecting the current values.
    std::string session_user;
    auth::Role session_role{auth::Role::user};
    bool perm_should_grant{true};

    std::vector<AuditRecord> audit_log;
    std::vector<std::pair<std::string, std::size_t>> revoke_calls;
    std::size_t revoke_returns{0};

    RestApiV1 api;

    RestSessionsHarness() {
        auto auth_fn =
            [this](const httplib::Request&, httplib::Response& res)
            -> std::optional<auth::Session> {
            if (session_user.empty()) {
                res.status = 401;
                return std::nullopt;
            }
            auth::Session s;
            s.username = session_user;
            s.role = session_role;
            return s;
        };

        // perm_fn returns the harness-controlled flag. When false it sets
        // 403 like the real require_permission would (so we exercise the
        // admin gate path on the admin DELETE route).
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string&, const std::string&) -> bool {
            if (perm_should_grant)
                return true;
            res.status = 403;
            return false;
        };

        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string&,
                               const std::string& target_id, const std::string& detail) {
            audit_log.push_back({action, result, target_id, detail});
        };

        auto session_revoke_fn = [this](const std::string& username) -> std::size_t {
            revoke_calls.emplace_back(username, revoke_returns);
            return revoke_returns;
        };

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr,
                            /*mgmt_store=*/nullptr,
                            /*token_store=*/nullptr,
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
                            /*sw_deploy_store=*/nullptr,
                            /*device_token_store=*/nullptr,
                            /*license_store=*/nullptr,
                            /*guaranteed_state_store=*/nullptr,
                            std::move(session_revoke_fn));
    }
};

} // namespace

TEST_CASE("REST DELETE /api/v1/sessions: admin can force-logout another user",
          "[rest][session][revoke][admin]") {
    RestSessionsHarness h;
    h.session_user = "root";
    h.session_role = auth::Role::admin;
    h.revoke_returns = 2;

    auto res = h.sink.Delete("/api/v1/sessions?username=alice");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("\"revoked\":2") != std::string::npos);
    CHECK(res->body.find("\"username\":\"alice\"") != std::string::npos);

    REQUIRE(h.revoke_calls.size() == 1);
    CHECK(h.revoke_calls[0].first == "alice");

    // Audit: action is `session.revoke_all` (cross-user), not the self
    // variant — forensics must be able to distinguish the two.
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "session.revoke_all");
    CHECK(h.audit_log[0].result == "success");
    CHECK(h.audit_log[0].target_id == "alice");
    CHECK(h.audit_log[0].detail == "count=2");
}

TEST_CASE("REST DELETE /api/v1/sessions: non-admin caller is rejected by perm gate",
          "[rest][session][revoke][rbac]") {
    RestSessionsHarness h;
    h.session_user = "bob";
    h.session_role = auth::Role::user;
    h.perm_should_grant = false;

    auto res = h.sink.Delete("/api/v1/sessions?username=alice");
    REQUIRE(res);
    CHECK(res->status == 403);

    // Crucial: the revoke callback must NOT have fired. The 403 is the
    // gate, the callback only runs after perm_fn returns true.
    CHECK(h.revoke_calls.empty());
    // Audit emission for the 403 is the perm gate's job (require_permission
    // emits `auth.permission_required` denied), not this handler's. So
    // this fixture's audit_log stays empty here.
    CHECK(h.audit_log.empty());
}

TEST_CASE("REST DELETE /api/v1/sessions: admin self-revoke audits as 'self'",
          "[rest][session][revoke][self]") {
    RestSessionsHarness h;
    h.session_user = "root";
    h.session_role = auth::Role::admin;
    h.revoke_returns = 1;

    // Admin requesting their own username via the admin path. Allowed
    // (recoverable — operator just re-auths) but the audit row records
    // `session.revoke_all.self` so SIEM can split operator self-service
    // from a sibling-admin force-logout.
    auto res = h.sink.Delete("/api/v1/sessions?username=root");
    REQUIRE(res);
    CHECK(res->status == 200);

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "session.revoke_all.self");
    CHECK(h.audit_log[0].target_id == "root");
}

TEST_CASE("REST DELETE /api/v1/sessions: missing username 400s without revoke",
          "[rest][session][revoke][validation]") {
    RestSessionsHarness h;
    h.session_user = "root";
    h.session_role = auth::Role::admin;

    auto res = h.sink.Delete("/api/v1/sessions");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(res->body.find("username") != std::string::npos);
    CHECK(h.revoke_calls.empty());
    CHECK(h.audit_log.empty());
}

TEST_CASE("REST DELETE /api/v1/sessions: idempotent for unknown user (count=0)",
          "[rest][session][revoke][idempotent]") {
    RestSessionsHarness h;
    h.session_user = "root";
    h.session_role = auth::Role::admin;
    h.revoke_returns = 0; // no in-memory sessions for the username

    auto res = h.sink.Delete("/api/v1/sessions?username=ghost");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("\"revoked\":0") != std::string::npos);

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].detail == "count=0");
}

TEST_CASE("REST DELETE /api/v1/sessions/me: any authenticated user can self-revoke",
          "[rest][session][revoke][me]") {
    RestSessionsHarness h;
    h.session_user = "alice";
    h.session_role = auth::Role::user;
    h.revoke_returns = 3;
    // perm gate is *not* called on the /me route — auth alone is enough.
    h.perm_should_grant = false;

    auto res = h.sink.Delete("/api/v1/sessions/me");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find("\"revoked\":3") != std::string::npos);

    REQUIRE(h.revoke_calls.size() == 1);
    CHECK(h.revoke_calls[0].first == "alice");

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "session.revoke_all.self");
    CHECK(h.audit_log[0].target_id == "alice");
    CHECK(h.audit_log[0].detail == "count=3");
}

TEST_CASE("REST DELETE /api/v1/sessions/me: unauthenticated request is rejected",
          "[rest][session][revoke][me][auth]") {
    RestSessionsHarness h;
    // session_user empty → auth_fn returns nullopt and sets 401.

    auto res = h.sink.Delete("/api/v1/sessions/me");
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK(h.revoke_calls.empty());
    CHECK(h.audit_log.empty());
}
