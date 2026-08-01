/**
 * test_schedule_routes.cpp — route-handler coverage for POST /api/schedules
 * (governance remediation of the PR #1806 adversarial review; finding H-01).
 *
 * A created schedule fires unattended through ScheduleRunner::tick() with NO
 * per-fire permission check — there is no operator session on that
 * background-thread path, so schedule creation is the ONLY gate standing
 * between a principal and fleet-wide command dispatch (empty
 * scope_expression == send-to-all, default requires_approval == false ==
 * no approval gate). This test drives handle_create_schedule (extracted from
 * the inline server.cpp lambda for exactly this reason) against a REAL
 * RbacStore + AuthRoutes + ScheduleEngine and proves:
 *   - a principal with Schedule:Write but WITHOUT Execution:Execute is
 *     denied 403 and creates NO schedule row (H-01's falsifier — reverting
 *     the Execution:Execute check in schedule_routes.cpp makes this fail),
 *   - the symmetric case (Execution:Execute without Schedule:Write) is
 *     also denied,
 *   - a principal with BOTH permissions succeeds and the schedule is
 *     attributed to them via created_by.
 */

#include "schedule_routes.hpp"

#include "auth_routes.hpp"
#include "analytics_event_store.hpp"
#include "api_token_store.hpp"
#include "test_api_token_pg_helper.hpp" // ApiTokenStorePg — PR 4.1 PG port
#include "oidc_provider.hpp"
#include "pg/pg_pool.hpp"
#include "rbac_store.hpp"
#include "schedule_engine.hpp"
#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <sqlite3.h>

#include <filesystem>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::server;

namespace {

struct TestDb {
    sqlite3* db = nullptr;
    TestDb() { sqlite3_open(":memory:", &db); }
    ~TestDb() {
        if (db)
            sqlite3_close(db);
    }
};

// Pre-migrated template for RbacStore (PG port). Shares the "rbacstore" key
// with test_rbac_store.cpp's own template (identical setup, replay-verified
// — docs/postgres-store-playbook.md step 7). ScheduleRouteHarness needs a
// REAL RbacStore (not just an open one) — H-01's permission-gate assertions
// exercise create_role/set_permission/assign_role for real.
yuzu::test::PgTestTemplate schedule_rbac_tpl{
    "rbacstore", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        yuzu::server::RbacStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("rbac template: store failed to migrate/seed");
    }};

/// Real AuthRoutes + real RbacStore + real ScheduleEngine, wired so
/// handle_create_schedule's permission-gate ordering has genuine end-to-end
/// coverage — no stubbed require_permission that could pass regardless of
/// what schedule_routes.cpp actually checks.
struct ScheduleRouteHarness {
    Config cfg{};
    auth::AuthManager auth_mgr{};
    // rbac_db/rbac_pool must outlive rbac (declaration order = destruction
    // order); std::optional so the PG SKIP-if-no-DSN check can run before
    // any of them are constructed (RbacStore is neither movable nor
    // copyable, so they can't be built as locals and moved in).
    std::optional<yuzu::test::PostgresTestDb> rbac_db;
    std::optional<yuzu::server::pg::PgPool> rbac_pool;
    std::optional<RbacStore> rbac;
    TestDb sdb;
    ScheduleEngine schedule_engine{sdb.db};
    yuzu::test::TempDir tmp;
    // ApiTokenStore ported to Postgres (PR 4.1) — SKIPs the current TEST_CASE
    // when YUZU_TEST_POSTGRES_DSN is unset, FAILs when set but broken.
    // api_tokens removed (PR 4.1 review #3): this fixture never calls a token
    // store method, and AuthRoutes null-guards the pointer, so it gets nullptr
    // below — embedding the PG fixture only made every case skip without a DSN.
    std::unique_ptr<AnalyticsEventStore> analytics;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    std::unique_ptr<AuthRoutes> auth_routes;

    ScheduleRouteHarness() {
        // Manual equivalent of YUZU_REQUIRE_PG_DB_TPL (test_helpers.hpp) — the
        // macro declares a local, non-movable PostgresTestDb, so it can't be
        // used directly to populate a data member; emplace() constructs
        // rbac_db/rbac_pool/rbac in place instead.
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        rbac_db.emplace(schedule_rbac_tpl);
        INFO("[ScheduleRouteHarness rbac fixture] status (blank == came up OK): "
             << rbac_db->error());
        REQUIRE(rbac_db->available());
        rbac_pool.emplace(
            yuzu::server::pg::PgPool::Options{.conninfo = rbac_db->dsn(), .size = 4});
        REQUIRE(rbac_pool->valid());
        rbac.emplace(*rbac_pool);
        REQUIRE(rbac->is_open());

        schedule_engine.create_tables();
        rbac->set_rbac_enabled(true);

        // TempDir only computes a unique path; it does not create the
        // directory (see test_helpers.hpp), so create it before any store
        // tries to open a file underneath it.
        std::filesystem::create_directories(tmp.path);

        analytics = std::make_unique<AnalyticsEventStore>(tmp.path / "analytics.db");

        auth_routes = std::make_unique<AuthRoutes>(
            cfg, auth_mgr, &*rbac, /*api_token_store=*/nullptr,
            /*audit_store=*/nullptr, /*mgmt_group_store=*/nullptr,
            /*tag_store=*/nullptr, analytics.get(), oidc_mu, oidc_provider);
    }

    /// Create a user, a role granting exactly `perms`
    /// ({securable_type, operation} pairs), assign the role, and return a
    /// request carrying a valid session cookie for that user.
    httplib::Request
    session_request_for(const std::string& username, const std::string& role_name,
                        const std::vector<std::pair<std::string, std::string>>& perms) {
        REQUIRE(auth_mgr.upsert_user(username, username + "-password1", auth::Role::user));
        REQUIRE(rbac->create_role({.name = role_name}).has_value());
        for (const auto& [type, op] : perms) {
            REQUIRE(rbac->set_permission({.role_name = role_name,
                                         .securable_type = type,
                                         .operation = op,
                                         .effect = "allow"})
                        .has_value());
        }
        REQUIRE(rbac->assign_role({.principal_type = "user",
                                   .principal_id = username,
                                   .role_name = role_name})
                    .has_value());

        auto cookie = auth_mgr.authenticate(username, username + "-password1");
        REQUIRE(cookie.has_value());
        httplib::Request req;
        req.headers.emplace("Cookie", "yuzu_session=" + *cookie);
        return req;
    }
};

} // namespace

TEST_CASE("POST /api/schedules: Schedule:Write alone is rejected without Execution:Execute (H-01)",
          "[server][schedule][h01][rest][pg]") {
    ScheduleRouteHarness h;
    auto req = h.session_request_for("sched-writer", "ScheduleOnly", {{"Schedule", "Write"}});
    req.body = R"({"name":"nightly-scan","definition_id":"def-1","frequency_type":"daily"})";

    httplib::Response res;
    handle_create_schedule(*h.auth_routes, &h.schedule_engine, req, res);

    CHECK(res.status == 403);
    CHECK(h.schedule_engine.query_schedules().empty());
}

TEST_CASE("POST /api/schedules: Execution:Execute alone is rejected without Schedule:Write",
          "[server][schedule][h01][rest][pg]") {
    ScheduleRouteHarness h;
    auto req = h.session_request_for("exec-only", "ExecuteOnly", {{"Execution", "Execute"}});
    req.body = R"({"name":"nightly-scan","definition_id":"def-1","frequency_type":"daily"})";

    httplib::Response res;
    handle_create_schedule(*h.auth_routes, &h.schedule_engine, req, res);

    CHECK(res.status == 403);
    CHECK(h.schedule_engine.query_schedules().empty());
}

TEST_CASE("POST /api/schedules: Schedule:Write + Execution:Execute together create the schedule",
          "[server][schedule][h01][rest][pg]") {
    ScheduleRouteHarness h;
    auto req = h.session_request_for("sched-op", "ScheduleAndExecute",
                                     {{"Schedule", "Write"}, {"Execution", "Execute"}});
    req.body = R"({"name":"nightly-scan","definition_id":"def-1","frequency_type":"daily"})";

    httplib::Response res;
    handle_create_schedule(*h.auth_routes, &h.schedule_engine, req, res);

    CHECK(res.status != 403);
    auto scheds = h.schedule_engine.query_schedules();
    REQUIRE(scheds.size() == 1);
    CHECK(scheds[0].name == "nightly-scan");
    CHECK(scheds[0].created_by == "sched-op");

    auto body = nlohmann::json::parse(res.body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK(body.value("id", "") == scheds[0].id);
}
