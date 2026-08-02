/**
 * test_require_list_read.cpp — ADR-0017 #2473: the require_list_read wrapper.
 *
 * Drives AuthRoutes::require_list_read for a HUMAN (cookie) principal against a
 * real RbacStore + ManagementGroupStore + AuditStore, exercising the standard
 * admit-then-filter branch and the ListReadGate mapping:
 *   DenyAll   -> !admitted (403)
 *   AdmitAll  -> admitted, scope == nullopt   (unfiltered)
 *   AdmitScoped(set) -> admitted, scope == set (a VALUE even when empty -> zero
 *                       rows: the UP-14 / INV-2 contract, structurally distinct
 *                       from nullopt so a route cannot render empty as unfiltered)
 * plus the is_list_read audit flag on the denial row.
 *
 * The cookie principal itself is PG-free: a default AuthManager (config-file-only,
 * no AuthDB) mints the session in-memory via create_local_session, and
 * api_token_store is nullptr (the cookie branch of resolve_session never
 * dereferences it). The ManagementGroupStore it filters through, however, is
 * born-on-Postgres since the ADR-0042 migration, so the fixture is PG-gated:
 * skips when YUZU_TEST_POSTGRES_DSN is unset, fails when set-but-broken
 * (test_helpers.hpp skip-vs-fail contract). The ENGINE-principal branch (503/403,
 * RBAC-only, never legacy-open) needs the PG token harness and lives in the
 * sibling test_require_list_read_engine.cpp.
 */

#include "analytics_event_store.hpp"
#include "audit_store.hpp"
#include "auth_routes.hpp"
#include "management_group_store.hpp"
#include "oidc_provider.hpp"
#include "rbac_store.hpp"

#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp> // Config

#include <catch2/catch_test_macros.hpp>
#include <httplib.h>

#include <memory>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>

using namespace yuzu::server;

namespace {

// PG-backed ManagementGroupStore over its own migrated template clone (ADR-0042
// made this store Postgres-only). A distinct template name keeps the
// PgTestTemplate registry entry separate from sibling suites.
void setup_list_read_mgmt_template(const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    ManagementGroupStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("require_list_read mgmt template: store failed to migrate");
}

yuzu::test::PgTestTemplate list_read_mgmt_template{"listread_mgmt",
                                                   &setup_list_read_mgmt_template};

/// AuthRoutes rig: cookie auth (no ApiTokenStore), a SQLite RbacStore, and a
/// PG-backed ManagementGroupStore. RBAC enforcement ON so the standard branch
/// runs the real admit-then-filter gate.
struct ListReadRig {
    Config cfg{};
    auth::AuthManager auth_mgr{};
    RbacStore rbac{":memory:"};
    std::optional<yuzu::test::PostgresTestDb> mgmt_db;
    std::optional<yuzu::server::pg::PgPool> mgmt_pool;
    std::unique_ptr<ManagementGroupStore> mgmt;
    AuditStore audit{":memory:"};
    yuzu::test::TempDbFile an_db{"yuzu_test_rlr_an-"};
    std::unique_ptr<AnalyticsEventStore> analytics;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    std::unique_ptr<AuthRoutes> ar;

    ListReadRig() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        mgmt_db.emplace(list_read_mgmt_template);
        REQUIRE(mgmt_db->available());
        mgmt_pool.emplace(yuzu::server::pg::PgPool::Options{.conninfo = mgmt_db->dsn(), .size = 4});
        REQUIRE(mgmt_pool->valid());
        mgmt = std::make_unique<ManagementGroupStore>(*mgmt_pool);
        REQUIRE(mgmt->is_open());

        analytics = std::make_unique<AnalyticsEventStore>(an_db.path);
        REQUIRE(rbac.is_open());
        REQUIRE(audit.is_open());
        rbac.set_rbac_enabled(true); // enforcement in effect
        REQUIRE(rbac.create_role({"RespReader", "", false, 0}).has_value());
        REQUIRE(rbac.set_permission({"RespReader", "Response", "Read", "allow"}).has_value());
        // No upsert_user: after the AuthDB->PG migration (#2394) that needs a PG
        // AuthDB. We only need an in-memory SESSION, which create_local_session
        // mints directly (in-memory session store, no AuthDB) — see as_op().
        ar = std::make_unique<AuthRoutes>(cfg, auth_mgr, &rbac, /*api_token_store=*/nullptr, &audit,
                                          mgmt.get(), /*tag_store=*/nullptr, analytics.get(),
                                          oidc_mu, oidc_provider);
    }

    // A cookie-authenticated request as human user "op" — session minted in
    // memory (no AuthDB), principal_kind defaults to "human", mcp_tier and
    // token_scope_service empty, so require_list_read takes the standard branch.
    httplib::Request as_op() {
        auto cookie = auth_mgr.create_local_session("op", auth::Role::user, /*mfa_verified=*/true);
        REQUIRE_FALSE(cookie.empty());
        httplib::Request req;
        req.headers.emplace("Cookie", "yuzu_session=" + cookie);
        return req;
    }

    std::string make_group(const std::string& name, const std::string& parent = "") {
        ManagementGroup g;
        g.name = name;
        g.membership_type = "static";
        g.parent_id = parent;
        auto id = mgmt->create_group(g);
        REQUIRE(id.has_value());
        return *id;
    }
};

} // namespace

TEST_CASE("require_list_read: global grant -> AdmitAll (admitted, unfiltered)",
          "[pg][auth_routes][list_read]") {
    ListReadRig r;
    REQUIRE(r.rbac.assign_role({"user", "op", "RespReader"}).has_value()); // GLOBAL grant
    auto req = r.as_op();
    httplib::Response res;
    auto gate = r.ar->require_list_read(req, res, "Response", "Read");
    CHECK(gate.admitted);
    CHECK_FALSE(gate.scope.has_value()); // nullopt == unfiltered
}

TEST_CASE("require_list_read: confined operator -> AdmitScoped to group members",
          "[pg][auth_routes][list_read]") {
    ListReadRig r;
    auto g = r.make_group("G1");
    REQUIRE(r.mgmt->add_member(g, "agent-1").has_value());
    REQUIRE(r.mgmt->add_member(g, "agent-2").has_value());
    REQUIRE(r.mgmt->assign_role({g, "user", "op", "RespReader"}).has_value()); // group-scoped only
    auto req = r.as_op();
    httplib::Response res;
    auto gate = r.ar->require_list_read(req, res, "Response", "Read");
    CHECK(gate.admitted);
    REQUIRE(gate.scope.has_value()); // a filter set, not unfiltered
    CHECK(gate.scope->size() == 2);
}

TEST_CASE("require_list_read: confined on an EMPTY group -> AdmitScoped with empty scope (UP-14)",
          "[pg][auth_routes][list_read]") {
    ListReadRig r;
    auto g = r.make_group("Empty"); // holds the grant but has zero members
    REQUIRE(r.mgmt->assign_role({g, "user", "op", "RespReader"}).has_value());
    auto req = r.as_op();
    httplib::Response res;
    auto gate = r.ar->require_list_read(req, res, "Response", "Read");
    CHECK(gate.admitted);
    REQUIRE(gate.scope.has_value()); // a VALUE (not nullopt) — the zero-rows contract
    CHECK(gate.scope->empty());      // empty set => WHERE agent_id IN () => zero rows, never fleet
}

TEST_CASE("require_list_read: no grant -> DenyAll 403 + is_list_read audit row",
          "[pg][auth_routes][list_read]") {
    ListReadRig r;
    auto req = r.as_op();
    httplib::Response res;
    auto gate = r.ar->require_list_read(req, res, "Response", "Read");
    CHECK_FALSE(gate.admitted);
    CHECK(res.status == 403);
    CHECK_FALSE(gate.scope.has_value());

    // The denial is stamped is_list_read (shared verb + the flag, #2473).
    AuditQuery q;
    q.is_list_read = true;
    auto rows = r.audit.query(q);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].action == "auth.permission_required");
    CHECK(rows[0].result == "denied");
}

TEST_CASE("require_list_read: RBAC loaded-and-disabled -> legacy-open AdmitAll",
          "[pg][auth_routes][list_read]") {
    ListReadRig r;
    r.rbac.set_rbac_enabled(false); // loaded & disabled -> legacy-open (not a corrupt store)
    auto req = r.as_op();
    httplib::Response res;
    auto gate = r.ar->require_list_read(req, res, "Response", "Read");
    CHECK(gate.admitted);
    CHECK_FALSE(gate.scope.has_value()); // unfiltered
}
