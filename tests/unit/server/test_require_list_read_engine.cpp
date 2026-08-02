/**
 * test_require_list_read_engine.cpp — ADR-0017 #2473: the ENGINE-principal branch
 * of AuthRoutes::require_list_read.
 *
 * The PG-free human/cookie coverage (standard admit-then-filter branch + the
 * AdmitScoped-empty zero-rows contract) lives in test_require_list_read.cpp.
 * This file covers the one branch that needs a real engine credential — an
 * engine API token minted against a PG-backed ApiTokenStore + EnginePrincipalStore,
 * exactly as server.cpp wires them (mirrors test_engine_principal_integration.cpp
 * §6's EngineRbacGateFixture).
 *
 * The invariant under test (external-review Blocker 1, class of #2202): engine
 * principals are RBAC-ONLY. require_list_read's engine branch must reproduce
 * require_permission's engine branch exactly —
 *   - RBAC store unavailable            -> 503, not admitted
 *   - RBAC disabled (the DEFAULT!)      -> 403, NEVER the legacy-open fallthrough
 *   - RBAC enabled, no grant            -> 403
 *   - RBAC enabled, fleet-wide grant    -> AdmitAll, scope == nullopt (unfiltered)
 * and — the list-gate-specific half — an engine is AdmitAll or DenyAll, NEVER
 * AdmitScoped (engine grants are fleet-wide only, #2485), so an admitted engine's
 * scope is always nullopt. Every denial stamps is_list_read on the audit row.
 *
 * PG-gated: ApiTokenStore + EnginePrincipalStore are born-on-Postgres (ADR-0006).
 * Skips when YUZU_TEST_POSTGRES_DSN is unset; fails when set-but-broken
 * (test_helpers.hpp skip-vs-fail contract).
 */

#include "analytics_event_store.hpp"
#include "api_token_store.hpp"
#include "audit_store.hpp"
#include "auth_routes.hpp"
#include "engine_principal_store.hpp"
#include "oidc_provider.hpp"
#include "rbac_store.hpp"

#include "test_api_token_pg_helper.hpp" // ApiTokenStorePgShared

#include "pg/pg_pool.hpp"

#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp> // Config

#include <catch2/catch_test_macros.hpp>
#include <httplib.h>

#include <chrono>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>

#include "../test_helpers.hpp"

using namespace yuzu::server;

namespace {

std::int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// PG-backed EnginePrincipalStore over its own migrated template clone. A distinct
// template name keeps the PgTestTemplate registry entry separate from the sibling
// engine tests (no shared-state risk between files).
void setup_engine_principal_store_pg_template(const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    EnginePrincipalStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("engine_principal (list-read) template: store failed to migrate");
}

yuzu::test::PgTestTemplate engine_principal_listread_template{
    "engineprincipal_listread", &setup_engine_principal_store_pg_template};

class EnginePrincipalStorePg {
public:
    EnginePrincipalStorePg() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        db_.emplace(engine_principal_listread_template);
        REQUIRE(db_->available());
        pool_.emplace(yuzu::server::pg::PgPool::Options{.conninfo = db_->dsn(), .size = 4});
        REQUIRE(pool_->valid());
        store_ = std::make_unique<EnginePrincipalStore>(*pool_);
        REQUIRE(store_->is_open());
    }

    EnginePrincipalStorePg(const EnginePrincipalStorePg&) = delete;
    EnginePrincipalStorePg& operator=(const EnginePrincipalStorePg&) = delete;

    [[nodiscard]] EnginePrincipalStore* get() const noexcept { return store_.get(); }
    EnginePrincipalStore* operator->() const noexcept { return store_.get(); }

private:
    std::optional<yuzu::test::PostgresTestDb> db_;
    std::optional<yuzu::server::pg::PgPool> pool_;
    std::unique_ptr<EnginePrincipalStore> store_;
};

/// Wires a real (PG-backed) engine principal + a mintable engine API token, plus
/// an in-memory AuditStore/AnalyticsEventStore/ManagementGroupStore so the audit
/// flag and the never-AdmitScoped contract are both observable. Each test then
/// constructs the AuthRoutes/RbacStore combination it wants to exercise via make().
struct EngineListReadFixture {
    Config cfg{};
    auth::AuthManager auth_mgr{};
    yuzu::test::ApiTokenStorePgShared api_tokens;
    EnginePrincipalStorePg engine_store;
    AuditStore audit{":memory:"};
    yuzu::test::TempDbFile an_db{"yuzu_test_rlr_engine_an-"};
    std::unique_ptr<AnalyticsEventStore> analytics;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    std::string raw_token;
    std::unique_ptr<AuthRoutes> ar;

    EngineListReadFixture() {
        REQUIRE(audit.is_open());
        analytics = std::make_unique<AnalyticsEventStore>(an_db.path);
        REQUIRE(engine_store->create("Vuln Sync", "alice", "cloud IAM parity", "internal", "admin",
                                     "engine:vuln")
                   .has_value());
        api_tokens->set_engine_referent_check(
            [&](const std::string& id) { return engine_store->get_for_auth(id).status; });
        auto raw = api_tokens->create_token("engine-token", "engine:vuln", now_epoch() + 3600, "",
                                            "readonly", "engine");
        REQUIRE(raw.has_value());
        raw_token = *raw;
    }

    // Build the AuthRoutes under test. `rbac` may be nullptr to model an
    // unavailable RBAC store (the 503 branch).
    void make(RbacStore* rbac) {
        // mgmt_group_store=nullptr is deliberate: the engine branch returns before
        // authorize_list_read, so it never dereferences the mgmt store (and an
        // engine is fleet-wide only — never AdmitScoped, so no group resolution).
        ar = std::make_unique<AuthRoutes>(cfg, auth_mgr, rbac, api_tokens.get(), &audit,
                                          /*mgmt_group_store=*/nullptr,
                                          /*tag_store=*/nullptr, analytics.get(), oidc_mu,
                                          oidc_provider);
        ar->set_engine_principal_store(engine_store.get());
    }

    httplib::Request request() const {
        httplib::Request req;
        req.headers.emplace("Authorization", "Bearer " + raw_token);
        return req;
    }

    // Count of list-read denial rows currently in the audit log.
    std::size_t list_read_denials() {
        AuditQuery q;
        q.is_list_read = true;
        return audit.query(q).size();
    }
};

} // namespace

TEST_CASE("require_list_read engine: RBAC store unavailable -> 503, not admitted",
          "[pg][auth_routes][list_read][engine_principal][rbac]") {
    EngineListReadFixture fix;
    fix.make(/*rbac=*/nullptr); // models a store that never opened -> same 503 branch

    auto req = fix.request();
    httplib::Response res;
    auto gate = fix.ar->require_list_read(req, res, "Inventory", "Read");
    CHECK_FALSE(gate.admitted);
    CHECK(res.status == 503);
    CHECK_FALSE(gate.scope.has_value());
    CHECK(fix.list_read_denials() == 1); // stamped is_list_read even on the 503
}

TEST_CASE("require_list_read engine: RBAC disabled (default) -> 403, no legacy-open fallthrough",
          "[pg][auth_routes][list_read][engine_principal][rbac]") {
    EngineListReadFixture fix;
    auto db = yuzu::test::TempDbFile{"yuzu_test_rlr_engine_off-"};
    RbacStore rbac(db.path);
    REQUIRE(rbac.is_open());
    REQUIRE_FALSE(rbac.is_rbac_enabled()); // default-off: the hazard posture
    fix.make(&rbac);

    auto req = fix.request();
    httplib::Response res;
    auto gate = fix.ar->require_list_read(req, res, "Inventory", "Read");
    // The whole point of Blocker 1: an engine with RBAC off gets NOTHING, never
    // the fleet the legacy-open standard-branch fallback would hand a human.
    CHECK_FALSE(gate.admitted);
    CHECK(res.status == 403);
    CHECK_FALSE(gate.scope.has_value());

    // The denial is a list-read authorization row (shared verb + the flag).
    AuditQuery q;
    q.is_list_read = true;
    auto rows = fix.audit.query(q);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].action == "auth.permission_required");
    CHECK(rows[0].result == "denied");
}

TEST_CASE("require_list_read engine: RBAC enabled but no grant -> 403 DenyAll",
          "[pg][auth_routes][list_read][engine_principal][rbac]") {
    EngineListReadFixture fix;
    auto db = yuzu::test::TempDbFile{"yuzu_test_rlr_engine_nogrant-"};
    RbacStore rbac(db.path);
    REQUIRE(rbac.is_open());
    rbac.set_rbac_enabled(true); // enabled, but this engine holds no assignment
    fix.make(&rbac);

    auto req = fix.request();
    httplib::Response res;
    auto gate = fix.ar->require_list_read(req, res, "Inventory", "Read");
    CHECK_FALSE(gate.admitted);
    CHECK(res.status == 403);
    CHECK(fix.list_read_denials() == 1);
}

TEST_CASE("require_list_read engine: fleet-wide grant -> AdmitAll, scope==nullopt (never scoped)",
          "[pg][auth_routes][list_read][engine_principal][rbac]") {
    EngineListReadFixture fix;
    auto db = yuzu::test::TempDbFile{"yuzu_test_rlr_engine_grant-"};
    RbacStore rbac(db.path);
    REQUIRE(rbac.is_open());
    rbac.set_rbac_enabled(true);
    REQUIRE(rbac.create_role({.name = "EngineReader", .description = "d"}).has_value());
    REQUIRE(rbac.set_permission({"EngineReader", "Inventory", "Read", "allow"}).has_value());
    REQUIRE(rbac.assign_role({"engine", "engine:vuln", "EngineReader"}).has_value());
    fix.make(&rbac);

    auto req = fix.request();
    httplib::Response res;
    auto gate = fix.ar->require_list_read(req, res, "Inventory", "Read");
    CHECK(gate.admitted);
    // An engine grant is fleet-wide only (#2485) — the engine branch returns
    // AdmitAll (unfiltered) and NEVER AdmitScoped, so scope is always nullopt.
    // Structurally, a route cannot narrow an admitted engine to a group.
    CHECK_FALSE(gate.scope.has_value());
    CHECK(fix.list_read_denials() == 0); // an admit writes no denial row

    // Regression: an operation the grant does NOT cover is still denied — proves
    // this isn't silently falling through to a fleet-wide legacy path.
    httplib::Response res2;
    auto gate2 = fix.ar->require_list_read(req, res2, "Inventory", "Write");
    CHECK_FALSE(gate2.admitted);
    CHECK(res2.status == 403);
}
