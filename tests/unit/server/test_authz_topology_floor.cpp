/**
 * test_authz_topology_floor.cpp — coverage for the #2376 "topology floor":
 * a fresh install runs with RBAC OFF, and with RBAC off
 * `AuthRoutes::require_permission`/`require_scoped_permission` fall through
 * to a legacy branch that allows every `Read` to any authenticated
 * non-engine session. That legacy rule handed a plain `user` fleet-wide read
 * of the authorization TOPOLOGY itself — the access-review export (SOC 2
 * CC6.2 evidence), the RBAC role graph, and the engine-principal grant
 * graph. `authz_topology_floor.hpp`'s `kTopologyFloor` set closes exactly
 * that gap, and ONLY inside the RBAC-off legacy fallback — it must never run
 * ahead of (or instead of) a live RBAC grant, or it destroys the very
 * `Reviewer`/`AccessReview:Read` carve-out #2324 cut the securable for.
 *
 * See `server/core/src/authz_topology_floor.hpp` for the full rationale and
 * `server/core/src/auth_routes.cpp`'s two (require_permission/
 * require_scoped_permission) legacy-branch call sites.
 */

#include "auth_routes.hpp"
#include "authz_topology_floor.hpp"

#include "api_token_store.hpp"
#include "audit_store.hpp"
#include "engine_principal_store.hpp"
#include "oidc_provider.hpp"
#include "rbac_store.hpp"
#include "sqlite_raii.hpp"

#include "../test_helpers.hpp"

#include "pg/pg_pool.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <httplib.h>
#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

/// Wires a real (SQLite-backed) RbacStore + AuditStore behind AuthRoutes, so
/// each test only has to mint a cookie session and call
/// require_permission/require_scoped_permission directly — no ApiTokenStore
/// (PG-backed) or engine-principal machinery needed for the human-session
/// matrix below (`api_token_store=nullptr`; AuthRoutes null-guards it, and
/// resolve_session's cookie branch never touches it — mirrors
/// test_auth_routes_hardened.cpp's HardenedHarness).
struct FloorFixture {
    yuzu::test::TempDbFile rbac_db_file{"yuzu_test_authz_floor_rbac_"};
    yuzu::test::TempDbFile audit_db_file{"yuzu_test_authz_floor_audit_"};
    Config cfg{};
    yuzu::MetricsRegistry metrics;
    auth::AuthManager auth_mgr{};
    RbacStore rbac_store{rbac_db_file.path};
    std::unique_ptr<AuditStore> audit_store;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    std::unique_ptr<AuthRoutes> ar;

    FloorFixture() {
        REQUIRE(rbac_store.is_open());
        audit_store = std::make_unique<AuditStore>(audit_db_file.path);
        REQUIRE(audit_store->is_open());
        auth_mgr.set_metrics_registry(&metrics);
        ar = std::make_unique<AuthRoutes>(cfg, auth_mgr, &rbac_store,
                                          /*api_token_store=*/nullptr, audit_store.get(),
                                          /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr,
                                          /*analytics_store=*/nullptr, oidc_mu, oidc_provider);
    }

    /// Mint a cookie-authenticated request for a fresh user carrying the
    /// given legacy role. Each call needs a distinct `username` (AuthManager
    /// is keyed by username).
    httplib::Request session_request(const std::string& username, auth::Role role) {
        REQUIRE(auth_mgr.upsert_user(username, "password1234", role));
        auto token = auth_mgr.create_local_session(username, role, /*mfa_verified=*/true);
        httplib::Request req;
        req.headers.emplace("Cookie", "yuzu_session=" + token);
        return req;
    }

    /// Same as `session_request`, but the returned session carries an active
    /// JIT admin elevation (mirrors the production `/api/v1/elevate` route,
    /// minus the eligibility/MFA-step-up gates that route itself owns —
    /// `elevate_session`'s own contract puts eligibility on the caller).
    httplib::Request elevated_session_request(const std::string& username) {
        REQUIRE(auth_mgr.upsert_user(username, "password1234", auth::Role::user));
        auto token = auth_mgr.create_local_session(username, auth::Role::user, /*mfa_verified=*/true);
        REQUIRE(auth_mgr.elevate_session(token, std::chrono::seconds(300)).has_value());
        httplib::Request req;
        req.headers.emplace("Cookie", "yuzu_session=" + token);
        return req;
    }
};

/// Literal, INDEPENDENT copy of the three documented floored pairs — used by
/// every test below that needs to enumerate "the floored set" for anything
/// other than `topology_floor_applies` itself. Deliberately NOT derived from
/// `kTopologyFloor`: a test that iterates the production array to build its
/// own expectations shrinks in lockstep with an accidentally-shrunk array
/// and silently stops covering the missing entry (a false-green closure —
/// verified: the very failure mode this file's mutation-test evidence
/// exists to rule out). Only the cardinality/membership test above is
/// allowed to reference `kTopologyFloor` directly.
struct FloorPair {
    const char* securable;
    const char* operation;
};
constexpr FloorPair kExpectedFloorPairs[] = {
    {"AccessReview", "Read"},
    {"UserManagement", "Read"},
    {"EnginePrincipal", "Read"},
};

} // namespace

// ── 1. Lock the set ──────────────────────────────────────────────────────

TEST_CASE("topology_floor_applies: exactly the three documented pairs are floored",
          "[authz][floor]") {
    // Positive: the three floored pairs (a change to kTopologyFloor's
    // MEMBERSHIP must break these).
    CHECK(topology_floor_applies("AccessReview", "Read"));
    CHECK(topology_floor_applies("UserManagement", "Read"));
    CHECK(topology_floor_applies("EnginePrincipal", "Read"));

    // Negative: a representative spread of pairs that must NOT be floored —
    // proves the set is narrow, not "every Read" or "every op on these
    // securables".
    CHECK_FALSE(topology_floor_applies("Infrastructure", "Read"));
    CHECK_FALSE(topology_floor_applies("Security", "Read"));
    CHECK_FALSE(topology_floor_applies("AccessReview", "Attest"));
    CHECK_FALSE(topology_floor_applies("UserManagement", "Write"));

    // Cardinality lock: a fourth pair silently added to kTopologyFloor
    // without updating this file's positive/negative lists must still break
    // this test even though every entry it DOES check still round-trips.
    CHECK(std::size(kTopologyFloor) == 3);
}

// ── 2. RBAC OFF + non-admin → 403 on every floored pair ─────────────────

TEST_CASE("require_permission: RBAC off, non-admin is denied on every floored pair",
          "[authz][floor]") {
    FloorFixture fix;
    auto req = fix.session_request("mallory", auth::Role::user);
    REQUIRE_FALSE(fix.rbac_store.is_rbac_enabled()); // default-off — the hazard scenario

    for (const auto& entry : kExpectedFloorPairs) {
        httplib::Response res;
        INFO("securable=" << entry.securable << " operation=" << entry.operation);
        CHECK_FALSE(fix.ar->require_permission(req, res, entry.securable, entry.operation));
        CHECK(res.status == 403);
    }
}

// ── 3. RBAC OFF + non-admin → allowed on an UNFLOORED Read ──────────────

TEST_CASE("require_permission: RBAC off, non-admin still gets the ordinary legacy Read-allow "
          "on an unfloored securable",
          "[authz][floor]") {
    FloorFixture fix;
    auto req = fix.session_request("frank", auth::Role::user);

    httplib::Response res;
    CHECK(fix.ar->require_permission(req, res, "Infrastructure", "Read"));
}

// ── 4. RBAC OFF + admin → allowed on every floored pair ──────────────────

TEST_CASE("require_permission: RBAC off, admin is allowed on every floored pair",
          "[authz][floor]") {
    FloorFixture fix;
    auto req = fix.session_request("grace", auth::Role::admin);

    for (const auto& entry : kExpectedFloorPairs) {
        httplib::Response res;
        INFO("securable=" << entry.securable << " operation=" << entry.operation);
        CHECK(fix.ar->require_permission(req, res, entry.securable, entry.operation));
    }
}

// ── 5. RBAC ON + a real AccessReview:Read grant → allowed ───────────────
//
// The single most important assertion in this file: #2324 cut the dedicated
// AccessReview securable precisely so a non-admin Reviewer role could be
// seeded with AccessReview:Read. If the floor ever ran ahead of (or instead
// of) the live-RBAC branch, it would silently deny that seeded role and
// destroy the whole reason the securable exists.

TEST_CASE("require_permission: RBAC on, a non-admin with a real AccessReview:Read grant is "
          "allowed — the floor must never run ahead of a live RBAC grant",
          "[authz][floor]") {
    FloorFixture fix;
    REQUIRE(fix.rbac_store.create_role({"ReviewerTest", "d", false, 0}).has_value());
    REQUIRE(fix.rbac_store.set_permission({"ReviewerTest", "AccessReview", "Read", "allow"})
                .has_value());
    REQUIRE(fix.rbac_store.assign_role({"user", "carol", "ReviewerTest"}).has_value());
    fix.rbac_store.set_rbac_enabled(true);

    auto req = fix.session_request("carol", auth::Role::user);
    httplib::Response res;
    CHECK(fix.ar->require_permission(req, res, "AccessReview", "Read"));
}

// ── 6. Same matrix through require_scoped_permission ─────────────────────
//
// No floored pair reaches this branch in production today — it is floored
// defensively so a FUTURE scoped topology read cannot silently bypass the
// floor. This is what stops that regressing.

TEST_CASE("require_scoped_permission: mirrors require_permission's floor (RBAC-off denial + "
          "RBAC-on granted-allow)",
          "[authz][floor]") {
    FloorFixture fix;

    SECTION("RBAC off: non-admin is denied") {
        auto req = fix.session_request("dave", auth::Role::user);
        httplib::Response res;
        CHECK_FALSE(fix.ar->require_scoped_permission(req, res, "AccessReview", "Read", "agent-1"));
        CHECK(res.status == 403);
    }

    SECTION("RBAC on: a real AccessReview:Read grant is allowed") {
        REQUIRE(fix.rbac_store.create_role({"ReviewerTest2", "d", false, 0}).has_value());
        REQUIRE(fix.rbac_store.set_permission({"ReviewerTest2", "AccessReview", "Read", "allow"})
                    .has_value());
        REQUIRE(fix.rbac_store.assign_role({"user", "erin", "ReviewerTest2"}).has_value());
        fix.rbac_store.set_rbac_enabled(true);

        auto req = fix.session_request("erin", auth::Role::user);
        httplib::Response res;
        // A global grant short-circuits check_scoped_permission's step 1
        // (check_permission) regardless of agent_id/mgmt-group wiring — see
        // RbacStore::check_scoped_permission.
        CHECK(fix.ar->require_scoped_permission(req, res, "AccessReview", "Read", "agent-1"));
    }
}

// ── 7. JIT-elevated non-admin → allowed (elevation short-circuits above the floor) ──

TEST_CASE("require_permission: a JIT-elevated non-admin is allowed on every floored pair",
          "[authz][floor]") {
    FloorFixture fix;
    auto req = fix.elevated_session_request("heidi");

    for (const auto& entry : kExpectedFloorPairs) {
        httplib::Response res;
        INFO("securable=" << entry.securable << " operation=" << entry.operation);
        CHECK(fix.ar->require_permission(req, res, entry.securable, entry.operation));
    }
}

// ── 9. Denial side-effects: audit reason + counter ────────────────────────

TEST_CASE("require_permission: a floored denial's audit reason and counter are distinguishable "
          "from an ordinary non-Read denial",
          "[authz][floor]") {
    FloorFixture fix;

    SECTION("floored denial: audit reason starts 'topology floor: ' and the counter increments") {
        auto req = fix.session_request("ivan", auth::Role::user);
        httplib::Response res;
        CHECK_FALSE(fix.ar->require_permission(req, res, "AccessReview", "Read"));

        auto rows = fix.audit_store->query(AuditQuery{.action = "auth.permission_required", .limit = 1});
        REQUIRE_FALSE(rows.empty());
        CHECK(rows.front().detail.starts_with("topology floor: "));

        auto& counter = fix.metrics.counter("yuzu_auth_topology_floor_denied_total",
                                            {{"permission", "AccessReview:Read"}});
        CHECK(counter.value() == 1.0);
    }

    SECTION("ordinary non-Read denial: generic reason, counter does NOT bump") {
        auto req = fix.session_request("judy", auth::Role::user);
        httplib::Response res;
        CHECK_FALSE(fix.ar->require_permission(req, res, "Infrastructure", "Write"));

        auto rows = fix.audit_store->query(AuditQuery{.action = "auth.permission_required", .limit = 1});
        REQUIRE_FALSE(rows.empty());
        CHECK(rows.front().detail.starts_with("non-admin role denied "));
        CHECK_FALSE(rows.front().detail.starts_with("topology floor: "));

        auto& counter = fix.metrics.counter("yuzu_auth_topology_floor_denied_total",
                                            {{"permission", "Infrastructure:Write"}});
        CHECK(counter.value() == 0.0);
    }
}

// ── 10. Securable seeding ─────────────────────────────────────────────────

TEST_CASE("RbacStore::seed_defaults: EnginePrincipal is seeded with Administrator+Viewer Read",
          "[authz][floor]") {
    FloorFixture fix;

    auto types = fix.rbac_store.list_securable_types();
    CHECK(std::find(types.begin(), types.end(), "EnginePrincipal") != types.end());

    REQUIRE(fix.rbac_store.assign_role({"user", "kevin", "Administrator"}).has_value());
    CHECK(fix.rbac_store.check_permission("kevin", "EnginePrincipal", "Read"));

    REQUIRE(fix.rbac_store.assign_role({"user", "linda", "Viewer"}).has_value());
    CHECK(fix.rbac_store.check_permission("linda", "EnginePrincipal", "Read"));
}

// ── 7b. The UPGRADE path — the claim the no-migration decision rests on ──
//
// #2376 deliberately ships NO schema migration for the new `EnginePrincipal`
// securable. The whole justification is that `seed_defaults()` runs
// unconditionally on every construction and its `types[]` / Administrator-CRUD
// / `viewer_types[]` loops are all `INSERT OR IGNORE`, so an EXISTING
// deployment picks the securable and its grants up on the next boot with no
// migration at all — exactly how `AccessReview` and `SoftwareLicensing` were
// introduced. (A migration is needed only where a change cannot be an
// idempotent additive re-seed: `rbac_store.cpp`'s v4 DELETEs rows, which is
// why that one had to be one.)
//
// The seeding test above only proves that on a FRESH store. That is not the
// claim — the claim is about a database that already exists and predates the
// securable. This reconstructs that database (open, then delete the
// EnginePrincipal rows so the file looks pre-#2376 while its `schema_version`
// stays where it was), reopens it, and asserts the next boot restores
// everything. If someone later makes `seed_defaults()` conditional — a
// run-once guard, a version gate — this fails, which is the point: it would
// silently strand every upgraded deployment without the securable, and the
// engine-principal routes would 403 for Administrator and Viewer alike.
TEST_CASE("RbacStore: an EXISTING pre-#2376 database gains EnginePrincipal on the next boot, "
          "with no migration — the no-migration decision's actual claim",
          "[authz][floor]") {
    yuzu::test::TempDbFile rbac_db_file{"yuzu_test_authz_floor_upgrade_"};

    // Boot once so the file exists and is fully seeded/migrated, then strip the
    // securable back out to simulate a database created before #2376.
    {
        RbacStore store{rbac_db_file.path};
        REQUIRE(store.is_open());
        auto types = store.list_securable_types();
        REQUIRE(std::find(types.begin(), types.end(), "EnginePrincipal") != types.end());
    }

    // Strip the securable back out, and confirm the strip actually took — all
    // through raw SQL with NO RbacStore open, because merely constructing one
    // re-seeds and would restore the rows. An earlier draft of this test put a
    // store construction between the strip and the assertion; that made the
    // "upgrade boot" the third open and the test passed for the wrong reason.
    {
        // RAII throughout: every REQUIRE below throws on failure, and a raw
        // sqlite3*/sqlite3_stmt* pair would unwind past its own close/finalize —
        // leaking the connection exactly when an assertion catches the regression
        // this test exists to catch. `SqliteHandleOwner` closes with
        // `sqlite3_close_v2`, so a still-outstanding statement defers the close
        // rather than leaking the handle outright.
        yuzu::test::SqliteHandleOwner<sqlite3> raw;
        REQUIRE(sqlite3_open(rbac_db_file.path.c_str(), &raw.db) == SQLITE_OK);
        REQUIRE(sqlite3_exec(raw.db,
                             "DELETE FROM role_permissions WHERE securable_type='EnginePrincipal';"
                             "DELETE FROM securable_types WHERE name='EnginePrincipal';",
                             nullptr, nullptr, nullptr) == SQLITE_OK);

        auto count_of = [&](const char* sql) {
            yuzu::server::SqliteStmt s;
            REQUIRE(sqlite3_prepare_v2(raw.db, sql, -1, s.addr(), nullptr) == SQLITE_OK);
            REQUIRE(sqlite3_step(s.get()) == SQLITE_ROW);
            return sqlite3_column_int(s.get(), 0);
        };
        REQUIRE(count_of("SELECT COUNT(*) FROM securable_types WHERE name='EnginePrincipal';") == 0);
        REQUIRE(count_of(
                    "SELECT COUNT(*) FROM role_permissions WHERE securable_type='EnginePrincipal';")
                == 0);
    }

    // The upgrade boot — the FIRST store construction since the strip.
    RbacStore upgraded{rbac_db_file.path};
    REQUIRE(upgraded.is_open());

    auto types = upgraded.list_securable_types();
    CHECK(std::find(types.begin(), types.end(), "EnginePrincipal") != types.end());

    REQUIRE(upgraded.assign_role({"user", "morag", "Administrator"}).has_value());
    CHECK(upgraded.check_permission("morag", "EnginePrincipal", "Read"));

    REQUIRE(upgraded.assign_role({"user", "niall", "Viewer"}).has_value());
    CHECK(upgraded.check_permission("niall", "EnginePrincipal", "Read"));
}

// ── 8. Engine principal → still denied, behaviour unchanged by the floor ──
//
// PG-gated (ApiTokenStore + EnginePrincipalStore are both Postgres-backed —
// ADR-0006/ADR-0031): SKIPs when YUZU_TEST_POSTGRES_DSN is unset, FAILs when
// it is set but broken (the standard skip-vs-fail contract, test_helpers.hpp).
// The engine branch in require_permission/require_scoped_permission resolves
// BEFORE the legacy fallback the floor lives in (auth_routes.cpp: engine
// sessions return from their own RBAC-only block), so the floor's addition
// must be a complete no-op for an engine session — this locks that.

TEST_CASE("require_permission: an engine principal is still denied Read on every floored pair "
          "when RBAC is off — the floor never reaches the engine branch",
          "[pg][authz][floor]") {
    YUZU_REQUIRE_PG_DB(db);

    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    EnginePrincipalStore engine_store{pool};
    REQUIRE(engine_store.is_open());
    ApiTokenStore api_tokens{pool};
    REQUIRE(api_tokens.is_open());

    REQUIRE(engine_store
                .create("Floor Test Engine", "alice", "authz topology floor coverage", "internal",
                       "admin", "engine:floor-test")
                .has_value());
    api_tokens.set_engine_referent_check(
        [&](const std::string& id) { return engine_store.get_for_auth(id).status; });
    const auto now_epoch = std::chrono::duration_cast<std::chrono::seconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count();
    auto raw = api_tokens.create_token("engine-floor-token", "engine:floor-test", now_epoch + 3600,
                                       "", "readonly", "engine");
    REQUIRE(raw.has_value());

    Config cfg{};
    auth::AuthManager auth_mgr{};
    auto rbac_db = yuzu::test::TempDbFile{"yuzu_test_authz_floor_engine_rbac_"};
    RbacStore rbac_store{rbac_db.path};
    REQUIRE(rbac_store.is_open());
    REQUIRE_FALSE(rbac_store.is_rbac_enabled()); // default-off — the hazard scenario

    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    AuthRoutes ar(cfg, auth_mgr, &rbac_store, &api_tokens, /*audit_store=*/nullptr,
                 /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr, /*analytics_store=*/nullptr,
                 oidc_mu, oidc_provider);
    ar.set_engine_principal_store(&engine_store);

    for (const auto& entry : kExpectedFloorPairs) {
        httplib::Request req;
        req.headers.emplace("Authorization", "Bearer " + *raw);
        httplib::Response res;
        INFO("securable=" << entry.securable << " operation=" << entry.operation);
        CHECK_FALSE(ar.require_permission(req, res, entry.securable, entry.operation));
        CHECK(res.status == 403);
    }
}
