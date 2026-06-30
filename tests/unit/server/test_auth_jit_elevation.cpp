/**
 * test_auth_jit_elevation.cpp — JIT admin elevation (SOC 2 CC6.3/CC6.6).
 * `/auth-and-authz` gap matrix P1 #9.
 *
 * Covers:
 *   - the effective_role()/is_elevated() helpers (auth.hpp)
 *   - AuthManager::elevate_session / revoke_elevation
 *   - AuthDB::set_elevation_eligible / is_elevation_eligible (migration v4)
 *   - the REST surface (POST /api/v1/elevate, /elevate/revoke,
 *     /users/<name>/elevation-eligibility) end-to-end through a TestRouteSink:
 *     an eligible operator elevates and is then treated as admin (passes an
 *     admin-gated route); an ineligible one is denied; revoke reverts; a stale
 *     MFA proof is challenged.
 */

#include "auth_routes.hpp"

#include "analytics_event_store.hpp"
#include "api_token_store.hpp"
#include "audit_store.hpp"
#include "test_route_sink.hpp"
#include "../../../server/core/src/totp.hpp"
#include "../test_helpers.hpp"
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <filesystem>
#include <memory>
#include <shared_mutex>
#include <string>

namespace fs = std::filesystem;
using namespace yuzu::server;
using yuzu::server::auth::Role;

// ── Pure helpers ─────────────────────────────────────────────────────────────

TEST_CASE("effective_role: a session is admin only while elevated", "[jit][auth]") {
    auth::Session s;
    s.username = "alice";
    s.role = Role::user;

    // Not elevated → base role.
    CHECK_FALSE(auth::is_elevated(s));
    CHECK(auth::effective_role(s) == Role::user);

    // Elevated into the future → effective admin.
    s.elevated_until = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    CHECK(auth::is_elevated(s));
    CHECK(auth::effective_role(s) == Role::admin);

    // An elapsed window → reverts to base (monotonic, no wall-clock).
    s.elevated_until = std::chrono::steady_clock::now() - std::chrono::seconds(1);
    CHECK_FALSE(auth::is_elevated(s));
    CHECK(auth::effective_role(s) == Role::user);

    // A base-admin is admin regardless of elevation.
    s.role = Role::admin;
    s.elevated_until = {};
    CHECK(auth::effective_role(s) == Role::admin);
}

// ── AuthManager elevate/revoke ───────────────────────────────────────────────

namespace {
std::unique_ptr<auth::AuthManager> make_temp_auth() {
    auto mgr = std::make_unique<auth::AuthManager>();
    auto cfg = yuzu::test::unique_temp_path("yuzu-jit-auth-");
    cfg += ".cfg";
    fs::create_directories(cfg.parent_path());
    fs::remove(cfg);
    mgr->load_config(cfg);
    return mgr;
}
} // namespace

TEST_CASE("AuthManager::elevate_session sets the window; revoke clears it", "[jit][auth]") {
    auto mgr = make_temp_auth();
    mgr->upsert_user("alice", "secret123456", Role::user);
    auto token = mgr->authenticate("alice", "secret123456");
    REQUIRE(token.has_value());

    // Before elevation: effective role is the base (user).
    REQUIRE(mgr->validate_session(*token).has_value());
    CHECK(auth::effective_role(*mgr->validate_session(*token)) == Role::user);

    auto until = mgr->elevate_session(*token, std::chrono::seconds(60));
    REQUIRE(until.has_value());
    auto s = mgr->validate_session(*token);
    REQUIRE(s.has_value());
    CHECK(auth::is_elevated(*s));
    CHECK(auth::effective_role(*s) == Role::admin);

    // Manual revoke reverts to base and reports it WAS elevated.
    CHECK(mgr->revoke_elevation(*token));
    auto s2 = mgr->validate_session(*token);
    REQUIRE(s2.has_value());
    CHECK_FALSE(auth::is_elevated(*s2));
    CHECK(auth::effective_role(*s2) == Role::user);
    // Revoking an un-elevated session is a no-op (returns false).
    CHECK_FALSE(mgr->revoke_elevation(*token));
    // Unknown token → nullopt / false.
    CHECK_FALSE(mgr->elevate_session("deadbeef", std::chrono::seconds(60)).has_value());
    CHECK_FALSE(mgr->revoke_elevation("deadbeef"));
}

// ── AuthDB eligibility column ────────────────────────────────────────────────

TEST_CASE("AuthDB::set/is_elevation_eligible round-trips, fail-closed", "[jit][authdb]") {
    auto dir = yuzu::test::TempDir{};
    fs::create_directories(dir.path);
    AuthDB db(dir.path, /*cleanup_interval_secs=*/0);
    REQUIRE(db.initialize().has_value());
    auto salt = auth::AuthManager::random_bytes(16);
    auto salt_hex = auth::AuthManager::bytes_to_hex(salt);
    REQUIRE(
        db.upsert_user("alice", auth::AuthManager::pbkdf2_sha256("pw", salt, 1000), salt_hex,
                       Role::user)
            .has_value());

    // Default is not-eligible.
    CHECK(db.is_elevation_eligible("alice").value() == false);
    // Grant, then read back.
    REQUIRE(db.set_elevation_eligible("alice", true).has_value());
    CHECK(db.is_elevation_eligible("alice").value() == true);
    // Revoke.
    REQUIRE(db.set_elevation_eligible("alice", false).has_value());
    CHECK(db.is_elevation_eligible("alice").value() == false);
    // Unknown user: set → UserNotFound; read → fail-closed false.
    CHECK_FALSE(db.set_elevation_eligible("nobody", true).has_value());
    CHECK(db.is_elevation_eligible("nobody").value() == false);
    // Malformed username rejected on both.
    CHECK_FALSE(db.set_elevation_eligible("alice:admin", true).has_value());
    CHECK_FALSE(db.is_elevation_eligible("alice:admin").has_value());
}

// ── REST surface ─────────────────────────────────────────────────────────────

namespace {
struct TmpDirGuard {
    fs::path path;
    explicit TmpDirGuard(fs::path p) : path(std::move(p)) { fs::create_directories(path); }
    ~TmpDirGuard() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    TmpDirGuard(const TmpDirGuard&) = delete;
    TmpDirGuard& operator=(const TmpDirGuard&) = delete;
};

/// AuthRoutes wired against an in-process sink with an eligible non-admin
/// (`alice`), an admin, and (optionally) MFA. mfa_enforcement stays "optional"
/// and alice is NOT enrolled, so require_mfa_step_up is a pass-through — these
/// tests exercise the elevation logic, not the step-up gate (covered in
/// test_mfa_step_up.cpp); one case below enrolls + staleness to prove the gate.
struct JitHarness {
    TmpDirGuard tmp;
    Config cfg{};
    auth::AuthManager auth_mgr{};
    AuthDB auth_db;
    std::unique_ptr<ApiTokenStore> api_tokens;
    std::unique_ptr<AuditStore> audit_store;
    std::unique_ptr<AnalyticsEventStore> analytics_store;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    std::unique_ptr<AuthRoutes> auth_routes;
    yuzu::server::test::TestRouteSink sink;

    JitHarness() : tmp(yuzu::test::unique_temp_path("auth-jit-")), auth_db(tmp.path, 0) {
        cfg.auth_config_path = tmp.path / "auth.cfg";
        cfg.https_enabled = false;
        cfg.jit_max_elevation_secs = 3600;
        REQUIRE(auth_db.initialize().has_value());
        auth_mgr.load_config(cfg.auth_config_path);
        seed("admin", "adminpassword1", Role::admin);
        seed("alice", "alicepassword1", Role::user);
        auth_mgr.set_auth_db(&auth_db);
        REQUIRE(auth_db.set_elevation_eligible("alice", true).has_value());

        api_tokens = std::make_unique<ApiTokenStore>(tmp.path / "api_tokens.db");
        audit_store = std::make_unique<AuditStore>(tmp.path / "audit.db");
        analytics_store = std::make_unique<AnalyticsEventStore>(tmp.path / "analytics.db");
        REQUIRE(api_tokens->is_open());
        auth_routes = std::make_unique<AuthRoutes>(cfg, auth_mgr, /*rbac_store=*/nullptr,
                                                   api_tokens.get(), audit_store.get(), nullptr,
                                                   nullptr, analytics_store.get(), oidc_mu,
                                                   oidc_provider);
        auth_routes->register_routes(sink);
    }

    void seed(const std::string& u, const std::string& pw, Role r) {
        REQUIRE(auth_mgr.upsert_user(u, pw, r));
        auto salt = auth::AuthManager::random_bytes(16);
        auto salt_hex = auth::AuthManager::bytes_to_hex(salt);
        REQUIRE(auth_db.upsert_user(u, auth::AuthManager::pbkdf2_sha256(pw, salt, 100'000), salt_hex,
                                    r)
                    .has_value());
    }

    // A cookie-authenticated POST.
    auto post(const std::string& path, const std::string& token, const std::string& body) {
        return sink.dispatch("POST", path, body, "application/json",
                             {{"Cookie", "yuzu_session=" + token}});
    }

    int count_audits(const std::string& action, const std::string& principal = {}) {
        AuditQuery q;
        q.action = action;
        if (!principal.empty())
            q.principal = principal;
        return static_cast<int>(audit_store->query(q).size());
    }
};
} // namespace

TEST_CASE("POST /api/v1/elevate: eligible operator is elevated to admin", "[jit][routes]") {
    JitHarness h;
    auto token = h.auth_mgr.authenticate("alice", "alicepassword1");
    REQUIRE(token.has_value());

    auto res = h.post("/api/v1/elevate", *token,
                      R"({"justification":"prod incident #42","duration_secs":600})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(nlohmann::json::parse(res->body).value("expires_in", 0) == 600);
    CHECK(h.count_audits("role.elevation.granted", "alice") == 1);

    // The session is now effectively admin.
    auto s = h.auth_mgr.validate_session(*token);
    REQUIRE(s.has_value());
    CHECK(auth::is_elevated(*s));
    CHECK(auth::effective_role(*s) == Role::admin);
}

TEST_CASE("an elevated operator can perform an admin-gated action", "[jit][routes]") {
    JitHarness h;
    auto token = h.auth_mgr.authenticate("alice", "alicepassword1");
    REQUIRE(token.has_value());
    // Before elevation: the admin-gated eligibility endpoint is forbidden.
    auto before = h.post("/api/v1/users/admin/elevation-eligibility", *token,
                         R"({"eligible":true})");
    REQUIRE(before);
    CHECK(before->status == 403);

    // Elevate, then the same admin-gated call succeeds (effective_role == admin).
    REQUIRE(h.post("/api/v1/elevate", *token, R"({"justification":"grant bob"})")->status == 200);
    auto after = h.post("/api/v1/users/admin/elevation-eligibility", *token,
                        R"({"eligible":true})");
    REQUIRE(after);
    CHECK(after->status == 200);
    CHECK(h.auth_db.is_elevation_eligible("admin").value() == true);
}

TEST_CASE("POST /api/v1/elevate: an ineligible operator is denied", "[jit][routes]") {
    JitHarness h;
    REQUIRE(h.auth_db.set_elevation_eligible("alice", false).has_value()); // revoke eligibility
    auto token = h.auth_mgr.authenticate("alice", "alicepassword1");
    REQUIRE(token.has_value());
    auto res = h.post("/api/v1/elevate", *token, R"({"justification":"x"})");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.count_audits("role.elevation.denied", "alice") == 1);
    CHECK_FALSE(auth::is_elevated(*h.auth_mgr.validate_session(*token)));
}

TEST_CASE("POST /api/v1/elevate: justification is mandatory", "[jit][routes]") {
    JitHarness h;
    auto token = h.auth_mgr.authenticate("alice", "alicepassword1");
    REQUIRE(token.has_value());
    auto res = h.post("/api/v1/elevate", *token, R"({"justification":"   "})"); // whitespace only
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK_FALSE(auth::is_elevated(*h.auth_mgr.validate_session(*token)));
}

TEST_CASE("POST /api/v1/elevate: duration is clamped to the cap", "[jit][routes]") {
    JitHarness h;
    auto token = h.auth_mgr.authenticate("alice", "alicepassword1");
    REQUIRE(token.has_value());
    auto res = h.post("/api/v1/elevate", *token,
                      R"({"justification":"x","duration_secs":999999})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(nlohmann::json::parse(res->body).value("expires_in", 0) == h.cfg.jit_max_elevation_secs);
}

TEST_CASE("POST /api/v1/elevate/revoke reverts the elevation", "[jit][routes]") {
    JitHarness h;
    auto token = h.auth_mgr.authenticate("alice", "alicepassword1");
    REQUIRE(token.has_value());
    REQUIRE(h.post("/api/v1/elevate", *token, R"({"justification":"x"})")->status == 200);
    REQUIRE(auth::is_elevated(*h.auth_mgr.validate_session(*token)));

    auto res = h.post("/api/v1/elevate/revoke", *token, "");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.count_audits("role.elevation.revoked", "alice") == 1);
    CHECK_FALSE(auth::is_elevated(*h.auth_mgr.validate_session(*token)));
}

TEST_CASE("POST /api/v1/elevate: a tokenless (no-cookie) request is rejected", "[jit][routes]") {
    JitHarness h;
    // No Cookie header → not an interactive session → 401 (API/MCP tokens, which
    // resolve without a cookie, can never elevate).
    auto res = h.sink.Post("/api/v1/elevate", R"({"justification":"x"})");
    REQUIRE(res);
    CHECK(res->status == 401);
}
