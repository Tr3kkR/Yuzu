/**
 * test_auth_sso_identity.cpp — durable SSO identity (#1852).
 *
 * `create_oidc_session` mints a stable `oidc:<iss>#<sub>` principal but
 * historically wrote NO row to `auth.db users`, so JIT admin elevation
 * (which reads `users.elevation_eligible`) had nothing to key on for an
 * SSO operator — OIDC elevation was unreachable (#1837 fallout). This
 * covers the durable-identity slice restoring it:
 *
 *   - AuthDB::upsert_sso_identity round-trips with set/is_elevation_eligible,
 *     and preserves role/eligibility across re-login (re-upsert).
 *   - mfa_status stays strict — still rejects an SSO principal.
 *   - Migration v6 adds the identity columns and existing rows survive.
 *   - POST /api/v1/elevate end-to-end for an OIDC session: eligible +
 *     provisioned succeeds; eligible-in-intent-but-unprovisioned (no row)
 *     is denied fail-closed; a local elevation flow is unaffected.
 */

#include "auth_routes.hpp"

#include "analytics_event_store.hpp"
#include "api_token_store.hpp"
#include "test_api_token_pg_helper.hpp" // ApiTokenStorePg — PR 4.1 PG port
#include "audit_store.hpp"
#include "migration_runner.hpp"
#include "test_route_sink.hpp"
#include "../test_helpers.hpp"
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <sqlite3.h>

#include <chrono>
#include <filesystem>
#include <memory>
#include <shared_mutex>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::server;
using yuzu::server::auth::Role;

// ── AuthDB::upsert_sso_identity ─────────────────────────────────────────────

TEST_CASE("AuthDB::upsert_sso_identity round-trips with elevation eligibility",
          "[sso][authdb]") {
    auto dir = yuzu::test::TempDir{};
    fs::create_directories(dir.path);
    AuthDB db(dir.path, /*cleanup_interval_secs=*/0);
    REQUIRE(db.initialize().has_value());

    const std::string principal = "oidc:https://idp.example.com/#sub-42";

    REQUIRE(db.upsert_sso_identity(principal, "https://idp.example.com/", "sub-42",
                                   "Ada Lovelace", "oidc")
                .has_value());

    // Default is not-eligible (same fail-closed default as a local row).
    CHECK(db.is_elevation_eligible(principal).value() == false);

    // Grant, then read back — this is the exact operation #1852 restores.
    REQUIRE(db.set_elevation_eligible(principal, true).has_value());
    CHECK(db.is_elevation_eligible(principal).value() == true);
    REQUIRE(db.set_elevation_eligible(principal, false).has_value());
    CHECK(db.is_elevation_eligible(principal).value() == false);
}

TEST_CASE("AuthDB::upsert_sso_identity re-upsert preserves role and elevation_eligible",
          "[sso][authdb]") {
    auto dir = yuzu::test::TempDir{};
    fs::create_directories(dir.path);
    AuthDB db(dir.path, /*cleanup_interval_secs=*/0);
    REQUIRE(db.initialize().has_value());

    const std::string principal = "oidc:https://idp.example.com/#sub-99";

    // First login: provision, an admin grants elevation eligibility. Note:
    // `AuthDB::update_role` deliberately stays on the STRICT
    // `is_valid_username` gate (#1852 item 5 — it is NOT one of the moved
    // call sites), so there is no standing-role-grant path for an SSO
    // principal in this slice; the row's `role` column stays at the
    // INSERT-time default ('user') for the lifetime of the identity. The
    // CRITICAL invariant this test pins is `elevation_eligible` survival —
    // the field an admin actually can and does set for an SSO principal.
    REQUIRE(db.upsert_sso_identity(principal, "https://idp.example.com/", "sub-99", "Bob", "oidc")
                .has_value());
    REQUIRE(db.set_elevation_eligible(principal, true).has_value());

    // Second login (re-upsert with a changed display name — an IdP-side
    // profile edit): eligibility (and role) must survive UNTOUCHED — the
    // ON CONFLICT arm touches ONLY display_name/last_seen_at/is_active.
    REQUIRE(db.upsert_sso_identity(principal, "https://idp.example.com/", "sub-99",
                                   "Bob Renamed", "oidc")
                .has_value());
    auto entry = db.get_user(principal);
    REQUIRE(entry.has_value());
    CHECK(entry->role == Role::user); // ON CONFLICT never touches role — unchanged from INSERT
    CHECK(db.is_elevation_eligible(principal).value() == true); // eligibility preserved
}

TEST_CASE("AuthDB::upsert_sso_identity rejects a non-principal, non-username string",
          "[sso][authdb]") {
    auto dir = yuzu::test::TempDir{};
    fs::create_directories(dir.path);
    AuthDB db(dir.path, /*cleanup_interval_secs=*/0);
    REQUIRE(db.initialize().has_value());

    // No reserved prefix and fails the strict local charset (':').
    CHECK_FALSE(db.upsert_sso_identity("not:reserved", "https://idp/", "sub", "x", "oidc")
                    .has_value());
}

TEST_CASE("AuthDB::mfa_status stays strict — rejects an SSO principal", "[sso][authdb]") {
    auto dir = yuzu::test::TempDir{};
    fs::create_directories(dir.path);
    AuthDB db(dir.path, /*cleanup_interval_secs=*/0);
    REQUIRE(db.initialize().has_value());

    const std::string principal = "oidc:https://idp.example.com/#sub-7";
    REQUIRE(db.upsert_sso_identity(principal, "https://idp.example.com/", "sub-7", "Carol", "oidc")
                .has_value());

    // mfa_status is deliberately NOT moved to is_valid_principal (#1852 item
    // 5) — a local TOTP secret is meaningless for an external identity, and
    // the elevate handler's `auth_source == "local"` gate is what actually
    // skips this check for OIDC sessions (see auth_routes.cpp), not a
    // loosened validator here.
    CHECK_FALSE(db.mfa_status(principal).has_value());
}

// ── Migration v6 ─────────────────────────────────────────────────────────────

namespace {
/// The auth_db kMigrations v1-v5 entries, verbatim, so this test can
/// construct a pre-#1852 auth.db (schema at v5) and exercise the REAL
/// upgrade path AuthDB::initialize() takes against an existing production
/// database — rather than only ever observing a fresh v6-from-scratch DB.
const std::vector<Migration> kV1ToV5 = {
    {1, R"(
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt_hex TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_login_at DATETIME,
            is_active INTEGER NOT NULL DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
        CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active) WHERE is_active = 1;

        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_token TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            auth_source TEXT NOT NULL DEFAULT 'password',
            oidc_sub TEXT,
            expires_at DATETIME NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_activity_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token);
        CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
        CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username);

        CREATE TABLE IF NOT EXISTS enrollment_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash TEXT NOT NULL UNIQUE,
            created_by TEXT NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            is_used INTEGER NOT NULL DEFAULT 0,
            used_at DATETIME,
            used_by_agent_id TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_enrollment_token_hash ON enrollment_tokens(token_hash);
        CREATE INDEX IF NOT EXISTS idx_enrollment_expires ON enrollment_tokens(expires_at);

        CREATE TABLE IF NOT EXISTS pending_agents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL UNIQUE,
            hostname TEXT NOT NULL,
            os TEXT,
            arch TEXT,
            agent_version TEXT,
            enrollment_token_id INTEGER,
            requested_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            approved_at DATETIME,
            approved_by TEXT,
            status TEXT NOT NULL DEFAULT 'pending'
        );
        CREATE INDEX IF NOT EXISTS idx_pending_agents_agent_id ON pending_agents(agent_id);
        CREATE INDEX IF NOT EXISTS idx_pending_agents_status ON pending_agents(status);
    )"},
    {2, R"(
        ALTER TABLE users ADD COLUMN mfa_totp_secret BLOB;
        ALTER TABLE users ADD COLUMN mfa_enrolled_at DATETIME;
        ALTER TABLE users ADD COLUMN mfa_disabled_at DATETIME;
        ALTER TABLE users ADD COLUMN mfa_last_counter INTEGER NOT NULL DEFAULT 0;

        ALTER TABLE sessions ADD COLUMN mfa_verified_at DATETIME;

        CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            code_salt TEXT NOT NULL,
            consumed_at DATETIME,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_mfa_recovery_username ON mfa_recovery_codes(username);
        CREATE INDEX IF NOT EXISTS idx_mfa_recovery_unconsumed
            ON mfa_recovery_codes(username) WHERE consumed_at IS NULL;

        CREATE TABLE IF NOT EXISTS auth_kv (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
    )"},
    {3, R"(
        ALTER TABLE users ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE users ADD COLUMN last_failed_login_at DATETIME;
        ALTER TABLE users ADD COLUMN locked_until DATETIME;
    )"},
    {4, R"(
        ALTER TABLE users ADD COLUMN break_glass_armed_until DATETIME;
    )"},
    {5, R"(
        ALTER TABLE users ADD COLUMN elevation_eligible INTEGER NOT NULL DEFAULT 0;
    )"},
};

bool column_exists(sqlite3* db, const char* table, const char* column) {
    std::string sql = "PRAGMA table_info(" + std::string(table) + ")";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return false;
    bool found = false;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        if (name && std::string(name) == column) {
            found = true;
            break;
        }
    }
    sqlite3_finalize(stmt);
    return found;
}
} // namespace

TEST_CASE("AuthDB migration v6: identity columns added, existing v5 rows survive",
          "[sso][authdb][migration]") {
    auto dir = yuzu::test::TempDir{};
    fs::create_directories(dir.path);
    auto db_path = dir.path / "auth.db";

    // Build a pre-#1852 (v5) auth.db and seed a legacy local user row.
    // Inner scope: the raw sqlite3 handle is closed before AuthDB reopens
    // the SAME file below — required on Windows, where a second handle
    // cannot open a file another handle still holds (test_helpers.hpp's
    // TempDbFile doc comment; this mirrors that pattern for a directory-
    // rooted store instead of a single temp file).
    {
        sqlite3* raw = nullptr;
        REQUIRE(sqlite3_open_v2(db_path.string().c_str(), &raw,
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                                nullptr) == SQLITE_OK);
        REQUIRE(MigrationRunner::run(raw, "auth_db", kV1ToV5));
        REQUIRE(MigrationRunner::current_version(raw, "auth_db") == 5);

        char* err = nullptr;
        int rc = sqlite3_exec(raw,
                              "INSERT INTO users (username, password_hash, salt_hex, role) "
                              "VALUES ('legacyuser', 'h', 's', 'user')",
                              nullptr, nullptr, &err);
        REQUIRE(rc == SQLITE_OK);
        sqlite3_close(raw);
    }

    // Open via the production path — this applies ONLY v6 (current==5).
    AuthDB db(dir.path, /*cleanup_interval_secs=*/0);
    REQUIRE(db.initialize().has_value());

    // The migration v6 columns exist on the `users` table (schema-level
    // check via a second read-only connection — SQLite supports concurrent
    // readers, so this does not race AuthDB's own open handle).
    {
        sqlite3* ro = nullptr;
        REQUIRE(sqlite3_open_v2(db_path.string().c_str(), &ro, SQLITE_OPEN_READONLY, nullptr) ==
                SQLITE_OK);
        CHECK(column_exists(ro, "users", "identity_source"));
        CHECK(column_exists(ro, "users", "external_iss"));
        CHECK(column_exists(ro, "users", "external_sub"));
        CHECK(column_exists(ro, "users", "display_name"));
        CHECK(column_exists(ro, "users", "last_seen_at"));
        sqlite3_close(ro);
    }

    // Existing row survives, unmigrated data intact.
    auto entry = db.get_user("legacyuser");
    REQUIRE(entry.has_value());
    CHECK(entry->username == "legacyuser");
    CHECK(entry->role == Role::user);

    // New columns exist and default correctly for a pre-v6 row.
    auto listed = db.list_users();
    REQUIRE(listed.has_value());
    bool found = false;
    for (const auto& u : *listed) {
        if (u.username == "legacyuser") {
            found = true;
            CHECK(u.identity_source == "local");
        }
    }
    CHECK(found);

    // The migration unblocks upsert_sso_identity against this now-v6 DB.
    REQUIRE(db.upsert_sso_identity("oidc:https://idp/#sub1", "https://idp/", "sub1", "New SSO User",
                                   "oidc")
                .has_value());
}

// ── POST /api/v1/elevate — OIDC session end-to-end ──────────────────────────

namespace {
/// Mirrors JitHarness (test_auth_jit_elevation.cpp) but adds an OIDC-session
/// helper. Kept separate rather than extending the shared harness so the
/// two files stay independently reviewable.
struct SsoJitHarness {
    yuzu::test::TempDir tmp;
    Config cfg{};
    auth::AuthManager auth_mgr{};
    AuthDB auth_db;
    // ApiTokenStore ported to Postgres (PR 4.1) — SKIPs the current TEST_CASE
    // when YUZU_TEST_POSTGRES_DSN is unset, FAILs when set but broken.
    // api_tokens removed (PR 4.1 review #3): this fixture never calls a token
    // store method, and AuthRoutes null-guards the pointer, so it gets nullptr
    // below — embedding the PG fixture only made every case skip without a DSN.
    std::unique_ptr<AuditStore> audit_store;
    std::unique_ptr<AnalyticsEventStore> analytics_store;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider;
    std::unique_ptr<AuthRoutes> auth_routes;
    yuzu::server::test::TestRouteSink sink;

    SsoJitHarness() : auth_db((fs::create_directories(tmp.path), tmp.path), 0) {
        cfg.auth_config_path = tmp.path / "auth.cfg";
        cfg.https_enabled = false;
        cfg.jit_max_elevation_secs = 3600;
        REQUIRE(auth_db.initialize().has_value());
        auth_mgr.load_config(cfg.auth_config_path);
        auth_mgr.set_auth_db(&auth_db);

        audit_store = std::make_unique<AuditStore>(tmp.path / "audit.db");
        analytics_store = std::make_unique<AnalyticsEventStore>(tmp.path / "analytics.db");
        auth_routes = std::make_unique<AuthRoutes>(cfg, auth_mgr, /*rbac_store=*/nullptr,
                                                   /*api_token_store=*/nullptr, audit_store.get(), nullptr,
                                                   nullptr, analytics_store.get(), oidc_mu,
                                                   oidc_provider);
        auth_routes->register_routes(sink);
    }

    // Mints an OIDC cookie session exactly as /auth/callback would, with a
    // fresh amr-attested MFA proof (mfa_verified_at = now). Returns
    // {token, stable principal}.
    std::pair<std::string, std::string> oidc_session(const std::string& sub,
                                                      const std::string& iss =
                                                          "https://idp.example.com/",
                                                      bool amr_mfa = true) {
        auto mfa_at = amr_mfa ? std::chrono::steady_clock::now()
                              : std::chrono::steady_clock::time_point{};
        auto token = auth_mgr.create_oidc_session("Display Name", "user@example.com", sub, iss,
                                                   /*groups=*/{}, /*admin_group_id=*/{}, mfa_at);
        return {token, "oidc:" + iss + "#" + sub};
    }

    auto post(const std::string& path, const std::string& token, const std::string& body) {
        return sink.dispatch("POST", path, body, "application/json",
                             {{"Cookie", "yuzu_session=" + token}});
    }

    // A fresh-MFA admin cookie session, for tests exercising the
    // admin-gated elevation-eligibility-grant route on THIS harness (which
    // otherwise only sets up OIDC identities, never a local admin). Mirrors
    // JitHarness::seed + session_for, collapsed to what the step-up gate
    // needs: a `users` row to key `mfa_status` on (unenrolled — the gate's
    // not-enrolled branch passes unconditionally) plus a session-level
    // fresh MFA proof. Unlike JitHarness (which seeds before
    // `set_auth_db`), this harness's constructor already wired `auth_db`
    // into `auth_mgr` — so `upsert_user` alone persists the row; a second
    // explicit `auth_db.upsert_user` call would double-insert and fail
    // with `UserAlreadyExists`.
    std::string admin_session() {
        REQUIRE(auth_mgr.upsert_user("admin", "adminpassword1", Role::admin));
        return auth_mgr.create_local_session("admin", Role::admin, /*mfa_verified=*/true);
    }
};
} // namespace

TEST_CASE("POST /api/v1/elevate: a provisioned, eligible OIDC session elevates",
          "[sso][jit][routes]") {
    SsoJitHarness h;
    auto [token, principal] = h.oidc_session("sub-alice");

    // Provisioning + eligibility grant — exactly what /auth/callback now does
    // (provision_sso_identity) plus an admin's elevation-eligibility grant.
    REQUIRE(h.auth_db.upsert_sso_identity(principal, "https://idp.example.com/", "sub-alice",
                                          "Display Name", "oidc")
                .has_value());
    REQUIRE(h.auth_db.set_elevation_eligible(principal, true).has_value());

    auto res = h.post("/api/v1/elevate", token,
                      R"({"justification":"prod incident","duration_secs":600})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(nlohmann::json::parse(res->body).value("expires_in", 0) == 600);

    auto s = h.auth_mgr.validate_session(token);
    REQUIRE(s.has_value());
    CHECK(auth::is_elevated(*s));
    CHECK(auth::effective_role(*s) == Role::admin);
}

TEST_CASE("POST /api/v1/elevate: an OIDC session with no durable row is denied fail-closed",
          "[sso][jit][routes]") {
    SsoJitHarness h;
    // No upsert_sso_identity call — simulates a provisioning miss (or simply
    // no admin having granted eligibility, since a never-provisioned
    // principal has no row to grant it on in the first place).
    auto [token, principal] = h.oidc_session("sub-bob");

    auto res = h.post("/api/v1/elevate", token, R"({"justification":"x"})");
    REQUIRE(res);
    CHECK(res->status == 403);

    auto s = h.auth_mgr.validate_session(token);
    REQUIRE(s.has_value());
    CHECK_FALSE(auth::is_elevated(*s));
}

TEST_CASE("POST /api/v1/elevate: an OIDC session with no amr-attested MFA is denied "
          "unconditionally (even under the default --mfa-enforcement=optional)",
          "[sso][jit][routes]") {
    SsoJitHarness h;
    // Provisioned + eligible, but the IdP never attested MFA (amr_mfa=false)
    // — mfa_verified_at is unset (epoch sentinel).
    //
    // Config::mfa_enforcement defaults to "optional" (server.hpp), under
    // which the SHARED require_mfa_step_up gate's OIDC-no-proof branch
    // deliberately PASSES a proof-free session through (PR #1199 HIGH —
    // avoids locking out every non-MFA IdP at lower-risk step-up sites).
    // The elevate route's OWN unconditional amr-proof-exists gate (added
    // alongside this restoration, #1852 security core) is what must deny
    // this session — NOT elevation_step_up, and NOT dependent on the
    // enforcement-mode default. This pins that regression: without the
    // dedicated gate, a non-MFA'd OIDC login could elevate to full admin
    // under the out-of-the-box config.
    REQUIRE(h.cfg.mfa_enforcement == "optional");
    auto [token, principal] = h.oidc_session("sub-carol", "https://idp.example.com/",
                                             /*amr_mfa=*/false);
    REQUIRE(h.auth_db.upsert_sso_identity(principal, "https://idp.example.com/", "sub-carol",
                                          "Carol", "oidc")
                .has_value());
    REQUIRE(h.auth_db.set_elevation_eligible(principal, true).has_value());

    auto res = h.post("/api/v1/elevate", token, R"({"justification":"x"})");
    REQUIRE(res);
    CHECK(res->status == 403);

    auto s = h.auth_mgr.validate_session(token);
    REQUIRE(s.has_value());
    CHECK_FALSE(auth::is_elevated(*s));
}

// ── governance round: source-scope the elevation eligibility (UP-6/UP-7/cons-N2) ──

TEST_CASE("POST /api/v1/elevate: an OIDC session cannot borrow a legacy identity_source='local' "
          "row's eligibility grant even when the principal strings collide",
          "[sso][jit][routes]") {
    SsoJitHarness h;
    // Simulate the exact landmine cons-N2 describes: a row named exactly
    // like a durable OIDC principal, but whose identity_source is 'local'
    // (a legacy row from before #1852, or one an admin somehow created
    // with this shape) — and that row happens to carry
    // elevation_eligible=1. `upsert_sso_identity`'s `source` parameter
    // writes straight into `identity_source`, so passing "local" here
    // constructs exactly that shape via the public API.
    auto [token, principal] = h.oidc_session("sub-mallory");
    REQUIRE(h.auth_db
                .upsert_sso_identity(principal, "https://idp.example.com/", "sub-mallory",
                                     "Legacy Row", "local")
                .has_value());
    REQUIRE(h.auth_db.set_elevation_eligible(principal, true).has_value());

    // Without the source-scope guard, is_elevation_eligible(principal) alone
    // would report true (it only reads the flag, not identity_source) and
    // the OIDC session would elevate on a grant that was never actually
    // made against an OIDC-sourced row.
    auto res = h.post("/api/v1/elevate", token,
                      R"({"justification":"prod incident","duration_secs":600})");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->body.find("not authorized to elevate") != std::string::npos);

    auto s = h.auth_mgr.validate_session(token);
    REQUIRE(s.has_value());
    CHECK_FALSE(auth::is_elevated(*s));
}

TEST_CASE("POST /api/v1/elevate: a SAML session whose NameID collides with a provisioned OIDC "
          "principal is denied (identity-source mismatch, not just the no-amr gate)",
          "[sso][jit][routes][saml]") {
    SsoJitHarness h;
    // The other half of cons-N2: a crafted SAML NameID equal to a real,
    // eligible OIDC principal string. SAML sessions already fail closed at
    // the amr-proof / MFA gates further down this handler (SAML carries no
    // amr claim), but this pins that the identity-source guard denies it
    // FIRST and independently — so a future SAML-MFA workstream that adds
    // an amr-equivalent for SAML cannot accidentally reopen this specific
    // cross-protocol collision.
    const std::string iss = "https://idp.example.com/";
    const std::string sub = "sub-mallory-saml";
    const std::string principal = "oidc:" + iss + "#" + sub;

    REQUIRE(h.auth_db.upsert_sso_identity(principal, iss, sub, "Real OIDC User", "oidc")
                .has_value());
    REQUIRE(h.auth_db.set_elevation_eligible(principal, true).has_value());

    // A SAML session whose NameID is crafted to equal the OIDC principal
    // string verbatim.
    auto token = h.auth_mgr.create_saml_session(principal);

    auto res = h.post("/api/v1/elevate", token, R"({"justification":"x"})");
    REQUIRE(res);
    CHECK(res->status == 403);

    auto s = h.auth_mgr.validate_session(token);
    REQUIRE(s.has_value());
    CHECK_FALSE(auth::is_elevated(*s));
}

// ── governance round: don't resurrect a disabled SSO row (UP-3) ────────────

TEST_CASE("AuthDB::upsert_sso_identity does not reactivate a deprovisioned row on re-login",
          "[sso][authdb]") {
    auto dir = yuzu::test::TempDir{};
    fs::create_directories(dir.path);
    AuthDB db(dir.path, /*cleanup_interval_secs=*/0);
    REQUIRE(db.initialize().has_value());

    const std::string principal = "oidc:https://idp.example.com/#sub-deprovisioned";
    REQUIRE(db.upsert_sso_identity(principal, "https://idp.example.com/", "sub-deprovisioned",
                                   "Dave", "oidc")
                .has_value());

    // Simulate a future deprovisioning sweep (#1859) soft-deleting the row.
    // remove_user takes no is_valid_username gate (it's a target-lookup
    // UPDATE, like set_elevation_eligible/is_elevation_eligible), so it
    // works against the durable SSO principal string directly.
    auto removed = db.remove_user(principal);
    REQUIRE(removed.has_value());
    CHECK(*removed == true);
    CHECK_FALSE(db.get_user(principal).has_value()); // is_active=0 now

    // Re-login (the IdP still asserts this identity — there is no push
    // signal into Yuzu on an IdP-side removal) must NOT resurrect the
    // deactivated row. Before this fix the ON CONFLICT arm unconditionally
    // set is_active=1, silently undoing the deprovisioning.
    REQUIRE(db.upsert_sso_identity(principal, "https://idp.example.com/", "sub-deprovisioned",
                                   "Dave", "oidc")
                .has_value());
    CHECK_FALSE(db.get_user(principal).has_value()); // still inactive
}

// ── governance round: SSO force-logout audit fidelity (cons-S1) ────────────

TEST_CASE("AuthManager::invalidate_user_sessions reports db_persisted=true for a durable SSO "
          "principal (not InvalidUsername)",
          "[sso][authdb]") {
    auto dir = yuzu::test::TempDir{};
    fs::create_directories(dir.path);
    AuthDB db(dir.path, /*cleanup_interval_secs=*/0);
    REQUIRE(db.initialize().has_value());
    auth::AuthManager mgr;
    mgr.set_auth_db(&db);

    const std::string principal = "oidc:https://idp.example.com/#sub-revoke";
    // Before this fix, AuthDB::invalidate_all_sessions gated on the strict
    // is_valid_username (rejects ':'/'#'), so this call always returned
    // AuthDBError::InvalidUsername for a durable SSO principal — even
    // though OIDC sessions are never persisted to the `sessions` table in
    // the first place (0 matched rows IS success). The REST DELETE
    // /api/v1/sessions handler surfaced that as result="partial" +
    // db_error=true for an action that fully succeeded end-to-end.
    auto result = mgr.invalidate_user_sessions(principal);
    CHECK(result.db_persisted);
}

// Direct AuthDB-level pin, independent of AuthManager's wrapping —
// confirms the store method itself now accepts the principal shape.
TEST_CASE("AuthDB::invalidate_all_sessions accepts a durable SSO principal", "[sso][authdb]") {
    auto dir = yuzu::test::TempDir{};
    fs::create_directories(dir.path);
    AuthDB db(dir.path, /*cleanup_interval_secs=*/0);
    REQUIRE(db.initialize().has_value());

    const std::string principal = "oidc:https://idp.example.com/#sub-revoke2";
    CHECK(db.invalidate_all_sessions(principal).has_value());
}

// ── review round: elevation-eligibility grant route reachability for SSO ────

TEST_CASE("POST /api/v1/users/elevation-eligibility?username=: the query form reaches "
          "a durable SSO principal that the path form can never carry",
          "[sso][routes]") {
    SsoJitHarness h;
    // A realistic OIDC principal — contains '/' (in the issuer URL) and '#'
    // (the iss/sub separator). httplib percent-decodes the path (%2F -> '/',
    // %23 -> '#') and strips the literal '#' fragment BEFORE route-regex
    // matching, so a `([^/]+)` PATH SEGMENT can never carry this shape — the
    // path-only route 404s for every real IdP identity (this is exactly what
    // this test must observe against the pre-fix route below).
    const std::string principal = "oidc:https://idp.example.com/#sub-4821";
    REQUIRE(h.auth_db.upsert_sso_identity(principal, "https://idp.example.com/", "sub-4821",
                                          "Test SSO", "oidc")
                .has_value());
    CHECK(h.auth_db.is_elevation_eligible(principal).value() == false);

    auto admin = h.admin_session();
    // Query value: '#' percent-encoded (%23) so it survives to the handler
    // as part of the query string rather than being parsed as a URL
    // fragment; the '/' in the issuer is passed through literal (query
    // values don't need '/' escaped).
    auto res = h.post(
        "/api/v1/users/elevation-eligibility?username=oidc:https://idp.example.com/%23sub-4821",
        admin, R"({"eligible":true})");

    // Against the OLD path-only route
    // (`/api/v1/users/([^/]+)/elevation-eligibility`), this fixed two-segment
    // path (`/api/v1/users/elevation-eligibility`) never matches the
    // three-segment pattern — TestRouteSink::dispatch returns nullptr,
    // mirroring httplib's 404. This REQUIRE is the fail-without/pass-with
    // pin: it fails on the pre-fix route registration and passes once the
    // query-form route is registered.
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.auth_db.is_elevation_eligible(principal).value() == true);
}
