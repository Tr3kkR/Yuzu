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
#include <thread>

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

// ── Follow-up B: clamp to the session's absolute lifetime ──────────────────

TEST_CASE("AuthManager::elevate_session clamps the window to the session's own "
         "absolute expiry",
         "[jit][auth]") {
    auto mgr = make_temp_auth();
    mgr->upsert_user("carol", "secret123456", Role::user);
    auto token = mgr->authenticate("carol", "secret123456");
    REQUIRE(token.has_value());
    auto session_before = mgr->validate_session(*token);
    REQUIRE(session_before.has_value());

    // Request a window far longer than the session's own absolute lifetime
    // (kSessionDuration = 8h) — an elevation must never outlive the cookie
    // session that carries it (residual-risk follow-up B).
    auto until = mgr->elevate_session(*token, std::chrono::hours(48));
    REQUIRE(until.has_value());
    CHECK(*until <= session_before->expires_at);
    // And meaningfully clamped, not merely coincidentally equal — the naive
    // (unclamped) now+48h would be far beyond the session's ~8h expiry.
    CHECK(*until < std::chrono::steady_clock::now() + std::chrono::hours(47));

    // A short, well-inside-the-session-lifetime window is NOT clamped.
    auto token2 = mgr->authenticate("carol", "secret123456");
    REQUIRE(token2.has_value());
    auto before2 = std::chrono::steady_clock::now();
    auto until2 = mgr->elevate_session(*token2, std::chrono::seconds(60));
    REQUIRE(until2.has_value());
    CHECK(*until2 >= before2 + std::chrono::seconds(58));
    CHECK(*until2 <= before2 + std::chrono::seconds(65));
}

// ── Follow-up A: lazy passive-expiry reaping ────────────────────────────────

TEST_CASE("AuthManager::reap_expired_elevation fires exactly once on a passive "
         "lapse",
         "[jit][auth]") {
    auto mgr = make_temp_auth();
    mgr->upsert_user("dave", "secret123456", Role::user);
    auto token = mgr->authenticate("dave", "secret123456");
    REQUIRE(token.has_value());

    // A 1s window, then a real sleep past it — duration(0) no longer works
    // here: elevate_session's dead-window guard (governance hardening round,
    // UP-1/UP-4) now REJECTS a request that would clamp to `until <= now`
    // rather than granting a zero-length window, so the smallest grantable
    // positive window must actually lapse via real time.
    REQUIRE(mgr->elevate_session(*token, std::chrono::seconds(1)).has_value());
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    auto reaped = mgr->reap_expired_elevation(*token);
    REQUIRE(reaped.has_value());
    CHECK(*reaped == "dave");
    // Idempotent: the sentinel-clear on the first reap makes a second call a
    // no-op (never double-emits `role.elevation.expired`).
    CHECK_FALSE(mgr->reap_expired_elevation(*token).has_value());

    auto s = mgr->validate_session(*token);
    REQUIRE(s.has_value());
    CHECK_FALSE(auth::is_elevated(*s));

    // Unknown / oversized token → nullopt, same posture as the sibling methods.
    CHECK_FALSE(mgr->reap_expired_elevation("deadbeef").has_value());
    CHECK_FALSE(mgr->reap_expired_elevation(std::string(600, 'a')).has_value());
}

TEST_CASE("AuthManager::reap_expired_elevation is a no-op after a manual revoke",
         "[jit][auth]") {
    auto mgr = make_temp_auth();
    mgr->upsert_user("erin", "secret123456", Role::user);
    auto token = mgr->authenticate("erin", "secret123456");
    REQUIRE(token.has_value());
    REQUIRE(mgr->elevate_session(*token, std::chrono::seconds(60)).has_value());

    // Manual step-down clears elevated_until to the same sentinel a passive
    // reap would — so a manually-revoked window must never ALSO report an
    // "expired" event (it already has its own role.elevation.revoked row).
    CHECK(mgr->revoke_elevation(*token));
    CHECK_FALSE(mgr->reap_expired_elevation(*token).has_value());

    // Not-yet-elevated / never-elevated is likewise a no-op.
    auto token2 = mgr->authenticate("erin", "secret123456");
    REQUIRE(token2.has_value());
    CHECK_FALSE(mgr->reap_expired_elevation(*token2).has_value());
}

// ── Governance hardening round: dead-window guard (UP-1/UP-4) ──────────────

TEST_CASE("AuthManager::elevate_session rejects a dead window (nullopt) when the "
         "session is already at/past its own absolute expiry",
         "[jit][auth]") {
    auto mgr = make_temp_auth();
    mgr->upsert_user("frank", "secret123456", Role::user);
    auto token = mgr->authenticate("frank", "secret123456");
    REQUIRE(token.has_value());

    // Push the session's absolute expires_at into the past (TEST-ONLY seam —
    // no clean way to construct an already-expired session through the
    // public API, since kSessionDuration is a fixed 8h and there is no
    // reduced-lifetime session constructor). Any clamp against an
    // already-past expires_at yields `until <= now`, which the dead-window
    // guard must REJECT — never mutate the session or report a granted
    // zero-or-negative-length window.
    mgr->expire_session_for_test(*token, std::chrono::hours(9)); // > kSessionDuration (8h)

    CHECK_FALSE(mgr->elevate_session(*token, std::chrono::seconds(60)).has_value());
    // The rejected grant must not have mutated the session: no elevation was
    // set, so a subsequent reap finds nothing to reap either.
    CHECK_FALSE(mgr->reap_expired_elevation(*token).has_value());
}

TEST_CASE("AuthManager::reap_expired_elevation is exactly-once under concurrent "
         "racers (TOCTOU guard, UP-7)",
         "[jit][auth]") {
    auto mgr = make_temp_auth();
    mgr->upsert_user("grace", "secret123456", Role::user);
    auto token = mgr->authenticate("grace", "secret123456");
    REQUIRE(token.has_value());
    REQUIRE(mgr->elevate_session(*token, std::chrono::seconds(1)).has_value());
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    // Two threads race reap_expired_elevation on the SAME already-lapsed
    // token. The shared-lock-first-then-escalate-and-recheck design
    // (governance hardening round) must serialise the clear-and-report step
    // under the exclusive lock so exactly one racer observes the username
    // and the other observes the (by-then-cleared) sentinel — never both,
    // never neither.
    std::optional<std::string> r1, r2;
    std::thread t1([&] { r1 = mgr->reap_expired_elevation(*token); });
    std::thread t2([&] { r2 = mgr->reap_expired_elevation(*token); });
    t1.join();
    t2.join();

    const int wins = (r1.has_value() ? 1 : 0) + (r2.has_value() ? 1 : 0);
    CHECK(wins == 1);
    if (r1)
        CHECK(*r1 == "grace");
    if (r2)
        CHECK(*r2 == "grace");
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
/// AuthRoutes wired against an in-process sink with: `alice` — eligible, MFA
/// enrolled (the normal elevation actor); `bob` — eligible but NOT MFA enrolled
/// (proves the mandatory-MFA gate, review security-F1); `admin` — standing
/// admin, enrolled. Elevation now REQUIRES MFA enrollment + a fresh step-up, so
/// happy-path sessions are minted via `session_for(..., fresh_mfa=true)`.
struct JitHarness {
    yuzu::test::TempDir tmp;
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

    // The comma-operator creates the temp dir (TempDir only computes the path)
    // before AuthDB opens its files under it. `audit_store_broken` (governance
    // hardening round, UP-3 guard) points the AuditStore at an unopenable
    // path — SQLITE_CANTOPEN leaves it wired-but-closed (db_==nullptr), so
    // AuditStore::log() fail-returns false without throwing, matching the
    // idiom at test_rest_audit_sample.cpp:51.
    explicit JitHarness(bool audit_store_broken = false)
        : auth_db((fs::create_directories(tmp.path), tmp.path), 0) {
        cfg.auth_config_path = tmp.path / "auth.cfg";
        cfg.https_enabled = false;
        cfg.jit_max_elevation_secs = 3600;
        REQUIRE(auth_db.initialize().has_value());
        auth_mgr.load_config(cfg.auth_config_path);
        seed("admin", "adminpassword1", Role::admin);
        seed("alice", "alicepassword1", Role::user);
        seed("bob", "bobpassword1234", Role::user);
        auth_mgr.set_auth_db(&auth_db);
        enroll_mfa("admin");
        enroll_mfa("alice");
        // bob is deliberately left WITHOUT MFA (mandatory-MFA gate test).
        REQUIRE(auth_db.set_elevation_eligible("alice", true).has_value());
        REQUIRE(auth_db.set_elevation_eligible("bob", true).has_value());

        api_tokens = std::make_unique<ApiTokenStore>(tmp.path / "api_tokens.db");
        audit_store = audit_store_broken
                          ? std::make_unique<AuditStore>("/nonexistent-yuzu-test-dir/audit-broken.db")
                          : std::make_unique<AuditStore>(tmp.path / "audit.db");
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

    void enroll_mfa(const std::string& u) {
        auto init = auth_db.mfa_init_enrollment(u, "Yuzu");
        REQUIRE(init.has_value());
        auto bytes = mfa::base32_decode(init->secret_base32);
        REQUIRE(bytes.has_value());
        std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
        auto code = mfa::generate(raw, mfa::current_counter(std::chrono::system_clock::now()));
        REQUIRE(auth_db.mfa_verify_enrollment(u, code).has_value());
    }

    // A cookie session for `u`. fresh_mfa=true stamps mfa_verified_at=now so the
    // elevation step-up passes; false leaves the epoch sentinel (stale) to
    // exercise the step-up challenge.
    std::string session_for(const std::string& u, Role r = Role::user, bool fresh_mfa = true) {
        return auth_mgr.create_local_session(u, r, fresh_mfa);
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

    // principal_role recorded on the most-recent matching audit row ("" if none).
    std::string audit_role(const std::string& action, const std::string& principal) {
        AuditQuery q;
        q.action = action;
        q.principal = principal;
        auto rows = audit_store->query(q);
        return rows.empty() ? std::string{} : rows.front().principal_role;
    }
};
} // namespace

TEST_CASE("POST /api/v1/elevate: eligible operator is elevated to admin", "[jit][routes]") {
    JitHarness h;
    auto token = h.session_for("alice");

    auto res = h.post("/api/v1/elevate", token,
                      R"({"justification":"prod incident #42","duration_secs":600})");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    // expires_in is now the TRUE remaining time (follow-up B, computed a
    // moment after the grant) — never MORE than the requested duration, and
    // within a second or two of it (no clamp applies: the session's absolute
    // lifetime is 8h, far longer than 600s).
    int expires_in = body.value("expires_in", -1);
    CHECK(expires_in <= 600);
    CHECK(expires_in >= 598);
    // expires_at is the wall-clock RFC3339 UTC projection (follow-up B),
    // well-formed "YYYY-MM-DDTHH:MM:SSZ" — not just non-empty (governance
    // hardening round, format assertion).
    auto expires_at = body.value("expires_at", std::string{});
    CHECK_FALSE(expires_at.empty());
    CHECK(expires_at.size() == 20);
    CHECK(expires_at.back() == 'Z');
    CHECK(h.count_audits("role.elevation.granted", "alice") == 1);
    // The granted audit detail carries expires_at too (governance hardening
    // round consistency check — grant audit, response body, and analytics
    // event must all agree).
    {
        AuditQuery q;
        q.action = "role.elevation.granted";
        q.principal = "alice";
        auto rows = h.audit_store->query(q);
        REQUIRE_FALSE(rows.empty());
        CHECK(rows.front().detail.find("expires_at=") != std::string::npos);
    }

    // The session is now effectively admin.
    auto s = h.auth_mgr.validate_session(token);
    REQUIRE(s.has_value());
    CHECK(auth::is_elevated(*s));
    CHECK(auth::effective_role(*s) == Role::admin);
}

TEST_CASE("an elevated operator can perform an admin-gated action", "[jit][routes]") {
    JitHarness h;
    auto token = h.session_for("alice");
    // Before elevation: the admin-gated eligibility endpoint is forbidden.
    auto before = h.post("/api/v1/users/bob/elevation-eligibility", token,
                         R"({"eligible":false})");
    REQUIRE(before);
    CHECK(before->status == 403);

    // Elevate, then the same admin-gated call succeeds (effective_role == admin).
    REQUIRE(h.post("/api/v1/elevate", token, R"({"justification":"manage bob"})")->status == 200);
    auto after = h.post("/api/v1/users/bob/elevation-eligibility", token,
                        R"({"eligible":false})");
    REQUIRE(after);
    CHECK(after->status == 200);
    CHECK(h.auth_db.is_elevation_eligible("bob").value() == false);
}

TEST_CASE("an elevated admin action is audited as principal_role=admin (H1)", "[jit][routes]") {
    JitHarness h;
    auto token = h.session_for("alice"); // base role: user
    REQUIRE(h.post("/api/v1/elevate", token, R"({"justification":"x"})")->status == 200);
    // An admin-gated action performed under the elevation must record the
    // EFFECTIVE role (admin), not alice's base role — SOC 2 evidence-integrity.
    REQUIRE(h.post("/api/v1/users/bob/elevation-eligibility", token,
                   R"({"eligible":false})")->status == 200);
    CHECK(h.audit_role("user.elevation_eligibility.set", "alice") == "admin");
    // The grant row itself is also admin (granted stamps the effective role).
    CHECK(h.audit_role("role.elevation.granted", "alice") == "admin");
}

TEST_CASE("POST /api/v1/elevate: MFA enrollment is mandatory to elevate", "[jit][routes]") {
    JitHarness h;
    // bob is eligible but has NO second factor enrolled — elevation is the
    // privilege-crossing boundary, so it is refused regardless of mfa_enforcement
    // (review security-F1). A fresh-proof flag cannot substitute for enrollment.
    auto token = h.session_for("bob");
    auto res = h.post("/api/v1/elevate", token, R"({"justification":"let me in"})");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.count_audits("role.elevation.denied", "bob") == 1);
    CHECK_FALSE(auth::is_elevated(*h.auth_mgr.validate_session(token)));
}

TEST_CASE("POST /api/v1/elevate: a stale MFA proof is challenged, not granted", "[jit][routes]") {
    JitHarness h;
    // alice IS enrolled but the session has no fresh proof (mfa_verified_at at the
    // epoch sentinel) → the step-up gate challenges; elevation is NOT granted.
    auto token = h.session_for("alice", Role::user, /*fresh_mfa=*/false);
    auto res = h.post("/api/v1/elevate", token, R"({"justification":"x"})");
    REQUIRE(res);
    CHECK(res->status != 200); // step-up challenge (4xx), not a grant
    CHECK(h.count_audits("role.elevation.granted", "alice") == 0);
    CHECK_FALSE(auth::is_elevated(*h.auth_mgr.validate_session(token)));
}

TEST_CASE("POST /api/v1/elevate: an ineligible operator is denied", "[jit][routes]") {
    JitHarness h;
    REQUIRE(h.auth_db.set_elevation_eligible("alice", false).has_value()); // revoke eligibility
    auto token = h.session_for("alice");
    auto res = h.post("/api/v1/elevate", token, R"({"justification":"x"})");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.count_audits("role.elevation.denied", "alice") == 1);
    CHECK_FALSE(auth::is_elevated(*h.auth_mgr.validate_session(token)));
}

TEST_CASE("POST /api/v1/elevate: justification is mandatory", "[jit][routes]") {
    JitHarness h;
    auto token = h.session_for("alice");
    auto res = h.post("/api/v1/elevate", token, R"({"justification":"   "})"); // whitespace only
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK_FALSE(auth::is_elevated(*h.auth_mgr.validate_session(token)));
}

TEST_CASE("POST /api/v1/elevate: wrong-typed fields are a 400, not a 500", "[jit][routes]") {
    JitHarness h;
    auto token = h.session_for("alice");
    // A present-but-wrong-type field must be a clean client error (review UP-2).
    CHECK(h.post("/api/v1/elevate", token, R"({"justification":123})")->status == 400);
    CHECK(h.post("/api/v1/elevate", token,
                 R"({"justification":"x","duration_secs":"soon"})")->status == 400);
    // A negative duration is rejected, not silently mapped to the max (review UP-5).
    CHECK(h.post("/api/v1/elevate", token,
                 R"({"justification":"x","duration_secs":-5})")->status == 400);
    CHECK_FALSE(auth::is_elevated(*h.auth_mgr.validate_session(token)));
    // A duration > INT_MAX passes is_number_integer() but must not throw → 500
    // (Hermes pass-1 #1): it clamps to the cap, granting a bounded window.
    auto huge = h.post("/api/v1/elevate", token,
                       R"({"justification":"x","duration_secs":9999999999999999})");
    REQUIRE(huge);
    CHECK(huge->status == 200);
    // expires_in is the TRUE remaining time (follow-up B) — at most the cap,
    // and within a second or two of it (no session-lifetime clamp applies).
    int huge_expires_in = nlohmann::json::parse(huge->body).value("expires_in", -1);
    CHECK(huge_expires_in <= h.cfg.jit_max_elevation_secs);
    CHECK(huge_expires_in >= h.cfg.jit_max_elevation_secs - 2);
}

TEST_CASE("POST /api/v1/elevate: duration is clamped to the cap", "[jit][routes]") {
    JitHarness h;
    auto token = h.session_for("alice");
    auto res = h.post("/api/v1/elevate", token,
                      R"({"justification":"x","duration_secs":999999})");
    REQUIRE(res);
    CHECK(res->status == 200);
    int expires_in = nlohmann::json::parse(res->body).value("expires_in", -1);
    CHECK(expires_in <= h.cfg.jit_max_elevation_secs);
    CHECK(expires_in >= h.cfg.jit_max_elevation_secs - 2);
}

TEST_CASE("POST /api/v1/elevate/revoke reverts the elevation", "[jit][routes]") {
    JitHarness h;
    auto token = h.session_for("alice");
    REQUIRE(h.post("/api/v1/elevate", token, R"({"justification":"x"})")->status == 200);
    REQUIRE(auth::is_elevated(*h.auth_mgr.validate_session(token)));

    auto res = h.post("/api/v1/elevate/revoke", token, "");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.count_audits("role.elevation.revoked", "alice") == 1);
    CHECK_FALSE(auth::is_elevated(*h.auth_mgr.validate_session(token)));
}

TEST_CASE("revoking eligibility terminates an active elevation", "[jit][routes]") {
    JitHarness h;
    // alice elevates, then an admin revokes her eligibility — her in-flight
    // elevation must drop immediately (review UP-1), not linger for the window.
    auto alice = h.session_for("alice");
    REQUIRE(h.post("/api/v1/elevate", alice, R"({"justification":"x"})")->status == 200);
    REQUIRE(auth::is_elevated(*h.auth_mgr.validate_session(alice)));

    auto admin = h.session_for("admin", Role::admin);
    auto res = h.post("/api/v1/users/alice/elevation-eligibility", admin, R"({"eligible":false})");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_FALSE(auth::is_elevated(*h.auth_mgr.validate_session(alice))); // elevation cleared
}

TEST_CASE("an operator cannot set their own elevation eligibility", "[jit][routes]") {
    JitHarness h;
    // Self-grant is blocked (review UP-6) so a temporary admin window cannot
    // manufacture a durable self-elevation right.
    auto admin = h.session_for("admin", Role::admin);
    auto res = h.post("/api/v1/users/admin/elevation-eligibility", admin, R"({"eligible":true})");
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("POST /api/v1/elevate: a tokenless (no-cookie) request is rejected", "[jit][routes]") {
    JitHarness h;
    // No Cookie header → not an interactive session → 401 (API/MCP tokens, which
    // resolve without a cookie, can never elevate).
    auto res = h.sink.Post("/api/v1/elevate", R"({"justification":"x"})");
    REQUIRE(res);
    CHECK(res->status == 401);
}

// ── Follow-up A: role.elevation.expired lazily audited at the cookie chokepoint ──

TEST_CASE("role.elevation.expired is audited lazily on the next authenticated "
         "request after a passive lapse",
         "[jit][routes]") {
    JitHarness h;
    auto token = h.session_for("alice");
    // Force a lapsed elevation directly via AuthManager (bypassing the REST
    // handler, which always grants at least a bounded window): a 1s window
    // plus a real sleep past it. duration(0) is no longer usable for this —
    // elevate_session's dead-window guard (governance hardening round,
    // UP-1/UP-4) REJECTS a request that would clamp to `until <= now` rather
    // than granting a zero-length window.
    REQUIRE(h.auth_mgr.elevate_session(token, std::chrono::seconds(1)).has_value());
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    CHECK(h.count_audits("role.elevation.expired", "alice") == 0);

    // The next authenticated request through resolve_session (the cookie
    // chokepoint) lazily reaps the lapsed window and audits it exactly once —
    // even though alice is no longer effectively admin, so the request itself
    // is denied.
    auto res = h.post("/api/v1/users/bob/elevation-eligibility", token, R"({"eligible":false})");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.count_audits("role.elevation.expired", "alice") == 1);

    // A second request does not double-emit (idempotent reap).
    auto res2 = h.post("/api/v1/users/bob/elevation-eligibility", token, R"({"eligible":false})");
    REQUIRE(res2);
    CHECK(h.count_audits("role.elevation.expired", "alice") == 1);
}

TEST_CASE("a manually revoked elevation does not ALSO emit role.elevation.expired",
         "[jit][routes]") {
    JitHarness h;
    auto token = h.session_for("alice");
    REQUIRE(h.post("/api/v1/elevate", token, R"({"justification":"x"})")->status == 200);
    REQUIRE(h.post("/api/v1/elevate/revoke", token, "")->status == 200);
    CHECK(h.count_audits("role.elevation.revoked", "alice") == 1);

    // A subsequent authenticated request must not report a spurious passive
    // expiry on top of the manual revoke's own audit row.
    auto res = h.post("/api/v1/users/bob/elevation-eligibility", token, R"({"eligible":false})");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.count_audits("role.elevation.expired", "alice") == 0);
}

TEST_CASE("a reap that fires within a request leaves THAT request's session "
         "resolving as base role (UP-9)",
         "[jit][routes]") {
    JitHarness h;
    auto token = h.session_for("alice");
    REQUIRE(h.auth_mgr.elevate_session(token, std::chrono::seconds(1)).has_value());
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    // The lazy reap fires INSIDE resolve_session, on this very request — the
    // request must be evaluated against the now-lapsed (base) role, not the
    // stale elevated one, so an admin-gated action is correctly refused in
    // the SAME request that observes the expiry.
    auto res = h.post("/api/v1/users/bob/elevation-eligibility", token, R"({"eligible":false})");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.count_audits("role.elevation.expired", "alice") == 1);

    // And the session itself now reads as base role going forward.
    auto s = h.auth_mgr.validate_session(token);
    REQUIRE(s.has_value());
    CHECK_FALSE(auth::is_elevated(*s));
    CHECK(auth::effective_role(*s) == Role::user);
}

TEST_CASE("a lazy role.elevation.expired reap survives an unwritable audit store "
         "(best-effort, UP-3)",
         "[jit][routes]") {
    JitHarness h(/*audit_store_broken=*/true);
    auto token = h.session_for("alice");
    REQUIRE(h.auth_mgr.elevate_session(token, std::chrono::seconds(1)).has_value());
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    // The AuditStore can't persist (unopenable path, db_==nullptr) — the
    // lazy reap at the resolve_session chokepoint must not crash or throw,
    // and must still CLEAR the elevation despite losing the confirmatory
    // `role.elevation.expired` row (the window's end is still reconstructible
    // from the — separately fail-closed — `granted` row's `duration_secs`/
    // `expires_at`, when the grant went through the REST path; here the
    // elevation was set directly via AuthManager to force a deterministic
    // lapse, so there is no granted row in this harness either way — the
    // assertion under test is narrowly "the reap itself doesn't crash and
    // still reaps").
    std::unique_ptr<httplib::Response> res;
    REQUIRE_NOTHROW(res = h.post("/api/v1/users/bob/elevation-eligibility", token,
                                 R"({"eligible":false})"));
    REQUIRE(res);
    CHECK(res->status == 403); // no longer effectively admin — the reap still happened

    auto s = h.auth_mgr.validate_session(token);
    REQUIRE(s.has_value());
    CHECK_FALSE(auth::is_elevated(*s));
}
