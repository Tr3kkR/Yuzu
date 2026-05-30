/**
 * test_auth_routes_mfa.cpp — Route-level coverage for the MFA login flow
 * added by PR1 of the TOTP MFA ladder (SOC 2 CC6.6).
 *
 * Closes the quality-engineer Gate 3 SHOULD-FIX that PR1 deferred. The
 * internal governance pipeline missed Hermes Agent's CRITICAL finding
 * (`/login/mfa` was unreachable behind the pre-routing auth gate at
 * `server.cpp:2393`) because the review never exercised the wire path
 * end-to-end. Hermes hit it within 30 seconds of live `curl` probing.
 * This file is the regression net for that class of bug — every
 * MFA-related handler is dispatched through a real `TestRouteSink` so a
 * future contributor narrowing the exemption list or breaking the
 * pending-token contract trips a test instead of shipping.
 *
 * Pattern: same as `test_settings_routes_users.cpp` — register AuthRoutes
 * against an in-process TestRouteSink, dispatch synthesized requests,
 * assert on response status / cookie / body and on the audit chain via
 * the real AuditStore.
 *
 * Why in-process and not a real `httplib::Server`: the prior fixture
 * pattern spun up a listening server behind a `std::thread` acceptor,
 * which crashes under TSan with no TSan report (#438).
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

#include <chrono>
#include <filesystem>
#include <memory>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace fs = std::filesystem;
using namespace yuzu::server;

namespace {

/// RAII temp-dir guard. Must be the first member so the directory is
/// cleaned up even when a later REQUIRE in the harness constructor
/// throws.
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

/// Harness that wires AuthRoutes against an in-process TestRouteSink,
/// seeds an admin and a regular user, and exposes Get/Post helpers.
///
/// `auth_mgr` has AuthDB attached so the MFA accessors (`mfa_status`,
/// `mfa_init_enrollment`, `mfa_verify_login_code`, etc.) work. AuthDB
/// is constructed with `cleanup_interval_secs=0` to skip the background
/// reaper jthread (per PR #1199's macOS-arm64 SIGSEGV fix).
struct AuthRoutesHarness {
    TmpDirGuard tmp;
    Config cfg{};
    auth::AuthManager auth_mgr{};
    AuthDB auth_db;
    std::unique_ptr<ApiTokenStore> api_tokens;
    std::unique_ptr<AuditStore> audit_store;
    std::unique_ptr<AnalyticsEventStore> analytics_store;
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    std::unique_ptr<AuthRoutes> auth_routes;

    yuzu::server::test::TestRouteSink sink;

    AuthRoutesHarness()
        : tmp(yuzu::test::unique_temp_path("auth-routes-mfa-")),
          auth_db(tmp.path, /*cleanup_interval_secs=*/0) {
        cfg.auth_config_path = tmp.path / "auth.cfg";
        // Tight pending-token TTL so we can assert expiry without
        // sleeping minutes in tests.
        cfg.mfa_login_pending_secs = 2;
        cfg.https_enabled = false; // no Secure cookie suffix

        REQUIRE(auth_db.initialize().has_value());
        auth_mgr.load_config(cfg.auth_config_path);
        REQUIRE(auth_mgr.upsert_user("admin", "adminpassword1", auth::Role::admin));
        REQUIRE(auth_mgr.upsert_user("alice", "alicepassword1", auth::Role::user));
        // Mirror users into AuthDB so verify_password's "still active in
        // AuthDB" check succeeds (auth.cpp:443).
        auto salt = auth::AuthManager::random_bytes(16);
        auto salt_hex = auth::AuthManager::bytes_to_hex(salt);
        REQUIRE(auth_db
                    .upsert_user("admin", auth::AuthManager::pbkdf2_sha256("adminpassword1", salt,
                                                                            100'000),
                                 salt_hex, auth::Role::admin)
                    .has_value());
        salt = auth::AuthManager::random_bytes(16);
        salt_hex = auth::AuthManager::bytes_to_hex(salt);
        REQUIRE(auth_db
                    .upsert_user("alice", auth::AuthManager::pbkdf2_sha256("alicepassword1", salt,
                                                                            100'000),
                                 salt_hex, auth::Role::user)
                    .has_value());

        // Connect AuthDB to AuthManager so mfa_status / verify_password
        // / create_local_session can find each other.
        auth_mgr.set_auth_db(&auth_db);

        // Force AuthManager's in-memory users_ to use the DB-side salt
        // by re-loading "admin"/"alice" through upsert_user (which
        // stores its own salt). We rebuild AuthManager's view with
        // PBKDF2-matching salts so `verify_password` succeeds end-to-end.
        // (This is a quirk of the dual-store layout: AuthManager keeps
        // the in-memory users_ map for verify; AuthDB is the persisted
        // mirror used by mfa_* and the post-soft-delete is_active gate.)
        // The simplest fix is to use the same password through
        // AuthManager and AuthDB.
        // No-op here — auth_mgr.upsert_user already hashed with its own
        // salt and wrote the in-memory entry. AuthDB's row is for the
        // is_active check only.

        api_tokens = std::make_unique<ApiTokenStore>(tmp.path / "api_tokens.db");
        audit_store = std::make_unique<AuditStore>(tmp.path / "audit.db");
        analytics_store = std::make_unique<AnalyticsEventStore>(tmp.path / "analytics.db");
        REQUIRE(api_tokens->is_open());

        auth_routes = std::make_unique<AuthRoutes>(
            cfg, auth_mgr,
            /*rbac_store=*/nullptr, api_tokens.get(), audit_store.get(),
            /*mgmt_group_store=*/nullptr, /*tag_store=*/nullptr, analytics_store.get(), oidc_mu,
            oidc_provider);
        auth_routes->register_routes(sink);
    }

    /// Compute a TOTP code for the given base32 secret at a counter
    /// `offset` steps from now. Default `offset=1` puts the code one
    /// step in the future, safely past the `mfa_last_counter` floor
    /// that mfa_verify_enrollment wrote during enroll_mfa() — without
    /// this, enrollment-verify and the immediately-following /login/mfa
    /// land in the same 30 s window and the login code is rejected as
    /// replay. verify_window accepts ±1 step skew so counter+1 still
    /// lands within the acceptance window for both N=E and N=E+1.
    std::string totp_at(const std::string& secret_b32, int offset = 1) {
        auto bytes = mfa::base32_decode(secret_b32);
        REQUIRE(bytes.has_value());
        std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
        auto counter = mfa::current_counter(std::chrono::system_clock::now()) + offset;
        return mfa::generate(raw, counter);
    }

    /// Enroll `username` (defaults to admin) in MFA. Returns the base32
    /// secret so the test can compute fresh TOTP codes against it.
    std::string enroll_mfa(const std::string& username = "admin") {
        auto init = auth_db.mfa_init_enrollment(username, "Yuzu");
        REQUIRE(init.has_value());
        auto code = totp_at(init->secret_base32, 0);
        REQUIRE(auth_db.mfa_verify_enrollment(username, code).has_value());
        return init->secret_base32;
    }

    /// Count audit rows that match action + principal.
    int count_audits(const std::string& action, const std::string& principal = {}) {
        AuditQuery q;
        q.action = action;
        if (!principal.empty())
            q.principal = principal;
        return static_cast<int>(audit_store->query(q).size());
    }
};

/// Build a form-encoded body from `key=value` pairs.
std::string form(std::initializer_list<std::pair<std::string, std::string>> kv) {
    std::string out;
    bool first = true;
    for (const auto& [k, v] : kv) {
        if (!first)
            out += "&";
        first = false;
        out += k + "=" + v;
    }
    return out;
}

} // namespace

TEST_CASE("POST /login no-MFA success returns 200 + session cookie + auth.login audit",
          "[mfa][routes][auth_routes]") {
    AuthRoutesHarness h;
    auto res = h.sink.Post("/login", form({{"username", "admin"}, {"password", "adminpassword1"}}),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body == R"({"status":"ok"})");
    auto cookie = res->get_header_value("Set-Cookie");
    CHECK(cookie.find("yuzu_session=") != std::string::npos);
    CHECK(h.count_audits("auth.login", "admin") >= 1);
    // 202 path was NOT taken — no mfa.login.required row.
    CHECK(h.count_audits("mfa.login.required", "admin") == 0);
}

TEST_CASE("POST /login bad password returns 401 + auth.login_failed audit",
          "[mfa][routes][auth_routes]") {
    AuthRoutesHarness h;
    auto res = h.sink.Post("/login", form({{"username", "admin"}, {"password", "wrong"}}),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK(res->body.find(R"("code":401)") != std::string::npos);
    CHECK(res->get_header_value("Set-Cookie").empty());
    CHECK(h.count_audits("auth.login_failed") >= 1);
}

TEST_CASE("POST /login MFA-enrolled returns 202 + mfa_pending_token, no cookie",
          "[mfa][routes][auth_routes]") {
    AuthRoutesHarness h;
    h.enroll_mfa("admin");
    auto res = h.sink.Post("/login", form({{"username", "admin"}, {"password", "adminpassword1"}}),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 202);
    CHECK(res->body.find(R"("status":"mfa_required")") != std::string::npos);
    CHECK(res->body.find(R"("mfa_pending_token")") != std::string::npos);
    CHECK(res->body.find(R"("expires_in":2)") != std::string::npos);
    CHECK(res->get_header_value("Set-Cookie").empty());
    CHECK(h.count_audits("mfa.login.required", "admin") >= 1);
    // Crucially, auth.login is NOT emitted yet — only the .required
    // verb. The terminal auth.login lands on the /login/mfa success
    // path.
    CHECK(h.count_audits("auth.login", "admin") == 0);
}

TEST_CASE("POST /login/mfa with valid TOTP mints session and emits dual audit (mfa.login.verified "
          "+ auth.login)",
          "[mfa][routes][auth_routes]") {
    AuthRoutesHarness h;
    auto secret_b32 = h.enroll_mfa("admin");
    // First leg: /login → 202 + pending token
    auto step1 = h.sink.Post("/login",
                             form({{"username", "admin"}, {"password", "adminpassword1"}}),
                             "application/x-www-form-urlencoded");
    REQUIRE(step1->status == 202);
    auto body = step1->body;
    auto pending_start = body.find(R"("mfa_pending_token":")") + 21;
    auto pending_end = body.find('"', pending_start);
    auto pending = body.substr(pending_start, pending_end - pending_start);
    REQUIRE(pending.size() == 64);

    auto code = h.totp_at(secret_b32);
    auto step2 = h.sink.Post("/login/mfa", form({{"mfa_pending_token", pending}, {"code", code}}),
                             "application/x-www-form-urlencoded");
    REQUIRE(step2);
    CHECK(step2->status == 200);
    CHECK(step2->get_header_value("Set-Cookie").find("yuzu_session=") != std::string::npos);
    // Dual audit emission per the Gate 4 architect S2 fix.
    CHECK(h.count_audits("mfa.login.verified", "admin") >= 1);
    CHECK(h.count_audits("auth.login", "admin") >= 1);
}

TEST_CASE("POST /login/mfa with valid recovery code emits mfa.recovery_code.used + auth.login",
          "[mfa][routes][auth_routes]") {
    AuthRoutesHarness h;
    h.enroll_mfa("admin");
    // Pull a freshly minted recovery code by regenerating (init's reveal
    // is consumed inside enroll_mfa via mfa_verify_enrollment which
    // returned them, but we discarded the return — regenerate gives a
    // clean batch we own).
    auto codes = h.auth_db.mfa_regenerate_recovery_codes("admin");
    REQUIRE(codes.has_value());
    REQUIRE_FALSE(codes->empty());
    auto recovery = codes->front();

    auto step1 = h.sink.Post("/login",
                             form({{"username", "admin"}, {"password", "adminpassword1"}}),
                             "application/x-www-form-urlencoded");
    REQUIRE(step1->status == 202);
    auto body = step1->body;
    auto p_start = body.find(R"("mfa_pending_token":")") + 21;
    auto pending = body.substr(p_start, body.find('"', p_start) - p_start);

    auto step2 =
        h.sink.Post("/login/mfa", form({{"mfa_pending_token", pending}, {"code", recovery}}),
                    "application/x-www-form-urlencoded");
    REQUIRE(step2);
    CHECK(step2->status == 200);
    CHECK(step2->get_header_value("Set-Cookie").find("yuzu_session=") != std::string::npos);
    CHECK(h.count_audits("mfa.recovery_code.used", "admin") >= 1);
    CHECK(h.count_audits("auth.login", "admin") >= 1);
    // The recovery-code branch must NOT also emit mfa.login.verified —
    // that verb belongs to the TOTP branch (otherwise the count of
    // "TOTP logins" is double-attributed).
    CHECK(h.count_audits("mfa.login.verified", "admin") == 0);
}

TEST_CASE("POST /login/mfa with invalid pending token returns 401 + audit",
          "[mfa][routes][auth_routes]") {
    AuthRoutesHarness h;
    auto res = h.sink.Post(
        "/login/mfa",
        form({{"mfa_pending_token", std::string(64, 'a')}, {"code", "123456"}}),
        "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK(res->body == R"({"error":{"code":401,"message":"Invalid verification code"},"meta":{"api_version":"v1"}})");
    CHECK(h.count_audits("mfa.login.failed") >= 1);
}

TEST_CASE("POST /login/mfa attempts cap erases pending after 5 failures",
          "[mfa][routes][auth_routes]") {
    AuthRoutesHarness h;
    h.enroll_mfa("admin");
    auto step1 = h.sink.Post("/login",
                             form({{"username", "admin"}, {"password", "adminpassword1"}}),
                             "application/x-www-form-urlencoded");
    auto body = step1->body;
    auto p_start = body.find(R"("mfa_pending_token":")") + 21;
    auto pending = body.substr(p_start, body.find('"', p_start) - p_start);

    // First 5 attempts return 401 but the token survives (attempts
    // counter increments).
    for (int i = 0; i < 5; ++i) {
        auto r = h.sink.Post("/login/mfa",
                             form({{"mfa_pending_token", pending}, {"code", "000000"}}),
                             "application/x-www-form-urlencoded");
        REQUIRE(r);
        CHECK(r->status == 401);
    }
    // 6th attempt: same token, would have been valid TOTP — but the
    // entry is gone after the 5th failure, so it returns the "pending
    // invalid" branch (same 401 body, indistinguishable on the wire).
    auto r6 = h.sink.Post("/login/mfa",
                          form({{"mfa_pending_token", pending}, {"code", "000000"}}),
                          "application/x-www-form-urlencoded");
    REQUIRE(r6);
    CHECK(r6->status == 401);
    // Audit detail distinguishes attempts-exhausted from per-attempt
    // failures.
    AuditQuery q;
    q.action = "mfa.login.failed";
    auto rows = h.audit_store->query(q);
    bool saw_exhausted = false;
    for (const auto& r : rows) {
        if (r.detail.find("attempts exhausted") != std::string::npos) {
            saw_exhausted = true;
            break;
        }
    }
    CHECK(saw_exhausted);
}

TEST_CASE("POST /login/mfa strict shape gate routes non-6-digit to recovery path",
          "[mfa][routes][auth_routes]") {
    AuthRoutesHarness h;
    h.enroll_mfa("admin");
    auto codes = h.auth_db.mfa_regenerate_recovery_codes("admin");
    REQUIRE(codes.has_value());

    auto step1 = h.sink.Post("/login",
                             form({{"username", "admin"}, {"password", "adminpassword1"}}),
                             "application/x-www-form-urlencoded");
    auto body = step1->body;
    auto p_start = body.find(R"("mfa_pending_token":")") + 21;
    auto pending = body.substr(p_start, body.find('"', p_start) - p_start);

    // "12345A" is 6 chars but contains a non-digit → routed to recovery.
    // No matching recovery code → 401, detail says "recovery code
    // rejected" (NOT "totp code rejected").
    auto r = h.sink.Post("/login/mfa",
                         form({{"mfa_pending_token", pending}, {"code", "12345A"}}),
                         "application/x-www-form-urlencoded");
    REQUIRE(r);
    CHECK(r->status == 401);

    AuditQuery q;
    q.action = "mfa.login.failed";
    auto rows = h.audit_store->query(q);
    bool saw_recovery = false;
    for (const auto& r : rows) {
        if (r.detail.find("recovery") != std::string::npos) {
            saw_recovery = true;
            break;
        }
    }
    CHECK(saw_recovery);
}

TEST_CASE("POST /login/mfa pending token expires after TTL", "[mfa][routes][auth_routes]") {
    AuthRoutesHarness h;
    h.enroll_mfa("admin");
    auto step1 = h.sink.Post("/login",
                             form({{"username", "admin"}, {"password", "adminpassword1"}}),
                             "application/x-www-form-urlencoded");
    auto body = step1->body;
    auto p_start = body.find(R"("mfa_pending_token":")") + 21;
    auto pending = body.substr(p_start, body.find('"', p_start) - p_start);

    // Sleep past the TTL (configured to 2 s in the harness). reap_mfa_
    // pending_locked fires on the next access via /login/mfa.
    //
    // 5000 ms = 2.5x the TTL — the conventional multiplier for wall-
    // clock-gated tests on a nightly sanitizer runner where ASan + UBSan
    // add 2-3x CPU overhead and scheduler preemption under load is
    // unbounded. Earlier iterations of this test used 2200 ms (10 %
    // margin) and 2800 ms (40 % margin); cpp-safety + qe both flagged
    // anything below 2x as fragile. Test now takes ~3 s extra but is
    // robust on the slowest runner in the matrix.
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));

    auto r = h.sink.Post("/login/mfa",
                         form({{"mfa_pending_token", pending}, {"code", "000000"}}),
                         "application/x-www-form-urlencoded");
    REQUIRE(r);
    CHECK(r->status == 401);
    AuditQuery q;
    q.action = "mfa.login.failed";
    auto rows = h.audit_store->query(q);
    bool saw_expired = false;
    for (const auto& r : rows) {
        if (r.detail.find("expired") != std::string::npos) {
            saw_expired = true;
            break;
        }
    }
    CHECK(saw_expired);
}

// ── /login/mfa/stepup tests (PR2) ─────────────────────────────────────────

namespace {

/// Helper: full PR1 login dance (password → 202 → TOTP → 200) and return
/// the session cookie value so step-up tests can authenticate. Drives the
/// real routes end-to-end so any future change that breaks the cookie
/// shape or the dual-audit trips a test in `[mfa][stepup]` as well as
/// `[mfa][routes][auth_routes]`.
std::string login_with_mfa(AuthRoutesHarness& h, const std::string& username,
                           const std::string& password, const std::string& secret_b32) {
    auto step1 =
        h.sink.Post("/login", form({{"username", username}, {"password", password}}),
                    "application/x-www-form-urlencoded");
    REQUIRE(step1);
    REQUIRE(step1->status == 202);
    auto body = step1->body;
    auto p_start = body.find(R"("mfa_pending_token":")") + 21;
    auto pending = body.substr(p_start, body.find('"', p_start) - p_start);

    auto code = h.totp_at(secret_b32, 1);
    auto step2 = h.sink.Post("/login/mfa", form({{"mfa_pending_token", pending}, {"code", code}}),
                             "application/x-www-form-urlencoded");
    REQUIRE(step2);
    REQUIRE(step2->status == 200);
    auto cookie_hdr = step2->get_header_value("Set-Cookie");
    auto eq = cookie_hdr.find("yuzu_session=");
    REQUIRE(eq != std::string::npos);
    auto sc = cookie_hdr.find(';', eq);
    return cookie_hdr.substr(eq, sc == std::string::npos ? cookie_hdr.size() - eq : sc - eq);
}

} // namespace

TEST_CASE(
    "POST /login/mfa/stepup with valid fresh TOTP succeeds and emits mfa.step_up.passed",
    "[mfa][stepup][routes]") {
    AuthRoutesHarness h;
    auto secret = h.enroll_mfa("admin");
    auto cookie = login_with_mfa(h, "admin", "adminpassword1", secret);

    // verify_window is ±1 step (PR1) and login_with_mfa consumed counter+1,
    // so the next code we could verify in this 30 s window is counter+2 —
    // which is OUT of window. Without sleeping 30 s, the only way to test
    // a TOTP-path step-up success deterministically is to disable + re-
    // enroll, which resets `mfa_last_counter` to 0. The session cookie
    // remains valid because the session row is keyed by token, not by the
    // user's MFA state.
    REQUIRE(h.auth_db.mfa_disable("admin").has_value());
    auto fresh_secret = h.enroll_mfa("admin");
    auto stepup_code = h.totp_at(fresh_secret, 1);

    auto res = h.sink.dispatch("POST", "/login/mfa/stepup",
                               form({{"code", stepup_code}}),
                               "application/x-www-form-urlencoded",
                               {{"Cookie", cookie}});
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->body.find(R"("status":"ok")") != std::string::npos);
    CHECK(h.count_audits("mfa.step_up.passed", "admin") >= 1);
    CHECK(h.count_audits("mfa.step_up.failed") == 0);
}

TEST_CASE(
    "POST /login/mfa/stepup with a recovery code succeeds and emits mfa.step_up.passed",
    "[mfa][stepup][routes]") {
    AuthRoutesHarness h;
    auto secret = h.enroll_mfa("admin");
    auto codes = h.auth_db.mfa_regenerate_recovery_codes("admin");
    REQUIRE(codes.has_value());
    REQUIRE_FALSE(codes->empty());
    auto recovery = codes->front();

    auto cookie = login_with_mfa(h, "admin", "adminpassword1", secret);

    auto res = h.sink.dispatch("POST", "/login/mfa/stepup",
                               form({{"code", recovery}}),
                               "application/x-www-form-urlencoded",
                               {{"Cookie", cookie}});
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.count_audits("mfa.step_up.passed", "admin") >= 1);
    // Recovery codes are single-use — second attempt must fail.
    auto res2 = h.sink.dispatch("POST", "/login/mfa/stepup",
                                form({{"code", recovery}}),
                                "application/x-www-form-urlencoded",
                                {{"Cookie", cookie}});
    REQUIRE(res2);
    CHECK(res2->status == 401);
    CHECK(h.count_audits("mfa.step_up.failed", "admin") >= 1);
}

TEST_CASE("POST /login/mfa/stepup without a session returns 401 (require_auth gate)",
          "[mfa][stepup][routes]") {
    AuthRoutesHarness h;
    h.enroll_mfa("admin");
    auto res = h.sink.Post("/login/mfa/stepup", form({{"code", "123456"}}),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 401);
    // No session → no principal → no mfa.step_up audit at all.
    CHECK(h.count_audits("mfa.step_up.passed") == 0);
    CHECK(h.count_audits("mfa.step_up.failed") == 0);
}

TEST_CASE("POST /login/mfa/stepup with empty code body returns 400 + audit",
          "[mfa][stepup][routes]") {
    AuthRoutesHarness h;
    auto secret = h.enroll_mfa("admin");
    auto cookie = login_with_mfa(h, "admin", "adminpassword1", secret);

    auto res = h.sink.dispatch("POST", "/login/mfa/stepup", "",
                               "application/x-www-form-urlencoded",
                               {{"Cookie", cookie}});
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.count_audits("mfa.step_up.failed", "admin") >= 1);
}

TEST_CASE("POST /login/mfa/stepup with wrong TOTP returns 401 + mfa.step_up.failed",
          "[mfa][stepup][routes]") {
    AuthRoutesHarness h;
    auto secret = h.enroll_mfa("admin");
    auto cookie = login_with_mfa(h, "admin", "adminpassword1", secret);

    auto res = h.sink.dispatch("POST", "/login/mfa/stepup",
                               form({{"code", "000000"}}),
                               "application/x-www-form-urlencoded",
                               {{"Cookie", cookie}});
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK(res->body.find("MFA step-up failed") != std::string::npos);

    AuditQuery q;
    q.action = "mfa.step_up.failed";
    q.principal = "admin";
    auto rows = h.audit_store->query(q);
    REQUIRE_FALSE(rows.empty());
    bool saw_totp_reject = false;
    for (const auto& r : rows) {
        if (r.detail.find("totp code rejected") != std::string::npos) {
            saw_totp_reject = true;
            break;
        }
    }
    CHECK(saw_totp_reject);
}

TEST_CASE("POST /login/mfa concurrent submit with same token: exactly one wins",
          "[mfa][routes][auth_routes]") {
    AuthRoutesHarness h;
    auto secret_b32 = h.enroll_mfa("admin");
    auto step1 = h.sink.Post("/login",
                             form({{"username", "admin"}, {"password", "adminpassword1"}}),
                             "application/x-www-form-urlencoded");
    auto body = step1->body;
    auto p_start = body.find(R"("mfa_pending_token":")") + 21;
    auto pending = body.substr(p_start, body.find('"', p_start) - p_start);

    auto code = h.totp_at(secret_b32);

    // Race two threads through /login/mfa with the same pending token +
    // same code. The atomic erase-on-lookup guarantees exactly one
    // succeeds.
    std::atomic<int> successes{0};
    std::atomic<int> failures{0};
    auto worker = [&]() {
        auto r = h.sink.Post("/login/mfa",
                             form({{"mfa_pending_token", pending}, {"code", code}}),
                             "application/x-www-form-urlencoded");
        if (r && r->status == 200) {
            ++successes;
        } else {
            ++failures;
        }
    };
    std::thread t1(worker);
    std::thread t2(worker);
    t1.join();
    t2.join();
    CHECK(successes.load() == 1);
    CHECK(failures.load() == 1);
}
