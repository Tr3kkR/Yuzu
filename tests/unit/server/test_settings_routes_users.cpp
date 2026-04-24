/**
 * test_settings_routes_users.cpp — HTTP-level tests for the Users section of
 * the Settings page, covering the self-deletion lockout guard added for
 * issues #397 and #403, the sibling self-demotion guard added in the Gate 4
 * ca-B1 hardening round, and the SOC 2 CC7.2 audit chain (CO-1).
 *
 * The bugs:
 *  - #397 (handler): DELETE /api/settings/users/:name did not reject self-
 *    targeted deletes. Confirming the hx-confirm dialog dropped the only
 *    usable credential on the running server.
 *  - #403 (UI): Settings > Users rendered a Remove button next to the
 *    operator's own row.
 *  - ca-B1 (sibling, found in governance Gate 4): POST /api/settings/users
 *    let an admin demote themselves to role=user — the same lockout class
 *    via a different route. Closed in the same hardening round.
 *  - CO-1 (compliance, found in governance Gate 6): the rejected and
 *    successful user lifecycle ops did not emit audit_fn_ events, breaking
 *    SOC 2 CC7.2 evidence chain. Closed in the hardening round.
 *
 * Pattern: register SettingsRoutes against an in-process TestRouteSink
 * and dispatch synthesized httplib::Request objects through the captured
 * handlers. The audit_fn mock captures every call into a vector so tests
 * can assert the SOC 2 evidence chain is intact on each guarded path.
 *
 * Why in-process and not a real httplib::Server: the prior fixture spun
 * up a listening server behind a std::thread acceptor, which crashes
 * deterministically under TSan with no TSan report (#438).
 */

#include "settings_routes.hpp"

#include "api_token_store.hpp"
#include "audit_store.hpp"
#include "management_group_store.hpp"
#include "oidc_provider.hpp"
#include "runtime_config_store.hpp"
#include "tag_store.hpp"
#include "test_route_sink.hpp"
#include "update_registry.hpp"
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <shared_mutex>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::server;

namespace {

static fs::path unique_temp_path(const std::string& prefix) {
    static std::atomic<unsigned> seq{0};
    auto tid = std::hash<std::thread::id>{}(std::this_thread::get_id());
    auto t = std::chrono::steady_clock::now().time_since_epoch().count();
    return fs::temp_directory_path() /
           (prefix + "-" + std::to_string(::getpid()) + "-" +
            std::to_string(tid) + "-" + std::to_string(t) + "-" +
            std::to_string(seq.fetch_add(1)));
}

/// RAII wrapper around a temp directory. Constructing it creates the
/// directory; destruction removes it. Declared as the FIRST member of the
/// harness so that even if a later REQUIRE inside the harness constructor
/// throws (port allocation, server bind, etc.) the directory is still
/// cleaned up — fully-constructed members of a partially-constructed object
/// have their destructors invoked, but the object's own destructor does
/// not. Governance Gate 3 qe-B1.
struct TmpDirGuard {
    fs::path path;
    explicit TmpDirGuard(fs::path p) : path(std::move(p)) {
        fs::create_directories(path);
    }
    ~TmpDirGuard() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    TmpDirGuard(const TmpDirGuard&) = delete;
    TmpDirGuard& operator=(const TmpDirGuard&) = delete;
};

/// Single audit call captured by the mock audit_fn.
struct AuditCall {
    std::string action;
    std::string result;
    std::string target_type;
    std::string target_id;
    std::string detail;
};

/// Harness that stands up a real httplib::Server with SettingsRoutes bound
/// to an AuthManager seeded with two accounts ("admin" + "bob"). The mock
/// auth/admin callbacks read `session_user` / `session_role` so individual
/// tests can switch perspective between calls without rebuilding the server.
/// The mock audit_fn appends every call into `audit_calls` so tests can
/// verify the SOC 2 evidence chain (CO-1).
struct SettingsRoutesHarness {
    // tmp must come first — its destructor handles cleanup if any of the
    // REQUIREs in the constructor body throw.
    TmpDirGuard tmp;
    Config cfg{};
    auth::AuthManager auth_mgr{};
    auth::AutoApproveEngine auto_approve{};
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    SettingsRoutes routes;

    yuzu::server::test::TestRouteSink sink;

    // Mock session state — the auth_fn / admin_fn closures read this so
    // tests can act as different principals against the same harness.
    std::string session_user;
    auth::Role session_role{auth::Role::admin};

    // Audit capture — each audit_fn_ call from the routes layer appends an
    // entry. Tests assert on this to verify CC7.2 evidence emission.
    std::vector<AuditCall> audit_calls;

    SettingsRoutesHarness() : tmp(unique_temp_path("settings-routes-users")) {
        cfg.auth_config_path = tmp.path / "auth.cfg";
        auth_mgr.load_config(cfg.auth_config_path);
        REQUIRE(auth_mgr.upsert_user("admin", "adminpassword1", auth::Role::admin));
        REQUIRE(auth_mgr.upsert_user("bob", "bobpassword12", auth::Role::user));

        auto auth_fn =
            [this](const httplib::Request&, httplib::Response&)
            -> std::optional<auth::Session> {
            if (session_user.empty())
                return std::nullopt;
            auth::Session s;
            s.username = session_user;
            s.role = session_role;
            return s;
        };

        auto admin_fn = [this](const httplib::Request&, httplib::Response& res) {
            if (session_user.empty() || session_role != auth::Role::admin) {
                res.status = 403;
                return false;
            }
            return true;
        };

        auto perm_fn = [](const httplib::Request&, httplib::Response&,
                          const std::string&, const std::string&) {
            return true;
        };

        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) {
            audit_calls.push_back({action, result, target_type, target_id, detail});
        };

        auto gateway_count_fn = []() -> std::size_t { return 0; };
        auto agents_json_fn = []() -> std::string { return "[]"; };

        routes.register_routes(sink, auth_fn, admin_fn, perm_fn, audit_fn,
                               cfg, auth_mgr, auto_approve,
                               /*api_token_store=*/nullptr,
                               /*mgmt_group_store=*/nullptr,
                               /*tag_store=*/nullptr,
                               /*update_registry=*/nullptr,
                               /*runtime_config_store=*/nullptr,
                               /*audit_store=*/nullptr,
                               /*gateway_enabled=*/false,
                               gateway_count_fn, agents_json_fn,
                               oidc_mu, oidc_provider);
    }
    // No destructor — TmpDirGuard cleans the temp dir on its own; nothing
    // else owns OS resources. The previous fixture had to stop() the
    // httplib::Server and join the acceptor thread; both are gone (#438).

    /// Dispatch a request through the registered routes. Returns
    /// std::unique_ptr<httplib::Response> so existing test sites that
    /// access res->status / res->body / res->get_header_value(...) keep
    /// working unchanged.
    auto Get(const std::string& path) { return sink.Get(path); }
    auto Delete(const std::string& path) { return sink.Delete(path); }
    auto Post(const std::string& path, const std::string& body,
              const std::string& ct = "application/json") {
        return sink.Post(path, body, ct);
    }
    auto Put(const std::string& path, const std::string& body,
             const std::string& ct = "application/json") {
        return sink.Put(path, body, ct);
    }

    /// True if `auth_mgr` currently lists a user with the given name.
    bool has_user(std::string_view name) const {
        for (const auto& u : auth_mgr.list_users()) {
            if (u.username == name)
                return true;
        }
        return false;
    }

    /// Current role of `name`, or std::nullopt if no such user.
    std::optional<auth::Role> role_of(std::string_view name) const {
        for (const auto& u : auth_mgr.list_users()) {
            if (u.username == name)
                return u.role;
        }
        return std::nullopt;
    }

    /// True if any captured audit call matches all four fields.
    bool has_audit(std::string_view action, std::string_view result,
                   std::string_view target_type, std::string_view target_id) const {
        for (const auto& a : audit_calls) {
            if (a.action == action && a.result == result &&
                a.target_type == target_type && a.target_id == target_id)
                return true;
        }
        return false;
    }
};

// Exact toast payloads — must stay in sync with settings_routes.cpp,
// docs/user-manual/server-admin.md, and the CHANGELOG entries.
constexpr std::string_view kSelfDeleteToast =
    R"({"showToast":{"message":"Cannot delete your own account","level":"error"}})";
constexpr std::string_view kSelfDemoteToast =
    R"({"showToast":{"message":"Cannot change your own role","level":"error"}})";
constexpr std::string_view kDuplicateUsernameToast =
    R"({"showToast":{"message":"Username already exists","level":"error"}})";
constexpr std::string_view kShortPasswordToast =
    R"({"showToast":{"message":"Password must be at least 12 characters","level":"error"}})";

} // namespace

// ── Self-deletion guard — handler side (#397) ────────────────────────────────

TEST_CASE("SettingsRoutes DELETE /api/settings/users: admin cannot delete self",
          "[settings][users][self-delete]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    auto res = h.Delete("/api/settings/users/admin");
    REQUIRE(res);
    CHECK(res->status == 403);
    // Full-payload assertion: a substring match would tolerate a regression
    // that drops the level field or injects an extra key.
    CHECK(res->get_header_value("HX-Trigger") == kSelfDeleteToast);
    CHECK(h.has_user("admin"));
    // SOC 2 CC7.2 evidence emission — denied destructive ops must reach
    // audit_store, not just spdlog (governance Gate 6 CO-1).
    CHECK(h.has_audit("user.delete", "denied", "User", "admin"));
}

TEST_CASE("SettingsRoutes DELETE /api/settings/users: admin can delete other users",
          "[settings][users]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    auto res = h.Delete("/api/settings/users/bob");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK_FALSE(h.has_user("bob"));
    // Successful destructive op also requires an audit entry (CO-1).
    CHECK(h.has_audit("user.delete", "success", "User", "bob"));
}

TEST_CASE("SettingsRoutes DELETE /api/settings/users: non-admin session rejected",
          "[settings][users]") {
    SettingsRoutesHarness h;
    h.session_user = "bob";
    h.session_role = auth::Role::user;

    auto res = h.Delete("/api/settings/users/admin");
    REQUIRE(res);
    // admin_fn_ rejects with 403 before the self-delete guard is even reached.
    CHECK(res->status == 403);
    CHECK(h.has_user("admin"));
    // No audit emission expected — the request never reached the handler
    // body, so no user-level audit event should be recorded.
    CHECK_FALSE(h.has_audit("user.delete", "denied", "User", "admin"));
}

TEST_CASE("SettingsRoutes DELETE /api/settings/users: unauthenticated session rejected",
          "[settings][users][auth]") {
    SettingsRoutesHarness h;
    // Empty session_user → mock auth_fn returns nullopt and admin_fn
    // returns false; admin_fn_ gate fires before either of the handler's
    // own defensive branches. Verifies the unauthenticated path does not
    // accidentally permit a destructive op (governance Gate 3 qe-S3).
    h.session_user = "";

    auto res = h.Delete("/api/settings/users/admin");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.has_user("admin"));
    CHECK(h.audit_calls.empty());
}

// ── Self-demotion guard — POST upsert sibling (ca-B1) ────────────────────────

TEST_CASE("SettingsRoutes POST /api/settings/users: admin cannot demote own role",
          "[settings][users][self-demote]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    // Form-urlencoded body — that's what the dashboard sends and what
    // extract_form_value parses.
    auto res = h.Post("/api/settings/users",
                        "username=admin&password=newadminpass1&role=user",
                        "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(res->get_header_value("HX-Trigger") == kSelfDemoteToast);
    // Role must remain admin — the upsert must not have run.
    auto role = h.role_of("admin");
    REQUIRE(role.has_value());
    CHECK(*role == auth::Role::admin);
    // Audit chain captures the rejection.
    CHECK(h.has_audit("user.upsert", "denied", "User", "admin"));
}

TEST_CASE("SettingsRoutes POST /api/settings/users: admin self-password-change allowed",
          "[settings][users]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    // Same role — only password is changing. The self-demotion guard must
    // NOT block this; it specifically targets role transitions.
    auto res = h.Post("/api/settings/users",
                        "username=admin&password=anotherpass12&role=admin",
                        "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto role = h.role_of("admin");
    REQUIRE(role.has_value());
    CHECK(*role == auth::Role::admin);
    CHECK(h.has_audit("user.upsert", "success", "User", "admin"));
}

TEST_CASE("SettingsRoutes POST /api/settings/users: success path renders self-row guard",
          "[settings][users][ui]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    // Add a new user. Response body is the re-rendered fragment; verify
    // (a) the new user shows up with a Remove button and (b) the operator's
    // own row still has the Current user badge — the self_name threading
    // through the success path matters because the dashboard swaps this
    // body into #user-section.
    auto res = h.Post("/api/settings/users",
                        "username=carol&password=carolpassword1&role=user",
                        "application/x-www-form-urlencoded");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    CHECK(h.has_user("carol"));
    CHECK(res->body.find("hx-delete=\"/api/settings/users/carol\"") != std::string::npos);
    CHECK(res->body.find("hx-delete=\"/api/settings/users/admin\"") == std::string::npos);
    CHECK(res->body.find("Current user") != std::string::npos);
    CHECK(h.has_audit("user.upsert", "success", "User", "carol"));
}

// ── Duplicate-username guard (#399) ──────────────────────────────────────────

TEST_CASE("SettingsRoutes POST /api/settings/users: duplicate username rejected",
          "[settings][users][duplicate]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    // 'bob' is pre-seeded by the harness with role=user. Re-creating must
    // fail with 409 + duplicate-username toast — the prior behavior was a
    // silent password overwrite via upsert_user (#399).
    auto res = h.Post("/api/settings/users",
                        "username=bob&password=newbobpassword&role=user",
                        "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 409);
    CHECK(res->get_header_value("HX-Trigger") == kDuplicateUsernameToast);
    CHECK(h.has_audit("user.upsert", "denied", "User", "bob"));
    // The original password must still authenticate — the rejection must
    // not have run upsert_user under the hood.
    CHECK(h.auth_mgr.authenticate("bob", "bobpassword12").has_value());
}

// ── Weak-password guard — UAT-reported silent fail ─────────────────────────
//
// Before this fix, POSTing a new user with a password shorter than 12 chars
// (the G2-SEC-A1-003 minimum enforced inside AuthManager::upsert_user) caused
// the handler to fire-and-forget the bool return value, then log
// "User added/updated", write a SUCCESS audit row, and emit the
// "User created" success toast — while nothing was persisted. UAT observed
// this as "setting a password less than 12 characters silently fails."
//
// The guard must: (1) return 400, (2) emit the short-password error toast,
// (3) audit the attempt as denied with detail="weak_password", (4) leave
// the user NOT persisted.

TEST_CASE("SettingsRoutes POST /api/settings/users: short password rejected with toast",
          "[settings][users][weak-password]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    // "shortpw" = 7 chars, below the 12-char minimum. Must be rejected
    // before any persistence or success audit occurs.
    auto res = h.Post("/api/settings/users",
                        "username=charlie&password=shortpw&role=user",
                        "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(res->get_header_value("HX-Trigger") == kShortPasswordToast);
    // User must NOT have been persisted.
    CHECK_FALSE(h.has_user("charlie"));
    // Audit chain must capture the denial with the weak_password reason.
    CHECK(h.has_audit("user.upsert", "denied", "User", "charlie"));
    // And must NOT show a success row for the same target.
    CHECK_FALSE(h.has_audit("user.upsert", "success", "User", "charlie"));
}

TEST_CASE("SettingsRoutes POST /api/settings/users: exactly-11-char password rejected",
          "[settings][users][weak-password]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    // Boundary: 11 chars (one below the minimum). 12 chars must pass, 11
    // must fail — this pins the inclusive-lower-bound on 12, not 11.
    auto res = h.Post("/api/settings/users",
                        "username=dave&password=elevenchars&role=user",
                        "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(res->get_header_value("HX-Trigger") == kShortPasswordToast);
    CHECK_FALSE(h.has_user("dave"));
}

TEST_CASE("SettingsRoutes /fragments/settings/users: add-user form carries minlength=12 hint",
          "[settings][users][ui][weak-password]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    // The rendered fragment must carry the HTML5 minlength hint so the
    // browser surfaces the rule natively before a short password even
    // reaches the server. Defence-in-UX, not a security control — the
    // server-side check above is canonical.
    auto res = h.Get("/fragments/settings/users");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    CHECK(res->body.find("minlength=\"12\"") != std::string::npos);
    CHECK(res->body.find("min 12 chars") != std::string::npos);
}

// ── Self-deletion guard — UI side (#403) ─────────────────────────────────────

TEST_CASE("SettingsRoutes GET /fragments/settings/users: Remove button hidden for self",
          "[settings][users][ui][self-delete]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    auto res = h.Get("/fragments/settings/users");
    REQUIRE(res);
    REQUIRE(res->status == 200);

    // The admin's own row must not carry a DELETE action; the other user's
    // row must. Searching for the hx-delete URL is the most surgical check —
    // presence of the text "Remove" alone would miss a future button rename.
    CHECK(res->body.find("hx-delete=\"/api/settings/users/admin\"") == std::string::npos);
    CHECK(res->body.find("hx-delete=\"/api/settings/users/bob\"") != std::string::npos);
    CHECK(res->body.find("Current user") != std::string::npos);
}

TEST_CASE("SettingsRoutes GET /fragments/settings/users: non-self rows all get Remove",
          "[settings][users][ui]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    REQUIRE(h.auth_mgr.upsert_user("carol", "carolpassword1", auth::Role::user));

    auto res = h.Get("/fragments/settings/users");
    REQUIRE(res);
    REQUIRE(res->status == 200);

    CHECK(res->body.find("hx-delete=\"/api/settings/users/bob\"") != std::string::npos);
    CHECK(res->body.find("hx-delete=\"/api/settings/users/carol\"") != std::string::npos);
    CHECK(res->body.find("hx-delete=\"/api/settings/users/admin\"") == std::string::npos);
}
