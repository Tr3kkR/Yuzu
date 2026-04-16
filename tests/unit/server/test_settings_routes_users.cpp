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
 * Pattern mirrors test_rest_api_tokens.cpp: spin up an httplib::Server on
 * a random port, register SettingsRoutes with mock session callbacks, and
 * hit the real HTTP surface with httplib::Client. The audit_fn mock
 * captures every call into a vector so tests can assert the evidence chain
 * is intact on each guarded path.
 */

#include "settings_routes.hpp"

#include "api_token_store.hpp"
#include "audit_store.hpp"
#include "management_group_store.hpp"
#include "oidc_provider.hpp"
#include "runtime_config_store.hpp"
#include "tag_store.hpp"
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

    httplib::Server svr;
    std::thread server_thread;
    int port{0};

    // Mock session state — the auth_fn / admin_fn closures read this so
    // tests can act as different principals against the same server.
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

        routes.register_routes(svr, auth_fn, admin_fn, perm_fn, audit_fn,
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

        port = svr.bind_to_any_port("127.0.0.1");
        REQUIRE(port > 0);
        server_thread = std::thread([this]() { svr.listen_after_bind(); });
        for (int i = 0; i < 100; ++i) {
            if (svr.is_running())
                break;
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        REQUIRE(svr.is_running());
    }

    ~SettingsRoutesHarness() {
        svr.stop();
        if (server_thread.joinable())
            server_thread.join();
        // tmp.~TmpDirGuard() runs after this body returns, removing tmp.path.
    }

    httplib::Client client() const {
        httplib::Client cli("127.0.0.1", port);
        cli.set_connection_timeout(5);
        cli.set_read_timeout(5);
        return cli;
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

} // namespace

// ── Self-deletion guard — handler side (#397) ────────────────────────────────

TEST_CASE("SettingsRoutes DELETE /api/settings/users: admin cannot delete self",
          "[settings][users][self-delete]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    auto cli = h.client();
    auto res = cli.Delete("/api/settings/users/admin");
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

    auto cli = h.client();
    auto res = cli.Delete("/api/settings/users/bob");
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

    auto cli = h.client();
    auto res = cli.Delete("/api/settings/users/admin");
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

    auto cli = h.client();
    auto res = cli.Delete("/api/settings/users/admin");
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

    auto cli = h.client();
    // Form-urlencoded body — that's what the dashboard sends and what
    // extract_form_value parses.
    auto res = cli.Post("/api/settings/users",
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

    auto cli = h.client();
    // Same role — only password is changing. The self-demotion guard must
    // NOT block this; it specifically targets role transitions.
    auto res = cli.Post("/api/settings/users",
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

    auto cli = h.client();
    // Add a new user. Response body is the re-rendered fragment; verify
    // (a) the new user shows up with a Remove button and (b) the operator's
    // own row still has the Current user badge — the self_name threading
    // through the success path matters because the dashboard swaps this
    // body into #user-section.
    auto res = cli.Post("/api/settings/users",
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

// ── Self-deletion guard — UI side (#403) ─────────────────────────────────────

TEST_CASE("SettingsRoutes GET /fragments/settings/users: Remove button hidden for self",
          "[settings][users][ui][self-delete]") {
    SettingsRoutesHarness h;
    h.session_user = "admin";
    h.session_role = auth::Role::admin;

    auto cli = h.client();
    auto res = cli.Get("/fragments/settings/users");
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

    auto cli = h.client();
    auto res = cli.Get("/fragments/settings/users");
    REQUIRE(res);
    REQUIRE(res->status == 200);

    CHECK(res->body.find("hx-delete=\"/api/settings/users/bob\"") != std::string::npos);
    CHECK(res->body.find("hx-delete=\"/api/settings/users/carol\"") != std::string::npos);
    CHECK(res->body.find("hx-delete=\"/api/settings/users/admin\"") == std::string::npos);
}
