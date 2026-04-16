/**
 * test_settings_routes_users.cpp — HTTP-level tests for the Users section of
 * the Settings page, covering the self-deletion lockout guard added for
 * issues #397 and #403.
 *
 * The bugs: an admin viewing Settings > Users was shown a "Remove" button
 * next to their own row, and the DELETE /api/settings/users/:name handler
 * did not reject self-targeted deletes. Confirming the hx-confirm dialog
 * dropped the only usable credential on the running server and locked every
 * operator out until the process was restarted against its on-disk config.
 *
 * The fix is two-sided — UI guard (hide the button for the current user)
 * plus handler guard (reject self-targeted DELETE with 403) — because a
 * hand-crafted HTTP request bypasses the dashboard. Both halves need
 * coverage here.
 *
 * Pattern mirrors test_rest_api_tokens.cpp: spin up an httplib::Server on
 * a random port, register SettingsRoutes with mock session callbacks, and
 * hit the real HTTP surface with httplib::Client.
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

namespace fs = std::filesystem;
using namespace yuzu::server;

namespace {

static fs::path unique_temp_path(const std::string& prefix) {
    static std::atomic<unsigned> seq{0};
    return fs::temp_directory_path() /
           (prefix + "-" + std::to_string(::getpid()) + "-" +
            std::to_string(seq.fetch_add(1)));
}

/// Harness that stands up a real httplib::Server with SettingsRoutes bound
/// to an AuthManager seeded with two accounts ("admin" + "bob"). The mock
/// auth/admin callbacks read `session_user` / `session_role` so individual
/// tests can switch perspective between calls without rebuilding the server.
struct SettingsRoutesHarness {
    fs::path tmp_dir;
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

    SettingsRoutesHarness() : tmp_dir(unique_temp_path("settings-routes-users")) {
        fs::create_directories(tmp_dir);
        cfg.auth_config_path = tmp_dir / "auth.cfg";
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

        auto audit_fn = [](const httplib::Request&, const std::string&,
                           const std::string&, const std::string&,
                           const std::string&, const std::string&) {};

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
        std::error_code ec;
        fs::remove_all(tmp_dir, ec);
    }

    httplib::Client client() const {
        httplib::Client cli("127.0.0.1", port);
        cli.set_connection_timeout(5);
        cli.set_read_timeout(5);
        return cli;
    }
};

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
    CHECK(res->get_header_value("HX-Trigger").find("Cannot delete your own account") !=
          std::string::npos);

    // The admin account must still exist after the rejected DELETE.
    auto users = h.auth_mgr.list_users();
    bool admin_present = false;
    for (const auto& u : users) {
        if (u.username == "admin")
            admin_present = true;
    }
    CHECK(admin_present);
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

    auto users = h.auth_mgr.list_users();
    bool bob_present = false;
    for (const auto& u : users) {
        if (u.username == "bob")
            bob_present = true;
    }
    CHECK_FALSE(bob_present);
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

    // Admin still exists.
    auto users = h.auth_mgr.list_users();
    bool admin_present = false;
    for (const auto& u : users) {
        if (u.username == "admin")
            admin_present = true;
    }
    CHECK(admin_present);
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
    // Log in as bob (user role) — this should be rejected by admin_fn_,
    // so the fragment is never rendered and we cannot test row visibility
    // from a non-admin perspective. Instead, delete bob's row via the
    // admin session and confirm admin still lacks a Remove button on
    // their own row.
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
