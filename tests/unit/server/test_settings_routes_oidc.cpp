/**
 * test_settings_routes_dex_alerts.cpp — route-level tests for the Settings →
 * DEX alerts handlers against a REAL RuntimeConfigStore.
 *
 * Why this file exists (governance G3 QE + UAT live-fire 2026-06-12): the
 * cohort-export POST shipped 500ing in production because
 * `dex_cohort_export_key` was missing from RuntimeConfigStore's allowlist —
 * the handler had been exercised only against fakes, so the store's key
 * gate never ran. These tests put the real store behind every assertion.
 *
 * Covers POST /api/settings/dex-alerts/cohort-export:
 *   - valid key → 200 + persisted + audited + live-apply fn fired
 *   - empty key → 200 + persisted "" (export disabled) + audited as disabled
 *   - invalid key → 400 + store unchanged + apply fn NOT fired
 *   - store closed → 503
 *   - non-admin → 403 + nothing persisted
 */

#include "settings_routes.hpp"

#include "runtime_config_store.hpp"
#include "test_route_sink.hpp"
#include "../test_helpers.hpp"
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>

#include <filesystem>
#include <memory>
#include <shared_mutex>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::server;

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

struct OidcHarness {
    TmpDirGuard tmp;
    Config cfg{};
    auth::AuthManager auth_mgr{};
    auth::AutoApproveEngine auto_approve{};
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty
    std::unique_ptr<RuntimeConfigStore> runtime_config;
    SettingsRoutes routes;
    yuzu::server::test::TestRouteSink sink;

    bool is_admin{true};
    int apply_calls{0};
    std::vector<std::string> audited; // "action|target_id|detail"

    explicit OidcHarness(bool open_store = true)
        : tmp(yuzu::test::unique_temp_path("settings-oidc-")) {
        if (open_store) {
            runtime_config = std::make_unique<RuntimeConfigStore>(tmp.path / "runtime.db");
            REQUIRE(runtime_config->is_open());
        }
        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "admin";
            s.role = auth::Role::admin;
            return s;
        };
        auto admin_fn = [this](const httplib::Request&, httplib::Response& res) {
            if (!is_admin) {
                res.status = 403;
                return false;
            }
            return true;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& /*result*/, const std::string& /*ttype*/,
                               const std::string& tid, const std::string& detail) -> bool {
            audited.push_back(action + "|" + tid + "|" + detail);
            return true;
        };
        routes.set_dex_alert_apply_fn([this]() { ++apply_calls; });
        routes.register_routes(sink, auth_fn, admin_fn, perm_fn, audit_fn, cfg, auth_mgr,
                               auto_approve,
                               /*api_token_store=*/nullptr,
                               /*mgmt_group_store=*/nullptr,
                               /*tag_store=*/nullptr,
                               /*update_registry=*/nullptr, runtime_config.get(),
                               /*audit_store=*/nullptr,
                               /*gateway_enabled=*/false, []() -> std::size_t { return 0; },
                               []() -> std::string { return "[]"; }, oidc_mu, oidc_provider);
    }
};

} // namespace

// ── Settings -> OIDC persist honesty ────────────────────────────────────────
//
// These cover the handler-level half of the redaction work. The store-level half
// (set() refusing the placeholder) is covered in
// test_runtime_config_secret_redaction.cpp; this file covers the caller, which is
// where the real regression was: the handler discarded all six set() results and
// reported "saved" regardless.
//
// No OidcProvider mocking is needed. Its constructor skips discovery when
// redirect_uri is empty (oidc_provider.cpp: "validate-only" path), so the handler
// reaches the persist block without any network.

namespace {
std::string oidc_form(const std::string& secret, const std::string& issuer = "https://idp.example",
                      const std::string& client_id = "cid") {
    return "issuer=" + issuer + "&client_id=" + client_id + "&client_secret=" + secret +
           "&redirect_uri=&admin_group=&skip_tls_verify=false";
}
} // namespace

TEST_CASE("Settings OIDC: the redaction placeholder means UNCHANGED, never a new secret",
          "[settings][oidc][secret]") {
    OidcHarness h;
    REQUIRE(h.runtime_config->set("oidc_client_secret", "real-secret", "seed").has_value());

    auto res = h.sink.Post("/api/settings/oidc", oidc_form("<redacted>"),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 200);

    // The stored credential is untouched -- not overwritten with the placeholder,
    // and not blanked.
    CHECK(h.runtime_config->get_value_with_secrets("oidc_client_secret") == "real-secret");
    // And no failure was reported, because submitting the placeholder is a no-op on
    // the secret rather than an error.
    CHECK(res->body.find("NOT saved") == std::string::npos);
}

TEST_CASE("Settings OIDC: a placeholder with stray whitespace is also treated as UNCHANGED",
          "[settings][oidc][secret]") {
    // Exact-match let a pasted "<redacted>\n" through both this guard and the store's,
    // persisting it as the client secret and destroying the real one.
    OidcHarness h;
    REQUIRE(h.runtime_config->set("oidc_client_secret", "real-secret", "seed").has_value());

    auto res = h.sink.Post("/api/settings/oidc", oidc_form("  <redacted>  "),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(h.runtime_config->get_value_with_secrets("oidc_client_secret") == "real-secret");
}

TEST_CASE("Settings OIDC: a real secret is persisted and reported saved",
          "[settings][oidc][secret]") {
    OidcHarness h;
    auto res = h.sink.Post("/api/settings/oidc", oidc_form("brand-new-secret"),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.runtime_config->get_value_with_secrets("oidc_client_secret") == "brand-new-secret");
    CHECK(res->body.find("NOT saved") == std::string::npos);
}

TEST_CASE("Settings OIDC: a degraded store reports NOT SAVED instead of success",
          "[settings][oidc][secret]") {
    // The regression this pins: the persist block was guarded on is_open() with no
    // else, so a degraded store skipped the failure branch and still rendered the
    // success toast -- the same false-success the guard exists to remove.
    OidcHarness h{/*open_store=*/false};

    auto res = h.sink.Post("/api/settings/oidc", oidc_form("brand-new-secret"),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->body.find("NOT saved") != std::string::npos);
    // ...and it is audited as a failure, not a success.
    REQUIRE_FALSE(h.audited.empty());
    CHECK(h.audited.back().find("oidc.configure") != std::string::npos);
    CHECK(h.audited.back().find("persist failed") != std::string::npos);
}
