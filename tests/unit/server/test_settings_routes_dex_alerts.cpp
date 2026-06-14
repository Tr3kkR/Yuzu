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

struct DexAlertsHarness {
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

    explicit DexAlertsHarness(bool open_store = true)
        : tmp(yuzu::test::unique_temp_path("settings-dex-alerts-")) {
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

TEST_CASE("cohort-export POST: valid key persists through the REAL store + applies + audits",
          "[settings][dex][perf]") {
    DexAlertsHarness h;
    auto res = h.sink.Post("/api/settings/dex-alerts/cohort-export", "export_key=model",
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 200);
    // The REAL store accepted the key — this is the assertion that would have
    // caught the missing-allowlist 500 before UAT did.
    CHECK(h.runtime_config->get_value("dex_cohort_export_key") == "model");
    CHECK(h.apply_calls == 1);
    REQUIRE_FALSE(h.audited.empty());
    CHECK(h.audited.back() ==
          "settings.dex_alerts.cohort_export|dex_cohort_export_key|export_key=model");
    // Re-render carries the saved key back into the form.
    CHECK(res->body.find("value=\"model\"") != std::string::npos);
}

TEST_CASE("cohort-export POST: empty key disables (valid, auditable choice)",
          "[settings][dex][perf]") {
    DexAlertsHarness h;
    REQUIRE(h.runtime_config->set("dex_cohort_export_key", "model", "seed").has_value());
    auto res = h.sink.Post("/api/settings/dex-alerts/cohort-export", "export_key=",
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.runtime_config->get_value("dex_cohort_export_key").empty());
    CHECK(h.apply_calls == 1);
    CHECK(h.audited.back().find("export disabled") != std::string::npos);
}

TEST_CASE("cohort-export POST: invalid key 400s, persists nothing, never applies",
          "[settings][dex][perf]") {
    DexAlertsHarness h;
    REQUIRE(h.runtime_config->set("dex_cohort_export_key", "model", "seed").has_value());
    auto res = h.sink.Post("/api/settings/dex-alerts/cohort-export",
                           "export_key=not%20a%20valid%20key%21",
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.runtime_config->get_value("dex_cohort_export_key") == "model"); // unchanged
    CHECK(h.apply_calls == 0);
}

TEST_CASE("cohort-export POST: store unavailable → 503; non-admin → 403",
          "[settings][dex][perf]") {
    SECTION("no store → 503") {
        DexAlertsHarness h(/*open_store=*/false);
        auto res = h.sink.Post("/api/settings/dex-alerts/cohort-export", "export_key=model",
                               "application/x-www-form-urlencoded");
        REQUIRE(res);
        CHECK(res->status == 503);
    }
    SECTION("non-admin → 403, nothing persisted") {
        DexAlertsHarness h;
        h.is_admin = false;
        auto res = h.sink.Post("/api/settings/dex-alerts/cohort-export", "export_key=model",
                               "application/x-www-form-urlencoded");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.runtime_config->get_value("dex_cohort_export_key").empty());
        CHECK(h.apply_calls == 0);
    }
}
