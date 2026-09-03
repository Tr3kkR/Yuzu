/// @file test_settings_routes_ota_audit.cpp
///
/// The OTA rollout route's audit row (#3692).
///
/// WHY THIS EXISTS. #3692 reports that the OTA package-management routes gate on
/// `admin_fn_` but never call `audit_fn_` — they only `spdlog::info`, which is
/// the application log, not the audit log. There is no compensating global
/// mechanism: `server.cpp`'s pre/post-routing handlers cover auth, quota, metrics
/// and security headers, not audit emission. So the row either comes from the
/// handler or it does not exist, and nothing but a test at this level can tell
/// the two apart.
///
/// The scenario the issue names is an admin — or a compromised admin session —
/// silently de-prioritising a mandatory security patch. What makes that
/// reconstructable is not "a rollout change happened" but the PRIOR value: 0%
/// alone cannot distinguish a patch pulled back from one never rolled out. These
/// cases therefore assert the `from=`/`to=` pair, not merely that a row landed.
///
/// This drives the real route through `TestRouteSink` against a real PG-backed
/// `UpdateRegistry`, because the value under test is what the HANDLER emits.
/// A pure-function test would pin the string and prove nothing about whether the
/// handler calls it.

#include "settings_routes.hpp"

#include "pg/pg_pool.hpp"
#include "test_route_sink.hpp"
#include "update_registry.hpp"
#include "../test_helpers.hpp"
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>
#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>

#include <filesystem>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <stdexcept>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::server;

namespace {

/// Pre-migrated template: `UpdateRegistry`'s constructor runs its own migration,
/// and per-test migration DDL is what drove the 2026-07-12 Windows server-suite
/// timeout. Cloning an already-migrated database keeps this route test off that
/// path.
yuzu::test::PgTestTemplate ota_audit_tpl{"otaaudit", [](const std::string& dsn) {
    pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    if (!pool.valid())
        throw std::runtime_error("ota_audit_tpl: pool invalid");
    yuzu::test::TempDir dir{"yuzu_test_ota_tpl_"};
    UpdateRegistry reg{pool, dir.path};
    if (!reg.is_open())
        throw std::runtime_error("ota_audit_tpl: UpdateRegistry migration failed");
}};

struct AuditRow {
    std::string action;
    std::string result;
    std::string target_type;
    std::string target_id;
    std::string detail;
};

struct OtaAuditHarness {
    yuzu::test::TempDir update_dir{"yuzu_test_ota_updates_"};
    Config cfg{};
    auth::AuthManager auth_mgr{};
    auth::AutoApproveEngine auto_approve{};
    std::shared_mutex oidc_mu;
    std::unique_ptr<oidc::OidcProvider> oidc_provider; // empty

    std::optional<pg::PgPool> pool;
    std::unique_ptr<UpdateRegistry> registry;
    SettingsRoutes routes;
    yuzu::server::test::TestRouteSink sink;

    std::vector<AuditRow> audited;

    explicit OtaAuditHarness(const std::string& dsn) {
        pool.emplace(pg::PgPool::Options{.conninfo = dsn, .size = 4});
        REQUIRE(pool->valid());
        registry = std::make_unique<UpdateRegistry>(*pool, update_dir.path);
        REQUIRE(registry->is_open());

        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "admin";
            s.role = auth::Role::admin;
            return s;
        };
        auto admin_fn = [](const httplib::Request&, httplib::Response&) { return true; };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& ttype,
                               const std::string& tid, const std::string& detail) -> bool {
            audited.push_back(AuditRow{action, result, ttype, tid, detail});
            return true;
        };
        routes.register_routes(sink, auth_fn, admin_fn, perm_fn, audit_fn, cfg, auth_mgr,
                               auto_approve,
                               /*api_token_store=*/nullptr,
                               /*mgmt_group_store=*/nullptr,
                               /*tag_store=*/nullptr, registry.get(),
                               /*runtime_config_store=*/nullptr,
                               /*audit_store=*/nullptr,
                               /*gateway_enabled=*/false, []() -> std::size_t { return 0; },
                               []() -> std::string { return "[]"; }, oidc_mu, oidc_provider);
    }

    void seed(int rollout_pct, bool mandatory) {
        UpdatePackage pkg;
        pkg.platform = "linux";
        pkg.arch = "x86_64";
        pkg.version = "1.2.3";
        pkg.sha256 = std::string(64, 'a');
        pkg.filename = "yuzu-agent-1.2.3";
        pkg.mandatory = mandatory;
        pkg.rollout_pct = rollout_pct;
        pkg.file_size = 1024;
        registry->upsert_package(pkg);
    }

    /// The rollout route parses an urlencoded body, so the content type matters:
    /// `Post(path, body)` alone defaults to application/json and would leave
    /// `req.params` empty, silently exercising the handler's fallback instead of
    /// its production branch (the #1786 false-green).
    std::unique_ptr<httplib::Response> post_rollout(const std::string& version,
                                                    const std::string& pct) {
        return sink.Post("/api/settings/updates/linux/x86_64/" + version + "/rollout",
                         "rollout_pct=" + pct, "application/x-www-form-urlencoded");
    }
};

} // namespace

TEST_CASE("OTA rollout change is audited with the value it changed FROM (#3692)",
          "[ota][audit][settings_routes][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ota_audit_tpl);
    OtaAuditHarness h{db.dsn()};
    h.seed(/*rollout_pct=*/100, /*mandatory=*/true);

    auto res = h.post_rollout("1.2.3", "0");
    REQUIRE(res);
    CHECK(res->status == 200);

    REQUIRE(h.audited.size() == 1);
    const auto& row = h.audited.front();
    CHECK(row.action == "ota.package.rollout_changed");
    CHECK(row.result == "success");
    CHECK(row.target_type == "UpdatePackage");
    CHECK(row.target_id == "linux/x86_64/1.2.3");

    // The load-bearing assertion. Without the prior value the row cannot
    // distinguish a mandatory patch being pulled back from one that was never
    // rolled out, which is the whole scenario #3692 describes.
    CHECK(row.detail.find("from=100%") != std::string::npos);
    CHECK(row.detail.find("to=0%") != std::string::npos);
    CHECK(row.detail.find("mandatory=true") != std::string::npos);

    // And the change actually landed, so the row is not describing a no-op.
    auto pkgs = h.registry->list_packages();
    REQUIRE(pkgs.size() == 1);
    CHECK(pkgs.front().rollout_pct == 0);
}

TEST_CASE("OTA rollout on a package that does not exist records not_found, not success",
          "[ota][audit][settings_routes][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, ota_audit_tpl);
    OtaAuditHarness h{db.dsn()};
    h.seed(/*rollout_pct=*/50, /*mandatory=*/false);

    auto res = h.post_rollout("9.9.9", "0");
    REQUIRE(res);
    CHECK(res->status == 200);

    // Recording a fictional success would put an event in the evidence store that
    // never happened, and would hide package-key enumeration from a SIEM rule.
    REQUIRE(h.audited.size() == 1);
    CHECK(h.audited.front().action == "ota.package.rollout_changed");
    CHECK(h.audited.front().result == "not_found");
    CHECK(h.audited.front().target_id == "linux/x86_64/9.9.9");

    // The real package is untouched.
    auto pkgs = h.registry->list_packages();
    REQUIRE(pkgs.size() == 1);
    CHECK(pkgs.front().rollout_pct == 50);
}

TEST_CASE("OTA rollout percentage is clamped, and the row reports the CLAMPED value",
          "[ota][audit][settings_routes][pg]") {
    // The handler clamps to 0..100. The audit row must report what was actually
    // stored, not what was requested, or the evidence disagrees with the state.
    YUZU_REQUIRE_PG_DB_TPL(db, ota_audit_tpl);
    OtaAuditHarness h{db.dsn()};
    h.seed(/*rollout_pct=*/10, /*mandatory=*/false);

    h.post_rollout("1.2.3", "500");

    REQUIRE(h.audited.size() == 1);
    CHECK(h.audited.front().detail.find("from=10%") != std::string::npos);
    CHECK(h.audited.front().detail.find("to=100%") != std::string::npos);
    CHECK(h.registry->list_packages().front().rollout_pct == 100);
}
