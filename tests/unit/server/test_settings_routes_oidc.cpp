/**
 * test_settings_routes_oidc.cpp - Settings -> OIDC persist honesty.
 *
 * Covers the CALLER half of the OIDC-secret redaction work. The sink half
 * (RuntimeConfigStore::set() refusing the redaction placeholder) lives in
 * test_runtime_config_secret_redaction.cpp.
 *
 * Why the caller needs its own cover: the handler discarded all six set() results and
 * reported "OIDC configuration saved" regardless, so a refused write left the live
 * provider and the store diverged behind a success toast, and a restart healed it
 * silently. Governance caught that twice - once as the discarded result, once as a
 * missing `else` on the store guard producing the same false success.
 *
 * Cases:
 *   1. the placeholder means UNCHANGED, never a new secret
 *   2. the placeholder with stray whitespace also means UNCHANGED
 *   3. a real secret persists and is reported saved
 *   4. a NULL store reports NOT SAVED (defensive; unreachable in the shipped server)
 *   5. a non-admin is refused and nothing persists
 *
 * KNOWN GAP: the production-reachable degraded state is a NON-NULL store whose
 * is_open() is false (unwritable db_dir, failed migration). Nothing covers it -- the
 * NULL case above is defensive only, since server.cpp constructs the store
 * unconditionally. Two reviewers asked for that case; it is not here yet.
 *
 * No OidcProvider mocking is needed: the handler populates authorization_endpoint in
 * both branches, so the provider ctor returns at its pre-configured-endpoints guard
 * without any network I/O.
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
        : tmp(yuzu::test::unique_temp_path("yuzu_test_settings_oidc_")) {
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
    CHECK(res->body.find("could NOT be saved") == std::string::npos);
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
    CHECK(res->body.find("could NOT be saved") == std::string::npos);
}

TEST_CASE("Settings OIDC: a NULL store reports NOT SAVED instead of success",
          "[settings][oidc][secret]") {
    // NULL store only - see the KNOWN GAP in this file's header. The regression this
    // pins: the persist block was guarded on is_open() with no
    // else, so a degraded store skipped the failure branch and still rendered the
    // success toast -- the same false-success the guard exists to remove.
    OidcHarness h{/*open_store=*/false};

    auto res = h.sink.Post("/api/settings/oidc", oidc_form("brand-new-secret"),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->body.find("could NOT be saved") != std::string::npos);
    // ...and it is audited as a failure, not a success.
    REQUIRE_FALSE(h.audited.empty());
    CHECK(h.audited.back().find("oidc.configure") != std::string::npos);
    CHECK(h.audited.back().find("persist failed") != std::string::npos);
}

TEST_CASE("Settings OIDC: a non-admin cannot set the client secret and nothing persists",
          "[settings][oidc][secret]") {
    // The admin gate is the outermost control on this handler. Asserting it here keeps
    // the redaction work from being the only thing standing between a lower-privileged
    // operator and the OIDC credential.
    OidcHarness h;
    h.is_admin = false;
    REQUIRE(h.runtime_config->set("oidc_client_secret", "real-secret", "seed").has_value());

    auto res = h.sink.Post("/api/settings/oidc", oidc_form("attacker-supplied"),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.runtime_config->get_value_with_secrets("oidc_client_secret") == "real-secret");
    CHECK(h.audited.empty());
}

TEST_CASE("Settings OIDC: a secret CONTAINING the placeholder is refused, not silently dropped",
          "[settings][oidc][secret]") {
    // CH-4. The handler used the CONTAINS predicate to mean "leave unchanged", so a real
    // credential containing the token was discarded and the operator was told SAVED -
    // the same false-success this branch exists to remove, re-entering through the guard
    // added to remove it. Four reviewers found it independently. Only an EXACT
    // placeholder means unchanged now; containment reaches the sink and is reported.
    OidcHarness h;
    REQUIRE(h.runtime_config->set("oidc_client_secret", "real-secret", "seed").has_value());

    auto res = h.sink.Post("/api/settings/oidc", oidc_form("abc<redacted>def"),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    // The operator is TOLD, rather than getting a success toast.
    CHECK(res->body.find("could NOT be saved") != std::string::npos);
    CHECK(res->body.find("oidc_client_secret") != std::string::npos);
    // The stored credential is untouched either way - the sink refused the write.
    CHECK(h.runtime_config->get_value_with_secrets("oidc_client_secret") == "real-secret");
    // ...and it is audited as a failure.
    REQUIRE_FALSE(h.audited.empty());
    CHECK(h.audited.back().find("persist failed") != std::string::npos);
}

TEST_CASE("Settings OIDC: an EXACT placeholder still means unchanged, and reports saved",
          "[settings][oidc][secret]") {
    // The benign case the CONTAINS rule was over-serving: re-submitting a form that was
    // pre-filled with the redacted value must remain a no-op, not an error.
    OidcHarness h;
    REQUIRE(h.runtime_config->set("oidc_client_secret", "real-secret", "seed").has_value());

    auto res = h.sink.Post("/api/settings/oidc", oidc_form("  <redacted>\n"),
                           "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->body.find("could NOT be saved") == std::string::npos);
    CHECK(h.runtime_config->get_value_with_secrets("oidc_client_secret") == "real-secret");
}
