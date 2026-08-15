/**
 * test_deployment_routes.cpp — SEC-2/SEC-3 confinement-gap class coverage for
 * DeploymentRoutes. DeploymentRoutes previously had no route-handler test
 * coverage at all (only DeploymentRunStore/deployment_engine had unit tests).
 *
 * GET /fragments/auto/deploy, GET /fragments/auto/deploy/result, and POST
 * /fragments/auto/deploy/delete all scope by session->username alone —
 * ApiToken::principal_id ("the username... who created it") means a
 * service-scoped token shares its creating principal's username, so a token
 * scoped to e.g. one IT service could otherwise read/advance/delete a
 * fleet-wide deployment its own principal created interactively. Denied the
 * same way as the sibling PreflightRoutes fix in this branch.
 *
 * POST /fragments/auto/deploy/run (the mutating create+first-dispatch route)
 * is DELIBERATELY NOT covered here — it is a separate, unfixed finding
 * pending its own review of the guarded-transition contract.
 */

#include "deployment_routes.hpp"
#include "deployment_run_store.hpp"
#include "preflight_run_store.hpp"
#include "pg/pg_pool.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;

namespace {

yuzu::test::PgTestTemplate deprun_routes_tpl{"deprun", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    DeploymentRunStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("deprun template: store failed to migrate");
}};

yuzu::test::PgTestTemplate preflight_routes_tpl{"preflight", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    PreflightRunStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("preflight template: store failed to migrate");
}};

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

PreflightRunRow make_run(const std::string& id, const std::string& owner, std::int64_t created) {
    PreflightRunRow r;
    r.run_id = id;
    r.execution_id = "preflight-" + id;
    r.created_by = owner;
    r.name = "test " + id;
    r.scope_label = "all visible devices";
    r.config_json = R"({"app_name":"","min_gib":20})";
    r.window_seconds = 300;
    r.created_at_ms = created;
    r.deadline_at_ms = created + 300000;
    r.status = "running";
    return r;
}

DeploymentRow make_dep(const std::string& id, const std::string& run_id, const std::string& owner,
                       std::int64_t created) {
    DeploymentRow d;
    d.deployment_id = id;
    d.source_run_id = run_id;
    d.created_by = owner;
    d.name = "test " + id;
    d.artifact_url = "https://repo.lan/pkg.msi";
    d.artifact_filename = "pkg.msi";
    d.artifact_sha256 = std::string(64, 'a');
    d.exec_args = "/qn";
    d.status = "running";
    d.created_at_ms = created;
    return d;
}

preflight::PreflightTarget tgt(const std::string& aid) { return {aid, "host-" + aid, "windows"}; }

} // namespace

// SEC-2/SEC-3 confinement-gap class (found via Gate 6 hardening re-check,
// the same "owner-scoped by username" sub-pattern as PreflightRoutes): a
// service-scoped token sharing its creating principal's username could
// otherwise read the deploy config form, poll/advance an in-flight
// deployment, or delete a deployment — all outside its own service.
TEST_CASE("deployment routes: config/result/delete deny a service-scoped "
          "token sharing the creator's username, nothing leaked or mutated",
          "[pg][deployment][routes][security]") {
    YUZU_REQUIRE_PG_DB_TPL(depdb, deprun_routes_tpl);
    YUZU_REQUIRE_PG_DB_TPL(predb, preflight_routes_tpl);
    PgPool dep_pool{{.conninfo = depdb.dsn(), .size = 4}};
    PgPool pre_pool{{.conninfo = predb.dsn(), .size = 4}};
    DeploymentRunStore deploy_store(dep_pool);
    PreflightRunStore preflight_store(pre_pool);
    REQUIRE(deploy_store.is_open());
    REQUIRE(preflight_store.is_open());

    const auto t = now_ms();
    const std::string run_id = "run-confinement-1";
    auto run = make_run(run_id, "alice", t);
    run.go = 1;
    REQUIRE(preflight_store.create_run(run, {{"agent-1", "host-1", "windows"}}));

    const std::string dep_id = "dep-confinement-1";
    auto dep = make_dep(dep_id, run_id, "alice", t);
    REQUIRE(deploy_store.create_deployment(dep, {tgt("agent-1")}));

    // The SAME principal ("alice") now authenticates with a service-scoped
    // token — mirrors ApiToken::principal_id sharing the creator's username.
    auto serviceScopedAuth = [](const httplib::Request&, httplib::Response&) {
        auth::Session s;
        s.username = "alice";
        s.token_scope_service = "printers";
        return std::optional<auth::Session>(s);
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    // Deliberately WIRED to authorize "agent-1" (the deployment's only device,
    // still in step="pending") — if the deny were bypassed, advance() would
    // claim + dispatch it (deployment_engine.cpp's CAS-claim-and-stage step).
    // An unwired/empty devices_fn would make dispatched==0 vacuously true
    // regardless of the fix (the device is SKIPPED, not dispatched, when
    // unauthorized) — gov QE review already caught this exact trap once in
    // this branch (PreflightRoutes' deny test).
    auto devices = [](const std::string&) {
        DeviceRow d;
        d.agent_id = "agent-1";
        return std::vector<DeviceRow>{d};
    };
    int dispatched = 0;
    auto dispatch = [&dispatched](const std::string&, const std::string&,
                                  const std::vector<std::string>&, const std::string&,
                                  const std::unordered_map<std::string, std::string>&,
                                  const std::string&,
                                  const yuzu::server::DispatchCaller&) -> std::pair<std::string, int> {
        ++dispatched;
        return {"cmd-1", 1};
    };
    auto poll = [](const std::string&) { return std::unordered_map<std::string, deployment::AgentResponse>{}; };
    std::vector<std::string> audit_log;
    auto audit = [&](const httplib::Request&, const std::string& a, const std::string& r,
                     const std::string&, const std::string&, const std::string&) -> bool {
        audit_log.push_back(a + "|" + r);
        return true;
    };

    DeploymentRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    routes.register_routes(sink, serviceScopedAuth, okPerm, devices, dispatch, poll, audit,
                           &preflight_store, &deploy_store);

    auto cfg = sink.Get("/fragments/auto/deploy?run=" + run_id);
    REQUIRE(cfg);
    CHECK(cfg->status == 403);
    CHECK(cfg->body.find(run.name) == std::string::npos);

    auto result = sink.Get("/fragments/auto/deploy/result?dep=" + dep_id);
    REQUIRE(result);
    CHECK(result->status == 403);
    CHECK(result->body.find(dep.artifact_filename) == std::string::npos);
    CHECK(dispatched == 0); // the mutating advance() tick never ran

    auto del = sink.Post("/fragments/auto/deploy/delete?dep=" + dep_id, "",
                         "application/x-www-form-urlencoded");
    REQUIRE(del);
    CHECK(del->status == 403);
    // The deployment survives — the deny fires before delete_deployment.
    REQUIRE(deploy_store.get_deployment(dep_id, "alice").has_value());
    // Gate 8 (GC-7): delete is gated on SoftwareDeployment:Execute in
    // production, not the helper's :Read default — the A4 .permission hint
    // must name the grant actually missing.
    auto del_body = nlohmann::json::parse(del->body, nullptr, false);
    REQUIRE_FALSE(del_body.is_discarded());
    CHECK(del_body["error"]["permission"] == "SoftwareDeployment:Execute");

    REQUIRE(audit_log.size() == 3);
    CHECK(audit_log[0] == "deployment.config.view|denied");
    CHECK(audit_log[1] == "deployment.advance|denied");
    CHECK(audit_log[2] == "deployment.delete|denied");
}

TEST_CASE("deployment routes: ordinary session reaches config/result/delete, "
          "audited success",
          "[pg][deployment][routes][security]") {
    YUZU_REQUIRE_PG_DB_TPL(depdb, deprun_routes_tpl);
    YUZU_REQUIRE_PG_DB_TPL(predb, preflight_routes_tpl);
    PgPool dep_pool{{.conninfo = depdb.dsn(), .size = 4}};
    PgPool pre_pool{{.conninfo = predb.dsn(), .size = 4}};
    DeploymentRunStore deploy_store(dep_pool);
    PreflightRunStore preflight_store(pre_pool);
    REQUIRE(deploy_store.is_open());
    REQUIRE(preflight_store.is_open());

    const auto t = now_ms();
    const std::string run_id = "run-ordinary-1";
    auto run = make_run(run_id, "alice", t);
    run.go = 1;
    REQUIRE(preflight_store.create_run(run, {{"agent-1", "host-1", "windows"}}));

    const std::string dep_id = "dep-ordinary-1";
    auto dep = make_dep(dep_id, run_id, "alice", t);
    REQUIRE(deploy_store.create_deployment(dep, {tgt("agent-1")}));

    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        auth::Session s;
        s.username = "alice";
        return std::optional<auth::Session>(s);
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    auto devices = [](const std::string&) { return std::vector<DeviceRow>{}; };
    auto dispatch = [](const std::string&, const std::string&, const std::vector<std::string>&,
                       const std::string&, const std::unordered_map<std::string, std::string>&,
                       const std::string&,
                       const yuzu::server::DispatchCaller&) -> std::pair<std::string, int> {
        return {"cmd-1", 1};
    };
    auto poll = [](const std::string&) { return std::unordered_map<std::string, deployment::AgentResponse>{}; };
    std::vector<std::string> audit_log;
    auto audit = [&](const httplib::Request&, const std::string& a, const std::string& r,
                     const std::string&, const std::string&, const std::string&) -> bool {
        audit_log.push_back(a + "|" + r);
        return true;
    };

    DeploymentRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    routes.register_routes(sink, okAuth, okPerm, devices, dispatch, poll, audit, &preflight_store,
                           &deploy_store);

    auto cfg = sink.Get("/fragments/auto/deploy?run=" + run_id);
    REQUIRE(cfg);
    CHECK(cfg->status != 403);
    CHECK(cfg->body.find(run.name) != std::string::npos);

    auto result = sink.Get("/fragments/auto/deploy/result?dep=" + dep_id);
    REQUIRE(result);
    CHECK(result->status != 403);

    auto del = sink.Post("/fragments/auto/deploy/delete?dep=" + dep_id, "",
                         "application/x-www-form-urlencoded");
    REQUIRE(del);
    CHECK(del->status != 403);
    CHECK_FALSE(deploy_store.get_deployment(dep_id, "alice").has_value());

    for (const auto& a : audit_log)
        CHECK(a.find("|denied") == std::string::npos);
}
