/**
 * test_rest_bundle.cpp — HTTP-level coverage for the live-query bundle REST
 * routes (ADR-0011, slice 2b):
 *
 *   POST /api/v1/bundles                 -> dispatch (async), 202 + execution_id
 *   GET  /api/v1/bundles/{correlation}   -> collate, server-grouped result
 *
 * Driven via the TestRouteSink in-process pattern (#438) with a REAL
 * ResponseStore and a FAKE command-dispatch closure that records its args and
 * returns deterministic command_ids. Asserts the route contract: 202 dispatch
 * shape + per-command fan-out + per-step audit verbs, the collated GET result,
 * the ownership (IDOR) 404, the validation 400s, and the 503 when dispatch is
 * unwired. The orchestration logic itself is covered in
 * test_bundle_orchestrator.cpp; this file asserts the REST wiring.
 */

#include "response_store.hpp"
#include "rest_api_v1.hpp"
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

struct DispatchCall {
    std::string plugin, action, scope_expr, execution_id;
    std::vector<std::string> agent_ids;
};

struct AuditRow {
    std::string verb, result, type, id;
};

struct BundleHarness {
    ResponseStore store{":memory:"};
    yuzu::server::test::TestRouteSink sink;
    yuzu::MetricsRegistry metrics;
    RestApiV1 api;

    std::vector<DispatchCall> calls;
    std::vector<AuditRow> audits;
    std::string principal = "alice";
    bool is_admin = true;
    int dispatch_sent = 1;
    bool wire_dispatch = true;

    explicit BundleHarness(bool with_dispatch = true) : wire_dispatch(with_dispatch) {
        REQUIRE(store.is_open());

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = principal;
            s.role = is_admin ? auth::Role::admin : auth::Role::user;
            return s;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& verb,
                               const std::string& result, const std::string& type,
                               const std::string& id, const std::string&) -> bool {
            audits.push_back({verb, result, type, id});
            return true;
        };

        RestApiV1::CommandDispatchFn dispatch_fn;
        if (wire_dispatch) {
            dispatch_fn = [this](const std::string& plugin, const std::string& action,
                                 const std::vector<std::string>& agent_ids,
                                 const std::string& scope_expr,
                                 const std::unordered_map<std::string, std::string>&,
                                 const std::string& exec_id) -> std::pair<std::string, int> {
                calls.push_back({plugin, action, scope_expr, exec_id, agent_ids});
                return {"cmd-" + plugin + "-" + action, dispatch_sent};
            };
        }

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr, /*token_store=*/nullptr,
                            /*quarantine_store=*/nullptr, store.is_open() ? &store : nullptr,
                            /*instruction_store=*/nullptr, /*execution_tracker=*/nullptr,
                            /*schedule_engine=*/nullptr, /*approval_manager=*/nullptr,
                            /*tag_store=*/nullptr, /*audit_store=*/nullptr, /*service_group_fn=*/{},
                            /*tag_push_fn=*/{}, /*inventory_store=*/nullptr,
                            /*product_pack_store=*/nullptr, /*sw_deploy_store=*/nullptr,
                            /*device_token_store=*/nullptr, /*license_store=*/nullptr,
                            /*guaranteed_state_store=*/nullptr, &metrics, /*session_revoke_fn=*/{},
                            /*execution_event_bus=*/nullptr, /*result_set_store=*/nullptr,
                            dispatch_fn);
    }

    nlohmann::json post(const std::string& path, const std::string& body, int& status) {
        auto res = sink.dispatch("POST", path, body);
        REQUIRE(res != nullptr);
        status = res->status;
        return nlohmann::json::parse(res->body, nullptr, false);
    }
    nlohmann::json get(const std::string& path, int& status) {
        auto res = sink.dispatch("GET", path, "");
        REQUIRE(res != nullptr);
        status = res->status;
        return nlohmann::json::parse(res->body, nullptr, false);
    }

    void put_response(const std::string& correlation, const std::string& command_id, int st,
                      const std::string& output) {
        StoredResponse r;
        r.execution_id = correlation;
        r.instruction_id = command_id;
        r.agent_id = "agent-1";
        r.status = st;
        r.output = output;
        r.timestamp = 100;
        store.store(r);
    }
};

bool has_audit(const std::vector<AuditRow>& a, const std::string& verb, const std::string& type) {
    for (const auto& r : a)
        if (r.verb == verb && r.type == type)
            return true;
    return false;
}

} // namespace

TEST_CASE("POST /api/v1/bundles dispatches each step and returns 202 + execution_id",
          "[bundle][rest]") {
    BundleHarness h;
    int status = 0;
    auto j = h.post(
        "/api/v1/bundles",
        R"({"agent_id":"agent-1","steps":[{"plugin":"os_info","action":"uptime"},{"plugin":"os_info","action":"os_name"}]})",
        status);
    REQUIRE(status == 202);
    auto data = j["data"];
    auto exec_id = data["execution_id"].get<std::string>();
    CHECK(exec_id.rfind("bundle-", 0) == 0); // bundle- prefix → notify_exec_tracker skips it
    CHECK(data["expected"] == 2);

    REQUIRE(h.calls.size() == 2);
    CHECK(h.calls[0].plugin == "os_info");
    CHECK(h.calls[0].agent_ids == std::vector<std::string>{"agent-1"});
    CHECK(h.calls[0].execution_id == exec_id); // all steps share the correlation id
    CHECK(h.calls[1].execution_id == exec_id);

    // Per-step audit verbs, device-scoped (governance F1), + the dispatch envelope.
    CHECK(has_audit(h.audits, "bundle.os_info.uptime", "Agent"));
    CHECK(has_audit(h.audits, "bundle.os_info.os_name", "Agent"));
    CHECK(has_audit(h.audits, "bundle.dispatch", "Execution"));
}

TEST_CASE("GET /api/v1/bundles/{id} collates the responses", "[bundle][rest]") {
    BundleHarness h;
    int status = 0;
    auto disp = h.post(
        "/api/v1/bundles",
        R"({"agent_id":"agent-1","steps":[{"plugin":"os_info","action":"uptime"},{"plugin":"os_info","action":"os_name"}]})",
        status);
    auto exec_id = disp["data"]["execution_id"].get<std::string>();

    // Before responses: complete=false.
    auto a0 = h.get("/api/v1/bundles/" + exec_id, status);
    REQUIRE(status == 200);
    CHECK(a0["data"]["complete"] == false);

    h.put_response(exec_id, "cmd-os_info-os_name", 1, "os_name|Win");
    h.put_response(exec_id, "cmd-os_info-uptime", 1, "up 3d");

    auto a1 = h.get("/api/v1/bundles/" + exec_id, status);
    REQUIRE(status == 200);
    auto data = a1["data"];
    CHECK(data["complete"] == true);
    CHECK(data["received"] == 2);
    REQUIRE(data["steps"].size() == 2);
    CHECK(data["steps"][0]["action"] == "uptime"); // request order
    CHECK(data["steps"][0]["output"] == "up 3d");
}

TEST_CASE("GET collate is 404 for a non-owner (IDOR guard)", "[bundle][rest]") {
    BundleHarness h;
    int status = 0;
    auto disp = h.post("/api/v1/bundles",
                       R"({"agent_id":"agent-1","steps":[{"plugin":"os_info","action":"uptime"}]})",
                       status);
    auto exec_id = disp["data"]["execution_id"].get<std::string>();

    // Collate as a different, non-admin principal → 404 (same as not-found).
    h.principal = "mallory";
    h.is_admin = false;
    h.get("/api/v1/bundles/" + exec_id, status);
    CHECK(status == 404);

    // Owner still gets it.
    h.principal = "alice";
    h.is_admin = true;
    h.get("/api/v1/bundles/" + exec_id, status);
    CHECK(status == 200);
}

TEST_CASE("POST /api/v1/bundles validation 400s", "[bundle][rest][unhappy]") {
    BundleHarness h;
    int status = 0;
    h.post("/api/v1/bundles", "not json", status);
    CHECK(status == 400);
    h.post("/api/v1/bundles", R"({"steps":[{"plugin":"p","action":"a"}]})", status); // no agent_id
    CHECK(status == 400);
    h.post("/api/v1/bundles", R"({"agent_id":"a","steps":[]})", status); // empty steps
    CHECK(status == 400);
    h.post("/api/v1/bundles", R"({"agent_id":"a","steps":[{"plugin":"p p","action":"a"}]})",
           status); // unsafe identifier
    CHECK(status == 400);
}

TEST_CASE("bundle routes 503 when dispatch is unwired", "[bundle][rest][unhappy]") {
    BundleHarness h{/*with_dispatch=*/false};
    int status = 0;
    h.post("/api/v1/bundles",
           R"({"agent_id":"a","steps":[{"plugin":"os_info","action":"uptime"}]})", status);
    CHECK(status == 503);
}
