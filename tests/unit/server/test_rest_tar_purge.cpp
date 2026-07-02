/**
 * test_rest_tar_purge.cpp — route-handler coverage for the REST TAR source-purge
 * endpoint POST /api/v1/tar/retention-paused/purge (governance remediation of the
 * PR #1781 adversarial review; finding #5 / issue #1779).
 *
 * Registers RestApiV1 over an in-process TestRouteSink (#438: no acceptor thread)
 * with stub scoped-perm / audit / command-dispatch, and drives the DESTRUCTIVE
 * endpoint end-to-end so a future refactor that drops one of its gates fails here:
 *   - source allowlist (only process/tcp/service/user),
 *   - per-device scope gate (Infrastructure:Delete via scoped_perm_fn, fail-closed),
 *   - audit-before-dispatch fail-closed (no dispatch if the evidence row is lost),
 *   - the success dispatch shape (tar/purge_source targeting the one device, {source}).
 *
 * The DashboardRoutes HTML fragment (/fragments/tar/retention-paused/purge) shares
 * these properties but is registered on a raw httplib::Server (not HttpRouteSink),
 * so it is not reachable by this in-process sink — its route-handler coverage is a
 * tracked follow-up (migrate those fragments to HttpRouteSink — Tr3kkR/Yuzu#1786).
 * The fragment's render-time button gating is covered in test_dashboard_tar_retention.cpp.
 */

#include "rest_api_v1.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

using namespace yuzu::server;

namespace {

struct DispatchCall {
    std::string plugin, action;
    std::vector<std::string> agent_ids;
    std::unordered_map<std::string, std::string> params;
};
struct AuditRow {
    std::string action, result, target_type, target_id, detail;
};

struct PurgeHarness {
    yuzu::server::test::TestRouteSink sink;
    yuzu::MetricsRegistry metrics;
    RestApiV1 api;

    std::vector<DispatchCall> calls;
    std::vector<AuditRow> audits;
    bool scope_allow{true}; // scoped_perm_fn verdict
    bool audit_ok{true};    // AuditFn return (false → fail-closed 503, no dispatch)
    int dispatch_sent{1};   // agents reached per dispatch

    PurgeHarness() {
        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "purge-op";
            s.role = auth::Role::admin;
            return s;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                               const std::string& tt, const std::string& tid,
                               const std::string& d) -> bool {
            audits.push_back({a, r, tt, tid, d});
            return audit_ok;
        };
        RestApiV1::ScopedPermFn scoped =
            [this](const httplib::Request&, httplib::Response& res, const std::string&,
                   const std::string&, const std::string&) -> bool {
            if (!scope_allow) {
                res.status = 403;
                res.set_content(
                    R"({"error":{"code":403,"message":"forbidden"},"meta":{"api_version":"v1"}})",
                    "application/json");
            }
            return scope_allow;
        };
        RestApiV1::CommandDispatchFn dispatch =
            [this](const std::string& plugin, const std::string& action,
                   const std::vector<std::string>& ids, const std::string&,
                   const std::unordered_map<std::string, std::string>& params,
                   const std::string&) -> std::pair<std::string, int> {
            calls.push_back({plugin, action, ids, params});
            return {"cmd-" + std::to_string(calls.size()), dispatch_sent};
        };

        api.register_routes(
            sink, auth_fn, perm_fn, audit_fn,
            /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr, /*token_store=*/nullptr,
            /*quarantine_store=*/nullptr, /*response_store=*/nullptr, /*instruction_store=*/nullptr,
            /*execution_tracker=*/nullptr, /*schedule_engine=*/nullptr, /*approval_manager=*/nullptr,
            /*tag_store=*/nullptr, /*audit_store=*/nullptr, /*service_group_fn=*/{},
            /*tag_push_fn=*/{}, /*inventory_store=*/nullptr, /*product_pack_store=*/nullptr,
            /*sw_deploy_store=*/nullptr, /*device_token_store=*/nullptr, /*license_store=*/nullptr,
            /*guaranteed_state_store=*/nullptr, &metrics, /*session_revoke_fn=*/{},
            /*execution_event_bus=*/nullptr, /*result_set_store=*/nullptr, dispatch,
            /*step_up_fn=*/{}, /*guardian_push_fn=*/{}, /*dex_perf_fn=*/{}, /*net_perf_fn=*/{},
            /*lockout_clear_fn=*/{}, /*baseline_store=*/nullptr, scoped);
    }

    nlohmann::json post(const std::string& body, int& status) {
        auto res = sink.dispatch("POST", "/api/v1/tar/retention-paused/purge", body);
        REQUIRE(res != nullptr);
        status = res->status;
        return nlohmann::json::parse(res->body, nullptr, false);
    }
    int audits_for(const std::string& action) const {
        int n = 0;
        for (const auto& a : audits)
            if (a.action == action)
                ++n;
        return n;
    }
};

} // namespace

TEST_CASE("REST purge: rejects non-JSON / missing fields / bad source (400, no dispatch)",
          "[server][tar][purge][rest]") {
    PurgeHarness h;
    int st = 0;
    h.post("not json", st);
    CHECK(st == 400);
    h.post(R"({"device_id":"dev-A"})", st); // missing source
    CHECK(st == 400);
    h.post(R"({"source":"process"})", st); // missing device
    CHECK(st == 400);
    h.post(R"({"device_id":"dev-A","source":""})", st); // present-but-empty source
    CHECK(st == 400);
    h.post(R"({"device_id":"dev-A","source":"evil"})", st); // not in the allowlist
    CHECK(st == 400);
    h.post(R"({"device_id":"dev-A","source":"software"})", st); // real source, deliberately not in the REST allowlist
    CHECK(st == 400);
    CHECK(h.calls.empty());
    CHECK(h.audits_for("tar.source.purge") == 0); // never reached the pre-dispatch audit
}

TEST_CASE("REST purge: per-device scope gate denies (403, no dispatch, no audit)",
          "[server][tar][purge][rest]") {
    PurgeHarness h;
    h.scope_allow = false;
    int st = 0;
    h.post(R"({"device_id":"dev-A","source":"process"})", st);
    CHECK(st == 403);
    CHECK(h.calls.empty());
    CHECK(h.audits_for("tar.source.purge") == 0);
}

TEST_CASE("REST purge: audit fail-closed → 503, no dispatch",
          "[server][tar][purge][rest]") {
    PurgeHarness h;
    h.audit_ok = false;
    int st = 0;
    h.post(R"({"device_id":"dev-A","source":"process"})", st);
    CHECK(st == 503);
    CHECK(h.calls.empty()); // must NOT dispatch when the evidence row is known lost
}

TEST_CASE("REST purge: success dispatches tar/purge_source with {source} and returns 202",
          "[server][tar][purge][rest]") {
    PurgeHarness h;
    int st = 0;
    auto body = h.post(R"({"device_id":"dev-A","source":"tcp"})", st);
    CHECK(st == 202);
    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].plugin == "tar");
    CHECK(h.calls[0].action == "purge_source");
    REQUIRE(h.calls[0].agent_ids.size() == 1);
    CHECK(h.calls[0].agent_ids[0] == "dev-A");
    REQUIRE(h.calls[0].params.count("source") == 1);
    CHECK(h.calls[0].params.at("source") == "tcp");
    // A4 envelope nests the payload under "data".
    REQUIRE(body.contains("data"));
    CHECK(body["data"].contains("command_id"));
    CHECK(body["data"].value("source", "") == "tcp");
    CHECK(h.audits_for("tar.source.purge") == 1); // the pre-dispatch "requested" row
}

TEST_CASE("REST purge: offline agent (0 reached) → 404 after dispatch attempt",
          "[server][tar][purge][rest]") {
    PurgeHarness h;
    h.dispatch_sent = 0;
    int st = 0;
    h.post(R"({"device_id":"dev-A","source":"process"})", st);
    CHECK(st == 404);
    REQUIRE(h.calls.size() == 1); // dispatch was attempted, reached 0 agents
}
