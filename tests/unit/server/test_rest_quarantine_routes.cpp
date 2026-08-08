/**
 * test_rest_quarantine_routes.cpp -- route-level regression tests for the REST
 * v1 quarantine surface (POST /api/v1/quarantine, DELETE
 * /api/v1/quarantine/{id}) after the CDX-P1-02 hardening. Mirrors
 * test_rest_tag_routes.cpp's harness shape: these dispatch synthesized
 * requests through the captured route closures against an in-process
 * TestRouteSink, proving the LAMBDA WIRING -- authenticate-first,
 * scoped-gate-as-sole-authorization, fail-closed-when-unwired -- not just the
 * shared require_scoped_permission logic the MCP quarantine_device twin
 * already covers (this route wiring previously had zero tests at all).
 */

#include "quarantine_store.hpp"
#include "rest_api_v1.hpp"

#include "../test_helpers.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

using namespace yuzu::server;

namespace {

struct AuditCall {
    std::string action;
    std::string result;
    std::string target_type;
    std::string target_id;
    std::string detail;
};

// A harness that registers ONLY the quarantine routes against a TestRouteSink,
// with a real QuarantineStore and injectable auth / scoped-permission
// behaviour.
struct QuarantineRouteHarness {
    yuzu::server::test::TestRouteSink sink;
    RestApiV1 api;

    yuzu::test::TempDbFile qdb{std::string_view{"yuzu_test_rest_quarantine-"}};
    QuarantineStore quarantine_store{qdb.path};

    // auth: empty session_user => require_auth writes 401 and returns nullopt.
    std::string session_user{"alice"};
    // scope decision the stub returns; when `wire_scope` is false the route is
    // registered with an UNWIRED scoped fn (the fail-closed 500 case).
    bool scope_allow{true};
    bool scope_fn_called{false};
    std::string scoped_target;
    // Per-agent override for the GET list-scoping tests, where different
    // records in the same response must resolve to DIFFERENT scope
    // decisions -- the single `scope_allow` bool can't express that. Checked
    // before falling back to `scope_allow`.
    std::unordered_map<std::string, bool> scope_allow_for;
    std::vector<AuditCall> audit_calls;

    explicit QuarantineRouteHarness(bool wire_scope = true) {
        REQUIRE(quarantine_store.is_open());

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response& res) -> std::optional<auth::Session> {
            if (session_user.empty()) {
                res.status = 401;
                return std::nullopt;
            }
            auth::Session s;
            s.username = session_user;
            return s;
        };
        // Global perm_fn is intentionally permissive: after the CDX-P1-02
        // change the quarantine routes do NOT call it -- if a regression
        // re-introduced a global pre-gate, these tests would still pass, but
        // the scope-deny case below would then fail (proving the scoped gate
        // is the one in force).
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_calls.push_back({action, result, target_type, target_id, detail});
            return true;
        };

        RestApiV1::ScopedPermFn scoped_fn{};
        if (wire_scope) {
            scoped_fn = [this](const httplib::Request&, httplib::Response& res,
                               const std::string&, const std::string&,
                               const std::string& agent_id) -> bool {
                scope_fn_called = true;
                scoped_target = agent_id;
                auto it = scope_allow_for.find(agent_id);
                bool allow = it != scope_allow_for.end() ? it->second : scope_allow;
                if (allow)
                    return true;
                res.status = 403;
                return false;
            };
        }

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr,
                            /*token_store=*/nullptr, &quarantine_store,
                            /*response_store=*/nullptr, /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr, /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr, /*tag_store=*/nullptr,
                            /*audit_store=*/nullptr, /*service_group_fn=*/{},
                            /*tag_push_fn=*/{}, /*inventory_store=*/nullptr,
                            /*product_pack_store=*/nullptr, /*sw_deploy_store=*/nullptr,
                            /*device_token_store=*/nullptr, /*license_store=*/nullptr,
                            /*guaranteed_state_store=*/nullptr, /*metrics_registry=*/nullptr,
                            /*session_revoke_fn=*/{}, /*execution_event_bus=*/nullptr,
                            /*result_set_store=*/nullptr, /*command_dispatch_fn=*/{},
                            /*step_up_fn=*/{}, /*guardian_push_fn=*/{}, /*dex_perf_fn=*/{},
                            /*net_perf_fn=*/{}, /*lockout_clear_fn=*/{},
                            /*baseline_store=*/nullptr, scoped_fn);
    }

    auto post(const std::string& body) {
        return sink.Post("/api/v1/quarantine", body, "application/json");
    }
    auto del(const std::string& agent) {
        return sink.Delete("/api/v1/quarantine/" + agent);
    }
    auto get() {
        return sink.Get("/api/v1/quarantine");
    }

    bool is_quarantined(const std::string& agent_id) {
        for (const auto& r : quarantine_store.list_quarantined())
            if (r.agent_id == agent_id)
                return true;
        return false;
    }
};

const std::string kBody = R"({"agent_id":"agent-B","reason":"test"})";

} // namespace

TEST_CASE("REST POST /api/v1/quarantine requires authentication before any store/body work "
          "(CDX-P1-02)",
          "[rest][quarantine][authz]") {
    QuarantineRouteHarness h;
    h.session_user = ""; // no session
    auto res = h.post(kBody);
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK_FALSE(h.scope_fn_called);
    CHECK_FALSE(h.is_quarantined("agent-B")); // no write
}

TEST_CASE("REST POST /api/v1/quarantine is denied per-target by the scoped gate (403, no write) "
          "(CDX-P1-02)",
          "[rest][quarantine][authz]") {
    QuarantineRouteHarness h;
    h.scope_allow = false;
    auto res = h.post(kBody);
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.scope_fn_called);
    CHECK(h.scoped_target == "agent-B"); // scoped on the PARSED target
    CHECK_FALSE(h.is_quarantined("agent-B"));
}

TEST_CASE("REST POST /api/v1/quarantine admits an in-scope caller and quarantines the device "
          "(201) (CDX-P1-02)",
          "[rest][quarantine][authz]") {
    QuarantineRouteHarness h;
    h.scope_allow = true;
    auto res = h.post(kBody);
    REQUIRE(res);
    CHECK(res->status == 201);
    CHECK(h.scope_fn_called);
    CHECK(h.is_quarantined("agent-B"));
}

TEST_CASE("REST POST /api/v1/quarantine fails CLOSED (500) when the scope gate is unwired "
          "(CDX-P1-02)",
          "[rest][quarantine][authz]") {
    QuarantineRouteHarness h(/*wire_scope=*/false);
    auto res = h.post(kBody);
    REQUIRE(res);
    CHECK(res->status == 500); // never a silent global fallback
    CHECK_FALSE(h.is_quarantined("agent-B"));
}

TEST_CASE("REST POST /api/v1/quarantine rejects a malformed JSON body (400, no dispatch) "
          "(gov-fix)",
          "[rest][quarantine][authz]") {
    QuarantineRouteHarness h;
    // Not a JSON object at all -- must NOT reach scoped_perm_fn/.value() and
    // must NOT throw (this is the exact shape that, absent the is_discarded()/
    // is_object() guard, previously reached `body.value("agent_id","")` on a
    // discarded parse result and threw nlohmann::json::type_error uncaught).
    auto res = h.post("not json");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK_FALSE(h.scope_fn_called);
    CHECK_FALSE(h.is_quarantined("agent-B"));
}

TEST_CASE("REST POST/DELETE /api/v1/quarantine audit the unwired-scope-gate 500 (gov-fix)",
          "[rest][quarantine][authz]") {
    SECTION("POST") {
        QuarantineRouteHarness h(/*wire_scope=*/false);
        auto res = h.post(kBody);
        REQUIRE(res);
        CHECK(res->status == 500);
        REQUIRE(h.audit_calls.size() == 1);
        CHECK(h.audit_calls[0].action == "quarantine.enable");
        CHECK(h.audit_calls[0].result == "failure");
        CHECK(h.audit_calls[0].target_id == "agent-B");
    }
    SECTION("DELETE") {
        QuarantineRouteHarness h(/*wire_scope=*/false);
        auto res = h.del("agent-B");
        REQUIRE(res);
        CHECK(res->status == 500);
        REQUIRE(h.audit_calls.size() == 1);
        CHECK(h.audit_calls[0].action == "quarantine.disable");
        CHECK(h.audit_calls[0].result == "failure");
        CHECK(h.audit_calls[0].target_id == "agent-B");
    }
}

TEST_CASE("REST GET /api/v1/quarantine admits-then-filters per record (gov-fix/consistency-"
          "auditor)",
          "[rest][quarantine][authz]") {
    SECTION("an out-of-scope record is dropped from the list, an in-scope record is kept") {
        QuarantineRouteHarness h;
        REQUIRE(h.quarantine_store.quarantine_device("agent-visible", "seed", "r1", ""));
        REQUIRE(h.quarantine_store.quarantine_device("agent-hidden", "seed", "r2", ""));
        h.scope_allow_for["agent-visible"] = true;
        h.scope_allow_for["agent-hidden"] = false;
        auto res = h.get();
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(res->body.find("agent-visible") != std::string::npos);
        CHECK(res->body.find("agent-hidden") == std::string::npos);
    }
    SECTION("unwired scope gate fails closed (500), not an unfiltered list") {
        QuarantineRouteHarness h(/*wire_scope=*/false);
        REQUIRE(h.quarantine_store.quarantine_device("agent-visible", "seed", "r1", ""));
        auto res = h.get();
        REQUIRE(res);
        CHECK(res->status == 500);
        CHECK(res->body.find("agent-visible") == std::string::npos);
    }
    SECTION("no session is refused before any store work") {
        QuarantineRouteHarness h;
        h.session_user = "";
        auto res = h.get();
        REQUIRE(res);
        CHECK(res->status == 401);
        CHECK_FALSE(h.scope_fn_called);
    }
}

TEST_CASE("REST DELETE /api/v1/quarantine admits in-scope and fails closed when unwired "
          "(CDX-P1-02)",
          "[rest][quarantine][authz]") {
    SECTION("in-scope delete releases the device") {
        QuarantineRouteHarness h;
        REQUIRE(h.quarantine_store.quarantine_device("agent-B", "seed", "pre-seeded", ""));
        auto res = h.del("agent-B");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(h.scoped_target == "agent-B");
        CHECK_FALSE(h.is_quarantined("agent-B"));
    }
    SECTION("out-of-scope delete is denied (403), device stays quarantined") {
        QuarantineRouteHarness h;
        h.scope_allow = false;
        REQUIRE(h.quarantine_store.quarantine_device("agent-B", "seed", "pre-seeded", ""));
        auto res = h.del("agent-B");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.is_quarantined("agent-B")); // untouched
    }
    SECTION("unwired scope gate fails closed, device untouched") {
        QuarantineRouteHarness h(/*wire_scope=*/false);
        REQUIRE(h.quarantine_store.quarantine_device("agent-B", "seed", "pre-seeded", ""));
        auto res = h.del("agent-B");
        REQUIRE(res);
        CHECK(res->status == 500);
        CHECK(h.is_quarantined("agent-B")); // untouched
    }
}
