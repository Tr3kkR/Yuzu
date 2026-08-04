/**
 * test_rest_tag_routes.cpp -- route-level regression tests for the REST v1
 * tag-mutation surface (PUT /api/v1/tags, DELETE /api/v1/tags/{id}/{key}) after
 * the CDX-03 / CDX-R4-02 / B4 hardening. These dispatch synthesized requests
 * through the captured route closures against an in-process TestRouteSink
 * (same pattern as test_rest_api_tokens.cpp), so they prove the LAMBDA WIRING
 * -- authenticate-first, scoped-gate-as-sole-authorization, fail-closed-when-
 * unwired -- not just the shared require_scoped_permission logic the MCP twin
 * already covers (K-05/CDX-R4-04: this route wiring previously had zero tests).
 */

#include "rest_api_v1.hpp"
#include "tag_store.hpp"

#include "../test_helpers.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>

using namespace yuzu::server;

namespace {

// A harness that registers ONLY the tag routes against a TestRouteSink, with a
// real TagStore and injectable auth / scoped-permission behaviour.
struct TagRouteHarness {
    yuzu::server::test::TestRouteSink sink;
    RestApiV1 api;

    yuzu::test::TempDbFile tag_db{std::string_view{"yuzu_test_rest_tag-"}};
    TagStore tag_store{tag_db.path};

    // auth: empty session_user => require_auth writes 401 and returns nullopt.
    std::string session_user{"alice"};
    // scope decision the stub returns; when `wire_scope` is false the route is
    // registered with an UNWIRED scoped fn (the fail-closed 500 case).
    bool scope_allow{true};
    bool scope_fn_called{false};
    std::string scoped_target;

    explicit TagRouteHarness(bool wire_scope = true) {
        REQUIRE(tag_store.is_open());

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
        // Global perm_fn is intentionally permissive: after the CDX-03 change the
        // tag routes do NOT call it -- if a regression re-introduced a global
        // pre-gate, these tests would still pass, but the scope-deny case below
        // would then fail (proving the scoped gate is the one in force).
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                           const std::string&, const std::string&, const std::string&) -> bool {
            return true;
        };

        RestApiV1::ScopedPermFn scoped_fn{};
        if (wire_scope) {
            scoped_fn = [this](const httplib::Request&, httplib::Response& res,
                               const std::string&, const std::string&,
                               const std::string& agent_id) -> bool {
                scope_fn_called = true;
                scoped_target = agent_id;
                if (scope_allow)
                    return true;
                res.status = 403;
                return false;
            };
        }

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr,
                            /*token_store=*/nullptr, /*quarantine_store=*/nullptr,
                            /*response_store=*/nullptr, /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr, /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr, &tag_store,
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

    auto put(const std::string& body) {
        return sink.Put("/api/v1/tags", body, "application/json");
    }
    auto del(const std::string& agent, const std::string& key) {
        return sink.Delete("/api/v1/tags/" + agent + "/" + key);
    }
};

const std::string kBody = R"({"agent_id":"agent-B","key":"service","value":"ServiceA"})";

} // namespace

TEST_CASE("REST PUT /api/v1/tags requires authentication before any store/body work (CDX-R4-02)",
          "[rest][tag][authz]") {
    TagRouteHarness h;
    h.session_user = ""; // no session
    auto res = h.put(kBody);
    REQUIRE(res);
    CHECK(res->status == 401);
    CHECK_FALSE(h.scope_fn_called);
    CHECK(h.tag_store.get_tag("agent-B", "service").empty()); // no write
}

TEST_CASE("REST PUT /api/v1/tags is denied per-target by the scoped gate (403, no write)",
          "[rest][tag][authz]") {
    TagRouteHarness h;
    h.scope_allow = false;
    auto res = h.put(kBody);
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.scope_fn_called);
    CHECK(h.scoped_target == "agent-B"); // scoped on the PARSED target
    CHECK(h.tag_store.get_tag("agent-B", "service").empty());
}

TEST_CASE("REST PUT /api/v1/tags admits an in-scope caller and writes the tag (200)",
          "[rest][tag][authz]") {
    TagRouteHarness h;
    h.scope_allow = true;
    auto res = h.put(kBody);
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(h.scope_fn_called);
    CHECK(h.tag_store.get_tag("agent-B", "service") == "ServiceA");
}

TEST_CASE("REST PUT /api/v1/tags fails CLOSED (500) when the scope gate is unwired (B4)",
          "[rest][tag][authz]") {
    TagRouteHarness h(/*wire_scope=*/false);
    auto res = h.put(kBody);
    REQUIRE(res);
    CHECK(res->status == 500); // never a silent global fallback
    CHECK(h.tag_store.get_tag("agent-B", "service").empty());
}

TEST_CASE("REST DELETE /api/v1/tags admits in-scope and fails closed when unwired",
          "[rest][tag][authz]") {
    SECTION("in-scope delete removes the tag") {
        TagRouteHarness h;
        h.tag_store.set_tag("agent-B", "service", "ServiceA", "seed");
        auto res = h.del("agent-B", "service");
        REQUIRE(res);
        CHECK(res->status == 200);
        CHECK(h.scoped_target == "agent-B");
        CHECK(h.tag_store.get_tag("agent-B", "service").empty());
    }
    SECTION("unwired scope gate fails closed, tag untouched") {
        TagRouteHarness h(/*wire_scope=*/false);
        h.tag_store.set_tag("agent-B", "service", "ServiceA", "seed");
        auto res = h.del("agent-B", "service");
        REQUIRE(res);
        CHECK(res->status == 500);
        CHECK(h.tag_store.get_tag("agent-B", "service") == "ServiceA"); // not deleted
    }
    SECTION("out-of-scope delete is denied (403), tag untouched") {
        TagRouteHarness h;
        h.scope_allow = false;
        h.tag_store.set_tag("agent-B", "service", "ServiceA", "seed");
        auto res = h.del("agent-B", "service");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(h.tag_store.get_tag("agent-B", "service") == "ServiceA");
    }
}
