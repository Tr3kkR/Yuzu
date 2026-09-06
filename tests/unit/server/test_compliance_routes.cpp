/**
 * test_compliance_routes.cpp — guardian-confinement-2298 PR3 §3e coverage for
 * the two compliance dashboard fragments (`/fragments/compliance/summary` and
 * `/fragments/compliance/{policy_id}`): both were `auth_fn`-only, no
 * `perm_fn` at all, rendering per-agent compliance rows fleet-wide with no
 * per-target parameter to scope against.
 *
 * ComplianceRoutes had no route-level test coverage before this file — the
 * sink-based `register_routes` overload (mirrors AuthRoutes/WorkflowRoutes,
 * added alongside this test) is what makes that possible without the #438
 * TSan-hostile live-socket pattern.
 */

#include "authz_gates.hpp"
#include "compliance_routes.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;

namespace {

struct AuditCall {
    std::string action, result, target_type, target_id, detail;
};

struct ComplianceHarness {
    // Declaration order matters (CLAUDE.md TestRouteSink convention): `sink`
    // captures `routes`'s `this` in its registered handlers, so `routes`
    // must outlive `sink` — declare it FIRST so it destructs LAST.
    ComplianceRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    std::vector<AuditCall> audit_calls;
    /// Empty ⇒ an ordinary session; a test sets this to prove the fragment
    /// deny fires independently of any perm_fn grant.
    std::string mock_token_scope_service;
    /// #4034: when false, audit_fn reports a persistence failure (returns
    /// false) so a test can exercise the set-and-proceed Sec-Audit-Failed
    /// header on GET /api/v1/compliance/{id}.
    bool audit_ok{true};

    /// #4034 — a fake `authz::FleetReadGate` gate the harness controls per
    /// test, same shape as test_rest_inventory_software.cpp's `InvHarness`.
    /// `nullopt` (default) ⇒ the gate does not exist (registered with no
    /// fleet_read_fn at all — misconfigured call site, 503); a test that
    /// wants the gate wired sets this via `wire_fleet_read_fn()` before
    /// constructing the harness is not possible (register_routes runs in
    /// the ctor), so this harness always wires a real fake gate and a test
    /// drives its behaviour via `fleet_admitted`/`fleet_scope` below.
    bool fleet_admitted{true};
    std::optional<std::unordered_set<std::string>> fleet_scope; // nullopt = TOP/unfiltered

    ComplianceHarness() {
        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "tester";
            s.role = auth::Role::admin;
            s.token_scope_service = mock_token_scope_service;
            return s;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_calls.push_back({action, result, target_type, target_id, detail});
            return audit_ok;
        };
        auto emit_fn = [](const std::string&, const httplib::Request&, const nlohmann::json&,
                          const nlohmann::json&) {};
        auto agents_json_fn = []() -> std::string { return "[]"; };
        ComplianceRoutes::FleetReadFn fleet_read_fn =
            [this](const httplib::Request&, httplib::Response& res, const std::string&,
                  const std::string&) -> authz::FleetReadGate {
            if (!fleet_admitted) {
                res.status = 403;
                res.set_content(R"({"error":{"message":"permission denied"}})",
                                "application/json");
                return {};
            }
            return {true, fleet_scope};
        };

        routes.register_routes(sink, auth_fn, perm_fn, audit_fn, emit_fn,
                               /*policy_store=*/nullptr, agents_json_fn,
                               /*policy_evaluator=*/nullptr, /*metrics=*/nullptr,
                               std::move(fleet_read_fn));
    }
};

} // namespace

TEST_CASE("/fragments/compliance/summary: a service-scoped token is denied",
          "[compliance][security]") {
    ComplianceHarness h;
    h.mock_token_scope_service = "printers";

    auto res = h.sink.Get("/fragments/compliance/summary");
    REQUIRE(res);
    CHECK(res->status == 403);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["message"].get<std::string>().find("service-scoped") != std::string::npos);
    // No permission field: this is a blanket deny with no perm_fn gate — the
    // A4 builder omits the field rather than name a grant that wouldn't help.
    CHECK_FALSE(j["error"].contains("permission"));
    // Header/body correlation-id parity (consistency-auditor, Gate 4): a
    // hand-built id used to land in the body only, never the header.
    CHECK_FALSE(j["error"]["correlation_id"].get<std::string>().empty());
    CHECK(res->get_header_value("X-Correlation-Id") ==
          j["error"]["correlation_id"].get<std::string>());

    bool saw_denied = false;
    for (const auto& c : h.audit_calls) {
        if (c.action == "compliance.fragment.access_denied" && c.result == "denied")
            saw_denied = true;
    }
    CHECK(saw_denied);
}

TEST_CASE("/fragments/compliance/summary: an ordinary session reaches the summary",
          "[compliance]") {
    ComplianceHarness h;

    auto res = h.sink.Get("/fragments/compliance/summary");
    REQUIRE(res);
    CHECK(res->status == 200);
    // policy_store is nullptr in this harness — the "No policies defined"
    // empty-state branch, not a denial. Confirms the deny above didn't also
    // block the legitimate path.
    CHECK(res->body.find("No policies defined") != std::string::npos);
    for (const auto& c : h.audit_calls) {
        CHECK(c.action != "compliance.fragment.access_denied");
    }
}

TEST_CASE("/fragments/compliance/{policy_id}: a service-scoped token is denied",
          "[compliance][security]") {
    ComplianceHarness h;
    h.mock_token_scope_service = "printers";

    auto res = h.sink.Get("/fragments/compliance/pol_1");
    REQUIRE(res);
    CHECK(res->status == 403);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["message"].get<std::string>().find("service-scoped") != std::string::npos);
    // Header/body correlation-id parity (consistency-auditor, Gate 4).
    CHECK_FALSE(j["error"]["correlation_id"].get<std::string>().empty());
    CHECK(res->get_header_value("X-Correlation-Id") ==
          j["error"]["correlation_id"].get<std::string>());

    bool saw_denied = false;
    for (const auto& c : h.audit_calls) {
        if (c.action == "compliance.fragment.access_denied" && c.result == "denied")
            saw_denied = true;
    }
    CHECK(saw_denied);
}

TEST_CASE("/fragments/compliance/{policy_id}: an ordinary session reaches the detail",
          "[compliance]") {
    ComplianceHarness h;

    auto res = h.sink.Get("/fragments/compliance/pol_1");
    REQUIRE(res);
    CHECK(res->status == 200);
    // policy_store is nullptr — the "No compliance data yet" empty-state
    // branch, not a denial.
    CHECK(res->body.find("No compliance data yet") != std::string::npos);
    for (const auto& c : h.audit_calls) {
        CHECK(c.action != "compliance.fragment.access_denied");
    }
}

// ═════════════════════════════════════════════════════════════════════════
// #4034 — GET /api/v1/compliance* + /api/v1/polic* REST v1 twins. The
// harness's `policy_store` is always nullptr (matching the pre-existing
// #3559 item 3 gap: ComplianceHarness cannot exercise a store-backed
// branch), so these pin the auth/gate/envelope/degraded-service wiring, not
// the real query/builder output — the confined_policy_compliance tally
// itself is unit-tested directly (pure, no store) in
// test_compliance_model.cpp.
// ═════════════════════════════════════════════════════════════════════════

TEST_CASE("GET /api/v1/policy-fragments: null store -> 503 A4 body",
          "[compliance][rest]") {
    ComplianceHarness h;
    auto res = h.sink.Get("/api/v1/policy-fragments");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 503);
    CHECK_FALSE(j["error"]["correlation_id"].get<std::string>().empty());
    CHECK(res->get_header_value("X-Correlation-Id") ==
          j["error"]["correlation_id"].get<std::string>());
    CHECK(j["meta"]["api_version"].get<std::string>() == "v1");
}

TEST_CASE("GET /api/v1/policies: null store -> 503 A4 body", "[compliance][rest]") {
    ComplianceHarness h;
    auto res = h.sink.Get("/api/v1/policies");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 503);
}

TEST_CASE("GET /api/v1/policies/{id}: null store -> 503 A4 body", "[compliance][rest]") {
    ComplianceHarness h;
    auto res = h.sink.Get("/api/v1/policies/pol_1");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 503);
}

TEST_CASE("GET /api/v1/compliance: null store -> 503 A4 body", "[compliance][rest]") {
    ComplianceHarness h;
    auto res = h.sink.Get("/api/v1/compliance");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 503);
}

TEST_CASE("GET /api/v1/compliance/{id}: fleet_read_fn denies -> gate's own response, "
          "no store touched, no route audit",
          "[compliance][rest][security]") {
    ComplianceHarness h;
    h.fleet_admitted = false;

    auto res = h.sink.Get("/api/v1/compliance/pol_1");
    REQUIRE(res);
    CHECK(res->status == 403); // the fake gate's own denial response
    for (const auto& c : h.audit_calls)
        CHECK(c.action != "compliance.agent_statuses.view");
}

TEST_CASE("GET /api/v1/compliance/{id}: fleet_read_fn admits, null store -> 503, "
          "gate is the SOLE authorization (never stacked with perm_fn)",
          "[compliance][rest]") {
    ComplianceHarness h;
    h.fleet_admitted = true;

    auto res = h.sink.Get("/api/v1/compliance/pol_1");
    REQUIRE(res);
    CHECK(res->status == 503);
    auto j = nlohmann::json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 503);
    // The route never reached the audit call (null-store short-circuit
    // precedes it) — same "no access, no audit row" contract as the null
    // store case above.
    for (const auto& c : h.audit_calls)
        CHECK(c.action != "compliance.agent_statuses.view");
}
