/**
 * test_policy_admin_routes.cpp — coverage for PolicyAdminRoutes, split out
 * of compliance_routes.cpp by ADR-0031 WS-A4 Task B (policy/fragment
 * mutator routes: no public REST v1/MCP twin — see policy_admin_routes.hpp's
 * file banner for why this deliberately stays outside the compliance
 * family's seam-closure enforcement).
 *
 * ComplianceRoutes had no route-level mutator test coverage before this
 * split (test_compliance_routes.cpp only ever called PolicyStore mutators
 * directly as fixture setup, never through the routes) — this file is NEW
 * coverage, not a move of pre-existing tests.
 */

#include "pg/pg_pool.hpp"
#include "policy_admin_routes.hpp"
#include "policy_store.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

struct AuditCall {
    std::string action, result, target_type, target_id, detail;
};

struct PolicyAdminHarness {
    // Declaration order matters (CLAUDE.md TestRouteSink convention): `sink`
    // captures `routes`'s `this` in its registered handlers, so `routes`
    // must outlive `sink` — declare it FIRST so it destructs LAST.
    PolicyAdminRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    std::vector<AuditCall> audit_calls;
    std::vector<std::string> emitted_events;

    explicit PolicyAdminHarness(PolicyStore* policy_store = nullptr) {
        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "tester";
            s.role = auth::Role::admin;
            return s;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string& target_type,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_calls.push_back({action, result, target_type, target_id, detail});
            return true;
        };
        auto emit_fn = [this](const std::string& event_type, const httplib::Request&,
                              const nlohmann::json&, const nlohmann::json&) {
            emitted_events.push_back(event_type);
        };

        routes.register_routes(sink, auth_fn, perm_fn, audit_fn, emit_fn, policy_store,
                               /*policy_evaluator=*/nullptr, /*metrics=*/nullptr);
    }
};

// Same template KEY as test_compliance_routes.cpp / test_policy_store.cpp —
// PgTestTemplate explicitly supports sharing a name across files needing the
// exact same store set, so this reuses the already-built template instead of
// paying a second migration pass.
yuzu::test::PgTestTemplate policy_admin_store_tpl{
    "policystore", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        PolicyStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("policy_store template: failed to migrate");
    }};

const std::string kFragmentYaml = R"(
apiVersion: yuzu.io/v1alpha1
kind: PolicyFragment
displayName: Admin Route Fragment
description: Verify a Windows service is running
spec:
  check:
    instruction: get_service_status
    compliance: "result.status == 'running'"
)";

} // namespace

TEST_CASE("POST /api/policies: null store -> 503", "[compliance][admin]") {
    PolicyAdminHarness h;
    auto res = h.sink.Post("/api/policies", R"({"yaml_source":"x"})");
    REQUIRE(res);
    CHECK(res->status == 503);
}

TEST_CASE("POST /api/policy-fragments: null store -> 503", "[compliance][admin]") {
    PolicyAdminHarness h;
    auto res = h.sink.Post("/api/policy-fragments", kFragmentYaml, "text/plain");
    REQUIRE(res);
    CHECK(res->status == 503);
}

TEST_CASE("POST /api/policy-fragments: creates a fragment, audits, and emits",
          "[compliance][admin]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_admin_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    PolicyStore store{pool};
    REQUIRE(store.is_open());
    PolicyAdminHarness h{&store};

    auto res = h.sink.Post("/api/policy-fragments", kFragmentYaml, "text/plain");
    REQUIRE(res);
    CHECK(res->status == 201);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["status"] == "created");
    REQUIRE(!h.audit_calls.empty());
    CHECK(h.audit_calls.back().action == "policy_fragment.create");
    CHECK(h.audit_calls.back().result == "success");
    REQUIRE(!h.emitted_events.empty());
    CHECK(h.emitted_events.back() == "policy_fragment.created");

    // The fragment is really there — visible through the store directly.
    auto frags = store.query_fragments();
    REQUIRE(frags);
    CHECK(frags->size() == 1);
}

TEST_CASE("DELETE /api/policy-fragments/:id: deletes a real fragment", "[compliance][admin]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_admin_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    PolicyStore store{pool};
    REQUIRE(store.is_open());
    auto created = store.create_fragment(kFragmentYaml);
    REQUIRE(created);

    PolicyAdminHarness h{&store};
    auto res = h.sink.Delete("/api/policy-fragments/" + *created);
    REQUIRE(res);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["deleted"] == true);
    REQUIRE(!h.audit_calls.empty());
    CHECK(h.audit_calls.back().action == "policy_fragment.delete");
}

TEST_CASE("POST /api/policies/:id/enable + /disable: round-trips a real policy",
          "[compliance][admin]") {
    YUZU_REQUIRE_PG_DB_TPL(db, policy_admin_store_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    PolicyStore store{pool};
    REQUIRE(store.is_open());
    auto frag = store.create_fragment(kFragmentYaml);
    REQUIRE(frag);
    auto policy = store.create_policy(R"(
apiVersion: yuzu.io/v1alpha1
kind: Policy
displayName: Admin Route Policy
description: A test policy
fragment: )" + *frag + R"(
scope: "tags.env == 'production'"
)");
    REQUIRE(policy);

    PolicyAdminHarness h{&store};

    auto disable_res = h.sink.Post("/api/policies/" + *policy + "/disable", "");
    REQUIRE(disable_res);
    CHECK(disable_res->status == 200);

    auto enable_res = h.sink.Post("/api/policies/" + *policy + "/enable", "");
    REQUIRE(enable_res);
    CHECK(enable_res->status == 200);

    REQUIRE(h.audit_calls.size() >= 2);
    CHECK(h.audit_calls[0].action == "policy.disable");
    CHECK(h.audit_calls[1].action == "policy.enable");
}
