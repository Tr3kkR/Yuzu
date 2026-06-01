/**
 * test_scope_walking_authz.cpp — cross-operator authorization for the
 * `from_result_set:` scope kind (scope-walking review finding B1).
 *
 * AgentRegistry::evaluate_scope must resolve `from_result_set:<id>` ONLY for a
 * dispatching principal that owns the set. An operator who learns another
 * operator's rs_ id and embeds it in a scope expression must target ZERO of
 * that set's devices (the IDOR the review blocked merge on). The owner check
 * lives in the preload step (ResultSetStore::member_set_owned), scoped to the
 * principal threaded into evaluate_scope; an empty principal (the untracked
 * raw-dispatch path with no operator) resolves nothing.
 */

#include "agent_registry.hpp"
#include "event_bus.hpp"
#include "result_set_store.hpp"
#include "scope_engine.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include "../test_helpers.hpp"

#include "agent.pb.h"

#include <algorithm>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::EventBus;
namespace agent_pb = ::yuzu::agent::v1;

namespace {

agent_pb::AgentInfo info(const std::string& id) {
    agent_pb::AgentInfo a;
    a.set_agent_id(id);
    a.set_hostname(id + ".local");
    return a;
}

bool has(const std::vector<std::string>& v, const std::string& id) {
    return std::find(v.begin(), v.end(), id) != v.end();
}

} // namespace

TEST_CASE("evaluate_scope: from_result_set is owner-scoped (no cross-operator targeting)",
          "[scope][result_set][authz]") {
    yuzu::test::TempDbFile rs_db{std::string_view{"scope-authz-rs-"}};
    ResultSetStore store(rs_db.path);
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.register_agent(info("agent-win"));
    registry.register_agent(info("agent-lin"));

    // Alice curates a set containing only one of the two connected agents.
    CreateRequest cr;
    cr.owner_principal = "alice";
    cr.name = "alice-suspects";
    cr.source_kind = std::string(source_kind::kManualCurate);
    cr.source_payload = "{}";
    auto set = store.create_materialized(cr, {"agent-win"});
    REQUIRE(set.has_value());

    auto expr = yuzu::scope::parse("from_result_set:" + set->id);
    REQUIRE(expr.has_value());

    SECTION("owner resolves exactly the set's members") {
        auto matched = registry.evaluate_scope(*expr, /*tag_store=*/nullptr,
                                               /*props_store=*/nullptr, &store, "alice");
        REQUIRE(matched.size() == 1);
        CHECK(has(matched, "agent-win"));
        CHECK_FALSE(has(matched, "agent-lin")); // not a broadcast
    }

    SECTION("a non-owner targets nothing — IDOR blocked (review B1)") {
        auto matched = registry.evaluate_scope(*expr, nullptr, nullptr, &store, "bob");
        CHECK(matched.empty());
    }

    SECTION("empty principal (untracked raw-dispatch path) resolves nothing") {
        auto matched = registry.evaluate_scope(*expr, nullptr, nullptr, &store, "");
        CHECK(matched.empty());
    }
}
