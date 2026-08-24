/**
 * test_execution_event_scope.cpp — the per-event admission rule the
 * scope-confined `ExecutionEventBus` consumers share (#1712).
 *
 * Pure-function coverage, no store / no HTTP / no PostgreSQL: the header is
 * deliberately a decision-only unit (`docs/cpp-conventions.md` "pure core,
 * thin shell"), so its whole contract is reachable from a fixture struct.
 * The ROUTE-level proof that `/sse/executions/{id}` actually applies it lives
 * in test_workflow_routes.cpp — a rule nothing calls is worth nothing, and
 * these cases cannot see that.
 */

#include "execution_event_scope.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using yuzu::server::classify_execution_event;
using yuzu::server::ExecutionEvent;
using yuzu::server::execution_event_in_scope;
using yuzu::server::ExecutionEventScopeClass;
using yuzu::server::ResponseScopePredicate;

namespace {

ExecutionEvent ev(std::string type, std::string agent_id = {}) {
    ExecutionEvent e;
    e.event_type = std::move(type);
    e.agent_id = std::move(agent_id);
    return e;
}

const ResponseScopePredicate kAdmitAll = [](const std::string&, const std::string&) {
    return true;
};
const ResponseScopePredicate kDenyAll = [](const std::string&, const std::string&) {
    return false;
};

} // namespace

TEST_CASE("execution event taxonomy classifies the three published types", "[1712][sse][scope]") {
    CHECK(classify_execution_event("agent-transition") ==
          ExecutionEventScopeClass::kAgentAttributed);
    CHECK(classify_execution_event("execution-progress") ==
          ExecutionEventScopeClass::kExecutionScoped);
    CHECK(classify_execution_event("execution-completed") ==
          ExecutionEventScopeClass::kExecutionScoped);
}

TEST_CASE("an unknown event type is UNCLASSIFIED and is never admitted", "[1712][sse][scope]") {
    // Fail-closed on taxonomy growth: a future publisher that adds a per-agent
    // event type without classifying it here withholds data from a confined
    // operator rather than leaking it. A permissive default would make the
    // omission invisible — which is exactly how the drawer shipped
    // half-confined the first time.
    CHECK(classify_execution_event("agent-secret-leak") == ExecutionEventScopeClass::kUnclassified);
    CHECK_FALSE(execution_event_in_scope(ev("agent-secret-leak", "a1"), "alice", kAdmitAll));
    CHECK_FALSE(execution_event_in_scope(ev(""), "alice", kAdmitAll));
}

TEST_CASE("an agent-attributed event is admitted only when the predicate admits the agent",
          "[1712][sse][scope]") {
    const ResponseScopePredicate only_a1 = [](const std::string&, const std::string& agent_id) {
        return agent_id == "a1";
    };
    CHECK(execution_event_in_scope(ev("agent-transition", "a1"), "alice", only_a1));
    CHECK_FALSE(execution_event_in_scope(ev("agent-transition", "a2"), "alice", only_a1));
}

TEST_CASE("a deny-all predicate (corrupt-rbac simulation) yields zero agent events, not the fleet",
          "[1712][sse][scope]") {
    // `response_agent_in_scope` returns false for EVERY agent when
    // rbac_enforcement_in_effect is true and the store cannot answer. The
    // degraded case must be zero, never "no filter".
    CHECK_FALSE(execution_event_in_scope(ev("agent-transition", "a1"), "alice", kDenyAll));
    CHECK_FALSE(execution_event_in_scope(ev("agent-transition", "a2"), "alice", kDenyAll));
}

TEST_CASE("an agent-attributed event carrying NO agent_id is dropped, not admitted",
          "[1712][sse][scope]") {
    // This is the guard that keeps `ExecutionEventBus::publish`'s defaulted
    // `agent_id` parameter from being a fail-open hole: a publisher that
    // forgets it produces an unattributable per-agent event, and an
    // unattributable per-agent event cannot be shown to be in scope.
    CHECK_FALSE(execution_event_in_scope(ev("agent-transition"), "alice", kAdmitAll));
}

TEST_CASE("execution-scoped frames are admitted — they name no agent", "[1712][sse][scope]") {
    // The two aggregate/lifecycle frames carry the parent execution row's
    // counts and no agent identity. They stay on the stream even under a
    // deny-all predicate, because dropping them would strand the drawer
    // (the terminal frame is what closes the EventSource) while withholding
    // nothing that identifies an agent. The residual aggregate-count
    // disclosure is documented at the top of execution_event_scope.hpp.
    CHECK(execution_event_in_scope(ev("execution-progress"), "alice", kDenyAll));
    CHECK(execution_event_in_scope(ev("execution-completed"), "alice", kDenyAll));
}

TEST_CASE("an admit-all predicate leaves every agent event on the stream", "[1712][sse][scope]") {
    // Without this the rule could be made unconditional-deny and every case
    // above would still pass — the filter must NARROW, never deny by default.
    CHECK(execution_event_in_scope(ev("agent-transition", "a1"), "alice", kAdmitAll));
    CHECK(execution_event_in_scope(ev("agent-transition", "a2"), "bob", kAdmitAll));
}
