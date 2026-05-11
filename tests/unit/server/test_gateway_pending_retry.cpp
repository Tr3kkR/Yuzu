/**
 * test_gateway_pending_retry.cpp — D.1 retry semantics for the lifted
 * `forward_gateway_pending()` (#376 PR 1c-5).
 *
 * The detached SendCommand thread maps gRPC `UNAVAILABLE` failures to
 * `transport::StatusCode::Unavailable` and calls
 * `AgentRegistry::reenqueue_gateway_pending(gp)` to re-queue the command
 * for the next dispatch tick. Non-`Unavailable` failures drop. The 3-strike
 * cap (preserved from the pre-PR-1c-5 inline-retry semantics) is enforced
 * inside `reenqueue_gateway_pending`. These pins guard that contract.
 */

#include "agent_registry.hpp"

#include <catch2/catch_test_macros.hpp>

#include "event_bus.hpp"
#include <yuzu/metrics.hpp>

namespace {

namespace apb = ::yuzu::agent::v1;

using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::EventBus;

struct Harness {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};

    static AgentRegistry::GatewayPendingCmd make_cmd(const std::string& agent_id,
                                                     const std::string& cmd_id,
                                                     int attempts = 0) {
        AgentRegistry::GatewayPendingCmd gp;
        gp.agent_id = agent_id;
        gp.cmd.set_command_id(cmd_id);
        gp.attempts = attempts;
        return gp;
    }
};

} // namespace

TEST_CASE("GatewayPendingCmd::attempts defaults to zero", "[gateway][retry]") {
    AgentRegistry::GatewayPendingCmd gp;
    REQUIRE(gp.attempts == 0);
}

TEST_CASE("reenqueue_gateway_pending increments attempts and requeues",
          "[gateway][retry]") {
    Harness h;
    auto gp = Harness::make_cmd("agent-A", "cmd-1");
    REQUIRE(gp.attempts == 0);

    bool requeued = h.registry.reenqueue_gateway_pending(std::move(gp));
    REQUIRE(requeued);

    auto drained = h.registry.drain_gateway_pending();
    REQUIRE(drained.size() == 1);
    REQUIRE(drained[0].agent_id == "agent-A");
    REQUIRE(drained[0].cmd.command_id() == "cmd-1");
    REQUIRE(drained[0].attempts == 1);  // ++ before re-queue
}

TEST_CASE("reenqueue_gateway_pending drops at 3-strike cap", "[gateway][retry]") {
    Harness h;

    // Start at attempts == 2 (representing two prior failures).
    auto gp = Harness::make_cmd("agent-B", "cmd-2", /*attempts=*/2);
    bool requeued = h.registry.reenqueue_gateway_pending(std::move(gp));

    // ++ brings attempts to 3 — at-cap; drop, do NOT re-queue.
    REQUIRE_FALSE(requeued);

    auto drained = h.registry.drain_gateway_pending();
    REQUIRE(drained.empty());
}

TEST_CASE("reenqueue_gateway_pending full sequence — 2 retries then drop",
          "[gateway][retry]") {
    Harness h;

    // Attempt 1 (attempts goes 0 → 1): requeue.
    REQUIRE(h.registry.reenqueue_gateway_pending(Harness::make_cmd("a", "c")));
    {
        auto d = h.registry.drain_gateway_pending();
        REQUIRE(d.size() == 1);
        REQUIRE(d[0].attempts == 1);
        // Attempt 2 (attempts goes 1 → 2): requeue.
        REQUIRE(h.registry.reenqueue_gateway_pending(std::move(d[0])));
    }
    {
        auto d = h.registry.drain_gateway_pending();
        REQUIRE(d.size() == 1);
        REQUIRE(d[0].attempts == 2);
        // Attempt 3 (attempts goes 2 → 3): cap-hit, drop.
        REQUIRE_FALSE(h.registry.reenqueue_gateway_pending(std::move(d[0])));
    }
    REQUIRE(h.registry.drain_gateway_pending().empty());
}

TEST_CASE("reenqueue_gateway_pending preserves cmd payload across requeues",
          "[gateway][retry]") {
    Harness h;
    auto gp = Harness::make_cmd("agent-pluto", "cmd-orbital");
    gp.cmd.set_action("inventory.os_facts");

    REQUIRE(h.registry.reenqueue_gateway_pending(std::move(gp)));
    auto d = h.registry.drain_gateway_pending();
    REQUIRE(d.size() == 1);
    REQUIRE(d[0].agent_id == "agent-pluto");
    REQUIRE(d[0].cmd.command_id() == "cmd-orbital");
    REQUIRE(d[0].cmd.action() == "inventory.os_facts");
    REQUIRE(d[0].attempts == 1);
}
