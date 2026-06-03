/**
 * test_heartbeat_ingestion.cpp — Guardian heartbeat-reconcile seam (#1209 M5 +
 * hardening). Pins the `yuzu.guardian_generation` tag → reconcile-callback path:
 * a valid generation fires the callback with the parsed value; a malformed,
 * trailing-garbage, or absent tag does NOT (the from_chars ptr==end strictness).
 *
 * The reconcile path in ingest() touches neither the health store, the fleet
 * topology store, nor the registry, so all three can be null / default — the
 * callback is the only observable.
 */

#include "heartbeat_ingestion.hpp"

#include "agent_registry.hpp"
#include "event_bus.hpp"

#include "agent.pb.h"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <string_view>

using yuzu::server::HeartbeatIngestion;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::EventBus;

namespace {

struct ReconcileCapture {
    bool called{false};
    std::string agent_id;
    std::uint64_t generation{0};
};

::yuzu::agent::v1::HeartbeatRequest make_hb(const std::string& gen_value, bool set_tag = true) {
    ::yuzu::agent::v1::HeartbeatRequest hb;
    if (set_tag)
        (*hb.mutable_status_tags())["yuzu.guardian_generation"] = gen_value;
    return hb;
}

} // namespace

TEST_CASE("HeartbeatIngestion: reconcile fires on a valid generation tag",
          "[heartbeat_ingestion][guardian]") {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    HeartbeatIngestion ingestion{registry, /*health=*/nullptr, /*fleet_topology=*/nullptr,
                                 &metrics};

    ReconcileCapture cap;
    ingestion.set_guardian_reconcile_fn([&](std::string_view aid, std::uint64_t gen) {
        cap.called = true;
        cap.agent_id = std::string(aid);
        cap.generation = gen;
    });

    ingestion.ingest(make_hb("42"), "agent-x", "direct");

    REQUIRE(cap.called);
    CHECK(cap.agent_id == "agent-x");
    CHECK(cap.generation == 42u);
}

TEST_CASE("HeartbeatIngestion: reconcile NOT fired on malformed / partial / absent tag",
          "[heartbeat_ingestion][guardian]") {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    HeartbeatIngestion ingestion{registry, nullptr, nullptr, &metrics};

    SECTION("non-numeric") {
        bool called = false;
        ingestion.set_guardian_reconcile_fn(
            [&](std::string_view, std::uint64_t) { called = true; });
        ingestion.ingest(make_hb("abc"), "agent-x", "direct");
        CHECK_FALSE(called);
    }
    SECTION("trailing garbage — whole tag must parse (ptr==end)") {
        bool called = false;
        ingestion.set_guardian_reconcile_fn(
            [&](std::string_view, std::uint64_t) { called = true; });
        ingestion.ingest(make_hb("123abc"), "agent-x", "direct");
        CHECK_FALSE(called);
    }
    SECTION("absent tag") {
        bool called = false;
        ingestion.set_guardian_reconcile_fn(
            [&](std::string_view, std::uint64_t) { called = true; });
        ingestion.ingest(make_hb("", /*set_tag=*/false), "agent-x", "direct");
        CHECK_FALSE(called);
    }
}

TEST_CASE("HeartbeatIngestion: no reconcile callback set is a no-op",
          "[heartbeat_ingestion][guardian]") {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    HeartbeatIngestion ingestion{registry, nullptr, nullptr, &metrics};
    // No set_guardian_reconcile_fn — must not crash even with a valid tag.
    ingestion.ingest(make_hb("7"), "agent-x", "direct");
    SUCCEED();
}
