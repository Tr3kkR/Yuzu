/**
 * test_guardian_ingest.cpp — the shared Guardian side-channel ingest chokepoint
 * (ingest_guardian_response, used by both the direct-agent and gateway paths).
 *
 * Pins the item-7 PR-Sv safety contract: the DEX blast-radius + alert observers fire
 * ONLY on a genuine first insert (`Inserted`) — never on an idempotent redelivery (the
 * durable agent lifecycle journal re-sends on every reconnect) and never on a
 * mismatched-payload collision. A regression that ran the observers on redelivery
 * would manufacture false fleet-wide blast-radius sightings and duplicate routed
 * alerts on every agent reconnect.
 */

#include "guardian_ingest.hpp"

#include "dex_blast_radius.hpp"
#include "guaranteed_state_store.hpp"
#include "guaranteed_state.pb.h"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace yuzu::server;
using yuzu::server::detail::ingest_guardian_response;

namespace {
namespace apb = ::yuzu::agent::v1;
namespace gpb = ::yuzu::guardian::v1;

// A ruleless DEX observation (rule_id == kObservationRuleId) — the only event class
// that feeds the blast-radius / alert observers.
apb::CommandResponse make_observation(const std::string& event_id, const std::string& process) {
    gpb::GuaranteedStateEvent ev;
    ev.set_event_id(event_id);
    ev.set_rule_id(kObservationRuleId);
    ev.set_event_type("process.crashed");
    ev.set_detail_json(std::string(R"({"process":")") + process + R"("})");
    ev.mutable_timestamp()->set_seconds(1718000000);

    apb::CommandResponse resp;
    resp.set_action("event");
    resp.set_payload(ev.SerializeAsString());
    return resp;
}
} // namespace

TEST_CASE("guardian ingest: DEX observers fire once on insert, never on redelivery/collision",
          "[guardian][ingest][redelivery]") {
    GuaranteedStateStore store(":memory:");

    BlastRadiusConfig cfg;
    cfg.min_devices = 1; // fire on the first sighting so a single event is observable
    BlastRadiusDetector blast(cfg);
    int incidents = 0;
    blast.set_on_incident([&](const BlastRadiusIncident&) { ++incidents; });

    const auto resp = make_observation("__observation__-1", "svc.exe");

    // 1) First delivery -> Inserted -> the observer fires exactly once.
    ingest_guardian_response(store, "agent-A", resp, &blast, nullptr);
    CHECK(store.event_count() == 1);
    CHECK(incidents == 1);

    // 2) Exact redelivery (same agent, same payload) -> Redelivered -> the observer
    //    MUST NOT fire again — no false fleet-wide sighting on a reconnect.
    ingest_guardian_response(store, "agent-A", resp, &blast, nullptr);
    CHECK(store.event_count() == 1);
    CHECK(store.events_redelivered_total() == 1);
    CHECK(incidents == 1);

    // 3) Same event_id from a DIFFERENT (connection-bound) agent -> mismatched-field
    //    Conflict -> not written, loud drop metric, and NO observer fire.
    ingest_guardian_response(store, "agent-B", resp, &blast, nullptr);
    CHECK(store.event_count() == 1);
    CHECK(store.events_dropped_total() == 1);
    CHECK(incidents == 1);
}
