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

#include <yuzu/metrics.hpp>

#include "dex_alert_router.hpp"
#include "dex_blast_radius.hpp"
#include "guaranteed_state_store.hpp"
#include "guaranteed_state.pb.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <unordered_set>

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

    // BOTH observers are wired (the two are gated together; a null router would leave the
    // alert-router half of the gating unproven — qa-S1). The router fires per routed
    // sighting, so on_alert firing is itself the "observe() was called" probe.
    DexAlertRouter router;
    router.set_routes(std::unordered_set<std::string>{"process.crashed"});
    int alerts = 0;
    router.set_on_alert([&](const RoutedSignalAlert&) { ++alerts; });

    const auto resp = make_observation("__observation__-1", "svc.exe");

    // 1) First delivery -> Inserted -> BOTH observers fire exactly once.
    ingest_guardian_response(store, "agent-A", resp, &blast, &router);
    CHECK(store.event_count() == 1);
    CHECK(incidents == 1);
    CHECK(alerts == 1);

    // 2) Exact redelivery (same agent, same payload) -> Redelivered -> NEITHER observer
    //    fires again — no false fleet-wide sighting / duplicate routed alert on reconnect.
    ingest_guardian_response(store, "agent-A", resp, &blast, &router);
    CHECK(store.event_count() == 1);
    CHECK(store.events_redelivered_total() == 1);
    CHECK(incidents == 1);
    CHECK(alerts == 1);

    // 3) Same event_id from a DIFFERENT (connection-bound) agent -> mismatched-field
    //    Conflict -> not written, loud drop metric, and NEITHER observer fires.
    ingest_guardian_response(store, "agent-B", resp, &blast, &router);
    CHECK(store.event_count() == 1);
    CHECK(store.events_dropped_total() == 1);
    CHECK(incidents == 1);
    CHECK(alerts == 1);
}

TEST_CASE("guardian ingest: latency histogram observes every store outcome, skips non-events",
          "[guardian][ingest][metrics]") {
    // Pins the yuzu_server_guardian_ingest_duration_seconds placement (A / #2298 warm-up):
    // the RAII timer sits AFTER the parse guard, so every event that reaches the store —
    // Inserted, Redelivered, AND Conflict — is timed exactly once, while a fast pre-store
    // reject (non-"event" action, unparseable frame) is NOT timed and a null registry is
    // inert. The store-compare latency this captures is the signal a future off-write-path
    // compare (#2298) would be judged against, so an under-count here would hide it.
    GuaranteedStateStore store(":memory:");
    yuzu::MetricsRegistry metrics;
    const std::string kName = "yuzu_server_guardian_ingest_duration_seconds";

    const auto resp = make_observation("__observation__-1", "svc.exe");

    // Inserted -> Redelivered -> Conflict: three store outcomes, three observations.
    ingest_guardian_response(store, "agent-A", resp, nullptr, nullptr, &metrics); // Inserted
    ingest_guardian_response(store, "agent-A", resp, nullptr, nullptr, &metrics); // Redelivered
    ingest_guardian_response(store, "agent-B", resp, nullptr, nullptr, &metrics); // Conflict
    CHECK(metrics.histogram(kName).snapshot().count == 3);
    // A real ingest takes non-zero wall time, so the sum is strictly positive (guards
    // against a placement that observed a zero-length or default-constructed duration).
    CHECK(metrics.histogram(kName).snapshot().sum > 0.0);

    // A non-"event" __guard__ action is dropped before any store work -> NOT timed.
    apb::CommandResponse status;
    status.set_action("status");
    ingest_guardian_response(store, "agent-A", status, nullptr, nullptr, &metrics);
    CHECK(metrics.histogram(kName).snapshot().count == 3);

    // Null registry (the gateway path with no metrics wired) -> inert, no crash, still ingests.
    ingest_guardian_response(store, "agent-C", make_observation("__observation__-2", "svc.exe"),
                             nullptr, nullptr, nullptr);
    CHECK(store.event_count() == 2);
    CHECK(metrics.histogram(kName).snapshot().count == 3);
}
