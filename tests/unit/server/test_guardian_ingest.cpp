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
using yuzu::server::detail::guardian_event_store_buckets;
using yuzu::server::detail::ingest_guardian_response;
using yuzu::server::detail::kGuardianEventStoreDurationMetric;
using yuzu::server::detail::warm_create_guardian_event_store_metric;

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

// An event that the store rejects with EventInsertOutcome::Error - an embedded NUL in a text
// field (the store never store-truncates one; recipe from test_guaranteed_state_store.cpp). Not
// a ruleless observation, so it never touches the DEX observers.
apb::CommandResponse make_error_event(const std::string& event_id) {
    gpb::GuaranteedStateEvent ev;
    ev.set_event_id(event_id);
    ev.set_rule_id("rule-err");
    ev.set_event_type("service.stopped");
    ev.set_detected_value(std::string("a\0b", 3)); // embedded NUL -> Error (round-trips via proto)
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

TEST_CASE("guardian ingest: event-store histogram splits by outcome status, skips non-store paths",
          "[guardian][ingest][metrics]") {
    // Pins yuzu_server_guardian_event_store_duration_seconds (A+): the timer wraps exactly the
    // insert_event_classified call and observes ONE sample per event under its outcome `status`
    // label. Only redelivered/conflict run the redelivery byte-compare, so the split is
    // load-bearing (a label-less aggregate would shift with the insert/redelivery mix). A frame
    // that never reaches the store (non-"event" action, unparseable payload) is NOT timed, and a
    // null registry is inert.
    GuaranteedStateStore store(":memory:");
    yuzu::MetricsRegistry metrics;
    warm_create_guardian_event_store_metric(metrics); // pin the ladder + boot the series at 0
    const std::string kName = kGuardianEventStoreDurationMetric;
    auto count = [&](const char* status) {
        return metrics.histogram(kName, {{"status", status}}).snapshot().count;
    };

    // Warm-create seeds all four status series at 0, with the CUSTOM ladder (created-with-buckets,
    // not the default) so #2298's sub-ms resolution survives a first-observe-before-warm-create.
    CHECK(count("inserted") == 0);
    CHECK(count("redelivered") == 0);
    CHECK(count("conflict") == 0);
    CHECK(count("error") == 0);
    CHECK(metrics.histogram(kName, {{"status", "inserted"}}).snapshot().boundaries ==
          guardian_event_store_buckets());

    const auto resp = make_observation("__observation__-1", "svc.exe");
    ingest_guardian_response(store, "agent-A", resp, nullptr, nullptr, &metrics); // Inserted
    ingest_guardian_response(store, "agent-A", resp, nullptr, nullptr, &metrics); // Redelivered
    ingest_guardian_response(store, "agent-B", resp, nullptr, nullptr, &metrics); // Conflict
    ingest_guardian_response(store, "agent-C", make_error_event("evt-err"), nullptr, nullptr,
                             &metrics); // Error (embedded NUL)

    // Each store outcome timed exactly once, under its own status series.
    CHECK(count("inserted") == 1);
    CHECK(count("redelivered") == 1);
    CHECK(count("conflict") == 1);
    CHECK(count("error") == 1);
    // A real store op takes non-zero wall time (guards a zero-length/default-constructed span).
    CHECK(metrics.histogram(kName, {{"status", "inserted"}}).snapshot().sum > 0.0);

    // A non-"event" action, and a malformed "event" payload, both return before the store call
    // -> NO observation on any status series.
    apb::CommandResponse status_action;
    status_action.set_action("status");
    ingest_guardian_response(store, "agent-A", status_action, nullptr, nullptr, &metrics);
    apb::CommandResponse malformed;
    malformed.set_action("event");
    malformed.set_payload(std::string("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", 11)); // bad varint
    ingest_guardian_response(store, "agent-A", malformed, nullptr, nullptr, &metrics);
    CHECK(count("inserted") == 1);
    CHECK(count("redelivered") == 1);
    CHECK(count("conflict") == 1);
    CHECK(count("error") == 1);

    // Null registry (the gateway path with no metrics wired) -> inert, no crash, still ingests.
    ingest_guardian_response(store, "agent-D", make_observation("__observation__-2", "svc.exe"),
                             nullptr, nullptr, nullptr);
    CHECK(store.event_count() == 2); // obs-1 (agent-A) + obs-2 (agent-D); conflict/error not stored
    CHECK(count("inserted") == 1);   // unchanged by the null-registry ingest
}
