#include "guardian_ingest.hpp"

#include <chrono>
#include <cstdint>
#include <ctime>

#include <spdlog/spdlog.h>

#include "dex_alert_router.hpp"
#include "dex_blast_radius.hpp"
#include "guaranteed_state.pb.h"
#include "guaranteed_state_store.hpp"

namespace yuzu::server::detail {

namespace {
// google.protobuf.Timestamp seconds → ISO-8601 UTC; falls back to "now" when
// unset (an agent that didn't stamp the event, or a 0 default). Mirrors
// iso_now() in rest_api_v1.cpp. Moved here from agent_service_impl.cpp when the
// Guardian ingest was factored out (Half B) — it had no other caller there.
std::string ts_to_iso8601(std::int64_t epoch_seconds) {
    std::time_t t = epoch_seconds > 0
                        ? static_cast<std::time_t>(epoch_seconds)
                        : std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string(buf);
}
} // namespace

void ingest_guardian_response(GuaranteedStateStore& store, const std::string& agent_id,
                              const pb::CommandResponse& resp,
                              BlastRadiusDetector* blast_radius, DexAlertRouter* alert_router) {
    if (resp.action() == "event") {
        ::yuzu::guardian::v1::GuaranteedStateEvent ev;
        if (!ev.ParseFromString(resp.payload())) {
            spdlog::warn("Guardian: failed to parse GuaranteedStateEvent from agent {}", agent_id);
            return;
        }
        GuaranteedStateEventRow ev_row;
        ev_row.event_id = ev.event_id();
        ev_row.rule_id = ev.rule_id();
        ev_row.agent_id = agent_id; // caller-supplied (cert-bound or gateway-asserted)
        ev_row.event_type = ev.event_type();
        ev_row.severity = ev.severity();
        ev_row.guard_type = ev.guard_type();
        ev_row.guard_category = ev.guard_category();
        ev_row.detected_value = ev.detected_value();
        ev_row.expected_value = ev.expected_value();
        ev_row.detail_json = ev.detail_json(); // structured companion (route a'); "" for plain drift
        // Ingest-boundary size cap (governance/adversarial-review F6): a legit
        // detail_json is well under 1 KiB; a compromised enrolled agent could ship
        // a multi-MB blob to bloat the events column and burn JSON-parse cost on the
        // ingest thread in-txn. Drop an over-cap blob (the event is still recorded;
        // the DEX projection degrades to empty fields — degrade-don't-destroy). 16
        // KiB is generous headroom over any real signal payload.
        constexpr std::size_t kMaxDetailJson = 16 * 1024;
        if (ev_row.detail_json.size() > kMaxDetailJson) {
            spdlog::warn("Guardian: dropping oversized detail_json ({} bytes) from agent {} "
                         "event {} (cap {})",
                         ev_row.detail_json.size(), agent_id, ev_row.event_id, kMaxDetailJson);
            ev_row.detail_json.clear();
        }

        ev_row.remediation_action = ev.remediation_action();
        ev_row.remediation_success = ev.remediation_success();
        ev_row.detection_latency_us = static_cast<int64_t>(ev.detection_latency_us());
        ev_row.remediation_latency_us = static_cast<int64_t>(ev.remediation_latency_us());
        ev_row.timestamp = ts_to_iso8601(ev.timestamp().seconds());
        // Enrich severity from the rule store (contract decision 4) — the agent
        // isn't pushed severity. Fall back to the event's own value, then
        // "unknown" for an already-deleted rule.
        if (auto rule = store.get_rule(ev_row.rule_id); rule)
            ev_row.severity = rule->severity;
        if (ev_row.severity.empty())
            ev_row.severity = "unknown";
        if (auto r = store.insert_event(ev_row); !r) {
            spdlog::warn("Guardian: insert_event failed (agent={}, rule={}): {}", agent_id,
                         ev_row.rule_id, r.error());
            return;
        }
        // Fleet-wide incident detection — RULELESS observations only, and only
        // AFTER the event committed (a rolled-back duplicate must never count a
        // device twice). Uses the SHARED kObservationRuleId constant, same one
        // is_reserved_rule_id keys on, so the feed gate and the projection guard
        // can't desync (gov architect/consistency). The window uses server
        // receipt time, not the agent's clock — "blast radius" is about
        // simultaneity as the FLEET experiences it, and a skewed agent clock
        // must not smear the window.
        if ((blast_radius || alert_router) && ev_row.rule_id == kObservationRuleId) {
            const std::int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                                         std::chrono::system_clock::now().time_since_epoch())
                                         .count();
            const auto subject = blast_subject_from_detail(ev_row.detail_json);
            if (blast_radius)
                blast_radius->observe(ev_row.event_type, subject, agent_id, now);
            // F1: operator-routed per-signal alerts — same chokepoint, same
            // both-paths coverage, same clamped subject (sec-M1).
            if (alert_router)
                alert_router->observe(ev_row.event_type, subject, agent_id, now);
        }
        return;
    }
    // action "status" ingest lands with the status slice; any other action is
    // logged and dropped — the "__guard__" channel is generic, so a future
    // status message (or a malformed one) must not crash this path. Never
    // enters the response store / executions drawer.
    spdlog::debug("Guardian: ignoring __guard__ action '{}' from agent {} (only 'event' ingested "
                  "in A1)",
                  resp.action(), agent_id);
}

} // namespace yuzu::server::detail
