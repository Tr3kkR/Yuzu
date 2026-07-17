#include "guardian_spark_send.hpp"

#include <cstdint>
#include <string>

namespace yuzu::agent {

namespace gpb = ::yuzu::guardian::v1;

namespace {

constexpr std::int64_t kNsPerSec = 1'000'000'000;

// Fields common to every domain. event_id and the timestamp come verbatim from the
// entry: event_id is the wire-idempotency key the runtime already made globally
// unique (agent_id + boot nonce folded in, #1307), and enqueued_ns is the wall-clock
// nanoseconds-since-epoch stamp fixed at enqueue (NOT a fresh now() at send time -
// the send may be a retry minutes later, and the observation time is when it was
// produced).
void set_common(gpb::GuaranteedStateEvent& ev, const OutboxEntry& e, std::string_view platform) {
    ev.set_event_id(e.event_id);
    ev.set_rule_id(e.rule_id);
    ev.set_guard_category("event");
    ev.mutable_timestamp()->set_seconds(e.enqueued_ns / kNsPerSec);
    ev.mutable_timestamp()->set_nanos(static_cast<std::int32_t>(e.enqueued_ns % kNsPerSec));
    ev.set_platform(std::string(platform));
}

} // namespace

gpb::GuaranteedStateEvent guardian_outbox_entry_to_event(const OutboxEntry& e,
                                                         std::string_view platform) {
    gpb::GuaranteedStateEvent ev;
    set_common(ev, e, platform);

    switch (e.domain) {
    case OutboxDomain::Compliance: {
        // Mirrors the legacy GuardianEngine::emit_guard_event mapping so the spark
        // and legacy paths produce byte-equivalent compliance events - EXCEPT the
        // event_id/timestamp, which the outbox fixes at enqueue rather than at send.
        const GuardDrift& d = e.drift;
        ev.set_rule_name(d.rule_name);
        ev.set_guard_type(d.guard_type);
        ev.set_detected_value(d.detected_value);
        ev.set_expected_value(d.expected_value);
        ev.set_detection_latency_us(d.detection_latency_us);
        if (d.compliant) {
            // A compliant edge is never a write-back: no remediation fields.
            ev.set_event_type("guard.compliant");
        } else if (d.remediation_attempted) {
            ev.set_remediation_action(d.remediation_action);
            ev.set_remediation_success(d.remediation_success);
            ev.set_remediation_latency_us(d.remediation_latency_us);
            ev.set_event_type(d.remediation_success ? "drift.remediated" : "remediation.failed");
        } else {
            ev.set_event_type("drift.detected");
        }
        // drift_rate carries the count of additional detections the sink debounce
        // collapsed into this one event (0 = sole detection in its window).
        if (d.collapsed_count > 0)
            ev.set_drift_rate(static_cast<double>(d.collapsed_count));
        break;
    }
    case OutboxDomain::Health:
        // healthy = the watch recovered (Unknown -> Known); !healthy = a read error
        // left the guard unable to evaluate. Separate from compliance state.
        ev.set_event_type(e.healthy ? "guard.healthy" : "guard.unhealthy");
        if (!e.healthy && !e.health_detail.empty())
            ev.set_detail_json(e.health_detail);
        break;
    case OutboxDomain::Lifecycle:
        // lifecycle_kind is one of "armed" | "disarmed" | "errored"; the wire token
        // is "guard." + kind. (Routed here only via GuardianLifecycleLog, whose drain
        // shares this send path - GuardianOutbox itself rejects Lifecycle entries.)
        ev.set_event_type("guard." + e.lifecycle_kind);
        break;
    }
    return ev;
}

} // namespace yuzu::agent
