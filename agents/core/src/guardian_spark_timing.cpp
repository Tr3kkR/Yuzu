#include "guardian_spark_timing.hpp"

#include <format>

namespace yuzu::agent {

namespace {

/// -1 sentinel for every trigger sub-field when a pass has no attributable Spark event
/// (Convergence reason). Kept as a single named constant so every sentinel write agrees.
constexpr std::int64_t kAbsentTriggerSentinel = -1;

const char* domain_name(OutboxDomain d) {
    switch (d) {
    case OutboxDomain::Compliance:
        return "compliance";
    case OutboxDomain::Health:
        return "health";
    case OutboxDomain::Lifecycle:
        return "lifecycle";
    }
    return "unknown"; // unreachable if the switch above is kept exhaustive
}

} // namespace

std::string format_eval_timing_line(const EvalTimingRecord& r) {
    std::string line = std::format(
        "Guardian T_detect event_id={} domain={} detect_wall_ns={} detect_mono_ns={} "
        "accepted={} fire_wall_ns={} fire_mono_ns={} trigger_present={}",
        r.event_id, domain_name(r.domain), r.detect_wall_ns, r.detect_mono_ns,
        r.accepted ? 1 : 0, r.fire_wall_ns, r.fire_mono_ns, r.trigger.has_value() ? 1 : 0);
    if (r.trigger) {
        line += std::format(
            " mechanism_wall_ns={} handler_wall_ns={} handler_mono_ns={} seq={}",
            r.trigger->mechanism_wall_ns, r.trigger->handler_wall_ns,
            r.trigger->handler_mono_ns, r.trigger->seq);
    } else {
        line += std::format(
            " mechanism_wall_ns={} handler_wall_ns={} handler_mono_ns={} seq={}",
            kAbsentTriggerSentinel, kAbsentTriggerSentinel, kAbsentTriggerSentinel,
            kAbsentTriggerSentinel);
    }
    return line;
}

std::string format_send_timing_line(const SendTimingRecord& r) {
    return std::format("Guardian T_wire event_id={} sent={} wire_wall_ns={}", r.event_id,
                        r.sent ? 1 : 0, r.wire_wall_ns);
}

} // namespace yuzu::agent
