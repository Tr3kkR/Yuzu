#include "crash_event.hpp"

#include <format>

namespace yuzu::agent {

namespace gpb = ::yuzu::guardian::v1;

namespace {

/// Compact, machine-greppable crash descriptor packed into `detected_value`
/// (slice 1 adds no proto fields — richer structure is a later slice). e.g.
///   "notepad.exe pid=1234 code=0xC0000005 ACCESS_VIOLATION module=ntdll.dll"
std::string format_detected(const CrashObservation& o) {
    std::string s = std::format("{} pid={} code=0x{:08X}",
                                o.process_name.empty() ? "<unknown>" : o.process_name, o.pid,
                                o.termination.code);
    if (!o.termination.symbolic.empty())
        s += " " + o.termination.symbolic;
    if (!o.faulting_module.empty())
        s += " module=" + o.faulting_module;
    return s;
}

} // namespace

gpb::GuaranteedStateEvent
crash_observation_to_event(const CrashObservation& obs, const std::string& event_id) {
    gpb::GuaranteedStateEvent ev;
    ev.set_event_id(event_id);
    ev.set_rule_id(kObservationRuleSentinel); // ruleless — half of the discriminator
    ev.set_event_type(kProcessCrashedEventType);
    ev.set_guard_type(kProcessGuardType);
    ev.set_severity(kCrashSeverity);
    ev.set_detected_value(format_detected(obs));
    // No expected_value (no desired state). guard_category left UNSET on purpose:
    // ruleless-ness + event_type is the DEX discriminator, not a category field.
    if (obs.timestamp_unix > 0)
        ev.mutable_timestamp()->set_seconds(obs.timestamp_unix);
    if (!obs.platform.empty())
        ev.set_platform(obs.platform);
    return ev;
}

} // namespace yuzu::agent
