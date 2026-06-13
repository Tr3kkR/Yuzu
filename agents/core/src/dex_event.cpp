#include "dex_event.hpp"

#include <nlohmann/json.hpp>

namespace yuzu::agent {

namespace gpb = ::yuzu::guardian::v1;

std::string signal_detail_json(const SignalObservation& o) {
    // Structured, machine-readable detail for the generic detail_json wire field
    // (route a'). Built with the JSON lib (not hand-rolled) so a subject with
    // quotes/backslashes/Unicode is correctly escaped. UNIFORM core keys — the
    // DEX projection reads these generically for every signal type. Optional
    // fields are emitted only when present so the object stays compact.
    //
    // PRIVACY: by the time an observation reaches here the catalogue extractor
    // has already dropped user content (DNS names, print document names,
    // usernames, image paths) — this builder only ever sees minimized fields.
    nlohmann::json j;
    j["subject"] = o.subject;
    if (!o.reason.empty())
        j["reason"] = o.reason;
    if (!o.symbolic.empty())
        j["symbolic"] = o.symbolic;
    if (!o.component.empty())
        j["component"] = o.component;
    if (o.metric > 0.0)
        j["metric"] = o.metric;
    if (o.pid != 0)
        j["pid"] = o.pid;
    if (!o.kind.empty())
        j["kind"] = o.kind;
    if (!o.platform.empty())
        j["platform"] = o.platform; // OS-neutral; the DEX projection's by-OS column

    // Legacy slice-1 crash keys (PR #1311 transition compat): a server still
    // running the crash-keyed projection reads these; a current server prefers
    // the uniform keys above. Crash-only — new signal types are uniform-only.
    if (o.obs_type == kProcessCrashedEventType) {
        j["process"] = o.subject;
        j["exception_code"] = o.reason;
        if (!o.component.empty())
            j["faulting_module"] = o.component;
    }
    // error_handler_t::replace is defense-in-depth (governance cpp-B1): clip() is
    // now UTF-8-safe, but should any future field ever carry invalid UTF-8, we
    // substitute U+FFFD instead of throwing out of the OS-callback path and
    // silently losing the observation.
    return j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

gpb::GuaranteedStateEvent
signal_observation_to_event(const SignalObservation& obs, const std::string& event_id) {
    gpb::GuaranteedStateEvent ev;
    ev.set_event_id(event_id);
    ev.set_rule_id(kObservationRuleSentinel); // ruleless — half of the discriminator
    ev.set_event_type(obs.obs_type);
    // guard_type = the obs_type's first dot-segment ("process", "service", "os",
    // …). An observation is ruleless, so this is NOT a Guardian rule type — it
    // gives the read model a stable, non-empty field to group by (the slice-1
    // "process" choice, generalized).
    const auto dot = obs.obs_type.find('.');
    ev.set_guard_type(dot == std::string::npos ? obs.obs_type : obs.obs_type.substr(0, dot));
    ev.set_severity(kObservationSeverity);
    ev.set_detected_value(obs.sentence.empty()
                              ? obs.obs_type + (obs.subject.empty() ? "" : " " + obs.subject)
                              : obs.sentence);
    ev.set_detail_json(signal_detail_json(obs)); // structured companion (route a')
    // No expected_value (no desired state). guard_category left UNSET on purpose:
    // ruleless-ness + event_type is the DEX discriminator, not a category field.
    if (obs.timestamp_unix > 0)
        ev.mutable_timestamp()->set_seconds(obs.timestamp_unix);
    if (!obs.platform.empty())
        ev.set_platform(obs.platform);
    return ev;
}

} // namespace yuzu::agent
