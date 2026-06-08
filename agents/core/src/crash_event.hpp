#pragma once

/**
 * crash_event.hpp — map a normalized CrashObservation onto the GuaranteedStateEvent
 * wire proto (Guardian DEX slice 1).
 *
 * Proto-aware: keep this OUT of any TU that includes windows.h / winevt.h (the
 * crash_observer.hpp rationale — protobuf headers and windows.h macros must not
 * share a TU). The Windows collector produces CrashObservation; the agent wiring
 * calls this to build the wire event and emits it through the existing Guardian
 * sink.
 */

#include <string>

#include <yuzu/agent/crash_observer.hpp>

#include "guaranteed_state.pb.h"

namespace yuzu::agent {

/// Reserved sentinel rule_id marking a RULELESS DEX observation (a crash is not
/// tied to any Guardian rule). This sentinel + `event_type` IS the DEX
/// discriminator — there is deliberately no `guard_category`/class field (see the
/// taxonomy decision in memory project-guardian-dex-direction). Future ruleless
/// observations (eventlog, …) reuse the same sentinel; `event_type` carries the
/// specific kind. Mirrors the reserved "__guard__" / "__guardian__" convention.
inline constexpr const char* kObservationRuleSentinel = "__observation__";
inline constexpr const char* kProcessCrashedEventType = "process.crashed";
inline constexpr const char* kProcessGuardType = "process";
/// DEX applies its own experience framing and ignores Guardian severity, and a
/// ruleless row never surfaces in Guardian's rule-centric views — so a fixed,
/// neutral value keeps the `NOT NULL severity` column well-formed without
/// implying Guardian-side urgency. (Server ingest keeps this agent-set value: no
/// rule is found for the sentinel, so the severity-enrich is a no-op.)
inline constexpr const char* kCrashSeverity = "info";

/// Build the wire event for one observed crash. `event_id` is the caller-owned
/// at-least-once dedup key (kept out of here so the mapping stays pure +
/// testable). No `expected_value` (a crash has no desired state); `guard_category`
/// is left UNSET on purpose.
YUZU_EXPORT ::yuzu::guardian::v1::GuaranteedStateEvent
crash_observation_to_event(const CrashObservation& obs, const std::string& event_id);

} // namespace yuzu::agent
