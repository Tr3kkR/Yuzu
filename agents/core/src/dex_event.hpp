#pragma once

/**
 * dex_event.hpp — map a normalized SignalObservation onto the GuaranteedStateEvent
 * wire proto (Guardian DEX, multi-signal).
 *
 * Proto-aware: keep this OUT of any TU that includes windows.h / winevt.h (the
 * dex_observer.hpp rationale — protobuf headers and windows.h macros must not
 * share a TU). The Windows engine produces SignalObservation via the catalogue;
 * the agent wiring calls this to build the wire event and emits it through the
 * existing Guardian sink. NO proto change was needed for multi-signal: the
 * `detail_json` field is keyed by event_type by design (route a'), so new signal
 * types ride the frozen wire.
 */

#include <string>

#include <yuzu/agent/dex_signal_catalog.hpp>

#include "guaranteed_state.pb.h"

namespace yuzu::agent {

/// Reserved sentinel rule_id marking a RULELESS DEX observation (a signal is not
/// tied to any Guardian rule). This sentinel + `event_type` IS the DEX
/// discriminator — there is deliberately no `guard_category`/class field (see the
/// taxonomy decision in memory project-guardian-dex-direction). Every catalogued
/// signal type reuses the same sentinel; `event_type` (= obs_type) carries the
/// specific kind. Mirrors the reserved "__guard__" / "__guardian__" convention.
inline constexpr const char* kObservationRuleSentinel = "__observation__";
inline constexpr const char* kProcessCrashedEventType = "process.crashed";
/// DEX applies its own experience framing and ignores Guardian severity, and a
/// ruleless row never surfaces in Guardian's rule-centric views — so a fixed,
/// neutral value keeps the `NOT NULL severity` column well-formed without
/// implying Guardian-side urgency. (Server ingest keeps this agent-set value: no
/// rule is found for the sentinel, so the severity-enrich is a no-op.)
inline constexpr const char* kObservationSeverity = "info";

/// Build the structured `detail_json` payload (route a') for one signal: a JSON
/// object with the UNIFORM core keys {subject, reason, symbolic?, component?,
/// metric?, pid?, kind?, platform} the server projection reads generically —
/// adding signal #21 needs ZERO server change. For process.crashed the legacy
/// slice-1 keys (process / exception_code / faulting_module) are ALSO emitted so
/// a server running the slice-1 projection still projects crashes from an
/// upgraded agent (PR #1311 compat; remove once that transition window closes).
/// Pure + cross-platform so the escaping is unit-testable off Windows; built
/// with the JSON lib so nasty subjects are escaped correctly.
YUZU_EXPORT std::string signal_detail_json(const SignalObservation& obs);

/// Build the wire event for one observed signal. `event_id` is the caller-owned
/// at-least-once dedup key (kept out of here so the mapping stays pure +
/// testable). No `expected_value` (an observation has no desired state);
/// `guard_category` is left UNSET on purpose. `guard_type` is the obs_type's
/// first dot-segment ("process", "service", "os", …) — a stable, non-empty
/// grouping field for the read model. Sets both the human-readable
/// `detected_value` (the extractor's sentence) and the structured `detail_json`.
YUZU_EXPORT ::yuzu::guardian::v1::GuaranteedStateEvent
signal_observation_to_event(const SignalObservation& obs, const std::string& event_id);

} // namespace yuzu::agent
