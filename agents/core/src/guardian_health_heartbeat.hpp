#pragma once

/// @file guardian_health_heartbeat.hpp
/// Writer side of the Guardian health-stream fleet telemetry (M1). Extracted from the agent
/// heartbeat lambda so the exact emitted key + the sparse-emit rule are unit-testable without a
/// heartbeat thread, and so the key is PINNED to the (future #2298) server-side rollup reader by
/// a unit test - a one-character drift would otherwise silently produce a zero fleet gauge with
/// nothing to catch it. Mirrors guardian_journal_heartbeat.hpp.
///
/// SPARSE: the counter is 0 on a healthy / inert (prefer_spark=false) agent, so the tag is
/// emitted ONLY when non-zero, keeping the "absent == nothing to report" reading honest.

#include <cstdint>
#include <string>

namespace yuzu::agent {

/// Heartbeat status_tag key for the edge-suppressed guard.unhealthy count (M1): the number of
/// convergence re-evals of a still-errored rule whose repeat guard.unhealthy was NOT re-emitted
/// (the flood guard). Shared by the emitter below and the pinning test; the #2298 Prometheus
/// rollup reader MUST key on this exact string.
inline constexpr char kGuardianUnhealthySuppressedTag[] = "yuzu.guardian_unhealthy_suppressed";

/// Populate `tags` with the (sparse) Guardian health telemetry. `TagMap` is any map with a
/// string `operator[]` - the protobuf status_tags map in production, std::map in tests.
template <typename TagMap>
void emit_guardian_health_heartbeat_tags(TagMap& tags, std::uint64_t unhealthy_suppressed) {
    if (unhealthy_suppressed != 0)
        tags[kGuardianUnhealthySuppressedTag] = std::to_string(unhealthy_suppressed);
}

} // namespace yuzu::agent
