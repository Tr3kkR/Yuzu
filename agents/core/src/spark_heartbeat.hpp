#pragma once

/// @file spark_heartbeat.hpp
/// Pure composition of the SparkEngine fleet-telemetry heartbeat tags (ADR-0021
/// Stage-2 rung 1). Extracted from the agent heartbeat lambda so the exact emitted
/// keys + the sparse-emit rule are unit-testable without standing up a heartbeat
/// thread. The keys are pinned to server/core/src/spark_fleet_tags.hpp by
/// tests/unit/server/test_spark_fleet_tags.cpp (the reader side); this header is the
/// writer side.

#include "spark_engine.hpp"    // SparkEngineStats, SparkType
#include "spark_mechanism.hpp" // SparkMechanismStats

#include <yuzu/agent/spark.hpp> // spark_type_token

#include <map>
#include <string>

namespace yuzu::agent {

/// Populate `tags` with the spark fleet telemetry. `TagMap` is any map with a
/// string `operator[]` (the protobuf status_tags map in production, std::map in
/// tests). SPARSE: a counter tag is omitted when 0 (fleet-scale, and every counter
/// is 0 at rung 1), so a quiescent agent ships only the two always-present
/// capability keys — `yuzu.spark_running` (the fleet reporting denominator) and
/// `yuzu.spark_mechs` (the CSV of registered mechanism types). The caller gates on
/// `!spark_disable && engine-present` and omits ALL tags when the engine is off.
template <typename TagMap>
void emit_spark_heartbeat_tags(TagMap& tags, const SparkEngineStats& ss,
                               const std::map<SparkType, SparkMechanismStats>& by_type) {
    tags["yuzu.spark_running"] = "1";
    // Capability: the registered mechanism types (map keys) as a CSV.
    std::string mechs;
    for (const auto& [type, ms] : by_type) {
        if (!mechs.empty())
            mechs += ',';
        mechs += spark_type_token(type);
    }
    tags["yuzu.spark_mechs"] = mechs;
    // Engine-level counters (sparse).
    if (ss.armed_faulted > 0)
        tags["yuzu.spark_armed_faulted"] = std::to_string(ss.armed_faulted);
    if (ss.watch_faults_total > 0)
        tags["yuzu.spark_watch_faults"] = std::to_string(ss.watch_faults_total);
    if (ss.queued_dropped_total > 0)
        tags["yuzu.spark_queued_dropped"] = std::to_string(ss.queued_dropped_total);
    if (ss.consumer_errors_total > 0)
        tags["yuzu.spark_consumer_errors"] = std::to_string(ss.consumer_errors_total);
    // Per-mechanism-type health counters (sparse). Key = "yuzu.spark_<type>_<metric>",
    // composed identically to spark_type_metric_tag() in spark_fleet_tags.hpp.
    for (const auto& [type, ms] : by_type) {
        const std::string p = std::string("yuzu.spark_") + spark_type_token(type) + "_";
        if (ms.watch_rejected_total > 0)
            tags[p + "watch_rejected"] = std::to_string(ms.watch_rejected_total);
        if (ms.quarantined_total > 0)
            tags[p + "quarantined"] = std::to_string(ms.quarantined_total);
        if (ms.slow_op_total > 0)
            tags[p + "slow_op"] = std::to_string(ms.slow_op_total);
    }
}

} // namespace yuzu::agent
