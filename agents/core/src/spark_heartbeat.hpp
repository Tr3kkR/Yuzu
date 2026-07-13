#pragma once

/// @file spark_heartbeat.hpp
/// Pure composition of the SparkEngine fleet-telemetry heartbeat tags (ADR-0021
/// Stage-2 rung 1). Extracted from the agent heartbeat lambda so the exact emitted
/// keys + the sparse-emit rule are unit-testable without standing up a heartbeat
/// thread. The keys are pinned to server/core/src/spark_fleet_tags.hpp by
/// tests/unit/server/test_spark_fleet_tags.cpp (the reader side); this header is the
/// writer side.
///
/// ── THE FOUR POSTURES ────────────────────────────────────────────────────────────
/// A spark-capable agent is always in exactly one of these, and each is DISTINGUISHABLE
/// on the wire. That distinguishability is the point of rung 1 — an engine that failed
/// to boot must not look like one that was never asked to (governance Gate-4
/// consistency + UP-10):
///
///   RUNNING   yuzu.spark_running=1, yuzu.spark_mechs=<CSV>, sparse counters
///   FAILED    yuzu.spark_running=0                       (enabled, but boot threw)
///   DISABLED  yuzu.spark_running=0, yuzu.spark_disabled=1  (--spark-disable)
///   ABSENT    no yuzu.spark_* key at all       (a pre-rung-1 agent, or a dead one)
///
/// Before this, FAILED emitted nothing — byte-identical to DISABLED and to ABSENT. A
/// fleet where spark failed to boot on 30% of endpoints was therefore *unobservable*,
/// which defeats rung 1's stated purpose ("prove the engine runs and reports at rest").
/// The DEX sibling already got this right: it emits `yuzu.dex_observer_armed = "0"`
/// when enabled-but-deaf rather than going quiet.

#include "spark_engine.hpp"    // SparkEngineStats, SparkType
#include "spark_mechanism.hpp" // SparkMechanismStats

#include <yuzu/agent/spark.hpp> // spark_type_token

#include <map>
#include <string>

namespace yuzu::agent {

/// FAILED / DISABLED: the engine is not running, so there is nothing to report but the
/// fact itself. `disabled` distinguishes the deliberate opt-out from a boot failure.
template <typename TagMap>
void emit_spark_absent_tags(TagMap& tags, bool disabled) {
    tags["yuzu.spark_running"] = "0";
    if (disabled)
        tags["yuzu.spark_disabled"] = "1";
}

/// RUNNING: populate `tags` with the spark fleet telemetry. `TagMap` is any map with a
/// string `operator[]` (the protobuf status_tags map in production, std::map in tests).
///
/// `running` MUST come from `SparkEngine::is_running()` — never from "the pointer is
/// non-null". After Agent::stop() calls spark_engine_->stop() the pointer is still
/// non-null, so a hardcoded "1" would ship a healthy-looking capability report from a
/// STOPPED engine (governance Gate-4 UP-4).
///
/// SPARSE: a counter tag is omitted when 0 (fleet-scale, and every counter is 0 at
/// rung 1), so a quiescent agent ships only the two always-present capability keys.
///
/// The `yuzu.spark_mechs` CSV lists only mechanisms that are registered AND FUNCTIONAL.
/// An inert mechanism — one that started but could not bind its OS facility (no systemd
/// system bus in a container, OpenSCManager denied, IOCP creation failed) — is EXCLUDED,
/// because every watch() on it will be refused. Listing it would advertise a capability
/// the agent cannot honour: "looks healthy, can detect nothing" (governance Gate-3
/// cross-platform + Gate-6 sre, reached independently).
///
/// HOW AN INERT MECHANISM IS OBSERVED, precisely. Inertness suppresses the CAPABILITY CLAIM
/// (the CSV above), not the telemetry: the per-type counter loop below does NOT skip inert
/// mechanisms, so a non-zero counter on one WOULD be reported. In practice none ever is —
/// the Registry and Service mechanisms track none of those counters (they are File-mechanism
/// concepts, #1979/#1980/#1982), so their stats are all-zero and the sparse rule drops every
/// tag. So TODAY an inert mechanism emits nothing of its own, but that is a property of which
/// counters exist, NOT a rule the code enforces — do not rely on it.
///
/// An inert mechanism is therefore visible as a CAPABILITY GAP on the server:
/// `yuzu_fleet_spark_reporting{os}` exceeds the sum of
/// `yuzu_fleet_spark_mechanisms{os,mechanism}` for that OS. That is the query to reach for;
/// it is documented in `docs/user-manual/metrics.md`.
///
/// (Two earlier versions of this comment contradicted each other here — one claimed inert
/// mechanisms "still report their counters", the next that they "emit NOTHING of their own"
/// as an invariant. The reconciled statement above is what the code actually does.
/// governance Gate-8 round 7 consistency N-3.)
template <typename TagMap>
void emit_spark_heartbeat_tags(TagMap& tags, bool running, const SparkEngineStats& ss,
                               const std::map<SparkType, SparkMechanismStats>& by_type) {
    if (!running) {
        // CONSTRUCTED BUT NOT RUNNING → emit NOTHING (the ABSENT posture). Do NOT fall
        // through to FAILED.
        //
        // The overwhelmingly common way to reach this is a GRACEFUL SHUTDOWN: Agent::stop()
        // and run()'s ScopeExit both call spark_engine_->stop(), and the heartbeat thread
        // can compose one more beat before it is joined. Reporting FAILED there would have
        // the server count a cleanly-stopping agent into yuzu_fleet_spark_failed{os} — the
        // ONE gauge documented "alert on it" — so every `systemctl restart`, every reboot
        // and every OTA cycle would page on-call with a fault that never happened.
        // STOPPED is not FAILED (governance Gate-2 security + Gate-3 cross-platform, found
        // independently).
        //
        // FAILED is therefore reserved for exactly one condition, decided by the CALLER:
        // spark was ENABLED but the engine is NULL because boot-time instantiation threw.
        return;
    }
    tags["yuzu.spark_running"] = "1";
    // Capability: the registered AND functional mechanism types, as a CSV.
    std::string mechs;
    for (const auto& [type, ms] : by_type) {
        if (ms.inert)
            continue; // registered but cannot watch — not a capability
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
    // Deliberately NOT skipped for inert mechanisms — inertness suppresses the capability
    // claim (the CSV above), not the telemetry. See the header note: today every inert
    // mechanism's counters happen to be zero, so the sparse rule drops them anyway.
    for (const auto& [type, ms] : by_type) {
        if (ms.watch_rejected_total == 0 && ms.quarantined_total == 0 && ms.slow_op_total == 0)
            continue; // nothing to say — don't build the key prefix (all-zero at rung 1)
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
