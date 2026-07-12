/**
 * spark_interval.cpp — the interval spark type (see spark_types.hpp).
 *
 * The wheel calls this when an interval spark's deadline elapses: every tick
 * emits (the tick IS the fact — no payload) and reschedules exactly one
 * interval out from `now`, so a delayed wheel pass drifts rather than bursts
 * (no catch-up storm after a laptop resume — network-kindness / NFR).
 */

#include "spark_types.hpp"

namespace yuzu::agent {

SparkFireDecision interval_process_due(std::uint64_t interval_ms,
                                       std::chrono::steady_clock::time_point now) {
    SparkFireDecision d;
    d.emit = true;
    d.reschedule = now + std::chrono::milliseconds(interval_ms);
    return d;
}

} // namespace yuzu::agent
