#pragma once

/**
 * guardian_spark_backend.hpp - binds GuardianSparkRuntime's abstract
 * ISparkBackend to the real SparkEngine (ADR-0021 Stage 2 rung 7).
 *
 * BREAKS A CONSTRUCTION CYCLE: GuardianSparkRuntime needs an ISparkBackend at
 * construction; this adapter needs a SparkEngine::ConsumerId to forward
 * arm()/disarm() to; the ConsumerId comes from SparkEngine::register_consumer(),
 * whose handler argument is GuardianSparkRuntime::make_handler(shared_ptr<
 * GuardianSparkRuntime>) - which needs the runtime to ALREADY exist. Two-phase
 * construction breaks it: build the adapter UNBOUND, build the runtime around
 * it, register the consumer (now possible - the runtime exists), THEN
 * bind_consumer() with the real id. No caller can reach attach_rule() (and
 * therefore arm()) before the whole wiring sequence - owned by
 * GuardianEngine::wire_spark_engine() - returns, so an unbound arm() call is
 * unreachable in production; it is guarded here anyway with a typed error
 * rather than silently forwarding a sentinel ConsumerId (SparkEngine's own
 * arm() would itself reject an unregistered id with "unknown consumer id", but
 * that reads as a mystery bug rather than a caller-sequencing one).
 *
 * LIFETIME: engine_ is BORROWED, never owned. This is safe ONLY because of the
 * agent.cpp member-declaration-order swap (rung 7.7): GuardianEngine (which
 * owns this adapter, transitively via GuardianSparkRuntime's shared_ptr<
 * ISparkBackend>) is declared AFTER spark_engine_, so it is destroyed FIRST -
 * spark_engine_ always outlives this adapter's lifetime.
 */

#include <yuzu/agent/spark.hpp> // SparkSpec

#include "guardian_spark_runtime.hpp" // ISparkBackend
#include "spark_engine.hpp"           // SparkEngine, SparkEngine::ConsumerId

#include <cstdint>
#include <expected>
#include <string>

namespace yuzu::agent {

class GuardianSparkEngineBackend : public ISparkBackend {
public:
    explicit GuardianSparkEngineBackend(SparkEngine& engine) noexcept : engine_(&engine) {}
    GuardianSparkEngineBackend(const GuardianSparkEngineBackend&) = delete;
    GuardianSparkEngineBackend& operator=(const GuardianSparkEngineBackend&) = delete;

    /// Complete the bind, once, after SparkEngine::register_consumer() succeeds.
    /// Called exactly once by the wiring sequence in
    /// GuardianEngine::wire_spark_engine() - never re-bound (a rebind would let
    /// rules armed under the old ConsumerId silently reroute to a new one).
    void bind_consumer(SparkEngine::ConsumerId id) noexcept {
        consumer_ = id;
        bound_ = true;
    }

    std::expected<std::uint64_t, std::string> arm(const SparkSpec& spec) override {
        if (!bound_)
            return std::unexpected(
                "GuardianSparkEngineBackend: arm() called before bind_consumer() completed "
                "wiring - this is a caller-sequencing bug, not a runtime condition");
        return engine_->arm(consumer_, spec);
    }

    void disarm(std::uint64_t subscription) override {
        if (!bound_)
            return; // nothing was ever armed through an unbound adapter
        engine_->disarm(subscription);
    }

private:
    SparkEngine* engine_; // BORROWED - see the lifetime note above
    SparkEngine::ConsumerId consumer_{0};
    bool bound_{false};
};

} // namespace yuzu::agent
