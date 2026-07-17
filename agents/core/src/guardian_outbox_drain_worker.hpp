#pragma once

/**
 * guardian_outbox_drain_worker.hpp - the live-drain worker for
 * GuardianSparkRuntime's outbox + Lifecycle audit log (ADR-0021 Stage 2 rung
 * 7, F6).
 *
 * Mirrors ConvergenceScheduler's proven CV-wake + shared-Signal lifetime shape
 * (twice-Sol-reviewed, TSan-clean): the waker installed on the runtime
 * captures ONLY a shared_ptr<Signal>, never `this`, so a copy invoked after
 * this worker is destroyed touches a still-alive Signal (a harmless no-op),
 * never a destroyed mutex/cv.
 *
 * WHY (F6): the approved outbox contract drains at sink-publication + every
 * reconnect. A healthy connection can stay up indefinitely, so that alone has
 * no bounded staleness for an event produced while already connected. This
 * worker adds a THIRD trigger: wake immediately whenever the runtime enqueues
 * anything (compliance/health/lifecycle), with a periodic bound as a backstop
 * in case a wake is ever missed.
 *
 * OWNERSHIP: GuardianEngine owns this as a member alongside the
 * GuardianSparkRuntime it references - constructed after, stopped/joined
 * before (see GuardianEngine::stop()'s documented shutdown order), so the
 * reference stays valid for this worker's entire lifetime, the same
 * relationship ConvergenceScheduler already has to the runtime.
 *
 * `send` MAY capture GuardianEngine/AgentImpl state (e.g. `this`) directly -
 * unlike the SparkEngine-queued-consumer handler (which can be DETACHED past
 * the shutdown budget and must therefore be fully self-contained), this
 * worker's thread is ALWAYS synchronously joined by stop() before the owner
 * tears down further, so a capture here does not need that level of
 * self-containment. Document this distinction at the call site if it becomes
 * non-obvious.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include "guardian_outbox.hpp"        // OutboxEntry, SendResult
#include "guardian_spark_runtime.hpp" // GuardianSparkRuntime

#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>

namespace yuzu::agent {

class YUZU_EXPORT GuardianOutboxDrainWorker {
public:
    using SendFn = std::function<SendResult(const OutboxEntry&)>;

    /// Backstop poll cadence when no enqueue-wake ever arrives. Matches the
    /// convergence scheduler's priority-lane cadence philosophy (fleet-kind,
    /// still bounds staleness in the pathological case).
    static constexpr std::uint64_t kDefaultPeriodicBoundMs = 5'000;

    GuardianOutboxDrainWorker(GuardianSparkRuntime& rt, SendFn send,
                              std::uint64_t periodic_bound_ms = kDefaultPeriodicBoundMs);
    ~GuardianOutboxDrainWorker();
    GuardianOutboxDrainWorker(const GuardianOutboxDrainWorker&) = delete;
    GuardianOutboxDrainWorker& operator=(const GuardianOutboxDrainWorker&) = delete;

    /// Install the enqueue waker on `rt` and start the worker thread.
    /// Single-shot (a second call is a no-op).
    void start();
    /// Clear the waker, wake the worker, and join. Idempotent; never blocks a
    /// full periodic bound (the CV wake is immediate).
    void stop();

    /// Deterministic test seam (also the worker thread's own loop body): run
    /// ONE drain pass synchronously on the caller's thread.
    void drain_once();

private:
    void loop();

    /// Heap sync state shared by the worker thread AND the waker (a
    /// std::function copied into the runtime) - see the class doc for why a
    /// copy invoked after this worker is destroyed is still safe.
    struct Signal {
        std::mutex mu;
        std::condition_variable cv;
        bool stopping{false};
        std::uint64_t gen{0}; ///< bumped by the waker; the loop waits on a change
    };

    GuardianSparkRuntime& rt_;
    SendFn send_;
    std::uint64_t periodic_bound_ms_;
    std::shared_ptr<Signal> sig_;
    bool started_{false};
    std::thread thread_;
};

} // namespace yuzu::agent
