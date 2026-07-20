#pragma once

/**
 * guardian_convergence_scheduler.hpp - the Guardian spark consumer's convergence
 * driver (ADR-0021 Stage 2 rung 4). Design:
 * docs/spark-stage2-guardian-consumer-design.md.
 *
 * Spark events are the fast path, but they are lossy hints (the queued consumer
 * can drop under a storm, and some initial state never produces an event). So a
 * dropped sole event for a key would leave its drift undetected forever. This
 * scheduler is the backstop: it periodically re-drives GuardianSparkRuntime::
 * evaluate_key(Convergence) for every armed key from CURRENT state, independent
 * of edges, so compliance always re-converges within a bounded age.
 *
 * Shape (Sol's rev-2 note "one convergence thread reintroduces head-of-line
 * blocking"): ONE scheduler owning ONE thread PER TYPE-LANE (file / registry /
 * service) plus a priority lane, so a slow file hash never blocks a fast service
 * reconcile. Lanes carry different cadences (service / registry ~60s, file
 * ~5-15min) with per-lane jitter (fleet-kindness: no synchronised convergence
 * herd). The priority lane services keys that still owe an initial eval; it is
 * CV-woken the moment a rule is attached (set_pending_initial_waker) so a fresh
 * rule learns its compliance promptly instead of waiting a full cadence.
 *
 * Every wait is CV-interruptible: stop() wakes all lanes at once rather than
 * blocking a multi-minute sleep on shutdown. Lanes hard-join (they are Guardian-
 * owned, never detached like the SparkEngine consumer); a sweep observes the
 * runtime's stopping flag and commits nothing, so a join waits only for the
 * current bounded read, not a whole cadence. (A truly hung reader is the
 * blocked-reader shutdown bound the runtime documents; the agent hard-exit is the
 * final backstop.)
 *
 * DEFERRED to rung 5 (where the real readers exist and there is a read cost to
 * meter): size+mtime skip before re-hash, forced periodic full hash, and the
 * file-lane byte token bucket. Against rung 4's fake instant reader there is
 * nothing to budget, so wiring them here would be untested theatre; they live at
 * the file StateReader / runtime boundary.
 */

#include <yuzu/plugin.h>        // YUZU_EXPORT
#include <yuzu/agent/spark.hpp> // SparkType

#include "guardian_spark_runtime.hpp"

#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <random>
#include <thread>
#include <vector>

namespace yuzu::agent {

class YUZU_EXPORT ConvergenceScheduler {
public:
    struct Config {
        std::uint64_t service_cadence_ms{60'000};
        std::uint64_t registry_cadence_ms{60'000};
        std::uint64_t file_cadence_ms{600'000}; ///< ~10 min (the 5-15 min band)
        std::uint64_t priority_poll_ms{5'000};  ///< pending-initial backstop poll (also CV-woken)
        std::uint32_t jitter_pct{20};            ///< +/- this % of the cadence, per lane
        std::uint64_t rng_seed{0x5eed};          ///< deterministic jitter source (per-lane offset)
    };

    explicit ConvergenceScheduler(GuardianSparkRuntime& rt);
    ConvergenceScheduler(GuardianSparkRuntime& rt, Config cfg);
    ~ConvergenceScheduler();
    ConvergenceScheduler(const ConvergenceScheduler&) = delete;
    ConvergenceScheduler& operator=(const ConvergenceScheduler&) = delete;

    /// Launch the lane threads and install the pending-initial waker. Single-shot.
    void start();
    /// Clear the waker, wake every lane, and join. Idempotent; never blocks a full
    /// cadence.
    void stop();

    /// Deterministic test seams (also the lane threads' bodies): run ONE sweep
    /// synchronously on the caller's thread.
    void sweep_lane(SparkType type);
    void sweep_pending_initial();

private:
    /// Heap sync state shared by the lane threads AND the pending-initial waker. The
    /// waker (a std::function copied into the runtime) captures shared_ptr<Signal>,
    /// NOT `this`, so a copy invoked after this scheduler is destroyed - e.g. an
    /// attach_rule that copied the waker just before stop() then ran it after the
    /// dtor - touches a still-alive Signal (a harmless no-op: `stopping` is set and no
    /// thread is waiting), never a destroyed mutex/CV. Clearing a std::function slot
    /// alone would not revoke that already-taken copy.
    struct Signal {
        std::mutex mu;
        std::condition_variable cv;
        bool stopping{false};
        std::uint64_t priority_gen{0}; ///< bumped by the waker; the priority lane waits on a change
    };

    void lane_loop(SparkType type, std::uint64_t cadence_ms, std::uint64_t rng_offset);
    void priority_loop();
    [[nodiscard]] std::chrono::milliseconds jittered(std::uint64_t base_ms, std::mt19937& rng) const;

    GuardianSparkRuntime& rt_;
    Config cfg_;
    std::shared_ptr<Signal> sig_;
    bool started_{false};
    std::vector<std::thread> threads_;
};

} // namespace yuzu::agent
