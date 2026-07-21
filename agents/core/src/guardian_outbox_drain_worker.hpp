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
 *
 * JOURNAL MAINTENANCE (C0, #2298 gate 1): this worker also runs the durable
 * lifecycle journal's retention prune + replay paging, which used to run inline
 * on the heartbeat thread (journal_maintenance_tick phase 2) and the reconnect /
 * run-loop thread (page_journal). Both are KvStore-bound and can block on its
 * 5 s busy timeout, so a large or contended journal stalled a latency-sensitive
 * thread; here the same work is already-async and co-located with the KvStore I/O
 * the drain path does anyway (mark_batch_sent per sent batch).
 *
 * THE CENTRAL CONSTRAINT: maintenance must NEVER take the GuardianEngine mtx_.
 * GuardianEngine::stop() holds mtx_ across its whole body AND joins this worker
 * inside it, so an mtx_ acquisition on this thread is a lock-vs-join deadlock.
 * That is why the journal arrives as a pre-resolved raw pointer captured at
 * construction (engine-owned, set once during wiring, never reassigned while the
 * worker runs) rather than being re-read off the engine under its lock - the same
 * shape as the enqueue-waker capturing only a shared Signal, never `this`.
 * Shutdown is coordinated purely by atomics: the journal's own stopping_ gate
 * (set FIRST in engine::stop()) plus this worker's stopping flag.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include "guardian_outbox.hpp"        // OutboxEntry, SendResult
#include "guardian_spark_runtime.hpp" // GuardianSparkRuntime

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>

namespace yuzu::agent {

class GuardianLifecycleJournal;

class YUZU_EXPORT GuardianOutboxDrainWorker {
public:
    using SendFn = std::function<SendResult(const OutboxEntry&)>;

    /// Backstop poll cadence when no enqueue-wake ever arrives. Matches the
    /// convergence scheduler's priority-lane cadence philosophy (fleet-kind,
    /// still bounds staleness in the pathological case).
    static constexpr std::uint64_t kDefaultPeriodicBoundMs = 5'000;

    /// Retention-prune cadence. TIME-based, not wake-based: this worker wakes on
    /// every outbox enqueue, so an "every Nth wake" rule (what the heartbeat tick
    /// used, where a wake WAS a fixed 30 s) would scan the whole journal far too
    /// often under an event burst. ~2 min preserves the old effective cadence
    /// (4 x 30 s heartbeats) while decoupling it from wake frequency.
    static constexpr std::uint64_t kDefaultPruneIntervalMs = 120'000;

    /// `journal` is BORROWED and may be null (no maintenance runs). It must outlive
    /// this worker; the owner guarantees that by joining here first - see the
    /// class doc's JOURNAL MAINTENANCE note and GuardianEngine's member order.
    GuardianOutboxDrainWorker(GuardianSparkRuntime& rt, SendFn send,
                              std::uint64_t periodic_bound_ms = kDefaultPeriodicBoundMs,
                              GuardianLifecycleJournal* journal = nullptr,
                              std::uint64_t prune_interval_ms = kDefaultPruneIntervalMs);
    ~GuardianOutboxDrainWorker();
    GuardianOutboxDrainWorker(const GuardianOutboxDrainWorker&) = delete;
    GuardianOutboxDrainWorker& operator=(const GuardianOutboxDrainWorker&) = delete;

    /// Install the enqueue waker on `rt` and start the worker thread.
    /// Single-shot (a second call is a no-op).
    void start();
    /// Clear the waker, wake the worker, and join. Idempotent; never blocks a
    /// full periodic bound (the CV wake is immediate).
    void stop();

    /// Wake the worker NOW rather than waiting out the periodic bound. Used by the
    /// reconnect hook so a freshly-connected stream gets its journal replay promptly
    /// (C0 #2298: the reconnect thread kicks, it no longer pages inline). A no-op
    /// after stop(). Safe to call before start(): the bumped generation is observed
    /// by the loop's first wait predicate.
    void notify();

    /// Deterministic test seam (also the worker thread's own loop body): run
    /// ONE drain pass synchronously on the caller's thread. Does NOT firewall
    /// exceptions - the worker thread's loop() does (so a test can still observe a
    /// throw, but a bad_alloc on the bare worker thread never terminates the agent).
    void drain_once();

    /// Deterministic test seam (also the worker thread's own loop body): run ONE
    /// journal-maintenance pass - a retention prune if `prune_interval_ms` has
    /// elapsed since the last one, then a replay page - synchronously on the caller's
    /// thread. Returns true if the pass paged net-new records into the send window,
    /// meaning the caller should drain again (try_page_batch does NOT wake this
    /// worker). A no-op with no journal. Does NOT firewall exceptions - loop() does.
    /// NOT thread-safe against the worker thread (the prune timer is plain state):
    /// call it from the worker thread, or with the worker not started.
    bool maintenance_once();

    /// Cumulative count of drain passes that threw and were firewalled by loop().
    /// A nonzero value means the drain path hit an exception (bad_alloc under memory
    /// pressure); surfaced via the heartbeat by item 9. Lock-free.
    [[nodiscard]] std::uint64_t drain_exception_count() const noexcept {
        return drain_exceptions_.load(std::memory_order_relaxed);
    }

    /// Cumulative count of journal-maintenance passes that threw and were firewalled
    /// by loop(). Counted SEPARATELY from drain_exception_count so the two failure
    /// domains stay distinguishable, but folded into the SAME operator-facing tag
    /// (guardian_journal_maint_exceptions) by GuardianEngine::journal_stats(), which
    /// is where prune/page throws were counted before C0. Lock-free.
    [[nodiscard]] std::uint64_t journal_maint_exception_count() const noexcept {
        return journal_maint_exceptions_.load(std::memory_order_relaxed);
    }

private:
    void loop();
    /// True once stop() has been requested. Takes the Signal mutex (uncontended).
    [[nodiscard]] bool stop_requested() const;

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
    /// BORROWED, may be null. Pre-resolved at construction precisely so the worker
    /// thread never re-reads it off the engine under mtx_ (see the class doc).
    GuardianLifecycleJournal* journal_;
    std::uint64_t prune_interval_ms_;
    std::shared_ptr<Signal> sig_;
    bool started_{false};
    std::thread thread_;
    std::atomic<std::uint64_t> drain_exceptions_{0}; ///< firewalled drain-pass throws (item 4 hardening)
    std::atomic<std::uint64_t> journal_maint_exceptions_{0}; ///< firewalled maintenance-pass throws (C0)
    /// Worker-thread-only (or pre-start): last prune's steady_clock stamp. Seeded at
    /// CONSTRUCTION, not epoch, so the first maintenance pass does not immediately
    /// re-prune what page_into_window's boot barrier is about to prune anyway.
    std::chrono::steady_clock::time_point last_prune_;
};

} // namespace yuzu::agent
