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
 * WITH ONE ABSOLUTE EXCEPTION: whatever `send` captures, it must never take
 * GuardianEngine::mtx_ - see the central constraint below. That applies to
 * EVERY path on this thread, the injected send included; `send` is in fact the
 * easiest place to reintroduce the deadlock, because it is an arbitrary
 * std::function supplied from agent.cpp. GuardianEngine aborts on this in
 * debug/sanitizer builds via the thread-local marker in
 * guardian_joined_thread_role.hpp, so a violation crashes loudly rather than
 * hanging a fleet.
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
 * That is why the journal arrives as a pre-resolved shared_ptr captured at
 * construction rather than being re-read off the engine under its lock - the same
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

/// Journal REPLAY-PAGE cadence. Load-bearing (#2298 governance f-1/A1): a paging pass is
/// a full `list_entries` + parse + `validate_record` sweep of the journal, and
/// JournalPagingBucket charges a token only when a batch pages NET-NEW work. So when the
/// send window already holds every candidate - the normal state while the link is down and
/// the backlog is retained - the bucket never throttles and every wake rescans the whole
/// journal. Since the drain worker wakes on EVERY outbox enqueue, "page on every wake" is
/// unbounded scan cost driven by the event rate. 30 s restores exactly the pre-C0 rate (one
/// page per heartbeat tick); the reconnect kick still forces an immediate page, so replay
/// promptness is unaffected.
inline constexpr std::chrono::milliseconds kGuardianJournalPageInterval{30'000};

/// Retention-prune cadence. TIME-based for the same reason, and additionally because the
/// heartbeat's old "every 4th tick" rule was only safe while a tick WAS a fixed 30 s.
/// ~2 min preserves that effective cadence (4 x 30 s) without depending on a tick count.
inline constexpr std::chrono::milliseconds kGuardianJournalPruneInterval{120'000};

/// Entries shipped per drain pass before the worker re-checks its other work. Unbounded, a
/// slow stream drains the whole 4096-entry window - at 20 ms/send that is ~82 s of
/// head-of-line blocking - which post-C0 would starve journal retention until the write
/// ceiling DROPS audit records (#2298 governance f-3). The worker re-drains immediately on
/// hitting this bound, so steady-state throughput is unchanged.
inline constexpr std::size_t kGuardianDrainBudget = 512;

/// Minimum gap between refill-driven forced pages. The refill re-arm exists so a reconnect
/// backlog moves without waiting out the page cadence, but each forced page is a full journal
/// scan, so it needs a floor. TIME rather than a cycle count: a counter reset on a
/// condition-variable wait is no bound at all, because that wait returns immediately whenever
/// an enqueue already moved the generation (#2345 Gate 4 UP-1).
inline constexpr std::chrono::milliseconds kGuardianMinRefillInterval{1'000};

/// Wall-clock companion to kGuardianDrainBudget. 512 entries bounds the COUNT but not the
/// TIME: at a pathological seconds-per-send it is still minutes, and the worker may be
/// holding up GuardianEngine::stop()'s join for all of it.
inline constexpr std::chrono::milliseconds kGuardianDrainMaxWall{2'000};

/// Journal-maintenance knobs for GuardianOutboxDrainWorker. A struct rather than more
/// positional parameters so the two same-typed intervals cannot be transposed at a call
/// site, and so a test can name only what it overrides:
/// `{.journal = j, .prune_interval = 0ms}`.
///
/// Namespace-scope, not nested: a default argument cannot require a nested class's default
/// member initializers before the enclosing class is complete.
struct GuardianMaintenanceConfig {
    /// SHARED, may be null (no maintenance runs). A shared_ptr rather than a raw borrow so
    /// the worker's dependency on the journal is expressed in the type system: previously
    /// correctness rested on GuardianEngine declaring the journal before the worker, an
    /// unenforceable ordering nothing would have caught if reordered (#2298 governance A4).
    /// One allocation, and the whole class of failure goes away.
    std::shared_ptr<GuardianLifecycleJournal> journal{};
    std::chrono::milliseconds page_interval{kGuardianJournalPageInterval};
    std::chrono::milliseconds prune_interval{kGuardianJournalPruneInterval};
    std::size_t drain_budget{kGuardianDrainBudget};
    /// Wall-clock cap on one drain pass. A COUNT bound is not a safety bound - one
    /// slow-but-succeeding send makes an N-entry pass arbitrarily long while
    /// GuardianEngine::stop() waits on our join (#2298 Sol review).
    std::chrono::milliseconds drain_max_wall{kGuardianDrainMaxWall};
};

/// Which maintenance passes to run this cycle. The CALLER owns cadence - the worker loop
/// keeps its timers as locals, so the worker holds no cross-thread timer state and
/// maintenance_once() is a pure function of its argument.
struct GuardianMaintenanceOps {
    /// Re-offer batches that already carry a durable sent-label. TRUE only on a FORCED page
    /// (boot replay, reconnect kick) - the events after which an in-flight send may have been
    /// lost. False on the cadence pass, so steady state does not re-deliver what the server
    /// already has (#2345 round 8).
    bool replay_sent{false};
    bool prune{false};
    bool page{false};
};

/// Outcome of one maintenance pass. Deliberately NOT JournalPageStats: keeping the journal
/// a forward declaration here holds the dependency direction to worker -> journal without
/// dragging the audit component into this header.
struct GuardianMaintenanceResult {
    bool page_attempted{false};   ///< a paging pass was requested and ran
    std::size_t records_paged{0}; ///< net-new records placed in the send window
    /// The pass had a candidate it could not place for lack of room FOR THAT BATCH (not
    /// necessarily a full window - headroom 255 blocks a 256-entry batch). Only
    /// this - never "records_paged == 0" - justifies re-attempting outside the cadence
    /// (#2298 Gate 4 UP-2).
    bool headroom_blocked{false};
    /// Smallest blocked batch's requirement; see JournalPageStats.
    std::size_t min_blocked_headroom{0};
    /// The pass did nothing because the paging rate-limiter had no token; see
    /// JournalPageStats::deferred_no_token. A forced page must be re-armed on this.
    bool deferred_no_token{false};
    /// Candidates skipped because they already carry a durable sent-label - per-pass and
    /// diagnostic. No cumulative counter and no heartbeat tag, so do not cite it as
    /// fleet-visible evidence (#2345 Gate 8).
    std::size_t skipped_already_sent{0};
    /// The sent-label scan failed and the pass fell back to re-offering everything.
    bool sent_scan_failed{false};
};

class YUZU_EXPORT GuardianOutboxDrainWorker {
public:
    using SendFn = std::function<SendResult(const OutboxEntry&)>;

    /// Backstop poll cadence when no enqueue-wake ever arrives. Matches the
    /// convergence scheduler's priority-lane cadence philosophy (fleet-kind,
    /// still bounds staleness in the pathological case).
    static constexpr std::uint64_t kDefaultPeriodicBoundMs = 5'000;

    GuardianOutboxDrainWorker(GuardianSparkRuntime& rt, SendFn send,
                              std::uint64_t periodic_bound_ms = kDefaultPeriodicBoundMs,
                              GuardianMaintenanceConfig maintenance = GuardianMaintenanceConfig{});
    ~GuardianOutboxDrainWorker();
    GuardianOutboxDrainWorker(const GuardianOutboxDrainWorker&) = delete;
    GuardianOutboxDrainWorker& operator=(const GuardianOutboxDrainWorker&) = delete;

    /// Install the enqueue waker on `rt` and start the worker thread.
    /// Single-shot (a second call is a no-op).
    void start();
    /// Clear the waker, wake the worker, and join. Idempotent; never blocks a
    /// full periodic bound (the CV wake is immediate).
    void stop();

    /// Wake the worker NOW, and force the next cycle to page regardless of the page
    /// cadence. Used by the reconnect hook so a freshly-connected stream gets its
    /// journal replay promptly (C0 #2298: the reconnect thread kicks, it no longer pages
    /// inline). The force is what keeps kDefaultPageInterval from delaying reconnect
    /// replay. A no-op after stop(). Safe before start(): both the bumped generation and
    /// the force flag are observed by the loop's first cycle.
    void notify();

    /// TEST-ONLY deterministic seam: run ONE drain pass synchronously on the caller's thread,
    /// UNBOUNDED. It has NO production caller by design - the loop body uses the bounded
    /// private drain_bounded(). Deliberately retained rather than deleted because several
    /// tests rely on a synchronous drain, but note it bypasses every limit the worker applies
    /// in production (count, wall clock, stop predicate), so it must not become a shortcut for
    /// production code (#2345 / Sol). Does NOT firewall
    /// exceptions - the worker thread's loop() does (so a test can still observe a
    /// throw, but a bad_alloc on the bare worker thread never terminates the agent).
    void drain_once();

    /// Deterministic test seam (also the worker thread's own loop body): run the
    /// maintenance passes named by `ops` synchronously on the caller's thread. Holds no
    /// timer state of its own, so unlike a cadence-owning variant it is safe to call
    /// from any thread. A no-op with no journal. Does NOT firewall exceptions - loop()
    /// does.
    GuardianMaintenanceResult maintenance_once(GuardianMaintenanceOps ops);

    /// Cumulative count of drain passes that threw and were firewalled by loop().
    /// A nonzero value means the drain path hit an exception (bad_alloc under memory
    /// pressure); surfaced via the heartbeat by item 9. Lock-free.
    [[nodiscard]] std::uint64_t drain_exception_count() const noexcept {
        return drain_exceptions_.load(std::memory_order_relaxed);
    }

    /// Cumulative count of journal-maintenance passes that threw and were firewalled
    /// by loop(). Surfaces as `yuzu.guardian_journal_maint_exceptions` alongside the
    /// heartbeat's retry-persist - that tag is JOURNAL work only. Delivery throws are
    /// counted separately (drain_exception_count) and emitted as
    /// `yuzu.guardian_drain_exceptions`: a retention failure and a delivery failure need
    /// different operator responses, so they are deliberately not one number. Lock-free.
    [[nodiscard]] std::uint64_t journal_maint_exception_count() const noexcept {
        return journal_maint_exceptions_.load(std::memory_order_relaxed);
    }

private:
    void loop();
    /// True once stop() has been requested. Lock-free and noexcept BY DESIGN: this is
    /// the one check loop() makes outside a try, and taking a mutex here would let
    /// std::system_error escape the bare worker thread and terminate the agent (the
    /// #2037 class of defect).
    [[nodiscard]] bool stop_requested() const noexcept {
        return sig_->stopping.load(std::memory_order_acquire);
    }
    /// One drain pass under the configured count / wall-clock / stop-predicate limits.
    /// `truncated` means entries remain and the loop should re-drain WITHOUT waiting.
    [[nodiscard]] GuardianSparkRuntime::DrainOutcome drain_bounded();

    /// Heap sync state shared by the worker thread AND the waker (a
    /// std::function copied into the runtime) - see the class doc for why a
    /// copy invoked after this worker is destroyed is still safe.
    struct Signal {
        std::mutex mu;
        std::condition_variable cv;
        /// Write-once-true. ATOMIC so stop_requested() needs no lock (see above); still
        /// STORED under `mu` so a waiter inside wait_for cannot miss the transition.
        std::atomic<bool> stopping{false};
        std::uint64_t gen{0}; ///< bumped by the waker; the loop waits on a change
    };

    GuardianSparkRuntime& rt_;
    SendFn send_;
    std::uint64_t periodic_bound_ms_;
    GuardianMaintenanceConfig maint_;
    std::shared_ptr<Signal> sig_;
    bool started_{false};
    std::thread thread_;
    std::atomic<std::uint64_t> drain_exceptions_{0}; ///< firewalled drain-pass throws (item 4 hardening)
    std::atomic<std::uint64_t> journal_maint_exceptions_{0}; ///< firewalled maintenance-pass throws (C0)
    /// Set by notify(), cleared by the loop: force ONE page irrespective of cadence.
    /// Seeded TRUE so the first cycle replays the journal at boot without waiting out
    /// kDefaultPageInterval.
    std::atomic<bool> force_page_{true};
};


} // namespace yuzu::agent
