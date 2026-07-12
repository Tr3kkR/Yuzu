#pragma once

/**
 * spark_engine.hpp — SparkEngine, the agent's single detection layer
 * (ADR-0021 Decisions 1 + 3; campaign plan Stage 1).
 *
 * Watchers are multiplexed by MECHANISM, never by rule: this PR ships the
 * timer wheel (one thread servicing every interval, startup, and poll-class
 * spark); the file-notification thread, the event-handle wait pool (TP_WAIT,
 * #1907), and the multiplexed service pump land in the follow-up PRs. Arming
 * is deduped across consumers: two subscriptions to an equal SparkSpec share
 * one watcher entry and one per-spark state (N consumers, 1 watcher).
 *
 * Delivery tiers (contract in spark.hpp):
 *   - Queued  — each registered consumer owns a bounded queue + dispatch
 *               thread. Watchers enqueue without ever blocking: when a queue
 *               is full the OLDEST event is dropped and counted
 *               (queued_dropped_total), so a stuck consumer can neither stall
 *               a watcher nor starve a sibling consumer. Queued handlers may
 *               block, dispatch plugins, do network I/O.
 *   - Inline  — runs synchronously on the PRODUCING watcher thread: the wheel
 *               for timer sparks, OR the mechanism's own thread (the file
 *               IOCP worker, a registry TP_WAIT pool thread) for event-driven
 *               sparks. Core-internal (never reachable from the plugin ABI);
 *               enforce-class only. Every inline call is timed — the duration
 *               counters (inline_us_*, inline_over_*) are the ADR §3 watchdog
 *               that feeds the Stage-11 resource gate. SLO is µs-MEDIAN,
 *               rare-ms tolerated (owner decision 2026-07-06).
 *
 * Lifecycle: construct → register consumers / arm sparks (any order) →
 * start() → … → stop(). Single-shot: the engine does not restart after
 * stop(). stop() drops + counts undelivered queued events and quiesces the
 * watcher + consumer threads. It is prompt FOR WELL-BEHAVED HANDLERS: a queued
 * handler that blocks past kConsumerJoinBudgetMs is detached + counted, not
 * joined, so a hung handler can never hang shutdown (governance UP-1 / #1311).
 *
 * Threading contract for callers: arm/disarm/register/stats are safe from any
 * thread, and from inside a handler WHILE THE ENGINE IS ALIVE. THREE exceptions:
 *   (1) unregister_consumer quiesces that consumer's thread — never call it
 *       from the consumer's own handler (self-join).
 *   (2) An INLINE handler on an EVENT-DRIVEN spark runs on the mechanism's own
 *       thread. Calling disarm() for that SAME registry spark from inside its
 *       inline handler can self-deadlock in the current TP_WAIT teardown (the
 *       callback waits on its own wait object). Queued handlers, and inline
 *       handlers disarming a DIFFERENT spark, are safe. The registry mechanism
 *       must defer teardown before an inline registry consumer is wired
 *       (Stage 2) — governance F3.
 *   (3) A QUEUED handler that may BLOCK must not call back into the engine
 *       (arm/disarm/stats). It can be DETACHED at shutdown (see above), and the
 *       engine — reached via the captured `this` such a call would use — may be
 *       destroyed by the time the blocked handler resumes → use-after-free
 *       (governance UP2-1). "Safe from inside a handler" holds only for the
 *       non-blocking, engine-outlives-the-call case; a blockable handler must
 *       treat the engine as possibly-gone once it has blocked.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT
#include <yuzu/agent/spark.hpp>

#include "spark_mechanism.hpp" // ISparkMechanism, register_mechanism
#include "spark_types.hpp"     // DiskReaderFn, SparkFireDecision

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace yuzu::agent {

/// Point-in-time counters, surfaced via heartbeat status_tags by the agent
/// wiring (the agent has no /metrics — the dex/guardian convention).
struct SparkEngineStats {
    std::uint64_t armed_sparks{0};       ///< deduped watcher entries
    std::uint64_t armed_faulted{0};      ///< armed sparks a mechanism reported deaf (B1 health)
    std::uint64_t subscriptions{0};      ///< live subscriptions across all armed sparks
    std::uint64_t consumers{0};          ///< registered queued consumers
    /// Watcher UNITS while running: the wheel + one per registered event-driven
    /// mechanism. NOT an OS thread count — a mechanism may run a small pool (the
    /// registry TP_WAIT pool is 2–4 threads). Named `_units` deliberately so a
    /// resource-gate cross-check doesn't mistake it for `ps -T` (governance S1).
    std::uint64_t watcher_units{0};
    std::uint64_t watch_faults_total{0}; ///< mechanism fault reports (post-arm deaf edges), monotonic
    std::uint64_t consumer_threads_detached{0}; ///< handlers that blocked past the shutdown budget
    std::uint64_t events_total{0};       ///< spark fires (post-dedup, pre-fan-out)
    std::uint64_t queued_delivered_total{0};
    std::uint64_t queued_dropped_total{0}; ///< bounded-queue overflow + shutdown drops
    std::uint64_t consumer_errors_total{0}; ///< queued handlers that threw
    // Inline-tier watchdog (ADR §3): duration accounting for every inline call.
    std::uint64_t inline_calls_total{0};
    std::uint64_t inline_errors_total{0}; ///< inline handlers that threw (contract breach)
    std::uint64_t inline_us_total{0};
    std::uint64_t inline_us_max{0};
    std::uint64_t inline_over_100us_total{0}; ///< tail counter (p-high proxy)
    std::uint64_t inline_over_10ms_total{0};  ///< scheduler-quantum-class outliers
    // Summed across every registered mechanism's stats() (#1979); see
    // SparkMechanismStats for per-field meaning.
    std::uint64_t mech_retiring{0};
    std::uint64_t mech_watch_rejected_total{0};
    std::uint64_t mech_quarantined_total{0};
    std::uint64_t mech_slow_op_total{0};
};

class YUZU_EXPORT SparkEngine {
public:
    using ConsumerId = std::uint64_t;
    using SubscriptionId = std::uint64_t;
    using QueuedHandler = std::function<void(const SparkEvent&)>;
    /// Stage 2 narrows this to (event, enforce-capability) — no dispatcher, no
    /// plugin-host handle, so a plugin call from an inline handler is a
    /// compile error (ADR §3 "enforced, not conventional").
    using InlineHandler = std::function<void(const SparkEvent&)>;

    static constexpr std::size_t kDefaultQueueCap = 1024;
    /// Cadence floor for interval/poll sparks (the TriggerEngine 30 s minimum).
    static constexpr std::uint64_t kMinCadenceMs = 30'000;
    /// A disk spark's FIRST poll runs within this of start — early, but
    /// timer-driven, never at-arm (the dex_win_poll macOS lesson).
    static constexpr std::uint64_t kFirstDiskPollCapMs = 60'000;
    /// Per-consumer shutdown budget: a dispatch thread still inside a handler
    /// past this on stop()/unregister is detached, not joined (governance UP-1).
    static constexpr std::uint64_t kConsumerJoinBudgetMs = 2'000;

    SparkEngine();
    ~SparkEngine();
    SparkEngine(const SparkEngine&) = delete;
    SparkEngine& operator=(const SparkEngine&) = delete;

    /// Register the watch mechanism for an event-driven spark type (File /
    /// Registry / Service). MUST be called before start(). Production wires the
    /// platform factories (make_file_mechanism / make_registry_mechanism);
    /// tests wire a fake. With NO mechanism registered for a type, arm() of
    /// that type is rejected — preserving the spark.hpp invariant "Armed means
    /// a watcher is running". Rejects a null mechanism, a timer-driven type
    /// (interval/startup/disk are the wheel's), a duplicate registration, and
    /// any call after start().
    [[nodiscard]] std::expected<void, std::string>
    register_mechanism(SparkType type, std::unique_ptr<ISparkMechanism> mechanism);

    /// Register a queued consumer. Its dispatch thread starts immediately;
    /// events flow once the engine starts and the consumer arms sparks.
    /// CAPTURE-LIFETIME CONTRACT (governance UP2-1): because a hung handler is
    /// DETACHED at shutdown (see unregister_consumer / stop()), its dispatch
    /// thread may still be executing `handler(ev)` after this engine — and its
    /// caller — return. Anything the handler CAPTURES (a plugin host, a network
    /// client, a Reflex context) must therefore be process-lifetime-stable, or
    /// its owner must outlive a possibly-detached dispatch. Capturing a
    /// stack/short-lived object by reference into a queued handler is a
    /// use-after-free waiting for a slow-handler shutdown.
    [[nodiscard]] std::expected<ConsumerId, std::string>
    register_consumer(std::string name, QueuedHandler handler,
                      std::size_t queue_cap = kDefaultQueueCap);

    /// Drop a consumer: disarms its subscriptions, then BOUNDED-joins its
    /// dispatch thread (kConsumerJoinBudgetMs). A handler still running past the
    /// budget (queued handlers may block on I/O) is DETACHED and counted
    /// (consumer_threads_detached) rather than hanging the caller — the detached
    /// thread touches only its own refcounted state, never the engine, so it is
    /// memory-safe. Never call from inside the consumer's own handler (self-join).
    void unregister_consumer(ConsumerId id);

    /// Arm a spark for queued delivery to `consumer`. Dedup: an equal spec
    /// already armed (by anyone) adds a subscription to the existing watcher.
    /// Rejects a malformed spec or an event-driven type with no registered
    /// mechanism (armed == a watcher is running).
    [[nodiscard]] std::expected<SubscriptionId, std::string> arm(ConsumerId consumer,
                                                                 SparkSpec spec);

    /// Arm a spark for INLINE delivery (see tier contract above). Core-internal.
    [[nodiscard]] std::expected<SubscriptionId, std::string> arm_inline(SparkSpec spec,
                                                                        InlineHandler handler);

    /// Remove one subscription; the watcher itself disarms when its last
    /// subscription goes. Unknown ids are ignored (idempotent).
    void disarm(SubscriptionId id);

    /// Start the mechanism threads. Interval/poll deadlines are (re)based on
    /// the start instant; startup sparks fire immediately. Single-shot.
    void start();

    /// Stop watchers (wheel + mechanisms), then consumer dispatch threads.
    /// PROMPT FOR WELL-BEHAVED HANDLERS ONLY: a queued handler that blocks past
    /// kConsumerJoinBudgetMs is DETACHED + counted rather than joined, so a hung
    /// handler can never hang agent shutdown (governance UP-1 / #1311 class).
    /// Undelivered queued events are dropped + counted. Idempotent.
    void stop();

    [[nodiscard]] bool is_running() const noexcept;

    [[nodiscard]] SparkEngineStats stats() const;

    /// Test seam: substitute the platform disk reader. Set BEFORE start().
    void set_disk_reader_for_test(DiskReaderFn reader);
    /// Test seam: lower the interval/poll cadence floor so tests run in ms.
    /// Set BEFORE any arm().
    void set_cadence_floor_for_test(std::uint64_t floor_ms);
    /// Test seam: shrink the per-consumer shutdown budget so the detach-a-hung-
    /// handler path (UP-1) is exercised in ms, not kConsumerJoinBudgetMs.
    void set_consumer_join_budget_for_test(std::uint64_t ms);
    /// Test seam: if set, invoked once inside register_consumer() right after
    /// its dispatch thread starts but before the consumers_ insert — lets a
    /// test deterministically force stop() into the exact
    /// register_consumer()/stop() race window instead of relying on a
    /// timing-dependent multi-threaded stress loop (governance Tr3kkR finding,
    /// PR #1927 review). Same set-then-use contract as the other test seams
    /// above: set before the register_consumer() call under test, no
    /// concurrent-access support.
    void set_register_race_hook_for_test(std::function<void()> hook);
    /// Test seam: if set, invoked once inside arm_impl() after the mechanism
    /// watch (if any) succeeds and before the post-insert consumer re-check —
    /// lets a test deterministically force unregister_consumer() into the M1
    /// ghost-subscription race window (#1994) instead of a timing-dependent
    /// stress loop. Same set-then-use contract as the other race-hook seams.
    void set_arm_race_hook_for_test(std::function<void()> hook);
    /// Test seam: if set, invoked once inside disarm() and
    /// unregister_consumer(), after mu_ is released and before the
    /// staleness-rechecked mechanism unwatch() call — lets a test
    /// deterministically force a concurrent equal-spec re-arm into the M2
    /// late-unwatch race window (#1994). Same set-then-use contract.
    void set_disarm_race_hook_for_test(std::function<void()> hook);

private:
    struct Subscriber {
        SubscriptionId id{0};
        SparkTier tier{SparkTier::Queued};
        ConsumerId consumer{0};  ///< Queued only
        InlineHandler inline_fn; ///< Inline only
        /// Startup sparks only: this subscriber has not yet received its
        /// one-shot. A late subscriber re-schedules the spark, but the fire is
        /// delivered ONLY to still-pending subscribers — an earlier subscriber
        /// never sees "startup" twice.
        bool startup_pending{true};
    };

    /// One deduped armed spark: the spec, its wheel schedule, its per-spark
    /// state, and every subscription fanned out from it.
    struct Armed {
        SparkSpec spec;
        std::uint64_t cadence_ms{0}; ///< floored interval/poll cadence
        std::uint64_t seq{0};
        std::chrono::steady_clock::time_point next_due{};
        bool scheduled{false};    ///< on the wheel (false once a one-shot fired)
        bool disk_latched{false}; ///< Disk sparks: poll-and-latch state
        /// A mechanism reported this event-driven spark's watch deaf after a
        /// successful arm (B1). Health-only: surfaced in stats, never blocks
        /// firing. Cleared when the mechanism reports recovery.
        bool faulted{false};
        std::vector<Subscriber> subs;
    };

    /// Delivery counters touched by consumer dispatch threads. Heap-owned via a
    /// shared_ptr the threads capture, so a DETACHED consumer thread (a handler
    /// that blocked past the shutdown budget, UP-1) can keep writing them safely
    /// after the engine is destroyed — the thread never dereferences the engine.
    struct DeliveryCounters {
        std::atomic<std::uint64_t> delivered{0};
        std::atomic<std::uint64_t> dropped{0};
        std::atomic<std::uint64_t> errors{0};
    };

    struct Consumer {
        std::string name;
        QueuedHandler handler;
        std::size_t cap{kDefaultQueueCap};
        std::mutex mu;
        std::condition_variable cv;
        std::deque<SparkEvent> queue;
        bool stopping{false};
        /// Bounded-shutdown signal: the dispatch thread sets `finished` + notifies
        /// `done_cv` on clean exit, so stop()/unregister can wait_for the budget
        /// then join-or-detach. A hung handler never sets it → we detach (UP-1).
        std::mutex done_mu;
        std::condition_variable done_cv;
        bool finished{false};
        std::thread thread;
    };

    std::expected<SubscriptionId, std::string> arm_impl(SparkSpec spec, Subscriber sub);
    /// Validate + normalise (cadence flooring). Returns the effective cadence
    /// (0 for the event-driven and startup types, which have no wheel cadence).
    std::expected<std::uint64_t, std::string> validate_and_floor(const SparkSpec& spec) const;
    [[nodiscard]] std::chrono::steady_clock::time_point
    initial_due(const SparkSpec& spec, std::uint64_t cadence_ms,
                std::chrono::steady_clock::time_point now) const;
    /// File / Registry / Service: serviced by a mechanism, never the wheel.
    [[nodiscard]] static bool is_event_driven(SparkType type) noexcept;
    /// The mechanism fire entry point: fan one event-driven fire out to every
    /// subscriber of `key`. Looks the key up + snapshots subs under mu_, then
    /// releases mu_ before delivering (an inline consumer that re-arms takes
    /// mu_ — delivering under it would deadlock). A key disarmed mid-flight is
    /// simply skipped. Distinct from the wheel's commit path, which also owns
    /// reschedule + per-subscriber startup semantics.
    void emit_event(const std::string& key, SparkData data);
    /// Mechanism health entry point (B1): a mechanism reports that a watch it had
    /// armed went deaf (faulted=true) or recovered (faulted=false). Folds the
    /// edge into Armed::faulted + the fault counter under mu_. Never blocks
    /// firing — health only. Called with the engine lock released.
    void report_fault(const std::string& key, bool faulted, std::string_view reason);
    void wheel_loop();
    void deliver(const SparkEvent& ev, const std::vector<Subscriber>& subs);
    /// Signal one consumer to stop (set stopping + notify). Non-blocking.
    static void signal_stop(const std::shared_ptr<Consumer>& consumer);
    /// Wait for one already-signalled consumer to finish until `deadline`, then
    /// join it; detach + count if it is still inside a handler at the deadline
    /// (UP-1). Caller holds NO lock.
    void await_consumer(const std::shared_ptr<Consumer>& consumer,
                        std::chrono::steady_clock::time_point deadline);
    /// signal_stop + await_consumer against a fresh per-consumer budget (the
    /// single-consumer path, unregister_consumer). Idempotent per consumer.
    void quiesce_consumer(const std::shared_ptr<Consumer>& consumer);
    /// Static (captures no `this`): a detached consumer thread must reference only
    /// the two shared_ptrs it was handed, so it stays memory-safe after the engine
    /// dies (UP-1).
    static void consumer_loop(std::shared_ptr<Consumer> consumer,
                              std::shared_ptr<DeliveryCounters> counters);

    // armed sparks + subscription index + wheel state, all under mu_.
    mutable std::mutex mu_;
    /// Serializes every mechanism watch()/unwatch() call engine-wide (#1994
    /// M2). Without this, a disarm()'s pending unwatch(key) and a concurrent
    /// re-arm's watch(key) for an equal spec can interleave out of order —
    /// the late unwatch tears down the fresh watch while armed_ still shows
    /// the key armed. Each call site re-checks armed_'s current state for the
    /// key WHILE HOLDING this lock, immediately before issuing the mechanism
    /// call, so the mechanism call always reflects the freshest armed_ state.
    /// Lock order: mech_ops_mu_ → mu_, NEVER reversed; mechanism worker
    /// threads (wheel/IOCP/TP_WAIT callbacks) call emit()/fault() with their
    /// own internal lock released and never touch mech_ops_mu_, so there is no
    /// cycle. REQUIRES (Stage-2 trap, enforced by convention): a mechanism must
    /// deliver emit()/fault() ASYNCHRONOUSLY — off the watch()/unwatch() call
    /// stack, from its own thread. A mechanism that fired emit() synchronously
    /// from inside watch(), reaching an inline consumer that re-arms, would
    /// re-enter arm_impl → mech_ops_mu_ and self-deadlock this non-recursive
    /// lock. All shipped mechanisms emit from worker threads, so this holds
    /// today; a future mechanism author must preserve it (cpp-safety Gate 3).
    /// Coarsened to per-engine (not per-key): arm/disarm are rare
    /// control-plane operations, so a mechanism call briefly blocking another
    /// unrelated key's arm/disarm is an acceptable trade for not needing
    /// per-key generation tokens. KNOWN COUPLING (accepted, tracked): because
    /// this is ONE engine-wide lock rather than per-mechanism, a slow
    /// watch() on one mechanism blocks a concurrent unwatch() on a DIFFERENT
    /// mechanism (e.g. File blocking Registry) that was fully independent
    /// before. The "acceptable" defence rests on a BOUNDED worst-case watch(),
    /// but that bound is WEAK and FILE-ONLY: spark_file's arm_ancestor deadline
    /// (#1980) checks the 500ms budget BETWEEN probes, and fs::is_directory is
    /// uninterruptible — so a single hung probe on a dead UNC/network path
    /// holds this lock for the full OS network timeout (tens of seconds), not
    /// ~500ms; the deadline bounds the NUMBER of slow probes to ~one, not the
    /// wall-clock of any one probe (unhappy-path UP-1). Registry (TP_WAIT) and
    /// Service (SCM query) watch latencies are entirely UNCHARACTERISED — a hung
    /// SCM RPC in Service::watch() would stall this engine-wide lock with no
    /// bound at all (architect Gate 3). Truly bounding this needs the
    /// walk-off-mu_ (probe on a separate thread) restructure — the deferred
    /// follow-up below.
    /// Only same-mechanism watch/unwatch were serialised previously (by each
    /// mechanism's own internal lock); this adds cross-mechanism serialisation
    /// that Stage 2's simultaneous File+Registry+Service guards will exercise.
    /// Correctness needs only same-KEY ordering; per-mechanism-type granularity
    /// drops the cross-mechanism coupling for modest extra bookkeeping — this
    /// is a HARD GATE before Stage 2 wires the SECOND live mechanism under
    /// load, not an open-ended backlog item.
    mutable std::mutex mech_ops_mu_;
    std::condition_variable wheel_cv_;
    std::map<std::string, Armed> armed_; ///< by spark_key
    std::map<SubscriptionId, std::string> sub_keys_;
    bool running_{false};
    /// Atomic (not just mu_-guarded, though every write and most reads still
    /// hold mu_ too): register_consumer() must re-check this under
    /// consumers_mu_ — a DIFFERENT mutex — to close the race where stop() lands
    /// between its stopped_ check and its consumers_ insert (governance Tr3kkR
    /// finding, PR #1927 review). Atomic gives that cross-mutex read a defined
    /// value without relying on a same-thread mu_-then-consumers_mu_ publish
    /// argument that a future refactor could silently break.
    std::atomic<bool> stopped_{false};
    std::thread wheel_thread_;
    std::uint64_t next_id_{1}; ///< shared consumer/subscription id counter

    /// Event-driven watch mechanisms by type. Registered before start(),
    /// structurally stable thereafter (entries never added/removed until
    /// destruction), so a raw pointer captured under mu_ stays valid for any
    /// operation. Mechanism methods (start/watch/unwatch/stop) are ALWAYS
    /// invoked with mu_ released — they may block on OS handle setup.
    std::map<SparkType, std::unique_ptr<ISparkMechanism>> mechanisms_;

    mutable std::mutex consumers_mu_;
    std::map<ConsumerId, std::shared_ptr<Consumer>> consumers_;

    DiskReaderFn disk_reader_; ///< test seam; null = read_disk_level (set before start; the
                               ///< wheel snapshots it once at thread start — set-then-start)
    std::atomic<std::uint64_t> cadence_floor_ms_{kMinCadenceMs}; ///< atomic: read at arm, set by test seam
    std::atomic<std::uint64_t> consumer_join_budget_ms_{kConsumerJoinBudgetMs}; ///< test seam
    std::function<void()> register_race_hook_for_test_; ///< test seam; null = no-op (set-then-use)
    std::function<void()> arm_race_hook_for_test_;      ///< test seam; null = no-op (set-then-use)
    std::function<void()> disarm_race_hook_for_test_;   ///< test seam; null = no-op (set-then-use)

    // Delivery counters touched by consumer dispatch threads live in a shared
    // block so a detached thread can write them after ~SparkEngine (UP-1). The
    // producer-side drop-oldest path (deliver, on watcher threads joined before
    // destruction) writes the same block via this handle.
    std::shared_ptr<DeliveryCounters> delivery_{std::make_shared<DeliveryCounters>()};
    std::atomic<std::uint64_t> consumer_threads_detached_{0};
    std::atomic<std::uint64_t> watch_faults_{0}; ///< monotonic mechanism fault-report count

    // Counters updated outside mu_ (delivery paths) — atomics.
    std::atomic<std::uint64_t> events_total_{0};
    std::atomic<std::uint64_t> inline_calls_{0};
    std::atomic<std::uint64_t> inline_errors_{0};
    std::atomic<std::uint64_t> inline_us_total_{0};
    std::atomic<std::uint64_t> inline_us_max_{0};
    std::atomic<std::uint64_t> inline_over_100us_{0};
    std::atomic<std::uint64_t> inline_over_10ms_{0};
};

} // namespace yuzu::agent
