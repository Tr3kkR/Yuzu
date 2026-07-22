#pragma once

/**
 * guardian_spark_runtime.hpp - the shared, lifetime-safe core of the Guardian
 * spark consumer (ADR-0021 Stage 2 rung 3). Design:
 * docs/spark-stage2-guardian-consumer-design.md.
 *
 * This is the object the SparkEngine queued handler captures - and ONLY this. A
 * queued handler that blocks past the shutdown budget is DETACHED and may run
 * after GuardianEngine and the SparkEngine are gone (spark_engine.hpp capture-
 * lifetime contract). So the handler captures a shared_ptr<GuardianSparkRuntime>
 * that owns everything it touches (registry, per-key state, readers, outbox); it
 * never captures GuardianEngine, the SparkEngine, or the server sink by raw
 * reference. Emits go to the in-memory outbox, never straight to a sink, so a
 * detached late handler is memory-safe: it mutates only runtime-owned state.
 *
 * Concurrency model (Sol's rev-2 shape; the orchestration review BLOCKED the
 * naive version):
 *   - ONE evaluate_key(key, reason) for initial / event / convergence. Events are
 *     invalidation HINTS: evaluate_key always re-reads live state via the
 *     StateReader, never trusts a queued payload (prevents a stale queued value
 *     committing backward).
 *   - Per-key eval mutex held across read+commit, so read order == commit order
 *     for a key and the freshest read commits last (no backward compliance).
 *   - registry mutex guards the index / rule generations / per-key maps + the
 *     stopping flag; held only for brief, IO-free snapshot and commit sections.
 *   - Monotonic per-rule generations: a rule update installs a NEW
 *     RuleGeneration (never mutates one in place), so an in-flight eval on the
 *     old generation finishes harmlessly and its commit is rejected by a
 *     generation/active recheck.
 *   - Tri-state Unknown (guardian_rule_eval.hpp) leaves decider state untouched
 *     and routes a health event; a Known read commits a compliance verdict.
 *
 * LOCK ORDER (total, never inverted): drain_mu_  ->  per-key eval_mu  ->
 * registry_mu_  ->  outbox_mu_. Registry mutations take registry_mu_ -> outbox_mu_.
 * The drain (item 4) takes drain_mu_ (single-drainer), then CYCLES outbox_mu_ per
 * entry - copy the head, RELEASE outbox_mu_, run the injected send off-lock, re-acquire,
 * pop-if-unchanged - so a slow send never holds outbox_mu_. The send fn MAY take runtime
 * locks (e.g. outbox_size()) since outbox_mu_ is released across it, but it must NOT
 * re-enter drain() (drain_mu_ is non-recursive).
 *
 * Rung 3 builds this against FAKE seams (IStateReader, ISparkBackend). The real
 * platform readers are rung 5; the convergence scheduler that also drives
 * evaluate_key is rung 4; the unified reconcile op (merge / full-sync / kill-
 * switch / mutual-exclusion) and the agent wiring are rung 7.
 */

#include <yuzu/plugin.h>        // YUZU_EXPORT
#include <yuzu/agent/spark.hpp> // SparkSpec, SparkEvent, SparkType, ServiceRunState

#include "guardian_journal_format.hpp" // JournalRecord + caps (item 7 PR-Ag)
#include "guardian_outbox.hpp"
#include "guardian_rule_eval.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <vector>

namespace yuzu::agent {

class SparkKeyRuleIndex; // spark_key_rule_index.hpp (fwd - kept out of this header's include set)

/// Why an evaluation is running. Initial and Convergence come from the runtime /
/// scheduler; Event comes from a SparkEvent hint. The verdict path is identical
/// (always a live re-read); the reason only tunes pending-initial bookkeeping.
enum class EvalReason { Initial, Event, Convergence };

/// What the file reader must resolve for a key. One watcher serves rules with
/// different caps, so the reader hashes ONCE at the largest admitting cap and the
/// evaluator projects oversize per-rule. hash_cap == 0 means no rule on the key
/// hashes (file-exists only) - skip hashing.
struct FileReadPlan {
    std::uint64_t hash_cap{0}; ///< max max_bytes over the key's file-hash rules; 0 = no hash needed
};

/// What the registry reader must resolve for a key. Rules under ONE (hive,key)
/// spark_key may watch DIFFERENT values, so the reader reads each requested value
/// (memoised per value_name) and returns a per-value map; the evaluator selects
/// its rule's value_name. Reading one snapshot and fanning it to all rules would
/// be wrong for a multi-value key.
struct RegistryReadPlan {
    std::vector<std::string> value_names; ///< distinct values to read under the key
};

/// The registry reader's result: a per-value_name read plus the measured latency
/// (registry is the one type that records detection_latency_us for parity). A key
/// that could not be opened fills every requested value_name with Unknown.
struct RegistryRead {
    std::unordered_map<std::string, ReadResult<RegistrySnapshot>> values;
    std::uint64_t latency_us{0};
};

/// The runtime's view of live endpoint state. Rung 5 supplies the platform
/// readers (file handle-scoped #807, registry RegOpenKeyExW, service SCM/sd-bus);
/// tests supply fakes.
///
/// CONTRACT for implementers (rung 5):
///   - A method returns Unknown (ReadResult.known == false) when it cannot
///     determine the value - never a fabricated absent/stopped.
///   - MUST be thread-safe: the convergence lanes and the consumer handler call it
///     concurrently for different keys (each call gets its own params/plan).
///   - MUST be bounded / cancellable: a read participates in shutdown (a lane join
///     and the consumer detach both wait on an in-flight read), so a platform call
///     that can block indefinitely (SCM, sd-bus, a filesystem stall) must carry a
///     timeout and degrade to Unknown rather than hang agent shutdown.
///   - MUST implement request_stop(): begin_stop() calls it (outside the runtime's
///     lock) so an in-flight / future read wakes and degrades to Unknown instead of
///     blocking a lane join or the consumer detach.
class IStateReader {
public:
    virtual ~IStateReader() = default;
    virtual ReadResult<FileSnapshot> read_file(const FileSparkParams& p, const FileReadPlan& plan) = 0;
    virtual RegistryRead read_registry(const RegistrySparkParams& p, const RegistryReadPlan& plan) = 0;
    virtual ReadResult<ServiceRunState> read_service(const ServiceSparkParams& p) = 0;
    /// Wake any waiting read and reject new ones so shutdown does not hang. Does NOT
    /// cancel a detached OS call already in a kernel syscall (that cannot be
    /// cancelled or joined); it decouples the waiter, which degrades to Unknown.
    /// MUST be idempotent and MUST NOT throw - the `noexcept` is load-bearing since
    /// begin_stop() runs from ~GuardianSparkRuntime(), where an escaping exception
    /// would std::terminate (the implementer must contain any exception itself, not
    /// merely avoid causing one). MUST NOT block on I/O or an unbounded wait; a
    /// short lock-protected critical section over in-memory state (no syscalls) is
    /// acceptable and is what GuardianStateReader does - this is not a wait-free /
    /// hard-realtime guarantee.
    virtual void request_stop() noexcept = 0;
};

/// The runtime's view of the spark backend: arm a watcher for a spec (returns the
/// per-key SubscriptionId) and disarm it. The production adapter binds the
/// runtime's ConsumerId to SparkEngine::arm/disarm (rung 7); tests fake it.
/// Uses a plain uint64 SubscriptionId so this header need not include
/// spark_engine.hpp.
class ISparkBackend {
public:
    virtual ~ISparkBackend() = default;
    virtual std::expected<std::uint64_t, std::string> arm(const SparkSpec& spec) = 0;
    virtual void disarm(std::uint64_t subscription) = 0;
};

/// Injected monotonic clock (steady). Tests supply a deterministic source; the
/// default is steady_clock::now.
using RuntimeClock = std::function<std::chrono::steady_clock::time_point()>;

class YUZU_EXPORT GuardianSparkRuntime : public std::enable_shared_from_this<GuardianSparkRuntime> {
public:
    /// A recovery emits a PAIR of entries (guard.healthy + the verdict) that
    /// enqueue_all lands atomically, so the outbox must always hold at least two -
    /// a smaller cap would reject every recovery forever (permanent health-recovery
    /// loss). The constructor floors the configured capacity at this.
    static constexpr std::size_t kMinOutboxCapacity = 2;

    struct Config {
        std::size_t outbox_capacity{4096};
    };

    /// The runtime OWNS the reader and backend (shared_ptr): a queued handler that
    /// is detached at shutdown may run past GuardianEngine, so keeping the captured
    /// runtime alive must transitively keep everything the handler touches alive -
    /// a borrowed reader reference would UAF the moment the agent destroyed it under
    /// a detached mid-read. The clock callable must likewise be self-contained (the
    /// default captures nothing); a clock that borrows agent state reintroduces the
    /// same hazard.
    GuardianSparkRuntime(std::shared_ptr<IStateReader> reader,
                         std::shared_ptr<ISparkBackend> backend);
    GuardianSparkRuntime(std::shared_ptr<IStateReader> reader,
                         std::shared_ptr<ISparkBackend> backend, Config cfg,
                         RuntimeClock clock = RuntimeClock{});
    ~GuardianSparkRuntime();
    GuardianSparkRuntime(const GuardianSparkRuntime&) = delete;
    GuardianSparkRuntime& operator=(const GuardianSparkRuntime&) = delete;

    /// Build the SparkEngine queued handler for `rt`. It captures the shared_ptr
    /// (detach-safe) and routes each event to on_event. Static so the capture is
    /// unambiguously the shared_ptr and nothing else.
    static std::function<void(const SparkEvent&)> make_handler(std::shared_ptr<GuardianSparkRuntime> rt);

    /// Attach a rule: index it under spark_key(spec), arm the watcher on the
    /// key's 0->1 edge, and mark it pending its initial eval. Replaces any prior
    /// mapping for the same rule_id (a fresh generation + fresh eval state - the
    /// reconcile op at rung 7 is what preserves state across an identical
    /// re-push). Returns the new generation on success; an error string if the
    /// backend refused to arm (the rule is left errored, NOT silently legacy -
    /// mutual exclusion). IO-free apart from the backend arm.
    std::expected<std::uint64_t, std::string> attach_rule(std::string rule_id, SparkSpec spec,
                                                          RuleAssertion assertion,
                                                          bool emit_compliant_edge);

    /// Detach a rule: drop it from the index, disarm the watcher on the key's ->0
    /// edge, mark its generation inactive, and purge its buffered outbox entries.
    /// Idempotent for an unknown rule.
    void detach_rule(const std::string& rule_id);

    /// Detach EVERY currently-attached rule (mirrors GuardianEngine's legacy
    /// stop_all_guards_locked()). For the reconcile op's full_sync branch: a
    /// full sync replaces the active set, so any spark-attached rule the new
    /// push omits must be withdrawn too, not just the ones the per-rule loop
    /// revisits. Equivalent to calling detach_rule() for every attached rule_id,
    /// but atomic under one registry_mu_ acquisition.
    void detach_all();

    /// The queued-handler body: resolve `ev.key` to its rules and run one
    /// evaluate_key(Event) pass. Safe to call on a detached thread post-shutdown
    /// (it observes the stopping flag and commits nothing).
    void on_event(const SparkEvent& ev);

    /// Evaluate every active rule on `key` against a single live re-read. The sole
    /// eval path for all reasons. Serialised per key; commits a verdict to the
    /// outbox (or a health event on Unknown). No-op if stopping or the key is gone.
    void evaluate_key(const std::string& key, EvalReason reason);

    /// Drain buffered emits through `send`. `send(const OutboxEntry&) -> SendResult`.
    /// Drains the Lifecycle audit log FIRST, then (only if it fully cleared) the
    /// compliance/health outbox - distinct structures internally (see
    /// GuardianLifecycleLog) but one send callback suffices since `send` can switch on
    /// OutboxEntry::domain. Holds drain_mu_ (single-drainer) and CYCLES outbox_mu_ per
    /// entry - the send runs with outbox_mu_ RELEASED (item 4), so a slow send never
    /// blocks enqueuers/heartbeat. The drain trigger (sink publication + reconnect +
    /// live wake-on-enqueue) is wired at rung 7; this is the mechanism. Returns the
    /// number SENT (not removed - a coalesced head counts as sent but is not popped).
    ///
    /// `limits` bounds ONE pass. Bounding exists because the caller's thread may carry
    /// OTHER periodic work (C0 #2298: the drain worker also runs journal retention).
    /// Unbounded, a slow stream drains the whole window - up to 4096 lifecycle entries -
    /// head-of-line blocking that work; on a slow link that starves retention until the
    /// journal hits its write ceiling and DROPS audit records. A caller that bounds a pass
    /// should re-drain immediately while `truncated` comes back true.
    struct DrainLimits {
        /// 0 = unbounded (the historical behaviour).
        std::size_t max_entries{0};
        /// Wall-clock cap on one pass, checked between sends. 0 = unbounded. A COUNT bound
        /// alone is not a safety bound: one slow-but-succeeding send makes an N-entry pass
        /// arbitrarily long, and the caller may be holding up a join (#2298 Sol review).
        std::chrono::milliseconds max_wall{0};
        /// Checked BEFORE every send. Lets a caller stop starting new sends the moment
        /// shutdown is requested rather than at the end of a whole bounded pass. The
        /// in-flight send is not interruptible; no further one begins.
        std::function<bool()> should_stop{};
        /// Fraction reserved for the compliance/health outbox so a busy lifecycle log cannot
        /// consume the entire pass. Applies to BOTH dimensions: the entry count and (gated on
        /// `max_wall > 0`, not on `max_entries`) the wall clock. The guarantee is that
        /// compliance gets an opportunity to START - not a slice of time, since an in-flight
        /// send cannot be interrupted. Unused lifecycle allowance rolls
        /// over, so this costs nothing when lifecycle is quiet. Load-bearing: draining
        /// lifecycle first with a SHARED budget silently recreated the detection blackout
        /// that Gate 4 UP-3 removed - compliance simply never ran (#2298 Sol review).
        std::size_t compliance_reserve_num{1};
        std::size_t compliance_reserve_den{2};
    };
    struct DrainOutcome {
        std::size_t sent{0};
        /// A limit cut the pass short (count, wall-clock, or should_stop) and entries may
        /// remain. The caller should re-drain without waiting rather than sleep.
        bool truncated{false};
    };
    /// Free slots in the lifecycle send window, sampled without a lock held by the caller.
    /// Used by the replay path as a pure OPTIMISATION - to avoid building entries for a batch
    /// that plainly cannot fit. It is NOT the authority on whether a batch was blocked: that
    /// comes back from try_page_batch's PageOutcome, decided under outbox_mu_, because this
    /// value can be stale by the time the attempt happens (#2345).
    [[nodiscard]] std::size_t lifecycle_headroom() const;
    /// Snapshot of the event_ids currently in the lifecycle send window, taken ONCE per replay
    /// pass. Lets the replay path size a candidate by its NET-NEW records rather than its raw
    /// entry count without taking outbox_mu_ per candidate. Same status as lifecycle_headroom():
    /// an optimisation, stale the moment it returns, never the authority - try_page_batch's
    /// PageOutcome decides under the lock (#2345 Gate 8 QE).
    [[nodiscard]] std::unordered_set<std::string> lifecycle_event_ids() const;

    std::size_t drain(const std::function<SendResult(const OutboxEntry&)>& send);
    DrainOutcome drain_bounded(const std::function<SendResult(const OutboxEntry&)>& send,
                               const DrainLimits& limits);

    // --- Durable lifecycle journal - staging seam (item 7 PR-Ag) ------------
    // Staging lives HERE (co-located with lifecycle_log_ under outbox_mu_) because
    // DISARM must stage inside detach_rule_locked. The KvStore-backed
    // persist/page/retention live in an engine-owned GuardianLifecycleJournal that
    // drives these via the narrow API below. The runtime NEVER touches a KvStore:
    // it is the detach-survival object and must OWN everything it touches (file
    // header), so the durable seam stays in the engine.

    /// A FIFO copy of the currently-staged (built + validated, not-yet-persisted)
    /// records. Immutable view; the caller serialises + writes them, then calls
    /// erase_persisted_prefix() for the count it durably wrote.
    /// `drops_at_snapshot`, when non-null, receives journal_stage_dropped() read UNDER the same
    /// lock as the snapshot - which is what makes erase_persisted_prefix able to identify the
    /// prefix it wrote rather than trust an index a concurrent overflow drop can shift.
    [[nodiscard]] std::vector<std::shared_ptr<const JournalRecord>>
    snapshot_pending(std::uint64_t* drops_at_snapshot = nullptr) const;

    /// Drop the oldest `n` staged records (those a persist just durably wrote).
    /// Clamped to the current size.
    /// TEST-ONLY: perform `n` overflow drop-oldest steps exactly as stage_pending_locked does
    /// at kMaxPendingJournalRecords (erase the front, count it). Reaching the real 4096-record
    /// ceiling from a test would need 4096 arms, which is why the interleaving that this
    /// models - a front-drop landing between snapshot_pending() and erase_persisted_prefix() -
    /// had no coverage. No production caller.
    void drop_oldest_pending_for_test(std::size_t n) {
        std::lock_guard<std::mutex> ob{outbox_mu_};
        n = std::min(n, pending_journal_.size());
        pending_journal_.erase(pending_journal_.begin(),
                               pending_journal_.begin() + static_cast<std::ptrdiff_t>(n));
        journal_stage_dropped_.fetch_add(n, std::memory_order_relaxed);
    }

    /// `drops_at_snapshot` is journal_stage_dropped() as read WITH the snapshot. It is what
    /// makes the erase identify the prefix rather than trust an index that a concurrent
    /// overflow drop can shift underneath it.
    void erase_persisted_prefix(std::size_t n, std::uint64_t drops_at_snapshot);

    /// Outcome of a page attempt, decided UNDER outbox_mu_ so it reflects the window as it
    /// actually was. A bare count could not distinguish "the window had no room for this
    /// batch" from "every entry was already a member" - opposite situations, and the caller
    /// needs the first to know a backlog is waiting (#2345 Gate 3).
    struct PageOutcome {
        std::size_t added{0};          ///< entries newly enqueued
        bool blocked_for_headroom{false}; ///< the batch did not fit, atomically observed
        std::size_t required{0};       ///< entries the batch needed when blocked
    };
    /// Page a REPLAYED batch into the send window: iff the window has >= batch-size headroom,
    /// enqueue each entry NOT already present (window-scan membership, no allocating set).
    /// Paged entries enter lifecycle_log_ ONLY (they are already durable - never
    /// pending_journal_). Does NOT wake the drain; the caller drives sending.
    ///
    /// Reports WHY nothing was added via PageOutcome above: a bare count could not separate
    /// "no room for this batch" from "every entry already a member", and the caller needs the
    /// first to know a backlog is waiting (#2345).
    [[nodiscard]] PageOutcome try_page_batch(std::vector<OutboxEntry> entries);

    /// Back-fill provenance onto the LIVE window entries of a just-persisted batch (review M3),
    /// so a live send writes its sent-label rather than the batch later ageing out counted
    /// evicted_without_send_evidence. Called from the engine persist boundary; takes outbox_mu_.
    /// `event_ids` are the batch's records in order; `last_event_id` is its last-in-batch record.
    void backfill_batch_provenance(const std::string& batch_key,
                                   const std::vector<std::string>& event_ids,
                                   const std::string& last_event_id);

    /// Current staged-record depth (gauge). Takes outbox_mu_.
    [[nodiscard]] std::size_t pending_journal_depth() const;

    // Staging integrity counters (design §2 loss table). Lock-free.
    [[nodiscard]] std::uint64_t journal_stage_dropped() const noexcept {
        return journal_stage_dropped_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t journal_stage_failures() const noexcept {
        return journal_stage_failures_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t journal_field_rejected() const noexcept {
        return journal_field_rejected_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t journal_clock_rejected() const noexcept {
        return journal_clock_rejected_.load(std::memory_order_relaxed);
    }
    /// Repeat Unknown evaluations whose guard.unhealthy was edge-suppressed (M1): a rule
    /// stuck errored is re-evaluated every convergence tick to catch recovery, but only the
    /// first Unknown of an episode emits a health event. Non-zero means at least one rule is
    /// persistently errored - the count is the number of ticks NOT flooded onto the wire.
    [[nodiscard]] std::uint64_t unhealthy_suppressed() const noexcept {
        return unhealthy_suppressed_.load(std::memory_order_relaxed);
    }

    /// Phase 1 of shutdown: set the stopping flag and mark every generation
    /// inactive under the registry lock, so no in-flight or late eval commits.
    /// Does NOT join threads (the SparkEngine consumer join is phase 2, owned by
    /// the caller at rung 7). Idempotent.
    void begin_stop();

    // --- Telemetry / introspection (rung 3: enough to test; rung 8 adds the
    // spark_unsupported heartbeat gauge). All take the registry lock. ---
    [[nodiscard]] std::size_t armed_key_count() const;
    [[nodiscard]] std::size_t rule_count() const;
    [[nodiscard]] std::size_t outbox_size() const;
    [[nodiscard]] std::uint64_t outbox_backpressure_drops() const;
    /// rule_ids still awaiting a first Known eval on `key` (the pending-initial
    /// dirty-set the convergence priority lane services).
    [[nodiscard]] std::vector<std::string> pending_initial(const std::string& key) const;
    [[nodiscard]] bool stopping() const;

    /// A live status snapshot for one currently-attached rule, reflecting the
    /// LAST COMMITTED eval outcome (not a fresh re-read - matching every other
    /// introspection method here). `in_unknown` true means the last committed
    /// read was Unknown (the rule is errored, not compliant/drifted).
    /// `last_compliant` is nullopt until the first Known verdict ever commits.
    struct RuleStatusSnapshot {
        bool in_unknown{false};
        std::optional<bool> last_compliant;
    };
    /// nullopt if rule_id is not attached here (unknown to the runtime - e.g.
    /// legacy-armed, invalid, or never pushed; the reconcile op / GuardianEngine
    /// owns the wider status picture across both backends, rung 7.5).
    [[nodiscard]] std::optional<RuleStatusSnapshot> status_for_rule(const std::string& rule_id) const;

    // --- Convergence-scheduler seam (rung 4) ---
    /// Armed spark_keys whose spec is `type` - the lane a convergence thread
    /// sweeps on its own cadence (so a slow file hash never blocks a service
    /// reconcile).
    [[nodiscard]] std::vector<std::string> keys_for_type(SparkType type) const;
    /// Armed keys that still carry a pending-initial rule (the priority lane's
    /// work-list).
    [[nodiscard]] std::vector<std::string> keys_with_pending_initial() const;
    /// Install a waker the runtime invokes (OUTSIDE its lock) whenever a rule is
    /// newly attached with a pending initial eval, so the scheduler can service
    /// it immediately rather than waiting a full cadence. Pass {} to clear (the
    /// scheduler clears it before it tears down).
    void set_pending_initial_waker(std::function<void()> waker);
    /// Test seam: a copy of the currently-installed waker, to exercise the
    /// copied-waker-outlives-scheduler lifetime path.
    [[nodiscard]] std::function<void()> pending_initial_waker_for_test() const;

    // --- Live-drain seam (rung 7, F6) ---
    /// Install a waker the runtime invokes (OUTSIDE its lock, same lifetime-
    /// safety shape as set_pending_initial_waker) whenever ANY outbox mutation
    /// happens - a compliance/health commit in evaluate_key's commit section, OR
    /// a Lifecycle armed/disarmed enqueue in attach_rule/detach_rule. Called
    /// unconditionally after any such mutation (not gated on "was this truly a
    /// new key vs a coalesce" - a coalesced-in-place update is still fresh data
    /// waiting to be sent, and an extra CV wake is harmless, whereas under-
    /// waking risks steady-state staleness with no bounded recovery). Lets
    /// GuardianEngine's drain worker (rung 7.5) wake immediately instead of
    /// waiting for the next reconnect or periodic tick. Pass {} to clear.
    void set_outbox_enqueue_waker(std::function<void()> waker);
    /// Test seam: a copy of the currently-installed waker.
    [[nodiscard]] std::function<void()> outbox_enqueue_waker_for_test() const;
    /// Count of Lifecycle audit entries rejected for capacity (arm/disarm still
    /// succeeds regardless - the audit trail never blocks a real detection-
    /// capability change - but a drop here must be loudly observable, never
    /// silent). Takes only the outbox lock.
    [[nodiscard]] std::uint64_t lifecycle_backpressure_drops() const;

    /// Cumulative count of drain sends that THREW (caught in drain(); the head is
    /// retained and that log's drain stops). A nonzero value means an entry could not be
    /// serialized/sent (e.g. a permanently-failing entry jamming the head, not just a
    /// stream-down Retain) - surfaced via the heartbeat by item 9. Lock-free.
    [[nodiscard]] std::uint64_t send_exception_count() const noexcept {
        return send_exceptions_.load(std::memory_order_relaxed);
    }

    /// Install the source of THIS agent's id, folded into every event_id so the
    /// server's global `event_id` PRIMARY KEY (drops on UNIQUE conflict, #1307)
    /// does not treat two agents drifting on the same rule - or the same agent
    /// after a restart - as duplicate events. A provider (not a fixed string)
    /// because the agent_id is empty pre-Register and populated later; default is
    /// empty (rung 7 wires the real provider after Register).
    ///
    /// The provider MUST be self-contained (process-lifetime-safe captures), like
    /// the clock: the runtime snapshots it at pass start so it is not called on the
    /// detached-post-read path, but a provider that borrows agent state and is
    /// invoked before a shutdown completes is still a hazard.
    void set_agent_id_provider(std::function<std::string()> provider);

private:
    /// Per-rule generation: an immutable assertion/spec-edge + monotonic
    /// generation + the mutable eval state. Held by shared_ptr so an in-flight
    /// eval keeps it alive across the registry-lock release; a rule update
    /// installs a NEW one rather than mutating fields, so eval() (which mutates
    /// `eval`) races nothing.
    struct RuleGeneration {
        std::uint64_t generation{0};
        bool active{true};            ///< registry_mu_-guarded; false once withdrawn / stopping
        bool emit_compliant_edge{true};
        RuleAssertion assertion;
        RuleEvalState eval;           ///< mutated only under the key's eval_mu (single serialisation domain)
    };

    /// Per-spark_key shared-watcher state. One armed watcher per key (the engine
    /// dedups); SubscriptionId is PER-KEY. `eval_mu` serialises a whole
    /// evaluate_key pass (read + fan-out + commit) for this key. Heap-stable
    /// (shared_ptr) because it holds a mutex.
    struct PerKey {
        SparkSpec spec;
        std::uint64_t subscription{0};
        std::mutex eval_mu;
        std::set<std::string> pending_initial; ///< rule_ids awaiting a first Known eval (registry_mu_-guarded)
    };

    // Helpers (all assume the documented lock discipline; see the .cpp).
    void detach_rule_locked(const std::string& rule_id); // registry_mu_ held
    EvalOutcome eval_rule(const SparkSpec& spec, const RuleAssertion& a, RuleEvalState& state,
                          std::chrono::steady_clock::time_point now, bool edge,
                          const ReadResult<FileSnapshot>* file,
                          const RegistryRead* reg,
                          const ReadResult<ServiceRunState>* svc);
    /// The outbox entries an outcome requires (0, 1, or 2): a recovery emits
    /// guard.healthy AND the verdict, which enqueue_all lands atomically. Called
    /// under registry_mu_ (make_event_id needs it).
    std::vector<OutboxEntry> build_entries(const RuleGeneration& gen, const EvalOutcome& out,
                                           const std::string& agent_id);
    /// Mint a wire event_id: `<agent_id>-<nonce>-<rule_id>-<wall_ms>-<seq>`
    /// (registry_mu_ held). agent_id (snapshotted at pass start) distinguishes
    /// agents, the boot nonce distinguishes restarts, wall_ms + seq distinguish
    /// observations - closing the collision the server's event_id PK would drop on.
    std::string make_event_id(const std::string& rule_id, std::int64_t wall_ms,
                              const std::string& agent_id);
    /// Build + buffer a Lifecycle("armed"|"disarmed") entry for `rule_id` into
    /// lifecycle_log_ (registry_mu_ held - make_event_id needs it) and return
    /// whether it was accepted (false => capacity; caller counts/logs, never
    /// rolls back the arm/disarm itself). Snapshots agent_id_fn_ itself (no
    /// separate pass-in needed - this is never called from the detached-read
    /// path, only from attach_rule/detach_rule_locked which already hold the
    /// lock and are not blocking-I/O call sites).
    bool enqueue_lifecycle_locked(const std::string& rule_id, std::uint64_t generation,
                                  const std::string& kind, const std::string& guard_type,
                                  const std::string& rule_name);
    /// Build + validate a durable JournalRecord (may throw bad_alloc on the string
    /// copies - the caller decides whether that propagates). Returns nullptr if the
    /// record is not journalable, counting the reason (field vs clock rejection).
    std::shared_ptr<JournalRecord> build_journal_record(
        const std::string& rule_id, std::uint64_t generation, const std::string& event_id,
        std::int64_t enqueued_ns, const std::string& kind, const std::string& guard_type,
        const std::string& rule_name);
    /// Append a record to the bounded pending_journal_ reserve (outbox_mu_ held).
    /// NOEXCEPT: the reserve is fixed at construction so push_back never reallocates;
    /// overflow drops the oldest and counts journal_stage_dropped. A null record is a
    /// no-op (it was rejected at build).
    void stage_pending_locked(std::shared_ptr<JournalRecord> record) noexcept;

    std::shared_ptr<IStateReader> reader_;   ///< OWNED: outlives any detached handler
    std::shared_ptr<ISparkBackend> backend_; ///< OWNED
    RuntimeClock clock_;
    std::uint64_t gen_counter_{0};   ///< registry_mu_-guarded monotonic generation source
    std::uint64_t event_seq_{0};     ///< registry_mu_-guarded event_id source
    std::string boot_nonce_;         ///< random, fixed at construction; disambiguates event_ids across
                                     ///< process restarts (wall_ms + seq alone are not restart-unique)

    mutable std::mutex registry_mu_;
    bool stopping_{false};
    std::function<void()> pending_initial_waker_; ///< registry_mu_-guarded; called outside the lock
    /// registry_mu_-guarded (same pattern as pending_initial_waker_ above, NOT
    /// outbox_mu_ - every call site that needs to copy+invoke it already holds
    /// registry_mu_: evaluate_key's commit section, attach_rule, detach_rule[_locked]).
    /// Called outside BOTH locks after any outbox_/lifecycle_log_ mutation.
    std::function<void()> outbox_enqueue_waker_;
    std::function<std::string()> agent_id_fn_;    ///< registry_mu_-guarded; empty until rung 7 wires it
    std::unique_ptr<SparkKeyRuleIndex> index_;                          // key <-> rule fan-out + refcount
    std::unordered_map<std::string, std::shared_ptr<RuleGeneration>> rules_; // rule_id -> generation
    std::unordered_map<std::string, std::shared_ptr<PerKey>> keys_;          // spark_key -> per-key

    mutable std::mutex outbox_mu_;
    GuardianOutbox outbox_;
    GuardianLifecycleLog lifecycle_log_; ///< capacity set in the ctor init list (see the .cpp)
    /// Durable-journal staging: built + validated records awaiting persist. Bounded
    /// (kMaxPendingJournalRecords), reserved ONCE in the ctor, drop-oldest on overflow.
    /// outbox_mu_-guarded (co-located with lifecycle_log_); in practice mutated only by
    /// mtx_-serialised engine paths (reconcile stage + persist), never by the drain.
    std::vector<std::shared_ptr<JournalRecord>> pending_journal_;
    std::atomic<std::uint64_t> journal_stage_dropped_{0};  ///< overflow drop-oldest (disk-full backpressure)
    std::atomic<std::uint64_t> journal_stage_failures_{0}; ///< disarm record un-buildable post-teardown
    std::atomic<std::uint64_t> journal_field_rejected_{0}; ///< NUL/oversized/non-UTF-8 field kept out
    std::atomic<std::uint64_t> journal_clock_rejected_{0}; ///< skewed clock (secs<=0) kept out (rev-4.1 #2)
    // Serialises drain() calls WITHOUT blocking enqueuers (they take outbox_mu_, not
    // this): drain() releases outbox_mu_ across each send, so two concurrent drainers
    // could otherwise both peek+send the same head. drain_once() is public, so this is
    // load-bearing, not just belt-and-braces (item 4). NOTE: a send callback must never
    // re-enter drain() (it would self-deadlock on this mutex); none does.
    std::mutex drain_mu_;
    std::atomic<std::uint64_t> send_exceptions_{0}; ///< drain sends that threw (item 4 hardening)
    std::atomic<std::uint64_t> unhealthy_suppressed_{0}; ///< repeat Unknown evals whose guard.unhealthy
                                                         ///< was edge-suppressed (rule stuck errored;
                                                         ///< NOT re-minted every ~5s convergence tick). M1.
};

} // namespace yuzu::agent
