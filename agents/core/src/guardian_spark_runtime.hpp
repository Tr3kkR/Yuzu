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
 * LOCK ORDER (total, never inverted): per-key eval_mu  ->  registry_mu_  ->
 * outbox_mu_. The outbox drain takes outbox_mu_ alone and its injected send fn
 * takes NO runtime lock. Registry mutations take registry_mu_ -> outbox_mu_.
 *
 * Rung 3 builds this against FAKE seams (IStateReader, ISparkBackend). The real
 * platform readers are rung 5; the convergence scheduler that also drives
 * evaluate_key is rung 4; the unified reconcile op (merge / full-sync / kill-
 * switch / mutual-exclusion) and the agent wiring are rung 7.
 */

#include <yuzu/plugin.h>        // YUZU_EXPORT
#include <yuzu/agent/spark.hpp> // SparkSpec, SparkEvent, SparkType, ServiceRunState

#include "guardian_outbox.hpp"
#include "guardian_rule_eval.hpp"

#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <mutex>
#include <set>
#include <string>
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
    /// MUST be idempotent and NONBLOCKING, and MUST NOT throw - begin_stop() runs
    /// from ~GuardianSparkRuntime(), so an escaping exception would std::terminate.
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

    /// The queued-handler body: resolve `ev.key` to its rules and run one
    /// evaluate_key(Event) pass. Safe to call on a detached thread post-shutdown
    /// (it observes the stopping flag and commits nothing).
    void on_event(const SparkEvent& ev);

    /// Evaluate every active rule on `key` against a single live re-read. The sole
    /// eval path for all reasons. Serialised per key; commits a verdict to the
    /// outbox (or a health event on Unknown). No-op if stopping or the key is gone.
    void evaluate_key(const std::string& key, EvalReason reason);

    /// Drain buffered emits through `send`. `send(const OutboxEntry&) -> SendResult`.
    /// The drain trigger (sink publication + reconnect) is wired at rung 7; this is
    /// the mechanism. Returns the number sent. Takes only the outbox lock.
    std::size_t drain(const std::function<SendResult(const OutboxEntry&)>& send);

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
    std::function<std::string()> agent_id_fn_;    ///< registry_mu_-guarded; empty until rung 7 wires it
    std::unique_ptr<SparkKeyRuleIndex> index_;                          // key <-> rule fan-out + refcount
    std::unordered_map<std::string, std::shared_ptr<RuleGeneration>> rules_; // rule_id -> generation
    std::unordered_map<std::string, std::shared_ptr<PerKey>> keys_;          // spark_key -> per-key

    mutable std::mutex outbox_mu_;
    GuardianOutbox outbox_;
};

} // namespace yuzu::agent
