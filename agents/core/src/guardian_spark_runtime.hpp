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

/// A registry read plus its measured latency (registry is the one type that
/// records detection_latency_us for parity).
struct RegistryRead {
    ReadResult<RegistrySnapshot> result;
    std::uint64_t latency_us{0};
};

/// The runtime's view of live endpoint state. Rung 5 supplies the platform
/// readers (file handle-scoped #807, registry RegOpenKeyExW, service SCM/sd-bus);
/// tests supply fakes. A method returns Unknown (ReadResult.known == false) when
/// it cannot determine the value - never a fabricated absent/stopped.
class IStateReader {
public:
    virtual ~IStateReader() = default;
    virtual ReadResult<FileSnapshot> read_file(const FileSparkParams& p) = 0;
    virtual RegistryRead read_registry(const RegistrySparkParams& p) = 0;
    virtual ReadResult<ServiceRunState> read_service(const ServiceSparkParams& p) = 0;
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
    struct Config {
        std::size_t outbox_capacity{4096};
    };

    GuardianSparkRuntime(IStateReader& reader, ISparkBackend& backend);
    GuardianSparkRuntime(IStateReader& reader, ISparkBackend& backend, Config cfg,
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
    /// dirty-set the convergence priority lane will service at rung 4).
    [[nodiscard]] std::vector<std::string> pending_initial(const std::string& key) const;
    [[nodiscard]] bool stopping() const;

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
        std::uint64_t pending_epoch{0};       ///< bumped when a rule joins; lets a pass detect a mid-flight join
        std::set<std::string> pending_initial; ///< rule_ids awaiting a first Known eval (registry_mu_-guarded)
    };

    // Helpers (all assume the documented lock discipline; see the .cpp).
    void detach_rule_locked(const std::string& rule_id); // registry_mu_ held
    EvalOutcome eval_rule(const SparkSpec& spec, const RuleAssertion& a, RuleEvalState& state,
                          std::chrono::steady_clock::time_point now, bool edge,
                          const ReadResult<FileSnapshot>* file,
                          const RegistryRead* reg,
                          const ReadResult<ServiceRunState>* svc);
    void enqueue_outcome(const RuleGeneration& gen, const EvalOutcome& out,
                         std::chrono::steady_clock::time_point now, bool& accepted);
    std::string next_event_id(const std::string& rule_id);

    IStateReader& reader_;
    ISparkBackend& backend_;
    RuntimeClock clock_;
    std::uint64_t gen_counter_{0};   ///< registry_mu_-guarded monotonic generation source
    std::uint64_t event_seq_{0};     ///< registry_mu_-guarded event_id source

    mutable std::mutex registry_mu_;
    bool stopping_{false};
    std::unique_ptr<SparkKeyRuleIndex> index_;                          // key <-> rule fan-out + refcount
    std::unordered_map<std::string, std::shared_ptr<RuleGeneration>> rules_; // rule_id -> generation
    std::unordered_map<std::string, std::shared_ptr<PerKey>> keys_;          // spark_key -> per-key

    mutable std::mutex outbox_mu_;
    GuardianOutbox outbox_;
};

} // namespace yuzu::agent
