#pragma once

/**
 * guardian_engine.hpp — Agent-side engine for the Yuzu Guardian (Guaranteed
 * State) policy loop. See docs/yuzu-guardian-design-v1.1.md.
 *
 * The engine accepts push_rules / get_status commands over the `__guard__`
 * dispatch hook, persists rule state into the agent's KvStore under the
 * reserved namespace "__guardian__", and arms one on-box IGuard per enabled
 * rule (File / Registry / Windows-Service / systemd). ADR-0021 rung 7 wires an
 * alternate SparkEngine-backed detection path (GuardianSparkRuntime,
 * guardian_spark_runtime.hpp) alongside the legacy IGuard path; a per-rule
 * reconcile op selects exactly one, never both.
 *
 * Two-phase startup (design §4 — pre-login activation):
 *   start_local()        — open persistent state, load cached rules;
 *                          safe to call before the Register RPC.
 *   sync_with_server()   — mark the engine network-connected; a future PR
 *                          will drain the buffered-event queue here.
 */

#include <yuzu/plugin.h>

#include <atomic>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <yuzu/agent/guard.hpp>  // IGuard, GuardDrift (guard abstraction)
#include <yuzu/agent/spark.hpp> // SparkType (for the classify() capability set)

namespace yuzu::agent {
class KvStore;
}

namespace yuzu::guardian::v1 {
class GuaranteedStatePush;
class GuaranteedStateRule;
class GuaranteedStateStatus;
class GuaranteedStateEvent;
} // namespace yuzu::guardian::v1

namespace yuzu::agent::v1 {
class CommandRequest;
} // namespace yuzu::agent::v1

// Forward-declared rather than #include-d: these live under agents/core/src/
// (agent-internal implementation headers), and no header under
// agents/core/include/yuzu/agent/ has ever crossed that boundary - this stays
// consistent. Only used here as std::function<SendResult(const OutboxEntry&)>
// parameter types, which do not need complete types to declare (only to call).
namespace yuzu::agent {
class SparkEngine;
class GuardianSparkRuntime;
class ConvergenceScheduler;
class GuardianOutboxDrainWorker;
class GuardianStateReader;
class GuardianSparkEngineBackend;
struct OutboxEntry;
enum class SendResult;
} // namespace yuzu::agent

namespace yuzu::agent {

/// Result of dispatching a `__guard__` command. The caller (agent.cpp)
/// converts this into a CommandResponse on the bidi stream.
struct GuardianDispatchResult {
    int exit_code{0};                 ///< 0 = success, non-zero = failure
    std::string output;               ///< payload — serialized proto on success, error detail otherwise
    std::string content_type;         ///< "proto" for SerializeAsString output, "text" otherwise
};

/// Engine lifecycle and dispatch surface. PR 2 scope: persist rules,
/// answer status queries, ignore everything else. Thread-safe — the
/// internal mutex serialises apply_rules / dispatch / get_status.
class YUZU_EXPORT GuardianEngine {
public:
    /// The immutable, set-once outcome of wire_spark_engine() - never a
    /// mutable runtime toggle (rung 7: Sol's rev-1 review explicitly rejected
    /// a test-only mutable setter for the spark-vs-legacy decision; this is a
    /// constructor-time parameter instead, see `prefer_spark` below).
    ///   Unwired       - wire_spark_engine() has not yet run (the member-
    ///                   initializer default). A programming fault if
    ///                   reconcile ever observes it with prefer_spark true -
    ///                   NEVER silently falls back to legacy.
    ///   SparkDisabled - --spark-disable: a deliberate kill-switch. Legacy is
    ///                   the CORRECT, expected path here, not a fallback.
    ///   SparkFailed   - spark_engine_ failed to boot, OR this engine's own
    ///                   wiring sequence failed after that (consumer
    ///                   registration, scheduler start). NEVER falls back to
    ///                   legacy - a failure must be visible (errored via
    ///                   get_status()'s existing fail-closed behaviour), not
    ///                   silently absorbed (the mutual-exclusion invariant).
    ///   Available     - spark_runtime_/spark_scheduler_/the drain worker are
    ///                   live; the reconcile op classifies per-rule from here.
    enum class SparkAvailability { Unwired, SparkDisabled, SparkFailed, Available };

    /// The KvStore pointer may be null at construction (e.g. KV open
    /// failed). All subsequent methods degrade to soft failures with
    /// error strings rather than crashing — matches the agent's
    /// existing "KV unavailable is a warning, not a fatal" posture.
    ///
    /// `prefer_spark`: whether the reconcile op ATTEMPTS the spark path at
    /// all when wire_spark_engine() later reports Available. IMMUTABLE for
    /// this object's lifetime (a constructor parameter, not a setter) - rung
    /// 7 ships with every production agent.cpp call site passing the literal
    /// `false` (legacy stays the observable default); rung 12's "default
    /// flip" changes that one literal. Tests pass `true` to exercise the
    /// spark path.
    GuardianEngine(KvStore* kv, std::string agent_id, bool prefer_spark = false);
    ~GuardianEngine();

    GuardianEngine(const GuardianEngine&) = delete;
    GuardianEngine& operator=(const GuardianEngine&) = delete;

    /// Phase 1 startup (pre-network). Loads cached rules from KvStore
    /// into the in-memory count cache so get_status() is cheap.
    std::expected<void, std::string> start_local();

    /// Phase 2 startup (post-Register). No-op in PR 2 — PR 4 uses this
    /// to drain a buffered-events queue over the command stream.
    void sync_with_server();

    /// Idempotent shutdown. After stop() returns, dispatch() will
    /// return a transient-failure result rather than touching KV.
    void stop();

    /// Sink for outbound Guardian events (drift, etc.). Wired by agent.cpp once
    /// the Subscribe stream is open and BEFORE any push arrives, so a guard started
    /// by apply_rules captures a live sink. The sink writes a
    /// CommandResponse{plugin:"__guard__", action:"event", payload:<event>} on the
    /// stream. Guards capture a copy at start, so this is set-once-then-read.
    using EventSink = std::function<void(const yuzu::guardian::v1::GuaranteedStateEvent&)>;
    void set_event_sink(EventSink sink);

    /// Replace (full_sync=true) or merge (full_sync=false) the active
    /// rule set with the contents of `push`. Persists each rule as a
    /// JSON blob under key "rule:<rule_id>". Returns the number of
    /// rules applied on success, or an error detail string.
    std::expected<std::size_t, std::string>
    apply_rules(const yuzu::guardian::v1::GuaranteedStatePush& push);

    /// Build a GuaranteedStateStatus reflecting currently cached rules.
    /// All rules report status="errored" in PR 2 because no guards are
    /// running yet — we cannot prove compliance without an evaluator, so
    /// be honest about it. The real status machine (compliant/drifted/
    /// errored per-rule) arrives with PR 3; dashboard presentation of the
    /// PR 2 state is also a PR 3 concern.
    yuzu::guardian::v1::GuaranteedStateStatus get_status() const;

    /// Entry point for `cmd.plugin() == "__guard__"`. Parses the
    /// action + params and returns a DispatchResult ready to be
    /// serialised into a CommandResponse by the caller.
    GuardianDispatchResult dispatch(const yuzu::agent::v1::CommandRequest& cmd);

    /// Number of rules currently persisted. Informational only.
    std::size_t rule_count() const;

    /// Number of guards CURRENTLY ARMED via the LEGACY IGuard path (may be <
    /// rule_count(): a disabled rule, an unsupported/off-platform spark type,
    /// or a failed start all persist the rule without arming a guard).
    /// Informational + the test seam for the enabled()/disable/re-enable/
    /// same-id-replace contract (rung 6) and the rung-7 mutual-exclusion
    /// invariant (a rule_id is never counted here AND in
    /// spark_armed_rule_count() at once).
    std::size_t armed_guard_count() const;

    /// Number of rules CURRENTLY ARMED via the SPARK path (0 if spark was
    /// never wired). The rung-7 counterpart to armed_guard_count() - the
    /// mutual-exclusion test seam.
    std::size_t spark_armed_rule_count() const;

    /// Current policy generation — monotonically increasing; bumped on
    /// every successful apply_rules call. Persisted across restarts.
    std::uint64_t policy_generation() const;

    /// KV namespace used for all Guardian persistent state. Exposed for
    /// tests — do not read from this namespace in production code.
    static std::string_view kv_namespace();

    /// Wire the spark detection path, once, before start_local() (agent.cpp,
    /// rung 7.7): builds the reader, the SparkEngine backend adapter, the
    /// runtime, registers the SparkEngine consumer, starts the convergence
    /// scheduler and the outbox drain worker - an all-or-nothing transaction
    /// (ANY step failing after `engine` is confirmed non-null rolls every
    /// partial construction back and reports SparkFailed; see the .cpp for
    /// the exact rollback sequence). `engine` is a BORROWED pointer, safe
    /// only because of the agent.cpp member-declaration-order guarantee that
    /// spark_engine_ outlives this GuardianEngine's teardown (guardian_ is
    /// declared before spark_engine_ in agent.cpp, so it is destroyed first).
    /// `spark_disabled_by_config` disambiguates a null `engine` meaning
    /// --spark-disable from one meaning spark_engine_ failed to boot -
    /// agent.cpp already knows which case it is; this method must not guess.
    /// `send` is the wire-serializing callback the drain worker uses; a fake
    /// suffices for tests that only need wiring/reconcile behaviour, not real
    /// delivery. Idempotent-once: a second call is a no-op (logs and returns)
    /// once spark_availability() is anything other than Unwired.
    void wire_spark_engine(SparkEngine* engine, bool spark_disabled_by_config,
                           std::function<SendResult(const OutboxEntry&)> send);

    /// The current, immutable-after-set outcome of wire_spark_engine().
    [[nodiscard]] SparkAvailability spark_availability() const;

    /// Live bounded-I/O worker count on the spark reader (0 if never wired) -
    /// the F3 orphan-exit obligation's plumbing (rung 7.6 is the enforcement).
    [[nodiscard]] std::size_t active_io_workers() const;

private:
    KvStore* kv_;
    std::string agent_id_;

    mutable std::mutex mtx_;
    bool started_{false};
    bool stopped_{false};
    std::uint64_t policy_generation_{0};
    std::size_t rule_count_{0};

    bool put_rule_locked(const yuzu::guardian::v1::GuaranteedStateRule& rule);
    void refresh_count_locked();
    void persist_generation_locked();

    /// Step 4: arm (or re-arm) the on-box guard for a rule. Reads the rule's
    /// spark type to pick the guard: file-change to FileGuard,
    /// service-status-change to ServiceGuard (Windows) or SystemdServiceGuard
    /// (Linux), registry-change to RegistryGuard (Windows). An unknown or
    /// off-platform type is a no-op. Called under mtx_. Returns true iff a guard
    /// was actually started (false for an unsupported type, an off-platform
    /// mechanism, or a failed start) so callers count armed guards accurately.
    bool start_guard_for_rule_locked(const yuzu::guardian::v1::GuaranteedStateRule& rule);
    void stop_all_guards_locked();

    /// Retire any legacy guard armed for rule_id, if one exists. Idempotent
    /// for a rule with none. This is start_guard_for_rule_locked's own
    /// rung-6 hoisted find-stop-erase block, factored out so
    /// reconcile_rule_locked (rung 7) can call it directly on the
    /// disabled/invalid/spark-armed paths without duplicating it.
    void withdraw_legacy_guard_locked(const std::string& rule_id);

    /// THE reconcile op (rung 7): the SOLE per-rule arm/disarm decision point,
    /// replacing the direct start_guard_for_rule_locked call apply_rules and
    /// start_local's A2 re-arm loop used to make. Decides spark vs legacy per
    /// rule (see the SparkAvailability doc above for the exact state matrix)
    /// and guarantees the mutual-exclusion invariant: a rule is armed in
    /// AT MOST ONE of guards_ / spark_runtime_, and an arm failure on
    /// whichever path was attempted is errored, NEVER a silent fallback to
    /// the other. Called under mtx_. Returns true iff the rule ended up armed
    /// via EITHER backend (so callers - A2's re-arm counter, apply_rules'
    /// telemetry - keep counting correctly regardless of which path armed it).
    bool reconcile_rule_locked(const yuzu::guardian::v1::GuaranteedStateRule& rule);

    /// Unwind a partially-completed wire_spark_engine() attempt, in the
    /// reverse order construction attempted the steps (each step is
    /// independently null-safe, so this is correct regardless of exactly how
    /// far wiring got before it threw). `registered` + `consumer_id` capture
    /// whether register_consumer() itself succeeded before the failure, so
    /// this can unregister a leaked consumer registration. Always ends by
    /// setting spark_availability_ to SparkFailed. Called under mtx_, only
    /// from wire_spark_engine() itself.
    void rollback_spark_wiring_locked(SparkEngine* engine, bool registered,
                                      std::uint64_t consumer_id);

    /// Build a GuaranteedStateEvent from a guard's drift report and ship it to
    /// the current event sink. Called from guard worker threads, so it takes
    /// ONLY sink_mtx_ (never mtx_): guards may fire during apply_rules / stop
    /// which hold mtx_, and taking mtx_ here would deadlock the stop-join.
    void emit_guard_event(const GuardDrift& drift);

    // Test seam: drift emission is otherwise reachable only through an armed
    // guard, and guards are Windows-only / no-op elsewhere — so the event_id
    // shape (the #1307 agent_id fold) has no cross-platform test path without
    // this. The helper drives emit_guard_event() with a synthetic GuardDrift;
    // a sink installed via set_event_sink() captures the resulting event.
    friend YUZU_EXPORT void guardian_emit_drift_for_test(GuardianEngine& engine,
                                                         const GuardDrift& drift);

    // event_sink_ is guarded by its own mutex (not mtx_) so a guard worker can
    // deliver an event without contending with — or deadlocking against — the
    // engine's rule-management path. The dedicated lock makes the A2 pre-network
    // arm (guards started by start_local before the sink is wired) race-free.
    mutable std::mutex sink_mtx_;
    EventSink event_sink_;
    std::atomic<std::uint64_t> event_seq_{0};
    std::unordered_map<std::string, std::unique_ptr<IGuard>> guards_;

    // --- Spark detection path (rung 7) - all guarded by mtx_ except where noted ---
    const bool prefer_spark_; ///< IMMUTABLE for object lifetime; set only at construction
    SparkAvailability spark_availability_{SparkAvailability::Unwired};
    SparkEngine* spark_engine_{nullptr}; ///< BORROWED - see wire_spark_engine's doc
    std::shared_ptr<GuardianStateReader> spark_reader_;
    std::shared_ptr<GuardianSparkEngineBackend> spark_backend_;
    std::shared_ptr<GuardianSparkRuntime> spark_runtime_;
    std::unique_ptr<ConvergenceScheduler> spark_scheduler_;
    std::unique_ptr<GuardianOutboxDrainWorker> spark_drain_worker_;
};

/// Test-support helper: builds a __guard__ `CommandRequest` inside the
/// agent-core DLL, populates `parameters["push"]` with the supplied bytes,
/// and dispatches it through `engine.dispatch()`. Intended ONLY for unit
/// tests — production code paths in `agent.cpp` already own the full
/// CommandRequest lifecycle inside the DLL.
///
/// Why this helper exists (#501, load-bearing):
///
///   On Windows MSVC debug, abseil's `MixingHashState::Seed()` returns
///   `reinterpret_cast<uintptr_t>(&MixingHashState::kSeed)`. `kSeed` lives
///   in the static library `absl_hash.lib`, which is linked once into the
///   test EXE and once into `yuzu_agent_core.dll` (yuzu_proto is a static
///   lib that pulls in absl transitively, and it's linked into both
///   targets). Each image therefore has its own copy of `kSeed` at a
///   different virtual address. That address is the hash seed for every
///   protobuf `Map<K,V>` operation (see `google::protobuf::internal::Hash`
///   in `map.h` — it calls `absl::HashOf(k, salt)` which mixes in `Seed()`).
///
///   Result: if the test EXE populates a `Map<string,string>` via `insert()`,
///   the bucket index is computed using EXE-side `Seed()`. When the DLL
///   then calls `.find()` on the same map, the bucket index is computed
///   using DLL-side `Seed()` — a different value — so `find()` returns
///   `end()` even though the key is present. With two buckets (`kMinTableSize
///   = 16 / sizeof(void*) = 2` on 64-bit), this fails ~50% of the time on
///   average, deterministically for any specific key/seed combination.
///
///   Production doesn't hit this because the gRPC Subscribe stream parses
///   `CommandRequest` bytes inside `yuzu_agent_core.dll` (see `agent.cpp`
///   Subscribe loop), so population and lookup both use the DLL's seed.
///
///   Release builds happen to pass because aggressive inlining + `/OPT:ICF`
///   can fold the seed accesses; debug builds with `/INCREMENTAL` keep the
///   split. The fix is to keep the map population inside the DLL by using
///   this helper instead of hand-constructing a `CommandRequest` in test
///   code. See `.claude/agents/build-ci.md` for the broader #375 context
///   and `docs/yuzu-guardian-design-v1.1.md` §10 for the Guardian test
///   strategy.
YUZU_EXPORT GuardianDispatchResult
guardian_dispatch_push_bytes_for_test(GuardianEngine& engine,
                                      std::string_view push_param_bytes);

/// Test-support helper: emit a synthetic GuardDrift through the engine's
/// private emit_guard_event() so the resulting GuaranteedStateEvent can be
/// captured by a sink installed via set_event_sink(). Intended ONLY for unit
/// tests — production drift originates inside Windows-only guard workers. Used
/// by the #1307 regression test to assert the event_id embeds the agent_id.
YUZU_EXPORT void guardian_emit_drift_for_test(GuardianEngine& engine,
                                              const GuardDrift& drift);

} // namespace yuzu::agent
