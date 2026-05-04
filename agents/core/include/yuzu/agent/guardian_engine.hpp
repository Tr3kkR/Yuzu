#pragma once

/**
 * guardian_engine.hpp — Agent-side engine for the Yuzu Guardian (Guaranteed
 * State) policy loop. See docs/yuzu-guardian-design-v1.1.md.
 *
 * This is the PR 2 skeleton: the engine accepts push_rules / get_status
 * commands over the `__guard__` dispatch hook and persists rule state into
 * the agent's KvStore under the reserved namespace "__guardian__". No
 * guard processes are spawned yet — that lands in PR 3.
 *
 * Two-phase startup (design §4 — pre-login activation):
 *   start_local()        — open persistent state, load cached rules;
 *                          safe to call before the Register RPC.
 *   sync_with_server()   — mark the engine network-connected; a future PR
 *                          will drain the buffered-event queue here.
 */

#include <yuzu/plugin.h>

#include <cstdint>
#include <expected>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::agent {
class KvStore;
}

namespace yuzu::guardian::v1 {
class GuaranteedStatePush;
class GuaranteedStateRule;
class GuaranteedStateStatus;
} // namespace yuzu::guardian::v1

namespace yuzu::agent::v1 {
class CommandRequest;
} // namespace yuzu::agent::v1

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
    /// The KvStore pointer may be null at construction (e.g. KV open
    /// failed). All subsequent methods degrade to soft failures with
    /// error strings rather than crashing — matches the agent's
    /// existing "KV unavailable is a warning, not a fatal" posture.
    GuardianEngine(KvStore* kv, std::string agent_id);
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

    /// Current policy generation — monotonically increasing; bumped on
    /// every successful apply_rules call. Persisted across restarts.
    std::uint64_t policy_generation() const;

    /// KV namespace used for all Guardian persistent state. Exposed for
    /// tests — do not read from this namespace in production code.
    static std::string_view kv_namespace();

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

} // namespace yuzu::agent
