#pragma once

/// @file policy_evaluator.hpp
/// Drives the compliance CHECK -> VERDICT pipeline that was previously dead.
///
/// Authored policies bind a fragment (a check instruction + a CEL
/// `check_compliance` expression) to a scope. Nothing used to evaluate them:
/// `PolicyStore::update_agent_status` (the only writer of compliance status)
/// had no caller and no trigger fired, so `get_fleet_compliance` always read
/// 0%. This component closes that gap.
///
/// Model (two-phase, async): a background thread `tick()`s on a cadence.
///   * dispatch_due(): claims due policies via `PolicyStore::claim_due_policies`
///     (ADR-0056 — a durable, fleet-wide single-sweeper claim; see that store's
///     header for why due-ness can no longer live in this class's own
///     memory), resolves scope -> agents, dispatches the fragment's
///     check_instruction with a generated execution_id, and records an
///     in-flight check.
///   * collect_ready(): for in-flight checks past a grace window (or once all
///     targets have responded), read each agent's result via
///     ResponseStore::query_by_execution, evaluate the CEL against the parsed
///     result fields, and write compliant / non_compliant / unknown / error
///     via PolicyStore::update_agent_status (one row per agent). Stays
///     per-replica and in-memory: only the replica that dispatched a check
///     ever holds its in-flight entry, so there is nothing to coordinate here
///     — `update_agent_status`'s UPSERT is naturally idempotent against a
///     racing manual evaluate_now()/remediate() call on another replica FOR
///     THE STATUS VALUE (each write converges to a consistent final row).
///     This does NOT extend to remediate()'s retry-attempt counter (governance
///     UP-3, 2026-08-24): two concurrent remediate() calls for the same
///     policy — same-process, guarded by `remediating_`; cross-replica,
///     still open — each independently increment it, which is a real double
///     count, not an idempotent no-op.
///
/// Remediation is MANUAL and opt-in (operator-gated) and only available when
/// the fragment defines a fix_instruction: `remediate()` marks targets
/// `fixing`, dispatches the fix, then (on a later tick) dispatches the
/// post-check / check instruction and writes the true post-fix verdict. There
/// is no automatic non_compliant -> fix loop. A concurrent `remediate()` call
/// for the same policy while one is already dispatching is rejected (error,
/// same-process only via `remediating_`/`ReservationGuard` below — a
/// cross-replica race is still possible, see the Multi-replica note above).
///
/// Multi-replica note (ADR-0056): a stranded `fixing` row (the dispatching
/// replica died mid-FixWait) is swept back to `unknown` by
/// `claim_due_policies`'s per-tick staleness check, not by this class's
/// constructor — the old unconditional every-restart reset would stomp
/// another replica's still-live remediation under N replicas.

#include <cstdint>
#include <expected>
#include <functional>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu {
class MetricsRegistry; // yuzu/metrics.hpp — observability counters (optional)
}

namespace yuzu::server {

// Forward declarations — full types are included in the .cpp.
class PolicyStore;
class InstructionStore;
class ResponseStore;
class TagStore;
class CustomPropertiesStore;
class ManagementGroupStore;
struct Policy;
struct PolicyFragment;

namespace detail {
class AgentRegistry; // lives in yuzu::server::detail (see agent_registry.hpp)
} // namespace detail

class PolicyEvaluator {
public:
    /// Same shape as WorkflowRoutes::CommandDispatchFn — the server hands the
    /// evaluator the one shared dispatch lambda so checks travel the exact same
    /// path as operator-initiated commands.
    using CommandDispatchFn = std::function<std::pair<std::string, int>(
        const std::string& plugin, const std::string& action,
        const std::vector<std::string>& agent_ids, const std::string& scope_expr,
        const std::unordered_map<std::string, std::string>& parameters,
        const std::string& execution_id)>;

    /// Epoch-seconds clock. Injectable for deterministic tests.
    using NowFn = std::function<int64_t()>;

    struct Deps {
        PolicyStore* policy_store{nullptr};
        InstructionStore* instruction_store{nullptr};
        ResponseStore* response_store{nullptr};
        detail::AgentRegistry* registry{nullptr};
        TagStore* tag_store{nullptr};
        CustomPropertiesStore* custom_properties_store{nullptr};
        ManagementGroupStore* mgmt_group_store{nullptr};
        yuzu::MetricsRegistry* metrics{nullptr}; // optional observability sink
        CommandDispatchFn dispatch_fn;
        NowFn now_fn;                          // defaults to system clock if unset
        int64_t default_interval_seconds{3600}; // when a policy has no interval trigger
        int64_t grace_seconds{15};             // wait before scoring non-responders
        // ADR-0056: how long a 'fixing' status may sit before
        // claim_due_policies' staleness sweep resets it to 'unknown' (the
        // dispatching replica died/restarted mid-remediation and no one will
        // ever collect its FixWait). Long enough that a genuinely slow fix
        // instruction (e.g. a content_dist software install, which can run
        // minutes) is not false-positive reset mid-flight; short enough that
        // a truly stranded fix does not sit invisible indefinitely.
        int64_t fixing_stale_seconds{1800};
    };

    explicit PolicyEvaluator(Deps deps);

    /// One scheduler cycle: collect matured in-flight checks, then dispatch due
    /// policies. Safe to call from a single background thread.
    void tick();

    /// Force an immediate check of one policy, ignoring its interval. Returns
    /// the dispatch execution_id, or "" if the policy is missing / has no check
    /// instruction / matches no agents / already has one in flight — a
    /// legitimate no-op, never an error. `unexpected` means an internal store
    /// failure (degraded policy read, the durable-dispatch-claim stamp failed,
    /// or — ADR-0058 — InstructionStore itself errored resolving the check
    /// instruction) — the caller must surface this as degraded (503), not as
    /// "no targets" (409).
    [[nodiscard]] std::expected<std::string, std::string>
    evaluate_now(const std::string& policy_id);

    struct RemediateResult {
        bool ok{false};
        std::string error;        // set when !ok
        // Governance (2026-08-24): set explicitly by remediate() at each
        // degrade return point — the caller must not infer this from a
        // string prefix on `error`. A previous route-layer version keyed off
        // `error.starts_with("policy store")`, an unshared, untested string
        // contract a future reword of any degrade message would silently
        // break (consistency-auditor SHOULD-2). Covers a genuine PolicyStore
        // degrade AND — ADR-0058 — InstructionStore erroring resolving the
        // fix instruction; both are the same "internal store failure, not a
        // business rejection" shape to every caller.
        bool degraded{false};
        std::string execution_id; // fix-dispatch execution id when ok
        int agents{0};            // agents the fix was dispatched to
    };

    /// Manually remediate a policy. Requires the fragment to define a
    /// fix_instruction (else ok=false). If `agent_ids` is empty, targets every
    /// agent currently non_compliant for the policy. Dispatches the fix, then a
    /// later tick runs the post-check and writes the verified verdict.
    RemediateResult remediate(const std::string& policy_id,
                              const std::vector<std::string>& agent_ids);

private:
    enum class Phase { Check, FixWait };

    struct InFlight {
        Phase phase{Phase::Check};
        std::string policy_id;
        std::string execution_id;
        std::string instruction_id;   // for result-schema lookup (Check phase)
        std::string compliance_expr;  // CEL evaluated in the Check phase
        std::vector<std::string> targets;
        int64_t dispatched_at{0};
        // FixWait -> verify hand-off (the post-check to run after the fix):
        std::string verify_instruction;
        std::string verify_compliance;
        std::string verify_parameters_json;
    };

    Deps d_;
    std::mutex mu_;                                   // guards in_flight_, remediating_
    std::vector<InFlight> in_flight_;
    // Governance UP-3 (2026-08-24): reserved policy_ids between remediate()'s
    // dedupe check and the FixWait entry landing in in_flight_ — the window
    // kickoff_check doesn't have (it dispatches, THEN registers, all under a
    // single caller). remediate() burns the attempt-counter retry budget on
    // its own dispatch, so a second concurrent call in that window is a
    // stronger hazard than kickoff_check's equivalent gap, not just a
    // duplicate-check nuisance. See remediate()'s RAII guard.
    std::set<std::string> remediating_;

    void dispatch_due();
    void collect_ready();

    // Resolve scope/groups -> unique agent ids. Must be called WITHOUT mu_
    // held (it does store/registry I/O that must not run under the evaluator
    // lock — see the lock-discipline note on kickoff_check).
    std::vector<std::string> resolve_targets(const Policy& p) const;

    // Resolve targets, dispatch the fragment's check_instruction, record a
    // Check in-flight. Returns the execution_id, or "" on failure / when a Check
    // for this policy is already in flight (dedupe). Lock discipline: this
    // acquires mu_ only briefly (dedupe scan, in-flight push) and NEVER holds it
    // across the dispatch call — dispatch_fn does blocking gRPC + gateway
    // forwarding, so it must run lock-free. Caller must NOT hold mu_.
    std::expected<std::string, std::string> kickoff_check(const Policy& p);

    // Dispatch `instruction_id` to `targets`; returns a fresh execution_id, or
    // "" on a legitimate no-op (unknown definition / empty targets — same as
    // pre-migration). `unexpected` when InstructionStore::get_definition itself
    // errors (ADR-0058: a genuine DB/lease failure must never collapse into the
    // same "" a not-found id returns — every caller propagates this the same
    // way it propagates its own other degrade paths). Must be called WITHOUT
    // mu_ held (invokes the blocking dispatch_fn).
    std::expected<std::string, std::string>
    dispatch_instruction(const std::string& instruction_id,
                         const std::unordered_map<std::string, std::string>& parameters,
                         const std::vector<std::string>& targets);

    int64_t now() const;
    static std::string gen_execution_id();
};

} // namespace yuzu::server
