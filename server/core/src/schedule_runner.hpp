#pragma once

#include "dispatch_confined_arms.hpp" // #3424/#3511: ConfinedDispatchOutcome -- DispatchFn/CommandDispatchFn return type

/// @file schedule_runner.hpp
/// Drives the recurring-instruction schedules that were previously dead.
///
/// `ScheduleEngine` persists schedules and computes due-ness
/// (`evaluate_due`) and the post-fire advance (`advance_schedule`), but
/// nothing ever called either in production (#1191) — schedules were
/// created, listed and never fired. This component closes that gap.
///
/// Model: a background thread in ServerImpl `tick()`s on a cadence (the
/// policy_eval_thread_ / preflight_runner_thread_ pattern). Each tick pulls
/// the due schedules and fires them through the SAME shared dispatch lambda
/// as operator-initiated commands, creating a tracked execution row before
/// dispatch (the create-before-dispatch contract from the executions-history
/// ladder, UP2-4) so scheduled runs appear in the Executions history exactly
/// like manual runs.
///
/// Approval posture — a scheduled fire NEVER bypasses the approval gate the
/// interactive execute path enforces. A fire requires approval when the
/// schedule's own `requires_approval` flag is set OR the definition's
/// `approval_mode` is anything but "auto" (there is no operator session on
/// this path, so "role-gated" fails closed to require-approval, matching the
/// interactive path's unknown-mode posture). An approval-gated occurrence:
///   * submits ONE approval ticket (deduped against an extant pending
///     ticket for the same definition/creator/scope) and leaves the
///     schedule due — it re-checks each tick,
///   * fires within a tick of the ticket being APPROVED. One-approval ==
///     one-run is enforced by the occurrence anchor: firing advances the
///     schedule, and only tickets submitted strictly AFTER the last advance
///     count for the next occurrence, so a spent ticket can never re-fire,
///   * skips the occurrence and advances when the ticket is REJECTED —
///     the next occurrence submits a fresh ticket.
///
/// Advance discipline: every non-approval outcome advances the schedule
/// (fire-and-advance — a missed/failed occurrence is recorded and skipped,
/// never retried into a backlog). Only a pending approval holds a schedule
/// at its due time.
///
/// Arming re-check (D7, PLAN-003) — a schedule can sit dormant for months
/// between occurrences, long enough for the authority it was armed under to
/// have changed (a role revoked, a definition re-pointed). `fire()` re-
/// verifies the arming principal via `Deps::arming_check` BEFORE branching
/// on approval, so the check covers the direct-dispatch arm exactly as much
/// as the approval-gated arm. It is an ADDITIONAL gate in front of the
/// approval-ticket flow (ApprovalManager / fire_with_approval, M-02/#1806),
/// not a second copy of it — a denial here means fire_with_approval never
/// runs at all for that occurrence.

#include "dispatch_caller.hpp"

#include <functional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu {
class MetricsRegistry; // yuzu/metrics.hpp — observability counters (optional)
}

namespace yuzu::server {

// Forward declarations — full types are included in the .cpp.
class ScheduleEngine;
class InstructionStore;
class ExecutionTracker;
class ApprovalManager;
class AuditStore;
struct InstructionSchedule;

class ScheduleRunner {
public:
    /// Same shape as WorkflowRoutes::CommandDispatchFn — the server hands the
    /// runner the one shared dispatch lambda so scheduled fires travel the
    /// exact same path as operator-initiated commands. Review finding
    /// (external PR review, #3133): this used to be narrower than its
    /// sibling — no `caller` parameter at all — so every fire went through
    /// `command_dispatch_fn`'s hardcoded `DispatchCaller{.system = true}`,
    /// bypassing the classify+authorize chokepoint's per-action check
    /// entirely. Widened to actually match the shape this comment always
    /// claimed.
    using CommandDispatchFn = std::function<yuzu::server::ConfinedDispatchOutcome(
        const std::string& plugin, const std::string& action,
        const std::vector<std::string>& agent_ids, const std::string& scope_expr,
        const std::unordered_map<std::string, std::string>& parameters,
        const std::string& execution_id, const yuzu::server::DispatchCaller& caller)>;

    /// ADR-1007 — a deliberate SIBLING of `CommandDispatchFn`, not a
    /// widening (same rationale as `WorkflowRoutes::ConcurrencyDispatchFn`,
    /// whose doc comment this mirrors): `CommandDispatchFn` here is bound
    /// from the SAME shared `command_dispatch_caller_fn` lambda server.cpp
    /// wires into dashboard/REST/MCP too, so widening it would ripple far
    /// beyond this file. Default-constructed (unwired) ⇒ `dispatch_tracked`
    /// falls back to `dispatch_fn` with no concurrency gate.
    using ConcurrencyDispatchFn = std::function<yuzu::server::ConfinedDispatchOutcome(
        const std::string& plugin, const std::string& action,
        const std::vector<std::string>& agent_ids, const std::string& scope_expr,
        const std::unordered_map<std::string, std::string>& parameters,
        const std::string& execution_id, const yuzu::server::DispatchCaller& caller,
        const std::string& definition_id, const std::string& concurrency_mode)>;

    /// Resolves the CURRENT `DispatchCaller` for a stored username at fire
    /// time — re-resolving live permissions, never trusting a stale
    /// creation-time snapshot (a schedule's creator may have gained or lost
    /// grants since `s.created_by` was recorded). A schedule fire has no
    /// live HTTP session to derive from, unlike every other dispatch
    /// surface's `CallerFn` — server.cpp wires this to a lookup against the
    /// current auth/RBAC state. REQUIRED: an unwired resolver would
    /// reproduce exactly the system-caller bypass this field exists to
    /// close, so `dispatch_tracked` calls it unconditionally rather than
    /// falling back to an unfiltered default.
    using ResolveCallerFn = std::function<yuzu::server::DispatchCaller(const std::string& username)>;

    /// Re-verify the arming principal's current authority to fire ONE
    /// plugin.action (D7, peer finding PLAN-003). Checked in `fire()`
    /// BEFORE the approval/direct branch, so it covers both the
    /// `approval_mode == "auto"` direct-dispatch arm AND the approval-gated
    /// arm — a check reachable only from inside `fire_with_approval` would
    /// leave every auto schedule dispatching under stale authority. This
    /// package owns only the fail-closed seam and its tests: an UNSET
    /// callback denies every fire. p14 wires the real RBAC/arming lookup.
    using ArmingCheckFn = std::function<bool(const std::string& principal,
                                             const std::string& plugin,
                                             const std::string& action)>;

    struct Deps {
        ScheduleEngine* schedule_engine{nullptr};       // required
        InstructionStore* instruction_store{nullptr};   // required
        ExecutionTracker* execution_tracker{nullptr};   // optional (fires untracked)
        ApprovalManager* approval_manager{nullptr};     // optional (see fire())
        AuditStore* audit_store{nullptr};               // optional forensic sink
        yuzu::MetricsRegistry* metrics{nullptr};        // optional observability sink
        CommandDispatchFn dispatch_fn;                  // required
        ConcurrencyDispatchFn dispatch_fn_concurrency;   // optional (ADR-1007) — see doc comment
        ResolveCallerFn resolve_caller;                 // required
        ArmingCheckFn arming_check;                      // fail-closed when unset — see above
        // #3495: lets a shutdown request stop tick() from firing further due
        // schedules once stop_requested_ flips — checked once per schedule,
        // before fire() runs, so a schedule already firing still completes
        // cleanly (this only stops the NEXT one from starting). Ports the
        // same field QuarantineContainmentReconciler::Deps already carries
        // (governance Gate 5, #3425). Unset (default) = never stop, matching
        // every existing production/test Deps that predates this field.
        std::function<bool()> should_stop;
    };

    explicit ScheduleRunner(Deps deps);

    /// One scheduler cycle: fire every due schedule. Safe to call from a
    /// single background thread; individual fire failures are contained
    /// (logged + counted) so one bad schedule cannot starve the rest.
    void tick();

private:
    // Fire one due schedule: approval gate, tracked dispatch, advance.
    void fire(const InstructionSchedule& s);

    // The approval-gated arm of fire(). Returns true when the occurrence is
    // settled (fired, skipped-rejected, or submit failed) and the schedule
    // was advanced; false when it stays due waiting on a pending ticket.
    bool fire_with_approval(const InstructionSchedule& s, const std::string& plugin,
                            const std::string& action);

    // Tracked dispatch shared by the direct and approved arms. Returns the
    // number of agents reached (0 on failure; the execution row, when a
    // tracker is wired, is cancelled on failure so it cannot idle forever).
    int dispatch_tracked(const InstructionSchedule& s, const std::string& plugin,
                         const std::string& action, const std::string& approval_id);

    void audit(const InstructionSchedule& s, const std::string& action,
               const std::string& result, const std::string& detail);
    void count(const char* name);

    Deps d_;
};

} // namespace yuzu::server
