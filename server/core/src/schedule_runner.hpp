#pragma once

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
    /// exact same path as operator-initiated commands.
    using CommandDispatchFn = std::function<std::pair<std::string, int>(
        const std::string& plugin, const std::string& action,
        const std::vector<std::string>& agent_ids, const std::string& scope_expr,
        const std::unordered_map<std::string, std::string>& parameters,
        const std::string& execution_id)>;

    struct Deps {
        ScheduleEngine* schedule_engine{nullptr};       // required
        InstructionStore* instruction_store{nullptr};   // required
        ExecutionTracker* execution_tracker{nullptr};   // optional (fires untracked)
        ApprovalManager* approval_manager{nullptr};     // optional (see fire())
        AuditStore* audit_store{nullptr};               // optional forensic sink
        yuzu::MetricsRegistry* metrics{nullptr};        // optional observability sink
        CommandDispatchFn dispatch_fn;                  // required
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
