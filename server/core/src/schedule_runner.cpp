#include "schedule_runner.hpp"

#include "approval_manager.hpp"
#include "audit_store.hpp"
#include "execution_tracker.hpp"
#include "instruction_store.hpp"
#include "schedule_engine.hpp"

#include <yuzu/metrics.hpp>

#include <spdlog/spdlog.h>

#include <chrono>
#include <tuple>

namespace yuzu::server {

namespace {

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Tickets submitted before this occurrence became the current one are stale:
// a rejected ticket from a PREVIOUS occurrence must not skip this one, and a
// long-spent approved ticket must not fire it. Once a schedule has advanced,
// only tickets submitted STRICTLY after the advance count — that strictness
// is the one-approval == one-run guarantee (advance stamps
// last_executed_at, retiring the ticket that settled the occurrence, even
// within the same second). A never-advanced schedule accepts any ticket
// since its creation (`>=` — create and submit can share a second).
bool ticket_is_current(const Approval& a, const InstructionSchedule& s) {
    return s.last_executed_at > 0 ? a.submitted_at > s.last_executed_at
                                  : a.submitted_at >= s.created_at;
}

} // namespace

ScheduleRunner::ScheduleRunner(Deps deps) : d_(std::move(deps)) {}

void ScheduleRunner::tick() {
    if (!d_.schedule_engine || !d_.instruction_store || !d_.dispatch_fn)
        return;

    for (const auto& s : d_.schedule_engine->evaluate_due()) {
        // Contain per-schedule failures: one malformed schedule/definition
        // must not stop the remaining due schedules from firing this tick.
        try {
            fire(s);
        } catch (const std::exception& e) {
            count("yuzu_schedule_fire_failures_total");
            spdlog::error("schedule_runner: fire threw for schedule '{}' (id={}): {}", s.name,
                          s.id, e.what());
            // Advance anyway — a schedule whose fire path always throws must
            // not re-fire every tick forever (fire-and-advance discipline).
            d_.schedule_engine->advance_schedule(s.id);
        }
    }
}

void ScheduleRunner::fire(const InstructionSchedule& s) {
    auto def = d_.instruction_store->get_definition(s.definition_id);
    if (!def || !def->enabled) {
        count("yuzu_schedule_fire_failures_total");
        spdlog::warn("schedule_runner: schedule '{}' (id={}) references {} definition '{}' — "
                     "occurrence skipped",
                     s.name, s.id, def ? "disabled" : "unknown", s.definition_id);
        audit(s, "instruction.schedule_fired", "failure",
              std::string(def ? "definition_disabled" : "definition_unknown") +
                  " schedule_id=" + s.id);
        d_.schedule_engine->advance_schedule(s.id);
        return;
    }

    // Approval gate — mirrors the interactive execute path: "auto" dispatches
    // directly, everything else (always / role-gated / unknown) requires an
    // approval ticket. There is no operator session here, so role-gated
    // cannot be bypassed and fails closed to require-approval.
    const bool needs_approval = s.requires_approval || def->approval_mode != "auto";
    if (needs_approval) {
        if (!d_.approval_manager) {
            // Fail closed: never dispatch an approval-gated instruction
            // without the gate. Advance so the schedule doesn't spin.
            count("yuzu_schedule_fire_failures_total");
            spdlog::error("schedule_runner: schedule '{}' (id={}) requires approval but no "
                          "approval manager is wired — occurrence skipped",
                          s.name, s.id);
            audit(s, "instruction.schedule_fired", "failure",
                  "approval_gate_unavailable schedule_id=" + s.id);
            d_.schedule_engine->advance_schedule(s.id);
            return;
        }
        if (fire_with_approval(s, def->plugin, def->action))
            d_.schedule_engine->advance_schedule(s.id);
        return; // pending → stays due, re-checked next tick
    }

    dispatch_tracked(s, def->plugin, def->action, /*approval_id=*/"");
    d_.schedule_engine->advance_schedule(s.id);
}

bool ScheduleRunner::fire_with_approval(const InstructionSchedule& s, const std::string& plugin,
                                        const std::string& action) {
    // 1) An APPROVED ticket for THIS schedule's occurrence → fire. The caller
    //    advances the schedule on our true return, which retires the ticket
    //    via the occurrence anchor (see ticket_is_current) — approve == at
    //    most one scheduled run. Single tick thread, so no concurrent-fire
    //    race. Matching on a.schedule_id == s.id (M-02, #1806) is required,
    //    not just belt-and-suspenders: without it, two schedules sharing
    //    (creator, definition, scope) would both fire off ONE approval.
    auto approved = d_.approval_manager->query({.status = "approved", .submitted_by = s.created_by});
    for (const auto& a : approved) {
        if (a.definition_id != s.definition_id || a.scope_expression != s.scope_expression ||
            a.schedule_id != s.id || !ticket_is_current(a, s))
            continue;
        dispatch_tracked(s, plugin, action, a.id);
        return true;
    }

    // 2) A PENDING ticket for THIS schedule → the occurrence waits (no
    //    advance), and we never stack a duplicate ask. Scoped to
    //    a.schedule_id == s.id for the same reason as (1): otherwise a
    //    sibling schedule's pending ticket would suppress this schedule's
    //    OWN submission in step 4, and it would never get a ticket to match.
    auto pending = d_.approval_manager->query({.status = "pending", .submitted_by = s.created_by});
    for (const auto& a : pending) {
        if (a.definition_id == s.definition_id && a.scope_expression == s.scope_expression &&
            a.schedule_id == s.id)
            return false;
    }

    // 3) A REJECTED ticket for this occurrence → skip it. The next occurrence
    //    submits a fresh ticket (each occurrence is one ask).
    auto rejected = d_.approval_manager->query({.status = "rejected", .submitted_by = s.created_by});
    for (const auto& a : rejected) {
        if (a.definition_id != s.definition_id || a.scope_expression != s.scope_expression ||
            a.schedule_id != s.id || !ticket_is_current(a, s))
            continue;
        spdlog::info("schedule_runner: schedule '{}' (id={}) occurrence skipped — approval {} "
                     "rejected by {}",
                     s.name, s.id, a.id, a.reviewed_by);
        audit(s, "instruction.schedule_fired", "denied",
              "approval_rejected approval_id=" + a.id + " schedule_id=" + s.id);
        return true;
    }

    // 4) No ticket yet → submit one (tagged with this schedule's id, M-02)
    //    and hold the occurrence at its due time.
    auto submitted =
        d_.approval_manager->submit(s.definition_id, s.created_by, s.scope_expression, s.id);
    if (!submitted) {
        // Submit failure (pending cap, store error): drop THIS occurrence
        // (advance) rather than re-submitting every tick against a full cap.
        count("yuzu_schedule_fire_failures_total");
        spdlog::warn("schedule_runner: approval submit failed for schedule '{}' (id={}): {} — "
                     "occurrence skipped",
                     s.name, s.id, submitted.error());
        audit(s, "instruction.schedule_fired", "failure",
              "approval_submit_failed schedule_id=" + s.id + " error=" + submitted.error());
        return true;
    }
    count("yuzu_schedule_approvals_submitted_total");
    spdlog::info("schedule_runner: schedule '{}' (id={}) requires approval — submitted {}", s.name,
                 s.id, *submitted);
    // Same action string as the interactive path's approval gate so the
    // audit taxonomy stays one-vocabulary; detail marks the scheduled origin.
    audit(s, "instruction.approval_required", "pending",
          "approval_id=" + *submitted + " mode=scheduled schedule_id=" + s.id);
    return false;
}

int ScheduleRunner::dispatch_tracked(const InstructionSchedule& s, const std::string& plugin,
                                     const std::string& action, const std::string& approval_id) {
    // Create-before-dispatch (executions ladder UP2-4): the execution row must
    // exist and the command_id→execution_id mapping must be registered by the
    // dispatch fn BEFORE any RPC, or a fast loopback agent can reply ahead of
    // the mapping. dispatched_by = the schedule's creator: scheduled runs are
    // attributed to the operator who authored the schedule, and the dispatch
    // fn recovers this principal for owner-scoped scope kinds.
    std::string exec_id;
    if (d_.execution_tracker) {
        Execution exec;
        exec.definition_id = s.definition_id;
        exec.status = "running";
        exec.scope_expression = s.scope_expression;
        exec.parameter_values = "{}";
        exec.dispatched_by = s.created_by;
        if (auto created = d_.execution_tracker->create_execution(exec); created.has_value())
            exec_id = *created;
        else
            spdlog::warn("schedule_runner: create_execution failed for schedule '{}' — firing "
                         "untracked",
                         s.name);
    }

    std::string command_id;
    int sent = 0;
    try {
        std::tie(command_id, sent) =
            d_.dispatch_fn(plugin, action, /*agent_ids=*/{}, s.scope_expression,
                           /*parameters=*/{}, exec_id);
    } catch (const std::exception& e) {
        count("yuzu_schedule_fire_failures_total");
        spdlog::error("schedule_runner: dispatch failed for schedule '{}' (id={}): {}", s.name,
                      s.id, e.what());
        if (d_.execution_tracker && !exec_id.empty())
            d_.execution_tracker->mark_cancelled(exec_id, s.created_by);
        audit(s, "instruction.schedule_fired", "failure",
              "dispatch_failed schedule_id=" + s.id + " execution_id=" + exec_id);
        return 0;
    }

    if (sent == 0) {
        // No agents in scope right now. Record the attempt and move on —
        // recurring schedules catch the fleet next period, and a phantom
        // 'running' row must not idle to the materialise timeout.
        count("yuzu_schedule_fire_failures_total");
        spdlog::warn("schedule_runner: schedule '{}' (id={}) reached no agents (scope='{}')",
                     s.name, s.id, s.scope_expression);
        if (d_.execution_tracker && !exec_id.empty())
            d_.execution_tracker->mark_cancelled(exec_id, s.created_by);
        audit(s, "instruction.schedule_fired", "failure",
              "no_agents schedule_id=" + s.id + " execution_id=" + exec_id);
        return 0;
    }

    if (d_.execution_tracker && !exec_id.empty()) {
        // L-03 (#1806): dispatch has already succeeded at this point — a
        // throw from set_agents_targeted (store error) must not leave the
        // execution row stuck at "running" forever, since tick()'s
        // outer catch only advances the SCHEDULE, not the execution it
        // already created. Mark the row failed here so it can't idle to the
        // materialise timeout while still counting the fire as a success.
        try {
            d_.execution_tracker->set_agents_targeted(exec_id, sent);
        } catch (const std::exception& e) {
            spdlog::error("schedule_runner: set_agents_targeted threw for schedule '{}' (id={}, "
                          "execution_id={}): {}",
                          s.name, s.id, exec_id, e.what());
            try {
                d_.execution_tracker->mark_cancelled(exec_id, s.created_by);
            } catch (const std::exception& e2) {
                spdlog::error("schedule_runner: mark_cancelled also threw for execution_id={}: {}",
                              exec_id, e2.what());
            }
            audit(s, "instruction.schedule_fired", "failure",
                  "set_agents_targeted_failed schedule_id=" + s.id + " execution_id=" + exec_id);
            count("yuzu_schedule_fire_failures_total");
            return sent;
        }
    }

    count("yuzu_schedule_fires_total");
    spdlog::info("schedule_runner: schedule '{}' (id={}) fired — command_id={} execution_id={} "
                 "agents={}",
                 s.name, s.id, command_id, exec_id, sent);
    std::string detail = "schedule_id=" + s.id + " command_id=" + command_id +
                         " execution_id=" + exec_id + " agents=" + std::to_string(sent);
    if (!approval_id.empty())
        detail += " approval_id=" + approval_id;
    audit(s, "instruction.schedule_fired", "success", detail);
    return sent;
}

void ScheduleRunner::audit(const InstructionSchedule& s, const std::string& action,
                           const std::string& result, const std::string& detail) {
    if (!d_.audit_store)
        return;
    AuditEvent ev;
    ev.timestamp = now_epoch();
    ev.principal = s.created_by;
    ev.action = action;
    ev.target_type = "instruction";
    ev.target_id = s.definition_id;
    ev.result = result;
    ev.detail = detail;
    // Background fire-and-forget per the AuditStore::log contract — there is
    // no response to surface partial-success on; a failed persist is counted
    // by the store's own emit_failed_ metric.
    (void)d_.audit_store->log(ev);
}

void ScheduleRunner::count(const char* name) {
    if (d_.metrics)
        d_.metrics->counter(name).increment();
}

} // namespace yuzu::server
