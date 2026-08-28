#include "schedule_runner.hpp"

#include "dispatch_target_shape.hpp" // kBroadcastScope (#2500)

#include "approval_manager.hpp"
#include "audit_store.hpp"
#include "execution_tracker.hpp"
#include "instruction_store.hpp"
#include "schedule_engine.hpp"
#include "schedule_params_parsers.hpp"

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
    auto def_result = d_.instruction_store->get_definition(s.definition_id);
    if (!def_result) {
        // ADR-0058: a genuine DB error (Postgres blip) — distinguished from
        // "unknown" (id doesn't exist) below so an operator doesn't mistake a
        // transient infrastructure issue for a stale/deleted schedule reference.
        // Do NOT advance: a store-unavailable attempt is not a completed
        // occurrence — advancing would permanently consume this schedule's due
        // slot on a transient failure. Leaving it un-advanced means evaluate_due()
        // returns it again next tick, matching PolicyEvaluator::dispatch_due's
        // throttle-restore-on-store-unavailable fix (gov Gate 3 sibling finding).
        count("yuzu_schedule_fire_failures_total");
        spdlog::warn("schedule_runner: schedule '{}' (id={}) instruction store read failed for "
                     "'{}' — retrying next tick",
                     s.name, s.id, s.definition_id);
        audit(s, "instruction.schedule_fired", "failure",
              "definition_store_unavailable schedule_id=" + s.id);
        return;
    }
    if (!*def_result || !(*def_result)->enabled) {
        count("yuzu_schedule_fire_failures_total");
        spdlog::warn("schedule_runner: schedule '{}' (id={}) references {} definition '{}' — "
                     "occurrence skipped",
                     s.name, s.id, *def_result ? "disabled" : "unknown", s.definition_id);
        audit(s, "instruction.schedule_fired", "failure",
              std::string(*def_result ? "definition_disabled" : "definition_unknown") +
                  " schedule_id=" + s.id);
        d_.schedule_engine->advance_schedule(s.id);
        return;
    }
    const auto& def = **def_result;

    // D7 (PLAN-003): re-verify the arming principal BEFORE the
    // approval/direct branch below, so BOTH arms are covered — a check
    // placed only inside fire_with_approval would let every
    // approval_mode == "auto" schedule dispatch under stale authority.
    // Fail-closed: an unset callback (p14 not wired yet, or a deliberate
    // lockdown) denies the fire exactly like an explicit `false`. Always
    // advance so a permanently-denied schedule cannot spin retrying every
    // tick forever.
    if (!d_.arming_check || !d_.arming_check(s.created_by, def.plugin, def.action)) {
        count("yuzu_schedule_arming_denied_total");
        spdlog::warn("schedule_runner: schedule '{}' (id={}) arming check denied — "
                     "principal='{}' target={}.{}",
                     s.name, s.id, s.created_by, def.plugin, def.action);
        audit(s, "instruction.schedule_fired", "denied",
              "arming_check_denied schedule_id=" + s.id + " principal=" + s.created_by +
                  " plugin=" + def.plugin + " action=" + def.action);
        d_.schedule_engine->advance_schedule(s.id);
        return;
    }

    // Approval gate — mirrors the interactive execute path: "auto" dispatches
    // directly, everything else (always / role-gated / unknown) requires an
    // approval ticket. There is no operator session here, so role-gated
    // cannot be bypassed and fails closed to require-approval.
    const bool needs_approval = s.requires_approval || def.approval_mode != "auto";
    if (needs_approval) {
        // #1398 (Gate 5 chaos-injector finding, LOW): checks is_open(), not
        // pointer-nullness. `d_.approval_manager` is a non-owning pointer set
        // once at server construction and stays non-null for the process
        // lifetime regardless of whether its internal migration later fails
        // (ApprovalManager::create_tables() sets its OWN db_ to nullptr on a
        // failed migration, never this pointer) — so the old `!d_.
        // approval_manager` check could never fire on a migration-closed
        // store, and this diagnostic branch's more specific audit/log
        // message never ran for that case. Net security effect was
        // unchanged either way (fire_with_approval's own query()/submit()
        // calls already fail closed on a closed store), but this is the
        // actually-reachable check for it.
        if (!d_.approval_manager || !d_.approval_manager->is_open()) {
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
        if (fire_with_approval(s, def.plugin, def.action))
            d_.schedule_engine->advance_schedule(s.id);
        return; // pending → stays due, re-checked next tick
    }

    dispatch_tracked(s, def.plugin, def.action, /*approval_id=*/"");
    d_.schedule_engine->advance_schedule(s.id);
}

bool ScheduleRunner::fire_with_approval(const InstructionSchedule& s, const std::string& plugin,
                                        const std::string& action) {
    // #1398 hardening (governance Gate 4 unhappy-path CRITICAL finding,
    // then re-hardened by security-guardian's re-review): the definition
    // this schedule fires can be MUTATED (PUT /api/instructions/{id}, gated
    // only on InstructionDefinition:Write) between a ticket's approval and
    // this schedule's next tick — `fire()` re-fetches `def` fresh every
    // time, so `plugin`/`action` here may be DIFFERENT from what was
    // actually reviewed when the ticket below was approved. Comparing
    // against `a.target_plugin`/`a.target_action` (see their doc comment,
    // approval_manager.hpp) closes that: a mismatch on EITHER field —
    // including a pre-migration empty value — simply fails the equality
    // check below and falls through to submitting a fresh ticket for the
    // NEW content, never redeeming stale review for unreviewed content.
    // TWO separate comparisons, not a concatenated string: `plugin`/`action`
    // are free text with no charset restriction, so a single `plugin+"."
    // +action` string would be collision-prone (28 shipped actions already
    // contain a literal `.`) — matching `CommandCapabilityRegistry::
    // classify`'s own independent-field shape eliminates that class.

    // 1) An APPROVED ticket for THIS schedule's occurrence, for THIS exact
    //    target → fire. The caller advances the schedule on our true return,
    //    which retires the ticket via the occurrence anchor (see
    //    ticket_is_current) — approve == at most one scheduled run. Single
    //    tick thread, so no concurrent-fire race. Matching on
    //    a.schedule_id == s.id (M-02, #1806) is required, not just
    //    belt-and-suspenders: without it, two schedules sharing (creator,
    //    definition, scope) would both fire off ONE approval.
    // #1398 (security-guardian re-review, MEDIUM): a ticket that matches
    // this occurrence's identity but NOT its current content is exactly the
    // attack this hardening defends against (get benign content approved,
    // then swap the definition before the next tick) — worth its own
    // detectable audit signal, distinct from "no ticket found at all"
    // (step 4's ordinary first-ask path below). Captured here, AUDITED
    // BELOW (only if this tick actually reaches step 4) rather than
    // immediately: the stale mismatched ticket stays in `approved` status
    // forever (nothing re-statuses it), so auditing on every detection
    // would re-fire this event every tick for as long as the resulting
    // fresh ticket (step 4) stays pending — sre governance finding, audit
    // volume, not correctness. Firing it once, on the tick that actually
    // acts on the mismatch by requesting fresh review, is the meaningful
    // event; every subsequent tick's re-detection of the SAME stale ticket
    // is not new information (step 2 below already suppresses the
    // resubmission that would otherwise duplicate-ask).
    std::string mismatch_audit_detail;
    auto approved = d_.approval_manager->query({.status = "approved", .submitted_by = s.created_by});
    for (const auto& a : approved) {
        if (a.definition_id != s.definition_id || a.scope_expression != s.scope_expression ||
            a.schedule_id != s.id || !ticket_is_current(a, s))
            continue;
        if (a.target_plugin != plugin || a.target_action != action) {
            spdlog::warn("schedule_runner: schedule '{}' (id={}) approval {} no longer matches "
                         "the definition's CURRENT target ({}.{} != approved {}.{}) — refusing "
                         "to redeem stale review; a fresh ticket will be requested",
                         s.name, s.id, a.id, plugin, action, a.target_plugin, a.target_action);
            if (mismatch_audit_detail.empty()) {
                mismatch_audit_detail =
                    "approval_content_mismatch approval_id=" + a.id + " schedule_id=" + s.id +
                    " approved_target=" + a.target_plugin + "." + a.target_action +
                    " current_target=" + plugin + "." + action;
            }
            continue;
        }
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
            a.schedule_id != s.id || a.target_plugin != plugin || a.target_action != action ||
            !ticket_is_current(a, s))
            continue;
        spdlog::info("schedule_runner: schedule '{}' (id={}) occurrence skipped — approval {} "
                     "rejected by {}",
                     s.name, s.id, a.id, a.reviewed_by);
        audit(s, "instruction.schedule_fired", "denied",
              "approval_rejected approval_id=" + a.id + " schedule_id=" + s.id);
        return true;
    }

    // 4) No ticket yet → submit one (tagged with this schedule's id, M-02,
    //    and this exact target plugin/action, #1398 hardening) and hold the
    //    occurrence at its due time. This is where a step-1 content mismatch
    //    (if any was found above) gets its one-shot audit row: reaching
    //    here means neither step 2 nor step 3 short-circuited, so this tick
    //    is genuinely the one requesting fresh review for the mismatch.
    if (!mismatch_audit_detail.empty())
        audit(s, "instruction.schedule_fired", "denied", mismatch_audit_detail);
    auto submitted = d_.approval_manager->submit(s.definition_id, s.created_by, s.scope_expression,
                                                 s.id, ApprovalOrigin::kSchedule, plugin, action);
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
        // PR1.5a: the schedule's own canonical parameters, not a hardcoded
        // "{}" — create_schedule() guarantees s.parameter_values is always a
        // validated canonical blob (never truly empty), but a schedule row
        // constructed off the persistence path (a test, a future direct
        // caller) is defended against here too.
        exec.parameter_values =
            s.parameter_values.empty() ? std::string(kEmptyScheduleParams) : s.parameter_values;
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
    // #2500: a schedule has no agent_ids, so an empty `scope_expression` is how
    // this path has always meant "the whole fleet" — but it meant it by falling
    // into the dispatch sink's empty-means-everybody default, which that issue
    // inverted. Say it explicitly so the behaviour survives the inversion and is
    // greppable at the call site rather than implied three files away.
    //
    // This PRESERVES today's semantics; it does not fix them. A schedule stored
    // with an empty scope still fires fleet-wide on every tick, unattended, and
    // `schedule_routes.cpp`'s `j.value("scope_expression","")` still collapses
    // omitted, supplied-but-empty and type-confused into the same empty string
    // at CREATE time, so an operator cannot express the difference. That is a
    // create-route validation gap with its own product decision (should a
    // schedule have to name `__all__`?) and is tracked separately — see #2500's
    // sibling issue. When it is fixed, this mapping is what stops being needed.
    const std::string dispatch_scope = s.scope_expression.empty()
                                           ? std::string(yuzu::server::kBroadcastScope)
                                           : s.scope_expression;
    auto parameters = schedule_params_to_map(s.parameter_values);
    try {
        // Review finding (#3133): re-resolve the creator's CURRENT
        // permissions at fire time rather than dispatching as `system` —
        // an operator who could create this schedule but does not (or no
        // longer) holds the classified permission for `plugin.action`
        // must be refused by the SAME chokepoint every operator-initiated
        // dispatch goes through, not silently bypass it. `parameters` is
        // this package's typed-schedule-params payload — the two are
        // independent: WHAT is dispatched vs WHO it is dispatched as.
        auto caller = d_.resolve_caller(s.created_by);
        // #1398: `approval_id` is empty on a direct auto-mode fire and a
        // real ApprovalManager ticket id on the approved-ticket branch
        // (fire_with_approval, above) — the same signal dispatch_tracked's
        // own audit detail already keys on (see `detail += " approval_id="`
        // below), reused here rather than re-derived.
        caller.approval_provenance =
            approval_id.empty() ? ApprovalProvenance::None : ApprovalProvenance::Ticket;
        std::tie(command_id, sent) = d_.dispatch_fn(plugin, action, /*agent_ids=*/{},
                                                    dispatch_scope, parameters, exec_id, caller);
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
