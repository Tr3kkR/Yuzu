#pragma once

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <spdlog/spdlog.h>

#include "agent_registry.hpp"
#include "authz_model.hpp"
#include "custom_properties_store.hpp"
#include "dispatch_confined_arms.hpp"
#include "dispatch_target_shape.hpp"
#include "execution_tracker.hpp"
#include "management_group_store.hpp"
#include "result_set_store.hpp"
#include "scope_engine.hpp"
#include "scope_yaml.hpp"
#include "tag_store.hpp"

/// @file dispatch_scope_ladder.hpp
/// ADR-0036 scope-resolution ladder (A-3), extracted from
/// `ServerImpl::dispatch_confined` and the `/api/command` handler — the two
/// copies had drifted apart only in HOW FAR each threads a principal/role and
/// an HTTP response outward; the ladder itself (alias resolution ->
/// owner-check gate -> parse -> registry evaluation, each step fail-closed)
/// was byte-identical, along with the `ConfinedDispatchSink` literal each
/// caller built around it.
///
/// Also the "middle link" QE-2 names: `resolve_and_dispatch_confined` is the
/// ONE place that classifies a dispatch arm (`classify_dispatch_arm`),
/// resolves ITS targets, and calls `dispatch_confined_arms` — so a caller-side
/// regression (e.g. collapsing the whole thing to an unfiltered loop over
/// `agent_ids`) cannot survive bound only by `dispatch_confined_arms`'s own
/// arm tests, which never exercise the classification or resolution that
/// feeds it. `ServerImpl::dispatch_confined` routes through it entirely; the
/// `/api/command` handler — which legitimately keeps its own HTTP-shaped
/// per-arm refusals (governance, #2557) — routes only its Scope arm's ladder
/// through `resolve_scope_targets` below, the part that was truly duplicated.
namespace yuzu::server {

/// Injected so the two callers can each supply their own audit-store wiring
/// (principal/role, command id) without duplicating the ladder that decides
/// WHEN to fire them. Each is called at most once per resolve.
struct ScopeLadderAudit {
    /// A referenced result-set failed the owner check (absent/expired/not
    /// owned) — one call per failing ref (governance M1 forensic row).
    std::function<void(const std::string& ref)> resolution_failed;
    /// The whole evaluation aborted; reason is one of "db_degraded",
    /// "owner_check_failed", "principal_unresolved".
    std::function<void(const std::string& reason)> evaluation_aborted;
};

/// `matched == nullopt` means ABORT — the caller must not dispatch (ADR-0036
/// fail-closed; mirrors `ConfinedDispatchTargets::scope_matched`'s null-is-
/// abort contract). `parse_error` is set ONLY when the abort was invalid
/// scope SYNTAX (as opposed to a degraded store or a failed owner check):
/// `/api/command` surfaces it as its own 400; `ServerImpl::dispatch_confined`
/// has no response to write and — matching its pre-existing behaviour —
/// simply reaches nobody, no audit row.
struct ScopeLadderResult {
    std::optional<std::vector<std::string>> matched;
    std::optional<std::string> parse_error;
};

/// The ladder itself: alias resolution -> owner-check gate -> parse ->
/// registry evaluation. `evaluate_scope_fn` is injected because the registry
/// call (`AgentRegistry::evaluate_scope`) already differs per caller only in
/// which stores are bound (tag/custom-properties/result-set) and which
/// principal is supplied — never in the ladder's control flow.
inline ScopeLadderResult resolve_scope_targets(
    std::string_view scope_expr, const std::string& principal, ResultSetStore* result_set_store,
    const std::function<std::optional<std::vector<std::string>>(const yuzu::scope::Expression&)>&
        evaluate_scope_fn,
    const ScopeLadderAudit& audit) {
    ScopeLadderResult result;

    auto resolved_scope = resolve_scope_aliases(scope_expr, principal, result_set_store);
    if (!resolved_scope) {
        spdlog::error("scope dispatch: resolve_scope_aliases degraded ({})",
                      to_string(resolved_scope.error()));
        if (audit.evaluation_aborted)
            audit.evaluation_aborted("db_degraded");
        return result;
    }

    std::vector<std::string> failing_refs;
    const auto gate =
        gate_scope_dispatch(*resolved_scope, principal, result_set_store, failing_refs);
    if (gate == ScopeDispatchGate::AbortDbDegraded) {
        spdlog::error("scope dispatch: owner-check scan degraded");
        if (audit.evaluation_aborted)
            audit.evaluation_aborted("db_degraded");
        return result;
    }
    if (gate == ScopeDispatchGate::AbortOwnerCheck) {
        // Governance M1: BINDING owner check — a failing ref aborts dispatch.
        for (const auto& ref : failing_refs)
            if (audit.resolution_failed)
                audit.resolution_failed(ref);
        if (audit.evaluation_aborted)
            audit.evaluation_aborted("owner_check_failed");
        return result;
    }

    auto parsed = yuzu::scope::parse(*resolved_scope);
    if (!parsed) {
        result.parse_error = parsed.error();
        return result;
    }

    if (auto matched = evaluate_scope_fn(*parsed)) {
        result.matched = std::move(matched);
        return result;
    }
    spdlog::error(
        "scope dispatch: evaluate_scope degraded (result-set membership preload failed)");
    if (audit.evaluation_aborted)
        audit.evaluation_aborted(principal.empty() ? "principal_unresolved" : "db_degraded");
    return result;
}

/// The Group/Scope arm resolvers a caller must supply so
/// `resolve_and_dispatch_confined` can own the classification + per-arm
/// dispatch call in one place (QE-2). `group_members_fn` reads the
/// management-group store; `scope_ladder_fn` wraps `resolve_scope_targets`
/// with the caller's principal + audit wiring already bound in.
struct DispatchResolvers {
    std::function<std::vector<std::string>(const std::string& group_id)> group_members_fn;
    std::function<ScopeLadderResult(std::string_view scope_expr)> scope_ladder_fn;
};

/// Outcome of `resolve_and_dispatch_confined`: `sent` is the count actually
/// dispatched; `scope_parse_error` is set only when the Scope arm's resolved
/// expression failed to parse — the one distinction a caller with an HTTP
/// response to shape might still act on differently than reaching nobody.
struct ConfinedDispatchOutcome {
    int sent = 0;
    std::optional<std::string> scope_parse_error;
};

/// The "middle link": classify the arm, resolve ITS targets via the injected
/// resolvers, and route the actual send through `dispatch_confined_arms` —
/// the ONE call every arm makes, so the classification + resolution that
/// feeds it is exercised by the same tests that bind the intersection itself.
inline ConfinedDispatchOutcome resolve_and_dispatch_confined(
    const std::vector<std::string>& agent_ids, const std::string& scope_expr,
    const authz::VisibleSet& exec_visible, bool broadcast_on_none,
    const DispatchResolvers& resolvers, const ConfinedDispatchSink& sink) {
    ConfinedDispatchOutcome outcome;
    const auto arm = classify_dispatch_arm(!agent_ids.empty(), scope_expr);

    if (arm == DispatchArm::Group) {
        std::vector<std::string> members;
        if (resolvers.group_members_fn)
            members = resolvers.group_members_fn(scope_expr.substr(6));
        ConfinedDispatchTargets t;
        t.group_members = &members;
        outcome.sent = dispatch_confined_arms(arm, t, exec_visible, broadcast_on_none, sink);
        return outcome;
    }

    if (arm == DispatchArm::Scope) {
        if (!resolvers.scope_ladder_fn)
            return outcome; // no resolver wired — reach nobody, matching a null store
        auto ladder = resolvers.scope_ladder_fn(scope_expr);
        outcome.scope_parse_error = ladder.parse_error;
        if (!ladder.matched)
            return outcome; // ABORTED — the ladder already audited it
        ConfinedDispatchTargets t;
        t.scope_matched = &*ladder.matched;
        outcome.sent = dispatch_confined_arms(arm, t, exec_visible, broadcast_on_none, sink);
        return outcome;
    }

    ConfinedDispatchTargets t;
    if (arm == DispatchArm::Ids)
        t.agent_ids = &agent_ids;
    outcome.sent = dispatch_confined_arms(arm, t, exec_visible, broadcast_on_none, sink);
    return outcome;
}

/// K-1 (QE-2 residual): the wiring `ServerImpl::dispatch_confined` builds
/// around `resolve_and_dispatch_confined` above — constructing the
/// `DispatchResolvers` + `ConfinedDispatchSink` from the concrete
/// registry/stores — extracted VERBATIM into this free function, taking those
/// dependencies as explicit parameters instead of implicit member access.
///
/// `resolve_and_dispatch_confined` itself was already mutation-bound
/// (test_dispatch_confined_arms.cpp), but the GLUE that builds its inputs from
/// `registry_`/the stores lived only inline inside the `ServerImpl` member and
/// had no test exercising it end-to-end: a mutation probe that replaced the
/// ENTIRE `dispatch_confined` body with a naive unfiltered `send_to` loop left
/// every existing test green, because none of them called through THIS glue —
/// they all called `resolve_and_dispatch_confined` directly with a fake sink.
/// `wire_and_dispatch_confined` IS that glue, now callable (and testable) with
/// a real `AgentRegistry` + real/null stores, independent of `ServerImpl`.
/// `ServerImpl::dispatch_confined` becomes a thin wrapper over this function;
/// its own body, behaviour, and every caller are unchanged.
inline std::pair<std::string, int> wire_and_dispatch_confined(
    yuzu::server::detail::AgentRegistry& registry, ManagementGroupStore* mgmt_group_store,
    ResultSetStore* result_set_store, const TagStore* tag_store,
    const CustomPropertiesStore* custom_properties_store, ExecutionTracker* execution_tracker,
    const std::function<void(const std::string& principal, const std::string& principal_role,
                             const std::string& command_id, const std::string& ref)>&
        audit_resolution_failed,
    const std::function<void(const std::string& principal, const std::string& principal_role,
                             const std::string& command_id, const std::string& reason)>&
        audit_evaluation_aborted,
    const std::string& command_id, const std::string& execution_id,
    const std::string& principal_role, const std::vector<std::string>& agent_ids,
    const std::string& scope_expr, const yuzu::server::authz::VisibleSet& exec_visible,
    bool broadcast_on_none, const yuzu::server::detail::pb::CommandRequest& cmd) {
    DispatchResolvers resolvers;
    resolvers.group_members_fn = [mgmt_group_store](const std::string& group_id) {
        std::vector<std::string> members;
        if (mgmt_group_store)
            for (const auto& m : mgmt_group_store->get_members(group_id))
                members.push_back(m.agent_id);
        return members;
    };
    resolvers.scope_ladder_fn = [&](std::string_view expr) {
        // Owner-scoped from_result_set: recover the principal from the
        // execution row (run_async / workflow / scheduled / MCP all create it
        // with dispatched_by before dispatch — review B1). Role is whatever
        // this call's caller supplied (C5).
        std::string principal;
        if (expr.find("from_result_set:") != std::string_view::npos &&
            !execution_id.empty() && execution_tracker) {
            if (auto ex = execution_tracker->get_execution(execution_id))
                principal = ex->dispatched_by;
        }
        yuzu::server::ScopeLadderAudit audit;
        audit.resolution_failed = [&](const std::string& ref) {
            audit_resolution_failed(principal, principal_role, command_id, ref);
        };
        audit.evaluation_aborted = [&](const std::string& reason) {
            audit_evaluation_aborted(principal, principal_role, command_id, reason);
        };
        return yuzu::server::resolve_scope_targets(
            expr, principal, result_set_store,
            [&](const yuzu::scope::Expression& parsed) {
                // #1788: intersect the matched set with the caller's
                // Execution:Execute visible set — done by
                // resolve_and_dispatch_confined below, not here.
                return registry.evaluate_scope(parsed, tag_store, custom_properties_store,
                                               result_set_store, principal);
            },
            audit);
    };

    yuzu::server::ConfinedDispatchSink sink{
        [&registry, &cmd](const std::string& aid) { return registry.send_to(aid, cmd); },
        [&registry, &cmd] { return registry.send_to_all(cmd); },
        [&registry] { return registry.all_ids(); }};

    const auto outcome = resolve_and_dispatch_confined(agent_ids, scope_expr, exec_visible,
                                                        broadcast_on_none, resolvers, sink);
    return {command_id, outcome.sent};
}

} // namespace yuzu::server
