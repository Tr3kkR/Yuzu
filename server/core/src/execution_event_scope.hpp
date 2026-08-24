#pragma once

#include <functional> // std::function::operator bool — used directly below
#include <string>
#include <string_view>

#include "execution_event_bus.hpp"
#include "response_scope_filter.hpp"

/// @file execution_event_scope.hpp
/// Per-event admission for a SCOPE-CONFINED consumer of `ExecutionEventBus`
/// (#1712, ADR-0017 INV-12 — the visible set constrains EVERY per-agent
/// source, and a live stream is a per-agent source).
///
/// TWO DIFFERENT THINGS, SPLIT THE SAME WAY `response_scope_filter.hpp`
/// splits them, because conflating them is how this defect class recurs:
///
///   - The **decision** ("may `username` see `agent_id`?") has exactly ONE
///     implementation, `ServerImpl::response_agent_in_scope` (`server.cpp`),
///     which gates on `rbac_enforcement_in_effect` so a corrupt/load-failed
///     `rbac_store` denies every agent instead of reading as "RBAC off → no
///     filter". This header does NOT re-implement, wrap or second-guess it —
///     it takes the same `ResponseScopePredicate` the row filter takes.
///
///   - The **mechanics** — which events on the shared bus are attributable
///     to an agent at all, and what happens to one that is not classifiable
///     — is what lives here. A row filter cannot answer that: rows have an
///     `agent_id` by construction, bus events have a TAXONOMY.
///
/// FAIL-CLOSED BY CONSTRUCTION. The publisher taxonomy is closed and named
/// in `docs/executions-history-ladder.md`: `agent-transition` (per-agent),
/// `execution-progress` / `execution-completed` (execution-wide). An event
/// type outside it is `kUnclassified` and is DROPPED for a confined
/// consumer — so a future publisher that adds a per-agent event type and
/// forgets to set `agent_id`, or forgets to classify it here, withholds
/// data from a confined operator rather than leaking it. Extend
/// `classify_execution_event` when the taxonomy grows; the bus-side taxonomy
/// rule ("add the type on the bus, never per consumer") is unchanged by it.
///
/// It is NOT yet the ONLY site that classifies this taxonomy. The MCP
/// progress bridge (`mcp_stream_bridge.cpp`) predates this header and carries
/// its own hardcoded allow-list of the two execution-scoped types, returning
/// early on everything else. That copy is safe today — its allow-list is
/// exactly the `kExecutionScoped` set, so it fails closed the same way — but
/// until it is migrated onto this function a new event type must be
/// classified in BOTH places. Migrating it is how this becomes the single
/// site; asserting that it already is would be the drift this header exists
/// to prevent.
///
/// WHAT CALLERS STILL OWN: the FAIL-OPEN-WHEN-UNWIRED test. An unwired
/// `ResponseScopePredicate` means "no filter" (legacy behaviour for
/// harnesses that wire no RBAC at all) and is decided at the call site,
/// never here — `nullopt`/unwired and a wired-but-denying predicate are NOT
/// interchangeable, and this function is only reached once the caller has
/// established it holds a wired one.
///
/// RESIDUAL, stated rather than left for a reader to discover: the two
/// execution-scoped frames carry the parent row's fleet-wide aggregate
/// counts (`agents_targeted` / `_responded` / `_success` / `_failure`).
/// Those name no agent, so they are admitted here — per-viewer
/// reconciliation is not possible on a shared bus without rewriting each
/// payload per connection (the per-event JSON parse this design exists to
/// avoid), so it is deliberately NOT attempted at this layer. The identity
/// leak — the live one — is what this function closes.
///
/// That makes the aggregate counts the CONSUMER's problem, and the drawer
/// handles them at the point of use rather than on the bus: the KPI strip
/// carries `data-scope-reconciled` whenever a scope filter is in force, and
/// `execApplyProgress` (`instruction_ui.cpp`) then leaves those three cells
/// to the scope-filtered fragment refetch instead of writing the frame's
/// fleet totals over the server-reconciled in-scope ones. Do not read this
/// paragraph as "the bus reconciles it" — it does not, and an earlier
/// revision of this comment claimed the static strip alone was sufficient,
/// which was false while the live frame overwrote it. Any NEW confined
/// consumer of these two frames inherits the same obligation and must decide
/// what to do with the aggregates itself.

namespace yuzu::server {

/// How an event on the shared bus relates to a single agent.
enum class ExecutionEventScopeClass {
    /// Names exactly one agent; admissible only if the predicate admits it.
    kAgentAttributed,
    /// Names no agent by construction (execution-wide aggregate/lifecycle).
    kExecutionScoped,
    /// Not in the published taxonomy — treated as agent-attributed with an
    /// unknown agent, i.e. never admitted to a confined consumer.
    kUnclassified,
};

/// Classify one bus event type. The taxonomy is the publisher list in
/// `docs/executions-history-ladder.md`; anything else is `kUnclassified`
/// ON PURPOSE (see the file comment) — do not add a permissive default.
inline ExecutionEventScopeClass classify_execution_event(std::string_view event_type) noexcept {
    if (event_type == "agent-transition")
        return ExecutionEventScopeClass::kAgentAttributed;
    if (event_type == "execution-progress" || event_type == "execution-completed")
        return ExecutionEventScopeClass::kExecutionScoped;
    return ExecutionEventScopeClass::kUnclassified;
}

/// True iff @p ev may be delivered to @p username under @p in_scope.
///
/// Callers MUST have established that @p in_scope is wired; an unwired
/// predicate is the caller's legacy-open decision, not this function's.
/// A wired predicate that denies everything — exactly what
/// `response_agent_in_scope` returns for every agent when the RBAC store is
/// corrupt or unreachable — yields zero agent-attributed events, never the
/// fleet.
inline bool execution_event_in_scope(const ExecutionEvent& ev, const std::string& username,
                                     const ResponseScopePredicate& in_scope) {
    switch (classify_execution_event(ev.event_type)) {
    case ExecutionEventScopeClass::kExecutionScoped:
        return true;
    case ExecutionEventScopeClass::kAgentAttributed:
        // An agent-attributed event with no agent named cannot be shown to
        // be in scope, so it is not shown. This is the guard that keeps
        // `publish`'s defaulted `agent_id` from being a fail-open hole.
        if (ev.agent_id.empty())
            return false;
        return static_cast<bool>(in_scope) && in_scope(username, ev.agent_id);
    case ExecutionEventScopeClass::kUnclassified:
        break;
    }
    return false;
}

} // namespace yuzu::server
