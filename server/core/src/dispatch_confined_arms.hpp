#pragma once

#include <functional>
#include <string>
#include <vector>

#include "authz_model.hpp"
#include "dispatch_target_shape.hpp"

/// @file dispatch_confined_arms.hpp
/// The ONE place a dispatch arm's VISIBLE-SET INTERSECTION is decided (#1788).
///
/// THE RULE, stated once: every arm — an explicit id list, a management group,
/// a scope expression, a named `__all__` broadcast — is a TARGETING mechanism,
/// never an authz exemption. Each resolves to a candidate set, and every
/// candidate set is intersected with the caller's `Execution:Execute` visible
/// set immediately before the send.
///
/// WHY THIS IS A SEPARATE, PURE FUNCTION and not just a shared member: the
/// callers legitimately DIFFER in how they resolve targets and report failure.
/// `ServerImpl::dispatch_confined` recovers a scope principal from the
/// execution row and has no `res` to write to (background runners call it);
/// the `/api/command` handler reads the live session and answers 400/503 on a
/// bad scope. Those differences are real and are why one closure could not
/// simply absorb the other. But the part that MUST NOT DRIFT is not the
/// resolution — it is the intersection, and that part is identical. So each
/// caller keeps its own resolution and error shaping, and both route the
/// decision of WHO IS ACTUALLY REACHED through here.
///
/// The routed concern (.claude/routed-concerns.md, "Dispatch targeting") says a
/// second copy of the shared rule is how the identical defect survived on REST
/// after MCP was fixed. Two byte-identical copies of the four-arm intersection
/// existed before this header; a future arm added to one and not the other is
/// precisely the drift it warns about.
///
/// Being dependency-injected, this is also the seam the confinement tests bind:
/// a fake sink records exactly who was reached, so a test FAILS when any single
/// `in_scope`/`filter_to_scope` call is removed. Route-level mocks that merely
/// observe the VisibleSet being handed over cannot do that (CDX-R8-02) — they
/// stay green while the intersection is deleted.
namespace yuzu::server {

/// The registry operations the arms need, injected so tests can observe the
/// exact send set without a live `AgentRegistry`.
struct ConfinedDispatchSink {
    /// Send to one agent; returns true when the command was actually delivered.
    std::function<bool(const std::string&)> send_to;
    /// UNFILTERED fleet broadcast — used ONLY when the caller's visible set is
    /// `nullopt` (genuinely unfiltered authority), never as an empty-set
    /// fallback.
    std::function<int()> send_to_all_unfiltered;
    /// Every currently-known agent id, used to narrow a broadcast when the
    /// caller IS filtered.
    std::function<std::vector<std::string>()> known_agent_ids;
};

/// Targets the CALLER has already resolved. Each arm reads only its own field;
/// resolution (group store, scope engine, principal recovery) and any audit or
/// HTTP response stays with the caller.
struct ConfinedDispatchTargets {
    /// `DispatchArm::Ids` — the explicit list as supplied.
    const std::vector<std::string>* agent_ids = nullptr;
    /// `DispatchArm::Group` — members already read from the management-group
    /// store. Null means the store was unavailable: reach nobody.
    const std::vector<std::string>* group_members = nullptr;
    /// `DispatchArm::Scope` — the set the scope engine matched. Null means
    /// resolution was ABORTED (parse failure, degraded DB, failed owner check);
    /// the caller has already audited it and this arm must reach nobody. That
    /// null-is-abort contract is what keeps ADR-0036's fail-closed rule from
    /// silently inverting under a NOT combinator.
    const std::vector<std::string>* scope_matched = nullptr;
};

/// Reach exactly the agents this caller is authorised to reach, and return how
/// many were actually sent to.
///
/// `broadcast_on_none` is the ONE thing the arms parameterise: a caller whose
/// UI/tool already normalised an empty selection into a deliberate fleet
/// broadcast passes true; the shared closure — where no target named at all
/// must reach NOBODY, not everybody (#2500) — passes false. The None arm never
/// decides this for itself, so the meaning cannot drift per caller.
[[nodiscard]] inline int dispatch_confined_arms(DispatchArm arm,
                                                const ConfinedDispatchTargets& targets,
                                                const authz::VisibleSet& exec_visible,
                                                bool broadcast_on_none,
                                                const ConfinedDispatchSink& sink) {
    // Broadcast narrowed to the caller's visible set. Unfiltered (nullopt)
    // authority keeps the fast send-to-all path; a present set — INCLUDING a
    // present EMPTY one, which means deny-all under ADR-0033 §1 — walks the
    // known ids filtered to scope, so an empty set reaches nobody.
    const auto confined_broadcast = [&]() -> int {
        if (!exec_visible)
            return sink.send_to_all_unfiltered();
        int n = 0;
        for (const auto& aid : authz::filter_to_scope(sink.known_agent_ids(), exec_visible))
            if (sink.send_to(aid))
                ++n;
        return n;
    };

    int sent = 0;
    switch (arm) {
    case DispatchArm::Group:
        // A management group is a targeting mechanism, not an authz exemption.
        if (targets.group_members)
            for (const auto& aid : *targets.group_members)
                if (authz::in_scope(exec_visible, aid) && sink.send_to(aid))
                    ++sent;
        break;
    case DispatchArm::Scope:
        // Null == the caller aborted resolution and already audited it.
        if (targets.scope_matched)
            for (const auto& aid : authz::filter_to_scope(*targets.scope_matched, exec_visible))
                if (sink.send_to(aid))
                    ++sent;
        break;
    case DispatchArm::Ids:
        if (targets.agent_ids)
            for (const auto& aid : authz::filter_to_scope(*targets.agent_ids, exec_visible))
                if (sink.send_to(aid))
                    ++sent;
        break;
    case DispatchArm::Broadcast:
        // Asked for by its published name (`__all__`) — still narrowed.
        sent = confined_broadcast();
        break;
    case DispatchArm::None:
        // No target named at all. The caller decides what that MEANS; when it
        // means "reach nobody" the caller also owns the counter/log, because
        // there is no `req` here and background runners call this too.
        if (broadcast_on_none)
            sent = confined_broadcast();
        break;
    }
    return sent;
}

} // namespace yuzu::server
