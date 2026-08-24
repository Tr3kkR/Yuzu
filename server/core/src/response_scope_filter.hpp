#pragma once

#include <cstddef>
#include <functional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

/// @file response_scope_filter.hpp
/// The home the per-agent Response-scope FILTER LOOP (#1712 / #1634 class) is
/// converging on — how a fan-out of response rows is narrowed to the agents a
/// caller may see.
///
/// HONEST STATUS, because overstating this is worse than not having it: three
/// hand-rolled copies of this loop PREDATE this header and are NOT yet
/// migrated — `server.cpp`'s legacy `/api/responses/*` export and get readers,
/// and MCP `query_responses` (`mcp_server.cpp`). They are semantically
/// equivalent (memoize per distinct agent, keep admitted rows, count distinct
/// drops) but structurally drifted, and a future change to the shared loop —
/// drop-count semantics, exception behaviour — would silently miss them.
/// Every reader this header is used by routes through it; migrating the other
/// three is tracked as follow-up work, deliberately not folded into a security
/// fix. Do NOT add a fourth copy: new readers use this function.
///
/// TWO DIFFERENT THINGS, DELIBERATELY SPLIT, because conflating them is how
/// this class of defect keeps recurring:
///
///   - The **decision** ("may `username` see `agent_id`?") has exactly one
///     implementation already: `ServerImpl::response_agent_in_scope`
///     (`server.cpp`), which gates on `rbac_enforcement_in_effect` — NOT raw
///     `is_rbac_enabled()` — so a corrupt/load-failed `rbac_store` denies
///     every agent rather than reading as "RBAC off → no filter". Every
///     response reader (legacy `/api/responses/*`, the REST visualization
///     `ResponseScopeFn`, MCP `query_responses`/`aggregate_responses`, and the
///     two readers #1712 added) routes through that one helper. This header
///     does NOT re-implement, wrap, or second-guess it — it takes it as a
///     predicate parameter.
///
///   - The **mechanics** of applying that decision across a row fan-out —
///     memoize per distinct `agent_id`, keep the admitted rows, count each
///     DISTINCT dropped agent once for the audit row — is what lives here.
///     #1712 originally shipped this loop TWICE, byte-identically, in
///     `dashboard_routes.cpp` (`/fragments/results`) and
///     `workflow_routes.cpp` (the executions drawer). That is the same
///     second-copy drift `dispatch_confined_arms.hpp`,
///     `dispatch_target_shape.hpp`, `authz_topology_floor.hpp` and
///     `body_cap_policy.hpp` each exist to prevent for their own chokepoint,
///     and it has no wrong outcome *today* — which is exactly why a review
///     that only asks "is the behaviour correct?" cannot see it.
///
/// WHAT CALLERS STILL OWN, and must: the FAIL-OPEN-WHEN-UNWIRED test. This
/// function is only reached when the caller has already established it holds a
/// wired predicate; an unwired `ResponseScopeFn` means "no filter" (legacy
/// behaviour for harnesses that wire no RBAC at all) and is decided at the call
/// site, never here. Callers also own their own audit row — the surface label
/// and the audited target id differ per reader, and only the caller knows them.
///
/// Templated on the row type so this header stays free of any store/wire
/// dependency, which is what lets it be unit-tested as a pure function against
/// a two-field fixture struct — no `ResponseStore`, no PostgreSQL, no HTTP.
/// (`tests/unit/server/test_response_scope_filter.cpp`.)

namespace yuzu::server {

/// Per-agent scope predicate: true iff `username` may see `agent_id`'s rows.
/// A FILTER, not a gate — it writes no response and denies nothing by itself.
using ResponseScopePredicate =
    std::function<bool(const std::string& username, const std::string& agent_id)>;

struct ResponseScopeFilterResult {
    /// Number of DISTINCT agents whose rows were dropped. Distinct, not row
    /// count, so a wide fan-out over one out-of-scope agent audits as one
    /// drop rather than N — the audit row answers "whose data was withheld",
    /// not "how many rows did that come to".
    std::size_t dropped_agents{0};
};

/// Narrow @p rows in place to those whose `agent_id` @p in_scope admits.
///
/// FAIL-CLOSED BY CONSTRUCTION: every row must be affirmatively admitted to
/// survive. A predicate that denies everything — which is exactly what
/// `response_agent_in_scope` returns for every agent when the RBAC store is
/// corrupt or unreadable — yields zero rows, never the fleet.
///
/// The predicate is invoked at most ONCE per distinct `agent_id` (memoized),
/// so a wide fan-out does not re-run the RBAC check per row. A consequence
/// worth stating because it is load-bearing rather than incidental: within a
/// single call the FIRST answer for an agent is the one that applies to all of
/// that agent's rows. A store that degrades mid-iteration therefore denies
/// every agent not yet decided — it can never retroactively widen an agent
/// already admitted, and it can never admit one already denied.
///
/// @tparam RowT any type with a `std::string agent_id` member.
template <typename RowT>
ResponseScopeFilterResult filter_rows_in_scope(std::vector<RowT>& rows,
                                               const std::string& username,
                                               const ResponseScopePredicate& in_scope) {
    ResponseScopeFilterResult result;
    std::unordered_map<std::string, bool> memo;
    std::vector<RowT> visible;
    visible.reserve(rows.size());
    for (auto& row : rows) {
        auto [it, inserted] = memo.try_emplace(row.agent_id, false);
        if (inserted)
            it->second = in_scope(username, row.agent_id);
        if (it->second)
            visible.push_back(std::move(row));
        else if (inserted) // count each DISTINCT dropped agent once
            ++result.dropped_agents;
    }
    rows.swap(visible);
    return result;
}

} // namespace yuzu::server
