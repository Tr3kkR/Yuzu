#pragma once

#include <string>

#include "authz_model.hpp" // yuzu::server::authz::VisibleSet

/// @file dispatch_caller.hpp
/// PLAN-006 (verified): `ServerImpl::dispatch_confined` and the three
/// dispatch typedefs that feed it — `McpServer::DispatchFn`,
/// `DashboardRoutes::DispatchFn`, `WorkflowRoutes::CommandDispatchFn` — used
/// to carry only the caller's `exec_visible` VISIBILITY filter, never the
/// caller's IDENTITY. `dispatch_scope_ladder.hpp` can only recover a
/// principal from `ex->dispatched_by` for owner-scoped `from_result_set`
/// expressions; every other dispatch reached the seam anonymously even
/// though the handler had authenticated a real Session moments earlier
/// (CDX-P1-03/K-3 declined to widen the typedefs for this, judging the
/// benefit an audit-completeness LOW — see the comment this struct now
/// answers, at `server.cpp`'s `dispatch_confined`).
///
/// `DispatchCaller` is that missing identity, threaded alongside
/// `exec_visible` through the SAME injection point every surface already
/// uses (`ExecVisibleFn` → `CallerFn`). This header adds no behaviour: it is
/// pure plumbing so a later chokepoint wave can authorize on `principal`
/// instead of merely filtering on `exec_visible`.
namespace yuzu::server {

/// The caller behind a confined dispatch. `principal`/`principal_role` are
/// EMPTY for a call site that has no caller at all — see `system` below —
/// and for one that has a caller but has not yet been wired to identify it
/// (a defaulted/unwired `CallerFn` fails closed on `exec_visible`, never on
/// `principal`: an empty principal alongside a deny-all `exec_visible` is
/// indistinguishable in effect from a wired-but-anonymous caller, and that
/// is deliberate — the VISIBILITY filter is what does the denying here, not
/// the identity field).
struct DispatchCaller {
    /// STABLE authorization principal — mirrors `auth::Session::username`.
    /// Empty when unknown (unwired CallerFn) or not applicable (`system`).
    std::string principal;
    /// Mirrors `auth::role_to_string(auth::Session::role)`. Empty under the
    /// same conditions as `principal`.
    std::string principal_role;
    /// The caller's Execution:Execute visible set (#1788). `nullopt` means
    /// unfiltered — reserved for callers that have deliberately opted out of
    /// confinement (background/system dispatch); every operator-facing
    /// surface's unwired fallback is a PRESENT-EMPTY set (deny-all), never
    /// `nullopt`. See each surface's `CallerFn` doc comment for its specific
    /// fail-closed contract.
    yuzu::server::authz::VisibleSet exec_visible;
    /// True ONLY for a background/system dispatcher that has no session at
    /// all (a policy-engine tick, a scheduled fire with no operator in the
    /// loop, ...). Set explicitly at each such call site — never a default
    /// stand-in for "principal happens to be empty" — so a background
    /// dispatch is a deliberate, greppable statement rather than a value
    /// that merely looks the same as an unwired one.
    bool system = false;
};

} // namespace yuzu::server
