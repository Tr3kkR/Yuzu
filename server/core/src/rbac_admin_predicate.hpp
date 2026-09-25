#pragma once

#include "rbac_store.hpp"

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

#include <string_view>

/// @file rbac_admin_predicate.hpp
/// THE gate for "is this caller allowed to author a fleet-wide RBAC role
/// grant" (A2, `.claude/plans/rbac-industry-leading-DELIVERY-PLAN.md` §2 "A2
/// — Global human role assignment/unassignment").
///
/// WHY THIS EXISTS: granting (or revoking) a role — especially `Administrator`
/// itself — is a stronger security decision than an ordinary permission
/// check. An `Administrator` grant is not merely a `Security:Write`-gated
/// mutation; it is the act of minting NEW standing Administrator authority
/// (or removing the last of it), so `POST/DELETE
/// /api/v1/rbac/roles/{name}/assignments` and their MCP twins are gated on
/// this dedicated predicate INSTEAD OF `perm_fn`/`require_permission`, not in
/// addition to it. A future PR in this same delivery plan (A1's
/// enable/disable toggle, §2 "A1 — Enable/disable toggle") reuses this
/// predicate verbatim — EXTEND it, never fork it, exactly like
/// `authz_topology_floor.hpp`'s own rule.
///
/// THE RULE: a caller passes iff they hold a DURABLE `Administrator`
/// authority right now, re-read fresh from the store rather than trusted
/// from the session's cached view:
///
///   - **RBAC enforcement OFF** (`!rbac_enforcement_in_effect(rbac_store)`):
///     re-read `auth_db->get_user(session.username)` and require
///     `.role == auth::Role::admin`. This is a DURABLE re-read, not
///     `session.role` — a session minted before an admin was demoted must
///     not keep authoring role grants for the lifetime of that session.
///   - **RBAC enforcement ON** (enabled, OR degraded — see
///     `rbac_enforcement_in_effect`'s own fail-closed doc comment):
///     require a `principal_roles` row for
///     `(principal_type="user", principal_id=session.username,
///     role_name="Administrator")`, via `get_principal_roles_checked`.
///
/// Four decisions this predicate makes explicit, each deliberate and
/// documented HERE rather than left implicit at a call site:
///
/// 1. **JIT elevation does NOT satisfy this predicate.** `auth::is_elevated`/
///    `auth::effective_role` are deliberately NOT consulted — both branches
///    above read a DURABLE role/grant, and an elevated `user`-role session's
///    durable row still reads `role='user'` (off) or carries no
///    `Administrator` `principal_roles` row (on). A time-boxed elevation
///    authorizing a temporary admin action must never be laundered into a
///    standing role grant that outlives the elevation window.
/// 2. **A group-held `Administrator` grant does NOT satisfy this
///    predicate**, even with RBAC on. `get_principal_roles_checked` is
///    called with `principal_type="user"` only — a caller whose only path to
///    `Administrator` is via `group_members` + a `principal_roles(group, …,
///    Administrator)` row is DENIED here. Deliberate A2 scope limit (the
///    delivery plan defers `principal_type=group` assignment entirely); this
///    predicate fails closed on that gap rather than silently admitting it.
/// 3. **Service-scoped tokens and engine sessions are structurally denied**,
///    unconditionally, before any I/O — the same posture
///    `AuthRoutes::require_admin` already carries (auth_routes.cpp) for
///    every other admin-only route. A service-scoped token's authority
///    ceiling is `ITServiceOwner`-equivalent regardless of what the minting
///    human holds; an engine session can never durably resolve `role=admin`
///    or hold `Administrator` (`RbacStore::validate_assignment` bars it
///    structurally), but denying it here too keeps this predicate fail-closed
///    entirely on its own, without relying on that other chokepoint holding.
/// 4. **Pre-provisioning is a caller decision, not this predicate's.** This
///    file answers only "is the CALLING session an administrator" — whether
///    a role may be ASSIGNED to a target username with no `auth.users` row
///    is a separate question the route/tool handler answers (see the A2
///    route's own doc comment).
///
/// Fail-closed on any I/O uncertainty: a `RbacStore`/`AuthDB` degrade that
/// cannot confirm admin authority returns `kUnavailable` (map to 503,
/// retryable) — never silently downgraded to `kDenied` (403), which would
/// let a transient store hiccup masquerade as a permanent policy denial, and
/// never silently upgraded to `kAdmin`, which would be a privilege-escalation
/// bug on every degrade.
namespace yuzu::server {

/// Outcome of `is_rbac_administrator`. Mirrors the shape of
/// `EngineLookupStatus` (`engine_principal_store.hpp`) — a terminal ALLOW, a
/// terminal DENY, and a retryable "could not confirm either way" — rather
/// than collapsing "not admin" and "can't tell" into one boolean.
enum class RbacAdminGate {
    kAdmin,       ///< Confirmed durable Administrator authority. Proceed.
    kDenied,      ///< Confirmed NOT administrator (or structurally excluded
                  ///< — service-scoped token, engine session). Terminal,
                  ///< 403-class.
    kUnavailable, ///< Could not confirm — a required store is null, closed,
                  ///< or a read degraded. Retryable, 503-class. NEVER treat
                  ///< this as either `kAdmin` or `kDenied`.
};

/// Evaluate the RBAC-administrator gate for `session`. See the file header
/// for the full rule and its four deliberate scope decisions. `rbac_store`
/// and `auth_db` are read-only from this function's perspective (no
/// mutation); both are required — a null pointer for the store the active
/// branch needs is `kUnavailable`, never treated as "assume the other
/// branch".
[[nodiscard]] inline RbacAdminGate is_rbac_administrator(const auth::Session& session,
                                                          AuthDB* auth_db,
                                                          const RbacStore* rbac_store) {
    // Structural exclusions first — no I/O, fail-closed, matches
    // AuthRoutes::require_admin's posture for every other admin-only route
    // (decision 3 above).
    if (session.is_engine())
        return RbacAdminGate::kDenied;
    if (!session.token_scope_service.empty())
        return RbacAdminGate::kDenied;

    // Both branches below need to know whether RBAC enforcement is in
    // effect, which itself needs a live `rbac_store` — a null store means
    // we cannot even pick a branch, let alone answer it.
    if (!rbac_store)
        return RbacAdminGate::kUnavailable;

    if (rbac_enforcement_in_effect(rbac_store)) {
        auto rows = rbac_store->get_principal_roles_checked("user", session.username);
        if (!rows.has_value())
            return RbacAdminGate::kUnavailable;
        for (const auto& pr : *rows) {
            if (pr.role_name == "Administrator")
                return RbacAdminGate::kAdmin;
        }
        return RbacAdminGate::kDenied;
    }

    // RBAC-off branch: durable re-read from AuthDB (decision 1 — never the
    // session's own cached role/elevation state).
    if (!auth_db)
        return RbacAdminGate::kUnavailable;
    auto user = auth_db->get_user(session.username);
    if (!user.has_value()) {
        if (is_store_unavailable(user.error()))
            return RbacAdminGate::kUnavailable;
        // UserNotFound / InvalidUsername / etc — a definitive "this session's
        // principal has no durable admin row", not a store problem.
        return RbacAdminGate::kDenied;
    }
    return user->role == auth::Role::admin ? RbacAdminGate::kAdmin : RbacAdminGate::kDenied;
}

/// True when `target_principal` names the CURRENTLY authenticated caller's
/// own stable principal (`session.username`) — the self-target-destruction
/// comparison used at `settings_routes.cpp`'s self-delete
/// (`user.delete`/#397) and self-role-change (`user.role_change`/#403)
/// guards, lifted here per those guards' own doc comment: a third call site
/// (A2's unassign-own-Administrator-grant guard) is exactly the trigger
/// named there. EXTEND this, never fork a second copy of the comparison.
///
/// An EMPTY `session.username` fails closed to `true` (self) — the same
/// defense-in-depth both existing call sites already comment on
/// individually: an unstamped/misconfigured session must never let a bare
/// `"" == ""` comparison read as "not self" and admit a destructive
/// self-target mutation. Both existing call sites already refuse an empty
/// `session.username` with a 500 before ever reaching this comparison, so in
/// practice this fail-closed branch is defense-in-depth, not the primary
/// guard.
[[nodiscard]] inline bool is_self_target(const auth::Session& session,
                                         std::string_view target_principal) {
    if (session.username.empty())
        return true;
    return session.username == target_principal;
}

} // namespace yuzu::server
