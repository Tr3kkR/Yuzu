#pragma once

#include <string_view>

/// @file rbac_assignable_roles.hpp
/// The closed set of built-in RBAC role names assignable via A2 — the
/// global human role-assignment surface
/// (`.claude/plans/rbac-industry-leading-DELIVERY-PLAN.md` §2):
/// `POST/DELETE /api/v1/rbac/roles/{name}/assignments` (rest_api_v1.cpp) and
/// its MCP twins `assign_rbac_role`/`unassign_rbac_role` (mcp_server.cpp).
///
/// WHY THIS EXISTS (adversarial-review finding, PR1/A2 "Should fix" #1): of
/// the 7 seeded roles, `ITServiceOwner` is excluded from this fleet-wide
/// surface — see `rbac_admin_predicate.hpp` / the A2 route's own doc comment
/// for the full reasoning (its 92-permission grant is designed around
/// group-scoped confinement this surface does not carry). Before this file
/// existed, the route/tool handlers rejected ONLY `ITServiceOwner` and a
/// genuinely-unknown role name — any OTHER existing role, including an
/// `is_system=false` CUSTOM role, was silently accepted, contradicting the
/// shipped docs' own claim of a closed 6-role set
/// (`docs/user-manual/rbac.md` "Fleet-Wide Role Assignment"). `RbacStore::
/// create_role` has zero production route callers today (a custom role can
/// only exist via direct SQL against a live database), so this was not a
/// live escalation path — but the code must still enforce what the docs
/// promise, not merely happen to agree with it while nothing exercises the
/// gap.
///
/// THE RULE: a role name is assignable through A2 iff it is one of these six
/// literals — EXACTLY the 7 seeded roles (`rbac_store.cpp`'s
/// `seed_defaults()`) minus `ITServiceOwner`. Not "any existing role in the
/// store", not "any `is_system` role" — a closed, hand-maintained list, so a
/// future 8th seeded role does NOT become assignable here by default.
///
/// EXTEND this, never fork it — REST route validation
/// (`rest_api_v1.cpp`) and `assign_rbac_role`'s MCP tool `role` input schema
/// `enum` (mcp_server.cpp's `kTools` entry) must both agree with this ONE
/// list. The MCP schema enum is a hand-typed JSON string literal (this
/// codebase's existing convention for every MCP input schema — there is no
/// C++-to-JSON-schema generation step anywhere in this file), so it cannot
/// include this header directly; `test_rbac_role_assignment.cpp`'s
/// "rbac_assignable_roles.hpp's kRbacAssignableRoles matches
/// assign_rbac_role's MCP tool schema role enum exactly" test asserts the
/// two stay in sync, by parsing the SERVED schema (mcp_server_testonly.hpp's
/// `input_schemas_for_test()`), not a second hand-copied literal.
/// `unassign_rbac_role`'s `role` field is DELIBERATELY unrestricted (its own
/// schema comment: unassign must stay able to clean up an out-of-band grant
/// — e.g. ITServiceOwner, or a custom role assigned by direct SQL — that
/// `assign_rbac_role` could never have created), so this sync guarantee is
/// scoped to `assign_rbac_role` only; there is no enum on the unassign side
/// for it to drift from.
namespace yuzu::server {

inline constexpr std::string_view kRbacAssignableRoles[] = {
    "Administrator", "PlatformEngineer", "Operator", "ApiTokenManager", "Viewer", "Reviewer",
};

/// True iff `role_name` is one of the six names above.
[[nodiscard]] inline bool is_rbac_assignable_role(std::string_view role_name) noexcept {
    for (auto r : kRbacAssignableRoles)
        if (r == role_name)
            return true;
    return false;
}

} // namespace yuzu::server
