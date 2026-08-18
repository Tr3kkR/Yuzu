#pragma once

#include <array>
#include <string_view>

/// @file service_scope_policy.hpp
/// The service-scope global-safe allow-list: `(securable_type, operation)`
/// pairs a service-scoped token may exercise UNCONFINED — i.e. without the
/// per-agent/`service`-tag narrowing `AuthRoutes::require_fleet_read` /
/// `confine_agent_target` (authz_gates.hpp) otherwise apply.
///
/// Seeded EMPTY. This is deliberate, not a placeholder to fill in "later":
/// the whole point of the default-deny flip (`require_permission`'s
/// service-token branch, PR 3) is that a pair gates confined data unless
/// PROVEN otherwise. Adding an entry here widens every service-scoped token
/// in the fleet at once, so it requires:
///   1. Proof derived from what the DATA actually is — never from the one
///      route being changed at the time (the #2376 rule: a pair can look
///      safe from a single call site and still gate per-agent data from a
///      different one).
///   2. A `.claude/routed-concerns-access-control.md` update recording the
///      proof.
///   3. security-guardian sign-off.
namespace yuzu::server::authz {

/// A (securable_type, operation) key — the same pair shape
/// `RbacStore::check_role_has_permission` and `mcp::tier_allows` key on.
struct PermPair {
    std::string_view securable_type;
    std::string_view operation;
};

/// The allow-list. Empty until an entry clears the bar documented above.
inline constexpr std::array<PermPair, 0> kServiceScopeGlobalSafe{};

/// Whether a service-scoped token may exercise `(securable_type, operation)`
/// unconfined. False for everything while `kServiceScopeGlobalSafe` is empty.
[[nodiscard]] inline bool service_scope_global_safe(std::string_view securable_type,
                                                    std::string_view operation) {
    for (const auto& pair : kServiceScopeGlobalSafe) {
        if (pair.securable_type == securable_type && pair.operation == operation)
            return true;
    }
    return false;
}

} // namespace yuzu::server::authz
