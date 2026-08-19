#pragma once

#include <array>
#include <cctype>
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

/// #3289: the tag key that IS a service-scoped token's own confinement
/// boundary (`AuthRoutes::require_scoped_permission`'s service branch reads
/// this key via `TagStore::get_tag` to decide admission). Every confinement
/// reader and every tag-mutation guard key on this single definition — a
/// second copy is the drift this seam exists to remove for `kPermPair`-shaped
/// policy above.
inline constexpr std::string_view kServiceTagKey = "service";

/// ASCII case-insensitive match against `kServiceTagKey`. Tag keys are
/// user-supplied strings (REST/MCP/legacy dashboard callers, and the agent's
/// own `tags.json`), so a `"Service"`/`"SERVICE"` variant must not bypass the
/// mutation guard below.
[[nodiscard]] inline bool is_service_tag_key(std::string_view key) {
    if (key.size() != kServiceTagKey.size())
        return false;
    for (std::size_t i = 0; i < key.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(key[i])) !=
            std::tolower(static_cast<unsigned char>(kServiceTagKey[i])))
            return false;
    }
    return true;
}

/// #3289: may a session whose token scope is `scope` mutate (write OR
/// delete) tag `key`? Deny iff `scope` is non-empty (i.e. the session is
/// service-scoped) and `key` is the service tag — VALUE-BLIND by design: even
/// a no-op rewrite of the token's own current value is denied. The tag being
/// mutated is the same datum `require_scoped_permission`'s service branch
/// reads to decide admission (`auth_routes.cpp:1065`), so authorizing a write
/// to it from its own pre-write value is a TOCTOU the value-blind rule avoids
/// entirely rather than closing with a read-compare.
[[nodiscard]] inline bool service_scope_may_mutate_tag_key(std::string_view scope,
                                                            std::string_view key) {
    return scope.empty() || !is_service_tag_key(key);
}

} // namespace yuzu::server::authz
