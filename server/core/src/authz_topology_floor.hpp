#pragma once

#include <string_view>

/// @file authz_topology_floor.hpp
/// The ONE place the "topology floor" set is decided (#2376).
///
/// THE DEFECT: `RbacStore::rbac_enabled_` defaults FALSE (a fresh install runs
/// with RBAC off), and with RBAC off `AuthRoutes::require_permission` /
/// `require_scoped_permission` fall through to the legacy branch, which
/// allows every `Read` to any authenticated non-engine session. On a default
/// install that hands a plain `user` fleet-wide read of the authorization
/// TOPOLOGY itself — the access-review export (SOC 2 CC6.2 evidence), the
/// RBAC role graph (`/api/v1/rbac/roles`), and the engine-principal grant
/// graph.
///
/// THE RULE: the reads named below require admin REGARDLESS of the RBAC
/// on/off toggle. This floor is applied ONLY inside the legacy (RBAC-off)
/// fallback of `require_permission`/`require_scoped_permission` — it never
/// overrides a live RBAC grant. That ordering matters: #2324 cut a dedicated
/// `AccessReview` securable specifically so a non-admin `Reviewer` role could
/// be seeded with `AccessReview:Read`; if this floor ran ahead of (or
/// instead of) the live-RBAC branch it would deny that seeded role and
/// destroy the whole reason the securable exists. The floor exists to close
/// the RBAC-OFF gap only.
///
/// The floor is deliberately NOT configurable — a toggle that can re-open a
/// security floor is a footgun, not a feature.
///
/// `Security:Read` was considered and deliberately EXCLUDED: it is too
/// coarse for this purpose — it also gates quarantine visibility, CA
/// issued-certs, `/ca/root-csr`, and KEK status, which are operational reads,
/// not authorization topology. `ApiToken:Read` and `ManagementGroup:Read`
/// were likewise considered and excluded for the same reason.
///
/// EXTEND this set, never fork it — a second copy of a floor set is exactly
/// the kind of drift the repo's other chokepoints (`dispatch_confined_arms.hpp`,
/// `principal_quota_gate.hpp`) exist to prevent.
namespace yuzu::server {

/// One (securable, operation) pair in the topology floor.
struct TopologyFloorEntry {
    std::string_view securable;
    std::string_view operation;
};

/// The topology floor set. `EnginePrincipal` is the securable cut in this
/// same change (#2376) to carry the ADR-0031 engine-principal inventory and
/// grant-graph reads away from the over-broad `Security:Read`; it is seeded
/// in `rbac_store.cpp`'s `seed_defaults()`. Matching here is by string, so
/// this list has no compile-time dependency on that seeding.
inline constexpr TopologyFloorEntry kTopologyFloor[] = {
    {"AccessReview", "Read"},
    {"UserManagement", "Read"},
    {"EnginePrincipal", "Read"},
};

/// True when `(securable, operation)` is in the topology floor, i.e. the
/// legacy RBAC-off fallback must deny it to a non-admin regardless of the
/// generic "Read is always allowed" legacy rule.
[[nodiscard]] inline bool topology_floor_applies(std::string_view securable,
                                                 std::string_view operation) noexcept {
    for (const auto& entry : kTopologyFloor) {
        if (entry.securable == securable && entry.operation == operation)
            return true;
    }
    return false;
}

} // namespace yuzu::server
