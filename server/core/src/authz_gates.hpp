#pragma once

#include "authz_model.hpp"

#include <cstdint>
#include <string>
#include <vector>

/// @file authz_gates.hpp
/// The two composite authority gates for list/fan-out and single-agent
/// reads, both defined out-of-line as `AuthRoutes` methods (authz_gates.cpp)
/// because they need `AuthRoutes`'s private `rbac_store_`/`mgmt_group_store_`/
/// `tag_store_`/`require_auth`/`audit_log`. Declared here rather than
/// directly in auth_routes.hpp only to keep `ListAuthority`'s definition
/// (and its `AuthRoutes`-only construction) out of that already-large header.
///
/// PHASE 0 (this PR): wired, tested, called by NO route. The default-deny
/// flip that starts routing traffic through these lives in a later PR.
namespace yuzu::server {
class AuthRoutes;
}

namespace yuzu::server::authz {

/// Why `authorize_fleet_read` did not produce a `ListAuthority`.
enum class GateFailure : std::uint8_t {
    Forbidden, ///< 403 — the management-group axis returned DenyAll (a real
               ///< deny OR a store/mgmt-store error; see rbac_store.hpp's
               ///< `authorize_list_read` doc — the promise is deliberately
               ///< weakened here rather than adding a discriminator).
    Degraded,  ///< 503 — the service-scope axis's tag-store lookup failed
               ///< (null `tag_store_`, or a degraded/failed query). Distinct
               ///< from Forbidden because it is retryable.
};

/// Move-only witness over an already-composed `VisibleSet` — the product of
/// `AuthRoutes::authorize_fleet_read`. `in_scope`/`filter` are the only
/// operations exposed on the witness itself.
///
/// Ergonomic, not structural: the stores this wraps still accept ordinary
/// unfiltered queries called directly, so `ListAuthority` does not make an
/// unconfined query path unreachable — it makes the confined path the easy,
/// obvious one. Only `AuthRoutes` can construct one (friend), which is what
/// keeps "call the gate" the sole way to obtain a witness.
class ListAuthority {
public:
    ListAuthority(ListAuthority&&) noexcept = default;
    ListAuthority& operator=(ListAuthority&&) noexcept = default;
    ListAuthority(const ListAuthority&) = delete;
    ListAuthority& operator=(const ListAuthority&) = delete;

    /// Whether `agent_id` is admitted — see `authz::in_scope`.
    [[nodiscard]] bool in_scope(const std::string& agent_id) const {
        return authz::in_scope(visible_, agent_id);
    }

    /// Narrow an already-resolved id list to this authority — see
    /// `authz::filter_to_scope`.
    template <class Ids>
    [[nodiscard]] std::vector<std::string> filter(const Ids& ids) const {
        return authz::filter_to_scope(ids, visible_);
    }

    /// True iff this authority is TOP (unfiltered) — a non-service session
    /// with a global management-group grant. Callers that branch on this to
    /// choose an unfiltered store query still get a real filter for every
    /// other case, including every service-scoped session (never top).
    [[nodiscard]] bool unfiltered() const { return !visible_.has_value(); }

    /// The raw `VisibleSet`, for a caller that must hand the scope to a
    /// store query (e.g. a SQL id-list) rather than filter an
    /// already-resolved list.
    [[nodiscard]] const VisibleSet& visible_for_query() const { return visible_; }

private:
    friend class yuzu::server::AuthRoutes;
    explicit ListAuthority(VisibleSet visible) : visible_(std::move(visible)) {}

    VisibleSet visible_;
};

} // namespace yuzu::server::authz
