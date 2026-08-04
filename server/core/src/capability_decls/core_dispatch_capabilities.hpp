#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file core_dispatch_capabilities.hpp
/// The ONE fragment of the command capability catalogue this package owns:
/// the three dispatches the SERVER issues to itself rather than on a
/// caller's behalf. Every other `capability_decls/*.hpp` fragment (the five
/// per-group plugin.action catalogues) belongs to a different package and is
/// composed alongside this one only at the `CommandCapabilityRegistry`
/// construction site — never merged into this array.
///
/// The three rows, each `system_reserved = true` because none of them is
/// reachable via an operator-attributable RBAC decision — they run on the
/// server's own schedule/reconcile loops:
///
///   - `tar.fleet_snapshot` (`server.cpp:2427`) — the periodic fleet-wide
///     snapshot pull. Read-only: it asks agents to report, it does not
///     change agent state.
///   - `__guard__.push_rules` (`server.cpp:2907`, `:14195`) — the Guardian
///     rule-set push/reconcile. Mutating-but-reversible: it replaces the
///     agent's active rule set, and a subsequent push replaces it again;
///     nothing about it is destructive.
///   - `asset_tags.sync` (`server.cpp:6586`) — structured tag-category sync
///     to an agent. Mutating-but-reversible for the same reason: a later
///     sync simply supersedes the prior one.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 3> kCoreDispatchCapabilities{{
    {
        .plugin = "tar",
        .action = "fleet_snapshot",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Response",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = true,
    },
    {
        .plugin = "__guard__",
        .action = "push_rules",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible,
        .securable = "GuaranteedState",
        .operation = authz::Operation::Push,
        .risk_tier = authz::RiskTier::High,
        .system_reserved = true,
    },
    {
        .plugin = "asset_tags",
        .action = "sync",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible,
        .securable = "Tag",
        .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = true,
    },
}};

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function
/// over file-scope `constexpr` storage, deliberately not a `CommandCapabilityRegistry`
/// instance itself: this header only DECLARES rows, it never aggregates or
/// singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability> core_dispatch_capabilities() noexcept {
    return detail::kCoreDispatchCapabilities;
}

} // namespace yuzu::server::capdecls
