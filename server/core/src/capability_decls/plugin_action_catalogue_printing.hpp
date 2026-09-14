#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_printing.hpp
/// One fragment of the command capability catalogue: `printing`'s two
/// read-only actions (`agents/plugins/printing/src/printing_plugin.cpp`).
/// Classified by READING the implementation, per this package's spec.
///
/// `printers`/`jobs` are ReadOnly/None — neither opens a mutating handle nor
/// issues a mutating IPP request on any platform; grouped under the
/// existing `Inventory` securable, the same read-only-fact-collection
/// precedent `power_health`'s three read actions use
/// (`plugin_action_catalogue_power_health.hpp`).
///
/// A focused follow-up PR on top of this one adds `clear_queue`, this
/// plugin's only mutating action (Destructive/Irreversible, admin-or-
/// approval) — its own row and targeting-gate reach are documented there.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 2> kPluginActionCataloguePrinting{{
    {
        .plugin = "printing",
        .action = "printers",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "printing",
        .action = "jobs",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
}};

// #1398: every row in kPluginActionCataloguePrinting must author
// .execute_gate — an omission would value-initialize to
// ExecuteGate::Unspecified (the zero enumerator), which is a genuine compile
// failure here rather than a silent runtime gap. See ExecuteGate's doc
// comment in command_capability.hpp.
static_assert(
    ::yuzu::server::detail::all_gates_specified(kPluginActionCataloguePrinting),
    "every row in kPluginActionCataloguePrinting must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function
/// over file-scope `constexpr` storage: this header only DECLARES rows, it
/// never aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_printing() noexcept {
    return detail::kPluginActionCataloguePrinting;
}

} // namespace yuzu::server::capdecls
