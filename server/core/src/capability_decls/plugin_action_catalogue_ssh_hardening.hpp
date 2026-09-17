#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_ssh_hardening.hpp
/// One fragment of the command capability catalogue: `ssh_hardening`'s
/// single action (`agents/plugins/ssh_hardening/src/ssh_hardening_plugin.cpp`).
/// Classified by READING the implementation, not the name, per this
/// package's spec. `Security` is the same securable `certificates`/
/// `pii_scan`/`cert_scan`/`quarantine`/`firewall` already use for
/// security-posture surfaces (`plugin_action_catalogue_c.hpp`).
///
///   - `audit` -- reads a fixed-location file (`/etc/ssh/sshd_config` and
///     any files it Includes, a plugin-owned path with no operator input
///     at all -- `spec.parameters.properties` in
///     `content/definitions/ssh_hardening.yaml` is empty) and reports
///     structural findings (which directive violates the Mozilla Modern
///     baseline). Never writes to the filesystem. ReadOnly/None,
///     `Security:Read`, risk_tier at the `Read` floor of Low -- unlike
///     `pii_scan`/`cert_scan`'s own `scan` actions (bumped to Medium
///     because the caller names arbitrary paths), this action's read
///     surface is entirely fixed by the plugin itself, matching the same
///     "fixed-location read stays at the floor" precedent
///     `certificates`/`license_scan` already establish in this catalogue.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 1> kPluginActionCatalogueSshHardening{{
    {
        .plugin = "ssh_hardening",
        .action = "audit",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
}};

// #1398: every row in kPluginActionCatalogueSshHardening must author
// .execute_gate -- an omission would value-initialize to
// ExecuteGate::Unspecified (the zero enumerator), which is a genuine
// compile failure here rather than a silent runtime gap. See
// ExecuteGate's doc comment in command_capability.hpp.
static_assert(::yuzu::server::detail::all_gates_specified(kPluginActionCatalogueSshHardening),
              "every row in kPluginActionCatalogueSshHardening must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above -- one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function
/// over file-scope `constexpr` storage: this header only DECLARES rows, it
/// never aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability>
plugin_action_catalogue_ssh_hardening() noexcept {
    return detail::kPluginActionCatalogueSshHardening;
}

} // namespace yuzu::server::capdecls
