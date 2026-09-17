#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_cert_scan.hpp
/// One fragment of the command capability catalogue: `cert_scan`'s single
/// action (`agents/plugins/cert_scan/src/cert_scan_plugin.cpp`). Classified
/// by READING the implementation, not the name, per this package's spec.
/// `Security` is the same securable `certificates`/`pii_scan`/`quarantine`/
/// `firewall` already use for security-posture surfaces
/// (`plugin_action_catalogue_c.hpp`).
///
///   - `scan` -- reads file content under every local user's home
///     directory (auto-discovered per-OS when `paths` is empty -- the
///     plugin's DEFAULT behaviour, broader in reach than a fixed-location
///     read) or an operator-supplied `paths` override, and reports
///     structural metadata findings only: a certificate's subject/issuer/
///     validity/serial/thumbprint, or a classification label + severity
///     for a private key/container/CSR. Never writes to the filesystem,
///     never emits raw key material or certificate bytes (see the
///     plugin's own file header comment). ReadOnly/None, `Security:Read`.
///     risk_tier bumped to Medium (above the `Read` floor of Low),
///     mirroring `pii_scan`'s own `scan` action
///     (`plugin_action_catalogue_pii_scan.hpp`): the DEFAULT scope here is
///     every local user's home directory system-wide, not a plugin-fixed
///     location, so the blast radius of what gets read is broader than a
///     `certificates`/`license_scan`-style fixed-store read (both stay at
///     the `Read` floor of Low). Not bumped to High: unlike `pii_scan`'s
///     `enable_realtime`, this is a single one-shot read with no standing
///     effect, and findings never carry the underlying secret bytes --
///     only a Critical/High severity label and a file path, the same
///     "classification only, never the material itself" shape that keeps
///     `pii_scan`'s masked-value `scan` at Medium rather than High.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 1> kPluginActionCatalogueCertScan{{
    {
        .plugin = "cert_scan",
        .action = "scan",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
}};

// #1398: every row in kPluginActionCatalogueCertScan must author
// .execute_gate -- an omission would value-initialize to
// ExecuteGate::Unspecified (the zero enumerator), which is a genuine
// compile failure here rather than a silent runtime gap. See
// ExecuteGate's doc comment in command_capability.hpp.
static_assert(::yuzu::server::detail::all_gates_specified(kPluginActionCatalogueCertScan),
              "every row in kPluginActionCatalogueCertScan must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above -- one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function
/// over file-scope `constexpr` storage: this header only DECLARES rows, it
/// never aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability> plugin_action_catalogue_cert_scan() noexcept {
    return detail::kPluginActionCatalogueCertScan;
}

} // namespace yuzu::server::capdecls
