#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_pii_scan.hpp
/// One fragment of the command capability catalogue: `pii_scan`'s four
/// actions (`agents/plugins/pii_scan/src/pii_scan_plugin.cpp`). Classified
/// by READING the implementation, not the name, per this package's spec.
/// Every `securable`/`operation` pair reuses an EXISTING `RbacStore`
/// `types[]`/`ops[]` entry; none is minted here — `Security` is the same
/// securable `quarantine`/`firewall`/`certificates` already use for
/// security-posture surfaces (`plugin_action_catalogue_c.hpp`).
///
///   - `scan` — reads file content under operator-supplied `paths` and
///     reports masked findings only (`pii_matcher.hpp::mask_value` — see
///     that file's own doc comment); never writes to the filesystem.
///     ReadOnly/None, `Security:Read`. risk_tier bumped to Medium (above
///     the `Read` floor of Low): unlike a fixed-location read (e.g.
///     `content_dist`'s `list_staged`), the caller names arbitrary
///     filesystem paths, so the blast radius of what gets read is
///     operator-controlled, not plugin-fixed — matching the same
///     "caller-scoped read, bump above floor" reasoning applied elsewhere
///     in this catalogue.
///   - `enable_realtime` — registers a STANDING filesystem trigger
///     (`agent's TriggerEngine`, `pii_scan_plugin.cpp`'s `enable_realtime`
///     action) that causes ongoing, unattended re-scans of a directory
///     tree for as long as the agent process keeps running. NOTE:
///     `TriggerEngine::register_trigger` is purely in-memory -- there is
///     no load/save/persist path anywhere in this codebase -- so an
///     agent restart silently and permanently stops realtime scanning
///     with no operator-visible signal; an earlier version of this
///     comment claimed the trigger "persists across agent restarts",
///     which was never true. The risk_tier reasoning below does not
///     depend on that false claim (it's about installing unattended,
///     ongoing behaviour while the agent process is alive, not about
///     restart survival), so the classification itself is unaffected --
///     only the prose was wrong. Classified Mutating/
///     Reversible (undone by `disable_realtime`) rather than Destructive:
///     it changes agent-local trigger configuration, not host or network
///     state, and carries a compensating action. `Security:Write`,
///     risk_tier bumped to High (above the `Write` floor of Medium): this
///     installs unattended, ongoing behaviour on the endpoint rather than
///     a one-shot mutation, matching the `InstructionDefinition`'s own
///     `approval.mode: role-gated` for this action (`content/definitions/
///     pii_scan.yaml`) — this row and that YAML gate must not drift.
///   - `disable_realtime` — unregisters the trigger `enable_realtime`
///     installed. Mutating/Reversible for the same reason (re-enabling
///     restores it). Gated the same as `enable_realtime` rather than left
///     ungated: silently turning off a security-scanning trigger is its
///     own security-relevant event (potential detection evasion), not a
///     lower-stakes action than installing one — mirrors this catalogue's
///     precedent of gating a mutating "undo" action the same as the
///     action it undoes (see `plugin_action_catalogue_c.hpp`'s
///     `unquarantine`, gated identically to `quarantine` itself).
///     `Security:Write`, risk_tier at the `Write` floor of Medium (lower
///     than `enable_realtime`: this row only reverts to the default
///     no-realtime-scanning state, it does not itself install new
///     standing behaviour).
///   - `scan_path` — the action the realtime filesystem trigger installed
///     by `enable_realtime` actually fires (`pii_scan_plugin.cpp`'s own
///     doc comment: "Internal ... but harmless to call directly"). Routed
///     to the exact same `run_scan` handler as `scan` with no different
///     read surface, so it is classified identically: ReadOnly/None,
///     `Security:Read`, risk_tier Medium, ungated. Needs its OWN row
///     despite being handler-identical to `scan` — the capability
///     catalogue keys on the exact dispatched action STRING
///     (`CommandCapabilityRegistry::classify`), and `scan_path` is a real,
///     separately-reachable action name once a realtime trigger exists,
///     not an alias `scan`'s row implicitly covers.
namespace yuzu::server::capdecls {

namespace detail {

inline constexpr std::array<CommandCapability, 4> kPluginActionCataloguePiiScan{{
    {
        .plugin = "pii_scan",
        .action = "scan",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
    {
        .plugin = "pii_scan",
        .action = "enable_realtime",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible,
        .securable = "Security",
        .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::High,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "pii_scan",
        .action = "disable_realtime",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible,
        .securable = "Security",
        .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::AdminOrApproval,
    },
    {
        .plugin = "pii_scan",
        .action = "scan_path",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
        .execute_gate = ExecuteGate::None,
    },
}};

// #1398: every row in kPluginActionCataloguePiiScan must author
// .execute_gate — an omission would value-initialize to
// ExecuteGate::Unspecified (the zero enumerator), which is a genuine
// compile failure here rather than a silent runtime gap. See
// ExecuteGate's doc comment in command_capability.hpp.
static_assert(::yuzu::server::detail::all_gates_specified(kPluginActionCataloguePiiScan),
              "every row in kPluginActionCataloguePiiScan must author .execute_gate");

} // namespace detail

/// A `std::span` view over the fixed catalogue above — one of the several
/// sources a `CommandCapabilityRegistry` is composed from. Inline function
/// over file-scope `constexpr` storage: this header only DECLARES rows, it
/// never aggregates or singleton-owns a registry.
[[nodiscard]] inline std::span<const CommandCapability> plugin_action_catalogue_pii_scan() noexcept {
    return detail::kPluginActionCataloguePiiScan;
}

} // namespace yuzu::server::capdecls
