#pragma once

#include <array>
#include <span>

#include "../authz_model.hpp"
#include "../command_capability.hpp"

/// @file plugin_action_catalogue_d.hpp
/// PR1.10 group D + PR1.9 data D: the capability-classification fragment for
/// the 15 endpoint-management plugins this package owns (group D of the
/// 49-plugin sweep — groups A/B/C and p7's content_dist classify the rest).
/// One row per OPERATOR-DISPATCHABLE action; `asset_tags.sync` is
/// deliberately excluded — it is `system_reserved` and already carried by
/// p1's `core_dispatch_capabilities.hpp` (the server, never an operator,
/// issues that dispatch — see that header's row comment). Composed alongside
/// every other `capability_decls/*.hpp` fragment only at the
/// `CommandCapabilityRegistry` construction site, never merged here.
///
/// Classification method: `dispatch_class` / `mutability` / `securable` /
/// `operation` are read off each plugin's ACTUAL implementation (never its
/// name), `securable` reuses only an `RbacStore::seed_defaults()`-seeded
/// type (`rbac_store.cpp:292-339`), `operation` reuses only a
/// `seed_defaults()`-seeded op (`rbac_store.cpp:380`), and every
/// `risk_tier >= min_risk_tier_for(operation)` (`authz_model.hpp`).
/// `system_reserved` is `false` on every row below — none of these 41 rows
/// is a server-self-issued dispatch.
///
/// FOUR of the six plugins the originating spec called out as carrying
/// "the arbitrary-code and endpoint-mutation surface" — `bitlocker`,
/// `msi_packages`, `software_actions`, and `agent_actions` — turn out, on
/// reading the code, to expose ONLY read-only query actions for the rows
/// listed below (`bitlocker.state`; `msi_packages.list`/`product_codes`;
/// `software_actions.list_upgradable`/`installed_count`;
/// `agent_actions.info`): none of the four plugins' shipped `actions()`
/// tables contains an install/uninstall/encrypt/write action at all. Per
/// this fragment's own "decide by reading the implementation, not the name"
/// mandate, those specific rows are classified `DispatchClass::ReadOnly`
/// here rather than forced non-`ReadOnly` — flagged for the Architect
/// alongside this patch; `script_exec` (arbitrary command/script execution)
/// and `interaction` (visible, device-facing dialogs/notifications, plus
/// `set_dnd`'s persisted local state) are the two members of that same list
/// whose rows genuinely do warrant a non-`ReadOnly` classification, and are
/// classified that way below.
namespace yuzu::server::capdecls {

namespace detail {

using yuzu::server::DispatchClass;
using yuzu::server::Mutability;
namespace authz = yuzu::server::authz;

inline constexpr std::array<CommandCapability, 41> kPluginActionCatalogueD{{
    // ── tags (agents/plugins/tags/src/tags_plugin.cpp) ──────────────────────
    // Local <data_dir>/tags.json store; no server round-trip. All 7 actions
    // from the plugin's actions() table, in order.
    {
        .plugin = "tags",
        .action = "set",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible, // overwriting the key restores prior shape
        .securable = "Tag",
        .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::Medium,
    },
    {
        .plugin = "tags",
        .action = "get",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Tag",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
    },
    {
        .plugin = "tags",
        .action = "get_all",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Tag",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
    },
    {
        .plugin = "tags",
        .action = "delete",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible, // a later `set` of the same key restores it
        .securable = "Tag",
        .operation = authz::Operation::Delete,
        .risk_tier = authz::RiskTier::High,
    },
    {
        .plugin = "tags",
        .action = "check",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Tag",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
    },
    {
        // Conservative: wipes every local tag in one call, unlike a single
        // `delete` — classified Destructive/Irreversible rather than
        // Mutating/Reversible (`delete`'s treatment) per the "when
        // ambiguous, prefer Irreversible" guidance.
        .plugin = "tags",
        .action = "clear",
        .dispatch_class = DispatchClass::Destructive,
        .mutability = Mutability::Irreversible,
        .securable = "Tag",
        .operation = authz::Operation::Delete,
        .risk_tier = authz::RiskTier::High,
    },
    {
        .plugin = "tags",
        .action = "count",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Tag",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
    },

    // ── asset_tags (agents/plugins/asset_tags/src/asset_tags_plugin.cpp) ───
    // `sync` is DELIBERATELY OMITTED: it is server.cpp's own push
    // (server.cpp:6586), already classified `system_reserved = true` by
    // p1's core_dispatch_capabilities.hpp — duplicating it here would be
    // Ambiguous under CommandCapabilityRegistry::classify. The 3 remaining
    // actions are pure local-cache reads.
    {
        .plugin = "asset_tags",
        .action = "status",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Tag",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
    },
    {
        .plugin = "asset_tags",
        .action = "get",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Tag",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
    },
    {
        .plugin = "asset_tags",
        .action = "changes",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Tag",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
    },

    // ── interaction (agents/plugins/interaction/src/interaction_plugin.cpp) ─
    // Desktop notifications/dialogs/DND: every action produces a visible or
    // persisted device-facing effect (a dialog on screen, a toggled DND
    // flag) — never an inert read — so all 5 are Mutating, never ReadOnly.
    {
        .plugin = "interaction",
        .action = "notify",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible,
        .securable = "Infrastructure",
        .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::Medium,
    },
    {
        .plugin = "interaction",
        .action = "message_box",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible,
        .securable = "Infrastructure",
        .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::Medium,
    },
    {
        .plugin = "interaction",
        .action = "input",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible,
        .securable = "Infrastructure",
        .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::Medium,
    },
    {
        .plugin = "interaction",
        .action = "survey",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible,
        .securable = "Infrastructure",
        .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::Medium,
    },
    {
        .plugin = "interaction",
        .action = "set_dnd",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible, // persisted flag, toggled back by a later call
        .securable = "Infrastructure",
        .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::Medium,
    },

    // ── windows_updates (agents/plugins/windows_updates/src/windows_updates_plugin.cpp) ─
    // Despite the name, genuinely cross-platform (Windows/apt-yum/softwareupdate
    // legs all real) — every one of its 4 actions only reports state, never
    // installs or defers an update.
    {
        .plugin = "windows_updates",
        .action = "installed",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "SoftwareDeployment",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
    },
    {
        .plugin = "windows_updates",
        .action = "missing",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "SoftwareDeployment",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
    },
    {
        .plugin = "windows_updates",
        .action = "pending_reboot",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "SoftwareDeployment",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
    },
    {
        .plugin = "windows_updates",
        .action = "patch_connectivity",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "SoftwareDeployment",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
    },

    // ── services (agents/plugins/services/src/services_plugin.cpp) ─────────
    {
        .plugin = "services",
        .action = "list",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
    },
    {
        .plugin = "services",
        .action = "running",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
    },
    {
        // Above the Write floor (Medium): flipping a service's startup type
        // can disable a security-relevant service, so conservatively High.
        .plugin = "services",
        .action = "set_start_mode",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible, // a later call restores the prior mode
        .securable = "Infrastructure",
        .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::High,
    },

    // ── script_exec (agents/plugins/script_exec/src/script_exec_plugin.cpp) ─
    // Arbitrary command/script execution ("admin-only" per the plugin's own
    // doc comment) — Execute-class on the highest risk tier the operation
    // permits (Critical), Destructive/Irreversible: nothing bounds what an
    // executed command or script can do to the endpoint.
    {
        .plugin = "script_exec",
        .action = "exec",
        .dispatch_class = DispatchClass::Destructive,
        .mutability = Mutability::Irreversible,
        .securable = "Execution",
        .operation = authz::Operation::Execute,
        .risk_tier = authz::RiskTier::Critical,
    },
    {
        .plugin = "script_exec",
        .action = "powershell",
        .dispatch_class = DispatchClass::Destructive,
        .mutability = Mutability::Irreversible,
        .securable = "Execution",
        .operation = authz::Operation::Execute,
        .risk_tier = authz::RiskTier::Critical,
    },
    {
        .plugin = "script_exec",
        .action = "bash",
        .dispatch_class = DispatchClass::Destructive,
        .mutability = Mutability::Irreversible,
        .securable = "Execution",
        .operation = authz::Operation::Execute,
        .risk_tier = authz::RiskTier::Critical,
    },

    // ── software_actions (agents/plugins/software_actions/src/software_actions_plugin.cpp) ─
    // Both actions are explicitly documented "(read-only)" in the plugin's
    // own header comment; the plugin ships no install/uninstall action.
    {
        .plugin = "software_actions",
        .action = "list_upgradable",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "SoftwareDeployment",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
    },
    {
        .plugin = "software_actions",
        .action = "installed_count",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "SoftwareDeployment",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
    },

    // ── msi_packages (agents/plugins/msi_packages/src/msi_packages_plugin.cpp) ─
    // Inventory enumeration only ("MSI / pkgutil package INVENTORY plugin"
    // per its own header) — no install/uninstall action exists.
    {
        .plugin = "msi_packages",
        .action = "list",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
    },
    {
        .plugin = "msi_packages",
        .action = "product_codes",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Inventory",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
    },

    // ── sccm (agents/plugins/sccm/src/sccm_plugin.cpp) ──────────────────────
    {
        .plugin = "sccm",
        .action = "client_version",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "SoftwareDeployment",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
    },
    {
        .plugin = "sccm",
        .action = "site",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "SoftwareDeployment",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
    },

    // ── wmi (agents/plugins/wmi/src/wmi_plugin.cpp) ─────────────────────────
    // Conservatively above the Read floor: an arbitrary (SELECT-only,
    // namespace-whitelisted) WQL query can still surface broad system data.
    {
        .plugin = "wmi",
        .action = "query",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Medium,
    },
    {
        .plugin = "wmi",
        .action = "get_instance",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Medium,
    },

    // ── event_logs (agents/plugins/event_logs/src/event_logs_plugin.cpp) ───
    // Conservatively above the Read floor: log content can carry sensitive
    // operational detail.
    {
        .plugin = "event_logs",
        .action = "errors",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "AuditLog",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Medium,
    },
    {
        .plugin = "event_logs",
        .action = "query",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "AuditLog",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Medium,
    },

    // ── antivirus (agents/plugins/antivirus/src/antivirus_plugin.cpp) ──────
    {
        .plugin = "antivirus",
        .action = "products",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
    },
    {
        .plugin = "antivirus",
        .action = "status",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
    },

    // ── bitlocker (agents/plugins/bitlocker/src/bitlocker_plugin.cpp) ──────
    // Single action, a status query (manage-bde/lsblk+cryptsetup/fdesetup+
    // diskutil) — no encrypt/decrypt/enable action exists. Conservatively
    // above the Read floor given the sensitivity of encryption-status data.
    {
        .plugin = "bitlocker",
        .action = "state",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Medium,
    },

    // ── ioc (agents/plugins/ioc/src/ioc_plugin.cpp) ─────────────────────────
    // Conservatively above the Read floor: matches operator-supplied
    // indicators against live connection/DNS/filesystem state.
    {
        .plugin = "ioc",
        .action = "check",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Medium,
    },

    // ── agent_actions (agents/plugins/agent_actions/src/agent_actions_plugin.cpp) ─
    {
        .plugin = "agent_actions",
        .action = "set_log_level",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible,
        .securable = "Infrastructure",
        .operation = authz::Operation::Write,
        .risk_tier = authz::RiskTier::Medium,
    },
    {
        // Pure config-value read (agent.id/version/server_address/
        // heartbeat_interval/plugins.count) — no mutation.
        .plugin = "agent_actions",
        .action = "info",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
    },
}};

} // namespace detail

/// A `std::span` view over the fixed catalogue above — composed alongside
/// the other four per-group plugin.action fragments (and p1's
/// `core_dispatch_capabilities()`) only at the `CommandCapabilityRegistry`
/// construction site. Inline function over file-scope `constexpr` storage,
/// same shape as `core_dispatch_capabilities()`.
[[nodiscard]] inline std::span<const CommandCapability> plugin_action_catalogue_d() noexcept {
    return detail::kPluginActionCatalogueD;
}

} // namespace yuzu::server::capdecls
