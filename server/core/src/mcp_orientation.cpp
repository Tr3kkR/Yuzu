#include "mcp_orientation.hpp"

#include <array>

namespace yuzu::server::mcp {

// ── Static orientation text ──────────────────────────────────────────────────
//
// Moved verbatim from the former inline literals in the mcp_server.cpp
// resources/read arms so the resource bytes are unchanged. Product copy; do not
// rewrite here to satisfy a style preference (the em-dash below is pre-existing
// primer text, kept byte-identical for the single-source guarantee).

std::string_view about_text() {
    return "# Yuzu\n\n"
           "Yuzu is an agentic enterprise endpoint management control plane for "
           "Windows, Linux, and macOS fleets. Through MCP, an LLM can inspect fleet "
           "state, inventory, compliance, command responses, audit evidence, DEX "
           "signals, and network posture.\n\n"
           "Safe operating rules: classify the question first; read existing facts "
           "before dispatch; narrow scope before action; use dry-run/read-only probes "
           "where possible; request explicit approval before remediation; label "
           "connector gaps honestly.\n\n"
           "Engine-principal management (create/list/get/revoke/mint/rotate/transfer-"
           "owner engine principals, plus a no-admin audit) is a supervised-tier, "
           "human-admin-only surface for provisioning the durable identities behind "
           "autonomous use-case-engine modules — engine-classed sessions are structurally "
           "barred from calling it, and every mutation is approval-gated.";
}

std::string_view operating_model_text() {
    return "Recommended MCP workflow: classify the question, identify connector gaps, "
           "read high-level posture, narrow scope by cohort/site/OS/management group, "
           "prefer existing responses and inventory, use live dispatch only for "
           "read-only probes, request approval for mutation, execute with the smallest "
           "safe scope, then monitor responses/audit/events.";
}

// ── Tool-family enumeration ──────────────────────────────────────────────────
//
// The union of every family's `tools` list is exactly the kTools[] set. This is
// asserted mechanically by the family-tether test against the live tools/list
// output, so a new tool with no family assignment (or a family dropped from the
// blob) is a test FAILURE, not a review miss. Keep names in kTools[] order.

namespace {

constexpr std::string_view kFleet[] = {"list_agents", "get_agent_details"};
constexpr std::string_view kTags[] = {"get_tags", "search_agents_by_tag", "set_tag", "delete_tag"};
constexpr std::string_view kDefinitions[] = {"list_definitions", "get_definition", "list_schedules"};
constexpr std::string_view kResponses[] = {"query_responses", "aggregate_responses"};
constexpr std::string_view kExecutionsAudit[] = {"get_execution_status", "list_executions",
                                                 "query_audit_log"};
constexpr std::string_view kInventory[] = {"query_inventory", "list_inventory_tables",
                                           "get_agent_inventory", "query_installed_software",
                                           "query_software_licenses"};
constexpr std::string_view kCompliance[] = {"list_policies", "get_compliance_summary",
                                            "get_fleet_compliance", "get_guardian_schemas"};
constexpr std::string_view kScope[] = {"validate_scope", "preview_scope_targets"};
constexpr std::string_view kMgmtGroups[] = {"list_management_groups"};
constexpr std::string_view kApprovals[] = {"list_pending_approvals", "approve_request",
                                           "reject_request"};
constexpr std::string_view kDexSignals[] = {"list_dex_signals", "get_dex_signal_scope",
                                            "get_dex_signal_detail"};
constexpr std::string_view kDexPerf[] = {"get_dex_perf_fleet",   "get_dex_perf_cohorts",
                                         "get_dex_perf_cohort_diff", "list_dex_perf_devices",
                                         "list_dex_perf_apps",   "get_dex_app_perf",
                                         "get_dex_group_app_perf",   "compare_app_perf_versions"};
constexpr std::string_view kNetwork[] = {"get_network_fleet", "list_network_devices"};
constexpr std::string_view kExecution[] = {"execute_instruction", "execute_bundle",
                                           "get_bundle_result"};
constexpr std::string_view kRemediation[] = {"quarantine_device"};
constexpr std::string_view kCerts[] = {"list_issued_certs", "revoke_certificate"};
// KEK rotation (#2395 track C) is its own family, distinct from Certificates:
// a KEK is the server's own secrets-at-rest encryption key, not a PKI
// certificate, and it gates on a different lifecycle (rotate/rewrap/status,
// no issue/revoke) even though both share the Security securable.
constexpr std::string_view kKekRotation[] = {"rotate_kek", "rewrap_secrets", "get_kek_status"};
constexpr std::string_view kEnginePrincipals[] = {
    "create_engine_principal",        "list_engine_principals",
    "get_engine_principal",           "revoke_engine_principal",
    "mint_engine_credential",         "rotate_engine_credential",
    "confirm_engine_rotation",        "transfer_engine_principal_owner",
    "audit_engine_no_admin",          "assign_engine_role",
    "unassign_engine_role",           "list_engine_roles"};
constexpr std::string_view kAccessReviews[] = {"export_access_review", "open_access_review",
                                               "record_attestation", "get_access_review",
                                               "list_access_reviews", "close_access_review"};
constexpr std::string_view kAgenticHelpers[] = {"get_fleet_posture_fast",
                                                "classify_operational_question",
                                                "get_incident_playbook", "summarize_working_set"};
constexpr std::string_view kDiscovery[] = {"discover_permissions", "discover_instructions",
                                           "discover_routes", "discover_scope_kinds",
                                           "discover_plugins"};

constexpr std::array<ToolFamily, 21> kFamilies{{
    {"Fleet & agents", "connected agents, their OS/arch/version, and details", kFleet},
    {"Tags", "read and write agent tags, and find agents by tag", kTags},
    {"Instructions & schedules", "instruction definitions and recurring schedules", kDefinitions},
    {"Command responses", "query and aggregate stored command/instruction responses", kResponses},
    {"Executions & audit", "execution status/history and the who-did-what audit log",
     kExecutionsAudit},
    {"Inventory & software", "collected inventory tables, installed software, and licenses",
     kInventory},
    {"Policy & compliance", "policies, per-device and fleet compliance, Guardian schemas",
     kCompliance},
    {"Scope targeting", "validate a scope expression and preview the devices it selects", kScope},
    {"Management groups", "the hierarchical device grouping used for access scoping", kMgmtGroups},
    {"Approvals", "list pending approvals and approve/reject maker-checker tickets", kApprovals},
    {"DEX signals", "digital-employee-experience reliability signals and their scope/detail",
     kDexSignals},
    {"DEX performance", "fleet, cohort, device, and per-app performance over time", kDexPerf},
    {"Network quality", "fleet and per-device network-quality posture", kNetwork},
    {"Live execution", "dispatch plugin actions or bundles to endpoints and collect results",
     kExecution},
    {"Device remediation", "quarantine a device (destructive, approval-gated)", kRemediation},
    {"Certificates", "list issued agent certificates and revoke one", kCerts},
    {"KEK rotation", "rotate the server's secrets-at-rest encryption key, resume an "
                     "interrupted re-wrap, and check rotation status",
     kKekRotation},
    {"Engine principals", "provision and manage the durable identities behind use-case engines",
     kEnginePrincipals},
    {"Access reviews", "open, attest, close, and export SOC 2 access-certification reviews",
     kAccessReviews},
    {"Agentic helpers", "high-level workflow helpers: fast posture, classification, playbooks",
     kAgenticHelpers},
    {"Discovery", "enumerate permissions, instructions, routes, scope kinds, and plugins",
     kDiscovery},
}};

}  // namespace

std::span<const ToolFamily> tool_families() { return kFamilies; }

// ── initialize.instructions blob ─────────────────────────────────────────────

const std::string& initialize_instructions() {
    static const std::string blob = [] {
        std::string s;
        s += about_text();
        s += "\n\n## Operating model\n\n";
        s += operating_model_text();
        s += "\n\n## Tool families\n\n";
        s += "The MCP tool surface groups into these capability areas; call "
             "tools/list for the full input/output schema of any tool.\n\n";
        for (const auto& f : tool_families()) {
            s += "- ";
            s += f.name;
            s += ": ";
            s += f.blurb;
            s += " (";
            bool first = true;
            for (const auto& t : f.tools) {
                if (!first)
                    s += ", ";
                s += t;
                first = false;
            }
            s += ")\n";
        }
        s += "\n## Where to start\n\n";
        s += "Enumerate the live surface before acting: the discovery tools "
             "(discover_routes, discover_permissions, discover_instructions, "
             "discover_scope_kinds, discover_plugins) and resources/list "
             "(yuzu://about, yuzu://operating-model, yuzu://capabilities) describe "
             "exactly what this deployment exposes to your principal.";
        return s;
    }();
    return blob;
}

}  // namespace yuzu::server::mcp
