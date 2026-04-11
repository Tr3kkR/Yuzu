#pragma once

#include <string_view>

namespace yuzu::server::mcp {

/// MCP authorization tiers (compiled-in, not configurable).
///
/// Tier check runs BEFORE RBAC: even if the token's RBAC role is Administrator,
/// a "readonly" tier blocks all writes/executes/deletes.
///
///   readonly   — read-only access to all data
///   operator   — readonly + tag writes + auto-approved instruction execution
///   supervised — operator + all executions + destructive ops (via approval workflow)

/// Returns true if the MCP tier permits (securable_type, operation).
/// An empty tier string means "not an MCP token" → allow everything (defer to RBAC).
inline bool tier_allows(std::string_view mcp_tier,
                        std::string_view securable_type,
                        std::string_view operation) {
    if (mcp_tier.empty()) return true;  // Not an MCP token

    // ── readonly: only Read operations ──────────────────────────────────
    if (mcp_tier == "readonly") {
        return operation == "Read";
    }

    // ── operator: Read + limited Write/Delete on tags ───────────────────
    if (mcp_tier == "operator") {
        if (operation == "Read") return true;
        if (securable_type == "Tag" && (operation == "Write" || operation == "Delete"))
            return true;
        if (securable_type == "Execution" && operation == "Execute")
            return true;  // Operator tier executes without approval (auto-approved)
        return false;
    }

    // ── supervised: all operations (but destructive ones go through approval) ─
    if (mcp_tier == "supervised") {
        return true;  // Approval enforcement is in requires_approval()
    }

    return false;  // Unknown tier → deny
}

/// Returns true if this (securable_type, operation) must go through the
/// approval workflow when invoked via MCP, regardless of the token's RBAC role.
///
/// This is checked AFTER tier_allows() returns true.
inline bool requires_approval(std::string_view mcp_tier,
                              std::string_view securable_type,
                              std::string_view operation) {
    if (mcp_tier.empty()) return false;  // Not an MCP token

    // readonly tokens can't do anything that needs approval
    if (mcp_tier == "readonly") return false;

    // ── supervised tier: destructive operations always require approval ──
    if (mcp_tier == "supervised") {
        if (securable_type == "Execution" && operation == "Execute") return true;
        if (operation == "Delete") return true;
        if (securable_type == "Policy" && operation == "Write") return true;
        if (securable_type == "Security" && operation == "Write") return true;
        if (securable_type == "UserManagement" && operation == "Write") return true;
        if (securable_type == "ManagementGroup" && operation == "Write") return true;
    }

    // ── operator tier: tag deletes require approval, executions are auto-approved ──
    if (mcp_tier == "operator") {
        if (securable_type == "Tag" && operation == "Delete") return true;
        // Execution/Execute is auto-approved for operator tier (no approval needed).
    }

    return false;
}

/// Returns true if the given string is a valid MCP tier name.
inline bool is_valid_tier(std::string_view tier) {
    return tier.empty() || tier == "readonly" || tier == "operator" || tier == "supervised";
}

} // namespace yuzu::server::mcp
