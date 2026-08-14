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
    //
    // ROUND-3 FINDING (security-critical, corrected twice):
    //
    // Attempt 1 added `if (securable_type == "ApiToken" && operation ==
    // "Write") return true;` here to admit rotate_api_token/
    // confirm_api_token_rotation at the operator tier. That was WRONG:
    // tier_allows() is keyed on (securable_type, operation), not on the
    // tool/route — `AuthRoutes::require_permission`/`require_scoped_permission`
    // (auth_routes.cpp) consult this SAME function for EVERY transport, so
    // the rule admitted every ApiToken:Write surface, not just the two
    // rotation tools: REST `POST /api/v1/tokens` (create_token, ApiToken:Write
    // and nothing else) and its settings twin `POST /api/settings/api-tokens`
    // both widened to operator-tier tokens. The escalation completes because
    // mcp_tier is CALLER-CHOSEN at token creation and an OMITTED mcp_tier
    // mints an untiered, perpetual token — after which every future call
    // skips this function entirely (`tier_allows` returns true immediately
    // when `mcp_tier` is empty). Neither compensating control saves it: MFA
    // step-up short-circuits true for api_token/mcp_token principals, and
    // with RBAC off (the default) the legacy fallback passes because a
    // tiered token carries its CREATOR's role — normally an admin's.
    //
    // Attempt 2 tried a TOOL-SCOPED exception instead — special-casing
    // `tier == "operator"` at the two tools' own call sites in
    // mcp_server.cpp, leaving `tier_allows()` itself supervised-only for
    // ApiToken:Write. That is structurally unreachable: mcp_server.cpp's
    // generic C8 gate resolves tier admission from `kToolSecurity`'s
    // (securable_type, operation) pair for EVERY known-registered tool
    // BEFORE any per-tool handler code runs, so a call-site-local exception
    // never executes — the generic gate denies first, using the SAME
    // ApiToken:Write pair every other ApiToken:Write route/tool uses.
    //
    // The fix is a DISTINCT OPERATION, `ApiToken:Rotate` — mapped ONLY by
    // rotate_api_token/confirm_api_token_rotation's `kToolSecurityRows`
    // entries (mcp_server.cpp) and the REST rotate/confirm routes' `perm_fn`
    // calls (rest_api_v1.cpp), never by `POST /api/v1/tokens` create or its
    // settings twin, which stay on plain `ApiToken:Write`. An operator-tier
    // allowance on `ApiToken:Rotate` here cannot touch `ApiToken:Write` at
    // all, on any transport, by construction — the two operations are
    // different strings, so no shared lookup can conflate them. This also
    // gives TRUE REST/MCP parity (an operator-tier token can now reach REST
    // rotate/confirm too), closing the asymmetry the tool-scoped attempt
    // would have left on record. See `docs/mcp-server.md`'s "Human
    // API-token rotation tools" note and `rbac_store.cpp`'s seed_defaults()
    // for the RBAC-on grant population (Administrator + ApiTokenManager,
    // matching the pre-existing ApiToken:Write holder set).
    if (mcp_tier == "operator") {
        if (operation == "Read") return true;
        if (securable_type == "Tag" && (operation == "Write" || operation == "Delete"))
            return true;
        if (securable_type == "Execution" && operation == "Execute")
            return true;  // Operator tier executes without approval (auto-approved)
        if (securable_type == "ApiToken" && operation == "Rotate")
            return true;  // rotate_api_token/confirm_api_token_rotation ONLY — see above
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
        // Security:Execute is live device isolation (quarantine) — as destructive
        // as it gets. This rule and the kToolSecurity mapping
        // {"quarantine_device", {"Security","Execute"}} in mcp_server.cpp move
        // TOGETHER (see the invariant note above kToolSecurity): the mapping
        // keys the C8 ticket gate on this rule, and AuthRoutes::require_permission
        // mirrors this SAME rule on non-MCP transports, so a supervised token
        // cannot bypass the ticket flow via POST/DELETE /api/v1/quarantine
        // (#520; PR #1796 review C2 closed the Write/Execute mismatch that made
        // that REST bypass possible).
        if (securable_type == "Security" && operation == "Execute") return true;
        if (securable_type == "UserManagement" && operation == "Write") return true;
        if (securable_type == "ManagementGroup" && operation == "Write") return true;

        // ApiToken:Rotate is DELIBERATELY ABSENT — recorded here rather than
        // left silent-by-omission (PR #2974 review).
        //
        // It is destructive by the usual test: it revokes a predecessor and
        // reveals a fresh raw secret. What makes it different from the entries
        // above is that it cannot move authority or reach another principal:
        //
        //   * self-service only — `requesting_user == principal_id` in the
        //     store, no admin override, so a supervised token can only ever
        //     rotate a token the SAME principal already owns;
        //   * authority-inheriting — the successor inherits the predecessor's
        //     (mcp_tier, scope_service) verbatim, and the caller's must EQUAL
        //     the predecessor's, so nothing is gained;
        //   * lifetime-neutral — the successor inherits `expires_at`, so it
        //     cannot be used to extend a credential quietly.
        //
        // So the worst a supervised token achieves unapproved is replacing one
        // of its own secrets with an equally-scoped one that dies at the same
        // instant. Requiring four-eyes for that would gate routine credential
        // hygiene — the CC6.3 behaviour this exists to encourage — behind an
        // admin, on the tier most likely to be automating it.
        //
        // If that trade is ever revisited, the entry goes HERE and the
        // `kToolSecurity` mapping for rotate_api_token /
        // confirm_api_token_rotation must move with it — see the invariant
        // note above `kToolSecurity`, and note `AuthRoutes::require_permission`
        // mirrors this rule on non-MCP transports, so a partial change would
        // open the same REST bypass #520/#1796 closed for quarantine.
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
