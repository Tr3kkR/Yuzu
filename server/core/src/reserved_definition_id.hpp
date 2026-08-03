#pragma once

#include <string>
#include <string_view>

// The reserved `mcp.` definition-id namespace (#2442) — AUTHORING ONLY.
//
// MCP approval tickets are minted under `mcp.<tool>`, and the MCP recall matches
// a ticket on (definition_id, scope_expression) WITHOUT binding the submitter.
// So a definition id under that prefix, reachable from another surface, names a
// ticket the MCP gate would otherwise accept.
//
// READ THIS BEFORE ADDING A SITE: this prefix is NOT the runtime defence against
// that forgery, and must not be made into one again. The runtime defence is
// `declares_non_mcp_surface` in approval_manager.hpp, applied at redemption in
// `ApprovalManager::consume_ticket`, and it is keyed on the ticket's recorded
// ORIGIN. The prefix was tried as the runtime control and removed, for two
// reasons that both still hold:
//
//   * it cannot tell a pre-existing operator definition from a hostile one, so
//     it failed closed on content it could not help — on the scheduler that was
//     a permanently dropped occurrence indistinguishable from a successful run,
//     with no safe rebuild available; and
//   * it is a proxy. It stops covering the real case the moment the MCP mint
//     stops building its id as `"mcp." + tool_name`, and nothing forces that to
//     stay true. The origin predicate does not have that failure mode.
//
// What remains here is forward-only namespace hygiene, and it holds at exactly
// two authoring sites that would otherwise each carry a copy:
//
//   * InstructionStore::create_definition_impl — authoring (create + import,
//     signed and unsigned, and the trusted boot auto-import; every route that
//     writes `instruction_definitions` funnels through it)
//   * validate_instruction_yaml        — the YAML validator, which MUST agree
//     with the store or the "YAML that validates always saves" contract breaks
//     (#1993, re-broken by #2010 and again by the first cut of #2442 — three
//     times, which is why the predicate is no longer copied)
//
// A third AUTHORING site would be a third chance to diverge: call
// `is_reserved_definition_id` and report `kReservedDefinitionIdError` rather
// than re-implementing either. A site that wants to refuse at RUNTIME wants
// `declares_non_mcp_surface` instead, and should not be here at all.
//
// One place still writes the prefix as a literal — mcp_server.cpp builds
// `"mcp." + tool_name` at the MINTING site — because that file is frozen for a
// parallel rebase. That literal is now cosmetic rather than load-bearing: the
// guard no longer depends on the id shape. It is still worth converging when the
// file reopens, alongside the mint declaring `ApprovalOrigin::kMcp`.
namespace yuzu::server {

/// Definition-id prefix reserved for MCP-minted approval tickets.
inline constexpr std::string_view kMcpDefinitionPrefix = "mcp.";

/// True iff `id` lands in the reserved namespace. Case-sensitive on purpose:
/// SQLite's default BINARY collation makes `MCP.` a different id everywhere
/// else, so treating it as reserved here would refuse an id nothing else
/// conflates.
[[nodiscard]] inline bool is_reserved_definition_id(std::string_view id) {
    return id.starts_with(kMcpDefinitionPrefix);
}

/// THE denial message, shared by both authoring sites. One rule reads as one
/// denial to an operator and keys as one stable token in a SIEM rule
/// (docs/user-manual/audit-log.md enumerates it) — two hand-written variants of
/// the same refusal is how that contract silently drifts. The redemption guard
/// deliberately does NOT use this string: it must not tell a remote caller which
/// rule refused it.
inline constexpr std::string_view kReservedDefinitionIdError =
    "definition id may not use the reserved 'mcp.' prefix (reserved for MCP approvals)";

} // namespace yuzu::server
