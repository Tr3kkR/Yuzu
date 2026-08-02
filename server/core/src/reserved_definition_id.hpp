#pragma once

#include <string>
#include <string_view>

// The reserved `mcp.` definition-id namespace (#2442).
//
// MCP approval tickets are minted under `mcp.<tool>`, and the MCP recall matches
// a ticket on (definition_id, scope_expression) WITHOUT binding the submitter.
// So a definition id under that prefix, reachable from any other surface, is a
// ticket the MCP gate would accept. The rule lives here, once, because it has
// to hold at three unrelated places that would otherwise each carry a copy:
//
//   * ApprovalManager::submit          — a mint declaring a non-MCP origin
//   * InstructionStore::create_definition_impl — authoring (create + import)
//   * validate_instruction_yaml        — the YAML validator, which MUST agree
//     with the store or the "YAML that validates always saves" contract breaks
//     (#1993, re-broken by #2010 and again by the first cut of #2442 — three
//     times, which is why the predicate is no longer copied)
//
// A fourth site would be a fourth chance to diverge: call `is_reserved_definition_id`
// and report `kReservedDefinitionIdError`; never re-implement the comparison,
// and never write the prefix as a literal.
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

/// THE denial message, shared by all three sites. One rule reads as one denial
/// to an operator and keys as one stable token in a SIEM rule
/// (docs/user-manual/audit-log.md enumerates it) — two hand-written variants of
/// the same refusal is how that contract silently drifts.
inline constexpr std::string_view kReservedDefinitionIdError =
    "definition id may not use the reserved 'mcp.' prefix (reserved for MCP approvals)";

} // namespace yuzu::server
