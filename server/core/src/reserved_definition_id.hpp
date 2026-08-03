#pragma once

#include <string>
#include <string_view>

// The reserved `mcp.` definition-id namespace (#2442).
//
// MCP approval tickets are minted under `mcp.<tool>`, and the MCP recall matches
// a ticket on (definition_id, scope_expression) WITHOUT binding the submitter.
// So a definition id under that prefix, reachable from any other surface, is a
// ticket the MCP gate would accept. The rule lives here, once, because it has
// to hold at four unrelated places that would otherwise each carry a copy:
//
//   * ApprovalManager::submit          — a mint declaring a non-MCP origin.
//     This is the CHOKEPOINT: it fails closed regardless of who calls it.
//   * InstructionStore::create_definition_impl — authoring (create + import)
//   * validate_instruction_yaml        — the YAML validator, which MUST agree
//     with the store or the "YAML that validates always saves" contract breaks
//     (#1993, re-broken by #2010 and again by the first cut of #2442 — three
//     times, which is why the predicate is no longer copied)
//   * WorkflowRoutes' instruction-execute handler — a caller-side PRE-CHECK, so
//     a doomed execute answers 400 naming the id instead of the chokepoint's
//     refusal surfacing as a 500. Note its condition is not the chokepoint's:
//     submit() gates on the declared origin, this site checks the id without
//     regard to origin (it sits on the approval-gated branch, so an ungated
//     run never reaches it), and the two agree only because that route always
//     declares kInstruction.
//
// A fifth site would be a fifth chance to diverge: call `is_reserved_definition_id`
// and report `kReservedDefinitionIdError` rather than re-implementing either.
// One place still writes the prefix as a literal — mcp_server.cpp builds
// `"mcp." + tool_name` at the MINTING site the reservation exists to protect —
// because that file is frozen for a parallel rebase. It is tracked, and it is
// the reason this rule is stated here rather than assumed.
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

/// THE denial message, shared by every site above. One rule reads as one denial
/// to an operator and keys as one stable token in a SIEM rule
/// (docs/user-manual/audit-log.md enumerates it) — two hand-written variants of
/// the same refusal is how that contract silently drifts.
inline constexpr std::string_view kReservedDefinitionIdError =
    "definition id may not use the reserved 'mcp.' prefix (reserved for MCP approvals)";

} // namespace yuzu::server
