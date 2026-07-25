#pragma once

#include <cstddef>
#include <format>
#include <optional>
#include <string>

#include <nlohmann/json.hpp>

#include "bundle_service.hpp" // kMaxParamCountPerStep / kMaxParamKeyLen (kMaxBundleSteps
                              // is used by the sizing test, not by this header)

/// @file mcp_input_bounds.hpp
/// The ONE home for MCP request-size bounds (#2437) — transport and handler.
///
/// These live in a header rather than TU-local in mcp_server.cpp for a
/// specific reason: the served `kTools[]` schema literals and these constants
/// are the SAME contract expressed twice, and a comment saying "keep them in
/// sync" is not a check. test_mcp_server.cpp reads the served schema back via
/// `input_schemas_for_test()` and asserts each literal equals its twin here,
/// so bumping one without the other fails a test instead of silently
/// reopening the gap this issue closed.
namespace yuzu::server::mcp {

// ── execute_instruction, per-field ────────────────────────────────────────
// Each has a twin in the served inputSchema; the cross-check test binds them.
inline constexpr std::size_t kExecInstrIdentMaxLen = 128;        // plugin, action, each agent_ids entry
inline constexpr std::size_t kExecInstrScopeMaxLen = 8192;       // scope expression
// Borrowed from bundle_service.hpp like the two below, NOT invented: the
// two execute surfaces bound the same thing and disagreeing by 8x was an
// accident of which constant was reached for, not a design.
inline constexpr std::size_t kExecInstrParamValueMaxLen = kMaxParamValueLen; // 64 KiB
inline constexpr std::size_t kExecInstrAgentIdsMaxItems = 10000; // agent_ids length

// The closed schema subset has no `maxProperties` / `propertyNames`, so these
// two CANNOT be expressed in the served schema and have no twin to cross-check.
// Consequence: C8 cannot pre-validate them from the schema, so
// `check_exec_instruction_shape` below is run EXPLICITLY inside the C8
// block as well as in the handler. Without that a supervised call violating
// one would mint a ticket, spend a human's approval, CONSUME it, then fail —
// the ticket-burn class #2405 exists to prevent. They remain invisible in
// `tools/list`; publishing them needs the subset catalogue extended (#2444).
//
// Borrowed from bundle_service.hpp rather than invented so the two execute
// surfaces agree on what a param may be — shape AND value size. They used to
// disagree 8x on value size; that was not a decision, and the divergence was
// documented as deliberate before anyone checked why it existed.
inline constexpr std::size_t kExecInstrParamCountMax = kMaxParamCountPerStep; // 32
inline constexpr std::size_t kExecInstrParamKeyMaxLen = kMaxParamKeyLen;      // 256

/// One violated bound. Neither field is ever caller-derived.
struct BoundViolation {
    /// Closed-set metric label - stays a literal.
    const char* reason;
    /// Operator-facing text, formatted FROM the constants: hardcoding the
    /// numbers here would let this path and the handler's std::format siblings
    /// report different limits for the same bound after a change.
    std::string message;
};

/// The `execute_instruction` bounds the CLOSED schema subset cannot express
/// (it has no `maxProperties` / `propertyNames`), factored out so the C8
/// approval gate can run them BEFORE a ticket is minted or consumed.
///
/// WHY PRE-MINT AND NOT HANDLER-ONLY: a rule checked only in the handler runs
/// AFTER the C8 gate has minted a ticket, waited for a human, and consumed it
/// - so a call that was always going to be refused burns an approval, and an
/// automated client re-mints on every retry and floods the approval queue.
/// That is the waste #2405 exists to prevent. Adding a rule HERE rather than
/// at a call site is what keeps both paths in agreement: mcp_server.cpp calls
/// this from the C8 block (pre-mint) and from the handler (defense in depth
/// for the ungated tiers, which never reach C8).
///
/// Pure and total: no I/O. Returns the FIRST violation in a deterministic
/// order so a denial is reproducible.
[[nodiscard]] inline std::optional<BoundViolation>
check_exec_instruction_shape(const nlohmann::json& args) {
    if (args.contains("params") && args["params"].is_object()) {
        const auto& p = args["params"];
        if (p.size() > kExecInstrParamCountMax)
            return BoundViolation{"param_count",
                                  std::format("params must have at most {} keys",
                                              kExecInstrParamCountMax)};
        for (const auto& [k, v] : p.items()) {
            (void)v;
            if (k.size() > kExecInstrParamKeyMaxLen)
                return BoundViolation{"param_key_len",
                                      std::format("a params key exceeds {} bytes",
                                                  kExecInstrParamKeyMaxLen)};
        }
    }
    return std::nullopt;
}

} // namespace yuzu::server::mcp
