#pragma once

#include <array>
#include <cstddef>
#include <format>
#include <optional>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

#include "bundle_service.hpp" // kMaxParamCountPerStep / kMaxParamKeyLen / kMaxParamValueLen
                              // (also kMaxBundleSteps, which the sizing test reaches
                              // through this header)
#include "mcp_jsonrpc.hpp"    // kMcpMaxRequestBodyBytes, for the sizing static_asserts below

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

/// The CLOSED `reason` label set for `yuzu_mcp_tool_args_too_large_total`.
///
/// This array is the single source: `server.cpp` pre-seeds the counter by
/// iterating it at boot, so the emitted set and the pre-seeded set cannot
/// drift apart. Before it existed the two were independent literal lists, and
/// a rule landing with an unseeded reason would still pass its own test (the
/// registry creates a series on demand) while silently breaking `absent()`
/// alerting — the dashboard reads zero while calls are being refused.
///
/// ADDING A REASON: append it here, emit it from `check_exec_instruction_shape`
/// or the handler's `too_large`, and document it in
/// `docs/user-manual/metrics.md`. The boot pre-seed follows automatically; the
/// docs copy does not, and a test asserts this array's size so the third copy
/// cannot be forgotten quietly.
inline constexpr std::array<std::string_view, 7> kExecInstrBoundReasons{
    "ident_len",       "scope_len",       "param_count",    "param_key_len",
    "param_value_len", "agent_ids_count", "agent_id_len",
};

// ── Sizing: the per-field caps must fit under the TRANSPORT cap ───────────
// #2478 refuses a /mcp/ body over kMcpMaxRequestBodyBytes before reading it.
// The caps above are what a caller may legitimately fill, so their sum has to
// stay UNDER that cap — otherwise a maximal-but-legal execute_instruction is
// 413'd at the transport before the handler could ever accept it.
//
// These are static_asserts in the HEADER, not checks in a test, so widening a
// field bound past the transport cap fails the BUILD rather than a test run.
// Derived from the constants rather than restated, so the relation cannot
// drift away from what is enforced.
inline constexpr std::size_t kExecInstrWorstCaseBody =
    kExecInstrAgentIdsMaxItems * (kExecInstrIdentMaxLen + 3) +  // "<ident>",
    kExecInstrParamCountMax * (kExecInstrParamKeyMaxLen + kExecInstrParamValueMaxLen + 6) +
    (kExecInstrScopeMaxLen + 16) + 2 * (kExecInstrIdentMaxLen + 16) +
    2048; // jsonrpc/method/id/_meta.progressToken envelope

// A MARGIN, not merely ">". The params widening took the headroom from 62% to
// 18% and nobody recomputed it until review, so the next careless bump should
// fail to compile rather than ship a cap that refuses schema-legal calls.
//
// 10% is a FLOOR, not "what the numbers support" - an earlier version of this
// comment said the latter and was wrong. The true ceiling is 22.4% (the actual
// headroom); 25% fails, 20% would still hold. 10% is deliberately slack so a
// small legitimate change does not fail the build, which means this assert
// alone would permit drift to ~9% headroom while the docs publish 18%. Closing
// that gap is the job of the exact-figure CHECK in test_mcp_server.cpp, not of
// a tighter bound here - the assert pins the RELATION, the test pins the
// PUBLISHED NUMBER. Both are needed; neither substitutes for the other.
//
// Written as cap/11*10 rather than worst*11/10: the latter multiplies a value
// that grows with the field bounds, and on a 32-bit size_t would WRAP above
// ~390 MB and satisfy the assert spuriously - precisely the careless-bump case
// it exists to catch. cap is a fixed 4 MiB, so cap*10 cannot overflow.
static_assert(kMcpMaxRequestBodyBytes / 11 * 10 > kExecInstrWorstCaseBody,
              "a maximal execute_instruction must fit with room for JSON escaping - if this "
              "fires, raise the transport cap or lower a field bound, and update the figures "
              "in docs/mcp-server.md");
static_assert(kMcpMaxRequestBodyBytes > kExecInstrWorstCaseBody,
              "the transport cap must admit the largest execute_instruction the per-field "
              "caps permit — below that, a legitimate maximal call would 413 before the "
              "handler ever saw it");

// The cap is DELIBERATELY below what execute_bundle's own validator accepts,
// and that clamp is the part most likely to be "fixed" by someone reading only
// the assert above. One saturated bundle step is ~2 MiB, so a 2-step bundle
// validate_bundle_steps would accept is refused at the transport. A stated
// product clamp (docs/mcp-server.md), NOT a derivation error.
inline constexpr std::size_t kOneSaturatedBundleStep =
    kMaxParamCountPerStep * (kMaxParamValueLen + kMaxParamKeyLen + 6);

static_assert(kOneSaturatedBundleStep < kMcpMaxRequestBodyBytes,
              "one saturated bundle step must still fit, or execute_bundle is unusable at "
              "its own declared per-step limits over MCP");
static_assert(2 * kOneSaturatedBundleStep > kMcpMaxRequestBodyBytes,
              "the bundle clamp documented in docs/mcp-server.md — if this stops holding, "
              "the clamp changed and the docs must change with it");

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
