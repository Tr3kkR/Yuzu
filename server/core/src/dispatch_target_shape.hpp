#pragma once

#include <array>
#include <optional>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

/// @file dispatch_target_shape.hpp
/// The ONE home for the rule that decides whether a caller named a device
/// target (#2437 / #2500).
///
/// THE RULE, stated once: **an OMITTED targeting argument means "the whole
/// fleet"; a SUPPLIED one that resolves to nothing is an ERROR.** The two are
/// not the same request and must never collapse into each other.
///
/// This lives in its own surface-neutral header rather than in
/// `mcp_input_bounds.hpp` because it is not an MCP rule. It was written for
/// MCP `execute_instruction` (#2492), and the REST twins `POST /api/command`
/// and `POST /api/instructions/{id}/execute` had the identical defect under a
/// weaker gate (#2500) — on `/api/command`, under plain `Execution:Execute`
/// with no approval step at all. Everything left behind in
/// `mcp_input_bounds.hpp` — the transport-cap static_asserts, the per-field
/// size constants, the C8 subset commentary — is genuinely MCP-only; this is
/// not, and a REST route including an `mcp_`-named header would be the first
/// step toward the two surfaces drifting again.
///
/// WHY A SHARED FUNCTION AND NOT A SHARED CONVENTION: the four dispatch
/// closures in `server.cpp` each end in their own `else if (agent_ids.empty())
/// send_to_all(cmd)`, and the callers that are safe are safe because their
/// authors each remembered. That is the property this header exists to
/// replace. A third copy of these rules is how #2500 happened after #2492
/// fixed #2437.
namespace yuzu::server {

/// One violated bound. Neither field is ever caller-derived.
struct BoundViolation {
    /// Closed-set metric label - stays a literal.
    const char* reason;
    /// Operator-facing text, formatted FROM the constants: hardcoding the
    /// numbers here would let this path and the handler's std::format siblings
    /// report different limits for the same bound after a change.
    std::string message;
};

/// The CLOSED `reason` label set this function can emit.
///
/// Single-sourced for the same reason `kExecInstrBoundReasons` is: the boot
/// pre-seed for `yuzu_server_dispatch_target_rejected_total` iterates THIS
/// array, so a reason added only at the emit site would be emitted-but-unseeded
/// — which passes its own test while silently breaking `absent()` alerting,
/// because the registry creates the series on demand and the dashboard reads
/// zero while calls are being refused.
///
/// Every entry here is also a member of `kExecInstrBoundReasons` in
/// `mcp_input_bounds.hpp`, and a static_assert there enforces that containment
/// — the MCP counter's pre-seed must not lose a label when one is added here.
inline constexpr std::array<std::string_view, 5> kTargetingShapeReasons{
    "agent_ids_type", "agent_ids_empty", "agent_id_type", "scope_type", "scope_empty",
};

/// Reject a targeting argument that was SUPPLIED but names nothing.
///
/// Both the type and the emptiness arms matter for the same reason: a handler
/// drops what it cannot use, an emptied target set falls into the broadcast
/// default, and broadcast means the entire fleet. Neither rule is expressible
/// in MCP's closed schema subset (`items` type-checking is not applied by the
/// operator tier, which has no C8 gate at all, and there is no `minItems`), and
/// on the REST twins there is no schema in the first place.
///
/// The consequences are worth stating separately per surface, because they are
/// different failures: on MCP, a human approving a ticket that reads
/// `agent_ids: []` must not be approving a fleet-wide dispatch. On REST there
/// is no human — `{"agent_ids":[1,2,3]}` from a client emitting numeric device
/// ids, or `{"agent_ids":[]}` from a device filter that matched nothing, became
/// a fleet-wide dispatch that returned success and audited as success.
///
/// MUST BE CALLED ON THE PARSED REQUEST BODY, never on values already run
/// through an extraction helper. `server.cpp`'s `extract_json_string_array`
/// returns `{}` for omitted, empty, not-an-array AND parse-failure alike; that
/// erasure IS the defect. A check written against its output cannot see the
/// non-array or non-string-`scope` cases at all, and would ship half the bug
/// with green tests.
///
/// Pure and total: no I/O. Returns the FIRST violation in a deterministic
/// order so a denial is reproducible.
[[nodiscard]] inline std::optional<BoundViolation>
check_targeting_shape(const nlohmann::json& args) {
    if (args.contains("agent_ids")) {
        const auto& a = args["agent_ids"];
        if (!a.is_array())
            return BoundViolation{"agent_ids_type", "agent_ids must be an array of strings"};
        if (a.empty())
            return BoundViolation{"agent_ids_empty",
                                  "agent_ids was supplied but is empty; omit it to target "
                                  "all agents deliberately"};
        for (const auto& v : a) {
            if (!v.is_string())
                return BoundViolation{"agent_id_type", "agent_ids entries must be strings"};
        }
    }
    if (args.contains("scope")) {
        const auto& sc = args["scope"];
        if (!sc.is_string())
            return BoundViolation{"scope_type", "scope must be a string"};
        if (sc.get_ref<const std::string&>().empty())
            return BoundViolation{"scope_empty",
                                  "scope was supplied but is empty; omit it to target all "
                                  "agents deliberately"};
    }
    return std::nullopt;
}

/// Did the caller name a target at all?
///
/// The companion to `check_targeting_shape`, and the reason a sink can tell
/// "broadcast me" from "I meant something specific". A sink that only sees an
/// empty id vector cannot distinguish them — which is why every fix here has to
/// reach the parsed body rather than the extracted values.
[[nodiscard]] inline bool targeting_supplied(const nlohmann::json& args) {
    return args.contains("agent_ids") || args.contains("scope");
}

} // namespace yuzu::server
