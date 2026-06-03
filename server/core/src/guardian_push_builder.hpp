#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "guaranteed_state.pb.h"
#include "guaranteed_state_store.hpp"  // GuaranteedStateRuleRow

// Pure helpers for building the per-agent Guardian push (M4 / #1209). Kept out
// of server.cpp's push lambda so the rule-filtering + spec_json→proto marshal is
// unit-testable without a live AgentRegistry or gRPC stream (M7).
namespace yuzu::server::guardian {

// True iff a rule with os_target `target` should be enforced on an agent
// reporting platform `agent_os`. Empty target = applies to all OSes. An empty
// `agent_os` (unknown OS — e.g. a disconnect race or partial registration) also
// returns true: fail OPEN so a guard is never silently dropped, matching the
// pre-M4 send-all posture (the agent marks an inapplicable guard errored). Match
// is otherwise by canonical OS token: BOTH sides are normalised (`normalize_os` —
// lowercased and mapped to a canonical token such as "windows"/"linux"/"macos")
// and then compared for EQUALITY, so a verbose agent platform string ("Windows 11
// Pro") still matches the target "windows" without the false positives a raw
// substring test would admit (e.g. "win" inside "darwin").
bool os_target_matches(std::string_view target, std::string_view agent_os);

// Build the GuaranteedStatePush addressed to a SINGLE agent. Includes only
// enabled rules that (a) target this agent's OS and (b) name this agent in their
// scope — an empty rule scope_expr means fleet-wide and always matches. The
// `in_scope` oracle is supplied by the caller (which owns the scope engine and
// registry), keeping this function pure. Without M4's filtering, every agent
// received every enabled rule, so a Linux box was handed Windows registry guards
// (wasted bandwidth + G11 "errored" noise).
::yuzu::guardian::v1::GuaranteedStatePush
build_agent_push(const std::vector<GuaranteedStateRuleRow>& rules, std::string_view agent_os,
                 const std::function<bool(const std::string& scope_expr)>& in_scope,
                 bool full_sync, std::uint64_t generation);

} // namespace yuzu::server::guardian
