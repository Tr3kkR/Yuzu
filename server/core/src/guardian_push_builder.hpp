#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_set>
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

// True iff the agent-side Guardian engine actually ARMS guards on `agent_os`.
// Today that is Windows only: RegistryGuard::start() / FileGuard::start() are
// compiled no-ops on macOS and Linux (agents/core/src/guard_registry.cpp,
// guard_file.cpp), so a guard "deployed" to a Mac/Linux box enforces nothing.
// The server must therefore report those agents as "not yet implemented" rather
// than letting them fold into the offline "unknown" bucket and read as armed —
// an operator must never mistake a no-op platform for a protected one. `agent_os`
// is the RAW token the agent reports (kAgentOs: "windows" | "linux" | "darwin");
// it is normalised before comparison. An empty `agent_os` (unknown — disconnect
// race / partial registration) returns true so we never mislabel it unimplemented.
// THIS is the single switch to flip as Linux/macOS guard support lands.
bool guardian_enforced_on_platform(std::string_view agent_os);

// Human-facing label for a raw agent platform token, for dashboard copy:
// "darwin" -> "macOS", "windows" -> "Windows", "linux" -> "Linux"; an
// unknown/empty token -> "unknown". (The canonical wire/author token stays
// "macos" per #1209; this only governs display.)
std::string platform_display_name(std::string_view agent_os);

// The Baseline gate. Returns the subset of `rules` whose rule_id is in
// `deployed_rule_ids` — the union of member Guards across all *deployed*
// Baselines. A Guard reaches an agent ONLY as a member of a deployed Baseline
// (docs/guardian-baseline-model.md); this filter is applied to the push/reconcile
// rule source so an enabled-but-undeployed Guard never enforces. Order preserved.
// An empty `deployed_rule_ids` yields an empty result — correct by model (with
// nothing deployed, a full_sync push converges agents to zero guards).
std::vector<GuaranteedStateRuleRow>
filter_deployed_members(const std::vector<GuaranteedStateRuleRow>& rules,
                        const std::unordered_set<std::string>& deployed_rule_ids);

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
