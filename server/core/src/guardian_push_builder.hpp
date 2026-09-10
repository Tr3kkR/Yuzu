#pragma once

#include <array>
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
// lower-cased and darwin mapped to macos) and then compared for EQUALITY, so a
// short/ambiguous target like "win" can never spuriously match "darwin" (a raw
// substring test would admit it). NOTE: `agent_os` is always the RAW kAgentOs
// token ("windows" | "linux" | "darwin"), never verbose free text —
// `normalize_os` does NOT parse a string like "Windows 11 Pro" down to
// "windows"; it only lower-cases and maps darwin to macos. An earlier version
// of this comment claimed otherwise; that claim was false (#4252).
bool os_target_matches(std::string_view target, std::string_view agent_os);

// True iff the agent-side Guardian engine actually ARMS a guard of spark type
// `spark_type` on `agent_os`. NOT a blanket OS check — support is PER GUARD
// TYPE (#4252 fixed a dashboard double-count caused by treating it as one):
//   registry-change / file-change  -> Windows only. RegistryGuard::start() /
//                                      FileGuard::start() are compiled no-ops
//                                      on macOS and Linux
//                                      (agents/core/src/guard_registry.cpp,
//                                      guard_file.cpp).
//   service-status-change          -> Windows AND Linux. SystemdServiceGuard
//                                      (agents/core/src/guard_systemd.cpp's
//                                      make_service_guard()) arms on Linux
//                                      today (observe-only; enforce is
//                                      deliberately deferred) — NOT a no-op,
//                                      unlike Registry/File on Linux. macOS
//                                      still falls to the no-op ServiceGuard
//                                      stub. See docs/os-capability-matrix.md's
//                                      Guardian rows and docs/user-manual/
//                                      guaranteed-state.md's Service section.
//   unknown / missing / non-string  -> falls back to the Windows-only rule,
//   spark_type                         so a malformed row or a guard type
//                                      this function doesn't yet recognise
//                                      can never silently regress
//                                      Registry/File support.
// The server must therefore report an unsupported (agent, rule) pair as "not
// yet implemented" rather than letting it fold into the offline "unknown"
// bucket and read as armed — an operator must never mistake a no-op platform
// for a protected one. Just as important, a caller MUST first check whether
// the pair already owns a REAL status row before treating "unsupported" as
// "the agent never reported" — Linux Service now legitimately reports real
// status, so skipping that check double-counts the pair (the #4252 bug); see
// the shared exclusion predicate in guardian_routes.cpp. `agent_os` is the RAW
// token the agent reports (kAgentOs: "windows" | "linux" | "darwin"); it is
// normalised before comparison. An empty `agent_os` (unknown — disconnect
// race / partial registration) returns true so we never mislabel it
// unimplemented, for any spark_type. THIS is the single place to extend as
// more guard types/platforms gain support.
bool guardian_guard_supported_on_platform(std::string_view agent_os,
                                          std::string_view spark_type);

// The 3 guard-type ("spark.type") tokens this matrix explicitly distinguishes.
// Single source shared with guardian_routes.cpp's platform-matrix-stale
// detectability counter's closed Prometheus label set, and cross-checked
// against the published schema catalog's "spark"-kind entries by
// test_guardian_resilience_schema.cpp's CROSS-CHECK tests (governance Gate 4
// finding, #4252 consolidated round) — so the schema catalog, this matrix, and
// the stale-counter's label set can no longer drift out of sync silently the
// way three independently hand-maintained lists could. A 4th spark type must
// be added HERE (and to this function's branch above) for the cross-check to
// stay green; the schema-registry side is guardian_schema_registry.cpp's
// build_catalog().
inline constexpr std::array<std::string_view, 3> kKnownGuardSparkTypes = {
    "registry-change", "file-change", "service-status-change"};

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
//
// Total over arbitrary stored bytes: a rule row with a malformed (present but
// non-string) spark/assertion/remediation `type` marshals to an inert empty
// type rather than throwing — the fan-out never aborts on one bad row (#1946).
::yuzu::guardian::v1::GuaranteedStatePush
build_agent_push(const std::vector<GuaranteedStateRuleRow>& rules, std::string_view agent_os,
                 const std::function<bool(const std::string& scope_expr)>& in_scope,
                 bool full_sync, std::uint64_t generation);

} // namespace yuzu::server::guardian
