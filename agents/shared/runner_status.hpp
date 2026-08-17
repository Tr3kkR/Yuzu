/**
 * runner_status.hpp — the ONE mapping from a bounded-runner outcome to the
 * ABI4 plugin→host result seam (ADR-3002 acquisition-ladder migration).
 * Consumers: every Wave-2 runner-migration plugin package (users, certificates,
 * discovery, network_actions, wol, quarantine, services, interaction) — the
 * first forwarders of a bounded-runner outcome through this seam.
 *
 * Maps only the NON-EXIT outcomes: whether a nonzero exit code is an error is
 * the caller's domain (a nonzero `ping` exit means "host down", not a plugin
 * failure), so `exited` — and the deliberate `line_limit` clean stop — return
 * nullopt and the caller owns the status (or leaves it for the agent's
 * exit-code derivation).
 *
 * Kept a pure classification + a thin forwarding wrapper so the table is
 * fixture-testable without a context or a spawn.
 */
#pragma once

#include <yuzu/agent/subprocess_runner.hpp>
#include <yuzu/plugin.hpp>

#include <optional>

namespace yuzu::shared {

struct RunnerFailureStatus {
    YuzuResultStatus status;
    YuzuResultCompleteness completeness;
    const char* provenance; // static string; the host copies it synchronously
};

// Pure. nullopt => the child exited (incl. a clean line_limit stop): the
// CALLER owns exit-code semantics.
inline std::optional<RunnerFailureStatus> classify_runner_failure(
    const yuzu::agent::SubprocessResult& r) {
    using yuzu::agent::TerminationReason;
    switch (r.termination_reason) {
    case TerminationReason::spawn_error:
        return RunnerFailureStatus{YUZU_RESULT_STATUS_UNAVAILABLE,
                                   YUZU_RESULT_COMPLETENESS_PARTIAL,
                                   "subprocess_runner:spawn_error"};
    case TerminationReason::deadline:
        return RunnerFailureStatus{YUZU_RESULT_STATUS_CONSTRAINED,
                                   YUZU_RESULT_COMPLETENESS_PARTIAL,
                                   "subprocess_runner:deadline"};
    case TerminationReason::cancelled:
        return RunnerFailureStatus{YUZU_RESULT_STATUS_CONSTRAINED,
                                   YUZU_RESULT_COMPLETENESS_PARTIAL,
                                   "subprocess_runner:cancelled"};
    case TerminationReason::signaled:
        return RunnerFailureStatus{YUZU_RESULT_STATUS_CONSTRAINED,
                                   YUZU_RESULT_COMPLETENESS_PARTIAL,
                                   "subprocess_runner:signaled"};
    case TerminationReason::exited:
    case TerminationReason::line_limit:
        return std::nullopt;
    }
    return std::nullopt; // unreachable; keeps -Wswitch happy across compilers
}

// Thin non-pure wrapper: forwards a runner failure through the ABI4 result
// seam. Returns true when a status was set (the caller should usually stop
// treating the output as complete).
inline bool forward_runner_failure(yuzu::CommandContext& ctx,
                                   const yuzu::agent::SubprocessResult& r) {
    const auto s = classify_runner_failure(r);
    if (!s)
        return false;
    ctx.set_result_status(s->status, s->completeness, s->provenance);
    return true;
}

} // namespace yuzu::shared
