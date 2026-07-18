#pragma once

// Terminate-safe rollback guard shared by GuardianEngine and GuardianSparkRuntime
// (ADR-0021 rung 7.7b, PR-1 item 3 / Sol B3 / Fable review).
//
// A rollback fires precisely when something ELSE already threw - very often a
// std::bad_alloc mid-unwind. Its cleanup (index removal that copies a key, a
// backend disarm that reaches a mechanism unwatch) can itself allocate and throw.
// A plain `~ScopeExit` is implicitly noexcept, so a throw from its cleanup during
// unwinding calls std::terminate and kills the whole agent daemon. This guard
// swallows a cleanup throw instead: surviving with a possible leak (e.g. an
// undisarmed watcher) beats crashing every plugin, the heartbeat, and every other
// rule. Swallowed failures are counted for observability (the agent has no /metrics;
// item 9 surfaces this via the heartbeat).

#include <cstdint>
#include <functional>

namespace yuzu::agent {

/// Process-wide count of rollback cleanups that threw during unwinding and were
/// swallowed to avoid std::terminate. A nonzero value means a rollback could not
/// fully undo its mutation under memory pressure - a real (if rare) leak signal.
[[nodiscard]] std::uint64_t guardian_rollback_cleanup_failures() noexcept;

/// A committed-or-rollback scope guard whose destructor NEVER propagates an
/// exception. Set `fn` to the undo action and `committed = true` on the success
/// path. Kept an aggregate (only data members + a user-declared destructor, which
/// preserves aggregate-ness in C++20) so call sites can `GuardianRollback g{fn}` or
/// default-construct then assign `g.fn`, exactly as the local ScopeExit guards did.
struct GuardianRollback {
    std::function<void()> fn;
    bool committed{false};
    ~GuardianRollback();
};

} // namespace yuzu::agent
