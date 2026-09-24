#pragma once

/// @file shutdown_drain_rules.hpp
/// HA WS-8 (ADR-2002 §12 "Draining: fail /readyz, let the fronting layer
/// drain, then stop"): the PURE decision behind `ServerImpl::stop()`'s drain
/// wait, and the one home of its bounds. `stop()` sets `draining_` (so `/readyz`
/// answers 503 `draining`) and then keeps the listener open while
/// `keep_draining()` says so. Everything else keeps serving during the wait —
/// the load balancer has not removed this replica yet, and in-flight requests
/// must still succeed.
///
/// Two independent reasons to wait:
///   1. `--shutdown-drain-seconds N` — a MINIMUM wait, so a load balancer
///      polling `/readyz` sees the 503 and stops routing here BEFORE the
///      socket closes. Without it, a replica with nothing in flight closed its
///      listener immediately and the LB learned about it from refused
///      connections. Default 0 (single-node shutdown unchanged).
///   2. In-flight executions — the pre-existing wait, capped at
///      `kExecutionDrainCap` from drain start.
///
/// Total wait is therefore max(N, time for executions to finish), and never more
/// than max(N, kExecutionDrainCap).
///
/// `kMaxShutdownDrainSeconds` is 60, not more, because the shipped stop budgets
/// (compose `stop_grace_period: 210s`, systemd `TimeoutStopSec=210`) must still
/// cover the whole stacked shutdown. docs/user-manual/upgrading.md documents a
/// ~115s stacked worst case whose FIRST stage is this 30s execution drain; the
/// grace replaces that stage with max(N, 30), so the worst case becomes
/// max(N, 30) + 85s — 145s at N = 60, and ~205s on the rare thread-exhaustion
/// fallback path server-admin.md documents (~175s today), only 5s inside 210s.
/// Raising this cap means raising those budgets (and both docs) in the same
/// change; the unit test pins both sums.

#include <chrono>

namespace yuzu::server::shutdown_drain {

inline constexpr int kMaxShutdownDrainSeconds = 60;
inline constexpr std::chrono::seconds kExecutionDrainCap{30};

/// True while `stop()` should keep the listener open.
constexpr bool keep_draining(std::chrono::steady_clock::duration elapsed,
                             std::chrono::seconds min_grace, bool executions_running) noexcept {
    if (elapsed < min_grace)
        return true;
    return executions_running && elapsed < kExecutionDrainCap;
}

} // namespace yuzu::server::shutdown_drain
