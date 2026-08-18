/**
 * bounded_wait.hpp — generic bounded-wait wrapper for an uncancellable
 * blocking call (Wave 2 PR2.1c, governance Gate 4 unhappy-path finding).
 *
 * Some blocking calls (getnameinfo's reverse-DNS lookup, in particular) have
 * no caller-supplied cancellation or timeout primitive. Calling one directly
 * from a task running on the agent's bounded ThreadPool risks pinning a
 * worker indefinitely if the underlying operation black-holes rather than
 * fails outright — and plugin execute() has no per-task cancellation to fall
 * back on, so a handful of stuck calls can exhaust the whole pool and stall
 * every other command dispatched to the agent.
 *
 * bounded_call() bounds the WAIT instead of the call: `fn` runs on a detached
 * thread, and the caller gives up after `timeout` if it hasn't finished,
 * leaving the detached thread to complete (or not) on its own — harmless
 * once abandoned, since nothing observes its result after the deadline.
 *
 * Two hardenings added by governance Gate 5 (chaos-injector), both closing
 * a real gap in the first cut of this primitive:
 *
 *  - Outstanding-thread ceiling. A caller retrying against a SUSTAINED
 *    black hole (not a one-off) still bounds each individual WAIT, but
 *    nothing bounded how many detached threads could pile up concurrently —
 *    verified by execution to reach dozens of concurrently-outstanding
 *    threads under a simulated black hole. Since this codebase has other,
 *    pre-existing unguarded std::thread spawns elsewhere in the agent
 *    (tracked separately — see the fix commit), letting this primitive grow
 *    the process's OS thread count without limit is itself a resource-
 *    exhaustion vector. Once kMaxOutstandingBoundedCalls threads are already
 *    outstanding, a new call degrades to an immediate nullopt (the same
 *    outcome as a timeout) rather than spawning another thread — this never
 *    blocks the caller, which is the whole point of the primitive.
 *  - Exception safety. `fn()` running on a raw detached thread is NOT
 *    covered by ThreadPool's own exception firewall (that only wraps
 *    pool-dispatched tasks). An exception escaping `fn()` uncaught would
 *    std::terminate() the whole process. Caught and treated as a
 *    non-arrival — the waiting side (if still waiting) simply times out.
 */
#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <type_traits>
#include <utility>

namespace yuzu::discovery {

namespace detail {

// Well above realistic legitimate concurrency (the agent's ThreadPool caps
// at 32 workers) but far below what would meaningfully threaten the
// process's OS thread budget.
constexpr int kMaxOutstandingBoundedCalls = 64;
inline std::atomic<int> g_outstanding_bounded_calls{0};

} // namespace detail

template <typename Fn>
auto bounded_call(std::chrono::milliseconds timeout, Fn fn)
    -> std::optional<std::invoke_result_t<Fn>> {
    using Result = std::invoke_result_t<Fn>;

    if (++detail::g_outstanding_bounded_calls > detail::kMaxOutstandingBoundedCalls) {
        --detail::g_outstanding_bounded_calls;
        return std::nullopt; // at the ceiling — degrade like a timeout, never block
    }

    struct State {
        std::mutex mtx;
        std::condition_variable cv;
        bool done = false;
        Result value{};
    };
    auto state = std::make_shared<State>();

    std::thread([fn = std::move(fn), state]() mutable {
        try {
            Result v = fn();
            std::lock_guard<std::mutex> lock(state->mtx);
            state->value = std::move(v);
            state->done = true;
        } catch (...) {
            // fn() throwing must not std::terminate() a detached thread.
            // Leave `done` false — a still-waiting caller simply times out.
        }
        state->cv.notify_all();
        --detail::g_outstanding_bounded_calls;
    }).detach();

    std::unique_lock<std::mutex> lock(state->mtx);
    if (state->cv.wait_for(lock, timeout, [&] { return state->done; }))
        return std::move(state->value);
    return std::nullopt; // timed out; the detached thread finishes on its own time
}

} // namespace yuzu::discovery
