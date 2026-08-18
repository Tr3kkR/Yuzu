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
 */
#pragma once

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <type_traits>
#include <utility>

namespace yuzu::discovery {

template <typename Fn>
auto bounded_call(std::chrono::milliseconds timeout, Fn fn)
    -> std::optional<std::invoke_result_t<Fn>> {
    using Result = std::invoke_result_t<Fn>;

    struct State {
        std::mutex mtx;
        std::condition_variable cv;
        bool done = false;
        Result value{};
    };
    auto state = std::make_shared<State>();

    std::thread([fn = std::move(fn), state]() mutable {
        Result v = fn();
        {
            std::lock_guard<std::mutex> lock(state->mtx);
            state->value = std::move(v);
            state->done = true;
        }
        state->cv.notify_all();
    }).detach();

    std::unique_lock<std::mutex> lock(state->mtx);
    if (state->cv.wait_for(lock, timeout, [&] { return state->done; }))
        return std::move(state->value);
    return std::nullopt; // timed out; the detached thread finishes on its own time
}

} // namespace yuzu::discovery
