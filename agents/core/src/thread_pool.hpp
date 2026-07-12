#pragma once

// ── Bounded Thread Pool ──────────────────────────────────────────────────────
// Replaces unbounded std::thread-per-command dispatch. Workers pull tasks from
// a shared queue protected by a mutex + condition variable. If the queue exceeds
// max_queue_size, submit() returns false so the caller can reject the command.
//
// Exception firewall (#2037): each task runs inside a try/catch(...) so that a
// task which lets an exception escape cannot propagate out of the worker's
// top-level callable — which would call std::terminate() -> abort() and kill the
// whole agent process. On Windows that abort surfaces as exception code
// 0xC0000409 (FAST_FAIL_FATAL_APP_EXIT), easily mistaken for a /GS stack-buffer
// overrun. Callers that need a per-task failure signal must still handle their
// own exceptions; this firewall is the last-resort net that keeps one task's
// failure from taking down the process or the other workers.

#include <algorithm>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

#include <spdlog/spdlog.h>

namespace yuzu::agent {

class ThreadPool {
public:
    explicit ThreadPool(std::size_t num_threads, std::size_t max_queue_size = 1000)
        : max_queue_size_{max_queue_size} {
        // Clamp thread count: min 4, max 32
        num_threads = std::max<std::size_t>(num_threads, 4);
        num_threads = std::min<std::size_t>(num_threads, 32);
        workers_.reserve(num_threads);
        for (std::size_t i = 0; i < num_threads; ++i) {
            workers_.emplace_back([this] {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock lock(mu_);
                        cv_.wait(lock, [this] { return stop_ || !tasks_.empty(); });
                        if (stop_ && tasks_.empty())
                            return;
                        task = std::move(tasks_.front());
                        tasks_.pop();
                    }
                    // Exception firewall (#2037): a task must never let an
                    // exception escape this callable — that would terminate() the
                    // whole agent. Contain it here so the worker survives and
                    // keeps pulling the next task. The log calls are themselves
                    // wrapped: spdlog can throw (alloc/sink/fmt failure), and a
                    // throw from this last-resort handler would re-open the very
                    // terminate() hole we are closing.
                    try {
                        task();
                    } catch (const std::exception& e) {
                        try {
                            spdlog::error("ThreadPool task threw std::exception (contained, "
                                          "worker survives): {}",
                                          e.what());
                        } catch (...) {}
                    } catch (...) {
                        try {
                            spdlog::error("ThreadPool task threw a non-std exception "
                                          "(contained, worker survives)");
                        } catch (...) {}
                    }
                }
            });
        }
        spdlog::info("Thread pool started: {} workers, max queue {}", num_threads, max_queue_size);
    }

    // Returns false if the queue is full (backpressure).
    bool submit(std::function<void()> task) {
        {
            std::lock_guard lock(mu_);
            if (stop_)
                return false;
            if (tasks_.size() >= max_queue_size_)
                return false;
            tasks_.push(std::move(task));
        }
        cv_.notify_one();
        return true;
    }

    ~ThreadPool() {
        {
            std::lock_guard lock(mu_);
            stop_ = true;
        }
        cv_.notify_all();
        for (auto& w : workers_) {
            if (w.joinable())
                w.join();
        }
    }

    // Non-copyable, non-movable
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

private:
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    std::mutex mu_;
    std::condition_variable cv_;
    bool stop_ = false;
    std::size_t max_queue_size_;
};

} // namespace yuzu::agent
