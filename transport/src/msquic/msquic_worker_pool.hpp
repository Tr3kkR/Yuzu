// SPDX-License-Identifier: Apache-2.0
// Fixed-size worker thread pool for the msquic backend.
//
// msquic delivers stream/connection events on its own internal worker
// threads. A transport handler MUST NOT run on one of those threads —
// blocking it stalls every other connection that thread serves. So the
// msquic listener hands handler invocations to this pool instead.
//
// #376 PR 3, increment 2 introduces the pool as a plain fixed-size
// executor (pre-spawned threads draining an unbounded queue). Increment 7
// layers the bounded-dispatcher saturation-rejection contract
// (ListenerOptions::bidi_dispatcher_pool_size, the exact-string reject
// detail, the metric-sink gauge deltas) on top of this primitive.

#pragma once

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

namespace yuzu::transport::msquic_backend {

class WorkerPool {
public:
    // Pre-spawns `size` worker threads (clamped to at least 1).
    explicit WorkerPool(std::size_t size) {
        if (size == 0) size = 1;
        workers_.reserve(size);
        for (std::size_t i = 0; i < size; ++i) {
            workers_.emplace_back([this] { run(); });
        }
    }

    // Joins every worker. Tasks already queued are drained first; no new
    // task may be submitted after destruction begins.
    ~WorkerPool() {
        {
            std::lock_guard<std::mutex> lock(mtx_);
            stopping_ = true;
        }
        cv_.notify_all();
        for (auto& w : workers_) {
            if (w.joinable()) w.join();
        }
    }

    WorkerPool(const WorkerPool&)            = delete;
    WorkerPool& operator=(const WorkerPool&) = delete;

    // Enqueue a task. Returns false if the pool is shutting down (the
    // task is not enqueued). The task runs on one of the pool threads.
    bool submit(std::function<void()> task) {
        {
            std::lock_guard<std::mutex> lock(mtx_);
            if (stopping_) return false;
            queue_.push_back(std::move(task));
        }
        cv_.notify_one();
        return true;
    }

    std::size_t size() const noexcept { return workers_.size(); }

private:
    void run() {
        for (;;) {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lock(mtx_);
                cv_.wait(lock, [this] {
                    return stopping_ || !queue_.empty();
                });
                if (queue_.empty()) {
                    // stopping_ && empty -> drained, exit.
                    return;
                }
                task = std::move(queue_.front());
                queue_.pop_front();
            }
            task();
        }
    }

    std::mutex                          mtx_;
    std::condition_variable             cv_;
    std::deque<std::function<void()>>   queue_;
    std::vector<std::thread>            workers_;
    bool                                stopping_ = false;
};

}  // namespace yuzu::transport::msquic_backend
