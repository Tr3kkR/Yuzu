#include "guardian_convergence_scheduler.hpp"

#include <algorithm>

namespace yuzu::agent {

ConvergenceScheduler::ConvergenceScheduler(GuardianSparkRuntime& rt)
    : ConvergenceScheduler(rt, Config{}) {}

ConvergenceScheduler::ConvergenceScheduler(GuardianSparkRuntime& rt, Config cfg)
    : rt_(rt), cfg_(cfg) {}

ConvergenceScheduler::~ConvergenceScheduler() { stop(); }

void ConvergenceScheduler::start() {
    {
        std::lock_guard<std::mutex> lk{mu_};
        if (started_ || stopping_)
            return;
        started_ = true;
    }
    // The waker lets a fresh attach jump the priority cadence. Installed before
    // the threads run so no early wake is lost.
    rt_.set_pending_initial_waker([this] { wake_priority(); });
    threads_.emplace_back([this] { lane_loop(SparkType::Service, cfg_.service_cadence_ms, 1); });
    threads_.emplace_back([this] { lane_loop(SparkType::Registry, cfg_.registry_cadence_ms, 2); });
    threads_.emplace_back([this] { lane_loop(SparkType::File, cfg_.file_cadence_ms, 3); });
    threads_.emplace_back([this] { priority_loop(); });
}

void ConvergenceScheduler::stop() {
    {
        std::lock_guard<std::mutex> lk{mu_};
        if (stopping_)
            return;
        stopping_ = true;
    }
    // Stop new wakes before tearing down, so no attach-driven waker outlives us.
    rt_.set_pending_initial_waker({});
    cv_.notify_all();
    for (auto& t : threads_)
        if (t.joinable())
            t.join();
    threads_.clear();
}

void ConvergenceScheduler::wake_priority() {
    {
        std::lock_guard<std::mutex> lk{mu_};
        ++priority_gen_;
    }
    cv_.notify_all(); // lanes re-check stopping_ (false) and re-block; the priority lane proceeds
}

std::chrono::milliseconds ConvergenceScheduler::jittered(std::uint64_t base_ms,
                                                         std::mt19937& rng) const {
    if (cfg_.jitter_pct == 0 || base_ms == 0)
        return std::chrono::milliseconds{base_ms};
    const std::uint64_t span = (base_ms * cfg_.jitter_pct) / 100; // +/- this many ms
    if (span == 0)
        return std::chrono::milliseconds{base_ms};
    std::uniform_int_distribution<std::int64_t> dist(-static_cast<std::int64_t>(span),
                                                     static_cast<std::int64_t>(span));
    const std::int64_t ms = static_cast<std::int64_t>(base_ms) + dist(rng);
    return std::chrono::milliseconds{std::max<std::int64_t>(1, ms)};
}

void ConvergenceScheduler::lane_loop(SparkType type, std::uint64_t cadence_ms,
                                     std::uint64_t rng_offset) {
    std::mt19937 rng{static_cast<std::uint32_t>(cfg_.rng_seed + rng_offset)};
    while (true) {
        {
            std::unique_lock<std::mutex> lk{mu_};
            // A priority wake (notify without stopping_) leaves the predicate false,
            // so this lane re-blocks until its own cadence: no head-of-line coupling.
            cv_.wait_for(lk, jittered(cadence_ms, rng), [this] { return stopping_; });
            if (stopping_)
                return;
        }
        sweep_lane(type);
    }
}

void ConvergenceScheduler::priority_loop() {
    std::mt19937 rng{static_cast<std::uint32_t>(cfg_.rng_seed + 99)};
    std::uint64_t seen = 0;
    while (true) {
        {
            std::unique_lock<std::mutex> lk{mu_};
            cv_.wait_for(lk, jittered(cfg_.priority_poll_ms, rng),
                         [this, seen] { return stopping_ || priority_gen_ != seen; });
            if (stopping_)
                return;
            seen = priority_gen_;
        }
        sweep_pending_initial();
    }
}

void ConvergenceScheduler::sweep_lane(SparkType type) {
    for (const std::string& key : rt_.keys_for_type(type))
        rt_.evaluate_key(key, EvalReason::Convergence);
}

void ConvergenceScheduler::sweep_pending_initial() {
    for (const std::string& key : rt_.keys_with_pending_initial())
        rt_.evaluate_key(key, EvalReason::Convergence);
}

} // namespace yuzu::agent
