#include "guardian_convergence_scheduler.hpp"

#include "guardian_joined_thread_role.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>

namespace yuzu::agent {

ConvergenceScheduler::ConvergenceScheduler(GuardianSparkRuntime& rt)
    : ConvergenceScheduler(rt, Config{}) {}

ConvergenceScheduler::ConvergenceScheduler(GuardianSparkRuntime& rt, Config cfg)
    : rt_(rt), cfg_(cfg), sig_(std::make_shared<Signal>()) {}

ConvergenceScheduler::~ConvergenceScheduler() { stop(); }

void ConvergenceScheduler::start() {
    {
        std::lock_guard<std::mutex> lk{sig_->mu};
        if (started_ || sig_->stopping)
            return;
        started_ = true;
    }
    // The waker lets a fresh attach jump the priority cadence. It captures the shared
    // Signal (NOT `this`), so a copy that outlives this scheduler stays safe.
    auto sig = sig_;
    rt_.set_pending_initial_waker([sig] {
        {
            std::lock_guard<std::mutex> lk{sig->mu};
            ++sig->priority_gen;
        }
        sig->cv.notify_all();
    });
    threads_.emplace_back([this] { lane_loop(SparkType::Service, cfg_.service_cadence_ms, 1); });
    threads_.emplace_back([this] { lane_loop(SparkType::Registry, cfg_.registry_cadence_ms, 2); });
    threads_.emplace_back([this] { lane_loop(SparkType::File, cfg_.file_cadence_ms, 3); });
    threads_.emplace_back([this] { priority_loop(); });
}

void ConvergenceScheduler::stop() {
    {
        std::lock_guard<std::mutex> lk{sig_->mu};
        if (sig_->stopping)
            return;
        sig_->stopping = true;
    }
    // Clear the runtime's slot so no NEW attach installs a wake; a copy already taken
    // by an in-flight attach stays safe (it holds the still-alive Signal).
    rt_.set_pending_initial_waker({});
    sig_->cv.notify_all();
    for (auto& t : threads_)
        if (t.joinable())
            t.join();
    threads_.clear();
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

void ConvergenceScheduler::firewalled_sweep(const std::function<void()>& fn) {
    try {
        fn();
    } catch (...) {
        const auto n = sweep_exceptions_.fetch_add(1, std::memory_order_relaxed) + 1;
        if (n == 1) {
            try {
                spdlog::error("Guardian convergence lane: sweep threw (firewalled; agent "
                              "survives, the lane keeps running). Further occurrences counted "
                              "only.");
            } catch (...) {
            }
        }
    }
}

void ConvergenceScheduler::lane_loop(SparkType type, std::uint64_t cadence_ms,
                                     std::uint64_t rng_offset) {
    // stop() joins this thread while GuardianEngine::stop() holds mtx_, so mtx_ must never
    // be taken from here - same hazard as the drain worker (#2298 Gate 4).
    const GuardianJoinedThreadRole role_marker;
    std::mt19937 rng{static_cast<std::uint32_t>(cfg_.rng_seed + rng_offset)};
    while (true) {
        {
            std::unique_lock<std::mutex> lk{sig_->mu};
            // A priority wake (notify without stopping) leaves the predicate false, so
            // this lane re-blocks until its own cadence: no head-of-line coupling.
            sig_->cv.wait_for(lk, jittered(cadence_ms, rng), [this] { return sig_->stopping; });
            if (sig_->stopping)
                return;
        }
        firewalled_sweep([this, type] { sweep_lane(type); });
    }
}

void ConvergenceScheduler::priority_loop() {
    const GuardianJoinedThreadRole role_marker;
    std::mt19937 rng{static_cast<std::uint32_t>(cfg_.rng_seed + 99)};
    std::uint64_t seen = 0;
    while (true) {
        {
            std::unique_lock<std::mutex> lk{sig_->mu};
            sig_->cv.wait_for(lk, jittered(cfg_.priority_poll_ms, rng),
                              [this, seen] { return sig_->stopping || sig_->priority_gen != seen; });
            if (sig_->stopping)
                return;
            seen = sig_->priority_gen;
        }
        firewalled_sweep([this] { sweep_pending_initial(); });
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
