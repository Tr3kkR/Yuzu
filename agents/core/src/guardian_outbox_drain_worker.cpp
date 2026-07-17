#include "guardian_outbox_drain_worker.hpp"

#include <chrono>

namespace yuzu::agent {

GuardianOutboxDrainWorker::GuardianOutboxDrainWorker(GuardianSparkRuntime& rt, SendFn send,
                                                     std::uint64_t periodic_bound_ms)
    : rt_(rt), send_(std::move(send)), periodic_bound_ms_(periodic_bound_ms),
      sig_(std::make_shared<Signal>()) {}

GuardianOutboxDrainWorker::~GuardianOutboxDrainWorker() { stop(); }

void GuardianOutboxDrainWorker::start() {
    {
        std::lock_guard<std::mutex> lk{sig_->mu};
        if (started_ || sig_->stopping)
            return;
        started_ = true;
    }
    // Captures the shared Signal (NOT `this`), so a copy that outlives this
    // worker (installed on the runtime, cleared in stop() but a copy already
    // taken by an in-flight enqueue stays safe) touches a still-alive Signal.
    auto sig = sig_;
    rt_.set_outbox_enqueue_waker([sig] {
        {
            std::lock_guard<std::mutex> lk{sig->mu};
            ++sig->gen;
        }
        sig->cv.notify_all();
    });
    thread_ = std::thread([this] { loop(); });
}

void GuardianOutboxDrainWorker::stop() {
    {
        std::lock_guard<std::mutex> lk{sig_->mu};
        if (sig_->stopping)
            return;
        sig_->stopping = true;
    }
    // Clear the runtime's slot so no NEW enqueue installs a wake; a copy
    // already taken by an in-flight enqueue stays safe (still-alive Signal).
    rt_.set_outbox_enqueue_waker({});
    sig_->cv.notify_all();
    if (thread_.joinable())
        thread_.join();
}

void GuardianOutboxDrainWorker::drain_once() { rt_.drain(send_); }

void GuardianOutboxDrainWorker::loop() {
    std::uint64_t seen = 0;
    while (true) {
        {
            std::unique_lock<std::mutex> lk{sig_->mu};
            sig_->cv.wait_for(lk, std::chrono::milliseconds(periodic_bound_ms_),
                              [this, seen] { return sig_->stopping || sig_->gen != seen; });
            if (sig_->stopping)
                return;
            seen = sig_->gen;
        }
        drain_once();
    }
}

} // namespace yuzu::agent
