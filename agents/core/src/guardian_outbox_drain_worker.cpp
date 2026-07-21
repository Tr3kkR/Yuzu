#include "guardian_outbox_drain_worker.hpp"

#include <spdlog/spdlog.h>

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
    bool first_stop = false;
    {
        std::lock_guard<std::mutex> lk{sig_->mu};
        if (!sig_->stopping) {
            sig_->stopping = true;
            first_stop = true;
        }
    }
    if (first_stop) {
        // Clear the runtime's slot so no NEW enqueue installs a wake; a copy
        // already taken by an in-flight enqueue stays safe (still-alive Signal).
        rt_.set_outbox_enqueue_waker({});
        sig_->cv.notify_all();
    }
    // The join is OUTSIDE the first_stop guard and keyed on joinable(), not on the
    // stopping flag: if a prior stop() threw after setting stopping but before joining
    // (e.g. from ~GuardianOutboxDrainWorker re-entry), a joinable thread would otherwise
    // reach ~std::thread and terminate. Always attempt the join while joinable (Fable).
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
        // Firewall the drain pass: this is a bare worker thread and the drain path
        // allocates (front_copy copies an OutboxEntry, pop_front_if builds a Key) plus
        // the injected send. A bad_alloc escaping here would terminate the whole agent
        // daemon (the #2037 class). Count it, log the first, keep looping - nothing was
        // popped, so entries stay buffered and the periodic backstop re-attempts once
        // memory recovers. (item 4 hardening / Fable.)
        try {
            drain_once();
        } catch (...) {
            const auto n = drain_exceptions_.fetch_add(1, std::memory_order_relaxed) + 1;
            if (n == 1) {
                try {
                    spdlog::error("Guardian drain worker: drain pass threw (firewalled; agent "
                                  "survives, entries retained). Further occurrences counted only.");
                } catch (...) {
                }
            }
        }
    }
}

} // namespace yuzu::agent
