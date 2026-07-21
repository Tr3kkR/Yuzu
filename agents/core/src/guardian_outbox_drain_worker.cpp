#include "guardian_outbox_drain_worker.hpp"

#include "guardian_lifecycle_journal.hpp"

#include <spdlog/spdlog.h>

#include <chrono>

namespace yuzu::agent {

namespace {
/// Wall clock in ms - the journal's retention basis (batch ts_ms is system_clock).
/// Deliberately NOT steady_clock: prune compares against persisted timestamps that
/// survive a reboot. The prune CADENCE below uses steady_clock instead, so a wall-clock
/// step cannot make maintenance either stall or spin.
std::int64_t journal_now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}
} // namespace

GuardianOutboxDrainWorker::GuardianOutboxDrainWorker(GuardianSparkRuntime& rt, SendFn send,
                                                     std::uint64_t periodic_bound_ms,
                                                     GuardianLifecycleJournal* journal,
                                                     std::uint64_t prune_interval_ms)
    : rt_(rt), send_(std::move(send)), periodic_bound_ms_(periodic_bound_ms), journal_(journal),
      prune_interval_ms_(prune_interval_ms), sig_(std::make_shared<Signal>()),
      last_prune_(std::chrono::steady_clock::now()) {}

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

void GuardianOutboxDrainWorker::notify() {
    {
        std::lock_guard<std::mutex> lk{sig_->mu};
        if (sig_->stopping)
            return;
        ++sig_->gen;
    }
    sig_->cv.notify_all();
}

bool GuardianOutboxDrainWorker::stop_requested() const {
    std::lock_guard<std::mutex> lk{sig_->mu};
    return sig_->stopping;
}

void GuardianOutboxDrainWorker::drain_once() { rt_.drain(send_); }

bool GuardianOutboxDrainWorker::maintenance_once() {
    if (!journal_)
        return false;
    // NOTE: no engine mtx_ anywhere on this path, by construction - see the class doc.
    const auto now = std::chrono::steady_clock::now();
    if (now - last_prune_ >= std::chrono::milliseconds(prune_interval_ms_)) {
        // Stamp BEFORE the pass: a prune that throws or is cut short by stopping_ must not
        // make every subsequent wake retry it (that would reinstate the per-wake full scan
        // this cadence exists to avoid). The next interval retries it normally.
        last_prune_ = now;
        journal_->prune(journal_now_ms());
    }
    return journal_->page_into_window(rt_, journal_now_ms()).records_paged > 0;
}

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
        const auto firewalled_drain = [this] {
            try {
                drain_once();
            } catch (...) {
                const auto n = drain_exceptions_.fetch_add(1, std::memory_order_relaxed) + 1;
                if (n == 1) {
                    try {
                        spdlog::error(
                            "Guardian drain worker: drain pass threw (firewalled; agent "
                            "survives, entries retained). Further occurrences counted only.");
                    } catch (...) {
                    }
                }
            }
        };
        firewalled_drain();

        // Journal maintenance (C0 #2298 gate 1): retention prune (time-cadenced) + replay
        // paging, relocated here off the heartbeat and reconnect threads. Firewalled
        // SEPARATELY from the drain pass in both directions - a maintenance throw must not
        // suppress draining, and a drain throw must not suppress retention - mirroring how
        // the heartbeat tick firewalled its two phases independently.
        if (stop_requested())
            return; // stop() is already waiting on the join; start no new KvStore work
        bool paged = false;
        try {
            paged = maintenance_once();
        } catch (...) {
            const auto n = journal_maint_exceptions_.fetch_add(1, std::memory_order_relaxed) + 1;
            if (n == 1) {
                try {
                    spdlog::error("Guardian drain worker: journal maintenance pass threw "
                                  "(firewalled; agent survives, journal retained). Further "
                                  "occurrences counted only.");
                } catch (...) {
                }
            }
        }
        // try_page_batch does NOT fire the enqueue waker, so records paged above would
        // otherwise sit in the window until the next wake. Drain again in the SAME pass.
        if (paged)
            firewalled_drain();
    }
}

} // namespace yuzu::agent
