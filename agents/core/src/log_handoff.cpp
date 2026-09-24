#include "log_handoff.hpp"

#include "hard_exit.hpp"              // hard_exit()
#include "shutdown_deadline_guard.hpp" // ShutdownDeadlineGuard

#include <spdlog/sinks/null_sink.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <condition_variable>
#include <thread>
#include <utility>

namespace yuzu::agent {

// ---------------------------------------------------------------------------
// StallObservableSink
// ---------------------------------------------------------------------------

StallObservableSink::WriteGuard::WriteGuard(StallObservableSink& self) noexcept : self_(self) {
    // Record the start time BEFORE flipping in_flight_ so a concurrent reader that
    // observes in_write()==true never sees a stale/unset started_at_ticks_ (see
    // write_started_at()'s doc comment).
    self_.started_at_ticks_.store(std::chrono::steady_clock::now().time_since_epoch().count(),
                                  std::memory_order_relaxed);
    self_.in_flight_.fetch_add(1, std::memory_order_acq_rel);
}

StallObservableSink::WriteGuard::~WriteGuard() {
    self_.in_flight_.fetch_sub(1, std::memory_order_acq_rel);
}

StallObservableSink::StallObservableSink(std::shared_ptr<spdlog::sinks::sink> inner)
    : inner_(std::move(inner)) {}

void StallObservableSink::log(const spdlog::details::log_msg& msg) {
    WriteGuard guard(*this);
    inner_->log(msg);
}

void StallObservableSink::flush() {
    WriteGuard guard(*this);
    inner_->flush();
}

void StallObservableSink::set_pattern(const std::string& pattern) { inner_->set_pattern(pattern); }

void StallObservableSink::set_formatter(std::unique_ptr<spdlog::formatter> sink_formatter) {
    inner_->set_formatter(std::move(sink_formatter));
}

bool StallObservableSink::in_write() const noexcept {
    return in_flight_.load(std::memory_order_acquire) != 0;
}

std::chrono::steady_clock::time_point StallObservableSink::write_started_at() const noexcept {
    return std::chrono::steady_clock::time_point(
        std::chrono::steady_clock::duration(started_at_ticks_.load(std::memory_order_relaxed)));
}

// ---------------------------------------------------------------------------
// Drain-reader lease (BLOCKER-1 fix, #4666 PR-1 adversarial review): the control block
// LogHandoff::drain_gate_ points at. See the header's DRAIN-READER LEASE paragraph for
// the full mechanism; this is the implementation. Defined at namespace scope (not
// anonymous) because DrainGate is forward-declared in the header as
// yuzu::agent::DrainGate.
// ---------------------------------------------------------------------------

struct DrainGate {
    std::mutex mu;
    std::condition_variable cv;
    int active_readers{0};
    bool closed{false};
};

// ---------------------------------------------------------------------------
// Worker-exit signal (fixes the general producer-thread race the drain-reader lease
// above does not cover -- second-round #4666 PR-1 adversarial review). See the
// header's WORKER-EXIT SIGNAL paragraph for the full mechanism. A one-shot latch: the
// pool's single worker thread sets `exited` and notifies from spdlog's own
// on_thread_stop callback, which fires ON THE WORKER THREAD ITSELF, strictly after
// worker_loop_() has genuinely returned (verified against thread_pool-inl.h's ctor).
// Defined at namespace scope (not anonymous), matching DrainGate, because
// WorkerExitSignal is forward-declared in the header as yuzu::agent::WorkerExitSignal.
// ---------------------------------------------------------------------------

struct WorkerExitSignal {
    std::mutex mu;
    std::condition_variable cv;
    bool exited{false};
};

// ---------------------------------------------------------------------------
// Global drain-lookup slot for drain_log_bounded() (plan 1.8). File-local: no header
// exposure needed, only LogHandoff's own private static members and the
// drain_log_bounded() free function below ever touch this.
// ---------------------------------------------------------------------------
namespace {

struct DrainHandle {
    const LogHandoff* owner{nullptr}; // identity only -- NEVER dereferenced
    std::weak_ptr<spdlog::details::thread_pool> pool;
    std::weak_ptr<spdlog::async_logger> logger;
    std::vector<std::weak_ptr<StallObservableSink>> sinks;
    std::shared_ptr<DrainGate> gate; // strong -- see DrainLease below; the gate itself
                                      // is a tiny mutex+cv+counter, never a blocking
                                      // destructor, so holding it strongly is safe.
};

std::mutex& drain_mutex() {
    static std::mutex m;
    return m;
}

std::shared_ptr<DrainHandle>& drain_slot() {
    static std::shared_ptr<DrainHandle> slot;
    return slot;
}

/// RAII drain-reader lease. Held for the ENTIRE span drain_log_bounded() can hold any
/// strong shared_ptr<thread_pool> reference -- declared FIRST in drain_log_bounded()
/// so it destructs LAST (C++ reverse-declaration-order destruction), strictly AFTER
/// every local `pool`/`p` shared_ptr in that function has already been dropped. This is
/// what makes active_readers==0 a reliable signal to teardown()'s
/// wait_for_drain_quiescence() that no external strong pool_ reference can remain.
class DrainLease {
public:
    explicit DrainLease(std::shared_ptr<DrainGate> gate) : gate_(std::move(gate)) {
        if (!gate_)
            return;
        std::lock_guard<std::mutex> lk(gate_->mu);
        if (gate_->closed)
            return; // teardown() has already closed admission -- refuse
        ++gate_->active_readers;
        acquired_ = true;
    }

    ~DrainLease() {
        if (!acquired_)
            return;
        bool notify = false;
        {
            std::lock_guard<std::mutex> lk(gate_->mu);
            if (--gate_->active_readers == 0)
                notify = true;
        }
        if (notify)
            gate_->cv.notify_all();
    }

    [[nodiscard]] bool acquired() const noexcept { return acquired_; }

    DrainLease(const DrainLease&) = delete;
    DrainLease& operator=(const DrainLease&) = delete;

private:
    std::shared_ptr<DrainGate> gate_;
    bool acquired_{false};
};

} // namespace

void LogHandoff::register_global_drain_handle(LogHandoff* self) {
    auto handle = std::make_shared<DrainHandle>();
    handle->owner = self;
    handle->pool = self->pool_;
    handle->logger = self->logger_;
    handle->sinks.assign(self->wrapped_sinks_.begin(), self->wrapped_sinks_.end());
    handle->gate = self->drain_gate_;
    std::lock_guard<std::mutex> lk(drain_mutex());
    drain_slot() = std::move(handle);
}

void LogHandoff::clear_global_drain_handle(const LogHandoff* self) {
    std::lock_guard<std::mutex> lk(drain_mutex());
    // Identity-checked: a NEWER LogHandoff's registration (a second instance
    // constructed before this one tore down -- tests only, production has exactly one
    // owner) must never be clobbered by an older instance's teardown().
    if (drain_slot() && drain_slot()->owner == self)
        drain_slot().reset();
}

void LogHandoff::close_drain_admission() {
    if (!drain_gate_)
        return; // construction never reached the point of assigning this -- nothing to
                // close (create_with_sinks() only builds a full LogHandoff once every
                // throwing step, including this one, has already succeeded)
    std::lock_guard<std::mutex> lk(drain_gate_->mu);
    drain_gate_->closed = true;
}

void LogHandoff::wait_for_drain_quiescence() {
    if (!drain_gate_)
        return;
    std::unique_lock<std::mutex> lk(drain_gate_->mu);
    drain_gate_->cv.wait(lk, [&] { return drain_gate_->active_readers == 0; });
}

void LogHandoff::wait_for_worker_exit() {
    if (!worker_exit_)
        return; // construction never reached the point of assigning this -- same
                // reasoning as close_drain_admission()'s null guard
    std::unique_lock<std::mutex> lk(worker_exit_->mu);
    worker_exit_->cv.wait(lk, [&] { return worker_exit_->exited; });
}

bool drain_log_bounded(std::chrono::milliseconds wait) {
    std::shared_ptr<DrainHandle> handle;
    {
        std::lock_guard<std::mutex> lk(drain_mutex());
        handle = drain_slot(); // ref-counted copy of the (weak-holding) handle itself --
                                // see the header's own paragraph for why this makes a
                                // concurrent teardown() safe rather than dangling.
    }
    if (!handle)
        return false; // nothing installed

    // Declared BEFORE any local pool/sink shared_ptr below -- see DrainLease's own
    // comment for why the destruction order is load-bearing, not stylistic.
    DrainLease lease(handle->gate);
    if (!lease.acquired())
        return false; // teardown() has already closed admission (concurrently tearing
                       // down, or already gone) -- nothing to drain

    auto pool = handle->pool.lock();
    if (!pool)
        return false; // already torn down

    const auto deadline = std::chrono::steady_clock::now() + wait;
    auto pending = [&] {
        if (pool->queue_size() != 0)
            return true;
        for (const auto& w : handle->sinks) {
            if (auto s = w.lock(); s && s->in_write())
                return true;
        }
        return false;
    };
    while (pending() && std::chrono::steady_clock::now() < deadline)
        std::this_thread::yield();
    // Release our temporary strong ref as soon as we are done reading through it. This
    // no longer needs to be "as early as possible to minimize a residual race" (that
    // residual is closed by the lease above) -- it is simply good hygiene, matching the
    // rest of this function's style.
    pool.reset();

    if (auto logger = handle->logger.lock())
        logger->flush(); // queued request; no delivery is claimed (plan 1.3/1.8)

    while (std::chrono::steady_clock::now() < deadline) {
        auto p = handle->pool.lock();
        if (!p)
            return true; // gone -- teardown()'s own blocking drain already finished it
        const bool empty = (p->queue_size() == 0);
        p.reset();
        if (empty)
            return true;
        std::this_thread::yield();
    }
    return false;
    // `lease` destructs here, after every local pool/sink shared_ptr above has already
    // gone out of scope -- decrementing active_readers and, if it reaches zero, waking
    // a concurrently-waiting teardown()'s wait_for_drain_quiescence().
}

// ---------------------------------------------------------------------------
// LogHandoff
// ---------------------------------------------------------------------------

std::size_t LogHandoff::overrun_total() const { return pool_ ? pool_->overrun_counter() : 0; }

std::size_t LogHandoff::queue_depth() const { return pool_ ? pool_->queue_size() : 0; }

bool LogHandoff::in_write() const noexcept {
    for (const auto& s : wrapped_sinks_)
        if (s->in_write())
            return true;
    return false;
}

std::chrono::seconds LogHandoff::stalled_for() const noexcept {
    using namespace std::chrono;
    seconds worst{0};
    const auto now = steady_clock::now();
    for (const auto& s : wrapped_sinks_) {
        if (!s->in_write())
            continue;
        const auto elapsed = duration_cast<seconds>(now - s->write_started_at());
        if (elapsed > worst)
            worst = elapsed;
    }
    return worst;
}

std::uint64_t LogHandoff::log_errors_total() const {
    if (!error_state_)
        return 0;
    std::lock_guard<std::mutex> lk(error_state_->mu);
    return error_state_->count;
}

std::string LogHandoff::last_log_error_for_test() const {
    if (!error_state_)
        return {};
    std::lock_guard<std::mutex> lk(error_state_->mu);
    return error_state_->last_message;
}

void LogHandoff::set_construction_fault_for_test(bool fail) noexcept {
    construction_fault_for_test_.store(fail, std::memory_order_relaxed);
}

std::expected<std::unique_ptr<LogHandoff>, std::string>
LogHandoff::create_with_sinks(std::vector<spdlog::sink_ptr> sinks, std::size_t queue_capacity) {
    if (sinks.empty())
        return std::unexpected("LogHandoff::create_with_sinks: at least one sink is required");

    if (construction_fault_for_test_.exchange(false, std::memory_order_relaxed))
        return std::unexpected(
            "LogHandoff: injected pool/logger construction failure (test)");

    try {
        std::vector<std::shared_ptr<StallObservableSink>> wrapped;
        wrapped.reserve(sinks.size());
        for (auto& s : sinks)
            wrapped.push_back(std::make_shared<StallObservableSink>(std::move(s)));

        // Worker-exit signal (see the header's WORKER-EXIT SIGNAL paragraph) -- built
        // BEFORE the pool so it can be captured into the pool's own on_thread_stop
        // callback below.
        auto worker_exit = std::make_shared<WorkerExitSignal>();

        // 4-arg constructor (q_max_items, threads_n, on_thread_start, on_thread_stop):
        // on_thread_stop fires ON THE WORKER THREAD ITSELF, after worker_loop_() has
        // genuinely returned (verified against thread_pool-inl.h's ctor -- the worker's
        // lambda is exactly `{ on_thread_start(); worker_loop_(); on_thread_stop(); }`).
        // This is the authoritative "the worker is actually done" signal
        // wait_for_worker_exit() waits on, independent of which thread's shared_ptr
        // reset happens to trigger ~thread_pool()'s destructor call.
        //
        // HARDENING NOTE (third-round adversarial review, Fable): WorkerExitSignal is a
        // ONE-SHOT latch, correct only because `1` below is hard-coded to exactly one
        // worker thread -- on_thread_stop fires once per worker, so wait_for_worker_exit()
        // would observe the FIRST exit, not "every worker has exited", if this pool ever
        // grew to N>1 threads. If a future change raises the thread count, replace the
        // one-shot bool with a countdown (or an atomic counter reaching zero) at the same
        // time -- do not carry this literal `1` and WorkerExitSignal's one-shot shape out
        // of sync with each other.
        auto pool = std::make_shared<spdlog::details::thread_pool>(
            queue_capacity, 1, [] {},
            [worker_exit] {
                {
                    std::lock_guard<std::mutex> lk(worker_exit->mu);
                    worker_exit->exited = true;
                }
                worker_exit->cv.notify_all();
            });

        std::vector<spdlog::sink_ptr> as_sink_ptrs(wrapped.begin(), wrapped.end());
        auto logger = std::make_shared<spdlog::async_logger>(
            std::string(""), as_sink_ptrs.begin(), as_sink_ptrs.end(),
            std::weak_ptr<spdlog::details::thread_pool>(pool),
            spdlog::async_overflow_policy::overrun_oldest);

        auto error_state = std::make_shared<ErrorState>();
        logger->set_error_handler([error_state](const std::string& msg) {
            // Firewalled: this handler must never itself throw back into spdlog's
            // error-handling machinery (plan 1.2). Guarded by a plain std::mutex, not
            // a lock-free/single-writer scheme -- it is reached concurrently from the
            // pool's worker thread (a sink throw) and any producer thread (a
            // formatter/allocation exception, or "pool gone"): see the header's own
            // NON-I/O ERROR HANDLER note.
            try {
                std::lock_guard<std::mutex> lk(error_state->mu);
                ++error_state->count;
                error_state->last_message.assign(msg, 0, std::min<std::size_t>(msg.size(), 256));
            } catch (...) {
            }
        });

        // Drain-reader-lease control block (BLOCKER-1 fix) -- built here, still inside
        // the "everything that can throw happens before the object exists" phase, same
        // as pool/logger/error_state above.
        auto drain_gate = std::make_shared<DrainGate>();

        // Only now, once every throwing step above has succeeded, build the actual
        // object -- its destructor unconditionally runs teardown() if not yet torn
        // down (see the header's TEARDOWN CONTRACT), so a PARTIALLY populated
        // LogHandoff must never become reachable via an exception path above this
        // line.
        auto handoff = std::unique_ptr<LogHandoff>(new LogHandoff());
        handoff->pool_ = std::move(pool);
        handoff->logger_ = std::move(logger);
        handoff->wrapped_sinks_ = std::move(wrapped);
        handoff->error_state_ = std::move(error_state);
        handoff->drain_gate_ = std::move(drain_gate);
        handoff->worker_exit_ = std::move(worker_exit);
        register_global_drain_handle(handoff.get());
        return handoff;
    } catch (const std::exception& e) {
        return std::unexpected(std::string("LogHandoff construction failed: ") + e.what());
    } catch (...) {
        return std::unexpected(std::string("LogHandoff construction failed: unknown exception"));
    }
}

std::expected<std::unique_ptr<LogHandoff>, std::string>
LogHandoff::create(const Options& options) {
    std::vector<spdlog::sink_ptr> sinks;
    bool used_fallback = false;
    std::string fallback_reason;

    if (options.log_file) {
        try {
            sinks.push_back(std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                options.log_file->string(), options.log_max_size, options.log_max_files));
            if (!options.service_mode)
                sinks.push_back(std::make_shared<spdlog::sinks::stderr_color_sink_mt>());
        } catch (const std::exception& e) {
            // 1.7 carve-out: a log-file OPEN failure is NOT a LogHandoff construction
            // failure -- fall back to console-only async logging, exactly like today's
            // main.cpp #1822 behavior (main.cpp:663-669), rather than refuse to start.
            sinks.clear();
            used_fallback = true;
            fallback_reason = e.what();
        }
    }
    if (sinks.empty()) {
        // SHOULD-FIX (#4666 PR-1 adversarial review): this construction sat outside
        // create_with_sinks()'s own try/catch below, so a bad_alloc-class throw here
        // (memory exhaustion) escaped as a raw exception instead of the documented
        // std::expected contract every other construction-failure path in this file
        // honors. Same mapping as create_with_sinks()'s own catch clauses.
        try {
            sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
        } catch (const std::exception& e) {
            return std::unexpected(std::string("LogHandoff construction failed: ") + e.what());
        } catch (...) {
            return std::unexpected("LogHandoff construction failed: unknown exception");
        }
    }

    auto result = create_with_sinks(std::move(sinks));
    if (result.has_value()) {
        (*result)->log_file_fallback_ = used_fallback;
        (*result)->log_file_fallback_reason_ = std::move(fallback_reason);
    }
    return result;
}

std::shared_ptr<spdlog::logger> LogHandoff::install() {
    spdlog::set_default_logger(logger_);
    return logger_;
}

LogHandoff::~LogHandoff() {
    if (!torn_down_.load(std::memory_order_acquire))
        teardown();
}

void LogHandoff::teardown_body() {
    // T1: a queued flush request (no delivery is claimed), then destroy the pool --
    // ~thread_pool posts a terminate message under the `block` policy and JOINS its
    // one worker. Healthy sink: drains in order, nothing lost, join returns. Blocked
    // sink: this simply does not return -- the ShutdownDeadlineGuard constructed
    // around teardown_body() (see teardown()/teardown_with_action_for_test() below)
    // is what bounds the wait, not this call itself.
    //
    // pool_.reset() here is NOT necessarily the call that actually destroys the pool
    // (WORKER-EXIT SIGNAL, header banner): an ordinary producer thread concurrently
    // inside logger_->info()/flush() can transiently hold its own strong
    // shared_ptr<thread_pool> (spdlog's async_logger::sink_it_()/flush_() do exactly
    // this), so this reset() can be a non-destructive ref-decrement. wait_for_worker_exit()
    // immediately below is what makes that harmless: it blocks until the pool's worker
    // thread has ACTUALLY exited, regardless of which thread's reset ends up triggering
    // ~thread_pool(), so a wedged sink is still caught by the watchdog armed around this
    // whole function (teardown()/teardown_with_action_for_test()).
    if (logger_)
        logger_->flush();
    pool_.reset();
    wait_for_worker_exit();

    // T2: every image's registry drops its reference to our logger by overwriting the
    // "" default-logger slot with a NULL-sink logger, rather than
    // spdlog::shutdown()/drop_all() (which null default_logger_ itself -- a straggler
    // spdlog::info() after that would dereference null). Runs UNCONDITIONALLY, even if
    // install() was never called on this instance (see the header's TEARDOWN CONTRACT
    // and U4/U10 in test_log_handoff.cpp).
    auto null_logger = std::make_shared<spdlog::logger>(
        std::string(""), std::make_shared<spdlog::sinks::null_sink_mt>());
    spdlog::set_default_logger(null_logger);

    // T3: this object's own last reference to the async logger's sinks -- runs under
    // the same watchdog as T1; final sink destruction (e.g. a rotating file sink's
    // fclose()) is exactly the uncovered I/O path the plan's adjudication table calls
    // out (3.4).
    logger_.reset();
    wrapped_sinks_.clear();
}

void LogHandoff::teardown(std::chrono::milliseconds grace) noexcept {
    if (torn_down_.exchange(true, std::memory_order_acq_rel))
        return; // idempotent -- second call (or the destructor after an explicit call)
                // is a no-op

    // T0: deregister from the global slot AND stop admitting new drain_log_bounded()
    // leases, both BEFORE any teardown work (see the header's TEARDOWN CONTRACT and
    // the DRAIN-READER LEASE paragraph -- BLOCKER-1 fix, #4666 PR-1 adversarial
    // review).
    clear_global_drain_handle(this);
    close_drain_admission();

    try {
        auto action = [] { hard_exit(kLogTeardownExitCode); };
        ShutdownDeadlineGuard<decltype(action)> guard{grace, action};
        // Still INSIDE the watchdog's scope, not after it: if a drain_log_bounded()
        // lease admitted just before close_drain_admission() above never releases (a
        // genuinely wedged sink), this wait is what the watchdog is covering -- not an
        // unwatched drain thread discovered later. This keeps drain_log_bounded()'s OWN
        // `wait` bound honest (it can no longer become the accidental last owner of the
        // pool right as its spin loop ends) -- it does NOT by itself guarantee
        // teardown_body()'s pool_.reset() observes the last reference in general (an
        // ordinary producer thread can still hold one transiently); wait_for_worker_exit()
        // inside teardown_body(), right after pool_.reset(), is what closes that wider
        // case (see the header's WORKER-EXIT SIGNAL paragraph).
        wait_for_drain_quiescence();
        teardown_body();
    } catch (...) {
        // teardown_body() must not throw in ordinary operation, but if something deep
        // inside spdlog's own error-handler rethrow path does, fail closed the same
        // way every other primitive in this shutdown-path family does -- never let an
        // exception escape a call the destructor depends on being noexcept (that would
        // reach std::terminate() instead of hard_exit(), which on Windows runs CRT
        // abort handling -- exactly the hazard hard_exit.hpp's own header warns
        // about).
        hard_exit(kLogTeardownExitCode);
    }
}

void LogHandoff::teardown_with_action_for_test(std::chrono::milliseconds grace,
                                               std::function<void()> action) {
    if (torn_down_.exchange(true, std::memory_order_acq_rel))
        return;

    clear_global_drain_handle(this);
    close_drain_admission();

    ShutdownDeadlineGuard<std::function<void()>> guard{grace, std::move(action)};
    wait_for_drain_quiescence(); // see teardown()'s own comment on this call
    teardown_body(); // let any exception propagate normally -- this is a TEST-ONLY
                      // entry point; unlike teardown() (noexcept, fail-closed to
                      // hard_exit) an exception here should fail the calling Catch2
                      // TEST_CASE, not the whole test binary (see the header's own
                      // comment on this method).
}

} // namespace yuzu::agent
