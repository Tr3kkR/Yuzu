#pragma once

/**
 * guardian_io_executor.hpp - a bounded, cancellable, single-flight I/O executor
 * for the Guardian spark state reader (ADR-0021 Stage 2 rung 5, F3).
 *
 * WHY: the IStateReader contract (guardian_spark_runtime.hpp) requires every read
 * be bounded/cancellable - a convergence-lane join and the consumer detach both
 * wait on an in-flight read, so a platform call that can block indefinitely (a
 * wedged SCM, a stalled sd-bus broker, a FUSE/network filesystem hang) must carry
 * a deadline and degrade to Unknown rather than hang agent shutdown. A thread
 * wedged in a D-state syscall CANNOT be cancelled or joined; we do NOT force-cancel
 * the kernel call. Instead we DECOUPLE the caller from it: run the blocking read on
 * a detached worker, wait with an absolute deadline + a stop signal, and degrade to
 * a typed failure the reader maps to Unknown. Spawn-per-read (not a pool): the
 * workload is cold (convergence 60s/5-15min lanes, events debounced) and a pool
 * only adds a stale-job queue plus the same wedged-worker problem.
 *
 * INVARIANTS (each is a Sol BLOCKING/SHOULD fix, code-verified):
 *  - Keyed single-flight: an op key = (IoClass, spark_key) is ACTIVE until the
 *    WORKER EXITS (not until the submitter times out). A run for an already-active
 *    key returns AlreadyRunning WITHOUT spawning. The key is the canonical
 *    spark_key (length-prefixed, injective) and EXCLUDES the file hash-cap and the
 *    registry value plan - those can change while the same physical read is stuck,
 *    and letting that change bypass single-flight recreates the wedged-slot bug.
 *  - Per-type bulkheads: per-class inflight quotas (File/Registry/Service) PLUS a
 *    total process bound, so a dead mount saturating the file lane never starves a
 *    healthy service reconcile. Combined with single-flight so one key cannot eat
 *    its whole type budget.
 *  - RAII admission ticket: admission is a transaction (the one throwing mutation,
 *    set::insert, runs before the nothrow counter increments; the ticket is armed
 *    last). A shared_ptr<TicketCore> owns the slot + active key. The KEY is freed by
 *    the worker at publish time (release_key_locked(), so a fast sequential re-read
 *    of the same key is not spuriously single-flighted); the INFLIGHT COUNTERS
 *    (what active_worker_count() reports) are freed only in the destructor, when the
 *    LAST holder dies - the worker's own captured copy, destroyed by the trampoline
 *    after the worker lambda has fully returned, i.e. at true OS-thread-exit time.
 *    The caller drops its copy after a successful launch, so a timed-out submitter
 *    does NOT release either - the worker does, on its own schedule.
 *  - No std::terminate path: the worker is launched DETACHED-at-creation
 *    (pthread_create PTHREAD_CREATE_DETACHED / _beginthreadex + CloseHandle), so
 *    there is no joinable std::thread whose destructor could terminate and no
 *    detach() that could throw. The worker trampoline is fully exception-contained
 *    (only the user fn() may throw, and it is caught); the result is heap-boxed and
 *    published into the cell by a nothrow unique_ptr move, so publication cannot
 *    throw for any result type (including MSVC's std::unordered_map, whose move is
 *    not noexcept).
 *  - Typed outcome: std::expected<T, IoFailure>; the reader maps each IoFailure to
 *    a precise bounded Unknown string (it lands in guard.unhealthy detail).
 *  - Absolute deadline captured at run() ENTRY (per-class deadline chosen by the
 *    reader), so allocation + launch time counts against the caller's budget.
 *
 * ORPHAN PROCESS-EXIT CONTRACT (rung-5 scope: expose + document; ENFORCEMENT
 * LANDED rung 7, see below):
 *  A shared_ptr keeps State and the result cell alive for a wedged detached worker,
 *  so there is no use-after-free. It does NOT make it safe for that worker to run
 *  libc / OpenSSL / libsystemd / Win32-RPC code THROUGH normal C++ static/DSO
 *  teardown. The process MUST NOT perform normal C++ teardown while
 *  active_worker_count() > 0. Rung 5 exposed that count (total + per class) here
 *  and re-exposed it through GuardianStateReader; rung 7's hard_exit.hpp is the
 *  enforcement: main.cpp/service_win.cpp construct an OrphanExitGuard before
 *  Agent::run(), sample guardian_active_io_workers() after it returns, and
 *  hard_exit() (TerminateProcess/_exit, skipping normal teardown entirely) if
 *  still nonzero after a bounded grace. Verified on POSIX (full test suite +
 *  TSan + real boot/SIGTERM smoke tests); the Windows SCM path
 *  (service_win.cpp) needs a DGRHP build+run before it's considered verified
 *  the same way. Currently inert in production either way - GuardianEngine's
 *  spark path (the only source of a nonzero active_worker_count()) has zero
 *  production wire_spark_engine() call sites yet.
 */

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <type_traits>
#include <utility>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <process.h> // _beginthreadex
#else
#include <pthread.h>
#endif

namespace yuzu::agent {

/// Which reader lane a read belongs to. Values 0/1/2 index the per-class arrays.
enum class IoClass { File = 0, Registry = 1, Service = 2 };

inline constexpr std::size_t kIoClassCount = 3;

[[nodiscard]] constexpr std::size_t io_class_index(IoClass c) noexcept {
    return static_cast<std::size_t>(c);
}

[[nodiscard]] constexpr const char* io_class_token(IoClass c) noexcept {
    switch (c) {
    case IoClass::File:     return "file";
    case IoClass::Registry: return "registry";
    case IoClass::Service:  return "service";
    }
    return "unknown";
}

/// Why a bounded read did not return a value. Six materially different operational
/// meanings (they end up in guard.unhealthy detail, so the reader maps each to a
/// precise string rather than a single "timed out or cancelled").
enum class IoFailure {
    Timeout,           ///< the per-class deadline elapsed before the worker published
    Stopped,           ///< the executor is stopping (shutdown); the submitter was woken / rejected
    CapacityExhausted, ///< the per-class or total inflight quota was full
    AlreadyRunning,    ///< a read for this exact (class, key) is already in flight (single-flight)
    LaunchFailed,      ///< the OS refused to create the worker thread (or an allocation failed)
    WorkerThrew,       ///< the read body threw (should not happen; contained, never terminates)
};

template <class T>
using IoResult = std::expected<T, IoFailure>;

namespace io_detail {

template <class Fn>
struct DetachedPayload {
    Fn fn;
};

#ifdef _WIN32
template <class Fn>
unsigned __stdcall detached_trampoline(void* arg) noexcept {
    std::unique_ptr<DetachedPayload<Fn>> p{static_cast<DetachedPayload<Fn>*>(arg)};
    p->fn();
    return 0;
}
#else
template <class Fn>
void* detached_trampoline(void* arg) noexcept {
    std::unique_ptr<DetachedPayload<Fn>> p{static_cast<DetachedPayload<Fn>*>(arg)};
    p->fn();
    return nullptr;
}
#endif

/// Launch `fn` on a thread that is DETACHED at creation. There is no joinable
/// std::thread whose destructor could std::terminate and no detach() that could
/// throw. Returns false ONLY if the OS refused to create the thread (the caller
/// maps that to IoFailure::LaunchFailed and rolls admission back). May throw
/// std::bad_alloc from the single payload allocation, which the caller's
/// admission transaction also rolls back. On success the worker owns the payload
/// and deletes it when it returns.
template <class Fn>
[[nodiscard]] bool spawn_detached(Fn&& fn) {
    using P = DetachedPayload<std::decay_t<Fn>>;
    std::unique_ptr<P> payload{new P{std::forward<Fn>(fn)}};
#ifdef _WIN32
    const std::uintptr_t h = _beginthreadex(nullptr, 0, &detached_trampoline<std::decay_t<Fn>>,
                                            payload.get(), 0, nullptr);
    if (h == 0)
        return false;
    payload.release();
    ::CloseHandle(reinterpret_cast<HANDLE>(h));
    return true;
#else
    pthread_attr_t attr;
    if (::pthread_attr_init(&attr) != 0)
        return false;
    ::pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_t tid;
    const int rc =
        ::pthread_create(&tid, &attr, &detached_trampoline<std::decay_t<Fn>>, payload.get());
    ::pthread_attr_destroy(&attr);
    if (rc != 0)
        return false;
    payload.release();
    return true;
#endif
}

} // namespace io_detail

class GuardianIoExecutor {
public:
    /// Process-wide ceiling on concurrent bounded-I/O workers, and the compile-time
    /// tripwire for the per-class quotas. The process bound is DERIVED as the sum of
    /// the class quotas (see the ctor), which makes the per-class bulkheads EXACT: a
    /// class cap always binds before the process bound can, so no class is ever starved
    /// by another saturating a different lane (ADR-0021 rung 9a, R3 - this replaces the
    /// prior independent `total_quota{8} < sum(10)`, which let File+Registry starve
    /// Service to 1 of its 3 slots with nothing wedged). A new IoClass or a raised
    /// default that pushes the sum past this ceiling fails the static_assert below:
    /// raise the ceiling deliberately, or shrink a class - never silently oversubscribe.
    static constexpr int kMaxProcessIoWorkers = 10;

    struct Config {
        int file_quota{4};
        int registry_quota{3};
        int service_quota{3};
    };
    // (The tripwire static_assert lives just after this class - a Config{} default
    // member initializer cannot be read inside the still-incomplete enclosing class.)

    /// Cumulative, rate-safe per-class counters (no per-rejection / per-retry log).
    struct Counters {
        std::uint64_t timed_out{0};
        std::uint64_t rejected_capacity{0};
        std::uint64_t rejected_key{0};
        std::uint64_t launch_failures{0};
        std::uint64_t worker_exceptions{0};
    };

    /// A by-value snapshot (never a reference into State after the lock releases).
    struct Stats {
        std::size_t active_total{0};
        std::array<std::size_t, kIoClassCount> active_by_class{};
        std::array<std::size_t, kIoClassCount> active_at_shutdown{};
        std::array<Counters, kIoClassCount> counters{};
        bool stopping{false};
    };

    GuardianIoExecutor() : GuardianIoExecutor(Config{}) {}
    explicit GuardianIoExecutor(Config cfg) : state_(std::make_shared<State>()) {
        state_->class_quota[io_class_index(IoClass::File)] = cfg.file_quota;
        state_->class_quota[io_class_index(IoClass::Registry)] = cfg.registry_quota;
        state_->class_quota[io_class_index(IoClass::Service)] = cfg.service_quota;
        // Derive the process bound from the class quotas so the bulkheads are EXACT:
        // total == sum(class quotas) means the process check can never bind before a
        // class cap does, so it never starves a lane. Kept as a live admission guard
        // (belt-and-braces, provably inert for a well-formed Config) rather than removed.
        state_->total_quota = cfg.file_quota + cfg.registry_quota + cfg.service_quota;
    }
    GuardianIoExecutor(const GuardianIoExecutor&) = delete;
    GuardianIoExecutor& operator=(const GuardianIoExecutor&) = delete;
    // Move is implicitly deleted (user-declared copy + atomic member); the reader
    // owns it by value and is never moved.

    /// Run `fn()` (the blocking read body) on a detached worker, bounded by
    /// `deadline` (absolute, captured at entry). `key` is the canonical spark_key
    /// of the target. Returns the worker's result on success, or a typed IoFailure.
    /// Forwarding callable (no std::function alloc); the worker captures a decayed
    /// OWNING copy of `fn`. No constraint on `T`'s own move-throwing-ness - the
    /// worker heap-boxes its result and publishes by a nothrow unique_ptr move
    /// (see below).
    template <class F>
    auto run(IoClass cls, std::string key, std::chrono::milliseconds deadline, F&& fn) {
        using T = std::decay_t<std::invoke_result_t<F&>>;
        // The worker heap-boxes its result (unique_ptr<IoResult<T>>) and publishes
        // it into the cell by a pointer move, which is nothrow for ANY result type -
        // including one whose own move is potentially-throwing (MSVC's
        // std::unordered_map move ctor is NOT noexcept, unlike libstdc++/libc++), so
        // no nothrow-move constraint on T is needed here. Result construction (the
        // only potentially-throwing step) happens on the worker BEFORE the publish
        // lock and is fully contained.
        const auto abs_deadline = std::chrono::steady_clock::now() + deadline;
        const std::size_t ci = io_class_index(cls);

        Ticket ticket;                          // function scope: armed under the lock; its RAII
                                                // destructor rolls admission back on any unwind
        std::shared_ptr<ResultCell<T>> cell;
        try {
            cell = std::make_shared<ResultCell<T>>();
            ticket = std::make_shared<TicketCore>(state_); // unarmed until admitted
            {
                std::unique_lock<std::mutex> lk{state_->mu};
                if (state_->stopping)
                    return IoResult<T>{std::unexpect, IoFailure::Stopped};
                if (state_->active_keys.contains({static_cast<int>(ci), key})) {
                    ++state_->counters[ci].rejected_key;
                    return IoResult<T>{std::unexpect, IoFailure::AlreadyRunning};
                }
                if (state_->total_inflight >= state_->total_quota ||
                    state_->class_inflight[ci] >= state_->class_quota[ci]) {
                    ++state_->counters[ci].rejected_capacity;
                    return IoResult<T>{std::unexpect, IoFailure::CapacityExhausted};
                }
                // Admission transaction: set::insert (the ONLY throwing step, strong
                // guarantee) runs BEFORE the nothrow counter bumps, so a bad_alloc here
                // leaves State unmutated. Arm the ticket last (all nothrow).
                auto it = state_->active_keys.insert({static_cast<int>(ci), std::move(key)}).first;
                ++state_->total_inflight;
                ++state_->class_inflight[ci];
                ticket->arm(ci, it);
            }

            auto st = state_;
            auto worker = [st, cell, ticket, ci,
                           fn = std::decay_t<F>(std::forward<F>(fn))]() mutable noexcept {
                // Construct the result on the heap OUTSIDE the publish lock; this is
                // the only potentially-throwing step (fn() itself, or the boxing
                // allocation) and it is fully contained. A null box means even the
                // WorkerThrew fallback could not allocate -> the submitter maps it to
                // WorkerThrew.
                std::unique_ptr<IoResult<T>> boxed;
                bool threw = false;
                try {
                    boxed = std::make_unique<IoResult<T>>(fn());
                } catch (...) {
                    threw = true;
                    try {
                        boxed = std::make_unique<IoResult<T>>(std::unexpect, IoFailure::WorkerThrew);
                    } catch (...) {
                        boxed.reset();
                    }
                }
                {
                    std::lock_guard<std::mutex> lk{st->mu};
                    if (threw)
                        ++st->counters[ci].worker_exceptions;
                    cell->result = std::move(boxed); // nothrow: unique_ptr pointer move
                    cell->done = true;
                    ticket->release_key_locked(); // free the single-flight key now;
                                                   // the inflight counters stay held
                                                   // until this ticket's destructor
                                                   // runs (worker's own copy, at true
                                                   // OS-thread-exit time)
                }
                st->cv.notify_all(); // after releasing the lock
                // `ticket` copy destroyed at worker scope end -> releases the counters
            };

            bool launched = false;
            if (!fail_launch_for_test_.load(std::memory_order_relaxed))
                launched = io_detail::spawn_detached(std::move(worker));
            if (!launched) {
                std::lock_guard<std::mutex> lk{state_->mu};
                ++state_->counters[ci].launch_failures;
                return IoResult<T>{std::unexpect, IoFailure::LaunchFailed}; // ticket rolls back
            }
        } catch (...) {
            // bad_alloc from cell / ticket / worker allocation, or from set::insert. An
            // armed ticket's function-scope destructor rolls admission back on return.
            try {
                std::lock_guard<std::mutex> lk{state_->mu};
                ++state_->counters[ci].launch_failures;
            } catch (...) {
            }
            return IoResult<T>{std::unexpect, IoFailure::LaunchFailed};
        }

        ticket.reset(); // success: drop the caller copy; the worker now owns the reservation

        std::unique_lock<std::mutex> lk{state_->mu};
        state_->cv.wait_until(lk, abs_deadline,
                              [&] { return cell->done || state_->stopping; });
        if (cell->done) {
            if (cell->result)
                return std::move(*cell->result); // real result wins over a concurrent stop
            return IoResult<T>{std::unexpect, IoFailure::WorkerThrew}; // null box: alloc-starved worker
        }
        if (state_->stopping)
            return IoResult<T>{std::unexpect, IoFailure::Stopped};
        ++state_->counters[ci].timed_out;
        return IoResult<T>{std::unexpect, IoFailure::Timeout}; // the late worker write is discarded
    }

    /// Wake every waiting submitter and reject new submissions. Idempotent,
    /// nonblocking; does NOT cancel the detached OS calls (they run to completion
    /// or their own per-call timeout). Snapshots the per-class inflight count at
    /// the first stop for telemetry.
    void stop() {
        {
            std::lock_guard<std::mutex> lk{state_->mu};
            if (!state_->stopping) {
                state_->stopping = true;
                for (std::size_t i = 0; i < kIoClassCount; ++i)
                    state_->active_at_shutdown[i] =
                        static_cast<std::size_t>(state_->class_inflight[i] > 0
                                                     ? state_->class_inflight[i]
                                                     : 0);
            }
        }
        state_->cv.notify_all();
    }

    [[nodiscard]] std::size_t active_worker_count() const {
        std::lock_guard<std::mutex> lk{state_->mu};
        return static_cast<std::size_t>(state_->total_inflight);
    }
    [[nodiscard]] std::size_t active_worker_count(IoClass c) const {
        std::lock_guard<std::mutex> lk{state_->mu};
        return static_cast<std::size_t>(state_->class_inflight[io_class_index(c)]);
    }
    [[nodiscard]] bool stopping() const {
        std::lock_guard<std::mutex> lk{state_->mu};
        return state_->stopping;
    }
    [[nodiscard]] Stats stats() const {
        std::lock_guard<std::mutex> lk{state_->mu};
        Stats s;
        s.active_total = static_cast<std::size_t>(state_->total_inflight);
        for (std::size_t i = 0; i < kIoClassCount; ++i)
            s.active_by_class[i] = static_cast<std::size_t>(state_->class_inflight[i]);
        s.active_at_shutdown = state_->active_at_shutdown;
        s.counters = state_->counters;
        s.stopping = state_->stopping;
        return s;
    }

    /// Test seam: force the next launch to fail, exercising the LaunchFailed
    /// rollback path without depending on real thread-resource exhaustion.
    void set_fail_launch_for_test(bool v) { fail_launch_for_test_.store(v); }

private:
    /// Heap state shared (via shared_ptr) by the executor AND every worker + ticket,
    /// so a wedged detached worker keeps it alive past the executor's destruction.
    struct State {
        mutable std::mutex mu;
        std::condition_variable cv;
        bool stopping{false};
        int total_inflight{0};                              // guarded by mu
        std::array<int, kIoClassCount> class_inflight{};    // guarded by mu
        std::set<std::pair<int, std::string>> active_keys;  // (classIdx, spark_key); guarded by mu
        std::array<std::size_t, kIoClassCount> active_at_shutdown{};
        std::array<Counters, kIoClassCount> counters{};
        std::array<int, kIoClassCount> class_quota{};       // immutable after ctor
        int total_quota{0};                                 // immutable after ctor
    };

    /// RAII admission slot. Two DISTINCT release moments, deliberately not merged:
    ///   - release_key_locked() frees only the single-flight KEY, called by the
    ///     worker in its publish critical section, so a fast sequential re-read of
    ///     the same key is not spuriously single-flighted the instant the result is
    ///     visible to a waiting submitter.
    ///   - the COUNTERS (total_inflight / class_inflight - what active_worker_count()
    ///     reports) are freed ONLY in the destructor, i.e. when the LAST shared
    ///     holder dies. The worker's own captured copy is that last holder, and it
    ///     is destroyed by the trampoline AFTER the worker lambda body has fully
    ///     returned (notify_all included) - i.e. at the latest point observable
    ///     before the OS thread itself exits. This is load-bearing for the
    ///     orphan-exit contract: active_worker_count() must not read 0 while any
    ///     worker code can still execute in the process image, even the trivial
    ///     capture-destruction tail after a result has published. Splitting the two
    ///     lets the key-reuse fix and the orphan-count accuracy both hold - merging
    ///     them (as an earlier revision did) made active_worker_count() reach 0
    ///     while the worker's OS thread was still unwinding.
    /// `armed` is false until admission succeeds, so a ticket destroyed before /
    /// without admission is a no-op. A ticket destroyed WITHOUT release_key_locked()
    /// having run first (the rollback / never-launched / never-published paths)
    /// still frees the key here - `key_released` guards against a double-erase.
    struct TicketCore {
        explicit TicketCore(std::shared_ptr<State> s) noexcept : state(std::move(s)) {}
        ~TicketCore() {
            if (!armed)
                return;
            {
                std::lock_guard<std::mutex> lk{state->mu};
                if (state->total_inflight > 0)
                    --state->total_inflight;
                if (state->class_inflight[ci] > 0)
                    --state->class_inflight[ci];
                if (!key_released)
                    state->active_keys.erase(key_it); // nothrow: erase by valid iterator
            }
            state->cv.notify_all(); // after releasing the lock
        }
        void arm(std::size_t c, std::set<std::pair<int, std::string>>::iterator it) noexcept {
            ci = c;
            key_it = it;
            armed = true;
        }
        // Free ONLY the single-flight key; the CALLER must hold State::mu. Does NOT
        // touch the inflight counters (see the class comment above) - a wedged
        // worker never reaches this call (it never publishes), preserving the
        // dead-target single-flight guard.
        void release_key_locked() noexcept {
            if (!armed || key_released)
                return;
            state->active_keys.erase(key_it);
            key_released = true;
        }
        TicketCore(const TicketCore&) = delete;
        TicketCore& operator=(const TicketCore&) = delete;

        std::shared_ptr<State> state;
        std::size_t ci{0};
        std::set<std::pair<int, std::string>>::iterator key_it{};
        bool armed{false};
        bool key_released{false};
    };
    using Ticket = std::shared_ptr<TicketCore>;

    /// Per-run result slot. `done` + `result` are written once by the worker under
    /// State::mu; the submitter reads them under the same lock. The result is held
    /// by unique_ptr so publication is an unconditional nothrow pointer move (a
    /// result type whose own move is potentially-throwing, e.g. MSVC's
    /// std::unordered_map, would otherwise terminate the noexcept worker). A null
    /// pointer with done == true means the worker could not allocate its result box.
    template <class T>
    struct ResultCell {
        bool done{false};
        std::unique_ptr<IoResult<T>> result;
    };

    std::shared_ptr<State> state_;
    std::atomic<bool> fail_launch_for_test_{false};
};

// Tripwire (ADR-0021 rung 9a R3): the default per-class quotas must not oversubscribe
// the process worker ceiling. A new IoClass or a raised default that pushes the sum
// past kMaxProcessIoWorkers fails here - raise the ceiling deliberately or shrink a
// class, never silently oversubscribe. At namespace scope so Config{}'s default member
// initializers are readable (they are not, inside the still-incomplete class).
static_assert(GuardianIoExecutor::Config{}.file_quota
                      + GuardianIoExecutor::Config{}.registry_quota
                      + GuardianIoExecutor::Config{}.service_quota
                  <= GuardianIoExecutor::kMaxProcessIoWorkers,
              "per-class I/O quotas oversubscribe kMaxProcessIoWorkers");

} // namespace yuzu::agent
