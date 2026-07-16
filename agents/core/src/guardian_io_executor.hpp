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
 *    last). A shared_ptr<TicketCore> owns the slot + active key and releases both
 *    exactly once, in a nothrow destructor (erase by stored iterator), when the
 *    LAST holder dies. The caller drops its copy after a successful launch, so a
 *    timed-out submitter does NOT release the slot - the worker's copy does, when
 *    it exits.
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
 * ORPHAN PROCESS-EXIT CONTRACT (rung-5 scope: expose + document; enforce later):
 *  A shared_ptr keeps State and the result cell alive for a wedged detached worker,
 *  so there is no use-after-free. It does NOT make it safe for that worker to run
 *  libc / OpenSSL / libsystemd / Win32-RPC code THROUGH normal C++ static/DSO
 *  teardown. Today main() returns EXIT_SUCCESS normally and the autonomous
 *  hard-exit deadline is deferred to a separate PR, so "process exit reaps it" is
 *  NOT a lifetime proof. The process MUST NOT perform normal C++ teardown while
 *  active_worker_count() > 0. Rung 5 exposes that count (total + per class) here
 *  and re-exposes it through GuardianStateReader; the ENFORCEMENT (main taking
 *  _exit / TerminateProcess after a bounded grace when orphans remain, or folding
 *  outstanding Guardian I/O workers into the deferred autonomous hard-exit
 *  deadline) is a tracked rung-7 / separate-PR dependency. F3 is not fully "safe"
 *  until that lands.
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
    struct Config {
        int file_quota{4};
        int registry_quota{3};
        int service_quota{3};
        int total_quota{8}; ///< process bound; < sum(class quotas) so it actually binds
    };

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
        state_->total_quota = cfg.total_quota;
    }
    GuardianIoExecutor(const GuardianIoExecutor&) = delete;
    GuardianIoExecutor& operator=(const GuardianIoExecutor&) = delete;
    // Move is implicitly deleted (user-declared copy + atomic member); the reader
    // owns it by value and is never moved.

    /// Run `fn()` (the blocking read body) on a detached worker, bounded by
    /// `deadline` (absolute, captured at entry). `key` is the canonical spark_key
    /// of the target. Returns the worker's result on success, or a typed IoFailure.
    /// Forwarding callable (no std::function alloc); the worker captures a decayed
    /// OWNING copy of `fn`. `T` must be nothrow-move-constructible so publication
    /// into the result cell cannot throw.
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
                    ticket->release_locked();        // free slot+key atomically with the result
                }
                st->cv.notify_all(); // after releasing the lock
                // `ticket` copy destroyed at worker scope end -> releases slot + key
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

    /// RAII admission slot: releases the inflight counters + the active key exactly
    /// once, in a nothrow destructor (erase by the stored iterator - no allocation,
    /// no comparator call), when the last shared holder dies. `armed` is false until
    /// admission succeeds, so a ticket destroyed before/without admission is a no-op.
    struct TicketCore {
        explicit TicketCore(std::shared_ptr<State> s) noexcept : state(std::move(s)) {}
        ~TicketCore() {
            if (!armed)
                return;
            {
                std::lock_guard<std::mutex> lk{state->mu};
                release_locked();
            }
            state->cv.notify_all(); // after releasing the lock
        }
        void arm(std::size_t c, std::set<std::pair<int, std::string>>::iterator it) noexcept {
            ci = c;
            key_it = it;
            armed = true;
        }
        // Free the slot + active key exactly once; the CALLER must hold State::mu.
        // The worker calls this in its publish critical section so the key is free
        // the instant the result is visible to a waiting submitter - a fast
        // sequential re-read of the same key is not spuriously single-flighted. A
        // wedged worker never publishes, so it never releases here, preserving the
        // dead-target guard; the destructor is the fallback for the never-published
        // and launch-failure paths.
        void release_locked() noexcept {
            if (!armed)
                return;
            if (state->total_inflight > 0)
                --state->total_inflight;
            if (state->class_inflight[ci] > 0)
                --state->class_inflight[ci];
            state->active_keys.erase(key_it); // nothrow: erase by valid iterator
            armed = false;
        }
        TicketCore(const TicketCore&) = delete;
        TicketCore& operator=(const TicketCore&) = delete;

        std::shared_ptr<State> state;
        std::size_t ci{0};
        std::set<std::pair<int, std::string>>::iterator key_it{};
        bool armed{false};
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

} // namespace yuzu::agent
