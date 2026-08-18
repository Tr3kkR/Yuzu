/**
 * test_store_worker_pool.cpp -- Unit tests for StoreWorkerPool (#3261
 * governance hardening).
 *
 * Deliberately has NO dependency on WebhookStore/OffloadTargetStore or
 * httplib -- those exercise the pool end-to-end via real HTTP delivery
 * (test_webhook_store.cpp / test_offload_target_store.cpp / the
 * [issue3261] cases in test_agent_service_impl.cpp), but a real HTTP call
 * triggers glibc's getaddrinfo_a async-resolver helper thread, which
 * crashes deterministically under this repo's TSan build for reasons
 * unrelated to this pool (issue #2504 -- TSan has no thread state for a
 * thread glibc spawned outside TSan's own pthread_create interceptor).
 * This file only ever submits plain lambdas with no I/O, so it gives clean
 * TSan coverage of the pool's actual concurrency logic (submit/quiesce/
 * worker_loop/destructor) without tripping that unrelated crash.
 */

#include "store_worker_pool.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <stdexcept>
#include <thread>
#include <vector>

using yuzu::server::StoreWorkerPool;

namespace {

/// RAII release for an indefinitely-blocking task's exit flag. Several
/// tests below submit a task that spins on `flag` until it's set, so the
/// pool's own destructor (which joins unconditionally) can complete. A
/// bare `flag.store(true)` at the end of the test body is NOT enough: if
/// any REQUIRE/CHECK between submitting that task and the release line
/// fails, Catch2 throws to unwind the test case, `pool`'s destructor runs
/// during that unwind, and its join() blocks FOREVER waiting for a worker
/// that will never see the release. This guard's destructor runs on every
/// exit path, including exception unwind, exactly like the SemaGuard
/// pattern in offload_target_store.cpp.
struct ReleaseGuard {
    std::atomic<bool>& flag;
    explicit ReleaseGuard(std::atomic<bool>& f) : flag(f) {}
    ~ReleaseGuard() { flag.store(true); }
    ReleaseGuard(const ReleaseGuard&) = delete;
    ReleaseGuard& operator=(const ReleaseGuard&) = delete;
};

} // namespace

// ── Basic dispatch ───────────────────────────────────────────────────────

TEST_CASE("StoreWorkerPool: submitted tasks run", "[store_worker_pool]") {
    StoreWorkerPool pool(/*num_threads=*/2, /*max_queue=*/16);
    std::atomic<int> count{0};
    for (int i = 0; i < 10; ++i) {
        REQUIRE(pool.submit([&count] { ++count; }));
    }
    REQUIRE(pool.quiesce(std::chrono::seconds(5)));
    CHECK(count.load() == 10);
}

// ── quiesce() drains before returning ───────────────────────────────────

TEST_CASE("StoreWorkerPool: quiesce blocks until slow in-flight tasks finish",
          "[store_worker_pool]") {
    StoreWorkerPool pool(/*num_threads=*/2, /*max_queue=*/16);
    std::atomic<bool> task_finished{false};
    REQUIRE(pool.submit([&task_finished] {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        task_finished.store(true);
    }));
    // quiesce() must not return true until the sleeping task above has
    // actually completed -- this is the core guarantee #3261's fix
    // depends on: a store built on this pool is safe to destroy the
    // instant quiesce() returns true.
    REQUIRE(pool.quiesce(std::chrono::seconds(5)));
    CHECK(task_finished.load());
}

TEST_CASE("StoreWorkerPool: quiesce times out on a task that outlives the bound",
          "[store_worker_pool]") {
    StoreWorkerPool pool(/*num_threads=*/1, /*max_queue=*/16);
    std::atomic<bool> released{false};
    ReleaseGuard guard(released); // always fires, even if a CHECK below fails
    REQUIRE(pool.submit([&released] {
        while (!released.load())
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }));
    // Bound is deliberately shorter than the task can possibly finish.
    CHECK_FALSE(pool.quiesce(std::chrono::milliseconds(100)));
}

// ── Backpressure ─────────────────────────────────────────────────────────

TEST_CASE("StoreWorkerPool: submit fails once the bounded queue is full",
          "[store_worker_pool]") {
    StoreWorkerPool pool(/*num_threads=*/1, /*max_queue=*/2);
    std::atomic<bool> release_first{false};
    ReleaseGuard guard(release_first); // always fires, even if a REQUIRE below fails
    std::atomic<bool> first_started{false};
    // Occupy the single worker so nothing drains the queue yet.
    REQUIRE(pool.submit([&] {
        first_started.store(true);
        while (!release_first.load())
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }));
    // Wait for the worker to actually DEQUEUE this task before submitting
    // more -- submit()'s bound checks tasks_.size(), which only reflects
    // still-QUEUED work. Without this barrier, submitting B/C races the
    // worker's own dequeue of A: if A is still sitting in the queue when B
    // is submitted, tasks_.size() reads 1 too high and B gets rejected
    // instead of C, making this test flaky rather than deterministic.
    while (!first_started.load())
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    // max_queue=2: two more tasks fit in the queue behind the running one.
    REQUIRE(pool.submit([] {}));
    REQUIRE(pool.submit([] {}));
    // A third queued task exceeds the bound -- this is the
    // unbounded-thread-creation fix (Gate 4 unhappy-path UP-2): a caller
    // sees `false` and must log+drop, never fall back to spawning a raw
    // thread.
    CHECK_FALSE(pool.submit([] {}));
}

TEST_CASE("StoreWorkerPool: submit fails after quiesce() has been called",
          "[store_worker_pool]") {
    StoreWorkerPool pool(/*num_threads=*/2, /*max_queue=*/16);
    REQUIRE(pool.quiesce(std::chrono::seconds(5))); // nothing in flight -> instant
    CHECK_FALSE(pool.submit([] {}));
}

// ── Concurrent submitters ────────────────────────────────────────────────

TEST_CASE("StoreWorkerPool: concurrent submitters do not race or drop accepted tasks",
          "[store_worker_pool]") {
    StoreWorkerPool pool(/*num_threads=*/4, /*max_queue=*/1000);
    std::atomic<int> count{0};
    std::atomic<int> accepted{0};
    std::vector<std::thread> submitters;
    for (int t = 0; t < 8; ++t) {
        submitters.emplace_back([&] {
            for (int i = 0; i < 50; ++i) {
                if (pool.submit([&count] { ++count; }))
                    ++accepted;
            }
        });
    }
    for (auto& t : submitters)
        t.join();
    REQUIRE(pool.quiesce(std::chrono::seconds(5)));
    // Every task the pool ACCEPTED must have actually run -- no accepted
    // task is silently dropped, even under concurrent submission.
    CHECK(count.load() == accepted.load());
}

// ── Exception firewall ───────────────────────────────────────────────────

TEST_CASE("StoreWorkerPool: a task that throws does not take down the worker",
          "[store_worker_pool]") {
    StoreWorkerPool pool(/*num_threads=*/1, /*max_queue=*/16);
    REQUIRE(pool.submit([] { throw std::runtime_error("boom"); }));
    std::atomic<bool> ran_after{false};
    REQUIRE(pool.submit([&ran_after] { ran_after.store(true); }));
    REQUIRE(pool.quiesce(std::chrono::seconds(5)));
    CHECK(ran_after.load());
}
