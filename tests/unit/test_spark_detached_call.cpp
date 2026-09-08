// test_spark_detached_call.cpp - SparkDetachedLane/DetachedCall<T>
// (agents/core/src/spark_detached_call.hpp), the PR-A shared primitive
// (#2012/#3840 plan, "Shared primitive" section). Cross-platform: this file
// exercises the primitive alone, not any Windows mechanism (those are PR-B).
//
// Each case is a caught-it test for one plan-required invariant: the
// ownership fix (Fn returned unconsumed on Rejected/LaunchFailed - the
// defect an earlier "launch_forget" design had), exactly-once delivery,
// the tightened F3-timing property (the lane/F3 counter stays nonzero
// until the WORKER's own disposal work fully completes, not merely until
// it decides not to publish), no-UAF on early handle destruction, and the
// Guardian-backend_op_deadline compile-time tripwire pattern.
//
// This file is also this primitive's TSan/ASan checkpoint (shared mutable
// state across threads) - see the session's final report for the exact
// sanitizer build/run commands used to verify it.

#include "spark_detached_call.hpp"

#include "test_helpers.hpp" // yuzu::test::spin_until

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>

using namespace yuzu::agent;
using namespace std::chrono_literals;
using yuzu::test::spin_until;

namespace {

// A worker gate: a launched fn blocks on wait() until the test releases it,
// so a test can hold a call "parked" (in flight) and observe admission/
// count state deterministically. Mirrors test_guardian_io_executor.cpp's
// own Gate exactly (that file's own header comment: this is also this
// primitive's TSan checkpoint).
struct Gate {
    std::mutex m;
    std::condition_variable cv;
    bool go{false};
    void wait() {
        std::unique_lock<std::mutex> lk{m};
        cv.wait(lk, [&] { return go; });
    }
    void release() {
        {
            std::lock_guard<std::mutex> lk{m};
            go = true;
        }
        cv.notify_all();
    }
};

// A move-only result type whose destructor records WHEN it started (an
// atomic<bool> flag) and ON WHICH THREAD, then sleeps `hold_for` before
// returning. Used to make the "disposal, not publication, is what the F3
// counter waits for" property directly observable: a poller on another
// thread can watch the flag flip and then confirm the lane/F3 counter stays
// nonzero for the FULL duration of the destructor's own run, not just up to
// the moment the worker decided whether to publish or self-dispose.
struct SlowDtor {
    std::atomic<bool>* started{nullptr};
    std::atomic<std::thread::id>* thread_id{nullptr};
    std::chrono::milliseconds hold_for{0};
    int value{0};

    SlowDtor() = default;
    SlowDtor(std::atomic<bool>* s, std::atomic<std::thread::id>* tid,
             std::chrono::milliseconds hold, int v)
        : started(s), thread_id(tid), hold_for(hold), value(v) {}
    SlowDtor(const SlowDtor&) = delete;
    SlowDtor& operator=(const SlowDtor&) = delete;
    SlowDtor(SlowDtor&& o) noexcept
        : started(o.started), thread_id(o.thread_id), hold_for(o.hold_for), value(o.value) {
        o.started = nullptr; // moved-from: its destructor becomes a no-op
        o.thread_id = nullptr;
    }
    SlowDtor& operator=(SlowDtor&& o) noexcept {
        if (this != &o) {
            started = o.started;
            thread_id = o.thread_id;
            hold_for = o.hold_for;
            value = o.value;
            o.started = nullptr;
            o.thread_id = nullptr;
        }
        return *this;
    }
    ~SlowDtor() {
        if (!started)
            return; // moved-from — nothing to record, nothing to hold
        started->store(true, std::memory_order_relaxed);
        if (thread_id)
            thread_id->store(std::this_thread::get_id(), std::memory_order_relaxed);
        if (hold_for.count() > 0)
            std::this_thread::sleep_for(hold_for);
    }
};

// A move-only, non-invokable-until-called-once marker used to prove a
// closure handed back on Rejected/LaunchFailed is genuinely the SAME,
// never-consumed object — not a fresh default-constructed stand-in and not
// a moved-from husk.
struct Marker {
    int tag{0};
    Marker() = default;
    explicit Marker(int t) : tag(t) {}
    Marker(const Marker&) = delete;
    Marker& operator=(const Marker&) = delete;
    Marker(Marker&&) noexcept = default;
    Marker& operator=(Marker&&) noexcept = default;
};

} // namespace

TEST_CASE("launch: a fast fn returns before the deadline", "[spark][detachedcall]") {
    auto f3 = std::make_shared<std::atomic<std::size_t>>(0);
    SparkDetachedLane lane(f3, /*cap=*/4);

    auto res = lane.launch([]() -> int { return 42; });
    REQUIRE(res.status == DetachedLaunch::Launched);
    REQUIRE(res.call.has_value());
    CHECK_FALSE(res.fn.has_value());

    auto v = res.call->wait_take(std::chrono::steady_clock::now() + 2s);
    REQUIRE(v.has_value());
    REQUIRE(v->has_value());
    CHECK(**v == 42);

    CHECK(spin_until([&] { return lane.active_workers() == 0; }));
    CHECK(f3->load() == 0);
}

TEST_CASE("launch: a gated fn times out on wait_take, then a later take delivers exactly once",
          "[spark][detachedcall]") {
    auto f3 = std::make_shared<std::atomic<std::size_t>>(0);
    SparkDetachedLane lane(f3, /*cap=*/4);
    Gate gate;

    auto res = lane.launch([&gate]() -> int {
        gate.wait();
        return 99;
    });
    REQUIRE(res.status == DetachedLaunch::Launched);
    CHECK(lane.active_workers() == 1);
    CHECK(f3->load() == 1);

    auto early = res.call->wait_take(std::chrono::steady_clock::now() + 50ms);
    CHECK_FALSE(early.has_value()); // Timeout — still gated, NOT abandoned

    gate.release();
    auto late = res.call->wait_take(std::chrono::steady_clock::now() + 5s);
    REQUIRE(late.has_value());
    REQUIRE(late->has_value());
    CHECK(**late == 99);

    // Exactly once — a further take after the late one is empty.
    CHECK_FALSE(res.call->try_take().has_value());

    // The lane/F3 counter reaches 0 once the worker is done — no ordering
    // claim is made here relative to the late take itself (F3 protects a
    // LIVE WORKER THREAD, not an inert parked value already delivered to
    // the owner; see spark_detached_call.hpp's own header comment).
    CHECK(spin_until([&] { return lane.active_workers() == 0; }));
    CHECK(f3->load() == 0);
}

TEST_CASE("launch: cap rejection returns Fn unconsumed", "[spark][detachedcall]") {
    auto f3 = std::make_shared<std::atomic<std::size_t>>(0);
    SparkDetachedLane lane(f3, /*cap=*/0); // 0: a deliberate, well-defined "never admit" lane

    auto res = lane.launch([m = Marker(11)]() mutable -> int { return m.tag; });
    CHECK(res.status == DetachedLaunch::Rejected);
    CHECK_FALSE(res.call.has_value());
    REQUIRE(res.fn.has_value());

    CHECK(lane.active_workers() == 0);
    CHECK(f3->load() == 0);
    CHECK(lane.rejected_total() == 1);

    // fn is genuinely the original, unconsumed closure — invoking it now
    // returns the original captured value, not a moved-from husk's garbage.
    CHECK((*res.fn)() == 11);
}

TEST_CASE("launch: OS launch failure returns Fn unconsumed", "[spark][detachedcall]") {
    auto f3 = std::make_shared<std::atomic<std::size_t>>(0);
    SparkDetachedLane lane(f3, /*cap=*/4);
    lane.set_fail_launch_for_test(true);

    auto res = lane.launch([m = Marker(23)]() mutable -> int { return m.tag; });
    CHECK(res.status == DetachedLaunch::LaunchFailed);
    CHECK_FALSE(res.call.has_value());
    REQUIRE(res.fn.has_value());

    CHECK(lane.active_workers() == 0);
    CHECK(f3->load() == 0);
    CHECK(lane.launch_failed_total() == 1);
    CHECK((*res.fn)() == 23);

    // The lane recovers once the test seam is cleared — a real launch after
    // a simulated failure succeeds normally.
    lane.set_fail_launch_for_test(false);
    auto res2 = lane.launch([]() -> int { return 1; });
    REQUIRE(res2.status == DetachedLaunch::Launched);
    auto v = res2.call->wait_take(std::chrono::steady_clock::now() + 2s);
    REQUIRE(v.has_value());
    REQUIRE(v->has_value());
    CHECK(**v == 1);
    CHECK(spin_until([&] { return lane.active_workers() == 0; }));
}

TEST_CASE("launch: a throwing fn maps to WorkerThrew and the process stays alive",
          "[spark][detachedcall]") {
    auto f3 = std::make_shared<std::atomic<std::size_t>>(0);
    SparkDetachedLane lane(f3, /*cap=*/4);

    auto res = lane.launch([]() -> int { throw std::runtime_error("boom"); });
    REQUIRE(res.status == DetachedLaunch::Launched);
    auto v = res.call->wait_take(std::chrono::steady_clock::now() + 5s);
    REQUIRE(v.has_value());
    CHECK_FALSE(v->has_value());
    CHECK(v->error() == DetachedCallError::WorkerThrew);

    CHECK(spin_until([&] { return lane.active_workers() == 0; }));
    CHECK(f3->load() == 0);
    CHECK(lane.worker_threw_total() == 1);
}

TEST_CASE("launch: owner handle destroyed while parked — no UAF, disposal happens on the "
          "WORKER thread",
          "[spark][detachedcall]") {
    auto f3 = std::make_shared<std::atomic<std::size_t>>(0);
    SparkDetachedLane lane(f3, /*cap=*/4);
    Gate gate;
    std::atomic<bool> dtor_ran{false};
    std::atomic<std::thread::id> dtor_thread{};

    auto res = lane.launch([&gate, &dtor_ran, &dtor_thread]() -> SlowDtor {
        gate.wait();
        return SlowDtor(&dtor_ran, &dtor_thread, 0ms, 3);
    });
    REQUIRE(res.status == DetachedLaunch::Launched);

    {
        // Destroying the handle WHILE the call is still parked (fn is
        // blocked on the gate) — this is the implicit-abandon path: the
        // worker discovers `abandoned` under cell.mu once it finally
        // completes, and self-disposes the SlowDtor LOCALLY (never
        // publishing it into the cell).
        [[maybe_unused]] auto dropped = std::move(*res.call);
    }
    // `res.call` (the optional) is still engaged but now holds a
    // moved-from, cell_==nullptr handle — deliberately not touched again.

    gate.release();
    REQUIRE(spin_until([&] { return dtor_ran.load(); }, 5s));
    CHECK(dtor_thread.load() != std::this_thread::get_id()); // disposed on the WORKER thread

    REQUIRE(spin_until([&] { return lane.active_workers() == 0; }, 5s));
    CHECK(f3->load() == 0);
}

TEST_CASE("launch: abandon() after publish returns the result exactly once",
          "[spark][detachedcall]") {
    auto f3 = std::make_shared<std::atomic<std::size_t>>(0);
    SparkDetachedLane lane(f3, /*cap=*/4);

    auto res = lane.launch([]() -> int { return 55; });
    REQUIRE(res.status == DetachedLaunch::Launched);
    REQUIRE(spin_until([&] { return res.call->done(); }, 5s));

    auto first = res.call->abandon();
    REQUIRE(first.has_value());
    REQUIRE(first->has_value());
    CHECK(**first == 55);

    auto second = res.call->abandon();
    CHECK_FALSE(second.has_value());

    CHECK(spin_until([&] { return lane.active_workers() == 0; }));
    CHECK(f3->load() == 0);
}

TEST_CASE("launch: an abandoned-before-publish result's disposal keeps the lane/F3 counter "
          "nonzero until the captured object's OWN destructor completes — not merely until "
          "the worker decides not to publish",
          "[spark][detachedcall]") {
    // This is the tightened F3-timing regression test (plan's "Ownership
    // fix" section, Astra table-12): a buggy implementation that decrements
    // the counters as soon as the worker records `abandoned` (i.e., right
    // when it would have published, had the owner not given up first) —
    // rather than only once the self-disposed value's OWN destructor has
    // fully finished running — would fail this test.
    auto f3 = std::make_shared<std::atomic<std::size_t>>(0);
    SparkDetachedLane lane(f3, /*cap=*/4);
    Gate gate;
    std::atomic<bool> dtor_started{false};
    std::atomic<std::thread::id> dtor_thread{};
    constexpr auto kHold = 300ms;

    auto res = lane.launch([&gate, &dtor_started, &dtor_thread]() -> SlowDtor {
        gate.wait();
        return SlowDtor(&dtor_started, &dtor_thread, kHold, 1);
    });
    REQUIRE(res.status == DetachedLaunch::Launched);
    CHECK(lane.active_workers() == 1);
    CHECK(f3->load() == 1);

    // Abandon BEFORE the worker has even called fn() (still gated) — a
    // not-yet-published call, per this file's own contract, so the worker
    // self-disposes when it eventually completes.
    auto pre_abandon = res.call->abandon();
    CHECK_FALSE(pre_abandon.has_value());

    gate.release();

    REQUIRE(spin_until([&] { return dtor_started.load(); }, 5s));
    // The destructor has STARTED (and is now sleeping for kHold) — poll for
    // a window comfortably inside that sleep and assert the counters never
    // read 0 during it. A premature-decrement bug would show 0 almost
    // immediately after dtor_started flips, well inside this window.
    const auto poll_until = std::chrono::steady_clock::now() + kHold - 50ms;
    bool saw_zero_early = false;
    while (std::chrono::steady_clock::now() < poll_until) {
        if (lane.active_workers() == 0 || f3->load() == 0) {
            saw_zero_early = true;
            break;
        }
        std::this_thread::sleep_for(10ms);
    }
    CHECK_FALSE(saw_zero_early);

    REQUIRE(spin_until([&] { return lane.active_workers() == 0; }, 5s));
    CHECK(f3->load() == 0);
    CHECK(dtor_thread.load() != std::this_thread::get_id()); // disposed on the WORKER thread
}

TEST_CASE("launch: fn's OWN captured RAII state outlives fn() returning, and the lane/F3 "
          "counter stays nonzero until IT is destroyed too",
          "[spark][detachedcall]") {
    // Pins the Payload<T,DFn> member-declaration-order fix directly (this
    // file's header comment, "Ticketing"): `held` is captured by the
    // closure and is unrelated to the returned T (an int) — it is only
    // destroyed when the closure itself (Payload's `fn` member) is
    // destroyed, which happens as part of Payload's own teardown AFTER
    // operator()() has already returned and the result has already been
    // published/taken. An implementation that captured the count-guard
    // ticket alongside fn in a lambda-capture list (UNSPECIFIED destruction
    // order — the shape this file's header comment says not to copy)
    // could destroy `held` AFTER the counters had already reached 0.
    auto f3 = std::make_shared<std::atomic<std::size_t>>(0);
    SparkDetachedLane lane(f3, /*cap=*/4);
    std::atomic<bool> dtor_started{false};
    std::atomic<std::thread::id> dtor_thread{};
    constexpr auto kHold = 300ms;

    SlowDtor held(&dtor_started, &dtor_thread, kHold, 2);
    auto res = lane.launch([held = std::move(held)]() -> int { return held.value; });
    REQUIRE(res.status == DetachedLaunch::Launched);

    auto v = res.call->wait_take(std::chrono::steady_clock::now() + 5s);
    REQUIRE(v.has_value());
    REQUIRE(v->has_value());
    CHECK(**v == 2);
    // fn() has returned and the result has been taken — `held` (fn's own
    // capture) is NOT destroyed yet; it lives inside Payload's `fn` member
    // until Payload itself is torn down, which happens strictly after this.

    REQUIRE(spin_until([&] { return dtor_started.load(); }, 5s));
    const auto poll_until = std::chrono::steady_clock::now() + kHold - 50ms;
    bool saw_zero_early = false;
    while (std::chrono::steady_clock::now() < poll_until) {
        if (lane.active_workers() == 0 || f3->load() == 0) {
            saw_zero_early = true;
            break;
        }
        std::this_thread::sleep_for(10ms);
    }
    CHECK_FALSE(saw_zero_early);

    REQUIRE(spin_until([&] { return lane.active_workers() == 0; }, 5s));
    CHECK(f3->load() == 0);
    CHECK(dtor_thread.load() != std::this_thread::get_id());
}

// ── Guardian-backend_op_deadline compile-time tripwire (the "audit this at
//    implementation time" note in the plan's "Shared primitive" section) ──
static_assert(spark_deadline_below_guardian_backend_op(std::chrono::milliseconds(200)));
static_assert(!spark_deadline_below_guardian_backend_op(std::chrono::milliseconds(5000)));
static_assert(!spark_deadline_below_guardian_backend_op(std::chrono::milliseconds(6000)));
static_assert(spark_deadline_below_guardian_backend_op(std::chrono::milliseconds(100), 4));
static_assert(!spark_deadline_below_guardian_backend_op(std::chrono::milliseconds(2000), 4));

TEST_CASE("spark_deadline_below_guardian_backend_op: tripwire matches the mirrored constant",
          "[spark][detachedcall]") {
    CHECK(kGuardianBackendOpDeadlineMirror == std::chrono::milliseconds(5000));
    CHECK(spark_deadline_below_guardian_backend_op(std::chrono::milliseconds(4999)));
    CHECK_FALSE(spark_deadline_below_guardian_backend_op(std::chrono::milliseconds(5000)));
    CHECK_FALSE(spark_deadline_below_guardian_backend_op(std::chrono::milliseconds(5001)));
}
