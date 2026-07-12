/**
 * test_spark_engine.cpp — SparkEngine core contract (spark_engine.cpp):
 * tier behaviour, arming dedup, consumer isolation, bounded-queue overflow,
 * and lifecycle. Uses the cadence-floor + disk-reader test seams so nothing
 * here waits on a real 30 s cadence or a real volume filling up.
 *
 * Timing style: assertions wait on observed effects with generous deadlines
 * (never "sleep then assert a count is exact") so the suite stays honest under
 * CI load and Defender-induced I/O serialisation (#473 lesson).
 */

#include "spark_engine.hpp"
#include "spark_heartbeat.hpp" // emit_spark_heartbeat_tags (rung-1 tag composition)

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu::agent;
using namespace std::chrono_literals;

namespace {

constexpr std::uint64_t kGiB = 1024ULL * 1024 * 1024;

/// Poll `pred` until true or the deadline passes. Returns its final value.
template <typename Pred>
bool eventually(Pred pred, std::chrono::milliseconds deadline = 5000ms) {
    const auto until = std::chrono::steady_clock::now() + deadline;
    while (!pred()) {
        if (std::chrono::steady_clock::now() >= until)
            return pred();
        std::this_thread::sleep_for(5ms);
    }
    return true;
}

/// Thread-safe event collector handed to queued consumers.
struct Collector {
    std::mutex mu;
    std::vector<SparkEvent> events;

    SparkEngine::QueuedHandler handler() {
        return [this](const SparkEvent& ev) {
            std::lock_guard lk(mu);
            events.push_back(ev);
        };
    }
    std::size_t count() {
        std::lock_guard lk(mu);
        return events.size();
    }
    SparkEvent at(std::size_t i) {
        std::lock_guard lk(mu);
        return events.at(i);
    }
};

SparkSpec interval_spec(std::uint64_t ms) {
    return SparkSpec{SparkType::Interval, IntervalSparkParams{ms}};
}

} // namespace

TEST_CASE("SparkEngine: interval spark delivers to a queued consumer", "[spark][engine]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    Collector got;
    auto consumer = engine.register_consumer("test", got.handler());
    REQUIRE(consumer.has_value());
    auto sub = engine.arm(*consumer, interval_spec(50));
    REQUIRE(sub.has_value());

    engine.start();
    REQUIRE(engine.is_running());
    CHECK(eventually([&] { return got.count() >= 3; }));

    // Events carry the armed key, the type, and a monotonically increasing seq.
    const SparkEvent first = got.at(0);
    CHECK(first.key == spark_key(interval_spec(50)));
    CHECK(first.type == SparkType::Interval);
    CHECK(got.at(1).seq == first.seq + 1);
    CHECK(std::holds_alternative<std::monostate>(first.data));

    engine.stop();
    const auto stats = engine.stats();
    CHECK(stats.events_total >= 3);
    CHECK(stats.queued_delivered_total >= 3);
}

TEST_CASE("SparkEngine: two distinct sparks due in one wheel tick both fire (no double-lock)",
          "[spark][engine]") {
    // Regression (governance HP-1): two DISTINCT-key timer sparks that clamp to
    // the same cadence floor get an identical next_due from start()'s shared
    // `now` and land in one wheel scan (due.size()==2). The prior wheel re-locked
    // mu_ per due item, so the second item's commit lk.lock() double-locked →
    // std::system_error, uncaught on the wheel thread → std::terminate (agent
    // crash). Every other multi-arm test reuses an IDENTICAL spec (dedup →
    // due.size()==1), so this path was never exercised. Without the fix this
    // test crashes the process.
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10); // both specs below clamp to 10ms
    Collector a;
    Collector b;
    auto ca = engine.register_consumer("a", a.handler());
    auto cb = engine.register_consumer("b", b.handler());
    REQUIRE(ca.has_value());
    REQUIRE(cb.has_value());
    // Raw intervals 5 and 8 → distinct spark_keys (not deduped) but BOTH floored
    // to the 10ms test floor → identical cadence → identical next_due at start().
    REQUIRE(engine.arm(*ca, interval_spec(5)).has_value());
    REQUIRE(engine.arm(*cb, interval_spec(8)).has_value());
    CHECK(engine.stats().armed_sparks == 2); // two distinct armed sparks, not one

    engine.start(); // both scheduled off one `now` → collide on the first tick
    CHECK(eventually([&] { return a.count() >= 2 && b.count() >= 2; }));
    engine.stop();
}

TEST_CASE("SparkEngine: equal specs dedup to one armed spark, fan out to all subscribers",
          "[spark][engine]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    Collector a;
    Collector b;
    auto ca = engine.register_consumer("a", a.handler());
    auto cb = engine.register_consumer("b", b.handler());
    REQUIRE(ca.has_value());
    REQUIRE(cb.has_value());
    REQUIRE(engine.arm(*ca, interval_spec(50)).has_value());
    REQUIRE(engine.arm(*cb, interval_spec(50)).has_value());

    CHECK(engine.stats().armed_sparks == 1); // deduped: N consumers, 1 watcher
    CHECK(engine.stats().subscriptions == 2);

    engine.start();
    CHECK(eventually([&] { return a.count() >= 2 && b.count() >= 2; }));
    // One fire, one seq — both consumers observe the SAME event stream.
    CHECK(a.at(0).seq == b.at(0).seq);
    engine.stop();
}

TEST_CASE("SparkEngine: startup spark fires once; late arm still fires once",
          "[spark][engine]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    Collector got;
    auto consumer = engine.register_consumer("test", got.handler());
    REQUIRE(consumer.has_value());
    const SparkSpec startup{SparkType::Startup, StartupSparkParams{}};
    REQUIRE(engine.arm(*consumer, startup).has_value());

    engine.start();
    CHECK(eventually([&] { return got.count() >= 1; }));
    std::this_thread::sleep_for(100ms); // one-shot: give a re-fire the chance to (not) happen
    CHECK(got.count() == 1);
    CHECK(got.at(0).type == SparkType::Startup);

    // A late subscriber to the SAME startup spec still gets its one-shot —
    // and the earlier subscriber does NOT see "startup" a second time.
    Collector late;
    auto late_consumer = engine.register_consumer("late", late.handler());
    REQUIRE(late_consumer.has_value());
    REQUIRE(engine.arm(*late_consumer, startup).has_value());
    CHECK(eventually([&] { return late.count() >= 1; }));
    std::this_thread::sleep_for(100ms);
    CHECK(late.count() == 1);
    CHECK(got.count() == 1);

    engine.stop();
}

TEST_CASE("SparkEngine: disk spark emits breach and recovery edges through the wheel",
          "[spark][engine][disk]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    std::atomic<bool> healthy{true};
    engine.set_disk_reader_for_test([&](const std::string&) {
        DiskReading r;
        r.valid = true;
        r.total_bytes = 100 * kGiB;
        r.free_bytes = healthy.load() ? 50 * kGiB : 1 * kGiB;
        return r;
    });
    Collector got;
    auto consumer = engine.register_consumer("dex-ish", got.handler());
    REQUIRE(consumer.has_value());
    SparkSpec spec{SparkType::Disk, DiskSparkParams{"/", 90, 5 * kGiB, 20}};
    REQUIRE(engine.arm(*consumer, spec).has_value());

    engine.start();
    // Healthy polls emit nothing; flip to bad → exactly one Breach.
    healthy = false;
    CHECK(eventually([&] { return got.count() >= 1; }));
    const SparkEvent breach_ev = got.at(0);
    const auto* breach = std::get_if<DiskSparkData>(&breach_ev.data);
    REQUIRE(breach != nullptr);
    CHECK(breach->edge == DiskEdge::Breach);

    // Back to healthy → exactly one Recovery.
    healthy = true;
    CHECK(eventually([&] { return got.count() >= 2; }));
    const SparkEvent recovery_ev = got.at(1);
    const auto* recovery = std::get_if<DiskSparkData>(&recovery_ev.data);
    REQUIRE(recovery != nullptr);
    CHECK(recovery->edge == DiskEdge::Recovery);

    // No further edges while steady.
    std::this_thread::sleep_for(150ms);
    CHECK(got.count() == 2);
    engine.stop();
}

TEST_CASE("SparkEngine: a stuck queued consumer stalls neither watchers nor siblings",
          "[spark][engine][isolation]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);

    // Heap-allocated: if a scheduling delay ever pushed this wedged handler's
    // wakeup past stop()'s join budget, stop() would detach rather than hang
    // (UP-1) — a still-running detached thread must not reference stack locals
    // destroyed when this TEST_CASE returns (#1957).
    struct Sync {
        std::promise<void> unstick;
        std::shared_future<void> unstick_f = unstick.get_future().share();
        std::atomic<int> stuck_calls{0};
    };
    auto sync = std::make_shared<Sync>();
    auto stuck = engine.register_consumer("stuck", [sync](const SparkEvent&) {
        ++sync->stuck_calls;
        sync->unstick_f.wait(); // deliberately blocked (a popup open for minutes)
    });
    Collector healthy;
    auto ok = engine.register_consumer("healthy", healthy.handler());
    REQUIRE(stuck.has_value());
    REQUIRE(ok.has_value());
    REQUIRE(engine.arm(*stuck, interval_spec(30)).has_value());
    REQUIRE(engine.arm(*ok, interval_spec(30)).has_value());

    engine.start();
    CHECK(eventually([&] { return sync->stuck_calls.load() >= 1; }));
    // The stuck consumer is wedged in its first event — the sibling keeps
    // receiving, which also proves the WATCHER thread never blocked.
    const auto before = healthy.count();
    CHECK(eventually([&] { return healthy.count() >= before + 3; }));

    sync->unstick.set_value(); // release before stop() so the join can complete
    engine.stop();
}

TEST_CASE("SparkEngine: full queue drops oldest and counts, never blocks",
          "[spark][engine][isolation]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);

    // Heap-allocated: if a scheduling delay ever pushed this wedged handler's
    // wakeup past stop()'s join budget, stop() would detach rather than hang
    // (UP-1) — a still-running detached thread must not reference stack locals
    // destroyed when this TEST_CASE returns (#1957).
    struct Sync {
        std::promise<void> unstick;
        std::shared_future<void> unstick_f = unstick.get_future().share();
        std::atomic<int> calls{0};
    };
    auto sync = std::make_shared<Sync>();
    auto consumer = engine.register_consumer(
        "slow",
        [sync](const SparkEvent&) {
            ++sync->calls;
            sync->unstick_f.wait();
        },
        /*queue_cap=*/2);
    REQUIRE(consumer.has_value());
    REQUIRE(engine.arm(*consumer, interval_spec(20)).has_value());

    engine.start();
    CHECK(eventually([&] { return sync->calls.load() >= 1; }));
    // Handler wedged: the queue (cap 2) must overflow and drop rather than
    // block the wheel.
    CHECK(eventually([&] { return engine.stats().queued_dropped_total >= 2; }));

    sync->unstick.set_value();
    engine.stop();
}

TEST_CASE("SparkEngine: bounded queue drops the OLDEST — newest survives (drop identity)",
          "[spark][engine][isolation]") {
    // A count-only assertion passes even for a drop-NEWEST bug. Assert identity:
    // the surviving events are the most recent, and an early one was dropped.
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);

    // Heap-allocated: if a scheduling delay ever pushed this wedged handler's
    // wakeup past stop()'s join budget, stop() would detach rather than hang
    // (UP-1) — a still-running detached thread must not reference stack locals
    // destroyed when this TEST_CASE returns (#1957).
    struct Sync {
        std::promise<void> unstick;
        std::shared_future<void> uf = unstick.get_future().share();
        std::mutex m;
        std::vector<std::uint64_t> got;
        std::atomic<int> calls{0};
    };
    auto sync = std::make_shared<Sync>();
    auto consumer = engine.register_consumer(
        "slow",
        [sync](const SparkEvent& ev) {
            if (++sync->calls == 1)
                sync->uf.wait(); // wedge on the first fire so later fires pile up + drop
            std::lock_guard lk(sync->m);
            sync->got.push_back(ev.seq);
        },
        /*queue_cap=*/2);
    REQUIRE(consumer.has_value());
    REQUIRE(engine.arm(*consumer, interval_spec(15)).has_value());

    engine.start();
    CHECK(eventually([&] { return sync->calls.load() >= 1; }));                    // wedged on seq 1
    CHECK(eventually([&] { return engine.stats().queued_dropped_total >= 3; })); // middle seqs dropped
    sync->unstick.set_value();
    CHECK(eventually([&] {
        std::lock_guard lk(sync->m);
        return sync->got.size() >= 3;
    }));
    engine.stop();

    std::lock_guard lk(sync->m);
    REQUIRE(sync->got.size() >= 3);
    CHECK(sync->got[0] == 1);      // the wedged first fire
    CHECK(sync->got[1] > 2);       // seq 2 was dropped as oldest → a NEWER seq survived
    CHECK(sync->got[2] > sync->got[1]);  // monotonic — most-recent-wins, not most-recent-lost
}

TEST_CASE("SparkEngine: a handler blocked past the shutdown budget is detached, not hung (UP-1)",
          "[spark][engine]") {
    // Queued handlers may block (network/plugin I/O). stop() must bound the join
    // and DETACH a hung handler rather than hang agent shutdown (#1311 class).
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    engine.set_consumer_join_budget_for_test(120); // shrink the budget for the test
    // Heap-allocated: on budget expiry stop() DETACHES this handler's thread, so
    // it may still be inside cv.wait() reacquiring `m` after this TEST_CASE
    // returns. Stack locals captured by reference would be destroyed out from
    // under it (UAF on the mutex/cv, observed as a libc++ "condition_variable
    // wait failed" abort in an unrelated later test) — the shared_ptr keeps
    // them alive for as long as the detached thread is still running.
    struct Sync {
        std::mutex m;
        std::condition_variable cv;
        bool release = false;
        std::atomic<bool> in_handler{false};
        std::atomic<bool> finished{false}; // confirms the detached thread actually wakes
    };
    auto sync = std::make_shared<Sync>();
    auto consumer = engine.register_consumer("blocker", [sync](const SparkEvent&) {
        sync->in_handler.store(true);
        {
            std::unique_lock lk(sync->m);
            sync->cv.wait(lk, [&] { return sync->release; }); // block until the test frees us
        }
        sync->finished.store(true);
    });
    REQUIRE(consumer.has_value());
    REQUIRE(engine.arm(*consumer, interval_spec(20)).has_value());

    engine.start();
    CHECK(eventually([&] { return sync->in_handler.load(); })); // handler is now wedged

    const auto t0 = std::chrono::steady_clock::now();
    engine.stop(); // MUST return within ~budget, not block on the wedged handler
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    CHECK(elapsed < 2000ms); // bounded (budget 120ms + generous slack), not hung
    CHECK(engine.stats().consumer_threads_detached >= 1);

    // Free the detached handler so its thread exits cleanly (no leaked blocker),
    // and confirm it actually does — a broken release/wakeup path would otherwise
    // leave the thread parked forever without failing anything.
    {
        std::lock_guard lk(sync->m);
        sync->release = true;
    }
    sync->cv.notify_all();
    CHECK(eventually([&] { return sync->finished.load(); }));
}

TEST_CASE("SparkEngine: N blocked handlers detach against ONE shared budget, not N× (UP2-3)",
          "[spark][engine]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    engine.set_consumer_join_budget_for_test(200);
    // Heap-allocated for the same reason as the UP-1 test above: the detached
    // handler threads may still be running (inside cv.wait()) after this
    // TEST_CASE returns, so stack locals captured by reference are unsafe.
    struct Sync {
        std::mutex m;
        std::condition_variable cv;
        bool release = false;
        std::atomic<int> wedged{0};
        std::atomic<int> finished{0}; // confirms every detached thread actually wakes
    };
    auto sync = std::make_shared<Sync>();
    auto blocker = [sync](const SparkEvent&) {
        sync->wedged.fetch_add(1);
        {
            std::unique_lock lk(sync->m);
            sync->cv.wait(lk, [&] { return sync->release; });
        }
        sync->finished.fetch_add(1);
    };
    for (int i = 0; i < 3; ++i) {
        auto c = engine.register_consumer("blk" + std::to_string(i), blocker);
        REQUIRE(c.has_value());
        REQUIRE(engine.arm(*c, interval_spec(20)).has_value()); // dedups → 1 spark, 3 subs
    }
    engine.start();
    CHECK(eventually([&] { return sync->wedged.load() >= 3; })); // all 3 handlers wedged

    const auto t0 = std::chrono::steady_clock::now();
    engine.stop();
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    // Serial join-then-detach would be 3×200ms=600ms; the shared deadline makes
    // it ~200ms. Assert well under the serial cost (generous ceiling for CI jitter).
    CHECK(elapsed < 450ms);
    CHECK(engine.stats().consumer_threads_detached >= 3);

    {
        std::lock_guard lk(sync->m);
        sync->release = true;
    }
    sync->cv.notify_all();
    CHECK(eventually([&] { return sync->finished.load() >= 3; }));
}

TEST_CASE("SparkEngine: inline tier runs on the watcher thread and is duration-accounted",
          "[spark][engine][inline]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    // No Catch2 assertions inside the handler — it runs on the watcher thread
    // and Catch2 macros are not thread-safe. Capture, assert on the main thread.
    std::atomic<int> inline_calls{0};
    std::atomic<bool> type_ok{true};
    auto sub = engine.arm_inline(interval_spec(30), [&](const SparkEvent& ev) {
        const int n = ++inline_calls;
        if (ev.type != SparkType::Interval)
            type_ok = false;
        if (n == 1)
            std::this_thread::sleep_for(2ms); // make the watchdog measurably time a call
        if (n == 2)
            throw std::runtime_error("contract breach"); // watcher must survive
    });
    REQUIRE(sub.has_value());

    engine.start();
    CHECK(eventually([&] { return inline_calls.load() >= 4; })); // survived the throw
    engine.stop();

    CHECK(type_ok.load());
    const auto stats = engine.stats();
    CHECK(stats.inline_calls_total >= 4);
    CHECK(stats.inline_errors_total == 1);
    CHECK(stats.inline_us_max >= 1000);      // the 2ms call was actually timed
    CHECK(stats.inline_over_100us_total >= 1); // ...and hit the tail counter
}

TEST_CASE("SparkEngine: disarm stops delivery; last disarm removes the watcher entry",
          "[spark][engine]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    Collector got;
    auto consumer = engine.register_consumer("test", got.handler());
    REQUIRE(consumer.has_value());
    auto sub = engine.arm(*consumer, interval_spec(30));
    REQUIRE(sub.has_value());

    engine.start();
    CHECK(eventually([&] { return got.count() >= 1; }));
    engine.disarm(*sub);
    CHECK(engine.stats().armed_sparks == 0);
    // Let anything already in-queue at disarm time drain before baselining.
    std::this_thread::sleep_for(50ms);
    const auto after = got.count();
    std::this_thread::sleep_for(150ms);
    CHECK(got.count() == after); // nothing delivered after disarm
    engine.disarm(*sub);         // idempotent
    engine.stop();
}

TEST_CASE("SparkEngine: arming validation", "[spark][engine]") {
    SparkEngine engine;
    Collector got;
    auto consumer = engine.register_consumer("test", got.handler());
    REQUIRE(consumer.has_value());

    // Unknown consumer.
    CHECK_FALSE(engine.arm(9999, interval_spec(60'000)).has_value());

    // Mechanisms not in this slice are rejected loudly, not silently inert.
    CHECK_FALSE(engine.arm(*consumer, SparkSpec{SparkType::File, FileSparkParams{"/etc/hosts"}})
                    .has_value());
    CHECK_FALSE(
        engine.arm(*consumer, SparkSpec{SparkType::Service, ServiceSparkParams{"sshd"}})
            .has_value());
    CHECK_FALSE(engine
                    .arm(*consumer,
                         SparkSpec{SparkType::Registry, RegistrySparkParams{"HKLM", "SOFTWARE"}})
                    .has_value());

    // Type/params mismatch.
    CHECK_FALSE(
        engine.arm(*consumer, SparkSpec{SparkType::Disk, IntervalSparkParams{60'000}}).has_value());

    // Disk param sanity.
    CHECK_FALSE(engine.arm(*consumer, SparkSpec{SparkType::Disk, DiskSparkParams{"", 90, 0, 0}})
                    .has_value());
    CHECK_FALSE(
        engine.arm(*consumer, SparkSpec{SparkType::Disk, DiskSparkParams{"/", 101, 0, 0}})
            .has_value());

    // Null handlers / empty names.
    CHECK_FALSE(engine.register_consumer("x", nullptr).has_value());
    CHECK_FALSE(engine.register_consumer("", got.handler()).has_value());
    CHECK_FALSE(engine.arm_inline(interval_spec(60'000), nullptr).has_value());
}

TEST_CASE("SparkEngine: unregister_consumer removes its subscriptions and joins its thread",
          "[spark][engine]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    Collector a;
    Collector b;
    auto ca = engine.register_consumer("a", a.handler());
    auto cb = engine.register_consumer("b", b.handler());
    REQUIRE(ca.has_value());
    REQUIRE(cb.has_value());
    REQUIRE(engine.arm(*ca, interval_spec(30)).has_value());
    REQUIRE(engine.arm(*cb, interval_spec(30)).has_value());

    engine.start();
    CHECK(eventually([&] { return a.count() >= 1 && b.count() >= 1; }));
    engine.unregister_consumer(*ca);
    CHECK(engine.stats().consumers == 1);
    CHECK(engine.stats().subscriptions == 1); // a's subscription went with it
    CHECK(engine.stats().armed_sparks == 1);  // b still holds the shared spark

    const auto a_after = a.count();
    const auto b_before = b.count();
    CHECK(eventually([&] { return b.count() >= b_before + 2; })); // b unaffected
    CHECK(a.count() == a_after);
    engine.stop();
}

TEST_CASE("SparkEngine: register_consumer racing stop() never strands an unjoined "
          "thread (governance Tr3kkR finding, PR #1927)",
          "[spark][engine]") {
    // Forces the exact interleaving the fix closes: stop() lands after
    // register_consumer's dispatch thread has started but before it is
    // inserted into consumers_. Before the fix, the insert proceeded
    // unconditionally — the new consumer was never signalled by stop(), and
    // its still-joinable std::thread inside consumers_ would std::terminate
    // the process (an un-joined joinable std::thread's destructor) once the
    // engine was destroyed.
    SparkEngine engine;
    engine.start();
    engine.set_register_race_hook_for_test([&] { engine.stop(); });

    Collector got;
    auto consumer = engine.register_consumer("racer", got.handler());

    // Lost the race: register_consumer must report failure, not silently
    // succeed into a stopped engine.
    CHECK_FALSE(consumer.has_value());
    CHECK(engine.stats().consumers == 0);
    CHECK_FALSE(engine.is_running());

    // ~SparkEngine (end of scope) must not terminate. That IS the regression
    // this test exists to catch: a joinable std::thread reachable from a live
    // shared_ptr<Consumer> at destruction crashes the whole test binary
    // (std::terminate), not just fails an assertion.
}

TEST_CASE("SparkEngine: register_consumer vs stop() under REAL concurrent scheduling "
          "never crashes (stress, governance quality-engineer finding, PR #1927)",
          "[spark][engine][stress]") {
    // The deterministic hook-based test above proves the re-check-then-branch
    // LOGIC is correct, but runs entirely on one thread — it would pass
    // identically even if stopped_ were reverted to a plain (non-atomic)
    // bool, since nothing there needs a second thread's write to become
    // visible. This test exercises the actual cross-thread memory-ordering
    // half of the fix with real concurrent scheduling and no seam, so a
    // future regression back to a non-atomic stopped_ has a real chance of
    // being caught here — and under the nightly TSan leg, which this test
    // is written for.
    for (int trial = 0; trial < 500; ++trial) {
        SparkEngine engine;
        engine.start();
        std::atomic<bool> go{false};
        std::thread registrar([&] {
            while (!go.load(std::memory_order_acquire))
                std::this_thread::yield();
            // Result intentionally unchecked: either outcome (won or lost the
            // race) is valid. A no-op handler captures nothing, so even a
            // detached-but-never-armed consumer thread (see the sibling
            // deterministic test's own reasoning) can never touch freed test
            // state.
            (void)engine.register_consumer("racer", [](const SparkEvent&) {});
        });
        go.store(true, std::memory_order_release);
        engine.stop();
        registrar.join();
    }
    SUCCEED("500 concurrent register_consumer()/stop() trials completed without a crash or hang");
}

TEST_CASE("SparkEngine: stop is prompt and idempotent; engine is single-shot",
          "[spark][engine]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    Collector got;
    auto consumer = engine.register_consumer("test", got.handler());
    REQUIRE(consumer.has_value());
    REQUIRE(engine.arm(*consumer, interval_spec(30)).has_value());

    engine.start();
    CHECK(eventually([&] { return got.count() >= 1; }));
    engine.stop();
    CHECK_FALSE(engine.is_running());
    engine.stop(); // idempotent

    // Single-shot: a restart attempt is refused, and post-stop arms fail.
    engine.start();
    CHECK_FALSE(engine.is_running());
    CHECK_FALSE(engine.arm(*consumer, interval_spec(30)).has_value());
    CHECK_FALSE(engine.register_consumer("post-stop", got.handler()).has_value());
}

namespace {
/// Fake event-driven mechanism reporting a FIXED SparkMechanismStats — verifies
/// the per-type breakdown (stats_by_type) and the engine-level mech_* sums
/// (#2011 rung 1) without needing a platform mechanism or any real watch.
struct StatStubMechanism : ISparkMechanism {
    SparkMechanismStats fixed;
    explicit StatStubMechanism(SparkMechanismStats s) : fixed(s) {}
    void start(SparkEmitFn, SparkFaultFn) override {}
    std::expected<void, std::string> watch(const std::string&, const SparkParams&) override {
        return {};
    }
    void unwatch(const std::string&) override {}
    void stop() override {}
    [[nodiscard]] SparkMechanismStats stats() const override { return fixed; }
};
} // namespace

TEST_CASE("stats_by_type preserves the per-mechanism-type breakdown", "[spark][stats]") {
    SparkEngine engine;

    SparkMechanismStats file_stats;
    file_stats.retiring = 3;
    file_stats.retiring_cap = 256;
    file_stats.watch_rejected_total = 2;
    file_stats.quarantined_total = 1;
    file_stats.slow_op_total = 4;
    SparkMechanismStats svc_stats;
    svc_stats.watch_rejected_total = 5;
    svc_stats.slow_op_total = 7;

    REQUIRE(engine.register_mechanism(SparkType::File,
                                      std::make_unique<StatStubMechanism>(file_stats))
                .has_value());
    REQUIRE(engine.register_mechanism(SparkType::Service,
                                      std::make_unique<StatStubMechanism>(svc_stats))
                .has_value());

    // Per-type: keys preserved, only registered types appear, values not blended.
    const auto by_type = engine.stats_by_type();
    REQUIRE(by_type.size() == 2);
    REQUIRE(by_type.contains(SparkType::File));
    REQUIRE(by_type.contains(SparkType::Service));
    CHECK(by_type.at(SparkType::File).watch_rejected_total == 2);
    CHECK(by_type.at(SparkType::File).retiring_cap == 256);
    CHECK(by_type.at(SparkType::Service).watch_rejected_total == 5);
    CHECK(by_type.at(SparkType::Service).slow_op_total == 7);

    // Engine-level sum folds them together, including the new mech_retiring_cap.
    const auto s = engine.stats();
    CHECK(s.mech_watch_rejected_total == 7); // 2 + 5
    CHECK(s.mech_quarantined_total == 1);    // 1 + 0
    CHECK(s.mech_slow_op_total == 11);       // 4 + 7
    CHECK(s.mech_retiring == 3);             // 3 + 0
    CHECK(s.mech_retiring_cap == 256);       // 256 + 0
}

TEST_CASE("emit_spark_heartbeat_tags: always-present keys + sparse counters", "[spark][stats]") {
    std::map<std::string, std::string> tags;

    SECTION("quiescent engine (rung-1 steady state) ships only the capability keys") {
        SparkEngineStats ss;                          // all zero
        std::map<SparkType, SparkMechanismStats> by_type;
        by_type[SparkType::File] = {};
        by_type[SparkType::Service] = {};
        emit_spark_heartbeat_tags(tags, ss, by_type);

        CHECK(tags.at("yuzu.spark_running") == "1");
        CHECK(tags.at("yuzu.spark_mechs") == "file,service"); // map order: File(3) < Service(4)
        // No counter tags when every counter is 0 (sparse).
        CHECK(tags.size() == 2);
    }

    SECTION("non-zero counters emit; zero counters stay absent") {
        SparkEngineStats ss;
        ss.armed_faulted = 2;
        ss.watch_faults_total = 9;
        // queued_dropped_total and consumer_errors_total stay 0 -> absent.
        std::map<SparkType, SparkMechanismStats> by_type;
        SparkMechanismStats file_stats;
        file_stats.watch_rejected_total = 4;
        file_stats.slow_op_total = 1;
        // quarantined_total 0 -> absent.
        by_type[SparkType::File] = file_stats;
        emit_spark_heartbeat_tags(tags, ss, by_type);

        CHECK(tags.at("yuzu.spark_running") == "1");
        CHECK(tags.at("yuzu.spark_mechs") == "file");
        CHECK(tags.at("yuzu.spark_armed_faulted") == "2");
        CHECK(tags.at("yuzu.spark_watch_faults") == "9");
        CHECK_FALSE(tags.contains("yuzu.spark_queued_dropped"));
        CHECK_FALSE(tags.contains("yuzu.spark_consumer_errors"));
        CHECK(tags.at("yuzu.spark_file_watch_rejected") == "4");
        CHECK(tags.at("yuzu.spark_file_slow_op") == "1");
        CHECK_FALSE(tags.contains("yuzu.spark_file_quarantined"));
    }
}
