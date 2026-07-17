// test_guardian_io_executor.cpp - the bounded/cancellable single-flight I/O
// executor behind the Guardian state reader (ADR-0021 rung 5, F3). Each case is a
// caught-it test for one Sol-required invariant: deadline + late-result discard,
// keyed single-flight, per-type + total bulkheads, stop wake/reject + shutdown
// snapshot, launch-failure rollback, contained worker exceptions, and
// destroy-then-release lifetime safety (the ASan case). This is also the executor's
// TSan checkpoint (shared mutable state + threads).

#include "guardian_io_executor.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu::agent;
using namespace std::chrono_literals;

namespace {

// A worker gate: the fake read body blocks on wait() until the test releases it,
// so a test can hold a worker in flight and observe admission/slot state.
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

// Bounded busy-wait on a predicate (the notification of a released detached worker
// arrives before its ticket destructor runs, so counts settle asynchronously).
template <class Pred>
bool spin_until(Pred p, std::chrono::milliseconds timeout = 5s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (p())
            return true;
        std::this_thread::sleep_for(1ms);
    }
    return p();
}

constexpr std::size_t kFile = io_class_index(IoClass::File);
constexpr std::size_t kSvc = io_class_index(IoClass::Service);

} // namespace

TEST_CASE("run: a read that completes before its deadline returns its value", "[spark][ioexecutor]") {
    GuardianIoExecutor ex;
    auto r = ex.run(IoClass::File, "k", 5s, [] { return 7; });
    REQUIRE(r.has_value());
    CHECK(*r == 7);
    // Not necessarily zero the instant run() returns (the ticket destructor runs
    // after the worker's notify) - wait boundedly.
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
}

TEST_CASE("run: exceeding the deadline returns Timeout and discards the late result",
          "[spark][ioexecutor]") {
    GuardianIoExecutor ex;
    auto gate = std::make_shared<Gate>();
    auto r = ex.run(IoClass::File, "k", 30ms, [gate]() -> int {
        gate->wait();
        return 99;
    });
    CHECK_FALSE(r.has_value());
    CHECK(r.error() == IoFailure::Timeout);
    CHECK(ex.active_worker_count() == 1); // the worker is still blocked
    gate->release();                      // its late write goes to the abandoned cell -> discarded
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
    CHECK(ex.stats().counters[kFile].timed_out == 1);
}

TEST_CASE("run: a second read for the same (class,key) returns AlreadyRunning without spawning",
          "[spark][ioexecutor]") {
    GuardianIoExecutor ex;
    auto gate = std::make_shared<Gate>();
    auto spawns = std::make_shared<std::atomic<int>>(0);
    auto first_started = std::make_shared<std::promise<void>>();
    auto first_started_fut = first_started->get_future();
    std::thread caller([&] {
        ex.run(IoClass::File, "dup", 30s, [gate, spawns, first_started] {
            spawns->fetch_add(1);
            first_started->set_value(); // proves the worker body, not just admission, ran
            gate->wait();
            return 1;
        });
    });
    // Wait for the FIRST worker to genuinely start executing, not merely for
    // admission to succeed - active_worker_count() flips before the OS thread is
    // ever scheduled, so gating on that alone could race a not-yet-running first
    // worker and let a would-be-erroneous second spawn slip past unobserved.
    REQUIRE(first_started_fut.wait_for(5s) == std::future_status::ready);
    auto r2 = ex.run(IoClass::File, "dup", 1s, [spawns] {
        spawns->fetch_add(1);
        return 2;
    });
    CHECK_FALSE(r2.has_value());
    CHECK(r2.error() == IoFailure::AlreadyRunning);
    // Give a hypothetical erroneously-spawned second worker ample time to run and
    // increment spawns before asserting it never did - an instant read here would
    // let a real single-flight regression pass if that second thread simply hadn't
    // been scheduled yet.
    std::this_thread::sleep_for(100ms);
    CHECK(spawns->load() == 1); // the second call never spawned a worker
    gate->release();
    caller.join();
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
}

TEST_CASE("run: file-lane saturation does not block a service read (per-type bulkhead)",
          "[spark][ioexecutor]") {
    GuardianIoExecutor ex{GuardianIoExecutor::Config{
        .file_quota = 2, .registry_quota = 2, .service_quota = 2}};
    auto gate = std::make_shared<Gate>();
    std::vector<std::thread> callers;
    auto park = [&](IoClass c, std::string k) {
        callers.emplace_back([&ex, gate, c, k] {
            ex.run(c, k, 30s, [gate] {
                gate->wait();
                return 0;
            });
        });
    };
    park(IoClass::File, "f1");
    park(IoClass::File, "f2");
    REQUIRE(spin_until([&] { return ex.active_worker_count(IoClass::File) == 2; }));

    // A third file read hits the per-type quota.
    auto rf = ex.run(IoClass::File, "f3", 1s, [gate] {
        gate->wait();
        return 0;
    });
    CHECK(rf.error() == IoFailure::CapacityExhausted);

    // A service read is unaffected: the file lane is full but the service quota is
    // free, and the derived process bound (2+2+2=6) never binds before a class cap.
    auto rs = ex.run(IoClass::Service, "s1", 5s, [] { return 5; });
    REQUIRE(rs.has_value());
    CHECK(*rs == 5);

    gate->release();
    for (auto& t : callers)
        t.join();
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
}

TEST_CASE("run: a saturated file+registry lane never starves the service lane (R3 exact bulkheads)",
          "[spark][ioexecutor]") {
    // The default config is the shipped-bug shape: File 4 + Registry 3 = 7 workers.
    // Under the old independent total_quota{8} that left Service just 1 of its 3
    // slots. With the derived process bound (== sum of class quotas, so exact
    // bulkheads) a saturated file+registry lane leaves Service its full 3 slots.
    GuardianIoExecutor ex; // defaults: 4 / 3 / 3
    auto gate = std::make_shared<Gate>();
    std::vector<std::thread> callers;
    auto park = [&](IoClass c, std::string k) {
        callers.emplace_back([&ex, gate, c, k] {
            ex.run(c, k, 30s, [gate] {
                gate->wait();
                return 0;
            });
        });
    };
    // Saturate File (4) and Registry (3): 7 workers, the exact old-total-quota point.
    park(IoClass::File, "f1");
    park(IoClass::File, "f2");
    park(IoClass::File, "f3");
    park(IoClass::File, "f4");
    park(IoClass::Registry, "r1");
    park(IoClass::Registry, "r2");
    park(IoClass::Registry, "r3");
    REQUIRE(spin_until([&] { return ex.active_worker_count() == 7; }));

    // All THREE service reads are admitted - the service lane keeps its full quota,
    // no cross-lane starvation. (Under the old total_quota{8} the 8th worker would
    // admit and the 9th+ reject, capping service at 1.)
    park(IoClass::Service, "s1");
    park(IoClass::Service, "s2");
    park(IoClass::Service, "s3");
    REQUIRE(spin_until([&] { return ex.active_worker_count(IoClass::Service) == 3; }));

    // A 4th service read hits the service class cap (3), not the process bound.
    auto rs4 = ex.run(IoClass::Service, "s4", 1s, [gate] {
        gate->wait();
        return 0;
    });
    CHECK(rs4.error() == IoFailure::CapacityExhausted);

    gate->release();
    for (auto& t : callers)
        t.join();
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
}

TEST_CASE("stop wakes an in-flight submitter, snapshots the shutdown count, and rejects new reads",
          "[spark][ioexecutor]") {
    GuardianIoExecutor ex;
    auto gate = std::make_shared<Gate>();
    std::promise<IoResult<int>> pr;
    auto fut = pr.get_future();
    std::thread caller([&] {
        pr.set_value(ex.run(IoClass::File, "k", 30s, [gate] {
            gate->wait();
            return 3;
        }));
    });
    REQUIRE(spin_until([&] { return ex.active_worker_count() == 1; }));

    ex.stop();
    REQUIRE(fut.wait_for(2s) == std::future_status::ready);
    CHECK(fut.get().error() == IoFailure::Stopped); // the parked submitter was woken
    CHECK(ex.stats().active_at_shutdown[kFile] == 1); // per-class shutdown snapshot

    auto r2 = ex.run(IoClass::File, "k2", 1s, [] { return 9; }); // every post-stop call is Stopped
    CHECK(r2.error() == IoFailure::Stopped);

    gate->release();
    caller.join();
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
}

TEST_CASE("stop racing concurrent admission never crashes and yields only valid outcomes",
          "[spark][ioexecutor]") {
    GuardianIoExecutor ex;
    std::atomic<bool> start{false};
    std::vector<std::thread> threads;
    for (int i = 0; i < 8; ++i) {
        threads.emplace_back([&ex, &start, i] {
            while (!start.load())
                std::this_thread::yield();
            for (int j = 0; j < 20; ++j) {
                auto r = ex.run(IoClass::Registry, "k" + std::to_string(i), 50ms, [] { return 1; });
                (void)r; // any outcome is acceptable; the point is no crash / terminate
            }
        });
    }
    start.store(true);
    std::this_thread::sleep_for(5ms);
    ex.stop();
    for (auto& t : threads)
        t.join();
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
    SUCCEED("no crash under the stop/admission race");
}

TEST_CASE("a failed worker launch rolls admission back and frees the key", "[spark][ioexecutor]") {
    GuardianIoExecutor ex;
    ex.set_fail_launch_for_test(true);
    auto r = ex.run(IoClass::File, "k", 1s, [] { return 1; });
    CHECK(r.error() == IoFailure::LaunchFailed);
    CHECK(ex.active_worker_count() == 0); // rolled back, not leaked
    CHECK(ex.stats().counters[kFile].launch_failures == 1);

    // The key was freed by the rollback: a real read for the same key now succeeds.
    ex.set_fail_launch_for_test(false);
    auto r2 = ex.run(IoClass::File, "k", 5s, [] { return 2; });
    REQUIRE(r2.has_value());
    CHECK(*r2 == 2);
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
}

TEST_CASE("a throwing read body maps to WorkerThrew and never terminates", "[spark][ioexecutor]") {
    GuardianIoExecutor ex;
    auto r = ex.run(IoClass::Service, "k", 5s, []() -> int { throw std::runtime_error("boom"); });
    CHECK_FALSE(r.has_value());
    CHECK(r.error() == IoFailure::WorkerThrew);
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
    CHECK(ex.stats().counters[kSvc].worker_exceptions == 1);
}

TEST_CASE("the executor may be destroyed while a worker is still blocked (no UAF)",
          "[spark][ioexecutor]") {
    auto gate = std::make_shared<Gate>();
    auto done = std::make_shared<std::promise<void>>();
    auto fut = done->get_future();
    {
        GuardianIoExecutor ex;
        auto r = ex.run(IoClass::File, "k", 20ms, [gate, done]() -> int {
            gate->wait();
            done->set_value();
            return 1;
        });
        CHECK(r.error() == IoFailure::Timeout);
        CHECK(ex.active_worker_count() == 1);
        // ex is destroyed here while the worker is still blocked; State stays alive
        // through the worker's shared_ptr, so its later publish + ticket release do
        // not use-after-free.
    }
    gate->release();
    REQUIRE(fut.wait_for(5s) == std::future_status::ready);
    // Let the trampoline epilogue (publish + ticket release against the still-alive
    // State) finish before the test returns - no orphan worker at process exit.
    std::this_thread::sleep_for(50ms);
    SUCCEED("worker released after executor destruction without UAF");
}

TEST_CASE("a slot and its key are reclaimed after a timed-out worker finally finishes",
          "[spark][ioexecutor]") {
    GuardianIoExecutor ex;
    auto gate = std::make_shared<Gate>();
    auto r = ex.run(IoClass::File, "k", 20ms, [gate] {
        gate->wait();
        return 1;
    });
    CHECK(r.error() == IoFailure::Timeout);
    CHECK(ex.active_worker_count() == 1);

    // Still single-flighted while the worker is wedged.
    auto dup = ex.run(IoClass::File, "k", 20ms, [] { return 2; });
    CHECK(dup.error() == IoFailure::AlreadyRunning);

    gate->release();
    REQUIRE(spin_until([&] { return ex.active_worker_count() == 0; }));

    // Reclaimed: a fresh same-key read runs.
    auto r2 = ex.run(IoClass::File, "k", 5s, [] { return 3; });
    REQUIRE(r2.has_value());
    CHECK(*r2 == 3);
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
}

TEST_CASE("the same key string under different IoClass values is independent",
          "[spark][ioexecutor]") {
    GuardianIoExecutor ex;
    auto gate = std::make_shared<Gate>();
    std::thread caller([&] {
        ex.run(IoClass::File, "same", 30s, [gate] {
            gate->wait();
            return 0;
        });
    });
    REQUIRE(spin_until([&] { return ex.active_worker_count(IoClass::File) == 1; }));

    // A Registry read with the SAME key string is a different op key -> admitted.
    auto r = ex.run(IoClass::Registry, "same", 5s, [] { return 8; });
    REQUIRE(r.has_value());
    CHECK(*r == 8);

    gate->release();
    caller.join();
    CHECK(spin_until([&] { return ex.active_worker_count() == 0; }));
}
