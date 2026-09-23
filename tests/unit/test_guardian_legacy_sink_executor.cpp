// test_guardian_legacy_sink_executor.cpp - direct, isolated coverage of
// GuardianLegacySinkExecutor (#4783 commit 2), independent of GuardianEngine's own
// call graph (not wired in yet - a later commit's job). Fast and deterministic:
// every "stall"/"block" here is a test-controlled condition_variable, never a real
// network wait.

#include "guardian_legacy_sink_executor.hpp"

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <spdlog/spdlog.h>

using namespace yuzu::agent;
using namespace std::chrono_literals;

using yuzu::test::kSpinScale;
using yuzu::test::ScopeExit;
using yuzu::test::spin_until;

namespace {

using Event = GuardianLegacySinkExecutor::Event;
using OfferOutcome = GuardianLegacySinkExecutor::OfferOutcome;
using LaunchFaultForTest = GuardianLegacySinkExecutor::LaunchFaultForTest;
using AdmissionFaultForTest = GuardianLegacySinkExecutor::AdmissionFaultForTest;

Event make_event(const std::string& rule_id, const std::string& event_type,
                 const std::string& guard_type = "file", const std::string& rule_name = "rn") {
    Event ev;
    ev.set_rule_id(rule_id);
    ev.set_event_type(event_type);
    ev.set_guard_type(guard_type);
    ev.set_rule_name(rule_name);
    ev.set_event_id(rule_id + "-" + event_type);
    return ev;
}

/// A send that blocks until release() is called, then returns `result`. Mirrors
/// test_guardian_outbox_send_executor.cpp's StallingSend.
struct StallingSend {
    std::mutex mu;
    std::condition_variable cv;
    bool release_flag{false};
    std::atomic<int> invocations{0};
    LegacySendOutcome result{LegacySendOutcome::Sent};

    LegacySendOutcome operator()(const Event&) {
        invocations.fetch_add(1);
        std::unique_lock<std::mutex> lk{mu};
        cv.wait(lk, [&] { return release_flag; });
        return result;
    }
    void release() {
        {
            std::lock_guard<std::mutex> lk{mu};
            release_flag = true;
        }
        cv.notify_all();
    }
};

/// A send that records every invocation (rule_id, event_type) in order, thread-safely,
/// and returns a fixed outcome. Used for the FIFO/ordering tests.
struct RecordingSend {
    std::mutex mu;
    std::vector<std::pair<std::string, std::string>> invocations;
    LegacySendOutcome result{LegacySendOutcome::Sent};

    LegacySendOutcome operator()(const Event& ev) {
        std::lock_guard<std::mutex> lk{mu};
        invocations.emplace_back(ev.rule_id(), ev.event_type());
        return result;
    }
    std::size_t count() {
        std::lock_guard<std::mutex> lk{mu};
        return invocations.size();
    }
};

/// Runs `fn` on a detached helper thread and requires it to complete within
/// `timeout` (sanitizer-scaled, matching spin_until's convention). If `fn` never
/// returns - a suspected self-deadlock in the code under test, not an ordinary
/// test failure - this logs via spdlog::critical and std::abort()s, so CI reports
/// a clean, diagnosable crash rather than relying on meson's outer `timeout:` to
/// silently kill the whole binary with nothing to point at (matches this repo's
/// WorkerHostileMutex "crash with a diagnostic beats a silent kill" posture). The
/// helper thread is intentionally leaked/detached on the failure path: if `fn()`
/// truly never returns, the process is about to abort() anyway.
void require_completes_within(std::chrono::milliseconds timeout, const char* what,
                              std::function<void()> fn) {
    auto done = std::make_shared<std::atomic<bool>>(false);
    std::thread t([fn = std::move(fn), done]() mutable {
        fn();
        done->store(true, std::memory_order_release);
    });
    t.detach();
    const auto deadline = std::chrono::steady_clock::now() + timeout * kSpinScale;
    while (!done->load(std::memory_order_acquire)) {
        if (std::chrono::steady_clock::now() >= deadline) {
            try {
                spdlog::critical("test watchdog: '{}' did not complete within {}ms - "
                                 "suspected hang/deadlock in the code under test",
                                 what, timeout.count());
            } catch (...) {
            }
            std::abort();
        }
        std::this_thread::sleep_for(1ms);
    }
}

} // namespace

TEST_CASE("offer() delivers a fast send and physical count returns to 0",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    auto outcome = exec.offer(make_event("r1", "drift.detected"),
                              [](const Event&) { return LegacySendOutcome::Sent; });
    CHECK(outcome == OfferOutcome::Queued);
    REQUIRE(exec.wait_workers_retired_for_test(5s));
    auto s = exec.stats();
    CHECK(s.events_lost == 0);
    CHECK(s.send_failures == 0);
}

TEST_CASE("a blocked send is observable via has_in_flight_send() and active_worker_count()",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    StallingSend send;
    ScopeExit cleanup{[&] {
        send.release();
        CHECK(exec.wait_workers_retired_for_test(5s));
    }};

    auto outcome = exec.offer(make_event("r1", "drift.detected"), std::ref(send));
    CHECK(outcome == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return send.invocations.load() >= 1; }));
    CHECK(exec.has_in_flight_send());
    CHECK(exec.active_worker_count() == 1);
}

TEST_CASE("FIFO: A-drift, A-compliant, A-drift are delivered in admission order, "
          "never coalesced",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    RecordingSend send;

    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(send)) == OfferOutcome::Queued);
    CHECK(exec.offer(make_event("A", "guard.compliant"), std::ref(send)) == OfferOutcome::Queued);
    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(send)) == OfferOutcome::Queued);

    REQUIRE(spin_until([&] { return send.count() == 3; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    std::lock_guard<std::mutex> lk{send.mu};
    REQUIRE(send.invocations.size() == 3);
    CHECK(send.invocations[0] == std::pair<std::string, std::string>{"A", "drift.detected"});
    CHECK(send.invocations[1] == std::pair<std::string, std::string>{"A", "guard.compliant"});
    CHECK(send.invocations[2] == std::pair<std::string, std::string>{"A", "drift.detected"});
}

TEST_CASE("mixed rules interleaved keep each rule's own event ordering",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    RecordingSend send;

    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(send)) == OfferOutcome::Queued);
    CHECK(exec.offer(make_event("B", "guard.compliant"), std::ref(send)) == OfferOutcome::Queued);
    CHECK(exec.offer(make_event("A", "drift.remediated"), std::ref(send)) == OfferOutcome::Queued);
    CHECK(exec.offer(make_event("B", "guard.unhealthy"), std::ref(send)) == OfferOutcome::Queued);

    REQUIRE(spin_until([&] { return send.count() == 4; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    std::lock_guard<std::mutex> lk{send.mu};
    REQUIRE(send.invocations.size() == 4);
    // Overall admission order preserved (single FIFO queue, no per-rule reordering).
    CHECK(send.invocations[0] == std::pair<std::string, std::string>{"A", "drift.detected"});
    CHECK(send.invocations[1] == std::pair<std::string, std::string>{"B", "guard.compliant"});
    CHECK(send.invocations[2] == std::pair<std::string, std::string>{"A", "drift.remediated"});
    CHECK(send.invocations[3] == std::pair<std::string, std::string>{"B", "guard.unhealthy"});
}

TEST_CASE("count-bound refusal counts, gaps, and leaves earlier events untouched",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor::Config cfg;
    cfg.max_events = 1;
    GuardianLegacySinkExecutor exec{cfg};
    StallingSend send;
    ScopeExit cleanup{[&] {
        send.release();
        CHECK(exec.wait_workers_retired_for_test(5s));
    }};

    // First offer is admitted and immediately picked up by the worker (blocked in
    // the send), so the queue is empty again by the time the second offer checks
    // the bound - spin until the worker has actually dequeued it before offering
    // the second event, or the count bound never actually triggers.
    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(send)) == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return send.invocations.load() >= 1; }));

    // Now queue capacity is exhausted by a second event sitting in the (max_events=1)
    // queue while A is in flight; a THIRD offer must be refused.
    CHECK(exec.offer(make_event("B", "drift.detected"),
                     [](const Event&) { return LegacySendOutcome::Sent; }) ==
         OfferOutcome::Queued);
    auto refused = exec.offer(make_event("C", "drift.detected"),
                              [](const Event&) { return LegacySendOutcome::Sent; });
    CHECK(refused == OfferOutcome::RefusedCapacity);

    auto s = exec.stats();
    CHECK(s.backpressure_drops == 1);
    CHECK(s.events_lost == 1);
    CHECK(s.gap_rules == 1);
    auto gaps = exec.gapped_rules_needing_repair(10);
    REQUIRE(gaps.size() == 1);
    CHECK(gaps[0].first == "C");
}

TEST_CASE("bytes-bound refusal counts, gaps, and leaves earlier events untouched",
          "[guardian][legacy_sink]") {
    Event probe = make_event("A", "drift.detected");
    const auto one_event_bytes = probe.ByteSizeLong();

    GuardianLegacySinkExecutor::Config cfg;
    cfg.max_events = 100;
    cfg.max_bytes = one_event_bytes; // room for exactly one queued event
    GuardianLegacySinkExecutor exec{cfg};
    StallingSend send;
    ScopeExit cleanup{[&] {
        send.release();
        CHECK(exec.wait_workers_retired_for_test(5s));
    }};

    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(send)) == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return send.invocations.load() >= 1; }));

    CHECK(exec.offer(make_event("B", "drift.detected"),
                     [](const Event&) { return LegacySendOutcome::Sent; }) ==
         OfferOutcome::Queued);
    auto refused = exec.offer(make_event("C", "drift.detected"),
                              [](const Event&) { return LegacySendOutcome::Sent; });
    CHECK(refused == OfferOutcome::RefusedCapacity);

    auto s = exec.stats();
    CHECK(s.backpressure_drops == 1);
    CHECK(s.events_lost == 1);
    CHECK(s.gap_rules == 1);
}

TEST_CASE("admission-fault injection (ThrowOnTicket) refuses admission, leaves state "
          "unchanged, records a gap, and the next ordinary offer succeeds",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    exec.set_admission_fault_for_test(AdmissionFaultForTest::ThrowOnTicket);

    auto outcome = exec.offer(make_event("A", "drift.detected"),
                              [](const Event&) { return LegacySendOutcome::Sent; });
    CHECK(outcome == OfferOutcome::RefusedAdmission);
    CHECK(exec.pending_count_for_test() == 0);
    CHECK(exec.active_worker_count() == 0);
    auto s = exec.stats();
    CHECK(s.admission_failures == 1);
    CHECK(s.events_lost == 1);
    CHECK(s.gap_rules == 1);

    exec.set_admission_fault_for_test(AdmissionFaultForTest::None);
    RecordingSend send;
    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(send)) == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return send.count() == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));
}

TEST_CASE("admission-fault injection (ThrowOnNode) refuses admission, leaves state "
          "unchanged, records a gap, and the next ordinary offer succeeds",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    exec.set_admission_fault_for_test(AdmissionFaultForTest::ThrowOnNode);

    auto outcome = exec.offer(make_event("A", "drift.detected"),
                              [](const Event&) { return LegacySendOutcome::Sent; });
    CHECK(outcome == OfferOutcome::RefusedAdmission);
    CHECK(exec.pending_count_for_test() == 0);
    CHECK(exec.active_worker_count() == 0);
    auto s = exec.stats();
    CHECK(s.admission_failures == 1);
    CHECK(s.events_lost == 1);
    CHECK(s.gap_rules == 1);

    exec.set_admission_fault_for_test(AdmissionFaultForTest::None);
    RecordingSend send;
    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(send)) == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return send.count() == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));
}

TEST_CASE("launch retry: a same-key repeat offer relaunches after SpawnRefused",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    exec.set_launch_fault_for_test(LaunchFaultForTest::SpawnRefused);

    auto first = exec.offer(make_event("A", "drift.detected"),
                            [](const Event&) { return LegacySendOutcome::Sent; });
    CHECK(first == OfferOutcome::Queued);
    // The launch failed - nothing is running, but the item stays queued.
    REQUIRE(spin_until([&] { return exec.active_worker_count() == 0; }));
    CHECK(exec.pending_count_for_test() == 1);
    CHECK(exec.stats().launch_failures >= 1);

    exec.set_launch_fault_for_test(LaunchFaultForTest::None);
    RecordingSend send;
    // Same key ("A") offered again - launch eligibility is re-evaluated on THIS
    // offer's own outcome regardless of key. This second offer's own event is
    // what drains via `send`; the first (stranded) item drains via its own
    // lambda, ahead of it in FIFO order.
    auto second = exec.offer(make_event("A", "drift.detected"), std::ref(send));
    CHECK(second == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return send.count() == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));
    CHECK(exec.pending_count_for_test() == 0); // both items (stranded + this one) drained
}

TEST_CASE("launch retry: a capacity-refused offer still relaunches the stranded worker",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor::Config cfg;
    cfg.max_events = 1;
    GuardianLegacySinkExecutor exec{cfg};
    exec.set_launch_fault_for_test(LaunchFaultForTest::SpawnRefused);

    auto first = exec.offer(make_event("A", "drift.detected"),
                            [](const Event&) { return LegacySendOutcome::Sent; });
    CHECK(first == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return exec.active_worker_count() == 0; }));
    CHECK(exec.pending_count_for_test() == 1);

    // Queue is now full (max_events=1) - this offer is refused on capacity, but
    // launch eligibility is STILL evaluated for it (property 3: "regardless of
    // outcome").
    auto refused = exec.offer(make_event("B", "drift.detected"),
                              [](const Event&) { return LegacySendOutcome::Sent; });
    CHECK(refused == OfferOutcome::RefusedCapacity);

    exec.set_launch_fault_for_test(LaunchFaultForTest::None);
    // A THIRD offer, still refused on capacity (queue still full of A), must
    // relaunch the worker that will drain A.
    RecordingSend send;
    auto refused2 = exec.offer(make_event("C", "drift.detected"), std::ref(send));
    CHECK(refused2 == OfferOutcome::RefusedCapacity);
    REQUIRE(exec.wait_workers_retired_for_test(5s));
    CHECK(exec.pending_count_for_test() == 0);
}

TEST_CASE("launch retry: kick() alone relaunches a stranded queue with zero new offers",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    exec.set_launch_fault_for_test(LaunchFaultForTest::SpawnRefused);

    RecordingSend send;
    auto first = exec.offer(make_event("A", "drift.detected"), std::ref(send));
    CHECK(first == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return exec.active_worker_count() == 0; }));
    CHECK(exec.pending_count_for_test() == 1);
    CHECK(send.count() == 0); // never launched

    exec.set_launch_fault_for_test(LaunchFaultForTest::None);
    exec.kick(); // no new offer() call at all
    REQUIRE(spin_until([&] { return send.count() == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));
}

TEST_CASE("B offered while A's launch is still outstanding does not double-launch, "
          "and both drain once the retried launch succeeds",
          "[guardian][legacy_sink][chaos]") {
    // Design note (documented per the task instructions - the delivery plan's
    // §3.1 sketch does not spell out a mechanism for this specific interleaving):
    // set_pre_launch_race_hook_for_test() fires on the calling thread, with
    // state_->mu NOT held, right before attempt_launch()'s actual spawn attempt -
    // i.e. exactly in the window the plan describes as "A's launch outstanding".
    // The hook synchronously offers B from inside A's own offer() call, so B's
    // offer() observes worker_running already true (set by A's offer before
    // releasing the lock) and simply enqueues without attempting a second launch -
    // deterministic via call ordering, no real thread race needed.
    GuardianLegacySinkExecutor exec;
    exec.set_launch_fault_for_test(LaunchFaultForTest::SpawnRefused);
    RecordingSend send;

    bool hook_fired = false;
    exec.set_pre_launch_race_hook_for_test([&] {
        hook_fired = true;
        auto outcome = exec.offer(make_event("B", "drift.detected"), std::ref(send));
        // B must be queued (not itself attempt a launch - if it did, and launch
        // is still faulted, it would just also fail harmlessly, but the point of
        // this test is that it does not need to: worker_running is already true).
        CHECK(outcome == OfferOutcome::Queued);
    });

    auto a_outcome = exec.offer(make_event("A", "drift.detected"), std::ref(send));
    CHECK(a_outcome == OfferOutcome::Queued);
    CHECK(hook_fired);
    exec.set_pre_launch_race_hook_for_test(nullptr);

    // A's launch failed (SpawnRefused); both A and B are stranded in the queue.
    REQUIRE(spin_until([&] { return exec.active_worker_count() == 0; }));
    CHECK(exec.pending_count_for_test() == 2);
    CHECK(send.count() == 0);

    exec.set_launch_fault_for_test(LaunchFaultForTest::None);
    exec.kick();
    REQUIRE(spin_until([&] { return send.count() == 2; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    std::lock_guard<std::mutex> lk{send.mu};
    REQUIRE(send.invocations.size() == 2);
    CHECK(send.invocations[0].first == "A");
    CHECK(send.invocations[1].first == "B");
}

TEST_CASE("stop() discards the backlog (counted) but does not touch an in-flight send",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    StallingSend send;
    ScopeExit cleanup{[&] {
        send.release();
        CHECK(exec.wait_workers_retired_for_test(5s));
    }};

    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(send)) == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return send.invocations.load() >= 1; })); // A is in flight

    RecordingSend send_b;
    CHECK(exec.offer(make_event("B", "drift.detected"), std::ref(send_b)) ==
         OfferOutcome::Queued); // B is queued behind A
    CHECK(exec.pending_count_for_test() == 1);

    require_completes_within(5s, "stop() while a send is in flight", [&] { exec.stop(); });

    auto s = exec.stats();
    CHECK(s.discarded_at_stop == 1); // B was discarded, not sent
    CHECK(exec.pending_count_for_test() == 0);
    CHECK(exec.has_in_flight_send()); // A is untouched by stop()
    CHECK(exec.active_worker_count() == 1);
    CHECK(send_b.count() == 0);

    // A offer after stop() is refused, never queued.
    auto after_stop = exec.offer(make_event("C", "drift.detected"),
                                 [](const Event&) { return LegacySendOutcome::Sent; });
    CHECK(after_stop == OfferOutcome::RefusedStopping);
}

TEST_CASE("a worker thread can still be spawned just after stopping() becomes true - "
          "documented safe case, it retires without touching the cleared backlog",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    // Admission committed BEFORE stop(), with the launch itself held back by a
    // SpawnRefused fault - reproducing "admission committed -> stop() -> spawn"
    // deterministically: worker_running is already true and the item is queued,
    // then stop() clears the (already-admitted) backlog, then a later kick()
    // (with the fault cleared) is the "spawn after stopping=true" moment.
    exec.set_launch_fault_for_test(LaunchFaultForTest::SpawnRefused);
    RecordingSend send;
    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(send)) == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return exec.active_worker_count() == 0; }));

    exec.stop();
    CHECK(exec.pending_count_for_test() == 0);

    exec.set_launch_fault_for_test(LaunchFaultForTest::None);
    // kick() itself does not spawn once stopping (worker_running is false but the
    // queue is empty), so directly exercise the actually-interesting case: a
    // worker created after stopping observes stopping+empty and retires cleanly.
    exec.kick();
    CHECK_FALSE(spin_until([&] { return send.count() >= 1; }, 200ms));
    CHECK(exec.active_worker_count() == 0);
}

TEST_CASE("a send already dequeued keeps running to completion after stop() returns",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    StallingSend send;
    ScopeExit cleanup{[&] {
        send.release();
        CHECK(exec.wait_workers_retired_for_test(5s));
    }};

    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(send)) == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return send.invocations.load() >= 1; }));

    require_completes_within(5s, "stop() must not block on an in-flight send",
                             [&] { exec.stop(); });
    CHECK(exec.active_worker_count() == 1); // still counted - not yet retired

    send.release();
    REQUIRE(exec.wait_workers_retired_for_test(5s));
    CHECK(exec.active_worker_count() == 0);
    // The completion still ran its normal accounting (Sent, no failure counters).
    auto s = exec.stats();
    CHECK(s.send_failures == 0);
    CHECK(s.send_exceptions == 0);
}

TEST_CASE("a quiet, fully-stalled queue (no new offers) is observed via kick()",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor::Config cfg;
    cfg.stall_threshold = 30ms;
    GuardianLegacySinkExecutor exec{cfg};
    StallingSend send;
    ScopeExit cleanup{[&] {
        send.release();
        CHECK(exec.wait_workers_retired_for_test(5s));
    }};

    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(send)) == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return send.invocations.load() >= 1; }));
    CHECK(exec.stats().stalls == 0); // not yet past the threshold

    std::this_thread::sleep_for(60ms * kSpinScale);
    // NO new offer() call anywhere in this test up to this point - kick() is the
    // ONLY thing that can notice the stall.
    exec.kick();
    CHECK(exec.stats().stalls == 1);

    // A second kick() before completion does not double-count.
    exec.kick();
    CHECK(exec.stats().stalls == 1);
}

TEST_CASE("WriteFailed counts send_failures and records a gap", "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    auto outcome = exec.offer(make_event("A", "drift.detected"),
                              [](const Event&) { return LegacySendOutcome::WriteFailed; });
    CHECK(outcome == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return exec.stats().send_failures == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    auto s = exec.stats();
    CHECK(s.send_failures == 1);
    CHECK(s.events_lost == 1);
    CHECK(s.gap_rules == 1);
    auto gaps = exec.gapped_rules_needing_repair(10);
    REQUIRE(gaps.size() == 1);
    CHECK(gaps[0].first == "A");
    CHECK(gaps[0].second.guard_type == "file");
}

TEST_CASE("LinkDown counts dropped_link_down with NO gap recorded",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    auto outcome = exec.offer(make_event("A", "drift.detected"),
                              [](const Event&) { return LegacySendOutcome::LinkDown; });
    CHECK(outcome == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return exec.stats().dropped_link_down == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    auto s = exec.stats();
    CHECK(s.dropped_link_down == 1);
    CHECK(s.events_lost == 0); // NOT a loss - D4b
    CHECK(s.gap_rules == 0);   // NOT a gap - D4b
}

TEST_CASE("a throwing send counts send_exceptions, records a gap, and the worker "
          "continues to the next item",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    RecordingSend send_b;
    CHECK(exec.offer(make_event("A", "drift.detected"),
                     [](const Event&) -> LegacySendOutcome {
                         throw std::runtime_error("send boom");
                     }) == OfferOutcome::Queued);
    CHECK(exec.offer(make_event("B", "drift.detected"), std::ref(send_b)) ==
         OfferOutcome::Queued);

    REQUIRE(spin_until([&] { return send_b.count() == 1; })); // worker survived A's throw
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    auto s = exec.stats();
    CHECK(s.send_exceptions == 1);
    CHECK(s.events_lost == 1);
    CHECK(s.gap_rules == 1);
    CHECK(s.worker_faults == 0); // the send's own throw is caught locally, not a
                                 // whole-iteration fault
}

TEST_CASE("a gap-ledger fault degrades gap_ledger_degraded instead of crashing the "
          "worker, which continues to the next item",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    exec.set_admission_fault_for_test(AdmissionFaultForTest::ThrowOnGapLedger);

    RecordingSend send_b;
    CHECK(exec.offer(make_event("A", "drift.detected"),
                     [](const Event&) { return LegacySendOutcome::WriteFailed; }) ==
         OfferOutcome::Queued);

    REQUIRE(spin_until([&] { return exec.stats().send_failures == 1; }));
    exec.set_admission_fault_for_test(AdmissionFaultForTest::None);
    CHECK(exec.offer(make_event("B", "drift.detected"), std::ref(send_b)) ==
         OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return send_b.count() == 1; })); // worker kept going
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    auto s = exec.stats();
    CHECK(s.gap_ledger_faults >= 1);
    CHECK(s.gap_rules == 0); // the gap itself never got recorded - the ledger
                             // write is exactly what failed
}

TEST_CASE("ticket rollback on a refused launch has no self-deadlock",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    exec.set_launch_fault_for_test(LaunchFaultForTest::SpawnRefused);

    require_completes_within(5s, "offer() after a SpawnRefused launch rollback", [&] {
        auto outcome = exec.offer(make_event("A", "drift.detected"),
                                  [](const Event&) { return LegacySendOutcome::Sent; });
        CHECK(outcome == OfferOutcome::Queued);
    });
    // If attempt_launch()'s rollback self-deadlocked on the executor's own
    // mutex, THIS call would hang forever - it must be callable immediately.
    require_completes_within(5s, "active_worker_count() right after a SpawnRefused rollback",
                             [&] { CHECK(exec.active_worker_count() == 0); });

    exec.set_launch_fault_for_test(LaunchFaultForTest::None);
    exec.kick();
    REQUIRE(exec.wait_workers_retired_for_test(5s));
}

TEST_CASE("gap repair lifecycle: recorded, listed, Sent clears it, anything else "
          "leaves the gap but resets repair_seq to 0",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;

    // Create a gap via a WriteFailed send.
    CHECK(exec.offer(make_event("A", "drift.detected"),
                     [](const Event&) { return LegacySendOutcome::WriteFailed; }) ==
         OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return exec.stats().gap_rules == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    auto gaps = exec.gapped_rules_needing_repair(10);
    REQUIRE(gaps.size() == 1);
    CHECK(gaps[0].first == "A");
    CHECK(gaps[0].second.repair_seq == 0);

    // A repair that fails (WriteFailed again) leaves the gap but resets
    // repair_seq to 0 so the NEXT kick can retry.
    CHECK(exec.offer(make_event("A", "guard.unhealthy"),
                     [](const Event&) { return LegacySendOutcome::WriteFailed; },
                     /*is_gap_repair=*/true) == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return exec.stats().send_failures == 2; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));
    gaps = exec.gapped_rules_needing_repair(10);
    REQUIRE(gaps.size() == 1);
    CHECK(gaps[0].second.repair_seq == 0);
    CHECK(gaps[0].second.lost == 2);

    // A repair that succeeds (Sent) clears the gap entirely.
    CHECK(exec.offer(make_event("A", "guard.unhealthy"),
                     [](const Event&) { return LegacySendOutcome::Sent; },
                     /*is_gap_repair=*/true) == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return exec.stats().gap_rules == 0; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));
    CHECK(exec.gapped_rules_needing_repair(10).empty());
}

// ── #4783 follow-up review: seq-guarded clearing + dequeue-time supersession ─
//
// These four cases prove the fix's parts (a) (seq-guarded clearing) and (b)
// (dequeue-time supersession) at the executor level, independently of one
// another - see this file's own header comment and the class doc comment in
// guardian_legacy_sink_executor.hpp for the full design. Test 1 and test 4
// would each fail under the REJECTED "clear on any Sent" naive fix (part (a)
// alone, without the seq guard); test 3 would fail if supersession were only
// checked at kick/fire time instead of at dequeue (part (b)).

TEST_CASE("#4783 gap: an in-flight OLDER send completing Sent does not clear a "
          "NEWER loss recorded for the same rule while it was still in flight",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor::Config cfg;
    cfg.max_events = 1;
    GuardianLegacySinkExecutor exec{cfg};
    StallingSend blocking;
    ScopeExit cleanup{[&] {
        blocking.release();
        CHECK(exec.wait_workers_retired_for_test(5s));
    }};

    // A1: dequeued into flight almost immediately - the queue is empty again by
    // the time A2 is offered.
    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(blocking)) ==
         OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return blocking.invocations.load() >= 1; }));

    // A2: admitted into the now-empty (max_events=1) queue - a filler that
    // drains normally once A1 completes.
    RecordingSend filler;
    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(filler)) ==
         OfferOutcome::Queued);

    // A3: the queue already holds A2 -> refused capacity, opening a gap whose
    // lost_seq is A3's own (newest) admission-time seq.
    auto refused = exec.offer(make_event("A", "drift.detected"),
                              [](const Event&) { return LegacySendOutcome::Sent; });
    CHECK(refused == OfferOutcome::RefusedCapacity);

    auto gaps_before = exec.gapped_rules_needing_repair(10);
    REQUIRE(gaps_before.size() == 1);
    const auto lost_seq_before = gaps_before[0].second.lost_seq;

    // Release A1 - both A1's and A2's Sent completions carry a STRICTLY OLDER
    // seq than A3's refusal, so NEITHER may clear the gap A3 opened. Under the
    // rejected "clear on any Sent" fix, A1 alone (let alone A2) would have
    // erased it here.
    blocking.release();
    REQUIRE(spin_until([&] { return filler.count() == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    auto gaps_after = exec.gapped_rules_needing_repair(10);
    REQUIRE(gaps_after.size() == 1);
    CHECK(gaps_after[0].second.lost_seq == lost_seq_before);
    CHECK(gaps_after[0].second.lost == 1); // still just the one recorded loss (A3)
}

TEST_CASE("#4783 gap: a fresh real Sent that postdates the loss clears the gap, "
          "and a subsequent kick() does not resurrect it",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;

    // Open a gap for A via a WriteFailed send.
    CHECK(exec.offer(make_event("A", "drift.detected"),
                     [](const Event&) { return LegacySendOutcome::WriteFailed; }) ==
         OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return exec.stats().gap_rules == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    // A fresh, ORDINARY (non-repair) event for A that succeeds - its
    // admission-time seq is strictly newer than the loss that opened the gap.
    RecordingSend send;
    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(send)) ==
         OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return send.count() == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    CHECK(exec.gapped_rules_needing_repair(10).empty());
    CHECK(exec.stats().gap_rules == 0);

    // kick() must not resurrect a gap a real delivery already closed - it only
    // relaunches a stranded worker / observes a stall, never rebuilds gaps.
    exec.kick();
    CHECK(exec.gapped_rules_needing_repair(10).empty());
    CHECK(exec.stats().gap_rules == 0);
}

TEST_CASE("#4783 gap: a queued repair superseded by a newer real Sent before "
          "reaching the front is suppressed at dequeue, never sent",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;

    // Open a gap for A.
    CHECK(exec.offer(make_event("A", "drift.detected"),
                     [](const Event&) { return LegacySendOutcome::WriteFailed; }) ==
         OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return exec.stats().gap_rules == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    // A fresh REAL event for A that will block - dequeued into flight
    // immediately (the queue is otherwise empty).
    StallingSend real_send;
    ScopeExit cleanup{[&] {
        real_send.release();
        CHECK(exec.wait_workers_retired_for_test(5s));
    }};
    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(real_send)) ==
         OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return real_send.invocations.load() >= 1; }));

    // Queue a repair for A behind the in-flight real event - its repair_seq is
    // stamped as the (currently) live one.
    RecordingSend repair_send;
    CHECK(exec.offer(make_event("A", "guard.unhealthy"), std::ref(repair_send),
                     /*is_gap_repair=*/true) == OfferOutcome::Queued);
    auto gaps_mid = exec.gapped_rules_needing_repair(10);
    REQUIRE(gaps_mid.size() == 1);
    CHECK(gaps_mid[0].second.repair_seq != 0);

    // Release the real event - it completes Sent with a NEWER seq than the
    // gap's lost_seq, clearing the gap per the previous test's mechanism.
    real_send.release();
    REQUIRE(spin_until([&] { return exec.stats().gap_rules == 0; }));

    // The queued repair now reaches the front of the FIFO - the gap it was
    // meant to repair is already gone, so it must be suppressed at dequeue,
    // never actually sent. A kick/fire-time-only check could not have caught
    // this: the repair was already queued (and thus already past any
    // kick-time check) before the real event's Sent cleared the gap.
    REQUIRE(exec.wait_workers_retired_for_test(5s));
    CHECK(repair_send.count() == 0);
    CHECK(exec.stats().repairs_suppressed == 1);
}

TEST_CASE("#4783 gap: a repair's own Sent does not clear a loss NEWER than the "
          "repair, and resets repair_seq so the next kick requeues a fresh one",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor::Config cfg;
    cfg.max_events = 1;
    GuardianLegacySinkExecutor exec{cfg};

    // Open a gap for A via an ordinary WriteFailed send.
    CHECK(exec.offer(make_event("A", "drift.detected"),
                     [](const Event&) { return LegacySendOutcome::WriteFailed; }) ==
         OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return exec.stats().gap_rules == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    // Queue a repair R for A - dequeued into flight immediately (queue empty).
    StallingSend blocking_repair;
    ScopeExit cleanup{[&] {
        blocking_repair.release();
        CHECK(exec.wait_workers_retired_for_test(5s));
    }};
    CHECK(exec.offer(make_event("A", "guard.unhealthy"), std::ref(blocking_repair),
                     /*is_gap_repair=*/true) == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return blocking_repair.invocations.load() >= 1; }));

    auto gaps_mid = exec.gapped_rules_needing_repair(10);
    REQUIRE(gaps_mid.size() == 1);
    REQUIRE(gaps_mid[0].second.repair_seq != 0);
    const auto repair_seq = gaps_mid[0].second.repair_seq;

    // A filler for A, admitted into the now-empty (max_events=1) queue.
    RecordingSend filler;
    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(filler)) ==
         OfferOutcome::Queued);

    // A fresh real offer for A - the queue is already full (filler) -> refused,
    // bumping lost_seq past R's own seq.
    auto refused = exec.offer(make_event("A", "drift.detected"),
                              [](const Event&) { return LegacySendOutcome::Sent; });
    CHECK(refused == OfferOutcome::RefusedCapacity);

    auto gaps_before_release = exec.gapped_rules_needing_repair(10);
    REQUIRE(gaps_before_release.size() == 1);
    CHECK(gaps_before_release[0].second.lost_seq > repair_seq);

    // Release R - its Sent carries an OLDER seq than the newest loss, so it
    // must NOT clear the gap; the repair itself completed, so repair_seq
    // resets to 0 so the next kick requeues a fresh repair covering the newer
    // loss. Under the rejected "clear on any Sent" fix, this Sent would have
    // erased the gap and silently lost the newer loss's evidence.
    blocking_repair.release();
    REQUIRE(spin_until([&] { return filler.count() == 1; }));
    REQUIRE(exec.wait_workers_retired_for_test(5s));

    auto gaps_after = exec.gapped_rules_needing_repair(10);
    REQUIRE(gaps_after.size() == 1);
    CHECK(gaps_after[0].second.repair_seq == 0);
}

TEST_CASE("wait_idle_for_test can read true while a retiring worker is still "
          "physically counted",
          "[guardian][legacy_sink]") {
    GuardianLegacySinkExecutor exec;
    StallingSend send;
    ScopeExit cleanup{[&] {
        send.release();
        CHECK(exec.wait_workers_retired_for_test(5s));
    }};

    CHECK(exec.offer(make_event("A", "drift.detected"), std::ref(send)) == OfferOutcome::Queued);
    REQUIRE(spin_until([&] { return send.invocations.load() >= 1; }));
    // Not idle yet: a send is in flight.
    CHECK_FALSE(exec.wait_idle_for_test(50ms));

    send.release();
    // Once the send returns, the queue empties and in_flight clears - idle
    // becomes true - but the worker's own trampoline may not have physically
    // retired (destroyed the ticket) at that exact instant. Both must eventually
    // hold; the distinction this test pins is that idle does not itself IMPLY
    // physical retirement.
    REQUIRE(exec.wait_idle_for_test(5s));
    REQUIRE(exec.wait_workers_retired_for_test(5s));
    CHECK(exec.active_worker_count() == 0);
}
