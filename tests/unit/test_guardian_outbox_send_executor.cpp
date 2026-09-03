// test_guardian_outbox_send_executor.cpp - direct, isolated coverage of
// GuardianOutboxSendExecutor (#2233 item 4), independent of GuardianOutboxDrainWorker's
// own call graph. Fast and deterministic: every "stall" here is a test-controlled
// condition_variable, never a real network wait.

#include "guardian_outbox_send_executor.hpp"

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <stdexcept>
#include <string>

using namespace yuzu::agent;
using namespace std::chrono_literals;

using yuzu::test::spin_until;

namespace {

OutboxEntry lifecycle_entry(const std::string& event_id) {
    return OutboxEntry::lifecycle("r1", /*generation=*/1, event_id,
                                  /*enqueued_ns=*/1'700'000'000'000'000'000, "armed");
}

/// A send that blocks until release() is called, then returns `result`.
struct StallingSend {
    std::mutex mu;
    std::condition_variable cv;
    bool release_flag{false};
    std::atomic<int> invocations{0};
    SendResult result{SendResult::Sent};

    SendResult operator()(const OutboxEntry&) {
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

} // namespace

TEST_CASE("offer() completes synchronously for a fast send", "[spark][guardian][send_executor]") {
    GuardianOutboxSendExecutor exec;
    auto entry = lifecycle_entry("e1");
    auto instant = [](const OutboxEntry&) -> SendResult { return SendResult::Sent; };
    auto result = exec.offer(entry, instant, 200ms);
    REQUIRE(result.has_value());
    CHECK(*result == SendResult::Sent);
    CHECK(exec.active_worker_count() == 0);
}

TEST_CASE("offer() returns nullopt while the send is still stalled, then the result once released",
          "[spark][guardian][send_executor]") {
    GuardianOutboxSendExecutor exec;
    StallingSend send;
    auto entry = lifecycle_entry("e1");

    auto first = exec.offer(entry, std::ref(send), 20ms);
    CHECK_FALSE(first.has_value()); // still running
    CHECK(spin_until([&] { return send.invocations.load() >= 1; }));

    // Re-offering the SAME entry does not resubmit - single-flight.
    auto second = exec.offer(entry, std::ref(send), 20ms);
    CHECK_FALSE(second.has_value());
    CHECK(send.invocations.load() == 1);

    send.release();
    // The next offer() for the SAME entry consumes the published result.
    std::optional<SendResult> consumed;
    REQUIRE(spin_until([&] {
        consumed = exec.offer(entry, std::ref(send), 20ms);
        return consumed.has_value();
    }));
    CHECK(*consumed == SendResult::Sent);
    REQUIRE(spin_until([&] { return exec.active_worker_count() == 0; }));
}

TEST_CASE("item 4 regression: a head change during a stall does not wedge the executor "
          "(#3847/#2233 item 4 - both security-guardian and cpp-safety independently found "
          "this in governance review of the fix's first draft)",
          "[spark][guardian][send_executor][chaos]") {
    // This is the exact scenario BOTH reviewers described: entry A's send is still running
    // (a stalled sink) when the log's head changes out from under it - a generation-supersede
    // purge or an ordinary withdrawal, not a rare race. offer() must not wedge on entry B
    // forever just because A's stale event_id will never recur.
    GuardianOutboxSendExecutor exec;
    StallingSend send_a;
    auto entry_a = lifecycle_entry("event-a");
    auto entry_b = lifecycle_entry("event-b");

    auto first = exec.offer(entry_a, std::ref(send_a), 20ms);
    CHECK_FALSE(first.has_value());
    REQUIRE(spin_until([&] { return send_a.invocations.load() >= 1; })); // A is now stuck

    // The head changed to B while A is still in flight. The orphaned A worker cannot be
    // touched (a second concurrent Write() on the same stream would be wrong); this must
    // Retain, not launch B's send yet, and must NOT invoke B's send function at all.
    std::atomic<int> b_invocations{0};
    auto send_b = [&](const OutboxEntry&) -> SendResult {
        b_invocations.fetch_add(1);
        return SendResult::Sent;
    };
    auto while_stalled = exec.offer(entry_b, send_b, 20ms);
    REQUIRE(while_stalled.has_value()); // Retain, not "still running" - a mismatch is decided
    CHECK(*while_stalled == SendResult::Retain);
    CHECK(b_invocations.load() == 0); // never touched the orphaned worker's stream

    // Unblock A. THE regression: once A's orphaned worker finishes, offer()ing B again must
    // reclaim the slot and actually launch B - not return Retain forever because "event-a"
    // will never again match a future entry's event_id (each is unique at enqueue).
    send_a.release();
    std::optional<SendResult> b_result;
    REQUIRE(spin_until(
        [&] {
            b_result = exec.offer(entry_b, send_b, 20ms);
            return b_result.has_value() && *b_result == SendResult::Sent;
        },
        3s));
    CHECK(b_invocations.load() == 1);
    REQUIRE(spin_until([&] { return exec.active_worker_count() == 0; }));
}

TEST_CASE("a throwing send is re-thrown by the next offer() call, not swallowed as Retain",
          "[spark][guardian][send_executor]") {
    GuardianOutboxSendExecutor exec;
    auto entry = lifecycle_entry("e1");
    auto throwing = [](const OutboxEntry&) -> SendResult {
        throw std::runtime_error("send boom");
    };
    bool threw = false;
    // The throw may surface on the launching call (fast completion) or a later poll -
    // either is a correct outcome of the bounded wait; only silently mapping it to a
    // plain Retain with no throw at all would be wrong.
    REQUIRE(spin_until([&] {
        try {
            auto r = exec.offer(entry, throwing, 20ms);
            return r.has_value(); // got Sent/Retain with no throw: wrong, but let REQUIRE below catch it
        } catch (const std::runtime_error& e) {
            threw = true;
            CHECK(std::string(e.what()) == "send boom");
            return true;
        }
    }));
    CHECK(threw);
}

TEST_CASE("stop() prevents a new launch but does not disturb one already in flight",
          "[spark][guardian][send_executor]") {
    GuardianOutboxSendExecutor exec;
    StallingSend send;
    auto entry = lifecycle_entry("e1");

    auto first = exec.offer(entry, std::ref(send), 20ms);
    CHECK_FALSE(first.has_value());
    REQUIRE(spin_until([&] { return send.invocations.load() >= 1; }));

    exec.stop();
    // Still waits out the ALREADY-launched worker rather than abandoning it.
    auto still_waiting = exec.offer(entry, std::ref(send), 20ms);
    CHECK_FALSE(still_waiting.has_value());

    send.release();
    std::optional<SendResult> result;
    REQUIRE(spin_until([&] {
        result = exec.offer(entry, std::ref(send), 20ms);
        return result.has_value();
    }));
    CHECK(*result == SendResult::Sent);

    // A DIFFERENT entry, offered after stop(), is never launched.
    std::atomic<int> b_invocations{0};
    auto send_b = [&](const OutboxEntry&) -> SendResult {
        b_invocations.fetch_add(1);
        return SendResult::Sent;
    };
    auto after_stop = exec.offer(lifecycle_entry("e2"), send_b, 20ms);
    REQUIRE(after_stop.has_value());
    CHECK(*after_stop == SendResult::Retain);
    CHECK(b_invocations.load() == 0);
}
