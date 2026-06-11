/**
 * test_execution_event_bus.cpp — coverage for the per-execution SSE event
 * bus introduced by PR 3 of the executions-history ladder.
 *
 * Contracts being pinned:
 *   - subscribe / publish / unsubscribe round-trip across one channel
 *   - per-execution channel partitioning (subscribers on exec A do NOT
 *     receive events for exec B)
 *   - ring buffer caps at kBufferCap; oldest events are evicted FIFO
 *   - replay_since respects the Last-Event-ID semantics (id strictly >)
 *   - terminal-marked channels survive past terminal time but get GC'd
 *     once retention expires AND no subscribers remain
 *   - listener invocation runs under the per-channel mutex but never
 *     blocks the publisher (a listener that mutates the bus state would
 *     deadlock — verified indirectly by the queue-and-notify pattern;
 *     the test for listener concurrency is a smoke).
 */

#include "execution_event_bus.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>  // std::sort -- not transitively pulled in by <vector>
                      // on MSVC's STL (Linux libstdc++ + libc++ both happen
                      // to include it indirectly, masking the omission).
#include <atomic>
#include <cstdint>
#include <thread>
#include <vector>

using namespace yuzu::server;

namespace {

ExecutionEvent only_event(const std::vector<ExecutionEvent>& v) {
    REQUIRE(v.size() == 1);
    return v.front();
}

} // namespace

TEST_CASE("execution_event_bus — subscribe / publish / unsubscribe round-trip",
          "[execution_event_bus][pr3]") {
    ExecutionEventBus bus;
    std::vector<ExecutionEvent> received;
    auto sub_id = bus.subscribe("exec-1", [&](const ExecutionEvent& ev) {
        received.push_back(ev);
    });
    REQUIRE(sub_id != 0);

    bus.publish("exec-1", "agent-transition", R"({"agent_id":"a1","status":"running"})");
    bus.publish("exec-1", "agent-transition", R"({"agent_id":"a2","status":"success"})");

    REQUIRE(received.size() == 2);
    CHECK(received[0].id == 1);
    CHECK(received[1].id == 2);
    CHECK(received[0].event_type == "agent-transition");
    CHECK(received[1].data.find("a2") != std::string::npos);

    bus.unsubscribe("exec-1", sub_id);
    bus.publish("exec-1", "agent-transition", R"({"agent_id":"a3","status":"failure"})");
    CHECK(received.size() == 2); // unsubscribe took effect
}

TEST_CASE("execution_event_bus — per-execution channel partitioning",
          "[execution_event_bus][pr3]") {
    ExecutionEventBus bus;
    int a_count = 0, b_count = 0;
    bus.subscribe("exec-A", [&](const ExecutionEvent&) { ++a_count; });
    bus.subscribe("exec-B", [&](const ExecutionEvent&) { ++b_count; });

    bus.publish("exec-A", "agent-transition", "{}");
    bus.publish("exec-A", "execution-progress", "{}");
    bus.publish("exec-B", "agent-transition", "{}");

    CHECK(a_count == 2);
    CHECK(b_count == 1);
    // Each channel has its own monotonic id — exec-B's first event is id 1,
    // not id 3.
    auto snap_b = bus.snapshot("exec-B");
    REQUIRE(snap_b.size() == 1);
    CHECK(snap_b[0].id == 1);
}

TEST_CASE("execution_event_bus — ring buffer caps at kBufferCap",
          "[execution_event_bus][pr3]") {
    ExecutionEventBus bus;
    // Publish 3 past the cap and assert the oldest 3 are evicted.
    for (std::size_t i = 0; i < ExecutionEventBus::kBufferCap + 3; ++i) {
        bus.publish("exec-1", "agent-transition",
                    std::string{"{\"i\":"} + std::to_string(i) + "}");
    }
    auto snap = bus.snapshot("exec-1");
    CHECK(snap.size() == ExecutionEventBus::kBufferCap);
    // The lowest surviving id is 4 (1, 2, 3 evicted).
    CHECK(snap.front().id == 4);
    CHECK(snap.back().id == ExecutionEventBus::kBufferCap + 3);
}

TEST_CASE("execution_event_bus — replay_since strictly greater than",
          "[execution_event_bus][pr3]") {
    ExecutionEventBus bus;
    for (int i = 0; i < 5; ++i) {
        bus.publish("exec-1", "agent-transition", "{}");
    }

    SECTION("replay_since(0) returns all 5 buffered events") {
        std::vector<std::uint64_t> ids;
        bus.replay_since("exec-1", 0,
                         [&](const ExecutionEvent& ev) { ids.push_back(ev.id); });
        REQUIRE(ids.size() == 5);
        CHECK(ids.front() == 1);
        CHECK(ids.back() == 5);
    }
    SECTION("replay_since(3) returns ids 4 and 5") {
        std::vector<std::uint64_t> ids;
        bus.replay_since("exec-1", 3,
                         [&](const ExecutionEvent& ev) { ids.push_back(ev.id); });
        REQUIRE(ids.size() == 2);
        CHECK(ids.front() == 4);
        CHECK(ids.back() == 5);
    }
    SECTION("replay_since past the head is empty (no spurious replays)") {
        std::vector<std::uint64_t> ids;
        bus.replay_since("exec-1", 999,
                         [&](const ExecutionEvent& ev) { ids.push_back(ev.id); });
        CHECK(ids.empty());
    }
    SECTION("replay_since on unknown channel is empty") {
        std::vector<std::uint64_t> ids;
        bus.replay_since("not-an-exec", 0,
                         [&](const ExecutionEvent& ev) { ids.push_back(ev.id); });
        CHECK(ids.empty());
    }
}

TEST_CASE("execution_event_bus — terminal flag and gc",
          "[execution_event_bus][pr3]") {
    ExecutionEventBus bus;

    SECTION("non-terminal channel is not GC'd") {
        bus.publish("exec-1", "agent-transition", "{}");
        CHECK(bus.gc_terminal_channels() == 0);
        CHECK(bus.channel_count() == 1);
    }
    SECTION("terminal channel with subscribers is not GC'd") {
        auto sub = bus.subscribe("exec-1", [](const ExecutionEvent&) {});
        bus.publish("exec-1", "execution-completed", "{}", /*is_terminal=*/true);
        CHECK(bus.gc_terminal_channels() == 0);
        bus.unsubscribe("exec-1", sub);
        // Channel is still present until retention expires (60 s); the GC
        // skips the entry but it remains.
        CHECK(bus.channel_count() == 1);
    }
}

TEST_CASE("execution_event_bus — GC collects an expired terminal channel "
          "without destroying a locked mutex (#1198)",
          "[execution_event_bus][pr3][gc]") {
    // Regression for #1198: gc_terminal_channels() erased the channel —
    // destroying the std::mutex inside it — while a lock_guard still owned
    // that mutex (the map held the only shared_ptr). The unlock of the
    // freed mutex aborted the whole server on MSVC and is UB everywhere.
    //
    // Detection: only MSVC's STL fails this deterministically (its unlock
    // validates ownership and aborts). On POSIX the bad unlock lands inside
    // uninstrumented libpthread, so ASan and TSan both stay silent — the
    // Windows CI leg is the enforcement point. Either way this pins the
    // collection path the older gc tests never reached (they only exercised
    // the not-collected branches).
    std::int64_t fake_now = 1'000'000; // past the throttle vs last_gc=0
    ExecutionEventBus bus;             // declared after the clock state it borrows
    bus.set_clock_fn([&] { return fake_now; });

    // Terminal event, no subscribers — exactly the channel shape GC targets.
    bus.publish("exec-1", "execution-completed", "{}", /*is_terminal=*/true);
    REQUIRE(bus.channel_count() == 1);

    // Advance past retention + GC throttle so the sweep both runs and
    // finds exec-1 expired.
    constexpr std::int64_t kAdvance =
        ExecutionEventBus::kRetentionAfterTerminalSec * 1000 +
        ExecutionEventBus::kMinGcIntervalMs + 1;

    SECTION("direct gc_terminal_channels() call") {
        fake_now += kAdvance;
        CHECK(bus.gc_terminal_channels() == 1);
        CHECK(bus.channel_count() == 0);
        CHECK(bus.gc_channels_total() == 1);
    }
    SECTION("publish-driven opportunistic sweep (production trigger)") {
        // In production the sweep fires from publish() on an unrelated
        // execution — the crash signature from the UAT rig.
        fake_now += kAdvance;
        bus.publish("exec-2", "agent-transition", "{}");
        CHECK(bus.channel_count() == 1); // exec-1 collected, exec-2 live
        CHECK(bus.gc_channels_total() == 1);
        CHECK(bus.snapshot("exec-1").empty());
    }
    SECTION("multi-victim sweep parks every collected channel") {
        // The dead vector must keep ALL victims alive past their locks,
        // not just the first.
        bus.publish("exec-2", "execution-completed", "{}", /*is_terminal=*/true);
        bus.publish("exec-3", "execution-completed", "{}", /*is_terminal=*/true);
        REQUIRE(bus.channel_count() == 3);
        fake_now += kAdvance;
        CHECK(bus.gc_terminal_channels() == 3);
        CHECK(bus.channel_count() == 0);
        CHECK(bus.gc_channels_total() == 3);
    }
    SECTION("expired channel with a live subscriber survives the sweep") {
        // Pins the listeners.empty() predicate that both GC passes share —
        // the same condition the pass-2 re-check applies when a subscriber
        // lands between the passes. (The true between-pass interleaving
        // needs a thread race and is covered by the CH-1 chaos scenario.)
        fake_now += kAdvance;
        auto sub = bus.subscribe("exec-1", [](const ExecutionEvent&) {});
        CHECK(bus.gc_terminal_channels() == 0);
        CHECK(bus.channel_count() == 1);

        bus.unsubscribe("exec-1", sub);
        // Within kMinGcIntervalMs of the sweep above — throttled no-op.
        CHECK(bus.gc_terminal_channels() == 0);
        CHECK(bus.channel_count() == 1);

        fake_now += ExecutionEventBus::kMinGcIntervalMs + 1;
        CHECK(bus.gc_terminal_channels() == 1); // collected once unsubscribed
        CHECK(bus.channel_count() == 0);
    }
}

TEST_CASE("execution_event_bus — listener invocation is synchronous within publish",
          "[execution_event_bus][pr3]") {
    ExecutionEventBus bus;
    std::atomic<int> seen{0};
    bus.subscribe("exec-1", [&](const ExecutionEvent&) {
        seen.fetch_add(1, std::memory_order_relaxed);
    });
    bus.publish("exec-1", "agent-transition", "{}");
    // Invocation happens before publish returns — no sleep needed.
    CHECK(seen.load() == 1);
}

TEST_CASE("execution_event_bus — concurrent publishers do not lose events",
          "[execution_event_bus][pr3][concurrency]") {
    ExecutionEventBus bus;
    constexpr int kThreads = 4;
    constexpr int kPerThread = 250;
    std::atomic<int> received{0};
    bus.subscribe("exec-1",
                  [&](const ExecutionEvent&) { received.fetch_add(1, std::memory_order_relaxed); });

    std::vector<std::thread> ts;
    ts.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        ts.emplace_back([&] {
            for (int i = 0; i < kPerThread; ++i) {
                bus.publish("exec-1", "agent-transition", "{}");
            }
        });
    }
    for (auto& t : ts) t.join();
    CHECK(received.load() == kThreads * kPerThread);
    auto snap = bus.snapshot("exec-1");
    // Total events fit within the 1000-cap, so all should be in the buffer.
    CHECK(snap.size() == kThreads * kPerThread);
    // Ids are strictly monotonic — sort and verify no gaps.
    std::vector<std::uint64_t> ids;
    ids.reserve(snap.size());
    for (const auto& e : snap) ids.push_back(e.id);
    std::sort(ids.begin(), ids.end());
    for (std::size_t i = 1; i < ids.size(); ++i) {
        CHECK(ids[i] == ids[i - 1] + 1);
    }
}

TEST_CASE("execution_event_bus — subscriber_count and channel_count smoke",
          "[execution_event_bus][pr3]") {
    ExecutionEventBus bus;
    CHECK(bus.subscriber_count("exec-1") == 0);
    auto s1 = bus.subscribe("exec-1", [](const ExecutionEvent&) {});
    auto s2 = bus.subscribe("exec-1", [](const ExecutionEvent&) {});
    bus.subscribe("exec-2", [](const ExecutionEvent&) {});
    CHECK(bus.subscriber_count("exec-1") == 2);
    CHECK(bus.subscriber_count("exec-2") == 1);
    CHECK(bus.subscriber_count("not-an-exec") == 0);
    CHECK(bus.channel_count() == 2);
    bus.unsubscribe("exec-1", s1);
    bus.unsubscribe("exec-1", s2);
    CHECK(bus.subscriber_count("exec-1") == 0);
}

TEST_CASE("execution_event_bus — unsubscribe is idempotent",
          "[execution_event_bus][pr3]") {
    ExecutionEventBus bus;
    auto s = bus.subscribe("exec-1", [](const ExecutionEvent&) {});
    bus.unsubscribe("exec-1", s);
    // Second unsubscribe must not crash or throw.
    bus.unsubscribe("exec-1", s);
    bus.unsubscribe("not-an-exec", 12345);
    SUCCEED("idempotent unsubscribe paths reached");
}

TEST_CASE("execution_event_bus — snapshot is a copy, not a view",
          "[execution_event_bus][pr3]") {
    ExecutionEventBus bus;
    bus.publish("exec-1", "agent-transition", R"({"x":1})");
    auto snap1 = bus.snapshot("exec-1");
    bus.publish("exec-1", "agent-transition", R"({"x":2})");
    auto snap2 = bus.snapshot("exec-1");
    CHECK(snap1.size() == 1);
    CHECK(snap2.size() == 2);
    // Pin the only_event helper just so the linker doesn't drop it as
    // unused — defensive against future test growth.
    auto first = only_event(snap1);
    CHECK(first.event_type == "agent-transition");
}
