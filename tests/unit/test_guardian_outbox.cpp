// test_guardian_outbox.cpp - the Guardian spark consumer's in-memory emit buffer
// (ADR-0021 rung 2). Exercises the full pinned contract off-thread: FIFO drain,
// per-(domain,rule_id) coalescing with separate domains, retain-on-failure and
// retain-on-throw (stop the drain, keep the head), generation purge, drop-rule,
// and cap/backpressure that never silently evicts.

#include "guardian_outbox.hpp"

#include <catch2/catch_test_macros.hpp>

#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::agent;

namespace {
OutboxEntry comp(const std::string& rule, std::uint64_t gen, const std::string& event_id,
                 std::int64_t ts, const std::string& detected) {
    GuardDrift d;
    d.rule_id = rule;
    d.detected_value = detected;
    return OutboxEntry::compliance(rule, gen, event_id, ts, std::move(d));
}
// Records what was sent and always succeeds.
struct Recorder {
    std::vector<std::string> sent; // "domain:rule:event_id"
    SendResult operator()(const OutboxEntry& e) {
        sent.push_back(std::to_string(static_cast<int>(e.domain)) + ":" + e.rule_id + ":" +
                       e.event_id);
        return SendResult::Sent;
    }
};
} // namespace

TEST_CASE("outbox drains in FIFO order and removes every sent entry", "[spark][outbox]") {
    GuardianOutbox ob{16};
    REQUIRE(ob.enqueue(comp("a", 1, "e1", 100, "x")));
    REQUIRE(ob.enqueue(comp("b", 1, "e2", 101, "y")));
    REQUIRE(ob.enqueue(comp("c", 1, "e3", 102, "z")));
    REQUIRE(ob.size() == 3);

    Recorder rec;
    const std::size_t n = ob.drain(std::ref(rec));
    REQUIRE(n == 3);
    REQUIRE(ob.empty());
    REQUIRE(rec.sent == std::vector<std::string>{"0:a:e1", "0:b:e2", "0:c:e3"});
}

TEST_CASE("compliance coalesces to the latest per rule, keeping position", "[spark][outbox]") {
    GuardianOutbox ob{16};
    REQUIRE(ob.enqueue(comp("a", 1, "e1", 100, "old")));
    REQUIRE(ob.enqueue(comp("b", 1, "e2", 101, "b")));
    REQUIRE(ob.enqueue(comp("a", 2, "e3", 200, "new"))); // coalesce a -> latest
    REQUIRE(ob.size() == 2);                             // still 2, not 3

    std::vector<OutboxEntry> got;
    ob.drain([&](const OutboxEntry& e) {
        got.push_back(e);
        return SendResult::Sent;
    });
    REQUIRE(got.size() == 2);
    // a stays in its ORIGINAL position (index 0) but carries the latest payload/id/ts/gen.
    REQUIRE(got[0].rule_id == "a");
    REQUIRE(got[0].event_id == "e3");
    REQUIRE(got[0].enqueued_ns == 200);
    REQUIRE(got[0].generation == 2);
    REQUIRE(got[0].drift.detected_value == "new");
    REQUIRE(got[1].rule_id == "b");
}

TEST_CASE("domains coalesce independently - health does not overwrite compliance", "[spark][outbox]") {
    GuardianOutbox ob{16};
    REQUIRE(ob.enqueue(comp("a", 1, "c1", 100, "v")));
    REQUIRE(ob.enqueue(OutboxEntry::health("a", 1, "h1", 101, false, "io error")));
    REQUIRE(ob.size() == 2); // same rule, different domains -> two entries
    REQUIRE(ob.enqueue(OutboxEntry::health("a", 1, "h2", 102, true, ""))); // coalesce health only
    REQUIRE(ob.size() == 2);

    std::vector<OutboxEntry> got;
    ob.drain([&](const OutboxEntry& e) {
        got.push_back(e);
        return SendResult::Sent;
    });
    REQUIRE(got[0].domain == OutboxDomain::Compliance);
    REQUIRE(got[0].event_id == "c1");
    REQUIRE(got[1].domain == OutboxDomain::Health);
    REQUIRE(got[1].event_id == "h2"); // latest health
    REQUIRE(got[1].healthy);
}

TEST_CASE("a Retain stops the drain and keeps the head and its successors", "[spark][outbox]") {
    GuardianOutbox ob{16};
    ob.enqueue(comp("a", 1, "e1", 100, "x"));
    ob.enqueue(comp("b", 1, "e2", 101, "y"));
    ob.enqueue(comp("c", 1, "e3", 102, "z"));

    int calls = 0;
    const std::size_t n = ob.drain([&](const OutboxEntry&) {
        ++calls;
        return calls == 1 ? SendResult::Sent : SendResult::Retain; // b fails
    });
    REQUIRE(n == 1);            // only a sent
    REQUIRE(calls == 2);        // stopped at b, never tried c
    REQUIRE(ob.size() == 2);    // b and c retained, in order

    // A later drain (reconnect) sends the rest in order.
    Recorder rec;
    REQUIRE(ob.drain(std::ref(rec)) == 2);
    REQUIRE(rec.sent == std::vector<std::string>{"0:b:e2", "0:c:e3"});
}

TEST_CASE("a throw from send retains the head and stops the drain", "[spark][outbox]") {
    GuardianOutbox ob{16};
    ob.enqueue(comp("a", 1, "e1", 100, "x"));
    ob.enqueue(comp("b", 1, "e2", 101, "y"));

    const std::size_t n = ob.drain([&](const OutboxEntry&) -> SendResult {
        throw std::runtime_error("write blew up");
    });
    REQUIRE(n == 0);
    REQUIRE(ob.size() == 2); // nothing removed

    Recorder rec;
    REQUIRE(ob.drain(std::ref(rec)) == 2); // recovers cleanly next time
}

TEST_CASE("at capacity a new key is rejected + counted, coalescing still succeeds",
          "[spark][outbox]") {
    GuardianOutbox ob{2};
    REQUIRE(ob.enqueue(comp("a", 1, "e1", 100, "x")));
    REQUIRE(ob.enqueue(comp("b", 1, "e2", 101, "y")));
    REQUIRE(ob.size() == 2);
    // New key at cap -> rejected, never evicts a or b.
    REQUIRE_FALSE(ob.enqueue(comp("c", 1, "e3", 102, "z")));
    REQUIRE(ob.size() == 2);
    REQUIRE(ob.backpressure_drops() == 1);
    // Coalescing an existing key does not grow -> still accepted at cap.
    REQUIRE(ob.enqueue(comp("a", 2, "e4", 200, "x2")));
    REQUIRE(ob.size() == 2);
    REQUIRE(ob.backpressure_drops() == 1);
    // Draining frees room for a new key again.
    Recorder rec;
    ob.drain(std::ref(rec));
    REQUIRE(ob.enqueue(comp("c", 1, "e5", 300, "z")));
}

TEST_CASE("enqueue_all is atomic: at cap NEITHER of a pair is buffered", "[spark][outbox]") {
    GuardianOutbox ob{1};
    REQUIRE(ob.enqueue(comp("a", 1, "e1", 100, "x"))); // fills the single slot
    // A health+verdict pair for rule b is two NEW keys, needs 2 slots -> reject both.
    std::vector<OutboxEntry> pair;
    pair.push_back(OutboxEntry::health("b", 1, "h", 101, true, ""));
    pair.push_back(comp("b", 2, "c", 102, "y"));
    REQUIRE_FALSE(ob.enqueue_all(std::move(pair)));
    REQUIRE(ob.size() == 1); // neither buffered - no partial commit
    REQUIRE(ob.backpressure_drops() == 1);
}

TEST_CASE("enqueue_all buffers a pair that fits; coalescing entries are not growth",
          "[spark][outbox]") {
    GuardianOutbox ob{2};
    std::vector<OutboxEntry> pair;
    pair.push_back(OutboxEntry::health("a", 1, "h", 100, true, ""));
    pair.push_back(comp("a", 1, "c", 101, "x"));
    REQUIRE(ob.enqueue_all(std::move(pair))); // 2 new keys (health + compliance), cap 2 -> fits
    REQUIRE(ob.size() == 2);
    // Re-enqueue a pair for the same rule/domains: both coalesce -> no growth, still fits at cap.
    std::vector<OutboxEntry> pair2;
    pair2.push_back(OutboxEntry::health("a", 1, "h2", 200, true, ""));
    pair2.push_back(comp("a", 2, "c2", 201, "y"));
    REQUIRE(ob.enqueue_all(std::move(pair2)));
    REQUIRE(ob.size() == 2);
}

TEST_CASE("purge_stale drops entries below the active generation, keeps the rest", "[spark][outbox]") {
    GuardianOutbox ob{16};
    ob.enqueue(comp("a", 1, "e1", 100, "x"));                        // gen 1 - stale
    ob.enqueue(OutboxEntry::health("a", 1, "h1", 101, false, "io")); // gen 1 - stale
    ob.enqueue(comp("b", 3, "e2", 102, "y"));                        // gen 3 - kept

    ob.purge_stale("a", /*active_generation=*/2);
    REQUIRE(ob.size() == 1);
    std::vector<OutboxEntry> got;
    ob.drain([&](const OutboxEntry& e) {
        got.push_back(e);
        return SendResult::Sent;
    });
    REQUIRE(got.size() == 1);
    REQUIRE(got[0].rule_id == "b");

    // An at-or-above-generation entry survives its own purge.
    ob.enqueue(comp("c", 5, "e3", 200, "z"));
    ob.purge_stale("c", 5);
    REQUIRE(ob.size() == 1);
}

TEST_CASE("drop_rule removes every domain for a rule", "[spark][outbox]") {
    GuardianOutbox ob{16};
    ob.enqueue(comp("a", 1, "e1", 100, "x"));
    ob.enqueue(OutboxEntry::health("a", 1, "h1", 101, false, "io"));
    ob.enqueue(OutboxEntry::lifecycle("a", 1, "l1", 102, "errored"));
    ob.enqueue(comp("b", 1, "e2", 103, "y"));
    REQUIRE(ob.size() == 4);

    ob.drop_rule("a");
    REQUIRE(ob.size() == 1);
    Recorder rec;
    ob.drain(std::ref(rec));
    REQUIRE(rec.sent == std::vector<std::string>{"0:b:e2"});
}
