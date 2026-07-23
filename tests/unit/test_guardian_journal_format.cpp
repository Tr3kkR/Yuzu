/**
 * test_guardian_journal_format.cpp -- unit tests for the pure journal substrate
 * (item 7, PR-Ag, C1): key helpers, mint-time validation, and batch
 * (de)serialization. No KvStore, no threads - deterministic in isolation.
 */

#include "guardian_journal_format.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace yuzu::agent;

namespace {

// A record that passes every gate - tests mutate one field to isolate a fault.
JournalRecord good_record() {
    return JournalRecord{
        .rule_id = "rule-1",
        .generation = 5,
        .event_id = "agent-abc123-rule-1-1700000000000-7",
        .enqueued_ns = 1'700'000'000'000'000'000, // ~2023-11, secs > 0
        .kind = "armed",
        .guard_type = "file",
        .rule_name = "My Rule",
    };
}

} // namespace

// ── Key helpers ──────────────────────────────────────────────────────────────

TEST_CASE("journal key helpers: batch/sent 12-digit seq + prefixes", "[guardian][journal][format]") {
    CHECK(journal_batch_key("deadbeef", 0) == "lc:deadbeef:000000000000");
    CHECK(journal_batch_key("deadbeef", 42) == "lc:deadbeef:000000000042");
    CHECK(journal_sent_key("deadbeef", 42) == "sent:deadbeef:000000000042");

    // The three prefixes are disjoint - a scan of one never matches another.
    const auto bk = journal_batch_key("nonce", 3);
    CHECK(bk.starts_with(kBatchKeyPrefix));
    CHECK_FALSE(bk.starts_with(kSentKeyPrefix));
    CHECK_FALSE(bk.starts_with(kQuarantineKeyPrefix));
}

TEST_CASE("journal quarantine key wraps the batch key", "[guardian][journal][format]") {
    const auto bk = journal_batch_key("nonce", 9);
    const auto qk = journal_quarantine_key(bk);
    CHECK(qk == "quarantine:lc:nonce:000000000009");
    CHECK(qk.starts_with(kQuarantineKeyPrefix));
    // A scan of the batch prefix must NOT see a quarantined key.
    CHECK_FALSE(qk.starts_with(kBatchKeyPrefix));
}

// ── validate_record ──────────────────────────────────────────────────────────

TEST_CASE("validate_record: a clean record is journalable", "[guardian][journal][format]") {
    CHECK(validate_record(good_record()) == JournalReject::None);
}

TEST_CASE("validate_record: embedded NUL rejected", "[guardian][journal][format]") {
    auto r = good_record();
    r.rule_name = std::string("bad\0name", 8);
    CHECK(validate_record(r) == JournalReject::EmbeddedNul);
}

TEST_CASE("validate_record: oversized field rejected", "[guardian][journal][format]") {
    auto r = good_record();
    r.rule_name = std::string(kMaxJournalFieldBytes + 1, 'x');
    CHECK(validate_record(r) == JournalReject::Oversized);

    r.rule_name = std::string(kMaxJournalFieldBytes, 'x'); // exactly at the cap is fine
    CHECK(validate_record(r) == JournalReject::None);
}

TEST_CASE("validate_record: invalid UTF-8 rejected", "[guardian][journal][format]") {
    auto r = good_record();
    r.guard_type = std::string("\x80"); // lone continuation byte
    CHECK(validate_record(r) == JournalReject::InvalidUtf8);

    r.guard_type = std::string("\xC0\xAF"); // overlong '/'
    CHECK(validate_record(r) == JournalReject::InvalidUtf8);

    r.guard_type = std::string("\xED\xA0\x80"); // UTF-16 surrogate half
    CHECK(validate_record(r) == JournalReject::InvalidUtf8);
}

TEST_CASE("validate_record: valid multibyte UTF-8 accepted", "[guardian][journal][format]") {
    auto r = good_record();
    r.rule_name = "café \xE2\x98\x95 \xE6\x97\xA5\xE6\x9C\xAC\xE8\xAA\x9E"; // café ☕ 日本語
    CHECK(validate_record(r) == JournalReject::None);
}

TEST_CASE("validate_record: skewed clock (secs<=0) rejected", "[guardian][journal][format]") {
    auto r = good_record();

    r.enqueued_ns = 0; // epoch second 0
    CHECK(validate_record(r) == JournalReject::SkewedClock);

    r.enqueued_ns = 999'999'999; // floors to second 0
    CHECK(validate_record(r) == JournalReject::SkewedClock);

    r.enqueued_ns = -1; // floors to second -1 (pre-epoch)
    CHECK(validate_record(r) == JournalReject::SkewedClock);

    r.enqueued_ns = 1'000'000'000; // exactly second 1 - the first valid ns
    CHECK(validate_record(r) == JournalReject::None);
}

TEST_CASE("validate_record: clock is checked before fields", "[guardian][journal][format]") {
    // A record that is BOTH skewed and field-bad reports the clock fault first
    // (the loss-channel taxonomy keeps them on distinct counters).
    auto r = good_record();
    r.enqueued_ns = 0;
    r.rule_name = std::string("x\0y", 3);
    CHECK(validate_record(r) == JournalReject::SkewedClock);
}

// ── serialize / parse round-trip ─────────────────────────────────────────────

TEST_CASE("journal batch round-trips byte-exact", "[guardian][journal][format]") {
    std::vector<JournalRecord> in{
        good_record(),
        JournalRecord{.rule_id = "rule-2",
                      .generation = 18446744073709551615ull, // uint64 max
                      .event_id = "agent-abc123-rule-2-1700000001000-8",
                      .enqueued_ns = 1'700'000'001'000'000'000,
                      .kind = "disarmed",
                      .guard_type = "registry",
                      .rule_name = "café \xE6\x97\xA5\xE6\x9C\xAC"}, // multibyte survives
    };

    const auto json = serialize_journal_batch(1'700'000'002'345, in);
    auto parsed = parse_journal_batch(json);
    REQUIRE(parsed.has_value());
    CHECK(parsed->ts_ms == 1'700'000'002'345);
    REQUIRE(parsed->entries.size() == 2);

    for (std::size_t i = 0; i < in.size(); ++i) {
        const auto& a = in[i];
        const auto& b = parsed->entries[i];
        CHECK(a.rule_id == b.rule_id);
        CHECK(a.generation == b.generation);
        CHECK(a.event_id == b.event_id);
        CHECK(a.enqueued_ns == b.enqueued_ns);
        CHECK(a.kind == b.kind);
        CHECK(a.guard_type == b.guard_type);
        CHECK(a.rule_name == b.rule_name);
    }
}

TEST_CASE("journal batch: empty entries round-trip", "[guardian][journal][format]") {
    const auto json = serialize_journal_batch(42, {});
    auto parsed = parse_journal_batch(json);
    REQUIRE(parsed.has_value());
    CHECK(parsed->ts_ms == 42);
    CHECK(parsed->entries.empty());
}

// ── parse rejection → quarantine ─────────────────────────────────────────────

TEST_CASE("parse_journal_batch: malformed JSON → Malformed", "[guardian][journal][format]") {
    auto p = parse_journal_batch("{not json");
    REQUIRE_FALSE(p.has_value());
    CHECK(p.error() == JournalParseError::Malformed);
}

TEST_CASE("parse_journal_batch: unknown version → UnknownVersion", "[guardian][journal][format]") {
    auto p = parse_journal_batch(R"({"v":3,"ts_ms":1,"entries":[]})");
    REQUIRE_FALSE(p.has_value());
    CHECK(p.error() == JournalParseError::UnknownVersion);
}

TEST_CASE("parse_journal_batch: missing/typewrong fields → Malformed", "[guardian][journal][format]") {
    // entries not an array
    CHECK(parse_journal_batch(R"({"v":4,"ts_ms":1,"entries":{}})").error() ==
          JournalParseError::Malformed);
    // ts_ms missing
    CHECK(parse_journal_batch(R"({"v":4,"entries":[]})").error() == JournalParseError::Malformed);
    // an entry missing a required string field (rule_name)
    CHECK(parse_journal_batch(
              R"({"v":4,"ts_ms":1,"entries":[{"rule_id":"r","generation":1,"event_id":"e","enqueued_ns":2000000000,"kind":"armed","guard_type":"file"}]})")
              .error() == JournalParseError::Malformed);
    // an entry with a typewrong numeric field (enqueued_ns as string)
    CHECK(parse_journal_batch(
              R"({"v":4,"ts_ms":1,"entries":[{"rule_id":"r","generation":1,"event_id":"e","enqueued_ns":"nope","kind":"armed","guard_type":"file","rule_name":"n"}]})")
              .error() == JournalParseError::Malformed);
}

TEST_CASE("parse_journal_batch: pathologically-nested JSON is rejected, never stack-overflows",
          "[guardian][journal][format]") {
    // A tampered kv_store.db value could nest '[' thousands deep; nlohmann's recursive-descent
    // parser would stack-overflow (an uncatchable ABORT) before returning. The depth pre-scan
    // must reject it as Malformed - the caller then quarantines it - without recursing (security
    // review). 50k deep is far past any legitimate v4 batch (which nests 3) and would blow the
    // stack if the guard were absent; reaching the CHECK at all proves the guard fired first.
    const std::string deep(50000, '[');
    auto p = parse_journal_batch(deep);
    REQUIRE_FALSE(p.has_value());
    CHECK(p.error() == JournalParseError::Malformed);

    // Brackets INSIDE a string literal are not real nesting and must not trip the guard: a v4
    // batch whose rule_name is full of '[' still parses fine.
    const std::string brackety(200, '[');
    auto ok = parse_journal_batch(
        R"({"v":4,"ts_ms":1,"entries":[{"rule_id":"r","generation":1,"event_id":"e","enqueued_ns":2000000000,"kind":"armed","guard_type":"file","rule_name":")" +
        brackety + R"("}]})");
    REQUIRE(ok.has_value());
    CHECK(ok->entries.at(0).rule_name == brackety);
}

TEST_CASE("parse_journal_batch rejects a row claiming more entries than a batch may hold",
          "[guardian][journal][format][chaos]") {
    // persist() writes at most kMaxJournalEntriesPerBatch, and the send window is floored at
    // exactly that, so the replay path's termination argument is "no batch can need more room
    // than the window holds". The READ boundary is what has to enforce that: an over-long row -
    // a torn write, a hand-edited kv_store.db, a future writer bug - would otherwise parse,
    // never fit, and hold a paging reservation for a batch that can never be placed, while
    // every counter stays clean. RED before the fix: the row parses.
    const auto row = [](std::size_t n) {
        std::string j = R"({"v":4,"ts_ms":1700000000000,"entries":[)";
        for (std::size_t i = 0; i < n; ++i) {
            if (i)
                j += ',';
            j += R"({"rule_id":"r","event_id":"e)" + std::to_string(i) +
                 R"(","kind":"armed","guard_type":"file","rule_name":"n","generation":1,)"
                 R"("enqueued_ns":1700000000000000000})";
        }
        return j + "]}";
    };
    // At the limit it parses; one over is Malformed, so prune quarantines it rather than
    // replaying it forever.
    auto ok = parse_journal_batch(row(kMaxJournalEntriesPerBatch));
    REQUIRE(ok.has_value());
    CHECK(ok->entries.size() == kMaxJournalEntriesPerBatch);

    auto bad = parse_journal_batch(row(kMaxJournalEntriesPerBatch + 1));
    REQUIRE_FALSE(bad.has_value());
    CHECK(bad.error() == JournalParseError::Malformed);
}
