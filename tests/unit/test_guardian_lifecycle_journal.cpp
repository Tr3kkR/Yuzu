/**
 * test_guardian_lifecycle_journal.cpp -- the engine-owned durable side of the
 * lifecycle journal (item 7 PR-Ag C2): persist() batching + round-trip against a
 * real KvStore. Staging + the persist BOUNDARY (apply_rules/start_local flush) are
 * exercised at the runtime + engine levels; this pins the component in isolation.
 */

#include "guardian_journal_format.hpp"
#include "guardian_lifecycle_journal.hpp"

#include <yuzu/agent/kv_store.hpp>

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <string>
#include <vector>

using namespace yuzu::agent;

namespace {

JournalRecord rec(const std::string& rid, const std::string& kind,
                  std::int64_t ns = 1'700'000'000'000'000'000) {
    return JournalRecord{.rule_id = rid,
                         .generation = 1,
                         .event_id = "agent-nonce-" + rid,
                         .enqueued_ns = ns,
                         .kind = kind,
                         .guard_type = "file",
                         .rule_name = "n"};
}

std::shared_ptr<const JournalRecord> ptr(const std::string& rid, const std::string& kind) {
    return std::make_shared<const JournalRecord>(rec(rid, kind));
}

// A one-record pending vector — std::span needs a named contiguous range, not a
// braced-init-list, so persist() calls take this rather than {ptr(...)}.
std::vector<std::shared_ptr<const JournalRecord>> one(const std::string& rid,
                                                     const std::string& kind) {
    return {ptr(rid, kind)};
}

// Read every batch back and flatten. Batch keys are lc:<nonce>:<seq12> with a fixed
// per-process nonce + zero-padded seq, so list_entries' key order == persist order.
std::vector<JournalRecord> read_all(KvStore& kv) {
    std::vector<JournalRecord> out;
    auto rows = kv.list_entries(kJournalNamespace, kBatchKeyPrefix);
    REQUIRE(rows.has_value());
    for (const auto& row : *rows) {
        auto b = parse_journal_batch(row.value);
        REQUIRE(b.has_value());
        for (auto& e : b->entries)
            out.push_back(std::move(e));
    }
    return out;
}

struct TestKv {
    yuzu::test::TempDbFile db{"yuzu_test_journal-"};
    std::unique_ptr<KvStore> kv;
    TestKv() {
        auto r = KvStore::open(db.path);
        REQUIRE(r.has_value());
        kv = std::make_unique<KvStore>(std::move(*r));
    }
};

} // namespace

TEST_CASE("journal persist: round-trips records durably", "[guardian][journal][persist]") {
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    std::vector<std::shared_ptr<const JournalRecord>> pending{ptr("r1", "armed"),
                                                              ptr("r2", "disarmed")};
    CHECK(j.persist(pending) == 2);
    CHECK(j.batches_written() == 1);
    CHECK(j.write_failures() == 0);

    auto got = read_all(*t.kv);
    REQUIRE(got.size() == 2);
    CHECK(got[0].rule_id == "r1");
    CHECK(got[0].kind == "armed");
    CHECK(got[0].event_id == "agent-nonce-r1");
    CHECK(got[1].rule_id == "r2");
    CHECK(got[1].kind == "disarmed");
}

TEST_CASE("journal persist: chunks a large push into multiple batches", "[guardian][journal][persist]") {
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    std::vector<std::shared_ptr<const JournalRecord>> pending;
    for (int i = 0; i < 300; ++i)
        pending.push_back(ptr("r" + std::to_string(i), "armed"));

    CHECK(j.persist(pending) == 300);
    CHECK(j.batches_written() >= 2); // 300 > kMaxJournalEntriesPerBatch (256)

    auto got = read_all(*t.kv);
    REQUIRE(got.size() == 300);
    CHECK(got.front().rule_id == "r0");
    CHECK(got.back().rule_id == "r299");
}

TEST_CASE("journal persist: empty pending writes nothing", "[guardian][journal][persist]") {
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    std::vector<std::shared_ptr<const JournalRecord>> empty;
    CHECK(j.persist(empty) == 0);
    CHECK(j.batches_written() == 0);
    CHECK(read_all(*t.kv).empty());
}

TEST_CASE("journal persist: null KvStore is a no-op", "[guardian][journal][persist]") {
    GuardianLifecycleJournal j(nullptr);
    std::vector<std::shared_ptr<const JournalRecord>> pending{ptr("r1", "armed")};
    CHECK(j.persist(pending) == 0);
    CHECK(j.batches_written() == 0);
}

TEST_CASE("journal persist: a write failure circuit-breaks; a retry of the same pending persists",
          "[guardian][journal][persist]") {
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    std::vector<std::shared_ptr<const JournalRecord>> pending{ptr("r1", "armed"), ptr("r2", "armed")};

    j.inject_write_failures_for_test(1); // force the (single) batch write to fail
    CHECK(j.persist(pending) == 0);      // circuit-broke — nothing durably written
    CHECK(j.write_failures() == 1);
    CHECK(read_all(*t.kv).empty());

    // Retry the SAME pending (as the maintenance tick would) — no injected fault now.
    CHECK(j.persist(pending) == 2);
    auto got = read_all(*t.kv);
    REQUIRE(got.size() == 2);
    CHECK(got[0].rule_id == "r1");
    CHECK(got[1].rule_id == "r2");
}

// ── Retention + quarantine (item 7 PR-Ag C4) ─────────────────────────────────

namespace {
constexpr std::size_t kNoCap = std::size_t(-1);
std::size_t count_keys(KvStore& kv, std::string_view prefix) {
    auto rows = kv.list_entries(kJournalNamespace, prefix);
    REQUIRE(rows.has_value());
    return rows->size();
}
} // namespace

TEST_CASE("journal prune: age cap evicts batches older than retention", "[guardian][journal][prune]") {
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    j.persist(one("r1", "armed"));
    j.persist(one("r2", "armed"));
    REQUIRE(count_keys(*t.kv, kBatchKeyPrefix) == 2);

    // A now_ms far in the future makes every real-now batch older than 7 days.
    auto stats = j.prune(32503680000000LL); // ~year 3000 in ms
    CHECK(stats.evicted == 2);
    CHECK(j.batches_pruned() == 2);
    CHECK(count_keys(*t.kv, kBatchKeyPrefix) == 0);
}

TEST_CASE("journal prune: count cap evicts the oldest batches by (ts_ms,key)", "[guardian][journal][prune]") {
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    j.set_retention_limits_for_test(/*days=*/100000, /*max_batches=*/2, /*max_bytes=*/kNoCap,
                                    /*max_quarantine=*/100);
    for (int i = 0; i < 4; ++i)
        j.persist(one("r" + std::to_string(i), "armed"));
    REQUIRE(count_keys(*t.kv, kBatchKeyPrefix) == 4);

    auto stats = j.prune(0); // now_ms=0 → nothing is "too old" under the 100000-day cap
    CHECK(stats.evicted == 2);
    auto remaining = read_all(*t.kv);
    REQUIRE(remaining.size() == 2); // the two NEWEST survive
    CHECK(remaining[0].rule_id == "r2");
    CHECK(remaining[1].rule_id == "r3");
}

TEST_CASE("journal prune: byte cap evicts to satisfy the budget", "[guardian][journal][prune]") {
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    j.set_retention_limits_for_test(100000, kNoCap, /*max_bytes=*/1, 100); // 1 byte < any batch
    for (int i = 0; i < 3; ++i)
        j.persist(one("r" + std::to_string(i), "armed"));
    REQUIRE(count_keys(*t.kv, kBatchKeyPrefix) == 3);

    auto stats = j.prune(0);
    CHECK(stats.evicted == 3); // no batch fits a 1-byte budget → all evicted
    CHECK(count_keys(*t.kv, kBatchKeyPrefix) == 0);
}

TEST_CASE("journal prune: an unparseable batch is quarantined; good batches survive",
          "[guardian][journal][prune]") {
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    REQUIRE(t.kv->set(kJournalNamespace, "lc:corrupt:000000000000", "not valid json"));
    j.persist(one("good", "armed"));

    auto stats = j.prune(0);
    CHECK(stats.quarantined == 1);
    CHECK(j.quarantined() == 1);

    auto batches = t.kv->list_entries(kJournalNamespace, kBatchKeyPrefix);
    REQUIRE(batches.has_value());
    REQUIRE(batches->size() == 1); // only the good batch remains under lc:
    auto b = parse_journal_batch((*batches)[0].value);
    REQUIRE(b.has_value());
    CHECK(b->entries.at(0).rule_id == "good");
    CHECK(count_keys(*t.kv, kQuarantineKeyPrefix) == 1); // the corrupt one moved aside
}

TEST_CASE("journal prune: an orphan sent-label is GC'd", "[guardian][journal][prune]") {
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    j.persist(one("r1", "armed")); // a surviving batch (its label, if any, is kept)
    REQUIRE(t.kv->set(kJournalNamespace, "sent:ghost:000000000000", "")); // orphan: no such batch

    auto stats = j.prune(0);
    CHECK(stats.sent_labels_gc >= 1);
    CHECK_FALSE(t.kv->exists(kJournalNamespace, "sent:ghost:000000000000"));
}

TEST_CASE("journal prune: the quarantine set is bounded", "[guardian][journal][prune]") {
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    j.set_retention_limits_for_test(100000, kNoCap, kNoCap, /*max_quarantine=*/1);
    for (int i = 0; i < 3; ++i)
        REQUIRE(t.kv->set(kJournalNamespace, "lc:bad" + std::to_string(i) + ":000000000000", "garbage"));

    j.prune(0); // quarantines 3, then bounds the quarantine set to 1
    CHECK(count_keys(*t.kv, kQuarantineKeyPrefix) == 1);
}
