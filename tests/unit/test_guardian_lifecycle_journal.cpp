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
