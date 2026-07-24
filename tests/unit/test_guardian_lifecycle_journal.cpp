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

#include <chrono>
#include <memory>
#include <span>
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

// A one-record pending vector - std::span needs a named contiguous range, not a
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
    CHECK(j.persist(pending) == 0);      // circuit-broke - nothing durably written
    CHECK(j.write_failures() == 1);
    CHECK(read_all(*t.kv).empty());

    // Retry the SAME pending (as the maintenance tick would) - no injected fault now.
    CHECK(j.persist(pending) == 2);
    auto got = read_all(*t.kv);
    REQUIRE(got.size() == 2);
    CHECK(got[0].rule_id == "r1");
    CHECK(got[1].rule_id == "r2");
}

TEST_CASE("journal persist: a mid-persist failure returns the committed-prefix count (no loss/dup)",
          "[guardian][journal][persist]") {
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    std::vector<std::shared_ptr<const JournalRecord>> pending;
    for (int i = 0; i < 300; ++i) // 300 records -> 2 batches (256 + 44)
        pending.push_back(ptr("r" + std::to_string(i), "armed"));

    // Batch 1 writes; batch 2's write fails. written must be batch 1's 256 records so the
    // caller erases exactly that prefix and the rest stay pending (review B4b).
    j.inject_write_failures_for_test(/*n=*/1, /*skip_first=*/1);
    CHECK(j.persist(pending) == 256);
    auto after1 = t.kv->list_entries(kJournalNamespace, kBatchKeyPrefix);
    REQUIRE(after1.has_value());
    CHECK(after1->size() == 1); // only batch 1 durable

    // Retry the remaining records (as the engine does after erasing the 256 prefix).
    std::vector<std::shared_ptr<const JournalRecord>> rest(pending.begin() + 256, pending.end());
    CHECK(j.persist(rest) == 44);
    CHECK(read_all(*t.kv).size() == 300); // every record durable exactly once
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
    REQUIRE(j.persist(one("r1", "armed")) == 1);
    REQUIRE(j.persist(one("r2", "armed")) == 1);
    REQUIRE(count_keys(*t.kv, kBatchKeyPrefix) == 2);

    // A now_ms far in the future makes every real-now batch older than 7 days. A pass that
    // would age out the WHOLE journal declines once and reports it, so a clock anomaly cannot
    // delete the audit trail wholesale (#2345 Gate 5 CH-5); the pass after it proceeds.
    auto declined = j.prune(32503680000000LL); // ~year 3000 in ms
    CHECK(declined.evicted == 0);
    CHECK(j.clock_jump_skips() == 1);
    CHECK(count_keys(*t.kv, kBatchKeyPrefix) == 2);

    auto stats = j.prune(32503680001000LL);
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
        REQUIRE(j.persist(one("r" + std::to_string(i), "armed")) == 1);
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
        REQUIRE(j.persist(one("r" + std::to_string(i), "armed")) == 1);
    REQUIRE(count_keys(*t.kv, kBatchKeyPrefix) == 3);

    auto stats = j.prune(0);
    CHECK(stats.evicted == 3); // no batch fits a 1-byte budget → all evicted
    CHECK(count_keys(*t.kv, kBatchKeyPrefix) == 0);
}

TEST_CASE("journal prune: a MALFORMED-KEY batch is quarantined; good batches survive",
          "[guardian][journal][prune]") {
    // A key that fails the strict shape check has no trustworthy timestamp, so retention can
    // neither age nor order it - it is quarantined on sight. (This key is also in the
    // pre-#2299 format, which is corruption for the same reason: the journal was dormant when
    // the format changed, so no row on any disk can legitimately carry it.)
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    REQUIRE(t.kv->set(kJournalNamespace, "lc:corrupt:000000000000", "not valid json"));
    REQUIRE(j.persist(one("good", "armed")) == 1);

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

TEST_CASE("journal prune: a corrupt VALUE under a good key survives prune (lazy-parse pin)",
          "[guardian][journal][prune]") {
    // The O(work) contract (#2299 perf-P-1): prune reads KEYS and value BYTE LENGTHS only, so
    // it can no longer see that a value is garbage - the replay pass quarantines it when it
    // reads the candidate it is about to place. Prune must therefore leave the row alone and
    // treat it as an ordinary retention candidate. This is the assertion that goes red if
    // someone "restores" a value parse to the prune scan.
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    const std::int64_t now = 1'700'000'000'000;
    REQUIRE(t.kv->set(kJournalNamespace, journal_batch_key(now, "wellkeyed", 0), "not valid json"));
    REQUIRE(j.persist(one("good", "armed")) == 1);

    auto stats = j.prune(now);
    CHECK(stats.quarantined == 0); // prune did not read the value, so it saw nothing wrong
    CHECK(j.quarantined() == 0);
    CHECK(count_keys(*t.kv, kBatchKeyPrefix) == 2);
    CHECK(count_keys(*t.kv, kQuarantineKeyPrefix) == 0);

    // It is still BOUNDED - the corrupt row is subject to every ceiling like any other row.
    j.set_retention_limits_for_test(/*days=*/100000, /*max_batches=*/1, /*max_bytes=*/kNoCap,
                                    /*max_quarantine=*/100);
    const auto trimmed = j.prune(now);
    CHECK(trimmed.evicted == 1);
    CHECK(count_keys(*t.kv, kBatchKeyPrefix) == 1);
}

TEST_CASE("journal prune: an orphan sent-label is GC'd", "[guardian][journal][prune]") {
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    REQUIRE(j.persist(one("r1", "armed")) == 1); // a surviving batch (its label, if any, is kept)
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

// ── Paging token bucket + sent-label classification (item 7 PR-Ag C5) ─────────

TEST_CASE("paging bucket delays then refills; caps at burst; never resets",
          "[guardian][journal][bucket]") {
    JournalPagingBucket b(/*refill_per_sec=*/1.0, /*burst=*/2.0);
    CHECK(b.ready(1000));
    b.take();
    CHECK(b.ready(1000));
    b.take();
    CHECK_FALSE(b.ready(1000)); // burst exhausted at the same instant

    CHECK(b.ready(2000)); // +1 token after 1 s
    b.take();
    CHECK_FALSE(b.ready(2000));

    // A long gap refills but CAPS at burst - no unbounded accumulation.
    CHECK(b.ready(1'000'000));
    CHECK(b.tokens() <= 2.0);
}

TEST_CASE("mark_batch_sent writes a sent-label; eviction classifies by its presence",
          "[guardian][journal][prune]") {
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    j.set_retention_limits_for_test(/*days=*/100000, /*max_batches=*/0, /*max_bytes=*/kNoCap,
                                    /*max_quarantine=*/100); // count cap 0 → prune evicts all
    REQUIRE(j.persist(one("r1", "armed")) == 1);
    auto rows = t.kv->list_entries(kJournalNamespace, kBatchKeyPrefix);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    j.mark_batch_sent((*rows)[0].key);
    CHECK(j.sent_labels_written() == 1);

    REQUIRE(j.persist(one("r2", "armed")) == 1); // a second, UNMARKED batch

    j.prune(0); // both evicted
    CHECK(j.evicted_sent_unacked() == 1);          // r1 had a sent-label
    CHECK(j.evicted_without_send_evidence() == 1);  // r2 had none
}

TEST_CASE("eviction classification falls back to a per-key read when the label scan fails",
          "[guardian][journal][prune]") {
    // The classifier reads the sent-label namespace ONCE per pass instead of once per evicted
    // key. If that scan fails it must still classify - from a bounded per-key read - or a
    // transient scan error would silently report a whole evict set as unsent.
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    j.set_retention_limits_for_test(/*days=*/100000, /*max_batches=*/0, /*max_bytes=*/kNoCap,
                                    /*max_quarantine=*/100); // count cap 0 -> evict everything
    REQUIRE(j.persist(one("r1", "armed")) == 1);
    auto rows = t.kv->list_entries(kJournalNamespace, kBatchKeyPrefix);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    j.mark_batch_sent((*rows)[0].key);          // this batch WAS delivered
    REQUIRE(j.persist(one("r2", "armed")) == 1); // this one was not

    j.inject_prune_sent_scan_failures_for_test(1);
    j.prune(0);
    CHECK(j.evicted_sent_unacked() == 1);         // the fallback found r1's label
    CHECK(j.evicted_without_send_evidence() == 1); // and correctly found none for r2
}

TEST_CASE("eviction classification: an UNREADABLE sent-label counts NEITHER outcome",
          "[guardian][journal][prune]") {
    // The fallback has to be the FALLIBLE per-key read. exists() answers false for both
    // "absent" and "the read failed", and the per-key read fails for exactly the reason the
    // scan just did - one broken database, not one broken key - so an exists()-based fallback
    // would report every evicted batch as "no send evidence", which is the reading an operator
    // is meant to treat as audit loss. Unknown is not evidence of absence.
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    j.set_retention_limits_for_test(/*days=*/100000, /*max_batches=*/0, /*max_bytes=*/kNoCap,
                                    /*max_quarantine=*/100);
    REQUIRE(j.persist(one("r1", "armed")) == 1);
    auto rows = t.kv->list_entries(kJournalNamespace, kBatchKeyPrefix);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    j.mark_batch_sent((*rows)[0].key);

    j.inject_prune_sent_scan_failures_for_test(1);
    j.inject_prune_sent_read_failures_for_test(5); // the correlated failure
    const auto stats = j.prune(0);

    CHECK(stats.evicted == 1); // the eviction itself still happened and is counted
    CHECK(j.batches_pruned() == 1);
    CHECK(j.evicted_sent_unacked() == 0);
    CHECK(j.evicted_without_send_evidence() == 0); // NOT reported as lost evidence
    CHECK(j.prune_failures() >= 1);                // counted instead - once, not per key
}

// ── Fault-injection + capacity hardening (governance Gate 7) ──────────────────

TEST_CASE("journal prune: an injected read failure is fail-safe (counted, read_ok false, retried)",
          "[guardian][journal][prune]") {
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    REQUIRE(j.persist(one("r1", "armed")) == 1);

    j.inject_read_failures_for_test(1); // the next scan reports a read error
    auto s = j.prune(0);
    CHECK_FALSE(s.read_ok);                         // distinguished from an empty journal (M5)
    CHECK(j.prune_failures() == 1);
    CHECK(count_keys(*t.kv, kBatchKeyPrefix) == 1); // nothing evicted on a failed scan

    // The failure did not latch anything permanently: the next pass reads cleanly.
    auto s2 = j.prune(0);
    CHECK(s2.read_ok);
    CHECK(j.prune_failures() == 1); // no new failure
}

TEST_CASE("journal prune: an injected delete failure leaves batches intact and is retried (M4)",
          "[guardian][journal][prune]") {
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    j.set_retention_limits_for_test(/*days=*/100000, /*max_batches=*/0, /*max_bytes=*/kNoCap,
                                    /*max_quarantine=*/100); // count cap 0 → prune evicts all
    REQUIRE(j.persist(one("r1", "armed")) == 1);
    REQUIRE(j.persist(one("r2", "armed")) == 1);

    j.inject_delete_failures_for_test(1);
    auto s = j.prune(0);
    CHECK(s.evicted == 0); // the delete failed
    CHECK(j.prune_failures() == 1);
    CHECK(count_keys(*t.kv, kBatchKeyPrefix) == 2); // batches NOT removed - left for the retry

    auto s2 = j.prune(0); // no injected fault now
    CHECK(s2.evicted == 2);
    CHECK(count_keys(*t.kv, kBatchKeyPrefix) == 0);
}

TEST_CASE("journal persist: a hard write ceiling refuses runaway growth, resumes after prune (UP-1)",
          "[guardian][journal][persist]") {
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    j.set_write_ceiling_for_test(/*max_batches=*/2, /*max_bytes=*/kNoCap);
    REQUIRE(j.persist(one("r1", "armed")) == 1);
    REQUIRE(j.persist(one("r2", "armed")) == 1); // journal now at the hard ceiling of 2
    CHECK(j.journal_batch_count() == 2);

    // A third batch is REFUSED (never written past the ceiling) + counted; the shared DB is bounded.
    CHECK(j.persist(one("r3", "armed")) == 0);
    CHECK(j.write_capacity_rejected() == 1);
    CHECK(count_keys(*t.kv, kBatchKeyPrefix) == 2); // r3 never written

    // A prune that ages everything out frees the ceiling; persist resumes. Two passes: the
    // first declines the whole-journal wipe (the clock-anomaly guard), the second proceeds.
    j.prune(32503680000000LL); // ~year 3000: all batches older than retention
    j.prune(32503680001000LL);
    CHECK(j.journal_batch_count() == 0);
    CHECK(j.persist(one("r3", "armed")) == 1);
    CHECK(j.write_capacity_rejected() == 1); // no new rejection
}

TEST_CASE("journal prune: over-cap quarantine eviction is counted, not silent (UP-7)",
          "[guardian][journal][prune]") {
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    j.set_retention_limits_for_test(100000, kNoCap, kNoCap, /*max_quarantine=*/1);
    for (int i = 0; i < 3; ++i)
        REQUIRE(
            t.kv->set(kJournalNamespace, "lc:bad" + std::to_string(i) + ":000000000000", "garbage"));

    j.prune(0); // quarantines 3, then sheds 2 over the cap of 1
    CHECK(count_keys(*t.kv, kQuarantineKeyPrefix) == 1);
    CHECK(j.quarantine_capacity_evicted() == 2); // the shed is COUNTED, not silent
    // Gauge tracks the lc: namespace: the rebase counted all 3 garbage rows, the quarantine
    // fetch_subs removed all 3 (they left lc:), so the live-batch gauge is back to 0 (#2303 -
    // the quarantine-path fetch_sub, otherwise untested here).
    CHECK(j.journal_batch_count() == 0);
    CHECK(j.journal_bytes() == 0);
}

TEST_CASE("journal size gauges track live batches + bytes across persist and prune",
          "[guardian][journal][prune]") {
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    CHECK(j.journal_batch_count() == 0);
    CHECK(j.journal_bytes() == 0);

    REQUIRE(j.persist(one("r1", "armed")) == 1);
    REQUIRE(j.persist(one("r2", "armed")) == 1);
    CHECK(j.journal_batch_count() == 2);
    CHECK(j.journal_bytes() > 0);
    const auto bytes2 = j.journal_bytes();

    // A prune with a count cap of 1 leaves one batch: the gauges follow the survivor set.
    j.set_retention_limits_for_test(100000, /*max_batches=*/1, kNoCap, 100);
    j.prune(0);
    CHECK(j.journal_batch_count() == 1);
    CHECK(j.journal_bytes() > 0);
    CHECK(j.journal_bytes() < bytes2);
}

// ── #2303 C1: the write ceiling must not forget the on-disk journal at startup ──

TEST_CASE("journal reopen: a fresh instance seeds its size gauges from the on-disk journal",
          "[guardian][journal][persist][reopen]") {
    TestKv t;
    std::uint64_t bytes_before = 0;
    {
        GuardianLifecycleJournal a(t.kv.get());
        REQUIRE(a.persist(one("r1", "armed")) == 1);
        REQUIRE(a.persist(one("r2", "armed")) == 1);
        REQUIRE(a.journal_batch_count() == 2);
        bytes_before = a.journal_bytes();
    }

    // Restart: a new journal instance over the SAME on-disk journal. Before the fix both gauges
    // started at 0 here, so the write ceiling was blind to everything already on disk until the
    // first successful prune - and start_local()'s arm flush persists before any prune runs.
    GuardianLifecycleJournal b(t.kv.get());
    CHECK(b.journal_batch_count() == 2);
    // Byte-EXACT, not merely non-zero: this cross-pins namespace_size's
    // SUM(octet_length(value)) against the value.size() accounting persist/prune use.
    CHECK(b.journal_bytes() == bytes_before);
}

TEST_CASE("journal reopen: the write ceiling is enforced against pre-existing batches",
          "[guardian][journal][persist][reopen]") {
    TestKv t;
    {
        GuardianLifecycleJournal a(t.kv.get());
        REQUIRE(a.persist(one("r1", "armed")) == 1);
        REQUIRE(a.persist(one("r2", "armed")) == 1);
    }

    // The reopened instance is at its ceiling from its FIRST write - no free window in which a
    // crash-loop could grow the SHARED kv_store.db past the hard cap.
    GuardianLifecycleJournal b(t.kv.get());
    b.set_write_ceiling_for_test(/*max_batches=*/2, /*max_bytes=*/kNoCap);
    CHECK(b.persist(one("r3", "armed")) == 0);
    CHECK(b.write_capacity_rejected() == 1);
    CHECK(b.write_failures() == 0);                 // refused by the ceiling, not a failed write
    CHECK(count_keys(*t.kv, kBatchKeyPrefix) == 2); // r3 never reached the shared DB
}

TEST_CASE("journal reopen: multibyte values are sized in BYTES, not characters",
          "[guardian][journal][persist][reopen]") {
    // Guards the octet_length(value) in namespace_size: bare LENGTH() on a TEXT column counts
    // CHARACTERS, so a multibyte rule_name would seed the byte gauge LOW - the one direction
    // that silently loosens the write ceiling.
    TestKv t;
    std::uint64_t bytes_before = 0;
    {
        GuardianLifecycleJournal a(t.kv.get());
        auto r = rec("r1", "armed");
        r.rule_name = "café-日本語-Ünïcödé"; // multibyte
        std::vector<std::shared_ptr<const JournalRecord>> pending{
            std::make_shared<const JournalRecord>(r)};
        REQUIRE(a.persist(pending) == 1);
        bytes_before = a.journal_bytes();
    }

    GuardianLifecycleJournal b(t.kv.get());
    CHECK(b.journal_batch_count() == 1);
    CHECK(b.journal_bytes() == bytes_before);
}

TEST_CASE("journal reopen: an un-sizable journal fails CLOSED (assume at ceiling)",
          "[guardian][journal][persist][reopen]") {
    TestKv t;
    // Move the store out from under the journal: the moved-from KvStore is closed (db_ null),
    // so the construction-time size probe fails exactly as a chronic SQLITE_BUSY or a corrupt
    // page would. We have least right to assume "empty" precisely when we cannot read it, so
    // the posture is assume-at-ceiling: refuse + COUNT, never silently write on.
    KvStore closed{std::move(*t.kv)};

    GuardianLifecycleJournal j(t.kv.get());
    CHECK(j.journal_batch_count() == kMaxJournalBatches * 2); // the default hard ceiling
    CHECK(j.journal_bytes() == kMaxJournalBytes * 2);

    CHECK(j.persist(one("r1", "armed")) == 0);
    CHECK(j.write_capacity_rejected() == 1);
    CHECK(j.write_failures() == 0); // refused BEFORE the write, not attempted and failed
}

// ── #2303 gauge-race: prune must not clobber a concurrent persist ───────────────

TEST_CASE("journal prune: rebase-as-delta preserves a concurrent persist's increment (#2303)",
          "[guardian][journal][prune]") {
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    REQUIRE(j.persist(one("r1", "armed")) == 1);
    REQUIRE(j.persist(one("r2", "armed")) == 1);
    REQUIRE(j.journal_batch_count() == 2);

    // Fire a simulated concurrent persist() in the exact window between prune's scan and its
    // removal accounting - the window an absolute survivor-store clobbers. The scan captured
    // 2 rows; the old `store(survivors.size())` would publish 2 and silently lose this 3rd
    // insert, under-counting the write ceiling. Rebase-as-delta (RMW only) must keep it.
    bool fired = false;
    j.set_post_scan_hook_for_test([&] {
        if (fired)
            return;
        fired = true;
        REQUIRE(j.persist(one("r3", "armed")) == 1); // lands on disk + fetch_adds the gauge
    });

    auto s = j.prune(0); // retention wide open: nothing evicted, so gauge == true on-disk size
    CHECK(s.read_ok);
    CHECK(fired);
    CHECK(count_keys(*t.kv, kBatchKeyPrefix) == 3);
    CHECK(j.journal_batch_count() == 3); // the concurrent insert survived the rebase, not clobbered
    // Exact bytes, not merely > 0: cross-pin the byte gauge against the true on-disk size so a
    // bytes-SIDE clobber (which the count check above would miss) also fails this test.
    auto sz = t.kv->namespace_size(kJournalNamespace, kBatchKeyPrefix);
    REQUIRE(sz.has_value());
    CHECK(j.journal_bytes() == sz->bytes);
    CHECK(sz->bytes > 0);
}

TEST_CASE("journal prune: rebases a fail-closed boot seed back to on-disk reality (#2303)",
          "[guardian][journal][prune][reopen]") {
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    REQUIRE(j.persist(one("r1", "armed")) == 1);
    REQUIRE(j.persist(one("r2", "armed")) == 1);
    j.set_write_ceiling_for_test(/*max_batches=*/1000, /*max_bytes=*/kNoCap);

    // Stage the fail-closed boot seed: the ctor size-probe failed once, pinning the gauge at
    // the hard ceiling. A pure fetch_sub scheme (no rebase) could never walk this back down -
    // one unlucky boot would brick journal writes forever. Rebase-as-delta must recover it.
    j.set_size_gauges_for_test(/*count=*/1000, /*bytes=*/1000);
    CHECK(j.persist(one("bricked", "armed")) == 0); // ceiling reads full -> rejected
    CHECK(j.write_capacity_rejected() == 1);

    auto s = j.prune(0); // a successful scan rebases the gauge to the true 2 on disk
    CHECK(s.read_ok);
    CHECK(j.journal_batch_count() == 2); // recovered from the conservative seed
    // Byte gauge recovers too: this is the ONLY test exercising the NEGATIVE-delta (ceiling ->
    // reality walk-down) byte rebase, so cross-pin it against on-disk truth (consistency review).
    auto sz = t.kv->namespace_size(kJournalNamespace, kBatchKeyPrefix);
    REQUIRE(sz.has_value());
    CHECK(j.journal_bytes() == sz->bytes);

    CHECK(j.persist(one("r3", "armed")) == 1); // writes work again - no longer bricked
    CHECK(j.journal_batch_count() == 3);
}

TEST_CASE("journal prune: a persist in the PRE-scan window over-counts safely, heals next scan "
          "(#2303 UP-3)",
          "[guardian][journal][prune]") {
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    REQUIRE(j.persist(one("r1", "armed")) == 1);
    REQUIRE(j.persist(one("r2", "armed")) == 1);

    // Fire a concurrent persist in the window AFTER pre_count is snapshotted but BEFORE
    // list_entries - so the new row is BOTH seen by the scan (in rows->size()) AND carries its
    // own fetch_add: the transient DOUBLE-count. It must be an OVER-count (ceiling tightens,
    // never loosens), then heal to on-disk truth on the next scan.
    bool fired = false;
    j.set_pre_scan_hook_for_test([&] {
        if (fired)
            return;
        fired = true;
        REQUIRE(j.persist(one("r3", "armed")) == 1);
    });

    auto s1 = j.prune(0);
    CHECK(s1.read_ok);
    CHECK(fired);
    CHECK(count_keys(*t.kv, kBatchKeyPrefix) == 3);
    CHECK(j.journal_batch_count() == 4);  // double-counted: rebase(+1) on top of persist(+1)
    CHECK(j.journal_batch_count() >= 3);  // the invariant: never BELOW on-disk (ceiling stays safe)

    // Next scan (no hook) rebases via the unclamped pre_count and heals exactly to the 3 on disk.
    j.set_pre_scan_hook_for_test(nullptr);
    auto s2 = j.prune(0);
    CHECK(s2.read_ok);
    CHECK(j.journal_batch_count() == 3);
    CHECK(j.gauge_underflow() == 0); // an over-count never trips the negative tripwire
}

TEST_CASE("journal persist: a negative gauge fails CLOSED and recovers after a prune rebase "
          "(#2303 UP-2 / Sol)",
          "[guardian][journal][persist]") {
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    REQUIRE(j.persist(one("r1", "armed")) == 1);

    // Force a negative gauge. This cannot happen in correct operation (every lc: row is
    // counted), so the seam stages the state a future over-subtraction bug would produce.
    j.set_size_gauges_for_test(/*count=*/-5, /*bytes=*/-5);

    // FAIL-CLOSED: the write is REFUSED (not admitted on a clamp-to-0 read, which would be
    // fail-OPEN and grow the shared kv_store.db on an untrusted size), and the tripwire counts.
    CHECK(j.persist(one("neg", "armed")) == 0);
    CHECK(j.gauge_underflow() >= 1);
    CHECK(j.write_failures() == 0);                 // refused BEFORE the write, not attempted and failed
    CHECK(count_keys(*t.kv, kBatchKeyPrefix) == 1); // the refused row never reached the shared DB

    // A successful prune rebases the gauge back to on-disk reality (the unclamped pre_count
    // walks the negative up); writes then resume.
    auto s = j.prune(0);
    CHECK(s.read_ok);
    CHECK(j.journal_batch_count() == 1); // rebased to the one row (r1) actually on disk
    CHECK(j.persist(one("r2", "armed")) == 1); // no longer refused
    CHECK(j.journal_batch_count() == 2);
}

TEST_CASE("journal persist: a negative gauge stays bricked while prune scans keep failing "
          "(#2303 UP-1 / chaos)",
          "[guardian][journal][persist]") {
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    REQUIRE(j.persist(one("r1", "armed")) == 1);
    j.set_size_gauges_for_test(/*count=*/-3, /*bytes=*/-3); // simulate an over-subtraction bug

    // Recovery is ONLY via a successful prune rebase (UP-1). While the scan chronically fails,
    // the negative gauge is never walked back and writes stay refused - bricked, but BOUNDED
    // (records defer to RAM staging, drops counted) rather than the old unbounded fail-open.
    j.inject_read_failures_for_test(2);
    CHECK(j.persist(one("x1", "armed")) == 0); // still refused
    auto f1 = j.prune(0);
    CHECK_FALSE(f1.read_ok); // scan failed -> no rebase
    CHECK(j.persist(one("x2", "armed")) == 0); // still bricked
    auto f2 = j.prune(0);
    CHECK_FALSE(f2.read_ok);
    CHECK(count_keys(*t.kv, kBatchKeyPrefix) == 1); // nothing written while bricked (only r1)

    // The FIRST successful scan rebases and unbricks - no latched-bad state.
    auto ok = j.prune(0);
    CHECK(ok.read_ok);
    CHECK(j.journal_batch_count() == 1);
    CHECK(j.persist(one("r2", "armed")) == 1); // recovered
}

TEST_CASE("journal prune: a future-dated batch is shed before real evidence",
          "[guardian][journal][prune][chaos]") {
    // A batch stamped implausibly far ahead can never be "too old", and oldest-first count
    // eviction never reaches it either - so it is immortal, and worse, it DISPLACES real
    // records: every genuine batch written afterwards is older, so it is the one evicted in
    // its place. Ordering future-dated batches first is what stops that.
    // RED before the fix: the two real batches are evicted and the future-dated one survives.
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    const std::int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();

    // Hand-write a batch stamped a year ahead, alongside two ordinary ones. The future stamp
    // has to be in the KEY: that is what retention reads, and a key carrying an ordinary
    // timestamp would make this an ordinary batch no matter what the value said.
    const std::int64_t future_ts = now + 365LL * 86400000;
    const std::string future_key = journal_batch_key(future_ts, "future", 1);
    REQUIRE(t.kv->set(kJournalNamespace, future_key,
                      std::format(R"({{"v":4,"ts_ms":{},"entries":[{}]}})", future_ts,
                                  R"({"rule_id":"r","event_id":"future-1","kind":"armed",)"
                                  R"("guard_type":"file","rule_name":"n","generation":1,)"
                                  R"("enqueued_ns":1700000000000000000})")));
    REQUIRE(j.persist(one("real1", "armed")) == 1);
    REQUIRE(j.persist(one("real2", "armed")) == 1);
    REQUIRE(count_keys(*t.kv, kBatchKeyPrefix) == 3);

    // Count ceiling of 2 forces exactly one eviction; it must be the future-dated one.
    j.set_retention_limits_for_test(/*days=*/100000, /*max_batches=*/2,
                                    /*max_bytes=*/kNoCap, /*max_quarantine=*/100);
    const auto stats = j.prune(now);
    CHECK(stats.evicted == 1);
    auto rows = t.kv->list_entries(kJournalNamespace, kBatchKeyPrefix);
    REQUIRE(rows.has_value());
    CHECK(rows->size() == 2);
    for (const auto& r : *rows)
        CHECK(r.key != future_key); // the real evidence is what survived
}

TEST_CASE("journal prune: a whole-journal wipe is declined even with no clock jump",
          "[guardian][journal][prune][chaos]") {
    // The anomaly guard fires on either of two signals: a big clock STEP since the last pass,
    // or the OUTCOME - this pass would age out everything. Every other test in the suite trips
    // it via the step, so the outcome branch was dead-covered: removing it left the whole suite
    // green (#2345 Gate 3 QE). Here the clock advances normally and the RETENTION WINDOW is
    // tiny, so only the outcome branch can fire.
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    const std::int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
    REQUIRE(j.persist(one("r1", "armed")) == 1);
    REQUIRE(j.persist(one("r2", "armed")) == 1);

    // Retention of 0 days: everything is expired, with no clock anomaly whatsoever.
    j.set_retention_limits_for_test(/*days=*/0, /*max_batches=*/1000,
                                    /*max_bytes=*/kNoCap, /*max_quarantine=*/100);
    // A few seconds later both batches are past a zero-length window. This is the FIRST pass,
    // so last_prune_now_ms_ is still zero and the clock-step branch cannot fire.
    const auto declined = j.prune(now + 5000);
    CHECK(declined.evicted == 0);
    CHECK(j.clock_jump_skips() == 1); // counted, and the trail survives the first pass
    CHECK(count_keys(*t.kv, kBatchKeyPrefix) == 2);

    const auto accepted = j.prune(now + 6000); // ...and the next pass proceeds
    CHECK(accepted.evicted == 2);
}

TEST_CASE("journal prune: an IMPLAUSIBLY LARGE value cannot evict the rest of the journal",
          "[guardian][journal][prune]") {
    // Gate 4 unhappy-path UP-1. Before #2299 prune parsed every value, so a corrupt row was
    // quarantined OUT of the candidate set and never counted toward the byte ceiling. With a
    // keys-only prune it counts for its full stored size - and byte eviction is deliberately
    // UNCAPPED (it has to bring an over-ceiling journal back under in one pass), so a single
    // tampered or bit-rotted oversized row would evict every older batch in one go, deleting
    // undelivered evidence and counting it as ordinary retention.
    //
    // A row larger than persist() can produce is corruption by size, detectable from the scan
    // alone. RED without the size check: the good batches are gone.
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    // persist() stamps the real wall clock, so the fat row's key must be minted from the SAME
    // clock to sit newest - a hardcoded epoch would make it oldest and the test would pass for
    // the wrong reason (oldest-first would evict the fat row first, sparing the rest anyway).
    const std::int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();

    // Three ordinary batches, then one oversized row stamped NEWEST, so oldest-first eviction
    // reaches the real evidence BEFORE it would ever reach the bad row.
    for (int i = 0; i < 3; ++i)
        REQUIRE(j.persist(one("real" + std::to_string(i), "armed")) == 1);
    // Sized from the stable BATCH cap, deliberately not from the threshold under test: a
    // fixture derived from kMaxPlausibleJournalValueBytes would move with it and could not
    // detect the threshold being widened.
    const std::string fat_key = journal_batch_key(now + 60'000, "fat", 0);
    REQUIRE(t.kv->set(kJournalNamespace, fat_key,
                      std::string(2 * kMaxJournalBatchBytes + 1, 'x')));

    // A byte ceiling far below the oversized row, so it alone would blow it.
    j.set_retention_limits_for_test(/*days=*/100000, /*max_batches=*/kNoCap,
                                    /*max_bytes=*/64 * 1024, /*max_quarantine=*/100);
    const auto stats = j.prune(now);

    CHECK(stats.quarantined == 1);                       // the oversized row moved aside...
    CHECK_FALSE(t.kv->exists(kJournalNamespace, fat_key));
    CHECK(stats.evicted == 0);                           // ...and took no real evidence with it
    CHECK(count_keys(*t.kv, kBatchKeyPrefix) == 3);      // all three genuine batches survive
    // And the gauge was adjusted by what actually left, not by a parsed size it never read.
    CHECK(j.quarantined() == 1);
}

TEST_CASE("journal prune: a MAXIMAL legitimate batch is never size-quarantined",
          "[guardian][journal][prune]") {
    // The other half of the size-quarantine pin (Gate 8 security). The first test proves an
    // oversized row IS quarantined; this one proves the threshold cannot reach a batch
    // persist() can actually write - because a quarantined row is eventually deleted by the
    // over-cap shed, so a threshold that crept below the write path's bound would silently
    // destroy real audit evidence with only a counter to show for it.
    //
    // Built at the write path's worst case: every record carrying maximum-length fields, so
    // the byte cap (not the entry cap) is what splits the batches.
    TestKv t;
    GuardianLifecycleJournal j(t.kv.get());
    const std::string big(kMaxJournalFieldBytes - 1, 'x');
    std::vector<std::shared_ptr<const JournalRecord>> pending;
    for (int i = 0; i < 200; ++i) {
        auto r = std::make_shared<JournalRecord>();
        r->rule_id = big;
        r->generation = 1;
        r->event_id = "e" + std::to_string(i);
        r->enqueued_ns = 1'700'000'000'000'000'000;
        r->kind = "armed";
        r->guard_type = "file";
        r->rule_name = big;
        pending.push_back(std::move(r));
    }
    REQUIRE(j.persist(pending) == 200);
    const auto batches = j.batches_written();
    REQUIRE(batches >= 2); // the byte cap really did split them

    // Every row persist() wrote must be within the plausible-size bound...
    auto rows = t.kv->list_keys_sized(kJournalNamespace, kBatchKeyPrefix);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == batches);
    for (const auto& r : *rows)
        CHECK(r.bytes <= kMaxPlausibleJournalValueBytes);

    // ...and a prune must leave every one of them alone.
    const std::int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
    const auto stats = j.prune(now);
    CHECK(stats.quarantined == 0);
    CHECK(j.quarantined() == 0);
    CHECK(count_keys(*t.kv, kBatchKeyPrefix) == batches);
}
