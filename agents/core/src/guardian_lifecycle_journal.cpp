#include "guardian_lifecycle_journal.hpp"

#include <yuzu/agent/kv_store.hpp>

#include <algorithm>
#include <chrono>
#include <format>
#include <random>
#include <set>
#include <vector>

namespace yuzu::agent {

namespace {

std::string make_journal_nonce() {
    std::random_device rd;
    const std::uint64_t v = (static_cast<std::uint64_t>(rd()) << 32) ^ static_cast<std::uint64_t>(rd());
    return std::format("{:016x}", v);
}

// A cheap byte estimate for one record's JSON entry — used only to decide when to
// start a new batch, so it can be approximate as long as it never UNDER-counts the
// wire fields by enough to blow past kMaxJournalBatchBytes on a realistic record.
std::size_t est_entry_bytes(const JournalRecord& r) {
    return r.rule_id.size() + r.event_id.size() + r.kind.size() + r.guard_type.size() +
           r.rule_name.size() + 128; // 128 = JSON keys/punctuation/number fields
}

} // namespace

GuardianLifecycleJournal::GuardianLifecycleJournal(KvStore* kv)
    : kv_(kv), boot_nonce_(make_journal_nonce()) {}

std::size_t
GuardianLifecycleJournal::persist(std::span<const std::shared_ptr<const JournalRecord>> pending) {
    if (!kv_ || pending.empty())
        return 0;

    std::size_t written = 0;
    std::size_t i = 0;
    while (i < pending.size()) {
        // Assemble one batch up to the entry-count and byte caps. A single record
        // larger than the byte cap still forms its own 1-entry batch (never dropped
        // here — validate_record already bounded each field).
        std::vector<JournalRecord> entries;
        std::size_t batch_bytes = 64; // envelope overhead ({"v":4,"ts_ms":...,"entries":[]})
        while (i < pending.size() && entries.size() < kMaxJournalEntriesPerBatch) {
            const auto& rec = pending[i];
            if (!rec) { // defensive: snapshot never stages nullptr, but don't trust it
                ++i;
                continue;
            }
            const std::size_t rb = est_entry_bytes(*rec);
            if (!entries.empty() && batch_bytes + rb > kMaxJournalBatchBytes)
                break; // this record starts the next batch
            entries.push_back(*rec);
            batch_bytes += rb;
            ++i;
        }
        if (entries.empty())
            continue;

        const std::int64_t ts_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                       std::chrono::system_clock::now().time_since_epoch())
                                       .count();
        const std::string value = serialize_journal_batch(ts_ms, entries);
        const std::string key = journal_batch_key(boot_nonce_, batch_seq_);

        KvInsert result;
        if (inject_fail_writes_.load(std::memory_order_relaxed) > 0) {
            inject_fail_writes_.fetch_sub(1, std::memory_order_relaxed); // test-only fault
            result = KvInsert::Error;
        } else {
            result = kv_->insert_if_absent(kJournalNamespace, key, value);
        }
        switch (result) {
        case KvInsert::Inserted:
            ++batch_seq_;
            batches_written_.fetch_add(1, std::memory_order_relaxed);
            written += entries.size();
            break;
        case KvInsert::Exists:
            // ~2^-64 boot-nonce+seq collision: DON'T overwrite. Count it, advance the
            // seq past the occupied key, and circuit-break (the tick retries the rest).
            key_collisions_.fetch_add(1, std::memory_order_relaxed);
            ++batch_seq_;
            write_failures_.fetch_add(1, std::memory_order_relaxed);
            return written;
        case KvInsert::Error:
            // Per-push circuit breaker: stop at the first write failure so one bad
            // write can't stall apply_rules for 500 × the 5 s busy timeout. Keep the
            // seq (nothing was written to this key), leave the rest pending.
            write_failures_.fetch_add(1, std::memory_order_relaxed);
            return written;
        }
    }
    return written;
}

JournalPruneStats GuardianLifecycleJournal::prune(std::int64_t now_ms) {
    JournalPruneStats stats;
    if (!kv_)
        return stats;

    auto rows = kv_->list_entries(kJournalNamespace, kBatchKeyPrefix);
    if (!rows) {
        prune_failures_.fetch_add(1, std::memory_order_relaxed); // read error → fail-safe, retry next pass
        return stats;
    }

    struct Live {
        std::string key;
        std::int64_t ts_ms;
        std::size_t bytes;
    };
    std::vector<Live> live;
    live.reserve(rows->size());
    for (auto& row : *rows) {
        auto parsed = parse_journal_batch(row.value);
        if (!parsed) {
            // Unparseable → move aside atomically so replay never re-parses it.
            if (kv_->rename_key(kJournalNamespace, row.key, journal_quarantine_key(row.key)) ==
                KvRename::Renamed) {
                quarantined_.fetch_add(1, std::memory_order_relaxed);
                ++stats.quarantined;
            } else {
                quarantine_failures_.fetch_add(1, std::memory_order_relaxed);
            }
            continue;
        }
        live.push_back(Live{row.key, parsed->ts_ms, row.value.size()});
    }

    // Oldest-first by (ts_ms, key) — NOT lexical key (the boot-nonce is random).
    std::sort(live.begin(), live.end(), [](const Live& a, const Live& b) {
        return a.ts_ms != b.ts_ms ? a.ts_ms < b.ts_ms : a.key < b.key;
    });

    const std::int64_t min_ts =
        now_ms - static_cast<std::int64_t>(retention_days_) * 86400 * 1000;
    std::size_t total_bytes = 0;
    for (const auto& l : live)
        total_bytes += l.bytes;

    std::vector<std::string> evict;
    std::size_t surviving = live.size();
    for (const auto& l : live) { // oldest first: age is absolute, count/bytes trim from this end
        const bool too_old = l.ts_ms < min_ts;
        const bool too_many = surviving > max_batches_;
        const bool too_big = total_bytes > max_bytes_;
        if (too_old || too_many || too_big) {
            evict.push_back(l.key);
            --surviving;
            total_bytes -= l.bytes;
        }
    }
    if (!evict.empty()) {
        const int n = kv_->del_keys(kJournalNamespace, evict);
        batches_pruned_.fetch_add(static_cast<std::uint64_t>(n), std::memory_order_relaxed);
        stats.evicted = static_cast<std::size_t>(n);
    }

    // Surviving batch keys (parseable, not evicted) — the reference set for sent-label GC.
    const std::set<std::string> evicted_set(evict.begin(), evict.end());
    std::set<std::string> survivors;
    for (const auto& l : live)
        if (!evicted_set.count(l.key))
            survivors.insert(l.key);

    // Sent-label GC: drop any sent:<...> whose batch no longer survives — an evicted batch's
    // label, or an orphan from a crash between the pop-after-send label write and eviction.
    if (auto sent = kv_->list_entries(kJournalNamespace, kSentKeyPrefix)) {
        std::vector<std::string> stale;
        for (const auto& s : *sent)
            if (!survivors.count(journal_batch_key_from_sent_key(s.key)))
                stale.push_back(s.key);
        if (!stale.empty())
            stats.sent_labels_gc =
                static_cast<std::size_t>(kv_->del_keys(kJournalNamespace, stale));
    }

    // Bound the quarantine set (drop oldest-by-key; corrupt batches have no trusted ts_ms).
    if (auto q = kv_->list_entries(kJournalNamespace, kQuarantineKeyPrefix)) {
        if (q->size() > max_quarantine_) {
            std::vector<std::string> drop;
            const std::size_t excess = q->size() - max_quarantine_;
            for (std::size_t i = 0; i < excess; ++i)
                drop.push_back((*q)[i].key); // list_entries is key-sorted
            kv_->del_keys(kJournalNamespace, drop);
        }
    }

    return stats;
}

} // namespace yuzu::agent
