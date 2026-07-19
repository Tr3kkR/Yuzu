#include "guardian_lifecycle_journal.hpp"

#include <yuzu/agent/kv_store.hpp>

#include <chrono>
#include <format>
#include <random>
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

} // namespace yuzu::agent
