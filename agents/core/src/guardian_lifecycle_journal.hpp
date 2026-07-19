#pragma once

/**
 * guardian_lifecycle_journal.hpp -- the ENGINE-owned durable side of the Guardian
 * lifecycle-audit journal (item 7 PR-Ag; design rev 4.1).
 *
 * Homed on GuardianEngine, NOT GuardianSparkRuntime: the runtime is the
 * detach-survival object (a late SparkEngine handler may run past the engine), so
 * it must own everything it touches and NEVER borrow a KvStore. The engine, by
 * contrast, already borrows the agent-owned KvStore (kv_) with a proven
 * member-destruction-order guarantee — this component makes the same borrow.
 *
 * C2 delivers persist() only; paging + retention (C4/C5) layer on later. NOT
 * thread-safe on its own: the engine calls into it only under its own mtx_, and
 * KvStore serialises its single connection.
 */

#include "guardian_journal_format.hpp"

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <atomic>
#include <cstdint>
#include <memory>
#include <span>
#include <string>

namespace yuzu::agent {

class KvStore;

/// One prune pass's outcome (also mirrored on the lock-free counters).
struct JournalPruneStats {
    std::size_t evicted{0};        ///< batches removed by retention (age/count/bytes)
    std::size_t quarantined{0};    ///< unparseable batches moved aside this pass
    std::size_t sent_labels_gc{0}; ///< orphaned/evicted sent-labels removed this pass
};

class YUZU_EXPORT GuardianLifecycleJournal {
public:
    /// `kv` is BORROWED and must outlive this component (the agent owns it and
    /// destroys it after the engine — agent.cpp member order). May be null (KV
    /// unavailable): persist() then durably writes nothing.
    explicit GuardianLifecycleJournal(KvStore* kv);

    /// Serialise + durably write the FIFO-ordered `pending` records in batches
    /// (each ≤ kMaxJournalEntriesPerBatch entries and ≈ kMaxJournalBatchBytes).
    /// Returns the count of RECORDS durably written — the caller passes it to
    /// GuardianSparkRuntime::erase_persisted_prefix(). A per-push CIRCUIT BREAKER
    /// stops at the first write failure (remaining records stay pending for the
    /// maintenance-tick retry) so one failing write cannot stall a 500-rule
    /// apply_rules for 500 × the 5 s KvStore busy timeout under mtx_.
    std::size_t persist(std::span<const std::shared_ptr<const JournalRecord>> pending);

    /// Enforce retention + quarantine (design §6, rev-4.1 #9). Evicts the oldest
    /// batches by (ts_ms, key) once they exceed the age (kJournalRetentionDays),
    /// count (kMaxJournalBatches), or byte (kMaxJournalBytes) caps; moves any
    /// unparseable batch aside to a bounded quarantine (atomic rename); GCs
    /// sent-labels whose batch no longer survives. `now_ms` is the wall clock in ms
    /// (a parameter so age eviction is testable). Fail-safe: a read error counts
    /// prune_failures and returns, never throws, never fatal. Runs off mtx_ (KvStore
    /// serialises itself); wired into the tick phase-2 + a boot barrier in C5.
    JournalPruneStats prune(std::int64_t now_ms);

    // Integrity counters (design §2 loss table). Lock-free.
    [[nodiscard]] std::uint64_t batches_written() const noexcept {
        return batches_written_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t write_failures() const noexcept {
        return write_failures_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t key_collisions() const noexcept {
        return key_collisions_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t quarantined() const noexcept {
        return quarantined_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t quarantine_failures() const noexcept {
        return quarantine_failures_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t batches_pruned() const noexcept {
        return batches_pruned_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t prune_failures() const noexcept {
        return prune_failures_.load(std::memory_order_relaxed);
    }

    /// TEST-ONLY: force the next `n` batch writes to fail (as if KvStore returned
    /// Error), exercising the per-push circuit breaker and the maintenance-tick
    /// retry (Sol BLOCKER-4) without a real disk fault. No production caller.
    void inject_write_failures_for_test(int n) noexcept {
        inject_fail_writes_.store(n, std::memory_order_relaxed);
    }

    /// TEST-ONLY: shrink the retention caps so count/byte/quarantine eviction is
    /// reachable at unit-test scale (production caps are 1000 batches / 32 MiB / 100
    /// quarantined). Age eviction needs no shrink — pass a future now_ms to prune().
    void set_retention_limits_for_test(int days, std::size_t max_batches, std::size_t max_bytes,
                                       std::size_t max_quarantine) noexcept {
        retention_days_ = days;
        max_batches_ = max_batches;
        max_bytes_ = max_bytes;
        max_quarantine_ = max_quarantine;
    }

private:
    KvStore* kv_;                ///< BORROWED; outlives this (agent owns it)
    std::string boot_nonce_;     ///< random, fixed at construction — batch-key uniqueness across restarts
    std::uint64_t batch_seq_{0}; ///< per-process monotonic batch-key sequence (persist runs single-threaded under mtx_)
    std::atomic<std::uint64_t> batches_written_{0};
    std::atomic<std::uint64_t> write_failures_{0};
    std::atomic<std::uint64_t> key_collisions_{0};
    std::atomic<std::uint64_t> quarantined_{0};         ///< unparseable batches moved aside
    std::atomic<std::uint64_t> quarantine_failures_{0}; ///< could not even quarantine a corrupt batch
    std::atomic<std::uint64_t> batches_pruned_{0};      ///< batches evicted by retention
    std::atomic<std::uint64_t> prune_failures_{0};      ///< a prune pass could not read the journal
    std::atomic<int> inject_fail_writes_{0};            ///< test-only forced-failure countdown
    // Retention caps — default to the production constants; a test may shrink them.
    int retention_days_{kJournalRetentionDays};
    std::size_t max_batches_{kMaxJournalBatches};
    std::size_t max_bytes_{kMaxJournalBytes};
    std::size_t max_quarantine_{kMaxQuarantineBatches};
};

} // namespace yuzu::agent
