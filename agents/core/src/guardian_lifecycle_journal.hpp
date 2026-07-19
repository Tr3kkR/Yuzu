#pragma once

/**
 * guardian_lifecycle_journal.hpp -- the ENGINE-owned durable side of the Guardian
 * lifecycle-audit journal (item 7 PR-Ag; design rev 4.1).
 *
 * Homed on GuardianEngine, NOT GuardianSparkRuntime: the runtime is the
 * detach-survival object (a late SparkEngine handler may run past the engine), so
 * it must own everything it touches and NEVER borrow a KvStore. The engine, by
 * contrast, already borrows the agent-owned KvStore (kv_) with a proven
 * member-destruction-order guarantee - this component makes the same borrow.
 *
 * C2 delivers persist() only; paging + retention (C4/C5) layer on later. NOT
 * thread-safe on its own: the engine calls into it only under its own mtx_, and
 * KvStore serialises its single connection.
 */

#include "guardian_journal_format.hpp"

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <utility>

namespace yuzu::agent {

class KvStore;
class GuardianSparkRuntime;

/// A monotonic token bucket for replay paging (rev-4.1 #8). PROCESS-LIFETIME: it is NOT
/// reset on reconnect, so a flapping agent cannot replay its whole backlog on every
/// reconnect. It DELAYS, never skips - a batch the bucket defers pages on a later pass, and
/// retention (not the bucket) is the only deletion path, so nothing is lost. now_ms is
/// passed in, so the pacing is deterministic + testable.
class YUZU_EXPORT JournalPagingBucket {
public:
    JournalPagingBucket(double refill_per_sec, double burst)
        : refill_per_sec_(refill_per_sec), burst_(burst), tokens_(burst) {}

    /// Refill for the elapsed time, then report whether at least one token is available.
    bool ready(std::int64_t now_ms) {
        refill(now_ms);
        return tokens_ >= 1.0;
    }
    /// Spend one token - call only after ready() returned true.
    void take() { tokens_ -= 1.0; }
    [[nodiscard]] double tokens() const { return tokens_; } // test introspection

private:
    void refill(std::int64_t now_ms) {
        if (last_ms_ == 0) {
            last_ms_ = now_ms;
            return;
        }
        if (now_ms > last_ms_) {
            tokens_ = std::min(burst_, tokens_ + refill_per_sec_ *
                                                     static_cast<double>(now_ms - last_ms_) / 1000.0);
            last_ms_ = now_ms;
        }
    }
    double refill_per_sec_;
    double burst_;
    double tokens_;
    std::int64_t last_ms_{0};
};

/// One page-into-window pass's outcome.
struct JournalPageStats {
    std::size_t batches_paged{0}; ///< batches that contributed >=1 net-new record this pass
    std::size_t records_paged{0}; ///< records newly enqueued into the send window this pass
};

/// A batch persist() durably wrote, for back-filling window-entry provenance (review M3): the
/// still-windowed LIVE entries get this batch key so their send writes the sent-label instead
/// of the batch later aging out falsely counted evicted_without_send_evidence. event_ids are in
/// batch order; back() is the batch's last-in-batch record.
struct PersistedBatch {
    std::string key;
    std::vector<std::string> event_ids;
};

/// One prune pass's outcome (also mirrored on the lock-free counters).
struct JournalPruneStats {
    bool read_ok{false};           ///< the initial journal scan succeeded (gates the boot barrier, M5)
    std::size_t evicted{0};        ///< batches removed by retention (age/count/bytes)
    std::size_t quarantined{0};    ///< unparseable batches moved aside this pass
    std::size_t sent_labels_gc{0}; ///< orphaned/evicted sent-labels removed this pass
};

class YUZU_EXPORT GuardianLifecycleJournal {
public:
    /// `kv` is BORROWED and must outlive this component (the agent owns it and
    /// destroys it after the engine - agent.cpp member order). May be null (KV
    /// unavailable): persist() then durably writes nothing.
    explicit GuardianLifecycleJournal(KvStore* kv);

    /// Serialise + durably write the FIFO-ordered `pending` records in batches
    /// (each ≤ kMaxJournalEntriesPerBatch entries and ≈ kMaxJournalBatchBytes).
    /// Returns the count of RECORDS durably written - the caller passes it to
    /// GuardianSparkRuntime::erase_persisted_prefix(). A per-push CIRCUIT BREAKER
    /// stops at the first write failure (remaining records stay pending for the
    /// maintenance-tick retry) so one failing write cannot stall a 500-rule
    /// apply_rules for 500 × the 5 s KvStore busy timeout under mtx_.
    [[nodiscard]] std::size_t persist(std::span<const std::shared_ptr<const JournalRecord>> pending,
                                      std::vector<PersistedBatch>* out_batches = nullptr);

    /// Enforce retention + quarantine (design §6, rev-4.1 #9). Evicts the oldest
    /// batches by (ts_ms, key) once they exceed the age (kJournalRetentionDays),
    /// count (kMaxJournalBatches), or byte (kMaxJournalBytes) caps; moves any
    /// unparseable batch aside to a bounded quarantine (atomic rename); GCs
    /// sent-labels whose batch no longer survives. `now_ms` is the wall clock in ms
    /// (a parameter so age eviction is testable). Fail-safe: a read error counts
    /// prune_failures and returns, never throws, never fatal. Runs off mtx_ (KvStore
    /// serialises itself); wired into the tick phase-2 + a boot barrier in C5.
    JournalPruneStats prune(std::int64_t now_ms);

    /// Replay the durable journal into `rt`'s send window (design §5; item 7 PR-Ag C5).
    /// Serialised by the paging mutex; the FIRST call runs a boot prune before returning
    /// any candidate (the prune-before-page barrier). Reads unexpired batches (fallible),
    /// orders them by (ts_ms, key), and for each - rate-limited by a process-lifetime token
    /// bucket charged ONLY for net-new work - reconstructs wire-identical entries (with
    /// replay provenance) and pages them via rt.try_page_batch. Re-send-all: nothing is
    /// permanently skipped (membership is a window scan; retention is the only deletion).
    /// Takes KvStore.mu_ then outbox_mu_ SEQUENTIALLY, never nested, never the engine mtx_.
    JournalPageStats page_into_window(GuardianSparkRuntime& rt, std::int64_t now_ms);

    /// Write the (best-effort) sent-label for a batch - called from the send path after the
    /// batch's LAST paged entry is delivered. Presence classifies eviction (sent-unacked vs
    /// no-send-evidence); it never gates re-paging or deletion.
    void mark_batch_sent(const std::string& batch_key);

    /// Signal that shutdown has begun: a concurrent page_into_window pass observes this
    /// between batches and stops enqueuing, so a late page never mutates the send window
    /// after stop() joins the drain worker (rev-4.1 #7 stop-race gate). Idempotent, lock-free.
    void request_stop() noexcept { stopping_.store(true, std::memory_order_release); }

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
    [[nodiscard]] std::uint64_t pages() const noexcept {
        return pages_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t records_paged() const noexcept {
        return records_paged_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t sent_labels_written() const noexcept {
        return sent_labels_written_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t evicted_sent_unacked() const noexcept {
        return evicted_sent_unacked_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t evicted_without_send_evidence() const noexcept {
        return evicted_without_send_evidence_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t write_capacity_rejected() const noexcept {
        return write_capacity_rejected_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t quarantine_capacity_evicted() const noexcept {
        return quarantine_capacity_evicted_.load(std::memory_order_relaxed);
    }
    // Current-size GAUGES (not cumulative): set exactly by each prune scan, incremented by
    // persist on a durable write. An operator watches these to see growth BEFORE a chronic
    // prune failure exhausts the shared kv_store.db (sre review). Approximate before the first
    // prune of a process (a restart re-establishes them from the boot-prune scan).
    [[nodiscard]] std::uint64_t journal_bytes() const noexcept {
        return journal_bytes_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t journal_batch_count() const noexcept {
        return journal_batch_count_.load(std::memory_order_relaxed);
    }

    /// TEST-ONLY: force the next `n` batch writes to fail (as if KvStore returned
    /// Error), exercising the per-push circuit breaker and the maintenance-tick
    /// retry (Sol BLOCKER-4) without a real disk fault. No production caller.
    void inject_write_failures_for_test(int n, int skip_first = 0) noexcept {
        inject_skip_writes_.store(skip_first, std::memory_order_relaxed);
        inject_fail_writes_.store(n, std::memory_order_relaxed);
    }

    /// TEST-ONLY: shrink the retention caps so count/byte/quarantine eviction is
    /// reachable at unit-test scale (production caps are 1000 batches / 32 MiB / 100
    /// quarantined). Age eviction needs no shrink - pass a future now_ms to prune().
    void set_retention_limits_for_test(int days, std::size_t max_batches, std::size_t max_bytes,
                                       std::size_t max_quarantine) noexcept {
        retention_days_ = days;
        max_batches_ = max_batches;
        max_bytes_ = max_bytes;
        max_quarantine_ = max_quarantine;
    }

    /// TEST-ONLY: shrink the hard WRITE ceiling (the UP-1 anti-runaway bound, default 2x the
    /// production retention caps) so a rejection is reachable at unit-test scale. Independent of
    /// set_retention_limits_for_test - retention is the soft cap prune trims to; this is the hard
    /// cap persist refuses to cross.
    void set_write_ceiling_for_test(std::size_t max_batches, std::size_t max_bytes) noexcept {
        hard_max_batches_ = max_batches;
        hard_max_bytes_ = max_bytes;
    }

    /// TEST-ONLY: force the next `n` journal SCANS (the list_entries at the head of a prune
    /// pass) to fail, exercising the read-error fail-safe: prune_failures increments, read_ok
    /// stays false, and the boot-prune barrier does NOT latch (design §10 "injected list
    /// failure distinguished from empty & retried"). No production caller.
    void inject_read_failures_for_test(int n) noexcept {
        inject_fail_reads_.store(n, std::memory_order_relaxed);
    }

    /// TEST-ONLY: force the next `n` retention DELETES (del_keys of the evict set) to report a
    /// 0/failure return, exercising the M4 delete-failure fail-safe (prune_failures increments,
    /// survivors' sent-labels are left intact and retried). No production caller.
    void inject_delete_failures_for_test(int n) noexcept {
        inject_fail_deletes_.store(n, std::memory_order_relaxed);
    }

private:
    /// The retention/quarantine body, serialised by paging_mutex_ against page_into_window
    /// (review round 2 MINOR-1). prune() is the public wrapper that takes the mutex; the
    /// boot-prune barrier inside page_into_window calls this directly (it already holds it).
    JournalPruneStats prune_locked_(std::int64_t now_ms);

    KvStore* kv_;                ///< BORROWED; outlives this (agent owns it)
    std::string boot_nonce_;     ///< random, fixed at construction - batch-key uniqueness across restarts
    std::uint64_t batch_seq_{0}; ///< per-process monotonic batch-key sequence (persist runs single-threaded under mtx_)
    std::atomic<std::uint64_t> batches_written_{0};
    std::atomic<std::uint64_t> write_failures_{0};
    std::atomic<std::uint64_t> key_collisions_{0};
    std::atomic<std::uint64_t> quarantined_{0};         ///< unparseable batches moved aside
    std::atomic<std::uint64_t> quarantine_failures_{0}; ///< could not even quarantine a corrupt batch
    std::atomic<std::uint64_t> batches_pruned_{0};      ///< batches evicted by retention
    std::atomic<std::uint64_t> prune_failures_{0};      ///< a prune pass could not read the journal
    std::atomic<std::uint64_t> pages_{0};               ///< page_into_window passes
    std::atomic<std::uint64_t> records_paged_{0};       ///< records newly enqueued into the window
    std::atomic<std::uint64_t> sent_labels_written_{0}; ///< sent-labels written (best-effort)
    std::atomic<std::uint64_t> evicted_sent_unacked_{0};          ///< aged out WITH a sent-label
    std::atomic<std::uint64_t> evicted_without_send_evidence_{0}; ///< aged out with NO sent-label (alert)
    std::atomic<std::uint64_t> write_capacity_rejected_{0};       ///< new batch refused: journal at cap (UP-1)
    std::atomic<std::uint64_t> quarantine_capacity_evicted_{0};   ///< over-cap quarantined batches shed (UP-7)
    std::atomic<std::uint64_t> journal_bytes_{0};                 ///< current live journal size estimate (gauge)
    std::atomic<std::uint64_t> journal_batch_count_{0};           ///< current live batch count (gauge)
    std::atomic<int> inject_fail_writes_{0};            ///< test-only forced-failure countdown
    std::atomic<int> inject_skip_writes_{0};            ///< test-only: skip this many writes before failing
    std::atomic<int> inject_fail_reads_{0};             ///< test-only: force the next N prune scans to fail
    std::atomic<int> inject_fail_deletes_{0};           ///< test-only: force the next N retention deletes to fail
    // Paging state - all guarded by paging_mutex_ (paging is single-threaded per pass).
    std::mutex paging_mutex_;
    bool boot_pruned_{false}; ///< the prune-before-first-page barrier has run
    JournalPagingBucket page_bucket_{kJournalPageRefillPerSec, kJournalPageBurst};
    std::atomic<bool> stopping_{false}; ///< set by request_stop(); page_into_window bails on it
    /// Fair-rotation cursor (review B2): the last-CONSIDERED (ts_ms, key). Each pass resumes at
    /// the first candidate strictly greater and wraps, so the never-sent tail is reached instead
    /// of the oldest sent-and-popped batches monopolising the bucket. Process-local (NOT
    /// persisted): a restart re-sends the whole unexpired journal, which is correct.
    std::optional<std::pair<std::int64_t, std::string>> page_cursor_;
    // Retention (SOFT) caps - default to the production constants; a test may shrink them.
    int retention_days_{kJournalRetentionDays};
    std::size_t max_batches_{kMaxJournalBatches};
    std::size_t max_bytes_{kMaxJournalBytes};
    std::size_t max_quarantine_{kMaxQuarantineBatches};
    // Hard WRITE ceiling (UP-1 anti-runaway bound) - 2x the retention caps, above normal
    // between-prune overshoot; persist refuses to cross it so a chronically-failing prune cannot
    // grow the shared kv_store.db without bound. Decoupled from the retention caps above.
    std::size_t hard_max_batches_{kMaxJournalBatches * 2};
    std::size_t hard_max_bytes_{kMaxJournalBytes * 2};
};

// Holds a std::mutex + atomics directly, so it is implicitly non-copyable AND non-movable; it
// is only ever owned via a std::unique_ptr on GuardianEngine. Pin that so an accidental by-value
// use (which would try to copy the borrowed kv_ and duplicate paging state) fails to compile.
static_assert(!std::is_copy_constructible_v<GuardianLifecycleJournal> &&
              !std::is_move_constructible_v<GuardianLifecycleJournal>);

} // namespace yuzu::agent
