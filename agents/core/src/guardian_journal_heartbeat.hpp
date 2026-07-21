#pragma once

/// @file guardian_journal_heartbeat.hpp
/// Writer side of the durable lifecycle-audit journal's fleet telemetry (item 7 PR-Ag,
/// design §8). Extracted from the agent heartbeat lambda so the exact emitted keys + the
/// sparse-emit rule are unit-testable without a heartbeat thread. Mirrors
/// spark_heartbeat.hpp; the keys are pinned to the server-side reader by a unit test.
///
/// SPARSE: every field is a counter (or a depth gauge) that is 0 on a healthy, quiescent,
/// or inert (prefer_spark=false) agent, so a tag is emitted ONLY when non-zero. A journal
/// that has never dropped/failed/quarantined/paged anything ships NO journal tags at all -
/// fleet-kind, and it keeps the "absent == nothing to report" reading honest.

#include <cstdint>
#include <string>

namespace yuzu::agent {

/// A snapshot of the journal's integrity + activity counters, assembled by
/// GuardianEngine::journal_stats() from the runtime (staging) + the journal component.
struct GuardianJournalStats {
    // Staging loss channels (runtime).
    std::uint64_t stage_dropped{0};   ///< pending reserve overflow under sustained write failure
    std::uint64_t stage_failures{0};  ///< a disarm record could not be built post-teardown
    std::uint64_t field_rejected{0};  ///< NUL / oversized / non-UTF-8 field kept a record out
    std::uint64_t clock_rejected{0};  ///< skewed clock (secs<=0) kept a record out
    std::uint64_t pending_depth{0};   ///< records staged but not yet persisted (gauge)
    // Persist (component).
    std::uint64_t batches_written{0};
    std::uint64_t write_failures{0};
    std::uint64_t key_collisions{0};
    // Retention / quarantine (component).
    std::uint64_t quarantined{0};
    std::uint64_t quarantine_failures{0};
    std::uint64_t quarantine_capacity_evicted{0}; ///< over-cap quarantined batches shed (UP-7)
    std::uint64_t batches_pruned{0};
    std::uint64_t prune_failures{0};
    std::uint64_t write_capacity_rejected{0}; ///< new batch refused: journal at its byte/count cap (UP-1)
    std::uint64_t journal_bytes{0};           ///< current live journal size estimate (gauge)
    std::uint64_t journal_batch_count{0};     ///< current live batch count (gauge)
    // Replay (component).
    std::uint64_t pages{0};
    std::uint64_t records_paged{0};
    std::uint64_t sent_labels_written{0};
    std::uint64_t evicted_sent_unacked{0};          ///< aged out WITH a sent-label (monitor)
    std::uint64_t evicted_without_send_evidence{0}; ///< aged out with NO sent-label (integrity gap, alert)
    std::uint64_t maint_exceptions{0};              ///< swallowed persist/prune/page throws (review B4)
    /// Firewalled OUTBOX-DELIVERY throws on the drain worker (bad_alloc in the drain
    /// machinery). Separate from maint_exceptions: delivery failing and retention failing
    /// need different operator responses.
    std::uint64_t drain_exceptions{0};
    /// Firewalled CONVERGENCE-SWEEP throws on the scheduler lanes. Deliberately NOT folded
    /// into maint_exceptions (#2298 Gate 6 sre): these are drift-DETECTION failures with
    /// nothing to do with the journal, and a tag named journal_maint_exceptions counting
    /// them leaves an operator unable to tell "audit trail at risk" from "detection
    /// degraded" - the two have different urgency and different remediation.
    std::uint64_t sweep_exceptions{0};
};

/// Populate `tags` with the (sparse) journal telemetry. `TagMap` is any map with a string
/// `operator[]` - the protobuf status_tags map in production, std::map in tests.
template <typename TagMap>
void emit_guardian_journal_heartbeat_tags(TagMap& tags, const GuardianJournalStats& s) {
    const auto put = [&](const char* key, std::uint64_t v) {
        if (v != 0)
            tags[key] = std::to_string(v);
    };
    put("yuzu.guardian_journal_stage_dropped", s.stage_dropped);
    put("yuzu.guardian_journal_stage_failures", s.stage_failures);
    put("yuzu.guardian_journal_field_rejected", s.field_rejected);
    put("yuzu.guardian_journal_clock_rejected", s.clock_rejected);
    put("yuzu.guardian_journal_pending", s.pending_depth);
    put("yuzu.guardian_journal_batches_written", s.batches_written);
    put("yuzu.guardian_journal_write_failures", s.write_failures);
    put("yuzu.guardian_journal_key_collisions", s.key_collisions);
    put("yuzu.guardian_journal_quarantined", s.quarantined);
    put("yuzu.guardian_journal_quarantine_failures", s.quarantine_failures);
    put("yuzu.guardian_journal_quarantine_capacity_evicted", s.quarantine_capacity_evicted);
    put("yuzu.guardian_journal_pruned", s.batches_pruned);
    put("yuzu.guardian_journal_prune_failures", s.prune_failures);
    put("yuzu.guardian_journal_write_capacity_rejected", s.write_capacity_rejected);
    put("yuzu.guardian_journal_bytes", s.journal_bytes);
    put("yuzu.guardian_journal_batch_count", s.journal_batch_count);
    put("yuzu.guardian_journal_pages", s.pages);
    put("yuzu.guardian_journal_records_paged", s.records_paged);
    put("yuzu.guardian_journal_sent_labels", s.sent_labels_written);
    put("yuzu.guardian_journal_evicted_sent_unacked", s.evicted_sent_unacked);
    put("yuzu.guardian_journal_evicted_no_send_evidence", s.evicted_without_send_evidence);
    put("yuzu.guardian_journal_maint_exceptions", s.maint_exceptions);
    put("yuzu.guardian_drain_exceptions", s.drain_exceptions);
    put("yuzu.guardian_sweep_exceptions", s.sweep_exceptions);
}

} // namespace yuzu::agent
