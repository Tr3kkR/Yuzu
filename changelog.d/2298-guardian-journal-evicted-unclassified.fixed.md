- Guardian lifecycle-audit journal retention now accounts every evicted batch
  exactly. A third eviction counter, `evicted_unclassified`, catches the batches a
  stop landing mid-classification (or an unreadable sent-label on the scan-failure
  fallback, or a `bad_alloc` mid-classification) previously left in NEITHER eviction
  bucket - a silent undercount of the audit-gap signal, in the wrong direction for a
  loss indicator. `batches_pruned == evicted_sent_unacked + evicted_no_send_evidence
  + evicted_unclassified` now holds on every pass, including shutdown and throwing
  passes, which is what lets `evicted_no_send_evidence` be read as a trustworthy
  FLOOR on lost lifecycle-audit evidence (CC7.2/CC7.3) rather than a value a mid-pass
  shutdown could silently shrink. Surfaced as the heartbeat tag
  `yuzu.guardian_journal_evicted_unclassified` and the fleet gauge
  `yuzu_fleet_guardian_journal_evicted_unclassified` (monitor-only, absent-not-zero,
  forged-value parsed, and pinned to the agent emitter by the same `static_assert`
  as its siblings). The value is neither loss nor success - the two live buckets keep
  their meaning. Inert until the Guardian spark cutover, like the rest of the family.
  See [metrics.md](docs/user-manual/metrics.md).
