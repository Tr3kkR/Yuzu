- **Audit retention: a pass that begins with NO stored clock reading is not guarded by
  a missing-anchor check, and the exposure does not end after one pass.** The retention
  clock guard (#2360) declines when a pass would expire every datable row, when the gap
  since the previous pass exceeds 7 days, or when the stored clock reading is unusable.
  A reading that is simply ABSENT -- which is every database on its first pass after
  upgrading to schema v3, since the `audit_retention_meta` table is new -- is not itself
  a trigger. If the host clock is already skewed FORWARD and rows written after the skew
  are still inside the retention window (so the would-expire-everything test does not
  fire either), that pass deletes up to the per-pass cap of 25,000 rows without
  declining. Persisting the anchor does not close it: while the clock stays skewed the
  guard has nothing to compare against that would register the skew, so deletion
  continues -- at up to 600k rows/day once a backlog binds the cap, and thereafter at
  the ingest rate, because effective retention stays shortened by the skew. The state
  also recurs after a failed anchor persist plus a restart, or after restoring a pre-v3
  snapshot. **Signals:** no decline and no
  `yuzu_server_audit_clock_anomaly_skips_total` increment; `..._rows_deleted_total` does
  rise and an `AuditStore: expired ...` info line is written, and a cap-binding backlog
  also raises `..._retention_cap_reached_total` (which `YuzuAuditRetentionCapBinding`
  alerts on, if you have wired the shipped rules, after six such passes -- roughly
  150,000 rows). None of these separates the case from healthy expiry on its own, and
  **there is no reliable retrospective test today** -- deletions are unrecoverable
  without a pre-incident backup. **Correct the clock before upgrading a server whose
  time may be wrong; if you cannot establish that it is right, defer the upgrade.**
  Tracked in #2579.
