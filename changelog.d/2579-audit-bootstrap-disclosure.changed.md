- **Audit retention: the first pass against an upgraded database is not guarded by a
  missing-anchor check.** The retention clock guard (#2360) reports a decline when a
  pass would expire every datable row, when the gap since the previous pass exceeds
  7 days, or when the stored clock reading is unusable. A stored reading that is
  simply ABSENT -- which is every database on its first pass after upgrading to
  schema v3, since the `audit_retention_meta` table is new -- is not itself a
  trigger. On that first pass, if the host clock is already skewed forward AND rows
  written after the skew are still inside the retention window (so the would-expire-
  everything test does not fire), the pass deletes up to the per-pass cap of 25,000
  rows with no decline, no counter increment and no warning. Measured on the upgrade
  shape: 30 expired rows plus 2 post-skew survivors deletes 30 and leaves
  `yuzu_server_audit_clock_anomaly_skips_total` at 0. Subsequent passes are guarded
  normally, because the first pass persists an anchor. **Before upgrading a server
  whose clock may be wrong, verify time sync first**, or snapshot `audit.db`. Tracked
  in #2579.
