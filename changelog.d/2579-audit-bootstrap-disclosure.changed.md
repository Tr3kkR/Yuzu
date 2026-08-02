- **Audit retention: a pass that begins with no stored clock reading is not guarded by
  a missing-anchor check, and the exposure does not end after one pass.** The
  retention clock guard (#2360) reports a decline when a pass would expire every
  datable row, when the gap since the previous pass exceeds 7 days, or when the stored
  clock reading is unusable. A stored reading that is simply ABSENT -- which is every
  database on its first pass after upgrading to schema v3, since the
  `audit_retention_meta` table is new -- is not itself a trigger. If the host clock is
  already skewed forward AND rows written after the skew are still inside the retention
  window (so the would-expire-everything test does not fire either), that pass deletes
  up to the per-pass cap of 25,000 rows without declining. Persisting the anchor does
  NOT close it: while the clock stays skewed, each later pass sees one tick of elapsed
  time and the same post-skew survivors, so it drains another capped batch -- roughly
  600k rows/day at the default hourly cadence -- until the backlog is gone. The state
  also recurs after a failed anchor persist plus a restart, or after restoring a pre-v3
  snapshot. **Signals:** no decline and no
  `yuzu_server_audit_clock_anomaly_skips_total` increment, but the pass does log a
  routine `AuditStore: expired N rows` line and does raise
  `yuzu_server_audit_rows_deleted_total`; a cap-binding backlog also raises
  `yuzu_server_audit_retention_cap_reached_total` (which `YuzuAuditRetentionCapBinding`
  alerts on once six passes inside six hours have bound the cap, if you have wired the
  shipped rules).
  A sub-cap pass raises neither and nothing shipped detects it -- measured on the
  upgrade shape, 30 expired rows plus 2 post-skew survivors deletes 30 and leaves
  `yuzu_server_audit_clock_anomaly_skips_total` at 0. **Before upgrading a server whose
  clock may be wrong, verify time sync first**, or back up `audit.db` with
  `sqlite3 ".backup"` and correct the clock before restoring it. Detection after the
  fact, and the full bound, are in `docs/user-manual/audit-log.md` under the retention
  clock guard. Tracked in #2579.
