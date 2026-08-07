- **`yuzu_server_audit_retention_last_pass_unixtime` now survives a server restart,
  including the first PostgreSQL boot.** `AuditStore` seeds the gauge from the durable
  `audit_retention_meta` anchor at construction and again after the legacy backfill
  completes, instead of starting at `0` on every process start. `0` now means "no
  retention pass has ever run on this **database**" rather than "not yet in this
  process" — anyone reading this gauge directly (a dashboard, a custom alert rule) should
  re-check what `0` means for them. A durable anchor that cannot be trusted as an
  integer (corrupt or hand-edited state, or an unreadable seed read) now seeds a distinct
  nonzero anomaly sentinel rather than being laundered into `0`, so corruption cannot
  silently earn the retention-liveness alert family's "never ran" grace. (#2854)
