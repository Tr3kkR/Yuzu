- **Audit retention now declines a pass that has no stored clock reading while rows are
  already expired, instead of deleting them.** The clock guard (#2360) declined when a
  pass would expire every datable row, when the gap since the previous pass exceeded 7
  days, or when the stored reading was unusable. An ABSENT reading -- every database on
  its first pass after upgrading to schema v3, since `audit_retention_meta` is new -- was
  not itself a trigger, so a host whose clock was ALREADY skewed forward, and whose
  post-skew rows were still inside the retention window (defeating the
  would-expire-everything test), deleted up to the per-pass cap of 25,000 rows with no
  decline, no counter and no warning. It then kept deleting rows stamped before the skew
  until that cohort was exhausted. **Affected: any server upgraded to schema v3 while its
  clock was already wrong**; a correct clock was never at risk. The pass now declines
  ONCE, warns, and anchors the reading, so the next pass proceeds normally -- deletion is
  paced, never blocked. A fresh install with nothing expired does NOT decline, so the
  trigger costs nothing until data is actually at risk. Declines of this kind are counted
  by a new `yuzu_server_audit_retention_bootstrap_declines_total`, deliberately separate
  from `yuzu_server_audit_clock_anomaly_skips_total`: this decline makes no claim that the
  clock moved, only that nothing can yet rule it out, so it must not fire an alert that
  says otherwise. Expect 0 or 1 per database. Verify server time before upgrading if it
  may be wrong. Closes #2579.
