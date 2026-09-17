- **TAR's retention clock guard no longer swallows a distinct clock anomaly
  under a still-active one.** The per-table decline was tracked with a single
  `bool` latch, which cannot carry anomaly identity: a DIFFERENT anomaly
  arriving while the latch was still set from a previous decline was neither
  declined nor counted, and the pass deleted the table silently (measured,
  #2573). The guard now dedups on the whole fact set (shared with the audit
  store's clock guard), so a distinct anomaly reports again instead of
  deleting, while an identical repeat still drains at the same paced rate as
  before.
- **TAR's retention pass now refuses an implausible caller-supplied clock
  reading outright.** `run_retention`'s `now_epoch` had no upper bound, unlike
  the audit store's `kMaxPlausibleNow`, and — worse than the unguarded
  arithmetic this allowed — an implausible reading was persisted as the
  durable comparison point unconditionally, poisoning every later pass's
  elapsed-time check. The whole pass now declines before anything is
  persisted when the reading is implausible, reported as
  `retention_guard_failed|__implausible_now__|<n>` in `tar status`.
