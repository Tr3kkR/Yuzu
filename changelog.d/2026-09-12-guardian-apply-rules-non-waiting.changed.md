- **Guardian's spark-backed rule arming no longer blocks the policy-push thread.**
  `apply_rules()` now accepts a rule for arming and returns immediately, instead of
  waiting for the backend call (service/file/registry watch) to actually resolve - a
  hung or slow backend can no longer stall the whole push, and therefore no longer
  delays agent shutdown the way it previously could. The reported policy generation
  (`yuzu.guardian_generation`) still only advances once every accepted rule in that
  push has actually armed (or been quarantined per the existing K-bound), tracked by
  a new per-push acknowledgment ledger and settled on the regular heartbeat cadence -
  so a generation can now take one or two extra heartbeat ticks to advance under a
  slow-arming rule, where it previously advanced (or blocked) synchronously. No
  change to what gets enforced, only to the timing of the push call itself and of the
  generation number's own advance.
