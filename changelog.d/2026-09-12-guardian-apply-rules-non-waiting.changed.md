- **Guardian's spark-backed rule arming no longer blocks the policy-push thread.**
  `apply_rules()` now accepts a rule for arming and returns immediately, instead of
  waiting for the backend call (service/file/registry watch) to actually resolve - a
  hung or slow backend can no longer stall the whole push, and therefore no longer
  delays agent shutdown the way it previously could. The reported policy generation
  (`yuzu.guardian_generation`) still only advances once every accepted rule in that
  push has actually armed or genuinely failed - tracked by a new per-push
  acknowledgment ledger and settled on the regular heartbeat cadence - so a generation
  can now take one or two extra heartbeat ticks to advance under a slow-arming rule,
  where it previously advanced (or blocked) synchronously. This PR is deliberately
  pre-K-bound: a rule that resolves to anything other than a confirmed arm still holds
  its generation indefinitely, exactly as the prior synchronous path did (no
  quarantine, no bounded-retry-then-waive - that is a later rung's scope, not this
  one's).
- **`persist_generation_locked()` now durably confirms a policy-generation write
  before advancing the in-memory value, and the retry that depends on it actually
  runs.** Previously a KV write failure was silently discarded, which could leave the
  reported generation advanced in memory with nothing durable behind it. This is now
  checked and gates the advance - and, closing a gap the checked-return fix on its own
  did not (found and fixed in the same hardening round): the server's own identical
  retry of a stuck push is what re-attempts the write, so that retry must not be
  suppressed as a no-op duplicate merely because nothing was left outstanding from the
  prior attempt. This half is unconditional - it runs on every push today, independent
  of whether spark-backed arming is enabled.
