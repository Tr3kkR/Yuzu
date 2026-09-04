- Agent: **Lands dormant — no deployment setting to review.** Guardian does not route
  detection through Spark in any shipped build, and this change ships no user-facing
  behavior. Closes two admission-race gaps in the outbox send/drain pipeline found by
  post-merge adversarial review of the prior stalled-sink fix: `GuardianOutboxSendExecutor`
  could report zero active workers for an instant after a send was already admitted and
  about to launch, and `GuardianOutboxDrainWorker::stop()` could admit one more send after
  shutdown had already begun. Both are now atomic with the admission they guard. Also closes
  five smaller residuals on the same pipeline: a stalled send is now counted and logged
  (previously silent), a reclaimed orphan's thrown exception is now counted (previously
  discarded with no signal), a send finishing between its per-attempt wait and the periodic
  backstop is now re-checked within ~200ms instead of up to 5 seconds, the Lifecycle-vs-
  Compliance/Health domain split the two-lane routing depends on is now asserted rather than
  convention-only, and a same-pass cross-lane wire-ordering residual is now accurately
  disclosed (tracked separately as #3972). `prefer_spark` (the same switch the Guardian
  journal entries in this release refer to) is a compile-time default that cannot be changed
  without a rebuild, so the existing detection path is unaffected. (#3966, #3953)
