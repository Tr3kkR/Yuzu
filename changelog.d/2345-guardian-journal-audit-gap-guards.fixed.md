- **Guardian's durable audit journal no longer loses records to a wall-clock anomaly or to its
  own size accounting.** (Dormant with the rest of the Guardian journal machinery until the
  Spark detection path becomes authoritative, so no currently-released agent changes behaviour.)
  Three ways a durably-written lifecycle record could be deleted without ever reaching the
  server are closed or bounded. (1) Retention is anchored to the wall clock, so one forward jump
  past the retention window - a VM restored from an old snapshot, a bad NTP correction - marked
  every batch expired at once and deleted the whole trail in a single transaction. Such a pass
  is now declined once and reported (`yuzu.guardian_journal_clock_jump_skips`), age eviction is
  capped per pass so even an accepted jump ages the journal out gradually, and replay stops
  treating expired batches as unshippable while that is in progress, so it can no longer skip
  exactly the records retention deliberately kept. Detection keys off the OUTCOME - would this
  pass age out the entire journal - rather than a process-local memory of the previous pass, so
  it survives the agent restart a restored VM actually performs. A backward step needs no guard:
  it simply pauses ageing until the clock is fixed, which is the safe direction for an audit
  trail, and the count and byte ceilings that bound the journal never read the clock at all.
  (2) A batch whose records were mostly already queued for sending was charged for its whole
  size rather than for what it actually needed, so the worker waited for room that could not
  appear while those same records held it; a batch that repeats an event_id is now also sized by
  its distinct records. (3) A journal row claiming more entries than a batch may legally hold is
  rejected at the read boundary and quarantined, rather than blocking replay behind a batch that
  could never be placed.
- **A record staged for the journal can no longer be discarded without being written.** (Also
  dormant.) The staging buffer drops its oldest entry when full, and the code that removed
  durably-written records identified them by POSITION - so a drop landing while the write was in
  flight shifted the buffer underneath it and discarded records that had never been persisted.
  It now identifies what it wrote, using a counter read under the same lock as the snapshot.
- **A Guardian replay pass that cannot read the journal, and a drain worker killed by an
  exception, are both visible on the heartbeat rather than silent.** (Also dormant.) Replay-side
  scan failures are counted separately from retention's
  (`yuzu.guardian_journal_page_read_failures`), because retention succeeding while replay is
  stalled means records are being deleted on schedule and shipped never - the worse of the two
  situations, and previously the invisible one. A reconnect's replay kick that arrived while the
  paging rate limiter was empty is also no longer dropped.
- **Known limitation, unchanged by this release and now tracked (#2364):** when the send window
  is nearly full, a large batch can be skipped by replay until retention deletes it unsent. Four
  mechanisms to close it were built and reverted during review - each pauses other replay to
  make room, which in the only regime where it matters either restores the loss or stalls
  everything else. It needs measurement before it needs a mechanism.
