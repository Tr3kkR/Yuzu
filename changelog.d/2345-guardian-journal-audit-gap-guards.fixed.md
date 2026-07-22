- **Guardian's durable audit journal no longer loses records to a wall-clock jump or to its own
  size accounting.** (Dormant with the rest of the Guardian journal machinery until the Spark
  detection path becomes authoritative, so no currently-released agent changes behaviour.) Three
  distinct ways a durably-written lifecycle record could be deleted without ever reaching the
  server are closed. (1) Retention is anchored to the wall clock, so one forward jump past the
  retention window - a VM restored from an old snapshot, a bad NTP correction - marked every
  batch expired at once and deleted the whole trail in a single transaction; the first such jump
  is now declined and reported (`yuzu.guardian_journal_clock_jump_skips`), and age eviction is
  capped per pass so even an accepted jump ages the journal out gradually instead of instantly.
  Replay now shares retention's decision about what "expired" means, so it can no longer skip
  records that retention deliberately kept. (2) A batch whose records were mostly already queued
  for sending was charged for its whole size rather than for what it actually needed, so the
  worker waited for room that could not appear while those same records held it. (3) The largest
  batches - mass arm/disarm bursts such as a Baseline deploy, the records most likely to be
  asked for in an audit - could be skipped indefinitely by a steady trickle of small ones and
  aged out unsent; a batch repeatedly passed over now takes priority until it fits.
- **A Guardian replay pass that cannot read the journal, and a drain worker killed by an
  exception, are both visible on the heartbeat rather than silent.** (Also dormant.) Replay-side
  scan failures are counted separately from retention's (`yuzu.guardian_journal_page_read_failures`)
  because retention succeeding while replay is stalled means records are being deleted on
  schedule and shipped never - the worse of the two situations, and previously the invisible one.
  A reconnect's replay kick that arrived while the paging rate limiter was empty is also no
  longer dropped.
