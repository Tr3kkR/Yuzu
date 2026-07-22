- **Guardian's durable audit journal no longer loses records to a wall-clock jump or to its own
  size accounting.** (Dormant with the rest of the Guardian journal machinery until the Spark
  detection path becomes authoritative, so no currently-released agent changes behaviour.) Four
  distinct ways a durably-written lifecycle record could be deleted without ever reaching the
  server are closed or bounded - the clock channel is bounded and reported rather than
  eliminated, because a clock that genuinely moved and stays moved really has put the data past
  retention. (1) Retention is anchored to the wall clock, so one forward jump past the
  retention window - a VM restored from an old snapshot, a bad NTP correction - marked every
  batch expired at once and deleted the whole trail in a single transaction; the first such jump
  is now declined once and reported (`yuzu.guardian_journal_clock_jump_skips`), and age eviction is
  capped per pass so even an accepted jump ages the journal out gradually instead of instantly.
  Detection keys off the OUTCOME - would this pass age out the entire journal - rather than off a
  process-local memory of the last pass, so it survives the agent restart that a restored VM
  actually performs. Replay now shares retention's decision about what "expired" means and stops
  treating expired batches as unshippable while a paced ageing-out is in progress, so it can no
  longer skip exactly the records retention deliberately kept. A backward step is guarded too, by
  never letting the cutoff move backwards: left alone it stopped retention entirely and the
  journal climbed to its write ceiling, where it REFUSES new records - a live gap, worse than the
  stored one. (2) A batch whose records were mostly already queued
  for sending was charged for its whole size rather than for what it actually needed, so the
  worker waited for room that could not appear while those same records held it. (3) The largest
  batches - mass arm/disarm bursts such as a Baseline deploy, the records most likely to be
  asked for in an audit - could be skipped indefinitely by a steady trickle of small ones and
  aged out unsent; the room a repeatedly-passed-over batch needs is now RESERVED against smaller
  ones until it fits, while anything that fits in the surplus still ships. (4) A journal row
  claiming more entries than a batch may legally contain is now rejected at the read boundary and
  quarantined, rather than blocking replay forever behind a batch that could never be placed.
- **A Guardian replay pass that cannot read the journal, and a drain worker killed by an
  exception, are both visible on the heartbeat rather than silent.** (Also dormant.) Replay-side
  scan failures are counted separately from retention's (`yuzu.guardian_journal_page_read_failures`)
  because retention succeeding while replay is stalled means records are being deleted on
  schedule and shipped never - the worse of the two situations, and previously the invisible one.
  A reconnect's replay kick that arrived while the paging rate limiter was empty is also no
  longer dropped.
