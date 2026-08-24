- **`DeviceTokenStore`'s legacy-file backfill no longer misattributes lock contention as a
  corrupt file, and no longer holds the whole legacy table in memory** (#3398, #3399). The
  read-only legacy SQLite connection now sets `PRAGMA busy_timeout=5000` (restoring the
  pre-migration store's setting, dropped by the initial rewrite) and wraps the scan in a
  deferred snapshot transaction, so a legacy file merely held by a concurrent writer's lock is
  waited out instead of surfacing as a corruption-flavoured "scan aborted mid-read" boot
  failure. The backfill also no longer materializes the legacy table into memory: the
  fingerprint is computed with a streaming SHA-256 (byte-identical to the prior algorithm, pinned
  by a regression test) and the copy pass inserts in 500-row batches instead of one row per
  round-trip, so resident memory no longer scales with legacy table size. Single-transaction,
  fail-closed, all-or-nothing atomicity is unchanged — a new fault-injection test proves a
  multi-batch backfill rolls back to zero rows and zero markers on a later failure, and that the
  same file retries cleanly once the fault is cleared. This store remains **dormant** — nothing
  in `server.cpp` constructs a `DeviceTokenStore`, so neither fix is runtime-observable until a
  future change wires the store in; both were found by external adversarial review before that
  wiring, not by a live incident.
