- **`PolicyStore` migrated to PostgreSQL (ADR-0056).** Compliance-policy storage
  (fragments, policies, inputs, triggers, group bindings, per-agent status) now
  lives in Postgres, closing the last major SQLite exception in the compliance
  evaluation pipeline. Policy dispatch is now coordinated across replicas via a
  durable, single-sweeper claim (`claim_due_policies`) instead of per-process
  memory, so running the server with multiple replicas no longer risks duplicate
  or missed policy dispatch. Existing `policies.db` files are backfilled
  automatically on first boot in the common case; the backfill refuses to
  boot (and logs why) if it finds two divergent legacy files or a status row
  Postgres has already advanced past — both require operator reconciliation,
  by design, rather than a silent merge.
