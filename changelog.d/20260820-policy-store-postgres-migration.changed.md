- **`PolicyStore` migrated to PostgreSQL (ADR-0056).** Compliance-policy storage
  (fragments, policies, inputs, triggers, group bindings, per-agent status) now
  lives in Postgres, closing the last major SQLite exception in the compliance
  evaluation pipeline. Policy dispatch is now coordinated across replicas via a
  durable, single-sweeper claim (`claim_due_policies`) instead of per-process
  memory, so running the server with multiple replicas no longer risks duplicate
  or missed policy dispatch. No legacy-SQLite migration path: no production
  fleet ever ran a pre-Postgres build of this store, so there was no real
  `policies.db` data to carry over — the one-time backfill mechanism this store
  originally shipped with was retired the same day it merged (ADR-0009's
  fresh-start-by-default amendment). See `docs/user-manual/upgrading.md`
  ("Compliance policy engine moves to Postgres") for the operator-visible
  behaviour changes.
