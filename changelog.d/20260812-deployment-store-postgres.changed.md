- **`DeploymentStore` (ad hoc deployment jobs — SSH/group-policy/manual installs) migrated
  from SQLite to PostgreSQL** (schema `deployment_store`, ADR-0043), with a mandatory
  first-boot backfill of the legacy `deployment-jobs.db`, tracked per distinct legacy-file
  content rather than a single fleet-wide flag so a database replica with no local legacy
  file can never block a different replica's real deployment-job history from being
  migrated. `GET /api/deployment-jobs`, `GET /api/deployment-jobs/:id`, `POST
  /api/deployment-jobs`, and `DELETE /api/deployment-jobs/:id` now return **HTTP 503** on a
  genuine database outage instead of the previous silent `400`/`404`/empty-list result — an
  operator or automation client can now tell "the database is unavailable, retry" apart from
  "that job doesn't exist" or "that request was invalid". Operator note: a corrupt local
  `deployment-jobs.db` now fails the WHOLE server's boot (previously it only silently disabled
  this one feature) — this store is small and low-volume, so this should only ever be observed
  as a startup log line naming the exact file and a repair-or-move-aside remediation, not a
  practical operational concern. Similarly, if two replicas' legacy files disagree on the
  content of a job sharing the same id (e.g. a data directory cloned or restored to provision a
  second replica, then diverged), the backfill compares the two: a difference in the job's
  identity (target host/OS/method/creation time — fields that never change once a job exists)
  fails the boot closed with the offending id named in the startup log, since that combination
  should never occur under normal operation (data corruption, a hand-edited legacy file, or two
  unrelated jobs whose ids collided). A difference confined to the job's lifecycle
  (status/timestamps/error — fields a job's own progress legitimately changes after migration)
  depends on which side is further along: if the database's value is at least as far along as the
  legacy file (e.g. a slower-booting replica whose legacy file predates a sibling replica
  completing that same job), that's a safe no-op — the database's current value is kept and the
  drift is logged at warning level for visibility, without blocking the boot. If instead the
  LEGACY file is further along than the database (e.g. after a rollback to the previous release
  runs against this same file and genuinely progresses the job, then rolls forward again), or the
  two sides reached DIFFERENT final outcomes (e.g. one shows `completed`, the other `failed`) even
  without one being simply "further along," the boot fails closed the same as an identity
  mismatch, so that progress or disagreement is never silently lost or papered over. A legacy
  job's status is also validated before it can reach the database at all — an unrecognised status
  (e.g. from a hand-edited legacy file) fails the boot closed rather than being silently accepted.
  `POST /api/deployment-jobs`'s `target_host` validation (unchanged, already live)
  also now rejects a leading or trailing `-` — not a valid DNS label, and defense-in-depth
  against a future SSH-option-injection shape (`-oProxyCommand=...`) for a not-yet-built `ssh`
  method executor. This applies to the already-released endpoint independent of the Postgres
  migration; a caller currently passing such a hostname (unusual — RFC 1123 already disallows it
  as a DNS label) now gets `400` where it previously succeeded.
