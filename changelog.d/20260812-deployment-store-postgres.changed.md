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
  practical operational concern.
