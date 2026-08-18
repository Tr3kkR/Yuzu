- **`SoftwareDeploymentStore` migrated from SQLite to PostgreSQL** (schema
  `software_deployment_store`, ADR-0051), covering the capability 7.6 software packaging +
  fleet deployment catalog's three tables (`software_packages` -> `software_deployments` ->
  `agent_software_status`). Postgres now **enforces** the two internal foreign keys the
  pre-migration SQLite store never did — deleting a package still referenced by a deployment
  now fails closed instead of silently orphaning the deployment. A mandatory first-boot backfill
  fingerprints all three tables together per distinct legacy-file content (SHA-256), so a
  replica with no local legacy file can never block a different replica's real deployment/
  install history from being migrated, and a legacy file with a partial schema or with
  corrupted/unreadable table-existence probes is refused rather than silently treated as a
  fresh install. This store is currently **dormant** — nothing in `server.cpp` constructs a
  `SoftwareDeploymentStore`, so this PR is a pure persistence-layer migration with no
  runtime-observable effect on any current caller; the `/api/v1/software-packages*` /
  `/api/v1/software-deployments*` REST endpoints remain unregistered until a future change
  re-wires construction.
