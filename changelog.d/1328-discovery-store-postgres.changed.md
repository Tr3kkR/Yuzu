- **`DiscoveryStore` moves to PostgreSQL** (ADR-0043, schema `discovery_store`). Network-discovered-device
  data migrates off the local `discovery.db` SQLite file via a mandatory, fingerprint-verified backfill on
  first boot; the legacy file is renamed aside once the backfill is verified. `GET /api/discovery/results`
  now returns `503` on a degraded read instead of silently rendering an empty device list, and
  `discovery_store` is added to the `/readyz` store-health check.
