- **`RuntimeConfigStore` migrated to PostgreSQL (ADR-0060) — the last store on the migration
  ladder.** Persistent runtime configuration overrides (retention windows, log level, DEX
  alert-routing knobs, and the OIDC settings) now live in Postgres. The OIDC client secret is no
  longer stored plaintext at rest: it is SecretCodec-envelope-encrypted (AES-256-GCM), matching
  the treatment webhook signing secrets and offload-target credentials receive. Existing
  `runtime-config.db` files are backfilled automatically on first boot; a legacy secret value is
  encrypted during the copy, never written to Postgres in plaintext. `GET /api/config` and `PUT
  /api/config/:key` now return an honest 503 on a genuine database error instead of a response
  that looked like "nothing configured" or a validation failure.
