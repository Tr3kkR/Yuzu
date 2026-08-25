- **`RuntimeConfigStore` migrated to PostgreSQL (ADR-0060) — the last store started on the
  migration ladder.** Persistent runtime configuration overrides (retention windows, log level,
  DEX alert-routing knobs, and the OIDC settings) now live in Postgres. The OIDC client secret is
  no longer stored plaintext at rest: it is SecretCodec-envelope-encrypted (AES-256-GCM), matching
  the treatment webhook signing secrets and offload-target credentials receive. **Existing
  `runtime-config.db` overrides do NOT carry over** — per ADR-0009's fresh-start-by-default
  amendment, this cutover does not read the legacy SQLite file; reapply any Settings overrides
  (including OIDC configuration) once after upgrading. The legacy `runtime-config.db` is left in
  place untouched and may still hold a plaintext OIDC client secret from before this release —
  see `docs/user-manual/upgrading.md` for removal guidance. `GET /api/config` and `PUT
  /api/config/:key` now return an honest 503 on a genuine database error instead of a response
  that looked like "nothing configured" or a validation failure.
