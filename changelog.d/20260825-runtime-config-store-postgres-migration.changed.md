- **`RuntimeConfigStore` migrated to PostgreSQL (ADR-0060) — `OffloadTargetStore` is now the only
  server store remaining on the ladder.** Persistent runtime configuration overrides (retention
  windows, log level, DEX alert-routing knobs, and the OIDC settings) now live in Postgres. The
  OIDC client secret is no longer stored plaintext at rest: it is SecretCodec-envelope-encrypted
  (AES-256-GCM), matching the treatment webhook signing secrets already receive (ADR-0057) —
  offload-target credentials do not yet get this treatment; that store has not migrated. **Existing
  `runtime-config.db` overrides do NOT carry over on this cutover** — per ADR-0009's
  fresh-start-by-default amendment, this cutover does not copy the legacy SQLite file; a boot
  that finds real pre-migration overrides logs a warning naming the exact count found. Reapply
  any Settings overrides (including OIDC configuration) once after upgrading. The legacy
  `runtime-config.db` is left in place untouched and may still hold a plaintext OIDC client
  secret from before this release — see `docs/user-manual/upgrading.md` for removal guidance.
  `GET /api/config` and `PUT
  /api/config/:key` now return an honest 503 on a genuine database error instead of a response
  that looked like "nothing configured" or a validation failure.
