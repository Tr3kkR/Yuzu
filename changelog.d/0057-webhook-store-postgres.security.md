- **`WebhookStore` migrated from SQLite to PostgreSQL** (schema `webhook_store`, ADR-0057) and
  its `secret` column (the outbound webhook HMAC signing secret) is now `SecretCodec`
  envelope-encrypted at rest (AES-256-GCM, ADR-0010) instead of a plain SQLite `TEXT` column —
  the second production consumer of the secrets-at-rest seam, after `AuthDB`'s
  `mfa_totp_secret`, and the template for the two remaining secret-gated stores
  (`OffloadTargetStore`, `RuntimeConfigStore`). `has_secret` is a new, independent, DB-enforced
  boolean column so "no secret configured" is never represented by column emptiness. A webhook's
  secret is decrypted only at the HMAC signing site, immediately before each delivery attempt,
  and a decrypt failure now skips that delivery entirely (logged + counted) rather than any
  possibility of firing unsigned. Backfill is mandatory for both `webhooks` and
  `webhook_deliveries` (the delivery log carries no TTL, unlike `ResponseStore`'s skippable
  class); the legacy `webhooks.db` is retained for one release, forced to `0600`, and moved
  aside — never deleted or scrubbed — after a verified backfill. `GET /api/webhooks` gains a
  `has_secret` field; `POST`/`DELETE /api/webhooks` now classify a bad request as `400` distinct
  from a store/database degradation (`503`).
