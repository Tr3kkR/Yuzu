- **MFA now fails closed on an authentication-store read/decrypt failure.** Previously, an error
  reading a user's MFA enrollment state (`mfa_status` and related lookups) could be treated the
  same as "MFA not enrolled," which — under the right failure conditions — would let a login
  proceed without the required second factor. Every MFA-state read now distinguishes a genuine
  store/decrypt failure from "not enrolled" and "code rejected," and denies (HTTP 503,
  retry-with-alert) rather than silently proceeding. This closes a latent bypass class that the
  move to a networked Postgres substrate (ADR-0006) made materially more exploitable than it was
  on a local SQLite file.
