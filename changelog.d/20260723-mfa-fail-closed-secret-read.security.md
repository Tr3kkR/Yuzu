- **MFA now fails closed on an authentication-store read/decrypt failure.** Previously, an error
  reading a user's MFA enrollment state (`mfa_status` and related lookups) could be treated the
  same as "MFA not enrolled," which — under the right failure conditions — would let a login
  proceed without the required second factor. Every MFA-state read now distinguishes a genuine
  store/decrypt failure from "not enrolled" and "code rejected," and denies (HTTP 503,
  retry-with-alert) rather than silently proceeding. This includes the login-code check itself
  (an enrolled account whose stored secret has gone missing now reports the outage instead of
  rejecting every code as wrong) and the enrollment reads (a failed secret lookup can no longer
  be mistaken for "no enrollment in progress" and overwrite a live one). This closes a latent
  bypass class that the move to a networked Postgres substrate (ADR-0006) made materially more
  exploitable than it was on a local SQLite file.
