- **BREAKING — the authentication store (`AuthDB`) and SCIM v2 provisioning now run on
  PostgreSQL (ADR-0006), not SQLite `auth.db`.** `AuthDB` migrates to schema `auth`; `ScimStore`
  migrates to its own schema, `scim_store`. This is a **fresh-start cutover, not a data
  migration** — a legacy SQLite `auth.db` is never read on upgrade. **Operator action:** on the
  first boot against a fresh Postgres database the server re-seeds the configured admin account
  from `yuzu-server.cfg` and logs a one-time "auth data reset on Postgres cutover" warning; every
  other local operator account, role assignment, and MFA (TOTP) enrollment that existed only in
  a pre-cutover `auth.db` is gone and must be re-created. SCIM-provisioned accounts self-heal on
  the IdP's next sync cycle. `--mfa-reset` / `--break-glass-arm` now require `--postgres-dsn`
  (not `--data-dir`) to reach the auth store. See `docs/auth-architecture.md` → "AuthDB —
  persistent authentication store" and `docs/user-manual/server-admin.md` "PostgreSQL substrate".
- **MFA TOTP secrets (`users.mfa_totp_secret`) are now encrypted at rest** via `pg::SecretCodec`
  (AES-256-GCM, ADR-0010) — `AuthDB` is `SecretCodec`'s first production consumer. Password
  hashes, recovery codes, enrollment tokens, and SCIM bearer tokens remain verify-only hashes
  (no change).
