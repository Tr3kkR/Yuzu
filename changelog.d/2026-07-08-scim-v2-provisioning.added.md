- **SCIM 2.0 user provisioning (`/scim/v2/*`, SOC 2 CC6.2/CC6.8).** An
  enterprise IdP (Okta/Entra/OneLogin) can now auto-provision and
  auto-deprovision Yuzu operators via its SCIM connector — enable with
  `--scim-enable` + `--scim-token` (HTTPS required; the server refuses to
  start without both). Provisioned users are created at the fixed, read-only
  `user` role and authenticate via SSO, never a local password. Deactivating
  a user in the IdP soft-deletes the account and revokes its sessions;
  reactivating restores it (MFA is not restored — the user re-enrolls). A
  provenance guard ensures SCIM can only ever mutate accounts it provisioned
  itself, so a locally-created admin or the break-glass account can never be
  touched by an IdP push. Users-only this slice — Groups→role mapping is a
  deferred follow-up. See `docs/auth-architecture.md` "SCIM v2 provisioning".
