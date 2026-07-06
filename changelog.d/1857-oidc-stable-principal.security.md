- **OIDC session principal is now keyed on the stable `iss`+`sub`, not the mutable display
  name (#1837, HIGH).** `create_oidc_session`'s authorization principal (`Session::username`,
  the value `check_permission`/`reconcile_idp_memberships`/audit rows key on) was previously
  `claims.name` (falling back to `claims.email`) — an IdP-editable, non-unique label. Two SSO
  users with the same display name collided onto one principal, and #1832's reconcile made
  that collision destructive (one user's login could delete the other's group memberships and
  silently inherit their roles). The stable principal is now `"oidc:" + iss + "#" + sub`
  (`sub` is only guaranteed unique per-issuer per RFC 7519, hence the `iss` scoping); the
  mutable display name moves to a new `Session::display_name` field, used for UI/audit-detail
  rendering only; every SSO audit row also carries the sanitized human name in its `detail`
  string, so a principal's name is recoverable from the audit log without a live session
  (there is no persistent principal→name directory — that is tracked as a fast-follow, #1852).
  Every nav-bar "who am I" render site (`/api/me`, `/api/v1/me`, and the ten dashboard-page
  `nav-user`/`context-user` JS blocks) now shows `display_name`, falling back to the stable id.
  SAML session-keying is unchanged this slice (still the raw NameID) — SAML doesn't sync to
  `rbac_store` yet, so its principal risk is dormant; tracked as a fast-follow.
  See `docs/auth-architecture.md` "Stable principal vs. display name".
  **Upgrade note (re-login required):** OIDC sessions now key on `oidc:<iss>#<sub>` instead
  of the display name. `RbacStore` migration v3 purges every IdP-sourced `group_members` row
  on upgrade (old display-name-keyed memberships are unreachable and would otherwise be a
  resurrected confused-deputy risk if a local user later took that display name) — they
  re-populate under the new stable key on each SSO user's next login. Between the v3 migration
  and a user's first re-login, an operator whose admin role comes *only* from SSO group
  membership is roleless — recover via a fresh SSO login, `--oidc-admin-group` (grants admin
  directly on next login without needing the group reconcile), or a local admin / break-glass
  account.
  **OIDC JIT admin elevation is temporarily unavailable for SSO operators (#1837):** pending
  durable SSO identity provisioning (#1852). The stable `oidc:<iss>#<sub>` principal fails
  `is_valid_username`'s alphanumeric-only check, and an OIDC login provisions no `users` row,
  so there is no local record to set the flag on. This is not a regression of a
  previously-supported flow — before #1837, SSO elevation only appeared to work by accident
  (name-collision borrowing a local user's `elevation_eligible` flag with no cryptographic
  binding). #1852 is the real restoration path, and this same `[Unreleased]` window DOES
  include it: durable SSO identity provisioning (`AuthDB::upsert_sso_identity`, PR #1861)
  gives every OIDC principal a durable `users` row to key `elevation_eligible` on — see
  `1861-durable-sso-identity-oidc-elevation.security.md`.
  Session revocation by username for SSO operators is **not** structurally blocked:
  `AuthManager::invalidate_user_sessions`'s in-memory sweep carries no `is_valid_username`
  gate and revokes any principal string, `oidc:<iss>#<sub>` included.
