- **Durable SSO identity — OIDC JIT admin elevation restored (#1852, HIGH).** `create_oidc_session`
  mints a stable `oidc:<iss>#<sub>` principal (#1837) but historically wrote **no `users` row** to
  `auth.db`, so `AuthDB::set_elevation_eligible`/`is_elevation_eligible` had nothing to key on and
  JIT admin elevation (`POST /api/v1/elevate`, #1799 "OIDC-amr JIT elevation") was unreachable for
  every SSO operator — a HIGH regression called out explicitly in #1837's Breaking Changes entry.
  Fix: auth.db migration v6 adds five nullable/defaulted columns to `users`
  (`identity_source`, `external_iss`, `external_sub`, `display_name`, `last_seen_at`); a new
  `AuthDB::upsert_sso_identity` auto-provisions (or refreshes) a row for the stable principal,
  called from `/auth/callback` immediately after `create_oidc_session` mints the session (fail-soft
  — a provisioning error is logged and the login still succeeds; the principal simply cannot elevate
  until a later successful login provisions it). The `ON CONFLICT` refresh path touches ONLY
  `display_name`/`last_seen_at`/`is_active` — it never resets `role` or `elevation_eligible`, so a
  standing admin grant survives re-login. A new `is_valid_principal` validator (strict superset of
  `is_valid_username`: unchanged for a local username, additionally accepts a reserved-prefixed
  `oidc:`/`saml:`/`ad:` principal after a control-byte/SQL-metacharacter blocklist) replaces
  `is_valid_username` at the elevation-cluster's target-lookup chokepoints (`set_elevation_eligible`,
  `is_elevation_eligible`, the elevation-eligibility grant route, force-logout-by-username) — every
  OTHER `is_valid_username` call site (local user create/delete/role-change, MFA, lockout, password)
  is deliberately left untouched. The elevate route's `mfa_status().enrolled` gate — which
  unconditionally denied every OIDC session, MFA'd or not, since `mfa_status` correctly stays strict
  — now applies to local sessions only; an OIDC session's second factor is the IdP-attested `amr`
  claim, and a **new, dedicated, unconditional gate** requires that proof to exist (`mfa_verified_at`
  seeded, not just fresh) before elevation is even attempted — closing a gap the restoration would
  otherwise have reopened under the default `--mfa-enforcement=optional`, where the SHARED
  `require_mfa_step_up` gate's OIDC-no-proof branch is deliberately lenient for lower-risk step-up
  sites (PR #1199) and would otherwise have let a never-MFA'd SSO login elevate to full admin.
  SAML sessions remain provisioned-but-cannot-elevate (no amr equivalent yet; SAML-MFA is a future
  workstream). Settings → Users now surfaces SSO rows (an `SSO` badge) and suppresses the buttons
  that would 400 against a non-local-charset principal (Remove); Revoke sessions stays available.
  See `docs/auth-architecture.md` "Durable SSO identity"; this restores the OIDC JIT elevation
  that #1837 had made temporarily unavailable for SSO operators.
- **Durable SSO identity — governance hardening round (#1852 follow-up).** Four fixes on top of the
  restoration above: (1) the elevate route now requires the target row's `identity_source` to match
  the session's `auth_source` before honouring an eligibility grant — closes a cross-protocol
  collision where a crafted SAML NameID, or a legacy `identity_source='local'` row, could share a
  principal string with a real OIDC identity and borrow its grant; (2) `upsert_sso_identity`'s
  `ON CONFLICT` refresh no longer sets `is_active = 1`, so a re-login can never resurrect a row a
  future deprovisioning sweep had soft-deleted; (3) `AuthDB::invalidate_all_sessions` moved to
  `is_valid_principal`, fixing a force-logout audit-fidelity bug where revoking an SSO principal's
  sessions always recorded `result="partial"`/`db_error=true` even though the revoke fully succeeded;
  (4) the Settings → Users "Revoke sessions" button now URL-encodes the principal (`html_escape` alone
  left `#` untouched, which the browser treated as a URL-fragment separator and silently truncated).
  A new `yuzu_auth_sso_provision_total{source}` counter makes IdP-provisioning volume observable
  (the `role.elevation.granted` row already records the MFA basis via its `mfa=oidc_amr|local_totp`
  field). Stale-row deactivation/reaper (SCIM-less deprovisioning) is tracked as **#1859**; a
  durable-SSO-identity access-review roster is tracked as **#1860**. See
  `docs/security-reviews/sso-durable-identity-2026-07-03.md`.
