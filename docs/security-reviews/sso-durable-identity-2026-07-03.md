# Security review — durable SSO identity + OIDC JIT elevation governance round (#1852)

**Date:** 2026-07-03
**Change:** `AuthManager::provision_sso_identity` auto-provisions a durable `auth.db`
row (`AuthDB::upsert_sso_identity`) for the stable OIDC principal `oidc:<iss>#<sub>`
on every login, so `POST /api/v1/elevate` — previously unreachable for every SSO
operator (#1837 fallout) — has a row to key eligibility/MFA-basis/audit off. This
record covers the governance hardening round on top of the initial #1852 commit:
source-scoping the eligibility grant, closing a re-provisioning reactivation gap,
fixing an SSO force-logout audit-fidelity bug, and a dashboard URL-encoding fix.
**Branch:** `feat/sso-durable-identity`
**Controls:** SOC 2 **CC6.3** (least privilege), **CC6.6** (privileged access —
MFA-gated, audited, time-boxed), **CC7.2** (anomaly detection / evidence integrity).

## What shipped (base #1852 commit)

- **auth.db migration v6** — `users` gains `identity_source` (`'local'` default),
  `external_iss`, `external_sub`, `display_name`, `last_seen_at`. Existing rows
  survive unmigrated (all columns nullable/defaulted).
- **`is_valid_principal`** — a strict superset of `is_valid_username` that
  additionally accepts `oidc:`/`saml:`/`ad:`-prefixed durable principals, gated
  to target-lookup call sites only (never user-creation).
- **`upsert_sso_identity`** — auto-provision-or-refresh on every OIDC login,
  fail-soft (a provisioning miss degrades to "cannot elevate", never "cannot log
  in"); the `ON CONFLICT` arm preserves `role`/`elevation_eligible` so a standing
  grant survives re-login.
- **`POST /api/v1/elevate` OIDC path** — an unconditional IdP-attested-`amr`-proof
  gate before the shared step-up (closing the PR #1199 optional-mode leniency that
  would otherwise pass a never-MFA'd OIDC login through to elevation). SAML fails
  closed (no `amr`-equivalent).

## The three-gate elevation control (after this hardening round)

Every `POST /api/v1/elevate` call for a durable-identity-eligible operator must
clear, in order:

1. **Eligibility** — `AuthDB::is_elevation_eligible(principal)` reads
   `users.elevation_eligible`, fail-closed on any read error or absent row.
2. **Identity-source scope (NEW this round, UP-6/UP-7/cons-N2)** — the row's
   `identity_source` must equal the session's `auth_source`, a direct mapping
   (`local`↔`local`, `oidc`↔`oidc`, `saml`↔`saml`), not "oidc-or-else-local".
   See "Source-scope guard" below.
3. **MFA basis** — local sessions require an enrolled TOTP secret (existing
   `mfa_status` check); OIDC sessions require `mfa_verified_at` to carry a live
   IdP-attested `amr` proof from login (existing #1852 check). Both are followed
   by the shared `elevation_step_up` freshness gate.

A TOCTOU re-check of gate 1 (`is_elevation_eligible`) still runs immediately
before the grant, after the human-time step-up delay (existing #1748 UP-1
invariant, untouched by this round).

## Source-scope guard (UP-6/UP-7/cons-N2) — the headline fix

**Problem.** `is_elevation_eligible` (and the eligibility read at the elevate
handler) keyed on the raw principal *string* alone. Two collision shapes could
borrow a grant that was never made against the calling session's own identity
source:

- A **crafted SAML NameID** equal to a real, eligible OIDC principal string
  (`oidc:<iss>#<sub>`) — SAML's `create_saml_session` sets `Session::username`
  to the raw, IdP-supplied NameID verbatim, with no reserved-prefix constraint.
- A **legacy `identity_source='local'` row** whose `username` happens to be
  `oidc:x#y` with `elevation_eligible=1` set on it (pre-#1852 data, or any row
  constructed with that shape).

Neither collision was reachable "for free" before this round — a SAML session
still failed at the amr-proof/MFA gate, and no known code path produces a local
row shaped like an OIDC principal — but both are landmines: a future SAML-MFA
workstream (tracked, dormant) would have reopened the SAML half, and any future
row-migration/seed script touching `identity_source` could reopen the local half.

**Fix.** `AuthDB::get_user` now selects `identity_source`. The elevate handler
fetches the target row via `get_user(session->username)` immediately after the
eligibility check and requires:

```cpp
const std::string& expected_identity_source = session->auth_source;
if (row->identity_source != expected_identity_source) {
    audit_log_for_principal(req, "role.elevation.denied", "denied", session->username,
                            auth::role_to_string(session->role), "User", session->username,
                            "identity-source mismatch");
    res.status = 403;
    res.set_content(detail::error_json_a4(403, "not authorized to elevate", cid), "application/json");
    return;
}
```

The check is a **direct equality** between the session's own `auth_source` and
the eligible row's `identity_source` (`local`↔`local`, `oidc`↔`oidc`,
`saml`↔`saml`) — NOT an "oidc-or-else-local" fallback. A local session can only
spend a grant recorded on an `identity_source='local'` row; a SAML session
would need an `identity_source='saml'` row, which no row carries today (SAML
provisioning is a fast-follow), so SAML fails closed at this gate too, same as
before. `identity_source` is read fresh at every elevate call (not cached on
`Session`), so a future deprovisioning/re-source event is honoured immediately.

**Regression tests** (`tests/unit/server/test_auth_sso_identity.cpp`, `[sso][jit][routes]`):
an OIDC session cannot borrow a `identity_source='local'` row's grant even when
the principal strings collide; a SAML session whose NameID collides with a real,
eligible OIDC principal is denied by this guard specifically (pinned independent
of the amr/MFA gates, so a future SAML-MFA addition cannot silently reopen the
collision).

## Don't resurrect a disabled SSO row (UP-3)

`upsert_sso_identity`'s `ON CONFLICT` arm previously included `is_active = 1` in
its `SET` clause. Since `username` is the `ON CONFLICT` key regardless of
`is_active`, a re-login against a row a future deprovisioning sweep (#1859,
tracked, not yet built) had soft-deleted (`is_active = 0`) would silently flip it
back to active — defeating the deprovisioning control the moment the IdP-side
account logs in again. `is_active` is now REMOVED from the `ON CONFLICT` `SET`
clause; only `display_name` and `last_seen_at` refresh on re-login. A first
`INSERT` still defaults `is_active = 1` (schema default) — a genuinely new
identity provisions normally.

Test: `upsert_sso_identity` re-login after `remove_user` does not resurrect the row
(`get_user` — which filters `is_active = 1` — stays `UserNotFound` after re-login).

## SSO force-logout audit fidelity (cons-S1)

`DELETE /api/v1/sessions?username=` was moved to `is_valid_principal` at the REST
layer in the base #1852 commit, but the downstream
`AuthDB::invalidate_all_sessions` still gated on the strict `is_valid_username` —
so calling it with an SSO principal (containing `:`/`#`) always returned
`InvalidUsername`, even though OIDC sessions are never persisted to the
`sessions` table in the first place (the correct outcome is "0 rows deleted,
success"). The REST handler then audited `role.elevation`-adjacent
`session.revoke_all` as `result="partial"` / `detail` carrying `db_error=true`
for an admin action that had, in fact, fully succeeded — a false-negative on the
CC7.2 evidence trail.

**Fix.** `invalidate_all_sessions` moved to `is_valid_principal`:

```cpp
// governance round (cons-S1) — gated on `is_valid_principal`, not the
// strict `is_valid_username`: this is a target-lookup DELETE against
// the `sessions` table (no row is ever CREATED here), so accepting a
// durable SSO principal (`oidc:<iss>#<sub>`) is safe by the same
// reasoning as the REST `DELETE /api/v1/sessions?username=` route...
if (!is_valid_principal(username)) {
    spdlog::warn("invalidate_all_sessions: invalid username");
    return std::unexpected(AuthDBError::InvalidUsername);
}
```

This method has three callers: the REST route (already principal-aware,
motivated this fix), `remove_user`, and `update_role` — both of the latter are
local-account-only call sites whose own inputs are already `is_valid_username`-
validated upstream, so widening this shared gate does not loosen anything for
them (a local username is always also a valid principal — `is_valid_principal`
is a strict superset).

Test: `AuthManager::invalidate_user_sessions(<sso principal>)` now reports
`db_persisted = true` (was previously always `false` for any SSO principal); a
direct `AuthDB::invalidate_all_sessions` pin confirms the store-level gate.

## Dashboard URL-encoding fix (arch-S1)

Settings → Users' "Revoke sessions" button built its `hx-delete` URL with
`html_escape(u.username)`. `html_escape` neutralises HTML metacharacters
(`&<>"'`) for body/attribute text but does **not** touch `#`. A durable SSO
principal's `#` (`oidc:<iss>#<sub>`) survived `html_escape` unchanged and was
then interpreted by the browser as a URL-fragment separator when the `hx-delete`
attribute fired — the server received a silently truncated `username` query
value with no error surfaced to the operator (an apparent no-op click).

**Fix.** A `url_encode` helper (percent-encodes everything outside the RFC 3986
unreserved set: alnum, `-`, `_`, `.`, `~`) is now used for the query-parameter
*value* specifically; `html_escape` remains in place for the surrounding
HTML-attribute quoting and the confirm-dialog body text. Added as a file-local
anonymous-namespace helper in `settings_routes.cpp`, matching the existing
per-file convention already used by ~9 other route files (`device_ui.cpp`,
`dex_routes.cpp`, `inventory_ui.cpp`, etc.) — deliberately **not** centralised in
`web_utils.hpp`, since several of those files already declare their own
same-named helper in their own anonymous namespace, and a namespace-scope
version there is ambiguous against unqualified lookup in every TU that includes
both (confirmed by a build failure when first attempted this way).

## MFA-basis audit enrichment (compliance-S)

`role.elevation.granted`'s `detail` records the MFA basis via the
`mfa=<oidc_amr|local_totp>` token (alongside `duration_secs`, `expires_at`, and
the free-text `justification`, with the machine-parsed tokens placed first) — so
an auditor can read whether the second factor was an IdP-attested `amr` assertion
or local TOTP directly off the audit row without cross-referencing the
(non-historical) session store. (This rides the pre-existing `mfa=` field from the
OIDC-amr elevation work rather than adding a separate `auth_source=`/`amr_attested=`
pair.)

## Provisioning-volume metric (sec-LOW/UP-5)

`yuzu_auth_sso_provision_total{source="oidc"}` increments on every successful
`upsert_sso_identity` call (first-provision **and** re-login refresh — the same
code path serves both), giving SRE/SIEM an observable signal for an IdP-side
provisioning flood or credential-stuffing sweep against the SSO login path,
independent of ordinary login-volume metrics.

## Threats considered

- **Grant-borrowing across identity sources.** Closed by the source-scope guard
  (above) — the headline fix of this round.
- **Deprovisioning bypass via re-login.** Closed by the `is_active` reactivation
  fix (above).
- **Audit-trail false negative on SSO force-logout.** Closed by the
  `invalidate_all_sessions` principal-gate fix (above).
- **Silent no-op admin action via URL-fragment truncation.** Closed by the
  `url_encode` fix (above).
- **IdP-side provisioning flood.** Now observable via the new counter; no rate
  limit is applied at the provisioning chokepoint itself in this round (the login
  path this rides on has its own existing controls — lockout, MFA challenge
  issuance load-shedding — this metric is an *additional* signal, not a new gate).

## Deferred (tracked, unchanged by this round)

- **Stale-row reaper / SCIM-less deprovisioning** — `last_seen_at` is populated
  on every login but nothing ages a row out yet. Tracked as **#1859**. Until it
  ships, revoking a compromised SSO operator's access is a two-lever manual
  process: `POST .../elevation-eligibility {"eligible":false}` (stops future JIT
  elevation immediately — also drops any active elevation window) **+**
  `DELETE /api/v1/sessions?username=<principal>` (force-logout the current
  session; the IdP can still mint a fresh one on next login, so this is not a
  substitute for IdP-side deprovisioning).
- **SSO/durable-identity roster / access-review surface** (list every durable SSO
  row with `elevation_eligible`, `last_seen_at`, `identity_source` for CC6.3
  reviews beyond the existing Settings → Users SSO badge). Tracked as **#1860**.
- **SAML provisioning + elevation.** SAML sessions still have no durable-identity
  provisioning path and no `amr`-equivalent proof, so they fail closed at the
  MFA/amr gate (and now additionally at the identity-source guard, pinned by this
  round's regression test). A SAML-MFA workstream is a separate, unstarted effort.

## Validation

- Unit: `tests/unit/server/test_auth_sso_identity.cpp` `[sso]` — 13 test cases /
  90 assertions, including the 5 new cases this round adds (source-scope
  mismatch via a legacy local row; SAML-NameID-collision regression pin;
  no-reactivation-on-re-login; `AuthManager`/`AuthDB` SSO-principal session-revoke
  fidelity). Broader `[principal][jit]` tag set green (368 assertions).
- `meson test -C build-linux --suite server --print-errorlogs` — full server
  suite green.
- Build: clean compile, no new warnings introduced by this round's diff.

## Reviewer

Governance hardening round on `feat/sso-durable-identity`, per the senior-led
dev-team workflow (`/dev-team`); items enumerated by the senior (Opus) reviewer,
implemented by a junior (Sonnet) worker in an isolated worktree.
