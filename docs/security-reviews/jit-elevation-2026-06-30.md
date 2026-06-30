# Security review — JIT admin elevation (SOC 2 CC6.3/CC6.6)

**Date:** 2026-06-30
**Change:** Just-in-time admin elevation — a pre-authorized operator activates a
time-boxed, justified, MFA-gated admin window via `POST /api/v1/elevate`, then
auto-reverts. Eligibility is the per-user `users.elevation_eligible` flag
(admin-managed via `POST /api/v1/users/<name>/elevation-eligibility`).
**Branch:** `feat/auth-jit-elevation`
**Controls:** SOC 2 **CC6.3** (least privilege — reduce standing admin), **CC6.6**
(privileged access — time-boxed, justified, MFA-gated, audited). Closes
`/auth-and-authz` gap-matrix **P1 #9**.

## What shipped

- **`POST /api/v1/elevate`** `{justification (required), duration_secs}` — sets
  the in-memory `Session::elevated_until = now + min(duration, --jit-max-elevation-secs)`
  (default 1h, max 24h). `auth::effective_role(session)` returns `admin` while
  the window is live; `require_admin` gates on it and
  `require_permission`/`require_scoped_permission` short-circuit to allow an
  elevated session. The same `effective_role` is honoured at the previously
  raw-`role` admin-bypass sites (workflow role-gated approval, cross-user API
  token revoke, the dashboard token-list filter) so "elevated = full admin" is
  uniform for the window.
- **`POST /api/v1/elevate/revoke`** — manual step-down. **`--jit-max-elevation-secs`**
  (`YUZU_JIT_MAX_ELEVATION_SECS`).
- **Eligibility** — `users.elevation_eligible` (auth.db migration v4), set via
  `POST /api/v1/users/<name>/elevation-eligibility` (`AuthDB::set_elevation_eligible`/
  `is_elevation_eligible`, parameterised, `RETURNING`, fail-closed read).

## Control / authz decisions

- **MFA is mandatory to elevate, unconditionally (security-F1).** Elevation is
  the privilege-crossing boundary (non-admin → full admin), so — unlike the other
  11 step-up sites where the actor is already admin — an eligible operator with
  **no enrolled second factor** is hard-denied 403 (not merely passed through
  under `--mfa-enforcement=optional`). Enrollment + a fresh step-up are both
  required. Deliberately mirrors the break-glass "no bare-password privilege"
  posture (#1735 UP-1).
- **Cookie sessions only.** `/api/v1/elevate` reads the session cookie and
  `elevate_session` keys on the cookie token; API/MCP tokens resolve via
  `synthesize_token_session` (no cookie, no `elevated_until`), so an automation
  credential can **never** be elevated, and the permission-gate short-circuits are
  unreachable by them.
- **Grant audit is fail-closed (UP-3).** If `role.elevation.granted` can't
  persist, the elevation is rolled back (compensating `revoke_elevation`) and the
  call 500s with `Sec-Audit-Failed` — a privileged activation never stands
  without a record (mirrors the break-glass arm).
- **Revoking eligibility terminates active elevations (UP-1).**
  `set_elevation_eligible(false)` calls `AuthManager::revoke_user_elevations`, so
  an incident-response "revoke now" drops the operator's admin access immediately
  rather than leaving it standing for the window — symmetric with the session
  wipe on demote/delete.
- **Self-grant blocked (UP-6).** An operator (including one acting under an
  active elevation) cannot set their own eligibility, so a temporary admin window
  can't manufacture a durable self-elevation right. Eligibility is always granted
  by another admin, and the grant records the granting actor.
- **Monotonic, in-memory window.** `elevated_until` is `steady_clock` (an NTP
  step can't extend it) and per-session in-memory — a restart or logout drops the
  elevation (fail-safe; nothing in auth.db resurrects it). It cannot outlive the
  session's absolute expiry (`validate_session` rejects past `expires_at`).

## Threats considered (governance pipeline, 8 reviewers + Hermes ×2)

- **Privilege escalation without eligibility / without MFA.** No path: eligibility
  is admin-granted + read fail-closed; MFA enrollment + step-up are mandatory.
- **Token elevation.** Impossible (cookie-only; verified by security-guardian).
- **Justification log/audit injection.** Control bytes (incl. DEL) → space; 1 KiB
  cap; non-empty required; goes into the audit detail as a trailing field.
- **Malformed body / negative-duration least-privilege miss.** Wrong-typed fields
  and negative durations are `400` (not a 500, not a silent max-window grant).

## Residual risks (accepted / tracked)

- **No `role.elevation.expired` event on passive lapse.** The `granted` row +
  `duration_secs` make expiry deterministic; a lazy/reaper-emitted expiry row is a
  tracked follow-up (happy-path / unhappy-path SHOULD).
- **An elevated operator can create standing admins / grant others' eligibility.**
  Inherent to "elevation = full admin" (a standing admin can too); self-grant is
  blocked and every eligibility change is audited with the actor. Access reviews
  must enumerate `users.elevation_eligible` and cross-check the granting actor.
- **`expires_in` reports the granted duration, not time-remaining vs the cookie's
  absolute expiry.** Cosmetic; an absolute `expires_at` is a tracked follow-up.
- **Migration v4 collides with the break-glass PR (#1735, also v4).** A merge-gate
  renumber-to-v5 item, flagged in-code.

## Validation

- Unit: `tests/unit/server/test_auth_jit_elevation.cpp` `[jit]` (15 cases / 275
  assertions) — `effective_role`/`is_elevated`, `AuthManager` elevate/revoke/
  revoke-user-elevations, `AuthDB` eligibility, and the REST surface end-to-end
  (granted; elevated-passes-admin-gate; **MFA-enrollment-mandatory**;
  **stale-proof-challenged**; ineligible-denied; justification-required;
  **wrong-typed/negative-duration → 400**; duration-clamp; revoke-reverts;
  **eligibility-revoke-kills-elevation**; **self-grant-blocked**;
  tokenless-rejected). Broader `[auth][mfa][session][rbac][rest][workflow][settings][token]`
  suite green (6280 assertions); server build + link clean.
- Governance pipeline: security-guardian PASS (no CRITICAL/HIGH; MEDIUM F1 fixed
  in the hardening round); authdb / cpp-safety / consistency-auditor / happy-path
  PASS; quality-engineer BLOCKING (untested step-up gate) + unhappy-path UP-1/UP-3
  fixed; docs-writer BLOCKING (rest-api) addressed (this record + rest-api +
  authentication + audit-log + server-admin + CHANGELOG + SKILL).

## Reviewer

Governance pipeline (8 agents) + Hermes pre-submission security passes on
`feat/auth-jit-elevation`.
