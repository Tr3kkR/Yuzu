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
- **Eligibility** — `users.elevation_eligible` (auth.db migration v5; renumbered
  from v4 at merge after break-glass #1735 took v4 on dev), set via
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

## Hermes pre-submission pass-1 fixes

- **`duration_secs` > INT_MAX → 500.** A JSON integer above `INT_MAX` passed
  `is_number_integer()` but `get<int>()` threw → 500. Now read as `int64_t`,
  range-checked, then narrowed (over-cap clamps to the window).
- **TOCTOU: eligibility revoked during the step-up delay.** Eligibility is
  re-checked immediately before `elevate_session` (the human-time MFA step-up sits
  between the first check and the grant), so an admin who revokes mid-step-up wins
  the race — `role.elevation.denied` / `detail=eligibility revoked during step-up`.
- **Step-up escape hatch on the privilege boundary.** The elevation step-up floors
  the window to 300 s when the operator has globally disabled step-up
  (`--mfa-step-up-window-secs <= 0`), so elevation ALWAYS requires a fresh proof
  even when the gate is disabled elsewhere. (For a local enrolled user
  `require_mfa_step_up` already runs the freshness check regardless of
  `--mfa-enforcement`; the floor closes the one remaining global-disable path.)
- **Audit gap on step-up refusal.** A refused elevation step-up now also emits
  `role.elevation.denied` / `detail=mfa_step_up_refused`, completing the
  elevation-specific trail beside the shared `mfa.step_up` row.

## Tr3kkR adversarial review (Codex vs Kimi) fixes — #1748

- **H1 — audit `principal_role` understated the effective role.** `make_audit_event`
  / `emit_event` (auth_routes) and the four `settings_routes` token-management rows
  stamped `principal_role` from the **base** `session->role` while authorizing via
  `effective_role` — so an action authorized as admin under an active elevation was
  logged as `user`. All six now stamp `auth::role_to_string(auth::effective_role(*session))`
  (a no-op for non-elevated sessions). Test: an elevated admin action records
  `principal_role=admin`.
- **H2 — migration-version collision.** Break-glass #1735 merged to `dev` first and
  took `v4`; the JIT `elevation_eligible` migration is **renumbered to `v5`** and the
  branch rebased on current `dev`, so the migrations are contiguous and the collision
  can never silently skip.
- **H3 — non-A4 admin-denial envelope.** `POST /api/v1/users/<name>/elevation-eligibility`
  no longer borrows `require_admin`'s legacy `{error:{code,message}}` 403; it runs an
  **inline A4 admin gate** (token-type guards + `effective_role`, `auth.admin_required`
  audit) returning the A4 envelope with the route's `X-Correlation-Id`.
- **M1 — discovery (A2).** The three routes (`/elevate`, `/elevate/revoke`,
  `/users/{username}/elevation-eligibility`) are added to `openapi_spec()` with request
  schemas + A4 error responses; a route-presence test guards them.
- **L2 — UTF-8 truncation.** The 1 KiB justification cap now backs up to a code-point
  boundary so the audit detail never ends mid-sequence.

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

## Follow-up shipped (2026-07-02) — OIDC amr-asserted elevation

The v1 limitation above ("OIDC-only operators cannot elevate") is closed,
**with a prerequisite**: eligibility and MFA status are both keyed on the
`users` table row, and OIDC login does not create one — a federated-only
identity needs a Yuzu `users` row provisioned first (e.g.
`POST /api/v1/users`) before an admin can grant it `elevation_eligible`. Given
that row, an OIDC session whose IdP login attested MFA via the `amr` claim (a
seeded `Session::mfa_verified_at`, set at `/auth/callback` via
`amr_asserts_mfa` — the same mechanism OIDC login step-up already used) now
satisfies the mandatory-second-factor requirement at `POST /api/v1/elevate`
**without** local TOTP enrollment.

### Hardening round (2026-07-02, post-13-agent-governance) — linchpin fix

The first cut of this follow-up gated the mandatory-MFA check with a single
`if (!oidc_amr_elevation) { <local enrollment check> } `. Governance (13
agents) found this let an OIDC session **fall through to a local namesake's
TOTP enrollment**: a user with the same username but a *different* identity
(local password login vs. federated SSO) could be locally enrolled, and an
OIDC caller with no seeded amr proof would pass the enrollment check on that
namesake's factor, then possibly clear `elevation_step_up` too (its
no-proof-OIDC branch PASSes under `--mfa-enforcement=optional`) — granting
elevation with **no second factor the OIDC caller actually presented**,
mislabeled `mfa=local_totp` in the audit trail (security-F1 / consistency
S-2). The toggle was also inert for OIDC (it only gated the enrollment-skip,
not the step-up's amr acceptance), so `--no-jit-oidc-amr-elevation` did not
actually block an OIDC elevation via the namesake path either.

**Fix — branch EXPLICITLY on identity source** (replaces the single-flag
guard):

```cpp
const bool oidc_amr_proof = session->auth_source == "oidc" &&
                            session->mfa_verified_at.time_since_epoch().count() != 0;
const bool oidc_amr_elevation = cfg_.jit_oidc_amr_elevation && oidc_amr_proof;

if (session->auth_source == "oidc") {
    // An OIDC session's ONLY acceptable second factor is a seeded amr proof
    // with the toggle on. It never consults the local `users` MFA column.
    if (!oidc_amr_elevation) {
        const char* reason = cfg_.jit_oidc_amr_elevation
            ? "no MFA in SSO login (the IdP did not assert amr MFA) — re-authenticate via your IdP with MFA"
            : "OIDC-amr elevation is disabled (--no-jit-oidc-amr-elevation); elevate from a local session with TOTP";
        /* audit role.elevation.denied with `reason`; 403 */
        return;
    }
    // fall through to elevation_step_up (freshness on the amr seed)
} else {
    if (auto st = db->mfa_status(session->username); !st || !st->enrolled) {
        /* audit role.elevation.denied "no MFA enrolled..."; 403 */
        return;
    }
}
```

- **security-F1 guardrail (re-verified twice now).** The OIDC branch is gated
  on a **seeded** proof (`mfa_verified_at != epoch`), never merely
  `auth_source == "oidc"`, AND the two identity sources are now structurally
  disjoint — an OIDC session can never reach the `db->mfa_status(...)` call at
  all. This closes both the original single-factor-under-`optional` gap and
  the namesake-fallthrough gap the hardening round found. This seam remains
  the ONLY unconditional block for a single-factor (no-amr) OIDC session —
  `require_mfa_step_up`'s no-proof-OIDC branch alone would PASS such a
  request under `optional` enforcement.
- A seeded-but-**stale** proof (older than the elevation step-up window, which
  floors to 300s even when the global gate is globally disabled) still falls
  through to `elevation_step_up` and is challenged, not silently granted.
- **Toggle semantics, corrected.** `--jit-oidc-amr-elevation` /
  `YUZU_JIT_OIDC_AMR_ELEVATION` (default true). Disabling it means **OIDC
  sessions cannot use JIT elevation at all** — not "fall back to requiring
  local TOTP for OIDC too" (an OIDC session structurally cannot present a
  local TOTP step-up; its step-up challenge is re-SSO). An operator on a
  toggle-off deployment must elevate from a local-authenticated session with
  local TOTP.
- **Distinct denied reasons.** The audit `detail` for `role.elevation.denied`
  now distinguishes "no MFA in SSO login" (no amr assertion) from "OIDC-amr
  elevation is disabled" (toggle-off) from "no MFA enrolled" (local session) —
  three different failure modes, three different operator remediations.
- **Audit field order (consistency S-3).** The `role.elevation.granted` detail
  is `duration_secs=<n> mfa=<oidc_amr|local_totp> justification=<text>` — the
  code-emitted `mfa=` field is placed **before** the operator free-text
  `justification=` field. `justification` is only control-byte-sanitised, so
  a crafted value like `"x mfa=local_totp"` could otherwise forge the factor
  token a first-match grep reads; putting the genuine field first means it is
  always found before any forged text embedded later in the justification.
- **SRE posture log (SHOULD).** A one-time INFO line is emitted at boot when
  OIDC is configured (`--oidc-issuer` + `--oidc-client-id` both set, the same
  predicate `oidc::Config::is_enabled()` uses) and
  `--jit-oidc-amr-elevation` is on, so an incident responder can discover the
  posture without reading source or an individual audit row's `mfa=` detail.

## Validation

- Unit: `tests/unit/server/test_auth_jit_elevation.cpp` `[jit]` — reconciled
  count read directly from the test binary
  (`tests-build-server-linux_x64/yuzu_server_tests "[jit]"`): **26 test cases,
  627 assertions**, all green (initial ship: 15 cases / 275 assertions; first
  OIDC-amr follow-up cut: 22 cases / 406 assertions; this hardening round adds
  4 more — the F-1 regression-pinning case (a locally-enrolled OIDC namesake
  with no amr proof), the toggle-off + namesake + fresh-amr case, the
  users-row-less-identity-denied-at-eligibility case, and the audit
  field-order anti-forgery case). Coverage: `effective_role`/`is_elevated`,
  `AuthManager` elevate/revoke/revoke-user-elevations, `AuthDB` eligibility,
  and the REST surface end-to-end (granted; elevated-passes-admin-gate;
  **MFA-enrollment-mandatory**; **stale-proof-challenged**; ineligible-denied;
  justification-required; **wrong-typed/negative-duration → 400**;
  duration-clamp; revoke-reverts; **eligibility-revoke-kills-elevation**;
  **self-grant-blocked**; tokenless-rejected; OIDC-amr fresh-proof-elevates;
  OIDC no-proof-still-denied with distinct reason; **the F-1 regression case**;
  OIDC stale-proof-challenged; toggle-off-blocks-OIDC-entirely with distinct
  reason; toggle-off + namesake + fresh-amr; users-row-less identity denied at
  eligibility; local-session-unaffected; audit-field-order anti-forgery). The
  F-1 regression case was verified to FAIL against the pre-fix single-flag
  guard (manually reverted, rebuilt, re-run: 4 cases failed exactly as
  expected — the regression case itself plus the 3 new distinct-reason
  assertions) and PASS against the disjoint-branch fix. Full `--suite server`
  green; server build + link clean.
- Governance pipeline: initial OIDC-amr follow-up review found no
  CRITICAL/HIGH; a 13-agent hardening round found the security-F1 /
  consistency-S2/S3 / unhappy-UP-1/UP-2/UP-8/UP-10 / compliance-MEDIUM cluster
  fixed in this round (all findings addressed pre-merge, no residual
  CRITICAL/HIGH). Earlier-ship governance: security-guardian PASS (no
  CRITICAL/HIGH; MEDIUM F1 fixed in that round); authdb / cpp-safety /
  consistency-auditor / happy-path PASS; quality-engineer BLOCKING (untested
  step-up gate) + unhappy-path UP-1/UP-3 fixed; docs-writer BLOCKING
  (rest-api) addressed (this record + rest-api + authentication + audit-log +
  server-admin + CHANGELOG + SKILL).

## Reviewer

Governance pipeline (8 agents) + Hermes pre-submission security passes on
`feat/auth-jit-elevation`.
