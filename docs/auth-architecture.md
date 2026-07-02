# Authentication & Authorization — Yuzu Server

Reference for the authentication and authorization features implemented in the Yuzu server. CLAUDE.md keeps only the hard invariants; this document is the implementation history and feature inventory.

## Transport and identity

- **mTLS** for agent ↔ server gRPC connections. Note that a migration from gRPC->QUIC is intended.
- **Windows certificate store integration** — agent can read mTLS client cert + private key from the Windows cert store instead of PEM files. Uses CryptoAPI/CNG (`CertOpenStore`, `CertFindCertificateInStore`, `NCryptExportKey`). Searches Local Machine first, falls back to Current User. Exports full certificate chain (leaf + intermediates) as PEM. CLI flags: `--cert-store MY --cert-subject "yuzu-agent"` or `--cert-thumbprint "AB12..."`.
- **Certificate hot-reload** — HTTPS cert/key PEM files are polled for changes (default 60s interval) and hot-swapped without server restart. Validates PEM parse, cert/key match, and key file permissions before applying. gRPC TLS reload not supported. CLI: `--no-cert-reload`, `--cert-reload-interval`. Audit action: `cert.reload`. Metrics: `yuzu_server_cert_reloads_total`, `yuzu_server_cert_reload_failures_total`.

Certificate setup instructions: `scripts/Certificate Instructions.txt`.

## Login and session management

- **RBAC login** — session-cookie auth with PBKDF2-hashed passwords in `yuzu-server.cfg`. Legacy roles: `admin` (full access) and `user` (read-only). First-run interactive setup prompts for credentials.
- **Login page** — dark-themed, with greyed-out OIDC SSO stub where appropriate. Yuzu does not support Light Mode.
- **Settings page** (admin-only) — TLS toggle, PEM cert upload, user management, enrollment tokens, pending agent approvals, AD/Entra section.
- **Hamburger menu** — upper-right dropdown with Settings, About (popup), and Logout.
- **Auth middleware** — `set_pre_routing_handler` redirects unauthenticated requests to `/login`, returns 401 for API calls.
- **HTMX paradigm** — Settings page uses HTMX for all server interactions; server renders HTML fragments. Vanilla JS reserved only for clipboard copy. Dominant UI pattern going forward.
- **Session revocation REST surface (CC6.3 revocation, CC6.7 disposition, CC6.8 termination).**
  - `DELETE /api/v1/sessions?username=<name>` — admin-only via `UserManagement:Write`. Cookie sessions only; API tokens deliberately not revoked.
  - `DELETE /api/v1/sessions/me` — any interactive authenticated principal. Wipes cookie sessions AND revokes the caller's API tokens (lost-laptop UX). MCP-tier and service-scoped tokens rejected with 403. Response sets `Set-Cookie: yuzu_session=; Max-Age=0` so the client side completes the disposition.
  - Both wrap `AuthManager::invalidate_user_sessions`, which performs the dual-write (AuthDB DELETE first outside `mu_`, then in-memory `sessions_` erase under `mu_`) and returns `RevokeResult { count, db_persisted }`. In-memory wipe runs even if the DB write fails (operator's "stop NOW" intent), but `db_persisted=false` surfaces up so the REST handler audits `result="partial"` with `detail` carrying `db_error=true`. Defence-in-depth: the AuthDB primitive itself validates username (matches sibling `add_user` / `update_role`).
  - Audit actions split for SIEM correlation: `session.revoke_all` (cross-user) vs `session.revoke_all.self` (self via either route, including admin self-target through the admin path). Both use `target_type=User` (project PascalCase convention). `result` ∈ {`success`, `partial`, `denied`}.
  - Prometheus counter `yuzu_auth_sessions_revoked_total{caller, result, scope}` for CC7.2 anomaly detection.
  - Self-target guard distinction (DO NOT CONFLATE WITH `#397/#403`): the existing `#397/#403` self-target guard on `DELETE /api/settings/users/<self>` and role demotion is a hard 403 to prevent admin-role self-lockout (an unrecoverable state). Session revocation self-target is recoverable (re-auth) and is permitted but audited as `.self`. Future refactors must not "fix" the session-revocation self-target into a hard 403.

## Account lockout (SOC 2 CC6.3)

Brute-force / credential-stuffing protection on the **local-password** login
path (`POST /login`). OIDC delegates throttling to the IdP; the MFA
code-verification path has its own per-token failure rate-limit — neither is in
scope here.

- **State** lives in three columns on the `users` table (`auth.db` migration
  v3): `failed_login_count`, `last_failed_login_at`, `locked_until`
  (`NULL` = not locked). A non-existent username has no row, so spraying random
  usernames neither locks a non-existent account nor grows storage
  (anti-enumeration). All three accessors (`AuthDB::lockout_status` /
  `record_failed_login` / `clear_failed_logins`) are parameterised and use
  `RETURNING`, never `sqlite3_changes()` (#1033).
- **Policy** is config, not schema, so operators retune without a migration:
  - `--auth-lockout-threshold` (`YUZU_AUTH_LOCKOUT_THRESHOLD`, default `5`,
    `0` disables) — consecutive failures before lock.
  - `--auth-lockout-window-secs` (`YUZU_AUTH_LOCKOUT_WINDOW_SECS`, default
    `900`) — lock duration. The lock **auto-expires** after the window; it is
    never permanent, so it cannot be weaponised to permanently DoS a
    legitimate principal. The posture is logged once at boot for CC6.3
    evidence.
- **Flow** in `auth_routes.cpp` `POST /login`:
  - *Pre-check* (before PBKDF2): if the account is currently locked, reject
    with the **same generic 401** as a bad password — no `Retry-After`, no
    "locked" wording, so the response body is not a username-enumeration /
    lock-state **content** oracle. `verify_password` is skipped entirely, so the
    ~100 ms PBKDF2 is never burned on a locked account. Fail-open on a read error
    (lockout protects against *wrong* passwords; `verify_password` is still the
    real gate). *Accepted residue:* skipping PBKDF2 makes the locked path
    measurably faster than a known-user wrong-password 401, so response **timing**
    is a weak lock-*state* oracle (it reveals that an account is locked, never a
    credential). This is an accepted trade-off — adding a constant-time floor to
    the locked path would re-introduce the PBKDF2-cost DoS the skip exists to
    avoid.
- **Concurrency — per-username serialized (single-node).** The flow is
  *check-then-act* (`lockout_status` → `verify_password` → `record_failed_login`).
  Without serialization a **synchronized burst** for one username could all
  observe `locked=false` and each verify a password before any sibling recorded
  its failure, so the effective single-burst guess budget would be the in-flight
  concurrency rather than `auth_lockout_threshold` (the per-IP `login_rate_limit`
  does **not** bound a distributed botnet firing one request per IP). The whole
  sequence is therefore held under a **striped per-username login lock**
  (`AuthRoutes::login_lock_for` / `login_locks_`): concurrent attempts for one
  account serialize, so at most `threshold` reach password verification before
  the lock arms (covered by a barrier-style concurrent route test). Different
  usernames hash to different stripes and log in fully in parallel — only a burst
  against one account is throttled, which is the intended effect. This is
  **single-process** scope, adequate for the current single-node SQLite
  `auth.db`; the HA/multi-replica-correct form is a DB-atomic attempt-reservation
  that lands with the auth store's Postgres migration (tracked follow-up).
  `login_rate_limit` remains the companion control for the distributed vector.
  - *On failure*: `record_failed_login` increments the counter and arms
    `locked_until` on the threshold-th failure. A window that has **fully
    expired** starts a fresh attempt budget (the waited-out user gets their
    attempts back).
  - *On success*: `clear_failed_logins` resets the counter (covers all three
    success exits — no-MFA mint, MFA challenge, enforced enrollment).
- **Admin unlock** — `POST /api/v1/users/<name>/unlock`, gated by
  `UserManagement:Write` and the MFA step-up gate. Self-target is permitted
  (recoverable, same reasoning as session self-revoke). The operability path
  for an operator who can't wait out the window.
- **Audit** — `auth.lockout.applied` (once, on the threshold crossing),
  `auth.lockout.cleared` (success reset or admin unlock, actor recorded). A
  blocked attempt while already locked is counted via the metric, **not**
  audited per-attempt (flood-amplification, same rationale as the MFA pending
  load-shed).
- **Metrics** — `yuzu_auth_lockout_applied_total`,
  `yuzu_auth_lockout_blocked_total`.

## Inactivity (idle) session timeout (SOC 2 CC6.3)

`/auth-and-authz` skill gap matrix P1 #8. A **sliding** idle window that
invalidates an operator dashboard cookie session after a period of inactivity,
*under* the absolute 8-hour session lifetime (`kSessionDuration`). Wires the
previously-reserved `sessions.last_activity_at` column end-to-end.

- **Config** — `--session-inactivity-secs` (`YUZU_SESSION_INACTIVITY_SECS`),
  `Config::session_inactivity_secs`. **Default 0 = disabled** (opt-in): the
  absolute lifetime already exists and an idle-logout that drops a legitimate
  user mid-coffee-break is a behaviour change, so it is off unless an operator
  turns it on (recommended `900` = 15 min). Boot posture is logged for CC6.3
  evidence. Enabling it satisfies the CC6.3 inactivity-timeout control.
- **In-memory is authoritative.** Sessions are validated from the in-memory
  `AuthManager::sessions_` map (the `auth.db` `sessions` rows are v1
  dead-writes), so the idle state lives on the in-memory `Session`:
  `last_activity_at` (a monotonic `steady_clock` stamp — an NTP step can neither
  extend nor collapse the window). `AuthManager::session_inactivity_` holds the
  configured window (set once at startup via `set_session_inactivity`).
- **Enforcement is in `validate_session`** (the same place the absolute
  `expires_at` is checked, and which already conditionally upgrades its shared
  lock for the opportunistic reap). When the feature is on: a session idle
  longer than the window is **rejected and evicted** (the reap re-reads
  `last_activity_at` under the write lock so a concurrent touch at the boundary
  doesn't kill a now-active session); an active one has `last_activity_at`
  **slid forward** (the window slides). **The touch is throttled** — the window
  is advanced (which needs the exclusive lock) at most once per
  `touch_granularity` (a quarter of the idle window, capped at 30 s), so a burst
  of requests for an active session stays on the **shared** lock rather than
  serialising on `mu_`; `last_activity_at` therefore lags real activity by at
  most the granularity (far inside any minutes-scale window, so an active session
  is never wrongly evicted — idle-out fires within `[window − granularity,
  window]`). The idle-*disabled* small-map read stays a pure shared-lock path (no
  behaviour change for deployments that leave it off).
- **Scope: cookie sessions only.** API tokens and MCP tokens resolve through
  `synthesize_token_session` (their own store), never `validate_session`, so a
  long-lived automation token is **never** idle-timed-out. OIDC sessions are
  subject to the same idle window but the user simply re-authenticates via SSO.
- **Durable mirror is best-effort + throttled.** On a touch, the in-memory stamp
  is authoritative; the `auth.db` column is updated via
  `AuthDB::touch_session_activity` (mirrors `mfa_mark_session_stepup`) at most
  once per session per `kActivityPersistGranularity` (60 s), off the `mu_` lock
  (snapshot-and-release), so the per-request touch is **not** a per-request SQL
  write. Idle expiry is not separately audited (neither is absolute expiry) and
  emits **no Prometheus counter** — the observable signal is the `auth.login`
  audit row on re-authentication.

## MFA / TOTP (v0.12+, SOC 2 CC6.6)

Full design: `docs/auth-mfa-design.md`. Summary:

- **RFC 6238 TOTP** (HMAC-SHA1, 30 s step, 6 digits, ±1 step skew with
  replay protection). 10 single-use base32 recovery codes per
  enrollment, PBKDF2-SHA256 hashed.
- **Self-service enrollment** via Settings → Multi-Factor Authentication.
  One-time `otpauth://` reveal in the same `<div class="token-reveal">`
  pattern as API-token issuance.
- **Login challenge** — `POST /login` returns HTTP 202 +
  `mfa_pending_token` (opaque, in-process, `cfg.mfa_login_pending_secs`
  TTL) when the user has TOTP enrolled; browser swaps to a TOTP form
  and posts to `POST /login/mfa`. Recovery codes share the same
  endpoint.
- **Storage** — TOTP secret as raw 20-byte BLOB in `users.mfa_totp_secret`,
  protected by the same 0600 file mode that backs `password_hash`.
  Encryption-at-rest (AES-256-GCM with key in `auth_kv`) is a follow-up;
  the `auth_kv` table is provisioned empty.
  **ADR-0010 (2026-06-10) supersedes the `auth_kv` plan:** the mechanism is
  `SecretCodec` (AES-256-GCM, DEK wrapped by the `KeyProvider`-custodied KEK),
  landing with the `auth` store's Postgres migration. `auth_kv` will not be
  used for this purpose.
- **CLI flags / Config** — `--mfa-enforcement <optional|admin-only|required>`
  (PR 1 honours `optional` only), `--mfa-step-up-window-secs` (default
  300), `--mfa-login-pending-secs` (default 120).
- **Step-up on high-risk surfaces** — `cfg.mfa_step_up_window_secs` (300 s
  default) controls how long after a TOTP proof high-risk endpoints
  accept the session as "stepped up." PR 2 wires the 11 step-up sites
  (user delete, role change, token create/revoke, session revoke,
  Guardian rule write / push, software-package write, software-deploy
  execute, file-retrieval upload) and the `/login/mfa/stepup` route.
- **OIDC `amr` short-circuit** (PR 3) — `IdTokenClaims.amr` parsing so
  IdP-asserted MFA skips the local TOTP step.

Hard invariants live in §"Hard invariants" of `docs/auth-mfa-design.md` —
do not regress them when shipping PR 2 / PR 3.

## JIT admin elevation (SOC 2 CC6.3/CC6.6)

`/auth-and-authz` skill gap matrix P1 #9. Reduce **standing** privilege: a
pre-authorized operator holds a non-admin base role day-to-day and **activates**
admin **just-in-time** for a bounded, justified, MFA-gated window, then
auto-reverts — so a compromised everyday session is not a standing admin session.

- **Eligibility is a per-user flag** — `users.elevation_eligible` (auth.db
  migration v5), distinct from holding standing admin and trivially enumerable
  for access reviews. Admin-managed (and MFA-step-up-gated) via
  `POST /api/v1/users/<name>/elevation-eligibility` `{"eligible": bool}`
  (`AuthDB::set_elevation_eligible`/`is_elevation_eligible`, parameterised,
  `RETURNING` — no `sqlite3_changes()`, #1033). Default 0 (not eligible) — nobody
  gains elevation rights silently. **Self-grant is blocked** (an operator — even
  one acting under an active elevation — cannot set their own eligibility, so a
  temporary admin window can't manufacture a durable self-elevation right).
  **Revoking eligibility immediately terminates any in-flight elevation** for
  that user (`AuthManager::revoke_user_elevations`, symmetric with the session
  wipe on demote/delete) — an incident-response "revoke now" drops admin access
  rather than leaving it standing for the window.
- **Activation** — `POST /api/v1/elevate`
  `{"justification": <required>, "duration_secs": <int>}`. Requires the caller to
  be eligible **and** have **MFA enrolled** **and** pass a fresh MFA step-up.
  MFA enrollment is mandatory **unconditionally** here, NOT gated on
  `--mfa-enforcement`: elevation is the privilege-crossing boundary (non-admin →
  full admin), so — unlike the other step-up sites where the actor is already
  admin — an eligible operator with no enrolled second factor is refused (403,
  `role.elevation.denied`). Sets
  `Session::elevated_until = min(now + min(duration, --jit-max-elevation-secs), session.expires_at)`
  (default cap 1h, max 24h; an absent/0 `duration_secs` defaults to the cap, a
  negative one is a 400, a present-but-wrong-typed field is a 400). **The window
  is also clamped to the session's own absolute `expires_at`** (follow-up B,
  shipped) — an elevation can never outlive the cookie session that carries it,
  even when the requested/capped duration would otherwise extend past it.
  **A session already AT or PAST its own `expires_at` — e.g. one that crosses
  its absolute lifetime in the window between `validate_session` and
  `elevate_session` — is REJECTED (401), not granted a zero-or-negative-length
  window** (governance hardening round, UP-1/UP-4 dead-window guard): a `200
  ok` response with `expires_in:0` would mislead a scripted caller into
  believing it holds admin, and the lapsed window would later mint a spurious
  `role.elevation.expired` for privilege that was never actually conferred.
  `AuthManager::elevate_session` computes this and leaves the session
  unmutated when it applies; the handler's existing nullopt→401 path (already
  used for "session vanished between validate and elevate") covers it, no
  separate branch needed. The response reports the TRUE remaining time as
  `expires_in` (seconds, computed after any clamp — always `<=` the
  requested/capped duration) alongside an absolute `expires_at` (RFC3339 UTC —
  a `system_clock` projection of the `steady_clock`-tracked remaining
  duration, since `elevated_until` itself has no wall-clock meaning
  off-process). The justification is sanitised (control bytes incl. DEL →
  space) and capped (1 KiB) into the audit detail. The `role.elevation.granted`
  audit is **fail-closed**: if it can't persist, the elevation is rolled back
  (compensating `revoke_elevation`) and the call 500s with `Sec-Audit-Failed`
  — a privileged activation never stands without a record. Audits
  `role.elevation.granted` (justification + the true post-clamp duration +
  `expires_at` — kept in sync across the audit row, the JSON response, and the
  analytics event); `role.elevation.denied` for an ineligible /
  failed-eligibility / not-MFA-enrolled caller.
- **Effective role** — `auth::effective_role(session)` returns `admin` while
  `steady_clock::now() < elevated_until`, else the base `role`. THE authorization
  functions gate on it: `require_admin` checks `effective_role`, and
  `require_permission`/`require_scoped_permission` **short-circuit to allow** an
  elevated session (full admin for the window). `elevated_until` is monotonic
  `steady_clock` (an NTP step can't extend it) and **per-session in-memory** — a
  restart or logout drops the elevation (fail-safe).
- **Scope: interactive cookie sessions only.** `/api/v1/elevate` reads the
  session cookie and `elevate_session` keys on the cookie token; API and MCP
  tokens resolve through `synthesize_token_session` (no cookie, no
  `elevated_until`), so a long-lived automation credential can **never** be
  elevated.
- **v1 limitation — local TOTP required.** The mandatory-MFA check is the local
  `mfa_status` (`auth.db`), so an **OIDC-only operator with no local TOTP
  enrolled cannot elevate** (fail-closed: `role.elevation.denied` / no MFA
  enrolled). This is safe but restrictive for SSO-first deployments; elevation
  gated on the OIDC `amr` MFA assertion (so an IdP-MFA'd SSO operator can elevate
  without a local TOTP) is a tracked follow-up.
- **Step-down** — `POST /api/v1/elevate/revoke` clears the window
  (`role.elevation.revoked`). **Passive expiry on lapse is now audited too
  (follow-up A, shipped)** — `role.elevation.expired` — but LAZILY, not via a
  background reaper thread: there is no standing timer, so the row is emitted
  by `AuthManager::reap_expired_elevation` at the `AuthRoutes::resolve_session`
  cookie chokepoint, on the FIRST authenticated request the operator makes
  *after* the window has lapsed. `elevated_until` is cleared to the sentinel on
  that first observing call, so emission is exactly-once — a request that finds
  the sentinel already cleared (a prior reap, or a manual
  `revoke_elevation`/`revoke_user_elevations`, which clear to the same
  sentinel) emits nothing, so a manual step-down never ALSO produces a spurious
  `expired` row. **The `role.elevation.expired` emission is itself best-effort
  / at-most-once** (governance hardening round, UP-3): `elevated_until` is
  cleared to the sentinel BEFORE the audit call, so a store failure loses only
  the confirmatory `expired` row, never the reap itself (the session still
  correctly reverts to base role) — and the window's end remains
  reconstructible from the earlier, fail-closed `role.elevation.granted` row's
  `duration_secs`/`expires_at`. **Boundary: an operator who elevates and never
  issues another authenticated request before abandoning the session (closing
  the browser, letting the tab idle) never triggers the lazy reap** — there is
  no event for that lapse, only the deterministic `granted` row + its
  `duration_secs`/`expires_at`, from which the window's end is still
  computable for audit reconstruction. **The same boundary applies to idle
  (inactivity) eviction** — see "Inactivity session timeout" below: if the
  idle reaper evicts the session (erases it from `sessions_`) before the
  operator's next request, that request never reaches `resolve_session`'s
  cookie-found branch at all, so the lazy reap likewise never fires; the
  window's end is, again, reconstructible from the `granted` row rather than
  from a live `expired` event. Implementation: `Session::elevated_until` +
  `AuthManager::elevate_session`/`revoke_elevation`/`reap_expired_elevation`
  (auth.cpp); the three
  endpoints in `auth_routes.cpp`; `Config::jit_max_elevation_secs`.

## Hardened mode (sso-only) + break-glass (SOC 2 CC6.3/CC6.6)

`/auth-and-authz` skill gap matrix P0 #3. Closes Workstream B *"Disable
local-password fallback in hardened mode (or tightly constrain break-glass
account policy)"* — this ships **both** halves.

- **`--auth-mode <standard|sso-only>`** (`YUZU_AUTH_MODE`, default `standard`).
  Under `sso-only` the local-password login path is disabled fleet-wide — only
  OIDC SSO (`/auth/callback`, untouched) mints a session. The rejection at
  `POST /login` returns the **same generic 401** as a bad password (no
  "disabled"/"sso-only" wording, no `Retry-After`) so the response BODY carries
  no enumeration/mode/arm-state oracle, and `verify_password` (PBKDF2) is
  skipped — same posture and accepted *timing* residue as the lockout pre-check.
  The denial is recorded as a **metric, not a per-attempt audit row**
  (`yuzu_auth_local_disabled_total{target=break_glass|other}`) — a credential
  spray would otherwise grow `audit.db` without bound, the exact amplification
  the lockout *blocked* path avoids; the CC6.3 evidence is the boot-posture
  banner + this counter (the `{target}` label, cardinality 2, flags probing of
  the break-glass account itself for SIEM alerting).
- **Boot guard (fail-closed).** `sso-only` **refuses to start** when OIDC is not
  **fully** configured — the guard requires both `--oidc-issuer` **and**
  `--oidc-client-id` (the same predicate the OIDC provider's `is_enabled()` uses;
  issuer-without-client-id leaves SSO silently non-functional). Otherwise every
  operator is locked out. The break-glass account is for an IdP **outage**, not
  for never wiring SSO. The active posture is logged once at boot for CC6.3
  evidence.
- **Break-glass account.** `--break-glass-user <name>` (`YUZU_BREAK_GLASS_USER`)
  designates the single local account exempt from `sso-only`, exempt **only
  while armed**. "Armed" is `users.break_glass_armed_until` (migration v4) — a
  future timestamp evaluated in SQL against `CURRENT_TIMESTAMP` exactly like
  `locked_until`, so the exemption **auto-expires** (default 24h,
  `--break-glass-window-secs` / `YUZU_BREAK_GLASS_WINDOW_SECS`, `86400`) and can
  never be a permanent standing bypass. A non-exempt or un-armed attempt gets
  the same generic 401 + `auth.local_disabled`.
- **Mandatory MFA, enforced two ways.** (1) Boot **fails closed** if the
  break-glass user doesn't exist or has no MFA enrolled
  (`break_glass_account_problem` in `auth_db`, shared by the boot guard and the
  arm one-shot; because `mfa_status` filters `is_active=1`, a soft-deleted user
  also reads as un-enrolled and is rejected). (2) If MFA is cleared out-of-band
  between boot and login, the login handler **hard-denies** the break-glass login
  (`403` + `auth.breakglass.denied`, `Severity::kCritical`) — it does **not**
  fall through to TOTP *enrollment*, because enrollment would hand a fresh secret
  to whoever proved the password and let a password-only adversary self-enrol and
  break the glass with no real second factor (governance UP-1). An enrolled
  break-glass login that proceeds emits `auth.breakglass.login` (`result=ok`,
  `kCritical` — `result=ok` means the *password* was accepted; the row's `detail`
  is explicit that the mandatory TOTP challenge still runs before a session is
  minted) + the metric `yuzu_auth_break_glass_login_total` + a `warn` log.
- **Lockout-exempt under sso-only (availability).** The break-glass account is
  exempt from failed-login lockout while `--auth-mode=sso-only`, so an attacker
  who learns its username cannot spray wrong passwords to keep it locked and
  render the escape hatch unreachable during an IdP outage (governance Hermes-F /
  UP-13). Safe because the second factor is still mandatory and, while un-armed,
  the password is never evaluated; wrong attempts are still audited
  (`auth.login_failed`) + per-IP rate-limited. Normal lockout still applies in
  standard mode.
- **Arming is an out-of-band host operation, never a session route.** The IdP
  being down is *why* you break the glass, so arming cannot depend on a login.
  `yuzu-server --break-glass-arm` (with `--break-glass-user` + `--data-dir`)
  arms the account for the window and exits — mirroring the `--mfa-reset`
  break-glass contract (#1226): it validates the account (exists + MFA),
  verifies the audit store is **writable before** mutating, and writes
  `auth.breakglass.armed` attributed to the **kernel-authoritative OS identity**
  (`resolve_os_principal`, not the forgeable `USER` env var), `principal_role =
  break-glass`. Refuses to arm — and exits non-zero — if any check fails or the
  audit row can't persist.

Implementation: gate at `auth_routes.cpp` `POST /login` (between the lockout
pre-check and `verify_password`); accessors `AuthDB::break_glass_status` /
`arm_break_glass` (single `UPDATE ... RETURNING`, no `sqlite3_changes()` —
#1033); flags + boot guard + arm one-shot in `main.cpp`; `Config::auth_mode` /
`break_glass_user` / `break_glass_window_secs` in `server.hpp`. Tests:
`tests/unit/server/test_auth_break_glass.cpp` (DB accessors) +
`test_auth_routes_hardened.cpp` (wire path).

## Granular RBAC (Phase 3)

- 6 roles, 19 securable types, per-operation permissions, deny-override logic.
- **OIDC SSO** — Full PKCE flow, Entra ID discovery, JWT validation, group-to-role mapping.
- **AD/Entra integration** — Microsoft Graph API for user/group import.

## API tokens and automation

- **API tokens** — Bearer token and `X-Yuzu-Token` header auth for automation. MCP tokens (see `docs/mcp-server.md`) use the same table with mandatory expiration (max 90 days).
- **Ownership-scoped revocation** — `DELETE /api/v1/tokens/{id}` and `DELETE /api/settings/api-tokens/{id}` both require the caller to own the token; the global `admin` role is the sole bypass. Cross-user revoke returns `404 token not found` (identical to unknown-id, to prevent enumeration). Denied attempts are recorded with `result=denied`, `detail=owner=<principal>`. See #222 and `docs/user-manual/server-admin.md` "Upgrade Notes".

## Agent enrollment (3 tiers)

- **Tier 1 (manual approval)** — agents without a token enter a pending queue; admin approves/denies via Settings page. Agents retry and are accepted once approved.
- **Tier 2 (pre-shared tokens)** — admin generates time/use-limited enrollment tokens via the dashboard; agents pass `--enrollment-token <token>` at startup for auto-enrollment.
- **Tier 3 (platform trust)** — proto fields reserved (`machine_certificate`, `attestation_signature`, `attestation_provider`) for future Windows cert store / cloud attestation enrollment.
- **Enrollment token persistence** — tokens stored in `enrollment-tokens.cfg`, pending agents in `pending-agents.cfg` (same directory as `yuzu-server.cfg`).
- **Agent `--enrollment-token` CLI flag** — passes token in `RegisterRequest.enrollment_token`.

## Per-session peer binding and NAT-aware relaxation

`Register` and `Subscribe` are separate gRPC connections correlated by a
`session_id`. To stop a sniffed `session_id` from being replayed from another
host, Subscribe is bound to the Register connection by **two layers**:

- **Peer-IP binding (#826, hardened #1058/#1059)** — Subscribe's source IP must
  equal the IP recorded at Register (or, under `--gateway-mode`, a trusted
  gateway IP). A mismatch increments
  `yuzu_grpc_subscribe_peer_mismatch_total{event="security"}` and emits a
  `session.peer_mismatch` audit row (`result="denied"`).
- **Identity binding (authoritative)** — the `agent_id`↔session binding (#827)
  and, under mTLS, the client-identity binding (#1118,
  `yuzu_grpc_subscribe_identity_mismatch_total`). These are *stronger* than
  source IP.

**NAT-aware relaxation (#1128).** Exact-IP binding false-rejects a legitimate
agent whose Register and Subscribe egress *different* public IPs (multi-egress
NAT, proxy pool, CG-NAT, SD-WAN). Strict exact-match is the **default**; two
**opt-in** accommodations downgrade a mismatch to *advisory* (audit + metric, no
reject) instead:

1. **mTLS-advisory — `--nat-trust-mtls-identity`** (`Config::nat_trust_mtls_identity`,
   **default off**) — when enabled, a verified client identity matching the one
   bound at Register treats the IP as defence-in-depth only, so the mismatch is
   tolerated. **Opt-in because it is safe ONLY with per-agent client certs:** a
   shared/fleet-wide cert makes every identity "match", which would let an
   insider agent replay another agent's session from its own IP (gov UP-2). Off
   by default — identity-match never relaxes the IP binding unless the operator
   affirms per-agent certs via this flag.
2. **`--trusted-nat-cidr <cidr>[,…]`** (`Config::trusted_nat_cidrs`) — when the
   Register *and* Subscribe IPs both fall inside one operator-declared range
   (analogous to `--gateway-mode`, but for direct-connect NAT). Declaring a
   range asserts the hosts in it are mutually trusted not to replay each other's
   sessions — keep ranges narrow (never `0.0.0.0/0`). Malformed entries are
   logged and ignored at startup.

A mismatch *outside* both accommodations is still a hard reject — the replay
guard is intact, and an empty/malformed extracted IP is always reject (#826:
empty is a mismatch, never a wildcard). A tolerated mismatch emits
`yuzu_grpc_subscribe_peer_advisory_total{event="security",reason=…}` plus a
`session.peer_mismatch` audit row with `result="ok" outcome=advisory`. The pure
decision lives in `AgentServiceImpl::evaluate_peer_binding` (unit-tested);
CIDR containment in `cidr_match.{hpp,cpp}`.

**Gateway origin-IP attribution (#1064).** On the gateway `ProxyRegister` path
the server's transport peer is the *gateway's* IP, so audit rows would
mis-attribute the source (SOC 2 IR-2). `RegisterRequest.gateway_observed_peer`
(an optional, gateway-authoritative, transport-agnostic field — survives the
planned gRPC→QUIC move) carries the agent's origin IP; the server records
`source_ip`=agent origin and `gateway_ip`=transport peer, falling back to the
gateway IP (`origin_observed=false`) when absent. The *direct* Register path
ignores the field, so a *direct* agent cannot forge a source IP. It is **not** a
defence against a compromised gateway (which is inside the trust boundary and
can set any value) — both `source_ip` and the gateway's `gateway_ip` are
recorded so an auditor can cross-check. **Server-side consumption ships now; the
gateway-side population is a follow-up** — today's grpcbox transport can only
source it from `x-forwarded-for` (proxied deployments), and the durable
direct-mode source arrives with the QUIC transport (#376) that owns its socket.

## HTTPS and bind defaults (hard invariants)

- **HTTPS by default** — `https_enabled` defaults to `true`. Operators must provide `--https-cert` and `--https-key`, or use `--no-https` for development. The `--https` flag was replaced with `--no-https`.
- **Secure bind default** — Web UI binds to `127.0.0.1` by default (not `0.0.0.0`). A startup warning is logged if overridden to all interfaces.
- **Metrics auth** — `/metrics` allows unauthenticated access from localhost only. Remote access requires authentication. `--metrics-no-auth` overrides for monitoring infrastructure.
- **Private key permission validation** — Server refuses to start if TLS private key files are group/others-readable on Unix. Uses `std::filesystem::perms` check. Skipped on Windows.
- **CORS on all API endpoints** — CORS headers applied via `set_post_routing_handler` for all `/api/` paths.
- **JSON error envelope** — All error responses use structured `{"error":{"code":N,"message":"..."},"meta":{"api_version":"v1"}}` envelope. Health probes (`/livez`, `/readyz`) use `{"status":"..."}` contract.

## Default certificates (PKI PR2, v0.13.0+)

A fresh install no longer refuses to start without operator certs. On first boot
the server generates a per-install internal CA (ECDSA P-384, 10-year) and P-256
leaves for the HTTPS, agent-gRPC, and management-gRPC listeners under the cert
directory (`auth::default_cert_dir()`; override with `--ca-dir`), recorded in
`ca.db`. Implementation: `default_certs.{hpp,cpp}` on the
`x509_ca`/`key_provider`/`ca_store` engine. Behaviour:

- **Per-surface, partial-override.** Defaults fill only the surfaces the
  operator left empty; an explicit `--https-cert`/`--cert` still wins. A surface
  with a cert but no key (or vice-versa) is a hard error (refuse to start) —
  operator and generated material are never mixed.
- **Agent-listener posture.** While the agent surface is on default certs the
  agent (and the management listener when it reuses agent creds) runs
  `REQUEST + VERIFY but NOT REQUIRE` client certs — encrypted +
  server-authenticated, so a first-boot agent with no client cert can connect
  and bootstrap one (per-agent mTLS, below). An operator-supplied agent surface
  keeps the strict `REQUEST_AND_REQUIRE` posture (the relaxation is gated on
  `using_default_agent_certs`, never the global `using_default_certs`).
- **Loud, impossible-to-miss notification (six surfaces):** ERROR startup banner
  with the CA SHA-256 + expiry; one-shot audit `server.default_certs_generated`;
  a 300 s periodic reminder + audit `server.default_certs_in_use`; Prometheus
  `yuzu_server_default_certs_active`; `/health` `tls.default_certs_active` +
  `ca_fingerprint` + `ca_expires_at` (unauthenticated — the CA is already in the
  TLS handshake); `/readyz` gains `ca_store`/`ca_root` checks (load-bearing only
  while on default certs).
- **Opt out** with `--no-default-certs` (legacy refuse-to-start). The CA root
  key is a 0600 file (HSM seam in `key_provider`); the threat model is local-host
  compromise — replace defaults with operator/HSM-backed certs for production.

## Per-agent mTLS (PKI PR3, v0.13.0+)

When the server runs with its built-in CA, agents are issued their own client
certificate at enrollment, so the agent↔server data plane is full mutual TLS with
a cryptographic identity bound to `agent_id`. This makes the existing
peer-identity binding (`#1118`) cryptographic with no new binding mechanism — the
issued leaf's `CN` *is* the `agent_id` the server already checks.

Issuance happens on **both** the direct `Register` and the gateway-proxied
`ProxyRegister` paths (PKI PR5d — both share one `sign_agent_csr` chokepoint); see
`docs/pki-architecture.md` "Per-agent enrollment through the gateway" for the
gateway specifics (the agent↔gateway hop is one-way TLS in M1, so through-gateway
identity stays the app-layer `gateway_observed_peer` until gateway mTLS lands).

**Bootstrap (chicken-and-egg) — resolved on one port.** The agent has no client
cert on first boot, but the data plane requires one. Resolution:

1. The agent connects server-authenticated TLS (verifies the server leaf against
   the CA cert it was given via `--ca-cert`), presenting **no** client cert.
2. The agent generates an EC P-256 keypair + a PKCS#10 CSR and sends the CSR in
   `Register` (`RegisterRequest.csr_pem`). The agent's private key never leaves
   the host.
3. When enrollment is approved (token / attestation / admin-approve — unchanged)
   **and** the built-in CA is active, the server verifies the CSR's
   proof-of-possession, signs a client leaf — `CN=<agent_id>` + URI SAN
   `yuzu://<ca-fingerprint>/agent/<agent_id>` — sized to ≤ the CA's `notAfter`,
   records it in `ca.db` (`purpose=agent`), and returns it in
   `RegisterResponse.issued_certificate` + `issued_ca_chain`. **The CSR's own
   subject/SAN are ignored** — identity is set by the server from the
   authenticated enrollment, never from attacker-controlled CSR fields (this is
   what stops an enrolling agent requesting another agent's identity).
4. The agent persists the leaf + key (`0600`) + chain under `--cert-dir`
   (default `<data-dir>/certs`), rebuilds its channel, and **re-Registers
   presenting the leaf** — a fresh session whose bound identity is the leaf's
   `CN`. (The first, no-cert session bound an empty identity, so the data plane
   would reject it; re-registering binds `CN=<agent_id>`.)

**App-layer enforcement.** `Register` is the only RPC permitted without a verified
client identity (it is how an agent obtains one). Enforcement is **gradual**, so
per-agent mTLS rolls out without breaking a heterogeneous or mid-upgrade fleet:

- `Register` is bootstrap-exempt but, if a client cert *is* presented (re-auth /
  renewal) and it is one of **ours** (issuer-scoped via `is_yuzu_issued`), it must
  match `agent_id` and must not be revoked. A foreign cert (multi-CA bundle) falls
  through to bootstrap.
- `Subscribe` rejects a presented leaf whose serial is on the CRL before taking
  the agent-plane lock (`yuzu_grpc_revoked_cert_total{rpc=subscribe}`), then
  enforces the `#1118` identity overlap **only when the session bound a client
  identity at Register** (i.e. the agent presented a cert). A provisioned agent
  therefore MUST present its leaf on `Subscribe` (a no-cert `Subscribe` against a
  cert-bound session fails the overlap → reject, so the stolen-session guard
  holds); a not-yet-provisioned or legacy (pre-PR3) agent has no bound identity
  and continues on the prior posture (session + `#826` peer-IP binding) rather
  than being hard-rejected.
- `Heartbeat`, `DownloadUpdate`, and `CheckForUpdate` reject a presented
  **revoked** leaf (`yuzu_grpc_revoked_cert_total{rpc=heartbeat|download_update|check_for_update}`)
  so a revoked agent is denied liveness, OTA download, *and* OTA version
  discovery — not just the command channel. `DownloadUpdate` also emits an audit
  row (`session.cert_revoked`); `Heartbeat`/`CheckForUpdate` are metric-only
  (high-frequency). `is_yuzu_issued` results are cached (immutable per cert) so
  the per-heartbeat check is not an ECDSA chain verify fleet-wide.
- **Open-stream revocation sweep (H-1).** The `Subscribe` gate above only runs at
  stream establishment, so a long-lived command channel would keep dispatching to
  an agent revoked *after* it connected (a hostile agent never voluntarily
  reconnects). The server's reaper thread therefore runs a periodic
  `AgentRegistry::sweep_revoked` (~15 s, well inside any CRL validity window) that
  re-evaluates every live Subscribe stream's stored leaf against the CRL and
  `TryCancel`s the stream of any now-revoked agent
  (`yuzu_grpc_revoked_cert_total{rpc=stream_sweep}`); the cancelled agent must
  reconnect, where the establishment gate refuses it. The presented leaf is
  stashed on the session only when a revocation checker is wired (CA active), so a
  non-PKI deployment stores nothing. PR4's operator-revoke handler calls the same
  sweep immediately so a dashboard/REST revoke tears the stream down promptly
  rather than waiting for the next tick. The revocation predicate runs off the
  per-session lock (it reads `ca.db`), and teardown re-checks the cert is
  unchanged so a reconnection mid-sweep is not cancelled by mistake.
- `require_client_identity_` is recomputed *after* the default-cert bootstrap
  (`tls_enabled && !tls_ca_cert.empty()`), since it is baked at construction
  before the CA exists.

**Rollout / upgrade.** Because enforcement is gradual, upgrading a fleet to PR3 is
non-breaking: agents that have not yet auto-provisioned (or run
`--no-auto-provision-cert`, or a pre-PR3 binary) keep connecting on session +
peer-IP binding, while provisioned agents get strict mTLS. Once a fleet is fully
provisioned, a future `--require-agent-identity` flag (tracked follow-up) can
harden this to require a bound identity for *every* agent and reject the
unprovisioned fallback. Folding revocation + identity into a single gRPC
interceptor so every identity-requiring RPC enforces them uniformly is the related
follow-up (today they are enforced at `Register`, `Subscribe`, `Heartbeat`,
`DownloadUpdate`).

**Custody & renewal.** The CA issuing key is loaded transiently per signature via
`FileKeyProvider` and zeroed (RAII) so the crown jewel is not resident for the
process lifetime. Server issuance is fail-closed: a cert that cannot be recorded
in `ca.db` (so it could never be revoked) is not handed out, and per-agent
issuance is rate-limited (one signature per `agent_id` per 30 s) so a holder of a
valid enrollment credential cannot spam the signer. Agent leaves are ~1-year and
auto-renew once two-thirds of their lifetime has elapsed (evaluated at agent
start; a fresh CSR rides the next `Register`). Issuance is audited
(`ca.cert.issued`). On the agent, the leaf key is written `0600` via an atomic
`O_EXCL` stage-and-rename on POSIX; **on Windows the key falls back to
`std::ofstream` + a best-effort permissions tightening — an explicit owner-only
ACL (`SetNamedSecurityInfoW`) is a tracked follow-up shared with the server's
`FileKeyProvider`, so on Windows run the agent under a dedicated service account
with no inherited group-read on the cert directory until then.**

**Trust scoping.** Presented client certs are accepted as agent identities only
when they signature-verify to *our* issuing CA (`verify_chain`), so in a
multi-CA trust bundle a foreign cert carrying a matching `CN` is not mistaken for
a Yuzu agent (nor conflated with a revoked Yuzu serial). If the server signs but
the agent never receives the cert (an active MITM stripping the field, or a
persistent signer outage), the agent bounds its retries and gives up
auto-provisioning for that run rather than looping.

**Agent CA pinning is fail-closed (#1303).** When the agent has TLS on but no CA
to pin — no `--ca-cert` **and** no install CA auto-discovered at the standard
shared-cert path (`/etc/yuzu/certs/default-ca.pem`, ProgramData on Windows) — it
**refuses to connect** rather than silently falling back to the system trust
store. An empty root set makes gRPC verify against the OS roots, which do **not**
trust a Yuzu self-signed install CA, so with the gateway one-way-TLS edge live any
publicly-trusted impostor cert for the dial host would be accepted — a fail-open
MITM on the command fan-out plane. The deliberate escape hatch is
`--tls-system-roots` / `YUZU_TLS_SYSTEM_ROOTS`, for the legitimate case where the
server certificate chains to a public or corporate CA already in the system store;
it logs a loud warning and is never the default. (`--no-tls` remains the dev/demo
opt-out.)

**Operator surface.** Server: `--ca-dir` (shared with the default-cert
bootstrap). Agent: `--cert-dir` / env `YUZU_CERT_DIR` (where the provisioned
credential lives) and `--no-auto-provision-cert` (disable the CSR-at-enrollment
flow — e.g. when supplying an operator-minted client cert via `--client-cert` /
`--client-key`, or an OS-store cert). The provisioned credential is written under
`--cert-dir` as `agent-client.key` (private key, `0600`), `agent-client.pem`
(the issued leaf), and `agent-ca.pem` (the issuing CA chain the agent pins the
server against). Deleting these files makes the agent **auto-re-provision** on
its next enrollment: it generates a fresh keypair + CSR and the server signs a
NEW leaf with a NEW serial. The previously-issued serial stays in `ca.db`
inventory as a now-orphaned `agent` row that no live agent holds — harmless, but
operators reconciling the issued-cert inventory should expect one orphan row per
key-loss event (revoke the orphan if a strict inventory is required).
**Revocation-bypass guard (#1239 H-2):** auto-re-provision is refused when the
agent's prior cert is *revoked* (not merely orphaned). `sign_agent_csr` scans
`ca.db` for a revoked, non-expired cert with `subject==agent_id` and, if found,
returns `nullopt` (audit `ca.cert.reissue_blocked`, metric
`yuzu_server_ca_reissue_blocked_total{reason=revoked_identity}`) — so a
compromised endpoint cannot drop its key and re-enroll its way back onto the data
plane. Clearing a revocation is a deliberate operator re-approval, never an
automatic consequence of key loss.
Implementation: server signer in `server.cpp`
(`sign_agent_csr` / `is_peer_cert_revoked`) on the
`x509_ca`/`key_provider`/`ca_store` engine; agent provisioning in
`agents/core/src/agent_csr.{hpp,cpp}` (self-contained OpenSSL) wired into the
`agent.cpp` connect/register loop.

**Gateway-proxied agents: revocation scope (known limitation).** Per-agent mTLS
identity and revocation enforcement are **authoritative on direct connect only**.
A gateway-proxied agent terminates its TLS at the *gateway*; on the
gateway→server hop the server's transport peer is the **gateway's** cert, not the
agent's leaf — so the server-side revocation gate and the open-stream sweep above
never see the proxied agent's serial, and a revoked agent behind a gateway stays
functional on the data plane. PR5d closes the *issuance* half of this gap
(gateway-proxied agents now obtain a per-agent leaf via `ProxyRegister`
CSR-signing, so the identity exists and is recorded/revocable in `ca.db`), but
*enforcing* that revocation at the gateway edge is future work: durable
cryptographic through-gateway identity (and therefore through-gateway revocation)
arrives with the QUIC single-connection migration (#376). Until then, to revoke a
gateway-proxied agent promptly, revoke at the gateway/management layer (disconnect
the agent) in addition to `POST /api/v1/ca/revoke`. This is the same
direct-connect-authoritative caveat called out in `docs/pki-architecture.md`
("Gateway path identity").

**Gateway CSR-swap forgery (R-5, accepted M1 residual).** Wiring `ProxyRegister`
to sign forwarded CSRs makes the gateway a bounded **confused deputy**. The
server signs the relayed CSR's public key under the **gateway-supplied**
`agent_id` (the through-gateway identity is the app-layer `gateway_observed_peer`,
not a transport-cryptographic binding in M1), so a compromised or on-path gateway
can relay a *victim's* `agent_id` paired with its *own* CSR and obtain a real
CA-signed leaf for that `agent_id`. Worse than a transient relay: that leaf is a
durable credential the attacker can present for **persistent direct mTLS
reconnect**, bypassing the gateway entirely — it **survives gateway eviction**.
Compensating controls (why this is accepted for M1, not a live break):

- Every forged leaf is recorded in `ca_issued` and is **revocable** — and #1290
  stamps `via=gateway_proxy` on the `ca.cert.issued` audit + issuance metric, so
  an incident responder can **scope and bulk-revoke the gateway-issued population**
  after a gateway compromise (the row the forensic control depends on).
- The gateway authenticates to the server over **upstream mutual TLS** (a rogue
  gateway cannot reach the issuance path without being an enrolled gateway).
- PR5c **one-way TLS** on the agent↔gateway edge mitigates the *on-path* (non-gateway-
  compromise) variant.

The actual cryptographic remediation — gateway agent-identity **attestation** +
per-gateway issuance **scoping** so a gateway can only obtain leaves for the
`agent_id`s it legitimately fronts — is tracked in **#1292** (cryptographic
through-gateway binding lands with the QUIC migration, #376). Full threat model:
`docs/security-reviews/pki-pr5-gateway-tls.md`; also summarised in
`docs/pki-architecture.md`.

## HTTP security response headers (SOC2-C1)

All HTTP responses (dashboard, REST API, MCP, metrics, health probes) carry six headers: `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy` (deny-all baseline for camera/mic/geo/usb/etc.), and `Strict-Transport-Security: max-age=31536000; includeSubDomains` (HTTPS only, per RFC 6797).

The CSP is fully `'self'`-only with no external CDN allowance because the HTMX runtime and SSE extension are embedded in the server binary (`server/core/src/static_js_bundle.cpp`) and served from `/static/htmx.js` and `/static/sse.js` — the dashboard works in air-gapped deployments.

The CSP uses `'unsafe-inline'` for `script-src`/`style-src` because the dashboard has inline `<script>`, `onclick=` handlers, and `<style>` blocks; tightening to nonce-based CSP requires a separate dashboard refactor. `upgrade-insecure-requests` is appended to the CSP only on HTTPS deployments.

Operators can extend the CSP via `--csp-extra-sources "https://cdn.example.com https://beacon.example.com"` (space-separated, validated at CLI parse — control bytes / semicolons / `'unsafe-eval'` are rejected at startup with a clear error). The flag's value is appended to `script-src`/`style-src`/`connect-src`/`img-src` only.

Header construction lives in `server/core/src/security_headers.{hpp,cpp}` (`yuzu::server::security` namespace) — the production server and the unit/integration tests in `tests/unit/server/test_security_headers.cpp` (38 cases) share the same `HeaderBundle::make()`/`apply()` code path. The resolved bundle is logged at INFO at startup so operators can confirm activation: `Security headers active: CSP=N bytes, HSTS=on/off, Referrer-Policy="...", Permissions-Policy=N bytes`.

## Self-target principal-destruction guard (hard invariant, #397/#403/ca-B1)

Any handler that destroys, demotes, or otherwise revokes a principal's privileges MUST reject the case where the URL/form target equals the caller's `session->username` (or differs from `session->role` for upserts that demote). UI suppression alone is insufficient — a hand-crafted HTTP request bypasses the dashboard.

**Load-bearing routes today:**

- `DELETE /api/settings/users/:name` — self-delete
- `POST /api/settings/users` — self-demote via role change

**Pattern requirements:**

1. Compare against `session->username` byte-exact. Fail closed when `session->username.empty()`.
2. Emit `audit_fn_(req, "<noun>.<verb>", "denied", "User", target, "<reason>_blocked")` on the rejection branch — `spdlog::warn` alone breaks the SOC 2 CC7.2 evidence chain.
3. Corresponding fragment renderers must accept the session username and suppress destructive controls on the matching row (see `render_users_fragment(const std::string& current_username)` — no default arg, every caller must pass explicitly so a future caller forgetting it is a compile-time failure rather than a silent UI regression).

**Scaling note:** when the third such handler ships, lift the comparison logic into a helper.

## AuthDB — persistent authentication store (v0.12.0+)

`auth.db` (lives in `--data-dir`) is the v0.12.0 SQLite-backed store for user
accounts, sessions, and enrollment tokens. Replaces the prior in-memory +
on-config-flush model that lost users on every restart (#618, #388, #527).
Operator recovery: `docs/ops-runbooks/auth-db-recovery.md`. Security review
record: `docs/security-reviews/authdb-2026-04-30.md`.

The hard invariants for AuthDB-touching changes (file-mode, migration
pattern, lifetime, config-as-seed-only, role-field ignored, gate-level audit,
cleanup cadence, snapshot-and-release publishing) live in
`.claude/agents/authdb.md` — the AuthDB review agent loads them on any
change to `auth_db.{hpp,cpp}` / `auth_routes.{hpp,cpp}` / `auth.{hpp,cpp}`.
