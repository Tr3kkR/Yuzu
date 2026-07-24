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
  be eligible **and** present a mandatory second factor **and** pass a fresh MFA
  step-up. The mandatory second factor is **local TOTP enrollment** for a local
  session, or a **fresh IdP-attested MFA `amr` proof** for an OIDC session when
  `--jit-oidc-amr-elevation` is enabled (OIDC elevation is **restored** by #1852's
  durable SSO identity provisioning — an OIDC session's stable principal now has a
  `users` row to key eligibility on; see "OIDC-amr elevation" below). This
  requirement is mandatory **unconditionally** here, NOT gated on
  `--mfa-enforcement`: elevation is the privilege-crossing boundary (non-admin →
  full admin), so — unlike the other step-up sites where the actor is already
  admin — an eligible operator who presents no second factor (a local session
  with no enrolled TOTP, or an OIDC session with no `amr` proof / the toggle
  off) is refused (403, `role.elevation.denied`). Sets
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
- **OIDC-amr elevation — RESTORED by durable SSO identity (#1852).** As of the
  `oidc:<iss>#<sub>` principal re-key (#1837/#1857), an OIDC session's principal
  is not a local-charset `users` username (it contains `:`/`#`), and before #1852
  the OIDC login path wrote **no `users` row at all** — so `is_elevation_eligible`
  fail-closed and OIDC operators could not JIT-elevate. #1852 auto-provisions a
  durable `users` row for the stable principal (`AuthDB::upsert_sso_identity`,
  migration v6 — see "Durable SSO identity" below), and the elevate route's
  target-lookup chokepoints now validate through `is_valid_principal` (a strict
  superset of `is_valid_username` that additionally accepts a reserved-prefixed
  `oidc:`/`saml:`/`ad:` principal), so an admin can grant `elevation_eligible`
  against the SSO principal and the eligibility gate passes. This does **not**
  resurrect the pre-#1837 accident where an SSO display name that coincidentally
  equalled a *local* username borrowed that local user's eligibility + TOTP — the
  principal is now the immutable `oidc:<iss>#<sub>`, bound to its own provisioned
  row.
- **OIDC-amr elevation (design).** An OIDC operator whose SSO
  session was authenticated with IdP MFA — asserted via the OIDC `amr` claim
  at `/auth/callback`, which seeds `Session::mfa_verified_at` when
  `amr_asserts_mfa(claims.amr)` is true (see `docs/auth-mfa-design.md` "OIDC
  interop") — CAN elevate without local TOTP enrollment. **Prerequisite:**
  eligibility is keyed on the `users` table row, which the OIDC login path now
  **auto-provisions** for the stable principal (`upsert_sso_identity`, #1852 —
  see "Durable SSO identity" below); an admin grants `elevation_eligible` against
  that SSO principal directly, no manual `POST /api/v1/users` step. MFA status is
  **not** consulted for an OIDC session — its second factor is the IdP `amr`
  proof, checked below, never a local TOTP secret. The mandatory-second-factor
  check at
  `POST /api/v1/elevate` (`auth_routes.cpp`) branches EXPLICITLY on identity
  source, not a single "skip the local check" flag:
  ```cpp
  const bool oidc_amr_proof = session->auth_source == "oidc" &&
                              session->mfa_verified_at.time_since_epoch().count() != 0;
  const bool oidc_amr_elevation = cfg_.jit_oidc_amr_elevation && oidc_amr_proof;
  if (session->auth_source == "oidc") {
      if (!oidc_amr_elevation) { /* 403 — distinct reason for no-amr vs toggle-off */ }
      // else fall through to elevation_step_up (freshness on the amr seed)
  } else {
      if (auto st = db->mfa_status(session->username); !st || !st->enrolled) { /* 403 */ }
  }
  ```
  **LOAD-BEARING (security-F1, hardening-round consistency S-2):** an OIDC
  session must **never** fall through to the local `mfa_status` lookup. A
  local *namesake* account (same username, unrelated identity) might be
  TOTP-enrolled, and an earlier draft that used a single `if (!oidc_amr_elevation)
  { <local enrollment check> }` guard let an OIDC caller with no amr proof
  inherit that namesake's enrollment — passing the enrollment gate on a factor
  the OIDC caller never actually presented, then possibly clearing
  `elevation_step_up` too (its no-proof-OIDC branch PASSes under
  `--mfa-enforcement=optional`), granting elevation with a **mislabeled**
  `mfa=local_totp` audit row. The disjoint `auth_source` branch above closes
  that: OIDC sessions have exactly one path to "second factor satisfied" (a
  seeded amr proof with the toggle on) and never consult the `users` MFA
  column at all. This seam remains the ONLY place that unconditionally blocks
  a single-factor (no-amr) OIDC session from elevating — `require_mfa_step_up`
  alone cannot, per the note above. **SAML** sessions carry no `amr` equivalent
  yet: they are provisioned but cannot elevate (no local TOTP to check either;
  SAML-MFA is a future workstream).
  A seeded-but-stale proof still falls through to the **same**
  `elevation_step_up` freshness gate every other session goes through — never
  a silent grant. The granted audit row records which factor source was used:
  `role.elevation.granted` detail is `duration_secs=<n> mfa=<oidc_amr|local_totp>
  expires_at=<rfc3339> justification=<text>` — `duration_secs` is the TRUE
  post-clamp window (follow-up B), and BOTH machine-parsed tokens (`mfa=` and
  `expires_at=`) are placed **before** the free-text `justification=` field
  (hardening-round consistency S-3) so a crafted justification containing a
  forged `mfa=...`/`expires_at=...` token can never be mistaken for the
  genuine, code-emitted values by a first-match grep.
  Toggle: **`--jit-oidc-amr-elevation`** (`YUZU_JIT_OIDC_AMR_ELEVATION`,
  default **true**; `--no-jit-oidc-amr-elevation` to disable). Disabling it
  means **OIDC sessions cannot use JIT elevation at all** — an operator must
  elevate from a local-authenticated session with local TOTP instead. This is
  NOT "OIDC sessions fall back to requiring local TOTP": an OIDC session has
  no way to present a local TOTP step-up (its step-up challenge is re-SSO, not
  a TOTP code), so the toggle-off denial is unconditional for that identity
  source, with its own distinct audited reason from the no-amr-assertion case.
  A one-time INFO log line is emitted at boot when OIDC is configured and the
  toggle is on, so an incident responder can discover the posture without
  reading source or an individual audit row.
- **`--mfa-step-up-window-secs` governs the OIDC-elevation proof-freshness
  bound too.** The elevate route's shared `elevation_step_up` gate (which
  every session — local and OIDC — must additionally clear after the
  unconditional enrolled/amr checks above) floors its window to
  `cfg.mfa_step_up_window_secs` (default 300 s; floored to 300 s even if the
  operator has globally disabled step-up via `<= 0`, so the privilege
  boundary always requires a fresh proof). For an OIDC session this is the
  same `Session::mfa_verified_at` freshness check the local branch uses —
  there is no separate OIDC-specific timer; an operator narrows the window
  operator-wide with the one flag.
- **Incident response for a compromised SSO operator (no reaper/SCIM yet —
  #1859, tracked).** Until a deprovisioning sweep ships, stopping a
  compromised SSO operator's privileged access is two manual levers, both
  immediate: (1) `POST /api/v1/users/{principal}/elevation-eligibility
  {"eligible":false}` — stops future JIT elevation and drops any
  currently-active elevation window (`AuthManager::revoke_user_elevations`);
  (2) `DELETE /api/v1/sessions?username=<principal>` — force-logs-out the
  operator's current cookie session(s). Neither lever deactivates the
  `auth.db` row itself or stops the IdP from minting the operator a fresh
  session on next login (that requires IdP-side deprovisioning today); (1)+
  (2) together are the full standing-access kill switch available in this
  slice. #1859 will add a durable-side deactivation/reaper so a stale IdP
  removal ages the row out even without an admin doing this manually.
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

## RBAC group provisioning (#1832)

Every OIDC `/auth/callback` login reconciles the IdP's `groups` claim into the
RBAC store (`RbacStore::reconcile_idp_memberships`), so group-scoped role
assignments made against an IdP-sourced group stay in sync with the IdP's
current membership. Mirrors the break-glass metric/audit treatment above.

- **Namespacing (confused-deputy fix).** Every IdP-asserted group is written
  as `<source>:<group-id>` (`entra:8f3c...`, via `namespaced_group_name`) —
  never the raw IdP id. A locally-created RBAC group can therefore never
  collide with (or be impersonated by) a same-named IdP group; `create_group`
  additionally rejects a `source='local'` create whose name starts with a
  reserved IdP prefix (`local:`/`entra:`/`saml:`/`ad:`, derived from the same
  list of recognized IdP sources `reconcile_idp_memberships` accepts — adding
  a future IdP there automatically reserves its prefix too).
- **Reconcile, not append-only (deprovisioning fix).** The transaction upserts
  every asserted `{external_id, display}` AND deletes any of the user's
  memberships in a `source`-owned group that was NOT re-asserted this login —
  scoped to `groups.source = ?`, so it is structurally incapable of touching a
  `source='local'` membership. An empty asserted set (the IdP now reports zero
  groups) removes ALL of the user's `source`-owned memberships — full
  deprovisioning takes effect on the user's next SSO login (residual: a live
  session/token retains its prior roles until re-authentication, tracked in
  #1836 — see the session-revocation REST surface above for the manual
  interim mitigation).
- **Source-verify guard.** Before joining a membership to a namespaced group
  row, the reconcile checks that row's `source` column matches the call's
  `source`. A pre-existing row of a DIFFERENT source occupying the same
  namespaced name (e.g. a local group literally named `entra:<gid>`, created
  before the `create_group` reserved-prefix guard existed) is never joined —
  closes a residual confused-deputy path the namespacing alone doesn't cover
  on an upgraded deployment carrying pre-guard data.
- **Group-overage skip (UP-1).** Entra omits the `groups` claim entirely
  (replacing it with a `_claim_names`/`_claim_sources` indirection pointer)
  once a user belongs to more groups than fit in the token. Treating the
  resulting empty claim as "zero groups" would delete every one of the user's
  existing memberships on that login — a silent mass-deprovision of a
  legitimate, heavily-grouped user. `OidcProvider::parse_id_token` sets
  `groups_claim_present`/`groups_overage` on `IdTokenClaims`; the free
  function `groups_claim_reconcilable(claims)` (mirrors `amr_asserts_mfa`,
  unit-testable without a live route) gates whether `/auth/callback` calls
  the reconcile at all. When it doesn't, existing memberships are left
  untouched and the login still proceeds — fail-OPEN on membership, never on
  authentication.
- **Cap + input validation (fail-closed on abuse, fail-soft on garbage).** An
  assertion of more than `RbacStore::kMaxIdpGroupsPerLogin` (200) groups
  denies the login outright (no session minted) before any mutation — defends
  against a compromised/misconfigured IdP turning one login into an unbounded
  write storm. Within the cap, an individual asserted entry with a blank or
  implausibly long (`>512` byte) `external_id` is silently dropped rather than
  seeding a garbage group.
- **Source contract.** `reconcile_idp_memberships` rejects `source == "local"`
  or an empty source outright (`unexpected`, no mutation) — the
  stale-membership DELETE's `source`-scoping is safe only for a real IdP
  source; a miswired call passing `"local"` would mass-delete every local
  group membership fleet-wide.
- **Fail-closed on the login.** An over-cap assertion or a reconcile-store
  failure (e.g. a locked/corrupt `rbac.db`) denies the login outright before a
  session is minted — a heavily-loaded or unhealthy `rbac.db` degrades
  availability (SSO logins fail) rather than integrity (a session with
  stale/unreconciled roles). The break-glass/local-password escape hatch
  (`/login`, hardened-mode) is unaffected — it never calls `/auth/callback`
  and so never touches group reconciliation.
- **Audit + metrics.** `auth.sso_group_provision` (`result=ok|skipped|error`)
  — `ok` only when the reconcile actually changed something
  (`detail=source=entra;added=N;removed=M`, `added+removed>0`; a no-op login
  writes no row), `skipped` for the group-overage/absent-claim case
  (`detail=reason=groups_overage|groups_absent;source=entra`), `error` for a
  denied login (`detail=reason=<cause>;source=entra`). An `error` result also
  emits the shared `auth.oidc_login_failed` audit row + analytics event (the
  same ones the token-exchange-failure branch emits) so a SIEM query counting
  failed OIDC logins by that action doesn't miss a provisioning-denied one.
  Metric: `yuzu_auth_sso_group_provision_total{source, result}` (same
  `result` vocabulary). See `docs/user-manual/audit-log.md`.

Implementation: `RbacStore::reconcile_idp_memberships` /
`namespaced_group_name` (`rbac_store.{hpp,cpp}`); the callback gate in
`auth_routes.cpp` `/auth/callback`; the claim parsing + gating decision in
`oidc_provider.{hpp,cpp}` (`IdTokenClaims::groups_claim_present` /
`groups_overage`, `groups_claim_reconcilable`). Tests:
`tests/unit/server/test_rbac_store.cpp`, `test_oidc_provider.cpp`. SAML group
sync is out of scope here (dropped in #1827; will ride this same reconcile
path once #1826 merges).

## Stable principal vs. display name (#1837)

`Session` carries two separate identity fields with different jobs:

- **`username`** — the STABLE authorization principal. `check_permission`,
  `reconcile_idp_memberships`, elevation eligibility, and every audit
  `principal` field key on this value. It must be immutable for the
  lifetime of the identity it represents.
- **`display_name`** — a human-readable label for UI/audit-DETAIL
  rendering ONLY. Never consulted for authorization; safe to change on
  every login.

**Why this split exists.** Before #1837, `create_oidc_session` keyed
`username` on `claims.name` (falling back to `claims.email`) — an
IdP-editable, non-unique display label. Two different SSO users who
happened to share a display name (a common collision in orgs with
duplicate names, or after a legal name change re-used an old name)
collided onto ONE authorization principal. Once #1832 shipped
`reconcile_idp_memberships` — which deletes a principal's un-reasserted
IdP-sourced group memberships on every login — that collision became
destructive: user B's login could silently delete user A's group
memberships (and, in the group-membership window between the two
logins, inherit A's roles).

**The fix.** OIDC sessions now key `username` on:

```
"oidc:" + iss + "#" + sub
```

`sub` (the OIDC subject claim) is only guaranteed unique **per issuer**
(RFC 7519) — a bare `sub` from two different IdPs (or two tenants of the
same IdP product) could theoretically collide, so `iss` (the token
issuer) scopes it. This is an OPAQUE id — never render it as a human
name. `display_name` is set to `claims.name` (falling back to
`claims.email`), exactly as `username` used to be computed, and is
free to change on every login without touching the stable principal or
the RBAC memberships/roles bound to it.

`sub` is now authorization-load-bearing (it is half of the RBAC
principal), so `OidcProvider::validate_claims` — the same chokepoint that
already rejects `iss`/`aud`/`exp`/`nonce` mismatches — also rejects a
token whose `sub` is empty, contains a control character (byte `< 0x20`
or `== 0x7F`, including CR/LF/tab), or exceeds 255 bytes, and rejects an
empty `iss` defensively. Without this, an IdP token that omits `sub`
would collapse every such login onto the single principal `oidc:<iss>#`
(destructive under the #1832 reconcile), and a control/newline byte in
`sub` would corrupt the audit `principal` column. Rejection is
fail-closed — the login is denied (`auth.oidc_login_failed`), no session
minted.

**Recovering a human name without a live session.** There is no
persistent principal→display-name directory. The audit `principal`
column is the authoritative stable id (`oidc:<iss>#<sub>`) for every SSO
audit row; the human name for that same login is carried alongside it in
that row's `detail` field (`display=<sanitized name>;email=<sanitized
email>` — see `/auth/callback`'s `audit_log_for_principal` calls, which
attach this to every SSO audit action: `auth.oidc_login`,
`auth.oidc_login_failed`, `auth.sso_group_provision`). A live session's
`Session::display_name` is the other source, for the currently-signed-in
user only. Rendering a principal for which no session is live and no
audit row is being inspected (e.g. an admin-facing user list keyed on raw
`username` strings) has no name to show today — a durable
principal→display-name directory (persistent, survives restart, joinable
outside an audit row) is tracked as a fast-follow in **issue #1852**. An
earlier revision of this section documented an in-memory
`AuthManager::sso_identities_` resolution map upserted on every
`create_oidc_session` call; it had zero production callers (every render
site used a live session or an audit-row detail instead) and was removed
as dead code in the #1837 governance hardening round.

**Render sites.** `GET /api/me` (the legacy dashboard nav-bar
"who am I", consumed by every page's `nav-user`/`context-user` JS) and
`GET /api/v1/me` both now return `display_name` alongside the stable
`username`; the dashboard JS shows `display_name`, falling back to
`username` for a legacy/local session predating this field.

**SAML is unaffected this slice.** `create_saml_session` still keys
`username` on the raw NameID (`display_name` is set to the same value,
purely for render-site parity) — SAML does not sync to `rbac_store` yet
(dropped in #1827), so the collision this fix closes is dormant there.
Keying SAML on `entity_id#NameID` is a tracked fast-follow, to land
alongside SAML group sync.

**Audit-detail-field injection defense (`sanitize_detail_value`).** Every
IdP-supplied value that reaches an audit `detail` string or an
`emit_event` JSON attribute — `name`/`email`/`sub` (and the derived
`display`) — is untrusted: a hostile or misconfigured IdP, or a
user-editable IdP profile field, controls it. `detail` is a flat
`"k=v;k=v"` string parsed by SIEM tooling, so an unsanitised value could
inject `;`/`=` to forge additional fields or `\r`/`\n`/other control
bytes to inject fake log lines. `detail::sanitize_detail_value`
(`auth_routes.hpp`/`.cpp`) is the single chokepoint that neutralises
this: it replaces `;`, `=`, `\r`, `\n`, and any control byte (incl. DEL)
with `_`, then truncates to 128 bytes on a UTF-8 code-point boundary.
Every `display=`/`email=`/`oidc_sub`/`name` value attached in
`/auth/callback` is run through it before concatenation. **It is
audit-detail-field-injection defense only — it does NOT strip HTML
markup and is not a stored-XSS defense by itself.** A value with no
control bytes (e.g. a display name containing `<script>`) passes through
unchanged; if that value is later rendered into HTML, the render layer's
own escaping (`html_escape`) is what neutralises it. See the docstring on
`detail::sanitize_detail_value` in `auth_routes.hpp` for the full contract.

**Migration.** `RbacStore` schema v3 deletes every `group_members` row
belonging to an IdP-sourced group (`groups.source != 'local'`) on
upgrade — those rows were keyed on the OLD display-name principal and
would otherwise be BOTH orphaned (never re-referenced by the new
stable-keyed principal) AND a resurrected confused-deputy hazard: a
LOCAL user who later takes the old display name as their username would
silently inherit whatever roles the stale row's group grants. The purge
is additive/safe — only `group_members` rows for non-local groups are
removed; `groups`/`roles`/`role_permissions`/local memberships are
untouched, and IdP membership re-populates under the new stable key on
each affected user's next SSO login via `reconcile_idp_memberships`.

**Resolved — durable SSO identity restores OIDC JIT admin elevation
(#1852).** `AuthDB::set_elevation_eligible`/`is_elevation_eligible` key on
`users.username` and were gated through `is_valid_username`, which allows
only alphanumerics plus `. _ -` and explicitly rejects `:` (comment:
"prevent config file format injection"). The stable OIDC principal shape
(`oidc:<iss>#<sub>`) contains both `:` and `#`, so it failed that check
unconditionally — `POST /api/v1/users/{name}/elevation-eligibility` 400'd
before reaching the store, and `is_elevation_eligible(session->username)`
for a live OIDC session returned `InvalidUsername`, treated as
fail-closed/denied by the caller. Widening `is_valid_username`'s charset
alone would not have been sufficient: an OIDC login provisioned **no
`users` row at all** — `elevation_eligible` is a column on `users`, and
there was no row for an SSO principal to set it on. Both halves are now
fixed:

- **Durable identity row.** `/auth/callback` calls
  `AuthManager::provision_sso_identity` immediately after
  `create_oidc_session` mints the session — a new, independent call, not
  folded into `create_oidc_session` itself (that method holds `mu_` for the
  in-memory session map; provisioning does unrelated `auth.db` I/O that must
  not serialize behind it). It forwards to `AuthDB::upsert_sso_identity`
  (auth.db migration v6: `users` gains `identity_source`, `external_iss`,
  `external_sub`, `display_name`, `last_seen_at`, all nullable/defaulted so
  every existing row survives without backfill), which `INSERT ... ON
  CONFLICT(username) DO UPDATE`s a row for the stable principal —
  `password_hash`/`salt_hex` are `''` (never resolvable on the local login
  path — see the constant-time-compare note at the top of this document),
  `role` defaults `'user'` on first insert only. The `ON CONFLICT` refresh
  arm updates **only** `display_name`/`last_seen_at`/`is_active` — it
  deliberately never touches `role` or `elevation_eligible`, so a standing
  admin grant and elevation eligibility survive every re-login. **Fail-soft
  by design:** a provisioning error is logged and the login still succeeds
  (a login must never fail because a secondary bookkeeping write failed);
  the principal simply cannot elevate until a later successful login
  provisions it. IdP-side deprovisioning has no push signal into Yuzu today
  — a removed IdP account's row goes stale, aged by `last_seen_at`; a
  reaper/SCIM-driven sweep of long-unseen SSO rows is a tracked follow-up,
  not built in this slice.
- **`is_valid_principal` at the elevation-cluster target-lookup
  chokepoints.** A strict SUPERSET of `is_valid_username` (any string the
  strict validator accepts is accepted unchanged) that additionally accepts
  a reserved-prefixed (`oidc:`/`saml:`/`ad:`) principal after a narrow
  control-byte/SQL-metacharacter blocklist (rejects `< 0x20`, `0x7F`, `;`,
  `=`, `\`, `'`, `"`, `` ` ``, space; caps at 255 bytes; permits `: # / . _
  - @ ~ % |` — the alphabet a real issuer URL + opaque sub actually need).
  Replaces `is_valid_username` at exactly four call sites, all
  target-lookups on an EXISTING row, never a create path:
  `AuthDB::set_elevation_eligible`, `AuthDB::is_elevation_eligible`, the
  `POST /api/v1/users/{name}/elevation-eligibility` target parameter, and
  `DELETE /api/v1/sessions?username=`'s target parameter. Every other
  `is_valid_username` call site — local user create (`upsert_user`),
  delete, role-change, `mfa_status`, account-unlock (a lockout-domain
  action; SSO logins never accumulate lockout state, so there is nothing to
  unlock), and all password/lockout sites — is deliberately left untouched.
- **The elevate route's mandatory-MFA gate branches on `auth_source`.**
  See "JIT admin elevation" above for the local-vs-OIDC split and the
  dedicated unconditional amr-proof gate that prevents the restoration from
  accidentally granting elevation to a never-MFA'd SSO login under the
  default `--mfa-enforcement=optional`.
- **Settings → Users surfaces SSO rows.** `AuthDB::list_users` now selects
  `identity_source`; the fragment renders an `SSO` badge and suppresses the
  Remove button for a non-local row (`DELETE
  /api/settings/users/:username` stays on the strict validator, so it would
  always 400 against a `oidc:<iss>#<sub>` target — there is no local-delete
  equivalent for a durable SSO identity; its lifecycle is IdP-driven).
  Revoke-sessions stays available (principal-keyed, per the previous
  bullet).
- **A side effect, not the goal: `users.display_name` is now a durable
  record for a provisioned principal.** The "Recovering a human name
  without a live session" gap described above is *narrowed* by this — a
  future render site could join `users.display_name` by principal instead
  of relying only on a live session or an audit-row `detail` field — but no
  such render site is wired in this slice; that remains a fast-follow.

**Governance hardening round (2026-07-03) — see
`docs/security-reviews/sso-durable-identity-2026-07-03.md` for the full
record.** Four fixes on top of the base restoration above:

- **Source-scope guard on the eligibility grant.** `is_elevation_eligible`
  keys on the raw principal string alone, which is a landmine: a crafted SAML
  NameID equal to a provisioned OIDC principal, or a legacy
  `identity_source='local'` row that happens to be named `oidc:<iss>#<sub>`
  with `elevation_eligible=1`, would otherwise let a session borrow a grant
  never made against its own identity source. The elevate handler now fetches
  the target row's `identity_source` (`AuthDB::get_user`, which selects it)
  immediately after the eligibility check and requires it EQUAL the session's
  `auth_source` — a direct mapping (`local`↔`local`, `oidc`↔`oidc`,
  `saml`↔`saml`), not "oidc-or-else-local" — denying with
  `role.elevation.denied` / `detail=identity-source mismatch` otherwise.
- **`upsert_sso_identity` no longer resurrects a deactivated row.** The
  `ON CONFLICT` refresh arm dropped `is_active = 1` from its `SET` clause — a
  re-login against a row a future deprovisioning sweep (#1859) had
  soft-deleted no longer silently reactivates it.
- **`AuthDB::invalidate_all_sessions` moved to `is_valid_principal`.** Force-
  logging-out an SSO principal via `DELETE /api/v1/sessions?username=`
  previously hit `InvalidUsername` at this inner call even though the REST
  layer had already accepted the principal — corrupting the audit trail with
  `result="partial"`/`db_error=true` for an action that fully succeeded (OIDC
  sessions are never persisted to `sessions`, so 0 matched rows IS success).
- **Settings → Users "Revoke sessions" URL-encodes the principal.** The
  button previously built its `hx-delete` URL with `html_escape` alone, which
  does not touch `#` — a durable SSO principal's `#` was silently truncated
  by the browser's URL-fragment parsing before the request left the client.

SAML is unaffected by this restoration: `create_saml_session` still keys
`username` on the raw NameID (no reserved-prefix stable principal — see
"SAML is unaffected this slice" above), so `is_valid_principal` does not
recognise it as an SSO principal and `provision_sso_identity` is not called
from the SAML ACS handler. A SAML session is therefore provisioned nowhere
and cannot elevate — not because of a missing MFA proof specifically, but
because there is no durable identity row to hold `elevation_eligible` on in
the first place. Keying SAML on `entity_id#NameID` (the tracked fast-follow
noted above) is a prerequisite for extending this restoration to SAML.

**This is not a regression of a previously-supported flow.** Before #1837,
`Session::username` for an OIDC session was the mutable display name
(`claims.name`, falling back to `claims.email`), and `is_elevation_eligible`
looked that string up directly in `users.username`. Elevation for an SSO
operator therefore only ever "worked" by accident, and only when **both**
of two coincidences held: the IdP-asserted display name had to consist
solely of `is_valid_username`'s narrow charset (no space, no `@` — so most
real display names/emails already failed this silently), **and** it had to
exactly match an existing *local* `users.username`. When both held, the SSO
login's principal silently **borrowed that local principal's
`elevation_eligible` flag and `mfa_totp_secret` enrollment** — a latent
cross-principal grant with zero cryptographic binding between the SSO
identity and the local account it happened to name-collide with: anyone
the IdP would authenticate under that same display name inherited that
local account's admin-elevation path. #1837 severs this borrowing as a
direct, correct consequence of closing the display-name collision it rode
on (see above) — it is closing an unsafe accident, not breaking a supported
capability. #1852 is the deliberate, durable restoration.

**Session-revocation-by-username is a narrower, structurally different
gap.** The operationally-critical kill step
(`AuthManager::invalidate_user_sessions`'s in-memory sweep, keyed by plain
string equality over `sessions_`) carries no `is_valid_username` gate and
revokes any principal string, `oidc:<iss>#<sub>` included — there is no
missing-row problem here, unlike elevation. `DELETE
/api/v1/sessions?username=`'s own query-parameter check does still run
`is_valid_username` at the REST layer, so an admin typing the literal
`oidc:<iss>#<sub>` string still gets a 400 today from that endpoint — but
that charset-only validator predates #1837 and would already have rejected
most OIDC display-name-keyed usernames (spaces, `@`) before this change
too, so this is a narrow, pre-existing, easily-widened validator gap, not a
new #1837 regression and not gated on #1852. Separately, the
`auth.db`-persisted half of revocation
(`AuthDB::invalidate_all_sessions`'s `DELETE FROM sessions`, surfaced as
`db_persisted=false` for an SSO target) was **already** a no-op for OIDC
before #1837 too: `AuthDB::create_session` is never called for an OIDC
login — SSO sessions have always been in-memory-only and were never
written to `auth.db`'s `sessions` table in the first place.

Implementation: `Session::username`/`display_name`
(`auth.hpp`), `AuthManager::create_oidc_session` (`auth.cpp`), the
stable-id construction and per-audit-row `display=`/`email=` detail
attachment in `auth_routes.cpp` `/auth/callback`, `RbacStore` migration
v3 (`rbac_store.cpp`). Tests: `tests/unit/server/test_oidc_principal_key.cpp`.

## SAML 2.0 SP

`/auth-and-authz` skill gap matrix P1 #6. Thin first slice: SP-initiated login
against a single, statically-pinned IdP. Mirrors the OIDC SSO session seam
(same cookie / `auth_source` / RBAC funnel) but uses the SAML 2.0 protocol.
**Linux and macOS only — SAML is unsupported on Windows builds and fails closed
there** (a Windows server logs an error at startup and does not enable SAML
regardless of flag values).

### Configuration

SAML is enabled only when **all five** required flags below are set; supplying
any subset produces a startup warning (naming the missing flag) and SAML is
disabled (fail-closed). All five are validated at startup as one unit — a
partial configuration never yields a "SAML SP initialized" log. The two
group→role flags are optional and independent of the enable gate (see Group→role
mapping below).

| Flag | Env var | Description |
|---|---|---|
| `--saml-idp-entity-id` | `YUZU_SAML_IDP_ENTITY_ID` | Entity ID URI of the IdP (e.g. `https://idp.example.com/saml`) |
| `--saml-idp-sso-url` | `YUZU_SAML_IDP_SSO_URL` | IdP's HTTP-Redirect SSO endpoint URL |
| `--saml-idp-cert` | `YUZU_SAML_IDP_CERT` | Filesystem path to the IdP's signing certificate (PEM) |
| `--saml-sp-entity-id` | `YUZU_SAML_SP_ENTITY_ID` | Entity ID URI the SP advertises to the IdP |
| `--saml-sp-acs-url` | `YUZU_SAML_SP_ACS_URL` | Full URL of this server's Assertion Consumer Service (`POST /saml/acs`) |
| `--saml-group-attribute` *(optional)* | `YUZU_SAML_GROUP_ATTRIBUTE` | `<Attribute Name="...">` in the assertion's `<AttributeStatement>` whose `<AttributeValue>`s are group identifiers (e.g. Entra's `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups`) |
| `--saml-admin-group` *(optional)* | `YUZU_SAML_ADMIN_GROUP` | Group value (from `--saml-group-attribute`) that grants `role=admin` |

Example startup:

```bash
./yuzu-server \
  --https-cert         /etc/yuzu/server.crt \
  --https-key          /etc/yuzu/server.key \
  --saml-idp-entity-id "https://idp.example.com/saml" \
  --saml-idp-sso-url   "https://idp.example.com/saml/sso" \
  --saml-idp-cert      /etc/yuzu/idp-signing.pem \
  --saml-sp-entity-id  "https://yuzu.example.com" \
  --saml-sp-acs-url    "https://yuzu.example.com/saml/acs"
```

> **HTTPS is required.** The `__Host-yuzu_saml_bind` browser-binding cookie is
> `Secure`-only; browsers silently drop `Secure` cookies over plain HTTP. If
> `--https-cert`/`--https-key` are not configured, the server logs an error at
> startup and leaves SAML disabled (fail-closed). Do not run SAML over HTTP.

### Login flow

SP-initiated via HTTP-Redirect binding; assertion consumed via HTTP-POST
binding.

1. The operator navigates to `GET /auth/saml/start`. There is no "Sign in with
   SAML" button on the login page in this release — the login-page SSO button
   for SAML is a deferred item (see Deferred items below).
2. The server builds a `<samlp:AuthnRequest>` (SP entity ID, ACS URL,
   `ID`=random, `IssueInstant`, `ForceAuthn=false`) and redirects the browser
   to the IdP's SSO URL via HTTP-Redirect binding (deflate-compressed,
   URL-encoded `SAMLRequest` query parameter). **AuthnRequest signing is not
   implemented in this slice** — the request is unsigned.
3. The user authenticates at the IdP.
4. The IdP POSTs a `<samlp:Response>` containing a signed `<saml:Assertion>`
   to the ACS endpoint (`POST /saml/acs`).
5. The server validates the response (see Security posture below) and, on
   success, mints an ephemeral session cookie.

```
Browser           Yuzu Server               IdP
  |                    |                          |
  |-- GET /auth/saml/start -->                    |
  |                    |-- 302 SAMLRequest? ---->|
  |                    |                          |
  |                    |      (user authenticates)|
  |                    |                          |
  |                    |<--- POST /saml/acs ------|
  |<-- Set-Cookie -----|                          |
```

### Session

The minted session is **in-memory and ephemeral** (lost on server restart,
identical lifetime to OIDC sessions — 8-hour absolute, subject to
`--session-inactivity-secs`). Session fields:

- `auth_source = "saml"`
- `role = admin` when `--saml-admin-group` is configured and the assertion's
  IdP-attested groups (see Group→role mapping below) contain it, `role = user`
  otherwise — including every login when the two group→role flags are unset
  (the unconfigured default). JIT elevation is non-functional for SAML users
  regardless of role: the elevation endpoint checks `is_elevation_eligible` and
  `mfa_status` in `auth.db`, and SAML users have no row in the local `users`
  table — both lookups fail-closed and the elevation is denied. A SAML admin
  therefore gets `role=admin` permissions immediately at login, not via
  elevation.

### Group→role mapping

SAML admin access is available via IdP-attested group membership, mirroring
the OIDC `--oidc-admin-group` mechanism:

- `--saml-group-attribute` names the `<Attribute Name="...">` element inside
  the assertion's `<AttributeStatement>` whose `<AttributeValue>` children are
  read as group identifiers.
- `--saml-admin-group` is the single group value that grants `role=admin`.
  Matching is **exact string equality only** — no wildcard, prefix, or regex
  matching.
- If either flag is empty (the default), no group is ever eligible for admin
  and every SAML login is `role=user` — identical to the original thin slice.

**Security:** admin is granted **only** from the configured group attribute's
values — **never** from `NameID`, email, or display name, all of which are
attacker-controlled fields that ride in the same assertion (mirrors the C3 fix
in `create_oidc_session`). Group values are parsed from the **same
XSW-verified assertion node** that `NameID` is read from — never a second,
unverified document-wide search — so a signature-wrapping attack cannot inject
groups the IdP didn't attest to. Parsing is capped at 64 `<AttributeValue>`
entries (across however many `<Attribute>` elements carry the configured
Name) as a DoS guard; values beyond the cap are silently ignored rather than
rejecting the assertion.

Because role is computed fresh at every session mint (no persisted mapping),
there is no schema or migration involved, and changing `--saml-admin-group`
takes effect on the next login after a server restart (see Rotating the IdP
signing certificate below for the general "no hot-reload" caveat that also
applies to these two flags).

### Audit actions

| Action | Result | When |
|---|---|---|
| `auth.saml_login` | `ok` | ACS validation passed; session minted |
| `auth.saml_login_failed` | `error` | ACS validation failed (signature, audience, expiry, replay, etc.) |

### Security posture

- **Assertion signature verified against the pinned IdP cert only.** The cert
  at `--saml-idp-cert` is the sole trusted signing authority. In-document
  `<KeyInfo>` values are ignored — the IdP cannot nominate its own trust
  anchor.
- **XML signature-wrapping (XSW) defended.** The server locates the signed
  element by `ID` attribute and verifies that the element under the
  `<Signature>` is the one that was actually consumed, preventing a wrapped
  unsigned sibling from being treated as validated.
- **Audience validated.** The `<saml:AudienceRestriction>` must include
  `--saml-sp-entity-id`.
- **Recipient validated.** The `<saml:SubjectConfirmationData Recipient>` must
  equal `--saml-sp-acs-url`.
- **Expiry validated.** `NotOnOrAfter` on `<saml:Conditions>` and
  `<saml:SubjectConfirmationData>` are enforced.
- **Solicited-only + single-use `InResponseTo` (replay-protected).** The
  server generates a random `ID` for each `AuthnRequest`, stores it in memory,
  and requires the `<samlp:Response>` `InResponseTo` to match exactly. The ID
  is consumed on first use; a replayed response is rejected.

### MFA enforcement with SAML

**MFA step-up is not supported for SAML sessions in this release.** A SAML
session hitting any of the 11 step-up-gated endpoints (token mint/revoke,
session revoke, Guardian rule write, software deploy, user delete/role change)
receives a `403` with `"MFA step-up is not available for SAML sessions in this
release"` — regardless of `--mfa-enforcement` mode. The gate (`require_mfa_step_up`
in `mfa_step_up.cpp`) exits with an honest denial before reaching the local
`mfa_status` lookup, which would fail anyway (SAML users have no local `users`
row). This means:

- `--mfa-enforcement=required` — SAML users are denied at every step-up gate.
- `--mfa-enforcement=admin-only` — the SAML-specific early exit fires on
  `auth_source == "saml"` before role is even consulted, so this applies
  equally to a `role=user` SAML session and a `role=admin` SAML session minted
  via group→role mapping (see Group→role mapping above) — both are denied.
- `--mfa-enforcement=optional` — same: the SAML-specific exit fires before
  enforcement mode is consulted.

**Recommendation:** Use `--mfa-enforcement=optional` or `--mfa-enforcement=admin-only`
when SAML is in use, and configure your IdP to enforce MFA at login time. Avoid
`required` unless you are prepared for SAML users to be denied at all step-up
gates. The recommended pattern for a SAML deployment is `optional` with IdP-side
MFA enforcement.

### `--auth-mode=sso-only` is OIDC-only in this release

`--auth-mode=sso-only` requires OIDC configuration (`--oidc-issuer` +
`--oidc-client-id`); a SAML-only deployment cannot disable local-password login
in this release. The boot guard explicitly requires OIDC — SAML configuration
alone does not satisfy it and the server refuses to start.

### HA / multi-replica

Pending `AuthnRequest` state (the random `ID` stored for replay protection) is
kept in process memory. In a multi-replica deployment, load-balancer **sticky
sessions (session affinity)** must be configured on `GET /auth/saml/start` and
`POST /saml/acs` so the ACS POST for a given request is always routed to the
replica that generated it. Without affinity, approximately `(N−1)/N` of logins
fail as "unsolicited" (no matching pending ID). OIDC shares this limitation via
its in-process PKCE state.

### Rotating the IdP signing certificate

Update `--saml-idp-cert` and **restart the server** — there is no hot-reload
for the IdP cert in this release.

### Deferred items (not in this slice)

- **Login-page SSO button.** There is no "Sign in with SAML" button on the
  login page; users must navigate directly to `GET /auth/saml/start`.
- **AuthnRequest signing.** The SP does not sign its `<samlp:AuthnRequest>`; the
  IdP must be configured to accept unsigned requests. If the IdP requires signed
  AuthnRequests, use OIDC.
- **`--auth-mode=sso-only` for SAML.** A SAML-only deployment cannot disable
  local-password login. Compliance impact: CC6.3 (local-password fallback
  remains active). OIDC is the path to `sso-only`.
- **AttributeStatement parsing beyond the group attribute.** Only the single
  configured `--saml-group-attribute` is read for group→role mapping; no other
  assertion attributes are stored or surfaced.
- **SP metadata endpoint.** No `GET /saml/metadata` endpoint is provided; IdP
  registration uses the manual flag values.
- **Windows support.** SAML depends on an XML processing library whose Windows
  build is not yet wired in the vcpkg manifest. The server detects Windows at
  startup, logs an error, and does not enable the SAML routes.
- **IdP-metadata auto-fetch.** The IdP cert and SSO URL are supplied statically
  via flags; SAML metadata XML auto-discovery is not implemented.
- **Settings-UI runtime reconfigure.** SAML can only be configured via CLI
  flags or environment variables; there is no dashboard panel for it in this
  slice. A server restart is required to change the configuration.

## SCIM v2 provisioning (SOC 2 CC6.2/CC6.7/CC6.8)

`/auth-and-authz` skill gap matrix P1 #7. RFC 7643 (Core Schema) / RFC 7644
(Protocol) — lets an enterprise IdP (Okta/Entra/OneLogin) auto-provision and
auto-deprovision Yuzu operators via its SCIM connector, rather than an admin
managing accounts by hand. Slice 1 (Users) shipped every SCIM-provisioned
account at the fixed, floor-privilege `user` role; slice 2 (this section's
"Groups → role mapping" below, issue #2021, SOC 2 **CC6.7**) lets an IdP grant
`role=admin` to members of a configured admin group.

### Configuration (fail-closed)

| Flag | Env var | Description |
|---|---|---|
| `--scim-enable` | `YUZU_SCIM_ENABLE` | Enable the `/scim/v2/*` route surface. Default `false` — SCIM is entirely inert when disabled (no routes registered, no boot-log line). |
| `--scim-token` | `YUZU_SCIM_TOKEN` | The bearer credential the IdP's SCIM connector authenticates with. Secret — treat like a password. |
| `--scim-admin-group` | `YUZU_SCIM_ADMIN_GROUP` | `displayName` of the SCIM group whose members are granted `role=admin`. Default empty — no SCIM group grants admin; every SCIM-provisioned user stays `role=user`. The value is whitespace-trimmed at load. Mirrors `--saml-admin-group`. **Requires a server restart to take effect** — there is no Settings-UI/live-reload path; renaming the group's `displayName` in the IdP likewise requires updating this flag and restarting. |

**Prefer `YUZU_SCIM_TOKEN` over `--scim-token`.** A value passed on argv is
visible to any local user via `ps`/`/proc/<pid>/cmdline`; the environment
variable does not appear there. `YUZU_SCIM_TOKEN` is the recommended
delivery method — the flag remains supported for parity with the other
`--scim-*` options and local/manual testing.

Two fail-closed startup guards, both refusing to start (`EXIT_FAILURE`):

- **`--scim-enable` without `--scim-token`.** There is no way to gate the
  surface without a credential, so the server does not boot rather than
  expose an unauthenticated provisioning API.
- **`--scim-enable` together with `--no-https`.** The bearer token is a
  long-lived, high-privilege credential (it can create/delete operator
  accounts); it must never cross the wire in plaintext. This mirrors the
  `--auth-mode=sso-only` boot posture — a security-relevant flag combination
  is rejected at boot, not silently degraded.

The active SCIM posture (enabled/disabled, and — if enabled — that a token is
configured) is logged **once at boot** as CC6.2 evidence, the same pattern as
the `sso-only` boot-posture banner.

### Auth

Every `/scim/v2/*` route — **including the discovery endpoints** — requires
`Authorization: Bearer <token>`, validated **constant-time** (`CRYPTO_memcmp`)
against the SHA-256 hash stored at `--scim-enable` time (mirrors
`ApiTokenStore`'s token-hashing pattern). A missing, malformed, or invalid
token is a `401` + `WWW-Authenticate: Bearer` — the same envelope regardless
of *why* it failed (no oracle distinguishing "wrong token" from "no token
configured"). SCIM tokens are their **own credential type**, entirely
distinct from operator API tokens and session cookies — there is no cookie,
no session, no shared token store. Every authenticated SCIM request maps to
a fixed `scim-service` audit principal (there is no notion of "which
operator" made a SCIM call; it is the IdP connector, always).

### Endpoints

All responses (and the accepted PATCH/PUT bodies) use
`Content-Type: application/scim+json`.

`ServiceProviderConfig` advertises **`etag.supported: false`** — there is no
conditional-write enforcement (`If-Match`/`If-None-Match` are not honored);
the `ETag`/`meta.version` a client sees back is informational only, not a
concurrency-control token.

| Endpoint | Purpose |
|---|---|
| `GET /scim/v2/ServiceProviderConfig` | Discovery — capability document |
| `GET /scim/v2/ResourceTypes` | Discovery — describes the User and Group resource types |
| `GET /scim/v2/Schemas` | Discovery — the core User and Group schemas |
| `POST /scim/v2/Users` | Provision a new user |
| `GET /scim/v2/Users/{id}` | Read a single user (`404` if unknown) |
| `GET /scim/v2/Users?filter=userName eq "x"&startIndex=&count=` | Existence check + pagination (SCIM `ListResponse`) |
| `PUT /scim/v2/Users/{id}` | Replace (`externalId`, `active`) |
| `PATCH /scim/v2/Users/{id}` | Primary lifecycle path — deactivate / reactivate |
| `DELETE /scim/v2/Users/{id}` | Deprovision |
| `POST /scim/v2/Groups` | Create a group (`displayName`, optional `members[]`) |
| `GET /scim/v2/Groups/{id}` | Read a single group |
| `GET /scim/v2/Groups?filter=displayName eq "x"&startIndex=&count=` | List groups (SCIM `ListResponse`, pagination) |
| `PUT /scim/v2/Groups/{id}` | Replace a group |
| `PATCH /scim/v2/Groups/{id}` | Add/remove members (RFC 7644 §3.5.2 PatchOp on `members`) |
| `DELETE /scim/v2/Groups/{id}` | Delete a group |

`Group` is now advertised alongside `User` in `/scim/v2/ResourceTypes` and
`/scim/v2/Schemas` (schema urn `urn:ietf:params:scim:schemas:core:2.0:Group`).

### Provisioning model

`POST /scim/v2/Users` creates the account with a discarded
CSPRNG-generated password — a SCIM-provisioned user never authenticates
with a local password; they sign in via the IdP/SSO. Role defaults to
`user` and is recomputed immediately against the current
`--scim-admin-group` membership (see Groups → role mapping below) — so a
user who already appears in the admin group's `members[]` at the moment
they are provisioned is created `role=admin`, not `user`-then-promoted. A
duplicate `userName` is rejected `409` (`scim_type=uniqueness`) rather than
silently upserting. Success is `201` + `Location` (the resource's canonical
URL) + `ETag` (the resource's `etag_version`, bumped on every mutation).

**Reprovisioning a returning employee works.** If the `userName` collision is
against an existing SCIM-provisioned account that is currently **deactivated**,
`POST` revives that account rather than rejecting `409` — this is the
"left, then rejoined" case an IdP connector replays automatically when a
person is re-added and re-assigned the app. The `409 uniqueness` rejection is
reserved for a `userName` collision against a **currently-active** account.

### `userName` charset — must be a slug, not an email address

Yuzu account usernames are slug-shaped: alphanumeric plus `.`, `_`, `-`
only — **no `@`**. Stock Okta/Entra provisioning defaults `userName` to the
user's email address, which contains `@` and is rejected `400` at
`POST /scim/v2/Users` (and at any subsequent identity-touching `PUT`/`PATCH`).
**Operators must remap `userName` to a non-email slug attribute** in the
IdP's provisioning/attribute-mapping configuration before assigning any
users — the `400` response carries an error-message hint calling out the
rejected character(s) to speed up this diagnosis. Native support for an
email-shaped `userName` (deriving a slug server-side) is a planned follow-up
— see Deferred below.

`GET .../Users?filter=userName eq "x"` is the connector's standard
existence-check-before-create call. **Only the `userName eq "..."` filter is
supported** (attribute + operator case-insensitive, value double-quoted);
any other attribute or operator is rejected `400` (`scim_type=invalidFilter`)
rather than silently ignored or partially matched.

`PUT /scim/v2/Users/{id}` replaces the mutable identity fields (`externalId`,
`active`). A `userName` change is rejected `400`
(`scim_type=mutability`) — **rename is out of scope this slice**; deleting
and re-provisioning is the only supported path for a IdP-side username
change today.

### Deprovision and reactivation

`PATCH /scim/v2/Users/{id}` is the primary lifecycle path (both the pathless
`{"value":{"active":false}}` and explicit `{"path":"active","value":false}`
PatchOp forms are accepted). **`PUT /scim/v2/Users/{id}` triggers the
identical deactivate/reactivate semantics** whenever its body's `active`
value differs from the account's current state — some IdP connectors issue a
full `PUT` rather than a `PATCH` for lifecycle changes, and that path gets
the same audit behavior described below, not a silent no-op:

- **`active:false` deprovisions** — soft-deletes the underlying auth account
  and **cascades session revocation** (an in-flight session for a
  just-terminated employee does not outlive the IdP's deprovisioning call).
- **`active:true` reactivates** — restores the account and **clears any
  stale lockout** (`failed_login_count`/`locked_until`), so a re-hire isn't
  stuck behind a lockout window from before their termination. **MFA is
  NOT restored** — a reactivated user re-enrolls TOTP from scratch on next
  login, the same posture as any other de-enrolled account; SCIM never
  resurrects a stale second factor.

`DELETE /scim/v2/Users/{id}` is the equivalent one-shot deprovision (`204`),
for IdPs that issue a hard delete rather than a PATCH/PUT-to-inactive.

**All lifecycle audit writes are set-and-proceed; evidence integrity is
enforced by an alert on the failure metric.** Every action (provision,
update, deactivate, reactivate, delete) completes even if its audit write
fails, and each failure unconditionally bumps
`yuzu_scim_audit_write_failures_total`. A fail-closed `500` on a
*termination* audit-write failure was considered and **rejected**: because
the account is already mutated, the IdP's retry re-reads the terminated
post-state, takes the non-termination (no-op / `404`) branch, and never
re-attempts the missing audit — the `500` fails the request without ever
re-landing the evidence row it was meant to guarantee. The correct CC6.8
control is therefore an **alert on `yuzu_scim_audit_write_failures_total`**
(same-day follow-up on a missed termination record); deploy that rule when
you enable SCIM.

### 🔴 Provenance guard (the load-bearing security invariant)

**SCIM may only ever mutate accounts that SCIM itself provisioned, and only
while they are still floor-privilege.** Every deactivate / reactivate /
delete / update re-verifies **both**
`provisioning_source == "scim"` (a new `users` column,
`AuthDB::set_provisioning_source`/`get_provisioning_source`, auth.db
migration **v7**) **and** `role == "user"` **immediately before** touching
the auth account — not at lookup time, at the mutation site. Either mismatch
(the target `scim_id` maps to a username whose `provisioning_source` is
`local` or anything else, **or** whose `role` has since been elevated, e.g.
by a dashboard admin promoting a former SCIM user) refuses with **`404`,
never `403`** — a `403` would be an existence oracle (it confirms the
resource exists but is protected); a `404` is indistinguishable from "no
such SCIM resource" — plus a `scim.user.provenance_denied` audit row so the
attempt is still recorded even though the caller sees a plain not-found.

This is the invariant that makes it safe to point a third-party IdP
connector at this endpoint at all: **a locally-created admin account, or the
`--break-glass-user` break-glass account, can never be deactivated by an IdP
push** — even if an attacker who compromises the IdP (or a misconfigured
connector) knows or guesses that account's SCIM-facing `id`. The `role`
half of the check adds a second belt: **an operator-elevated SCIM account is
not SCIM's to tear down** — once a SCIM-provisioned account has been
promoted (e.g. to `admin`) by a human through the dashboard, it drops out of
SCIM's write authority entirely, the same as if it had never been
SCIM-provisioned. **The one code path from a SCIM request to `role=admin`
is Groups → role mapping (below), and it is bounded by design:** admin is
granted only while the user is a current member of the single group named
by `--scim-admin-group` — there is no other field or code path by which a
SCIM request can set `role=admin`, so a compromised IdP can elevate a SCIM
account only as far as that one configured group, never past it, and (via
this guard) can still never touch a local or already-elevated-and-thus-
out-of-scope account, whether that account was always local or was
originally SCIM-provisioned and later promoted.

### Groups → role mapping (SOC 2 CC6.7, issue #2021)

`/scim/v2/Groups` lets an IdP push SCIM Group resources
(`POST`/`GET`/`PUT`/`PATCH`/`DELETE`, list with `startIndex`/`count`
pagination and an optional `filter=displayName eq "..."`; `PATCH` follows
RFC 7644 §3.5.2 PatchOp semantics on the `members` path). `Group` is
advertised alongside `User` in `/scim/v2/ResourceTypes` and
`/scim/v2/Schemas` (schema urn
`urn:ietf:params:scim:schemas:core:2.0:Group`).

**Role resolution reuses the existing machinery, not a parallel
implementation.** Because the `auth.db` role model is binary (`admin` |
`user`), granting admin via group membership is a parity check, not a
richer mapping: a SCIM-provisioned user is `role=admin` **iff** they are
currently a member of the group whose `displayName` equals
`--scim-admin-group` (`YUZU_SCIM_ADMIN_GROUP`, default empty — no SCIM
group grants admin). This calls the same `resolve_role_from_groups`
(`server/core/include/yuzu/server/auth.hpp`) helper SAML (#1826) and OIDC
already use for their own `--saml-admin-group`/`--oidc-admin-group`
mapping — one role-resolution function, three callers, not three
divergent implementations. Role is recomputed (never left stale) at every
point membership could have changed: on user creation, and on any Group
`POST`/`PUT`/`PATCH`/`DELETE` that could add or remove a user from the
admin group. Removing a user from the admin group demotes them back to
`user` on the next recomputation — there is no separate "apply pending
role change" step.

**The provenance guard is preserved, not bypassed, for group-driven role
changes.** A role recomputation triggered by a Group mutation only ever
writes to accounts with `provisioning_source == "scim"` — exactly the same
guard that already protects deactivate/reactivate/delete (see Provenance
guard above). If a Group's `members[]` includes the SCIM `id` of a
non-SCIM account (a locally-created admin, or the `--break-glass-user`
account), that member is silently skipped for role purposes — never
role-changed. A compromised or misconfigured IdP therefore cannot use
Group push to elevate, demote, or otherwise touch a local principal, even
by naming its SCIM-facing id in a group's membership list.

**`deprovision_role_ok` is a demote-before-delete ordering gate, not a
"manual elevation is protected" guarantee.** `deprovision_role_ok`
(`server/core/src/scim_routes.cpp`) refuses to delete/deactivate any
account whose DB-authoritative role is not `user`, returning `404` (never a
`403` existence oracle) — regardless of *how* that account came to be
non-`user` (a dashboard promotion or Groups → role mapping). Its job is
purely sequencing: SCIM must never be able to deprovision an elevated
account without an explicit, auditable demotion happening first. It is not
a promise that a manually-elevated account stays elevated — see Model A
below for what actually governs durability of a manual role change on a
SCIM account. Because Groups → role mapping can now put a SCIM-provisioned
user at `role=admin` through ordinary group membership (not just a manual
dashboard promotion), **a user who is admin via group membership cannot be
SCIM-deprovisioned until the IdP first removes them from the admin
group** — that removal demotes them back to `user` via the next
`recompute_scim_user_role` call, at which point the next deactivate/delete
call proceeds normally. This was evaluated and accepted rather than
special-cased: standard Okta/Entra offboarding already removes a departing
employee from all group assignments (including any admin group) as part of
unassigning the app, ahead of or alongside deactivating the user, so the
required ordering matches the normal IdP-side offboarding flow rather than
imposing an unusual one. Operator-facing guidance is
`docs/user-manual/scim-provisioning.md` "Deprovisioning order matters for
group-granted admins".

**Model A — IdP group membership is authoritative for a SCIM account's
role.** For any SCIM-provisioned account, `--scim-admin-group` membership,
not a manual dashboard edit, is the durable source of truth for role. A
manual (out-of-band, e.g. dashboard) role change to a SCIM-provisioned
account is **reverted to the group-derived role on the next event that
recomputes that user's membership** — i.e. a Group `POST`/`PUT`/`PATCH`/
`DELETE` that resolves to this user via `recompute_scim_user_role`, or a
`User` reprovision (`POST` reviving a deactivated account) — **not** on a
plain deactivate/delete (`deprovision_role_ok` blocks those against a
non-`user` account outright, so they never reach a recompute), and **not**
on server restart or on changing `--scim-admin-group` itself (both require
a subsequent Group mutation to actually re-evaluate membership — see
Recovery/alerting in `docs/user-manual/scim-provisioning.md`). **Residual
(carried from the Users slice, not new here):** a manually-promoted SCIM
account that is a member of **no** SCIM group is neither reverted by this
mechanism nor SCIM-deprovisionable (`deprovision_role_ok` still blocks it)
until an operator demotes it by hand — there is no membership-recompute
event that would ever touch it, because `recompute_scim_user_role` only
acts on users a Group mutation or reprovision actually resolves to.

**Architectural constraints, by design (not gaps):**

- **`displayName`-keyed, not stable-ID-keyed.** `--scim-admin-group` matches
  against a SCIM Group's mutable, non-unique-at-create `displayName` —
  unlike OIDC's `sub`+`iss` stable-identity keying (#1837), there is no
  IdP-durable group identifier in play here. A `displayName` rename in the
  IdP requires the operator to update `--scim-admin-group` to match and
  restart (see Configuration above) — the mapping does **not** follow a
  renamed group automatically. Group `POST`/`PUT` now reject `409` (create
  on an existing `displayName`, or a `PUT` rename onto one) rather than
  silently permitting a second same-named group, but this only prevents
  *duplicate* names — it does not make `displayName` a stable key.
- **Binary `admin`|`user` only.** `auth.db`'s role model has exactly two
  values; Groups → role mapping cannot express anything finer even if a
  future RBAC expansion introduces more roles — the same constraint SAML
  and OIDC group→role mapping already operate under.
- **Deliberately does not reuse `directory_group_role_mappings`
  (`directory_sync.cpp`).** That table is stable-`group_id`-keyed storage
  built for the AD/Entra directory-sync path and does not apply here: SCIM
  Groups → role mapping resolves live, per-request against
  `--scim-admin-group` via `resolve_role_from_groups`, with no persisted
  mapping row of its own. This was evaluated and rejected rather than
  overlooked — reusing a stable-ID-keyed table for a `displayName`-keyed
  mapping would either force a fabricated stable id onto SCIM Groups or
  quietly change the matching semantics; a dedicated (if narrower)
  resolution path was judged clearer than overloading a table built for a
  different keying model.
- **Bounded Group membership.** Each Group operation enforces a bounded
  maximum on `members[]` size, refusing an unbounded membership push rather
  than accepting an arbitrarily large list in one call.

**Threat model addition: a compromised IdP cannot elevate a local
account.** The provenance guard bounds Groups → role mapping to SCIM's own
accounts (see above); the group-parity design bounds it to exactly one
configured group (see Role resolution above). Combined, a compromised or
malicious IdP connector can grant admin only to accounts it itself
provisioned, only via the single group an operator explicitly configured
as `--scim-admin-group`, and never to a local admin or the break-glass
account regardless of what it puts in a group's membership list. Full
change record: `docs/security-reviews/scim-groups-role-2026-07-13.md`.

### Audit actions

Audit `result` is one of **`success` | `failure` | `denied`** — not
`ok`/`error`. `success` is a completed mutation; `denied` is a guard
refusing an otherwise-well-formed request (409 uniqueness, provenance/role
mismatch, bad bearer token); `failure` is an internal error after the
request was otherwise accepted (e.g. an audit-write or transaction failure
that triggers a `500`).

| Action | Result | When |
|---|---|---|
| `scim.user.provisioned` | `success` | `POST /scim/v2/Users` succeeds (new account, or a revived reprovision) |
| `scim.user.provisioned` | `denied` | `POST` rejected `409` — `userName` collision against a currently-active account |
| `scim.user.provisioned` | `failure` | `POST` rolls back after a `500` (e.g. the account-creation transaction fails) |
| `scim.user.updated` | `success` / `failure` | `PUT /scim/v2/Users/{id}` succeeds / fails `500` |
| `scim.user.deactivated` | `success` / `failure` | `PATCH`/`PUT`/`DELETE` sets the account inactive; `failure` (set-and-proceed) if the audit write could not persist |
| `scim.user.reactivated` | `success` / `failure` | `PATCH` or `PUT` sets `active:true`; `failure` (set-and-proceed) on an audit-write error |
| `scim.user.deleted` | `success` / `failure` | `DELETE /scim/v2/Users/{id}` succeeds / audit-write failure (set-and-proceed) |
| `scim.user.provenance_denied` | `denied` | A deactivate/reactivate/delete/update targets an account whose `provisioning_source != "scim"`, **or** whose current `role != "user"` |
| `scim.auth.denied` | `denied` | Bearer-auth validation fails (missing/malformed/wrong token) on any `/scim/v2/*` route, including discovery |
| `scim.group.created` | `success` / `denied` / `failure` | `POST /scim/v2/Groups` succeeds / rejected `409` — `displayName` collision against an existing group / rolls back `500` |
| `scim.group.updated` | `success` / `denied` / `failure` | `PUT`/`PATCH /scim/v2/Groups/{id}` succeeds / rejected `409` — rename onto an existing `displayName` / fails `500` |
| `scim.group.deleted` | `success` / `failure` | `DELETE /scim/v2/Groups/{id}` succeeds / audit-write failure (set-and-proceed) |
| `scim.user.role_changed` | `success` / `failure` | A user's role is recomputed to a new value (user create, or a Group create/replace/patch/delete affecting admin-group membership); records `old_role`→`new_role`, `reason=group` |

All rows carry `principal = "scim-service"`, `principal_role = "scim-service"`.
`target_type` is `"User"` for the user-lifecycle and `role_changed` rows,
`"Group"` for the group-lifecycle rows.

### Metrics

Prometheus counters (all in the `yuzu_scim_*` namespace):

| Metric | Labels | Meaning |
|---|---|---|
| `yuzu_scim_requests_total` | `op`, `status` | Every `/scim/v2/Users` **and now `/scim/v2/Groups`** request, by operation (`op` = `create`\|`get`\|`list`\|`replace`\|`patch`\|`delete` — the literal wire values `scim_routes.cpp` passes to `record_request`) and outcome bucket (`status` = `2xx`\|`4xx`\|`5xx`). The three discovery documents (`ServiceProviderConfig`/`ResourceTypes`/`Schemas`) are NOT counted here (they carry no lifecycle op) — a rejected bearer against them still surfaces via `yuzu_scim_auth_failures_total`. |
| `yuzu_scim_auth_failures_total` | — | Bearer-auth failures on any `/scim/v2/*` route; pairs with `scim.auth.denied` audit rows. |
| `yuzu_scim_audit_write_failures_total` | — | An audit-log write itself failed. All lifecycle actions (provision, update, deactivate, reactivate, delete, group create/update/delete, role change) are set-and-proceed on this failure mode — the SCIM call still succeeded and the bump is the only record that the evidence row is missing; alert on this counter rather than expecting a `500` (see "All lifecycle audit writes are set-and-proceed" above). |
| `yuzu_scim_provenance_denied_total` | — | Provenance- or role-guard refusals; pairs with `scim.user.provenance_denied` audit rows. |
| `yuzu_scim_role_changes_total` | — | A user's role was recomputed to a new value via Groups → role mapping; pairs with `scim.user.role_changed` audit rows (`success`). |
| `yuzu_scim_role_change_failures_total` | — | `recompute_scim_user_role`'s `AuthManager::update_role` call reported a genuine AuthDB write failure — a role change that was decided but did **not** durably apply; pairs with `scim.user.role_changed` audit rows (`failure`). A sustained non-zero rate means role changes are silently not taking effect — alert on it distinctly from `yuzu_scim_audit_write_failures_total` (that counter covers a lost *evidence row* for an otherwise-successful mutation; this one covers the mutation itself failing). |

### Storage

SCIM's resource-mapping table (`scim_resources` — the IdP-facing `id`/
`externalId` ↔ Yuzu `username` mapping) and its bearer-token table
(`scim_tokens` — sha256 hashes only) live **inside `auth.db`**, under their
own `MigrationRunner` component (`"scim"`, independent of AuthDB's own
`"auth_db"` migration track on the same underlying file) — **not** a new,
separate store. `ScimStore` opens its own `sqlite3` connection to the same
db file `AuthDB` manages. This keeps user identity on one substrate and lets
SCIM's tables ride `auth.db`'s eventual Postgres migration (ADR-0006) rather
than needing a second migration path. Group resources and membership are
new rows under the same `"scim"` `MigrationRunner` component, not a second
store or migration track.

**ADR-0006 exception note.** The 2026-06-22 update to ADR-0006 commits every
server store to Postgres, with no *new* server-side SQLite store absent an
explicit exception. `scim_resources`/`scim_tokens` are a deliberate,
eyes-open exception: they ride the existing `auth.db` SQLite file (their own
`"scim"` `MigrationRunner` component) rather than standing up a new Postgres
store, so identity state — accounts, sessions, provenance, and now SCIM's
id/token mapping — stays on one substrate until `auth.db` itself makes its
Postgres/`SecretCodec` cutover (`docs/postgres-migration-ladder.md` Wave 3,
`auth DB (auth_db.{hpp,cpp})` row). Recorded as a dated ADR-0006 exception bullet in
`docs/postgres-migration-ladder.md` "Notes" — the same place, and in the
same eyes-open-override style, as the existing `NvdDatabase` SQLite
carve-out — rather than a fresh standalone exception ADR.

### Residual risks / deferred (next slice)

- **Crash-window non-atomicity in the two-connection deactivate/reactivate
  path.** `ScimStore` and `AuthDB` open separate `sqlite3` connections onto
  the same `auth.db` file; a deactivate that soft-deletes the auth account
  and revokes sessions is not one atomic transaction across both. A crash
  between the two steps is an **irreducible** window given the two-connection
  design — it is reconciled by the IdP's own periodic re-sync (a deactivated
  user whose session survived the crash gets a follow-up deactivate call on
  the next sync cycle), not by a code-level fix in this slice.
- **No per-route SCIM rate limit.** SCIM calls share the server's global
  rate-limit only — there is no SCIM-specific throttle tuned to expected IdP
  connector call patterns.
- **`userName` is email-incompatible.** Yuzu usernames are slug-shaped
  (alnum, `.`, `_`, `-` — no `@`); a stock Okta/Entra `userName=email`
  mapping 400s. Operators must remap `userName` to a slug attribute (see
  above). Native email-shaped `userName` support is a planned follow-up.
- **Deprovision-ordering constraint on group-granted admins.** A
  SCIM-provisioned user who is `role=admin` via Groups → role mapping cannot
  be SCIM-deprovisioned until the IdP first removes them from the admin
  group (see Groups → role mapping above) — accepted as matching normal IdP
  offboarding order, not tracked as a defect.
- **`userName` rename via `PUT`.** Rejected `400 mutability` this slice;
  delete + re-provision is the only path for a username change.
- **At-rest encryption of the SCIM token.** The token is stored as a sha256
  hash (verify-only, like `ApiTokenStore`), not a reversible encrypted blob —
  there is nothing to decrypt, so this is a lower-urgency follow-up than the
  TOTP-secret case. It rides `auth.db`'s future Postgres/`SecretCodec`
  migration (ADR-0010) alongside the TOTP-secret-at-rest follow-up, should a
  reversible form ever be needed.

Implementation: `server/core/include/yuzu/server/scim_store.hpp` +
`server/core/src/scim_store.cpp` (storage layer), `server/core/include/yuzu/
server/scim_json.hpp` + `server/core/src/scim_json.cpp` (JSON codec +
discovery documents), `server/core/src/scim_routes.{hpp,cpp}` (HTTP routes).
Tests: `tests/unit/server/test_scim_store.cpp`,
`test_scim_json.cpp`, `test_scim_routes.cpp`.

## Periodic access reviews (SOC 2 CC6.2)

A fleet-wide access-review capability across all three RBAC principal types
— **user**, **group**, and **engine** — closing the "Periodic access
reviews with manager/security attestation" CC6.2 gap. Two independent
pieces: a stateless **export** (the current grant population, for a quick
spot-check or an offline CSV pull) and a durable **attestation campaign**
(freeze the population, have reviewers sign off on each grant, keep the
evidence forever).

### Export model

`GET /api/v1/access-reviews/export` (`AccessReview:Read`) builds one row per
principal via the pure read-model `access_review_model.hpp`
(`build_access_review`). For **all three** principal types uniformly it
reads the principal's **direct** role grants and expands each to its
permission set — deliberately **not**
`RbacStore::get_effective_permissions(username)`, which is user-keyed and
would silently mis-resolve if called with a group name (it would look up
`principal_type='user' AND principal_id=<group name>`, never the group's own
grants). A consequence: a user row lists only that user's own direct
grants — group-inherited access is not flattened onto the user row, it
appears on the **group's own row** instead. A reviewer must read both a
user's row and the rows of every group they belong to for the complete
picture; a future "resolved effective access" column is a tracked follow-up.

**Grant-table-driven completeness (UP-1).** The export's SPINE is the grant
table, not any roster. `build_access_review` reads **every**
`(principal_type, principal_id, role_name)` row on record via
`RbacStore::list_all_principal_roles_checked()` — one bulk read — and groups
it by principal; the users/groups/engine-principal rosters are still read,
but only to *enrich* a grant-table row with display metadata. Two
consequences that change what the export means and what it shows:

- **A principal with zero role grants produces no row.** This narrows the
  export's scope on purpose: it answers "who currently has access", not
  "who exists" — a dormant local account or a never-assigned engine
  principal is out of scope for a CC6.2 review because there is nothing on
  it to review.
- **A grant belonging to a principal that matches nothing in any roster is
  now surfaced, never silently dropped.** A since-deleted user, a stale
  IdP-provisioned row, or an OIDC/SSO principal minted outside every roster
  (e.g. `oidc:<iss>#<sub>`) still holds a live grant if one exists on
  record — that row is emitted with `display_name = principal_id`,
  `source = "orphan"`, `lifecycle_state = "unknown"` rather than being
  silently omitted. The prior design walked the three rosters and asked
  RBAC per member; a grant belonging to a principal outside every roster
  was a silent false negative in exactly the evidence CC6.2 exists to
  produce. Orphan/stale grants are exactly the kind of finding a periodic
  access review is supposed to catch — a reviewer should expect to see
  `source="orphan"` rows and treat them as a `flagged_revoke` candidate by
  default unless the principal is independently known-good.

**Disabled-user lifecycle honesty.** A user who is disabled but still holds
a live role grant is enriched from the `AuthDB` roster like any other user
row — `source="user"`, `lifecycle_state="disabled"` — never conflated with
`source="orphan"`/`lifecycle_state="unknown"`, which means "no roster entry
matched this grant at all". A disabled-but-still-granted user is exactly
the kind of finding a periodic access review exists to catch (a likely
`flagged_revoke` candidate); showing it as an unresolvable orphan would
obscure that it is a known, roster-matched account.

**Non-atomic, best-effort cross-substrate read.** The grant population this
export (and every campaign freeze) computes is a **point-in-time
best-effort cut** across two substrates — `RbacStore`/`EnginePrincipalStore`/
`AccessReviewStore` on PostgreSQL and `AuthDB` on SQLite — not a
transactional snapshot: there is no cross-database transaction spanning the
several bulk reads `build_access_review` issues, so a grant or user change
that lands mid-read may or may not be reflected in the result. This is an
accepted property, not a defect — the alternative (a distributed
transaction across two storage engines) is out of scope for this feature.
The **freeze itself**, once the population is computed, is atomic: `open_campaign`
inserts the campaign row and every frozen attestation row in **one**
PostgreSQL transaction (see "Attestation campaign model" below) — the
non-atomicity is confined to *assembling* the population, not to persisting
it once assembled.

**Fail-loud, never a silent partial export (R1).** `build_access_review`
returns `std::unexpected` on the FIRST read failure it hits across users,
groups, engine principals, API tokens, and every per-principal role/
permission read — never a partial `vector`. A compliance export that
silently drops rows on a transient read failure is worse than one that
fails loudly: a partial grant set that reads as "the complete list" is a
false negative in exactly the evidence this feature exists to produce. The
REST route maps a `build_access_review` failure to `503`, not a 200 with
fewer rows.

`last_activity_ms`/`last_activity_kind` and `owner_or_email` are
best-effort enrichment (`ApiTokenStore` for an engine row's most recent
credential use; `DirectorySync` for a user's email) — a missing enrichment
source degrades that one field, it does not fail the export. **Known
scoping, stated plainly rather than silently shipped:** every user row's
`last_activity_kind` is `"n/a"` today (`AuthDB` has no read accessor for
last-login yet — a noted follow-up, not a bug); `source="scim"` is
forward-compat and not yet populated by any write path.

### Attestation campaign model

`POST /api/v1/access-reviews` (`AccessReview:Attest`) expands the export into
one `GrantRef` per `(principal, role)` pair and calls
`AccessReviewStore::open_campaign`, which — in **one transaction** — inserts
the campaign row and one `decision='pending'` attestation row per frozen
grant. This is the **freeze-at-open completeness property**: every grant
that existed the instant the campaign opened has a reviewable row, and that
is a provable invariant, not a hope. A grant created after `open_campaign`
returns is simply out of scope for *this* campaign (it will appear in the
next one); a grant revoked afterward is **still reviewable here** — the row
is frozen, not re-derived from live state — because "who had access, on
this date, and did a reviewer sign off on it" is exactly the question CC6.2
evidence must answer, and a campaign that quietly dropped a since-revoked
grant would erase that history.

Reviewers record a decision via `POST /api/v1/access-reviews/{id}/attestations`
(`AccessReview:Attest`): `attested` (still appropriate) or `flagged_revoke`
(should be revoked). **`flag ≠ revoke`.** `flagged_revoke` records evidence
only — no RBAC or `EnginePrincipalStore` mutation happens on this path.
Acting on the flag (unassigning the role, revoking the engine principal,
etc.) is a separate, explicit operator action performed after reading the
evidence, on the ordinary RBAC/engine-principal write surface. This
deliberately keeps the access-review surface (`AccessReview:Attest`) from
becoming a second, less-audited path to a real authorization change — every
actual grant/revoke still goes through its own gated, individually-audited
route.

`POST /api/v1/access-reviews/{id}/close` (`AccessReview:Attest`) closes a
campaign without requiring every attestation to be decided — an incomplete
review is itself a fact the evidence should show (partial coverage), not
something the route silently forces to completion by auto-attesting the
remainder.

`GET /api/v1/access-reviews` (`AccessReview:Read`) lists every campaign's
metadata (not its attestations — `GET /api/v1/access-reviews/{id}` for
those), newest-first, capped at the most recent 500 — the surface an
auditor needs to prove reviews ran on cadence without already knowing a
`campaign_id` out-of-band.

### Store

`AccessReviewStore` (`server/core/src/access_review_store.{hpp,cpp}`,
schema `access_review_store`) is a born-on-Postgres store (ADR-0006) with
**authoritative/fail-hard** posture per ADR-0012 §1 — construction is
fail-**closed** (a reachable database whose schema can't migrate leaves
`!is_open()`, which `server.cpp` wires to `startup_failed_`, same as
`EnginePrincipalStore`), and every mutator/completeness-reader returns a
typed `std::expected`. Two tables: `access_review_campaign` (one row per
opened campaign) and `access_review_attestation` (one row per frozen
`(campaign, principal_type, principal_id, role_name)` grant — the PK is the
full 4-tuple, so a decision can only ever be recorded against a grant that
was actually in the frozen population; an unknown tuple never matches, and
`record_attestation`/`get_campaign`/`close_campaign` signal that with a
machine-checkable `"not_found: "`-prefixed error the REST/MCP layers map to
`404`/`kInvalidParams`, distinct from a genuine `503`/`kInternalError` read
or write failure). **Deliberately no prune method** — unlike the `/auto`
pre-flight/deployment runs (operational scratch state, 14-day-pruned), a
closed access-review campaign **is** the compliance evidence; it persists
indefinitely. Any future retention policy is an explicit, separately-
reviewed decision, never a default cadence inherited from an unrelated
store.

### #2225 — why this is a global gate, not `authorize_list_read`

Every new list/fan-out read of **per-agent** data must use the ADR-0017
`authorize_list_read` admit-then-filter chokepoint (see "Authentication,
RBAC..." in the routed-concerns table). Access-review export/campaign-open/
campaign-list are list reads too, but every one of them is deliberately
gated on the **global** `AccessReview:Read`/`AccessReview:Attest` instead —
a considered exception, not an oversight:

- The confinement model exists to stop a management-group-scoped operator
  from seeing agents/devices outside their scope. **A grant/role assignment
  is not scoped to a management group at all** — RBAC role assignments are
  fleet-wide facts about a principal, so there is no per-agent boundary to
  admit-then-filter against in the first place.
- Even if a confinement filter were bolted on (e.g. "only show grants for
  principals who touch devices in my groups"), the result would be
  **useless as CC6.2 evidence**: an auditor/reviewer certifying the access
  posture of the organization must see the *complete* grant population, not
  one operator's confined slice of it. A partial certification is not a
  certification.
- Access review is therefore intentionally **admin/auditor-only and
  unconfined by design**. The seeded `Reviewer` role (`AccessReview:Read` +
  `AccessReview:Attest` only — no Write/Delete/Approve/Push on
  `AccessReview`) is the least-privilege way to grant this: an organization
  can appoint a dedicated reviewer without also granting full
  `Administrator` access (separation of duties), mirroring the existing
  `GET /api/v1/audit/auth-sample` precedent (also gated on a dedicated
  read permission, not admin-only).

**Round-2 fix — dedicated `AccessReview` securable, not `AuditLog`.** The
original implementation gated this surface on the existing
`AuditLog:Read`/`AuditLog:Attest` operations, on the assumption that
`AuditLog:Read` was effectively `Reviewer`-only. A reviewer found that
assumption false: `AuditLog:Read` is also seeded to the built-in `Operator`
and `PlatformEngineer` roles (for `GET /api/v1/audit/auth-sample` and the
general audit-log read routes), neither of which holds
`UserManagement:Read` (`/rbac/roles`) or `Security:Read`
(`/engine-principals/{id}/roles`) — so both roles could pull the *complete*
fleet-wide grant population via the access-review export despite being
denied the two purpose-built routes for reading role-assignment data. The
fix is the dedicated `AccessReview` securable described above: it preserves
every argument in this section (the gate is still global/unconfined, and
still a dedicated RBAC-privileged operation nobody gets by default) while
closing the over-disclosure — `Operator`/`PlatformEngineer` keep
`AuditLog:Read` for their legitimate uses but hold no `AccessReview`
operation, so neither can reach `/api/v1/access-reviews*` any more. Full
narrative: `docs/security-reviews/access-reviews-2026-07-21.md` "#2225
round 2".

### RBAC additions

- New dedicated securable type **`AccessReview`** with two operations,
  **`Read`** (export/get/list) and **`Attest`** (open/attest/close),
  granted only to `Administrator` and the new `Reviewer` role. Not folded
  into the existing `AuditLog` securable — see the "Round-2 fix" note above
  for why a shared/broadly-seeded permission over-disclosed the fleet-wide
  grant population to `Operator`/`PlatformEngineer`. The `AuditLog:Attest`
  operation from the first round of this PR is removed as unused now that
  `AccessReview:Attest` exists; `AuditLog:Read`/`AuditLog:Write`/etc. are
  otherwise unchanged and keep their pre-existing scope.
- New seeded system role **`Reviewer`** — `AccessReview:Read` +
  `AccessReview:Attest` only (7 built-in roles total: Administrator,
  PlatformEngineer, Operator, ApiTokenManager, ITServiceOwner, Viewer,
  Reviewer).

### MCP twins

`export_access_review`, `open_access_review`, `record_attestation`,
`get_access_review`, `list_access_reviews`, `close_access_review` — JSON
only (CSV stays a REST-only presentation of the same export).
`record_attestation` carries `destructiveHint:true` — a second call for the
same `(campaign_id, principal_type, principal_id, role_name)` **overwrites**
the prior reviewer's decision, reviewer, and justification (an UPSERT with
no retained history of the earlier decision). `close_access_review` also
carries `destructiveHint:true` — a one-way `open`->`closed` lifecycle
transition (no reopen path) that permanently freezes outstanding attestations
(corrected 2g PR 2, was shipped `false`). The other four are
`destructiveHint:false` (`export_access_review`/`get_access_review`/
`list_access_reviews` are additionally `readOnlyHint:true`; `open_access_review`
mints campaign evidence but never a live access grant). See `docs/mcp-server.md`
and `docs/user-manual/mcp.md`
"Available Tools".

## Granular RBAC (Phase 3)

- 7 roles, 22 securable types (adds `AccessReview`, dedicated to Periodic
  Access Reviews — see "Periodic access reviews" above), 7 operations
  (`Read`/`Write`/`Execute`/`Delete`/`Approve`/`Push`/`Attest`),
  per-operation permissions, deny-override logic.
- **OIDC SSO** — Full PKCE flow, Entra ID discovery, JWT validation, group-to-role mapping.
- **AD/Entra integration** — Microsoft Graph API for user/group import.

## On-behalf-of assertions rejected (ADR-1005 Interim rules)

Until server-verifiable delegation ships (ADR-1005 auth follow-up), the server
accepts **no** on-behalf-of assertion on **any** ingress surface — any such
header or metadata key is **rejected, not ignored**. Five names are reserved
(case-insensitive; source of truth `server/core/src/on_behalf_guard.hpp`, and
the list only ever grows): `On-Behalf-Of`, `X-On-Behalf-Of`,
`X-Yuzu-On-Behalf-Of`, `X-Yuzu-Delegated-Operator`,
`X-Yuzu-Delegation-Artifact`.

Enforcement: **HTTP** — checked in the pre-routing chokepoint (`server.cpp`)
before auth, the allowlist, and the rate limiter, so REST, MCP, dashboard
fragments, and static files all reject with `403` + the A4 error envelope.
**Recorded exception (the only one):** the four liveness/readiness probe
paths (`/livez`, `/readyz`, `/health`, `/api/health`) are exempt — a
mesh/SSO proxy that stamps a reserved header on every request must not be
able to fail the probes and crash-loop the server (governance CH-3/UP-5); a
probe performs no identity-bearing action and nothing consumes the header on
that path. This exception is recorded in ADR-1005's exception ledger on
acceptance. **gRPC** — a single server interceptor on the
one `ServerBuilder` (`grpc_on_behalf_interceptor.hpp`) covers the agent,
management, and gateway-upstream services and every future RPC method by
construction; a call carrying a reserved metadata key is cancelled via
`ServerContext::TryCancel()` (client observes `CANCELLED`). `TryCancel()`
alone does not stop a handler from running, so it is paired with an
enforcement seam (`grpc_on_behalf_enforce.hpp`): the first statement of every
RPC handler on `AgentServiceImpl` and `GatewayUpstreamServiceImpl`
independently re-derives the same reserved-key check from
`context->client_metadata()` (not `ServerContext::IsCancelled()` — its
propagation from `TryCancel()` is not synchronous with handler dispatch,
confirmed by an end-to-end test) — the call is a true no-op on that surface,
not merely a wrong status code on an already-committed side effect. **Gateway
note:** the Erlang gateway's
own agent-facing listener reads only its known metadata keys and mints fresh
upstream calls, so a reserved key sent to the gateway is dropped rather than
rejected — tracked as a follow-up (Erlang-side reject, #1974) rather than an
exception. **Consequence for `GatewayUpstreamServiceImpl`'s own enforcement:**
today's gateway never forwards the agent's original gRPC metadata onward, so
an agent cannot smuggle a reserved key through it — the `ProxyRegister`/etc.
handlers' `onbehalf::enforce()` guard is currently defense-in-depth against
the gateway's own client, not a proven end-to-end control against relayed
agent metadata. If a future change adds metadata passthrough (e.g. for
tracing), it must re-derive the reserved-key check against the forwarded
metadata explicitly — the guard does not do this automatically. Rejections
are counted in
`yuzu_onbehalf_rejected_total{surface,event="security"}`; there is
deliberately **no audit row** (the rejection fires pre-auth, so there is no
resolved principal to attribute — the metric is the signal). **Accepted
evidence limit:** the warn log is sampled (1 per 100 rejections per surface,
a deliberate pre-rate-limiter flood defence), so the counter proves *how
many* attempts occurred while only ~1% carry a forensic log line with
timestamp/source — state this plainly if asked "can you show every attempt". When delegation
ships it will use a **server-issued artifact**, never a client-asserted
header, so these names stay rejected on client ingress permanently.

## API tokens and automation

- **API tokens** — Bearer token and `X-Yuzu-Token` header auth for automation. MCP tokens (see `docs/mcp-server.md`) use the same table with mandatory expiration (max 90 days).
- **Ownership-scoped revocation** — `DELETE /api/v1/tokens/{id}` and `DELETE /api/settings/api-tokens/{id}` both require the caller to own the token; the global `admin` role is the sole bypass. Cross-user revoke returns `404 token not found` (identical to unknown-id, to prevent enumeration). Denied attempts are recorded with `result=denied`, `detail=owner=<principal>`. See #222 and `docs/user-manual/server-admin.md` "Upgrade Notes".

## Engine principals & delegation (ADR-1005 — design)

**Stream liveness is cached; authorization is not** (#2367). The per-tick
re-check that keeps a held-open MCP/SSE stream alive reads the engine principal
through `EnginePrincipalStore::get_for_auth_revalidate` — a 15 s, Active-only
liveness cache with exactly one caller, the private
`AuthRoutes::engine_credential_state`. Every *fresh* authorization decision —
session synthesis, and the REST/MCP on-behalf-of target checks — still calls the
authoritative `get_for_auth` and reads through to Postgres on every call, so a
revoked principal cannot obtain a new session or a new delegation at any point.
A cached answer is reported as `auth::CredentialCheck::kValidStale` rather than
`kValid`, which is what stops a stream from riding the cache and then collecting
a full fresh outage-grace window on top of it. See ADR-0031 Consequences for the
invalidation and bounding rules, and `docs/mcp-server.md` "Revocation." for the
resulting latency bounds.

- **Design doc:** `docs/auth-engine-principals-design.md` (execution-plan item
  2b, feeds Phases 4–5). **Shipped (PR 4.1–4.3):** the identity store + RBAC
  resolution (PR 4.1–4.2) and the operator-facing REST + MCP + admin-console
  lifecycle surface (PR 4.3) below are live. Delegation (Phase 5, RFC 8693
  token exchange) remains design-only — not yet implemented.
- Third principal class (`engine`) for use-case-engine hosts: dedicated
  born-on-Postgres `EnginePrincipalStore` (named human owner, justification,
  required `internal`/`external` classification, soft-retained after revoke),
  reserved `engine:` id namespace, per-module granularity.
- Token sessions branch on a persisted `ApiToken.principal_kind`
  (`human`|`engine`) — an engine token attributes to the engine principal
  itself (`auth_source="engine_token"`), never to its creating human. Engine
  tokens are referentially checked against `EnginePrincipalStore` at mint
  time, always `mcp_tier=readonly`, and always carry a ≤90-day expiry.
- **Session-authorization semantics — RBAC-only, no fallback (PR 4.2 fix
  round).** `AuthRoutes::require_permission`/`require_scoped_permission`
  branch on `session->principal_kind == "engine"` **before** falling through
  to the legacy pre-RBAC path or the MCP-tier/service-scoped resolution used
  for human and agent sessions. An engine session's authority is resolved
  **exclusively** against `RbacStore`:
  - `rbac_store_` null/unopened → **`503`** (cannot evaluate authority;
    retryable, never a silent allow).
  - RBAC disabled, or no matching `(principal="engine:<slug>", role, scope)`
    grant → **`403`**.
  - A matching grant → allowed.

  This closes the gap where an engine credential — before this fix — inherited
  fleet-wide `Read` the moment RBAC was off (the historical default), via the
  same legacy fallback human sessions still use. Engine principals now get
  **no** legacy fallback and **no** service-scoped fallback under any
  circumstance; the only path to authority is an explicit assignment. This is
  the concrete mechanism behind design §4.2's promise: *"An engine principal
  with no assignments can do nothing."*
- **Audit attribution.** `AuthRoutes::make_audit_event` re-stamps
  `principal_class="engine"` from the resolved session's `principal_kind`
  after the generic (credential-presentation-based) classification runs —
  an engine principal's bearer-token requests previously mislabelled as
  `"agent"` in the audit trail (design §6 / `adr-1005-execution-plan.md`
  Decision 9) now attribute truthfully.
- **Reserved-namespace fail-closed guards.** `find_local_groups_with_prefix`
  returns `std::nullopt` (not an engaged-empty optional) when the RBAC store
  can't be read, and the `server.cpp` boot-time `engine:`-collision preflight
  requires `rbac_store_->is_open()` before trusting a clean scan — a corrupt
  `rbac.db` now fails the boot closed rather than booting "clean" past a
  reserved-namespace collision it could not actually see. `upsert_sso_identity`
  separately rejects any `engine:`-prefixed write at the SSO identity-sync
  surface (design §3.3), sharing the `kEngineReservedPrefix` constant with the
  store's own create-path guard.
- **Fleet-wide role-assignment authoring (PR 4.2 deliverable, design §4.1).**
  `GET`/`POST`/`DELETE /api/v1/engine-principals/{id}/roles` (+ MCP twins
  `list_engine_roles`/`assign_engine_role`/`unassign_engine_role`) are the
  authoring surface that makes `RbacStore::assign_role(principal_type="engine")`
  reachable in production — see `docs/user-manual/rest-api.md` "Engine
  Principals" for the full contract. Mutations require admin + MFA step-up;
  admin/built-in/wildcard role targets are rejected as `4xx`, never silently
  narrowed or a `500` (design §4.2 "no admin, ever").
- Authorization model: scoped role assignments `(principal, role, scope)`
  for **all** principal classes, evaluated permissions ∩ scope through
  ADR-0017's `authorize_list_read` chokepoint for list/fan-out reads and
  the per-device scoped-permission path for single-target operations
  (ADR-0017 PR-A is a named prerequisite, its charter to be amended or
  extended for the `engine` principal type). Engine principals are
  default-deny, structurally barred from `admin`. **Today (PR 4.2) grants are
  fleet-wide only** — scoped (management-group) engine assignment is rejected
  pending that Phase-5 chokepoint.
- Delegation (Phase 5): RFC 8693 token-exchange shape — server-issued
  opaque, audience-bound, short-TTL artifact; effective authority = engine
  principal's assignments ∩ operator's assignments ∩ operator's scope
  (decision-level intersection — a delegation only ever narrows);
  self-asserted delegation stays rejected permanently.
- Engine credentials: 90-day ceiling, overlap-pair rotation (≤2 active),
  minted **credentials** are MCP tier hard-locked `readonly` for v1. This is
  distinct from the tier a *human/automation caller* needs to invoke the
  lifecycle surface itself — see "Lifecycle surface (PR 4.3)" below.

### Lifecycle surface (PR 4.3)

Operator-facing CRUD for engine-principal identities and their credentials —
full reference: `docs/user-manual/rest-api.md` "Engine Principals" section,
`docs/user-manual/mcp.md` tools 55–63 (52–54 are the role-assignment tools), `docs/user-manual/engine-principals.md`
walkthrough.

- **Surfaces:** 9 REST routes under `/api/v1/engine-principals` (create, list,
  get, delete, credential mint/rotate/confirm, transfer-owner, and the
  `GET /audit/no-admin` auditor), 9 MCP twin tools, and an "Engine Principals"
  section in the Settings admin console (create form, list, mint/rotate buttons
  behind a one-time secret-reveal panel, revoked rows showing `superseded_by` +
  revoke detail).
- **REST gating:** every *mutating* route is human-admin + MFA-step-up gated;
  the three read routes (list, get, `audit/no-admin`) are human-admin + RBAC
  gated (`Security:Read`/`AuditLog:Read`) but not step-up gated. Every route —
  reads included — structurally denies a caller whose own session is
  engine-classed (`principal_kind="engine"` / `auth_source="engine_token"`, the
  §9 belt): an engine principal can never read or mutate its own or another
  engine principal's lifecycle surface.
- **MCP gating:** the 6 mutating tools all gate on `Security:Write`
  (`mint_engine_credential`/`rotate_engine_credential` included — aligned with
  their REST twins, not `Security:Execute`), require the `supervised` tier,
  and are maker-checker approval-gated (approver ≠ submitter), same posture
  as every other destructive MCP op. The 3 read tools (`list_engine_principals`,
  `get_engine_principal`, `audit_engine_no_admin`) are plain `Read`-class RBAC
  checks available on every MCP tier including `readonly`, and are not
  approval-gated. **All 9 tools**, mutating and read alike, carry the same §9
  engine-session denial belt as their REST twins — an engine-classed MCP
  caller is denied on every one of them, including the three reads.
- **Overlap-pair credential rotation** (design §7): at most 2 active
  credentials per principal, a 24-hour minimum overlap window (rejected
  outright, never truncated, below the floor), a ~120-second grace window
  that re-serves the same successor secret on a same-caller retry, and a
  60-second background sweep that auto-revokes the predecessor once its
  overlap window elapses and warns (an operational, non-security signal) on
  an unused successor nearing expiry.
- **No-admin auditor** — `GET /api/v1/engine-principals/audit/no-admin` /
  MCP `audit_engine_no_admin` — independently resolves every engine
  principal's actual roles + effective permissions against the live RBAC
  reference tables and reports any violation (literal admin/system-role
  grant, or a full securable × operation wildcard grant). Fails closed
  (`503`, "cannot verify") rather than reporting a false `ok:true` if RBAC
  reference data can't be resolved.
- **Owner-delete interlock (two-mode enforcement):** a user who owns an
  active engine principal must not be silently removed, or the principal's
  audit trail loses its named responsible human. Enforcement mode is chosen
  by whether an operator is in the loop (enterprise-architect ruling, PR 4.3
  governance):
  - **Interactive dashboard delete → prevention.** `DELETE
    /api/settings/users/{username}` (`settings_routes.cpp`) is blocked with
    `409` until ownership is transferred (`count_active_owned_by`,
    fail-closed on a store-unreachable read). An admin is present and can
    transfer first.
  - **Automated SCIM deprovision → detection.** SCIM deactivate/delete
    (`scim_routes.cpp` `deactivate()` + inline `DELETE`) is a CC6.8-mandated
    termination with no operator to transfer-first. Refusing it would leave a
    terminated employee **active** (a worse control failure); cascade
    auto-revoke is rejected because `revoke()` is terminal/irreversible (an
    IdP flap would destroy machine identities). So the deprovision **always
    succeeds** and a shared `flag_owner_deprovisioned` helper emits a
    high-signal audit `engine_principal.owner_deprovisioned` + increments
    `yuzu_engine_principal_owner_deprovisioned_total` when the departing user
    owned active principals (or ownership can't be verified), for out-of-band
    reassignment. It fires ONLY on the two genuine deprovision paths — never
    on SCIM undo/rollback (`remove_user` used to clean up a just-created or
    revived account). The orphaned principal keeps authenticating on its own
    `principal_type='engine'` credential and never derived authority from the
    owner, so the departed user gains nothing. Alert on the metric.

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
