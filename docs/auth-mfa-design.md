# MFA (TOTP) — Yuzu design reference

Status: **PR 1 + PR 2 of 3 shipped (v0.13+)** — self-service enrollment,
login challenge, recovery codes (PR 1) and step-up on 10 high-risk
REST + Settings surfaces (PR 2). PR 3 adds OIDC `amr` short-circuit and
enforcement modes (`admin-only` / `required`).

This doc is the single design reference for Yuzu's MFA implementation.
For why MFA matters at all and where it sits in the broader A&A roadmap,
see `.claude/skills/auth-and-authz/SKILL.md` gap matrix entry P0 #1 and
`docs/enterprise-readiness-soc2-first-customer.md` workstream B (SOC 2
CC6.6 — privileged access).

---

## TL;DR

- **TOTP only.** RFC 6238, HMAC-SHA1, 30 s step, 6 digits. Works with
  every shipping authenticator app out of the box. WebAuthn / FIDO2 is
  deliberately deferred.
- **Per-user enrollment via the Settings page.** Operator scans an
  `otpauth://` URI (one-time reveal in the existing `<div
  class="token-reveal">` pattern), enters the next code from their
  authenticator to confirm, receives 10 single-use base32 recovery codes.
- **Login challenge.** `POST /login` accepts the password and, if the
  user has TOTP enrolled, returns HTTP 202 + an opaque short-lived
  `mfa_pending_token` instead of minting a session. The browser swaps to
  a TOTP form and posts the token + 6-digit code to `POST /login/mfa`.
  Recovery codes share the same endpoint (heuristic: `-` separator or
  non-6-digit length).
- **Step-up window** (PR 2). On a successful TOTP proof the session's
  `mfa_verified_at` is bumped to `steady_clock::now()`. High-risk
  endpoints reject the session as "stale" if the gap exceeds
  `cfg.mfa_step_up_window_secs` (default 300 s) and prompt for a fresh
  code via `POST /login/mfa/stepup`.
- **Audit chain.** Every state transition emits an audit row through
  `AuthRoutes::audit_log`. The verbs are: `mfa.enroll.initiated`,
  `mfa.enroll.verified`, `mfa.enroll.failed`, `mfa.disabled`,
  `mfa.login.required`, `mfa.login.verified`, `mfa.login.failed`,
  `mfa.recovery_codes.generated`, `mfa.recovery_code.used` (PR 2 adds
  `mfa.step_up.*`).

---

## What ships in PR 1

The slice of the design that is live as of v0.12.

| Surface | File(s) | Notes |
|---|---|---|
| RFC 6238 TOTP + RFC 4648 base32 + otpauth URI | `server/core/src/totp.{hpp,cpp}` | Tested against RFC 6238 Appendix B SHA-1 vectors |
| Schema migration v2 | `server/core/src/auth_db.cpp` (`kMigrations`) | `users.mfa_*`, `sessions.mfa_verified_at`, `mfa_recovery_codes`, `auth_kv` |
| MFA accessors on `AuthDB` | `server/core/{src,include}/yuzu/server/auth_db.{cpp,hpp}` | `mfa_init_enrollment` / `mfa_verify_enrollment` / `mfa_verify_login_code` / `mfa_consume_recovery_code` / `mfa_regenerate_recovery_codes` / `mfa_disable` / `mfa_status` / `mfa_mark_session_stepup` |
| AuthManager glue | `server/core/{src,include}/yuzu/server/auth.{cpp,hpp}` | `verify_password`, `create_local_session(user, role, mfa_verified)`, `mark_session_mfa_verified`, `auth_db_ptr()` |
| `Session::mfa_verified_at` | `server/core/include/yuzu/server/auth.hpp` | `steady_clock::time_point`; default-constructed = not verified |
| Login flow | `server/core/src/auth_routes.{cpp,hpp}` | `POST /login` returns 202 + pending token on MFA-enrolled users; new `POST /login/mfa` route; `MfaPending` map with TTL reaper |
| Login page | `server/core/src/login_ui.cpp` | Hidden MFA form revealed on 202 response |
| Settings panel | `server/core/src/settings_routes.{cpp,hpp}`, `settings_ui.cpp` | `render_mfa_fragment` + four `/api/settings/mfa/*` POST routes; new "Multi-Factor Authentication" section |
| Config | `server/core/include/yuzu/server/server.hpp` + `main.cpp` | `mfa_enforcement`, `mfa_step_up_window_secs`, `mfa_login_pending_secs` + matching CLI flags |
| Tests | `tests/unit/server/test_totp.cpp`, `tests/unit/server/test_mfa_store.cpp` | RFC vectors + AuthDB end-to-end |

---

## Schema

v2 migration in `auth_db.cpp:kMigrations`. The columns are all nullable
so existing rows survive the migration unchanged; `mfa_last_counter` has
`DEFAULT 0` to keep its `NOT NULL` honest.

```
users:
  mfa_totp_secret BLOB          -- raw 20-byte HMAC-SHA1 key
  mfa_enrolled_at DATETIME      -- NULL = provisional or never enrolled
  mfa_disabled_at DATETIME      -- NULL = active or never enrolled
  mfa_last_counter INTEGER      -- replay floor; updated on every verify

sessions:
  mfa_verified_at DATETIME      -- NULL = never stepped up

mfa_recovery_codes:
  id INTEGER PK
  username TEXT
  code_hash TEXT                -- PBKDF2-SHA256 (matches password_hash)
  code_salt TEXT                -- 16 hex bytes
  consumed_at DATETIME          -- NULL = unused
  created_at DATETIME

auth_kv:
  key TEXT PK
  value BLOB
  created_at / updated_at DATETIME
```

`auth_kv` is provisioned empty for the future at-rest encryption work
(see "At-rest protection" below). v1 has no writes against it.

---

## At-rest protection

The TOTP secret is plaintext in `users.mfa_totp_secret`. The compensating
controls are:

- `auth.db` is created and re-chmod'd to **0600** on every open
  (`auth_db.cpp:236`). Same posture as password hashes.
- The parent directory is **0700** on Unix (`auth_db.cpp:204`).
- The agent process runs as a dedicated non-root account (`docs/agent-
  privilege-model.md`).

Threat model: an attacker with read access to `auth.db` already has the
password-hash store, the session cookie store, the enrollment-token
hashes, and every API-token row. Adding plaintext TOTP secrets does not
materially worsen that posture — both PBKDF2-cracking a password and
reading a TOTP secret give the attacker indefinite account access.

A follow-up encrypts the secret with **AES-256-GCM** using a per-server
master key stored in `auth_kv` under `key='mfa_master_key'`. The
plaintext column becomes `mfa_totp_secret_enc + nonce + tag`. Tracked as
a v3 schema migration; the `auth_kv` scaffolding is in place so the
later PR is purely additive.

---

## TOTP details

| Parameter | Value | Source |
|---|---|---|
| Algorithm | HMAC-SHA1 | RFC 6238 default |
| Time step | 30 seconds | RFC 6238 default |
| Code length | 6 digits | RFC 6238 default |
| Secret length | 20 bytes (160 bits) | RFC 4226 §4 R6 |
| Skew tolerance | ±1 step (90 s effective window) | RFC 6238 §5.2 small-skew recommendation |

`Totp::verify_window` walks `current ± 1` and rejects any candidate
`<= mfa_last_counter`. On a successful match, `mfa_last_counter` is
updated to the matched counter, so the same code cannot be reused within
its 90 s window even via clock-skew accommodation.

The constant-time string compare inside `verify_window` is moot for
6-digit codes (length leak is bounded) but defends against timing
oracles in case a future change widens the truncation.

---

## Recovery codes

10 codes per enrollment, format `XXXXX-XXXXX` (10 base32 characters with
a `-` separator inserted for readability). Stored as PBKDF2-SHA256
hashes against per-row 16-byte salts (same PBKDF2 parameters as the
password store: 100 000 iterations).

Single-use enforcement: `mfa_consume_recovery_code` finds an unconsumed
row, constant-time-compares the salted hash, and `UPDATE … SET
consumed_at = CURRENT_TIMESTAMP WHERE id = ? AND consumed_at IS NULL`.
The `WHERE consumed_at IS NULL` guard plus `sqlite3_changes()` check
means a concurrent consume that wins the race is treated as no-match by
the loser — race-safe without a transaction.

`mfa_regenerate_recovery_codes` deletes every row for the user (consumed
or otherwise) and issues 10 fresh ones. The UI surfaces this when
recovery_codes_remaining drops below 5 or when the operator presses
"Regenerate recovery codes".

`mfa_disable` deletes the user's recovery codes alongside clearing the
secret — leaving them around would let a disabled user authenticate via
a stale code after re-enrolling.

---

## Login flow (PR 1)

```
Browser                    Server (POST /login)             AuthDB
  │  username + password   │                                  │
  ├───────────────────────►│  verify_password(user, pw)       │
  │                        ├──────────────────────────────────►
  │                        │      Role / nullopt              │
  │                        ◄──────────────────────────────────┤
  │                        │                                  │
  │                        │  mfa_status(user)                │
  │                        ├──────────────────────────────────►
  │                        │      MfaStatus{ enrolled }       │
  │                        ◄──────────────────────────────────┤
  │                        │                                  │
  │                        │  ┌─ enrolled = false:            │
  │  Set-Cookie + 200 OK   │  │  create_local_session(…, false) →
  ◄────────────────────────│──┘                               │
  │                        │                                  │
  │                        │  ┌─ enrolled = true:             │
  │  202 + pending_token   │  │  store MfaPending{user, role, exp}
  ◄────────────────────────│──┘  return pending_token         │
  │                        │                                  │
  │  POST /login/mfa       │                                  │
  │  pending_token + code  │                                  │
  ├───────────────────────►│                                  │
  │                        │  lookup MfaPending               │
  │                        │  mfa_verify_login_code           │
  │                        ├──────────────────────────────────►
  │                        │      bool                        │
  │                        ◄──────────────────────────────────┤
  │                        │                                  │
  │  Set-Cookie + 200 OK   │  create_local_session(…, true)   │
  ◄────────────────────────│                                  │
```

The `mfa_pending_token` is opaque (32 random bytes hex-encoded), stored
in-process in `AuthRoutes::mfa_pending_`, TTL'd by
`cfg.mfa_login_pending_secs` (default 120 s), reaped lazily on every
access. Lost on server restart — the user just goes back to `/login`,
which is exactly the right UX.

Recovery codes ride the same endpoint: the handler distinguishes by
shape (`-` separator or non-6-digit length → recovery; otherwise TOTP).

---

## Step-up flow (PR 2 — design)

```
Browser                    Server (POST /api/v1/sessions)    AuthDB
  │  DELETE /sessions      │                                  │
  ├───────────────────────►│  require_permission(...)         │
  │                        │  mfa_step_up(session, "sessions.revoke")
  │                        │     │                            │
  │                        │     ├─ (now - mfa_verified_at) ≤ window
  │                        │     │      → pass, run handler   │
  │                        │     │                            │
  │  401 mfa_step_up_required ◄──┤      → return A4 envelope  │
  ◄────────────────────────│                                  │
  │                        │                                  │
  │  POST /login/mfa/stepup│                                  │
  │  code                  │                                  │
  ├───────────────────────►│                                  │
  │                        │  mfa_verify_login_code           │
  │                        ├──────────────────────────────────►
  │                        │      bool                        │
  │                        ◄──────────────────────────────────┤
  │                        │  mark_session_mfa_verified(token)│
  │                        │  mfa_mark_session_stepup(token)  │
  │                        ├──────────────────────────────────►
  │  200 OK                │                                  │
  ◄────────────────────────│                                  │
  │                        │                                  │
  │  DELETE /sessions retry│  mfa_step_up(...) → pass         │
  ├───────────────────────►│                                  │
  │  200 OK                │                                  │
  ◄────────────────────────│                                  │
```

Step-up sites (from the discovery pass): user delete + role change in
Settings; token create/revoke, session revoke, Guardian rule create /
update / push, software-package create + deployment execute, file
retrieval upload in REST API v1. Eleven sites total.

---

## Enforcement modes (PR 3 — design)

`Config::mfa_enforcement`:

- `optional` (default, ships in PR 1) — users may enrol themselves, but
  login does not require it. Operators get a self-service security
  posture.
- `admin-only` — `POST /login` rejects an admin who is not enrolled with
  a redirect to the enrolment UI. Non-admins are unaffected.
- `required` — same enforcement for every role.

The redirect target is the same Settings panel that PR 1 ships; no
separate "enrolment-only" UI.

Self-target guard interaction: the existing destruction guard at
`settings_routes.cpp:434/1830/2488` is extended so an admin cannot
`mfa_disable` their own account while `mfa_enforcement != optional`.
Without that, an admin in a hardened deployment could lock themselves
out of every high-risk surface by disabling MFA.

---

## OIDC interop (PR 3 — design)

**Until PR 3 lands, OIDC/SSO sessions are exempt from local step-up.**
An OIDC identity lives in the IdP — `create_oidc_session` never writes a
`users` row, so there is no local TOTP secret to step up against and a
`mfa_status()` lookup for such a session returns `UserNotFound`.
`require_mfa_step_up` therefore treats `auth_source == "oidc"` like a
bearer credential and returns `true` (pass) in its early exemption
block. Without this, every OIDC session — including an admin mapped via
their Entra group — would fail the gate closed and be permanently
locked out of all 11 gated endpoints (PR #1199 review HIGH). MFA on SSO
sessions is the IdP's responsibility until the `amr` short-circuit below
ships.

Microsoft Entra and most OIDC IdPs assert the methods used to
authenticate via the `amr` claim (RFC 8176, plus the Entra-specific
`mfa` value). Today `IdTokenClaims` does not parse `amr`. PR 3:

1. Adds `std::vector<std::string> amr` to `IdTokenClaims`.
2. Parses it in `oidc_provider.cpp` alongside the existing claims.
3. In `auth_routes.cpp:565-631` (the `/auth/callback` handler), if `amr`
   contains any of `mfa`, `otp`, `hwk`, `face`, `fpt`, `iris`, `pin`,
   `sms`, `swk`, `tel`, `user` → `session.mfa_verified_at = iat`.

4. Removes the `auth_source == "oidc"` early exemption in
   `require_mfa_step_up` (added by PR 2, see above) so OIDC sessions are
   gated against the `amr`-seeded `mfa_verified_at` instead of being
   unconditionally exempt.

The same step-up window applies. If the IdP-asserted MFA is older than
`mfa_step_up_window_secs`, the user is re-prompted via the local TOTP
flow.

---

## Audit chain

Every transition writes to `AuditStore` via `AuthRoutes::audit_log`
(or `SettingsRoutes::audit_fn_`). The verbs are:

| Verb | When |
|---|---|
| `mfa.enroll.initiated` | `POST /api/settings/mfa/init` — secret generated |
| `mfa.enroll.verified` | `POST /api/settings/mfa/verify` — first code accepted |
| `mfa.enroll.failed` | First code rejected |
| `mfa.disabled` | `POST /api/settings/mfa/disable` |
| `mfa.login.required` | `POST /login` returned a pending token |
| `mfa.login.verified` | `POST /login/mfa` TOTP code accepted |
| `mfa.login.failed` | `POST /login/mfa` rejected (TOTP or recovery) |
| `mfa.recovery_codes.generated` | Enrollment or regenerate |
| `mfa.recovery_code.used` | `POST /login/mfa` accepted a recovery code |

PR 2 adds `mfa.step_up.required`, `mfa.step_up.passed`,
`mfa.step_up.failed`.

For SOC 2 evidence, the relevant compliance control is CC6.6
(privileged access). The `mfa.enroll.verified` row plus the every-login
`mfa.login.verified` row together form the "every privileged login was
MFA-verified" assertion auditors look for.

---

## Test coverage

- `tests/unit/server/test_totp.cpp` — base32 RFC 4648 vectors, RFC 6238
  Appendix B SHA-1 vectors (truncated to 6 digits), ±1 skew acceptance,
  replay rejection, `otpauth://` URI shape, CSPRNG output.
- `tests/unit/server/test_mfa_store.cpp` — temp `AuthDB`, end-to-end
  enroll → verify → login → recovery → disable → re-enroll lifecycle.
  Verifies replay protection on login codes, single-use recovery codes,
  case-and-separator-insensitive recovery code matching.
- End-to-end / UAT coverage: enroll via Settings, log out, log back in
  with TOTP code, perform an admin action. `bash scripts/start-UAT.sh`.
- PR 2 will add route-level tests for the step-up surface using the same
  `HttpRouteSink` test pattern that `test_workflow_routes.cpp` uses.

---

## Hard invariants (do not regress)

When extending the MFA surface (step-up PR, enforcement PR, encryption-
at-rest PR) make sure none of these regress:

1. **TOTP secrets never leave `auth.db`.** `mfa_init_enrollment` returns
   the secret to the operator exactly once (one-time reveal); after
   that, no read path returns the bytes — even the `mfa_status`
   accessor only reports `enrolled / disabled / count`.
2. **Replay protection persists.** `mfa_last_counter` is the floor on
   every accepted code. Step-up verifies must update it too.
3. **`mfa_disable` is atomic against in-flight verifies.** The
   destructive UPDATE clears both the secret and all recovery codes;
   any concurrent verify either sees the old state (and matches) or the
   new state (and fails). No half-disabled "secret cleared but
   recovery codes still active" state.
4. **`mfa_pending_` token TTL is enforced on every access** via
   `reap_mfa_pending_locked`. A 5-minute window between password
   success and TOTP submission is a credential-stuffing surface — keep
   the default tight.
5. **`Session::mfa_verified_at` is `steady_clock`, not wall clock.**
   The step-up window math must use `steady_clock::now()` so an NTP
   step (or operator clock fiddling) cannot extend the window.
6. **Audit on every gate.** `audit_log` is called on success AND
   failure for `mfa.enroll`, `mfa.login`, and `mfa.step_up`. The
   CC6.6 evidence chain is the success row + the failure row together
   — losing either side breaks it.
7. **Self-target guard extends to MFA disable** once enforcement is
   wired (PR 3). Admin can not disable their own MFA in `required` or
   `admin-only` mode.
