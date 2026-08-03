# Authentication

Yuzu supports multiple authentication methods: local password auth with session cookies, OIDC single sign-on, and API tokens for automation. All methods funnel into the same RBAC system once a principal is identified.

## Local Password Authentication

### First-Run Setup

On first launch, the server prompts interactively for admin credentials. These are stored in `yuzu-server.cfg` with PBKDF2-hashed passwords.

```
$ ./yuzu-server
No admin account found. Let's create one.
Username: admin
Password: ********
Confirm:  ********
Admin account created.
```

### Login

Authenticate by posting credentials to `/login`. The server returns a `yuzu_session` cookie.

```bash
curl -s -c cookies.txt -X POST http://localhost:8080/login \
  -d "username=admin&password=s3cret"
```

On success the response is a `200 OK` with a JSON body `{"status":"ok"}` and a `Set-Cookie` header containing the `yuzu_session` token. **For users enrolled in TOTP MFA the response is HTTP 202** with body `{"status":"mfa_required","mfa_pending_token":"<opaque>","expires_in":120}` and no cookie — the operator must complete the challenge by posting the pending token + a 6-digit TOTP code (or a `XXXX-XXXX-XXXX-XXXX` recovery code) to `/login/mfa`, which then mints the session cookie. Under MFA enforcement (`--mfa-enforcement=admin-only|required`) an **un-enrolled** user instead receives a 202 with `{"status":"mfa_enrollment_required", ...}` and must enroll via `/login/mfa/enroll` first — distinguish the two 202 cases by the `status` field. See the [Multi-Factor Authentication (TOTP)](#multi-factor-authentication-totp) section below for the full flow. The `cookies.txt` file now contains the session cookie. Use it on subsequent requests:

```bash
curl -s -b cookies.txt http://localhost:8080/api/v1/me
```

```json
{
  "data": {
    "username": "admin",
    "role": "admin"
  },
  "meta": {
    "api_version": "v1"
  }
}
```

All REST API v1 responses are wrapped in this envelope. The `data` key holds the payload, and `meta` contains the API version. List endpoints also include a `pagination` key.

### Multi-Factor Authentication (TOTP)

Yuzu supports RFC 6238 TOTP (Time-based One-Time Passwords) as a second factor for operator login. Works with every standard authenticator app (Google Authenticator, 1Password, Authy, Microsoft Authenticator). SOC 2 CC6.6 — see `docs/auth-mfa-design.md` for the full design.

#### Enrollment

1. Sign in as an admin. Navigate to **Settings → Multi-Factor Authentication**.
2. Click **Enable MFA**. The server generates a fresh 20-byte secret and renders it as an **inline QR code** in the page, plus the base32 secret and `otpauth://` URI as text for manual entry — a one-time reveal (`Cache-Control: no-store` is set so the response will not be cached by browsers or proxies).
3. Scan the QR code with your authenticator app, or type the base32 secret in manually if you can't scan.
4. Enter the next 6-digit code shown by your authenticator app and click **Confirm**.
5. The server confirms enrollment and reveals 10 single-use recovery codes in the format `XXXX-XXXX-XXXX-XXXX` (80 bits of entropy). **Save the codes somewhere safe** — they are shown exactly once.
6. From now on, every login by this account will prompt for a TOTP code after the password.

#### Login with MFA enrolled

Browser flow: the login page automatically detects the 202 response and swaps to a TOTP code prompt. Programmatic / `curl` flow:

```bash
# Step 1 — post credentials. Response is 202 + mfa_pending_token if MFA enrolled.
curl -s -X POST http://localhost:8080/login \
  -d "username=admin&password=s3cret"
# {"status":"mfa_required","mfa_pending_token":"abc…64hex","expires_in":120}

# Step 2 — post the pending token + TOTP code (or a recovery code) to /login/mfa.
curl -s -c cookies.txt -X POST http://localhost:8080/login/mfa \
  -d "mfa_pending_token=abc…64hex&code=123456"
# {"status":"ok"}  — cookies.txt now has the session cookie.
```

Recovery codes work on the same endpoint — paste the `XXXX-XXXX-XXXX-XXXX` form. The server distinguishes by shape: exactly 6 ASCII digits is interpreted as TOTP, anything else routes through recovery-code validation. Each pending token allows at most 5 attempts before being invalidated.

#### Regenerating recovery codes

Settings → Multi-Factor Authentication → **Regenerate recovery codes**. The 10 prior codes (consumed or not) are deleted atomically and 10 fresh codes are revealed.

#### Disabling MFA

Settings → Multi-Factor Authentication → **Disable MFA**. Clears the secret + all recovery codes. After disable, the user falls back to password-only login.

#### Recovery when locked out

If a user loses both their authenticator and all 10 recovery codes (or is locked out by MFA enforcement), an operator clears their MFA on the server host with the audited break-glass command `yuzu-server --mfa-reset <username>`. See `docs/ops-runbooks/auth-db-recovery.md` "Emergency MFA disable" for the full procedure (it writes an `mfa.reset.breakglass` audit row; a direct-SQL fallback is documented for hosts without the binary).

#### Configuration flags

| Flag | Default | Description |
|---|---|---|
| `--mfa-enforcement` | `optional` | `optional`: users enroll voluntarily; login never requires it. `admin-only`: an admin without MFA must enroll before login completes. `required`: every role must enroll. Under `admin-only`/`required` an un-enrolled login is redirected through TOTP enrollment (`POST /login/mfa/enroll`) before a session is minted; the startup log emits an `INFO` line naming the active mode. **Breaking:** in releases before this one these values were accepted but a no-op — see `docs/user-manual/upgrading.md` before enabling. For SSO users see "MFA on SSO sessions" below — your IdP must assert an `amr` MFA method. |
| `--mfa-step-up-window-secs` | `300` | Seconds after a TOTP proof during which high-risk endpoints accept the session as "stepped up" without re-prompting. Set to `0` to disable the step-up gate entirely (escape hatch — emits a startup `WARN`). |
| `--mfa-login-pending-secs` | `120` | Lifetime of the intermediate `mfa_pending_token` between password success and TOTP submission. The pending state lives in process memory and is lost on server restart. |

Each flag also accepts the matching `YUZU_MFA_*` environment variable.

#### Audit verbs

Every MFA state transition emits an audit row (`docs/user-manual/audit-log.md` lists the full vocabulary). The verbs are:

- `mfa.enroll.initiated` — secret generated, awaiting verify
- `mfa.enroll.required` — `POST /login` blocked an un-enrolled login under enforcement and issued an enrollment-pending token (PR 3)
- `mfa.enroll.verified` — first code accepted; enrollment is live (Settings or the `POST /login/mfa/enroll` bootstrap)
- `mfa.enroll.failed` — first code rejected (Settings or login bootstrap)
- `mfa.disabled` — operator or admin cleared the secret (`error` + detail `blocked: mfa_enforcement=<mode>` when the self-target guard refuses a disable under enforcement)
- `mfa.login.required` — `POST /login` returned a 202 pending challenge
- `mfa.login.verified` — `POST /login/mfa` TOTP accepted, session minted
- `mfa.login.failed` — `POST /login/mfa` rejected the code or the pending token
- `mfa.recovery_codes.generated` — 10 codes issued (enrollment or rotation)
- `mfa.recovery_code.used` — one code consumed on login
- `mfa.step_up.required` — high-risk endpoint returned a 401 because the session's MFA proof was stale (PR 2)
- `mfa.step_up.passed` — `POST /login/mfa/stepup` accepted, session's MFA proof refreshed (PR 2)
- `mfa.step_up.failed` — `POST /login/mfa/stepup` rejected the code (PR 2)
- `mfa.reset.breakglass` — MFA enrollment cleared via `yuzu-server --mfa-reset <username>`; principal is the OS account that ran the CLI (not an authenticated session). Written to `audit.db` even when the server is not running in serving mode (#1226)

`auth.login` is also emitted on every successful MFA login alongside `mfa.login.verified` / `mfa.recovery_code.used`, so SIEM rules keying on `auth.login` for session-creation parity stay correct across password, OIDC, and MFA flows.

#### Step-up on high-risk surfaces (PR 2)

Eleven REST + Settings endpoints (token mint/revoke, admin session revoke, software package create / deployment start, Guardian rule create/update/delete/push, user delete, user role change) require a fresh MFA proof on the calling session before the mutation lands. If the proof is older than `--mfa-step-up-window-secs`, the endpoint returns HTTP `401` with an A4 envelope:

```json
{
  "error": {
    "code": 401,
    "message": "MFA step-up required",
    "correlation_id": "req-...",
    "remediation": "POST /login/mfa/stepup with current TOTP code or a recovery code, then retry"
  },
  "meta": {
    "api_version": "v1",
    "mfa_step_up_required": true,
    "challenge_url": "/login/mfa/stepup"
  }
}
```

Dashboard HTMX flows auto-intercept this envelope and prompt the operator inline (no context-switch). Programmatic clients should:

1. Detect the 401 + `meta.mfa_step_up_required == true`.
2. POST `code=<6-digit TOTP or recovery code>` (form-encoded) to `meta.challenge_url` (`/login/mfa/stepup` by default) on the same session cookie.
3. On `200 OK`, retry the original request — the session is now "stepped up" for `--mfa-step-up-window-secs` seconds.

API token / MCP token principals **bypass step-up entirely** — the token itself was issued as a long-lived bearer credential through an authenticated session and does not re-prompt. Step-up applies to session-cookie principals only.

#### MFA on SSO sessions (PR 3)

OIDC/SSO sessions carry no local TOTP secret, so they cannot use `/login/mfa/stepup` (it returns `400` for an OIDC caller, pointing back to SSO). Instead, the step-up gate honours the IdP's RFC 8176 `amr` claim:

- If the IdP attested a multi-factor login (`amr` contains `mfa`, `otp`, `hwk`, `fpt`, `face`, `iris`, `sms`, `swk`, or `tel`), the session is treated as stepped-up. Once that proof ages past `--mfa-step-up-window-secs`, high-risk endpoints return `401` with `challenge_url=/auth/oidc/start` — the operator re-authenticates through SSO to refresh it.
- If the IdP did **not** attest MFA, the outcome depends on the enforcement mode, symmetric with how a local user is treated:
  - Under `optional` (or `admin-only` for a non-admin SSO user): the session **passes** the gate. Yuzu cannot mint a second factor for an externally-owned identity, so for the default posture MFA on SSO is the IdP's responsibility.
  - Under `required` (or `admin-only` for an admin SSO user): the session is **gated** — high-risk endpoints return `401` pointing to re-SSO. The operator required MFA for this principal, so an SSO login the IdP did not MFA must re-authenticate (just as a local `required` user is forced to enrol).

**Therefore, before turning on `--mfa-enforcement=required` (or `admin-only` for admin SSO users), configure your IdP to assert `amr` and verify it pre-flight** — otherwise those SSO users will be unable to reach high-risk endpoints (recoverable by restarting in `optional`; see the runbook). Under `optional`, no IdP `amr` configuration is required.

#### Login-time enrollment (PR 3)

Under `--mfa-enforcement=admin-only|required`, an un-enrolled login does not 200. `POST /login` (after a valid password) returns a second 202 variant distinguished by `status`:

```json
{"status":"mfa_enrollment_required","mfa_pending_token":"<opaque>","otpauth_uri":"otpauth://...","secret_base32":"...","expires_in":120}
```

The browser shows the QR / secret, the operator scans it, and posts the pending token + the first 6-digit code to **`POST /login/mfa/enroll`**, which confirms enrollment, mints an MFA-verified session cookie, and returns the one-time recovery codes:

```bash
curl -s -c cookies.txt -X POST http://localhost:8080/login/mfa/enroll \
  -d 'mfa_pending_token=<from-202>&code=123456'
# {"status":"ok","recovery_codes":["XXXX-XXXX-XXXX-XXXX", ...]}
```

The recovery codes are revealed **once** here, exactly as in Settings enrollment — save them before continuing. The endpoint shares the `/login` rate-limit bucket and the 5-attempt-per-pending cap. If `auth_db` is unavailable the enforced login fails closed (`503`) rather than minting an unprotected session.

### Logout

```bash
curl -s -b cookies.txt -X POST http://localhost:8080/logout
```

Returns `200 OK` with `{"status":"ok"}`. The session is invalidated server-side and the `yuzu_session` cookie is cleared via `Set-Cookie` with `Max-Age=0`.

### Session lifetime

Dashboard cookie sessions have an **absolute lifetime of 8 hours** from login. When this expires the operator is redirected to `/login`. Sessions are also invalidated server-side on logout, on session revocation (Settings → User Management → Revoke sessions, or "Sign out everywhere"), and on server restart.

An optional **idle (inactivity) timeout** can shorten this. When `--session-inactivity-secs` (`YUZU_SESSION_INACTIVITY_SECS`) is set to a positive value, a session idle longer than that window is invalidated server-side and the operator is prompted to log in again — regardless of the 8-hour absolute limit. The default `0` disables it (only the absolute lifetime applies). The window is **sliding**: any authenticated request resets it. Scope is **cookie sessions only** — API tokens and MCP tokens are never idle-timed-out, and OIDC users simply re-authenticate via SSO. A recommended hardened value is `900` (15 minutes).

See [Server Administration — CLI flags](server-admin.md) for configuration and `docs/auth-architecture.md` "Inactivity session timeout" for design detail.

### Auth Middleware Behavior

| Client type | Unauthenticated behavior |
|---|---|
| Page request (path does not start with `/api/` or `/events`) | 302 redirect to `/login` |
| API request (path starts with `/api/` or is `/events`) | `401 Unauthorized` with JSON error body `{"error":"unauthorized"}` |

The middleware distinguishes browser from API by request path, not by the `Accept` header.

## HTTPS

Enable TLS for the dashboard and REST API with CLI flags:

| Flag | Default | Description |
|---|---|---|
| `--https` | off | Enable HTTPS listener |
| `--https-port` | `8443` | HTTPS listen port |
| `--https-cert` | (required) | Path to PEM certificate file |
| `--https-key` | (required) | Path to PEM private key file |
| `--no-https-redirect` | off | Disable automatic HTTP-to-HTTPS redirect |

Example:

```bash
./yuzu-server \
  --https \
  --https-port 8443 \
  --https-cert /etc/yuzu/server.crt \
  --https-key /etc/yuzu/server.key
```

When `--https` is enabled, plain HTTP requests are redirected to HTTPS by default. Pass `--no-https-redirect` to serve both protocols independently.

```bash
# Verify HTTPS is working
curl -s --cacert /etc/yuzu/ca.crt https://localhost:8443/api/v1/me \
  -b cookies.txt
```

## OIDC Single Sign-On

Yuzu supports OpenID Connect with PKCE for browser-based SSO. This has been tested with Microsoft Entra ID (Azure AD) and should work with any compliant OIDC provider.

### Server Configuration

OIDC can be configured in two ways:

**Option 1: Dashboard Settings (recommended)**

Navigate to **Settings > Directory Integration / OIDC SSO** in the dashboard. Enter the issuer URL, client ID, client secret, and admin group ID. Click "Test Connection" to verify discovery, then "Save OIDC Configuration". Changes take effect immediately on the running server - but **only on the running server**. The provider is rebuilt at the next startup from the command-line or environment values, before the stored settings are read, and nothing rebuilds it afterwards. **If you configure OIDC only here, SSO stops working after the next restart** (the dashboard and `GET /api/config` will still show it as configured). Set the same values as CLI flags or environment variables per Option 2 as well, and see [Security hardening -> OIDC](security-hardening.md#oidc-hardening) before rotating a secret.

**Option 2: CLI flags**

| Flag | Description |
|---|---|
| `--oidc-issuer` | Issuer URL (e.g., `https://login.microsoftonline.com/{tenant}/v2.0`) |
| `--oidc-client-id` | Application (client) ID from the IdP |
| `--oidc-client-secret` | Client secret (required for Entra/Azure AD web apps) |
| `--oidc-redirect-uri` | Callback URL (auto-computed from the request `Host` header if omitted; must match IdP registration if set explicitly) |
| `--oidc-admin-group` | Entra group object ID that maps to the admin role (the value is trimmed automatically, same as `--saml-admin-group` — #1830) |
| `--oidc-skip-tls-verify` | Disable TLS cert verification for OIDC endpoints (insecure, dev only) |

Example startup:

```bash
./yuzu-server \
  --https --https-port 8443 \
  --https-cert /etc/yuzu/server.crt \
  --https-key /etc/yuzu/server.key \
  --oidc-issuer "https://login.microsoftonline.com/abcd1234-.../v2.0" \
  --oidc-client-id "11111111-2222-3333-4444-555555555555" \
  --oidc-client-secret "your-client-secret" \
  --oidc-redirect-uri "https://yuzu.example.com:8443/auth/callback" \
  --oidc-admin-group "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
```

### OIDC Login Flow

1. User clicks "Sign in with SSO" on the login page.
2. Browser is redirected to `GET /auth/oidc/start`, which generates a PKCE challenge and redirects to the IdP's authorization endpoint.
3. User authenticates at the IdP.
4. IdP redirects back to `GET /auth/callback` with an authorization code.
5. Server exchanges the code for tokens, validates the ID token, extracts claims, and creates a local session.

```
Browser           Yuzu Server               IdP (Entra ID)
  |                    |                          |
  |-- GET /auth/oidc/start -->                    |
  |                    |-- 302 authorize?... ---->|
  |                    |                          |
  |                    |          (user authenticates)
  |                    |                          |
  |                    |<--- 302 /auth/callback --|
  |<-- Set-Cookie -----|                          |
```

### Group-to-Role Mapping

When the IdP includes group claims (e.g., Entra ID `groups` claim), Yuzu checks whether the user belongs to the admin group specified by `--oidc-admin-group`. If the user's group list contains that group ID, they receive the `admin` role. Otherwise they receive the default `user` role.

Admin via OIDC is granted **only** through explicit membership in the configured admin group. Email and display name are **never** used to elevate privileges — they are attacker-controllable values, so a match against a local admin account's name does **not** grant admin (enforced in `create_oidc_session`).

> **Note:** Only a single admin group mapping is currently supported via the `--oidc-admin-group` CLI flag. Multi-role group mapping (e.g., mapping different groups to ITServiceOwner or Operator) is planned for a future release and will use the RBAC store's group-scoped role assignments.

### RBAC Group Provisioning (#1832)

Independently of the `--oidc-admin-group` admin mapping above, every OIDC login reconciles the IdP's `groups` claim into the RBAC store so that group-scoped role assignments take effect for SSO users. There is no dedicated group-membership UI — a group-scoped role grant is made via the management-group role-delegation API, `POST /api/v1/management-groups/{id}/roles`, whose `principal_id` field is free text: set `"principal_type": "group"` and `"principal_id": "entra:<group-id>"` to delegate `Operator` or `Viewer` to everyone the IdP asserts is in that group. Each asserted group is written as `entra:<group-id>` — **namespaced** by identity source, never the raw IdP group id — so a locally-created RBAC group can never collide with (or be impersonated by) a same-named IdP group.
>
> **Do not confuse the two forms.** `--oidc-admin-group` (the admin mapping above) matches against the **raw** IdP group object id as it appears in the token's `groups` claim — configure it with the raw id (e.g. `a1b2c3d4-…`), *not* the namespaced `entra:<id>` form, or admin elevation silently fails. Only group-scoped RBAC role delegation (`principal_id`) uses the namespaced `entra:<id>` form.

The reconcile also removes any of the user's `entra:`-owned memberships that the IdP no longer asserts, so a group removal on the IdP side takes effect on the user's **next SSO login** — memberships are **not** revoked mid-session; a live cookie session or already-issued API token retains its prior roles until re-authentication (residual, tracked in #1836 — the operator's manual mitigation in the interim is `DELETE /api/v1/sessions?username=<name>`, "Session lifetime" above). A malformed or oversized (`>200` groups) assertion, or a reconcile-store failure, denies the login outright rather than granting a session with stale roles.

**Entra group overage.** Once a user belongs to more groups than fit in the ID token (Entra's documented threshold is 200 groups), Entra omits the `groups` claim entirely and sends a `_claim_names`/`_claim_sources` indirection pointer instead. Reconciliation is **skipped** for that login — existing memberships are left exactly as they were, and the login still succeeds — rather than reading the resulting empty claim as "this user is in zero groups" and deleting every one of their existing memberships. A heavily-grouped legitimate user simply doesn't get their SSO-driven roles updated on an overaged login until Entra can report the full set (out-of-band group lookup, e.g. via Microsoft Graph, is not implemented in this release).

See the `auth.sso_group_provision` audit action (`docs/user-manual/audit-log.md`) for the full `result=ok|skipped|error` contract and detail-field shape.

> **Upgrade note:** Before this fix, OIDC groups were synced under their raw (un-namespaced) id, so an operator may have assigned an RBAC role directly to a group named e.g. `8f3c...` (the raw Entra group id). Those role assignments do **not** automatically move to the new namespaced group. **Re-assign any such role to `entra:<group-id>`** via the same `POST /api/v1/management-groups/{id}/roles` API — the old raw-id group row is left in place (harmless, but no longer reachable by future logins) and can be deleted once you've confirmed the namespaced group has the role.

> **Operational note (fail-closed):** a transient `rbac.db` failure during an OIDC login denies the login outright (no session minted) rather than granting one under unreconciled roles (`docs/auth-architecture.md` "RBAC group provisioning (#1832)"). This does not affect the break-glass/local-password path (`/login`, hardened-mode escape hatch): break-glass logins never call `/auth/callback` and so never touch RBAC group reconciliation.

### Entra ID Setup Checklist

1. Register an application in Entra ID (Azure Portal > App registrations).
2. Set the redirect URI to `https://yuzu.example.com:8443/auth/callback` (type: Web).
3. Create a client secret under Certificates & secrets.
4. Under Token configuration, add the `groups` optional claim to the ID token.
5. Grant `openid`, `profile`, and `email` API permissions.
6. Pass the tenant-specific issuer URL, client ID, secret, and admin group ID to the Yuzu server flags (`--oidc-issuer`, `--oidc-client-id`, `--oidc-client-secret`, `--oidc-admin-group`).

## SAML 2.0 SSO

Yuzu supports SAML 2.0 SP-initiated single sign-on against a single, statically-configured IdP. This is an alternative to OIDC for enterprises whose identity infrastructure requires SAML rather than OpenID Connect.

> **Platform note:** SAML is supported on Linux and macOS only. A Windows server logs an error at startup and does not enable SAML regardless of flag values. If you need SSO on Windows, use OIDC.

> **Role note:** SAML sessions default to `role=user`. Configure `--saml-group-attribute` + `--saml-admin-group` to promote users in a specific IdP-attested group to `role=admin` — see [SAML Group-to-Role Mapping](#saml-group-to-role-mapping) below. Leave both flags unset (the default) and every SAML session lands as `role=user`, same as prior releases. JIT elevation is still non-functional for SAML users regardless of role (the elevation check requires a local `auth.users` row, which SAML users do not have) — a SAML admin gets `role=admin` directly at login via group mapping, not via the elevation endpoint.

> **HTTPS required:** SAML uses a `Secure` browser-binding cookie (`__Host-yuzu_saml_bind`). Browsers silently drop `Secure` cookies over plain HTTP. SAML fails closed at startup when `--https-cert`/`--https-key` are not configured. Do not run SAML over HTTP.

> **MFA step-up:** MFA step-up is not supported for SAML sessions in this release. A SAML session hitting any of the 11 step-up-gated endpoints (token mint/revoke, session revoke, Guardian rule write, software deploy, user management) receives a `403` regardless of `--mfa-enforcement` mode. Use `--mfa-enforcement=optional` and rely on your IdP to enforce MFA at login time. Do not use `--mfa-enforcement=required` for SAML deployments — it denies SAML users at all step-up gates.

### Registering the SP with Your IdP

Before configuring the server, register Yuzu as a Service Provider with your identity provider:

1. **SP Entity ID** — a URI that identifies this Yuzu installation to the IdP (e.g. `https://yuzu.example.com`). You choose this value; it must be unique within the IdP's SP registry.
2. **ACS URL** — the Assertion Consumer Service URL where the IdP will POST the SAML response. This is `https://yuzu.example.com/saml/acs` (or the equivalent for your host and port). Set this as the ACS / reply URL in your IdP.
3. **Bindings** — configure the IdP to use **HTTP-Redirect** for the AuthnRequest and **HTTP-POST** for the response to the ACS.
4. **IdP signing certificate** — download or copy the IdP's assertion-signing certificate in PEM format and store it on the Yuzu server host (e.g. `/etc/yuzu/idp-signing.pem`, readable by the `yuzu` service account).

### Server Configuration

SAML is enabled via CLI flags (or the matching environment variables). All five flags (`--saml-idp-entity-id`, `--saml-idp-sso-url`, `--saml-idp-cert`, `--saml-sp-entity-id`, `--saml-sp-acs-url`) are validated at startup as one unit — supplying any subset produces a startup warning that names the missing flag, and SAML is disabled (fail-closed). A partial configuration never logs "SAML SP initialized".

| Flag | Env var | Description |
|---|---|---|
| `--saml-idp-entity-id` | `YUZU_SAML_IDP_ENTITY_ID` | Entity ID URI of the IdP (must match what the IdP uses in its assertions) |
| `--saml-idp-sso-url` | `YUZU_SAML_IDP_SSO_URL` | IdP's HTTP-Redirect SSO endpoint URL |
| `--saml-idp-cert` | `YUZU_SAML_IDP_CERT` | Path to the IdP signing certificate PEM file on the server host |
| `--saml-sp-entity-id` | `YUZU_SAML_SP_ENTITY_ID` | Entity ID URI this SP advertises to the IdP |
| `--saml-sp-acs-url` | `YUZU_SAML_SP_ACS_URL` | Full public URL of the ACS endpoint (`https://<host>/saml/acs`) |

Example startup:

```bash
./yuzu-server \
  --https --https-port 8443 \
  --https-cert /etc/yuzu/server.crt \
  --https-key  /etc/yuzu/server.key \
  --saml-idp-entity-id "https://idp.example.com/saml" \
  --saml-idp-sso-url   "https://idp.example.com/saml/sso" \
  --saml-idp-cert      /etc/yuzu/idp-signing.pem \
  --saml-sp-entity-id  "https://yuzu.example.com" \
  --saml-sp-acs-url    "https://yuzu.example.com/saml/acs"
```

### SAML Group-to-Role Mapping

Two additional flags, both optional and independent of the five required
SAML flags above, let you grant admin access via IdP-attested group
membership:

| Flag | Env var | Description |
|---|---|---|
| `--saml-group-attribute` | `YUZU_SAML_GROUP_ATTRIBUTE` | Name of the `<Attribute Name="...">` in the assertion's `<AttributeStatement>` whose `<AttributeValue>`s are group identifiers (e.g. Entra's `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups`) |
| `--saml-admin-group` | `YUZU_SAML_ADMIN_GROUP` | The single group value (from `--saml-group-attribute`) that grants `role=admin` |

When both flags are configured and the assertion's group list contains the
value in `--saml-admin-group`, the resulting session is `role=admin`.
Otherwise (including when either flag is left empty) the session is
`role=user` — the same default as prior releases.

Matching is **exact string equality only** — no wildcard, prefix, or regex
matching, and only a single admin group is supported (no multi-group /
multi-role mapping, same limitation as OIDC's `--oidc-admin-group`).

Admin via SAML is granted **only** through explicit membership in the
configured group. `NameID`, email, and display name are **never** used to
elevate privileges — mirrors the OIDC guard described above
(`create_oidc_session`) — and group values are read from the same
signature-verified assertion as `NameID`, so a forged or wrapped assertion
element cannot inject group membership that the IdP didn't attest to.

> **Configuring `--saml-admin-group` against a real IdP:**
>
> - The value must be the **exact identifier your IdP puts in the assertion**
>   — not a human-friendly display name. Entra ID, for example, sends group
>   **object ID GUIDs** (e.g. `4fb5b234-...`) in the group claim, not the
>   group's display name; configure the GUID, not "Admins".
> - Matching is **case-sensitive** — a value that differs only in case (or
>   has stray leading/trailing whitespace copy-pasted from a portal — the
>   admin-group value is trimmed automatically, but the group values inside
>   the assertion itself are compared as the IdP sent them) will not match.
> - **Entra ID "groups overage"**: a user who is a member of more than ~150
>   groups gets **no `groups` claim at all** in the assertion — Entra
>   substitutes a Graph API link instead. Such a user's assertion carries zero
>   group values, so `--saml-admin-group` can never resolve them to admin
>   regardless of actual group membership. Either keep the target admin's
>   group count under the overage threshold or use a dedicated,
>   low-membership group for the admin mapping.
> - At most **64 group values** from the configured attribute are considered
>   (a DoS guard); a value beyond the 64th is never evaluated.

Changing either flag requires a server restart to take effect (no hot-reload,
same as the other SAML flags).

> **Unlike OIDC, SAML group values are not synced into `rbac_store`:**
> SAML group values feed the admin/user role decision only; they are NOT
> synced into `rbac_store` (group-scoped RBAC role assignments do not apply
> to SAML principals) — deferred pending source-aware group resolution, see
> issue #1832.

### SAML Login Flow

1. The operator navigates directly to `GET /auth/saml/start`. There is no "Sign in with SAML" button on the login page in this release — the login-page SSO button for SAML is deferred.
2. The server generates a `<samlp:AuthnRequest>` and redirects the browser to the IdP via **HTTP-Redirect binding** (the request is deflate-compressed and URL-encoded in the `SAMLRequest` query parameter).
3. The operator authenticates at the IdP.
4. The IdP POSTs a `<samlp:Response>` containing a signed assertion to the ACS endpoint (`POST /saml/acs`) via **HTTP-POST binding**.
5. The server validates the assertion (signature, audience, recipient, expiry, and replay protection) and mints a session cookie on success.

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

The resulting session behaves identically to an OIDC session — it is subject to the same 8-hour absolute lifetime and the optional `--session-inactivity-secs` idle timeout. See [Session lifetime](#session-lifetime) for details.

### What Is and Is Not Supported

| Capability | Status |
|---|---|
| SP-initiated login (HTTP-Redirect AuthnRequest) | Supported |
| Signed assertion validation (pinned IdP cert) | Supported |
| Audience / recipient / expiry validation | Supported |
| Replay protection (`InResponseTo` single-use) | Supported |
| Group-to-role mapping | Supported — `--saml-group-attribute` + `--saml-admin-group`, exact-match only; both unset ⇒ all SAML users are `role=user` (see [SAML Group-to-Role Mapping](#saml-group-to-role-mapping)) |
| Admin access for SAML users | Supported via group mapping above; JIT elevation itself is still non-functional for SAML users (no local `users` row) — an admin session is granted directly at login, not via the elevation endpoint |
| Login-page SSO button | Not in this release — navigate directly to `GET /auth/saml/start` |
| MFA step-up at high-risk endpoints | Not supported — SAML sessions receive 403 at all step-up-gated endpoints regardless of `--mfa-enforcement`; rely on IdP MFA |
| `--auth-mode=sso-only` with SAML-only | Not supported — `sso-only` requires OIDC configuration; local-password login cannot be disabled with SAML alone |
| Multi-replica / HA without sticky sessions | Not supported — pending AuthnRequest state is in-process; configure load-balancer session affinity on `/auth/saml/start` and `/saml/acs` |
| AuthnRequest signing | Not in this release — the IdP must accept unsigned requests; use OIDC if the IdP requires signed requests |
| AttributeStatement parsing | Only the configured `--saml-group-attribute` is read (for group-to-role mapping); no other assertion attributes are stored or surfaced beyond `NameID` |
| IdP-metadata auto-fetch | Not in this release — cert and SSO URL are configured statically |
| IdP cert hot-reload | Not supported — update `--saml-idp-cert` and restart the server |
| Runtime reconfigure via dashboard | Not in this release — a server restart is required to change SAML flags |
| SP metadata endpoint | Not in this release — register the SP manually using the flag values |
| Windows | Not supported — SAML is Linux/macOS only |

## API Tokens

API tokens provide non-interactive authentication for scripts, CI/CD pipelines, and integrations. Tokens are passed as Bearer tokens and bypass the session/cookie mechanism.

### Creating a Token

Requires `ApiToken:Write` RBAC permission.

```bash
curl -s -b cookies.txt -X POST http://localhost:8080/api/v1/tokens \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ci-pipeline",
    "expires_at": 1750185000
  }'
```

The `expires_at` field is a Unix epoch timestamp in seconds. Pass `0` or omit it for a non-expiring token.

```json
{
  "data": {
    "token": "yuzu_Ab3xK9m2...",
    "name": "ci-pipeline"
  },
  "meta": {
    "api_version": "v1"
  }
}
```

The `token` field (prefixed `yuzu_`) is returned only at creation time. Store it securely.

### Using a Token

Pass the token in the `Authorization` header:

```bash
curl -s -H "Authorization: Bearer yuzu_Ab3xK9m2..." \
  http://localhost:8080/api/v1/me
```

Alternatively, use the `X-Yuzu-Token` header:

```bash
curl -s -H "X-Yuzu-Token: yuzu_Ab3xK9m2..." \
  http://localhost:8080/api/v1/me
```

API tokens are always granted full admin-level access. RBAC scoping for API tokens is planned for a future release.

### Listing Tokens

Requires `ApiToken:Read` RBAC permission. Returns tokens owned by the authenticated user.

```bash
curl -s -b cookies.txt http://localhost:8080/api/v1/tokens
```

```json
{
  "data": [
    {
      "token_id": "a1b2c3d4e5f6",
      "name": "ci-pipeline",
      "principal_id": "admin",
      "created_at": 1742383800,
      "expires_at": 1750185000,
      "last_used_at": 1742397720,
      "revoked": false
    }
  ],
  "pagination": {
    "total": 1,
    "start": 0,
    "page_size": 1
  },
  "meta": {
    "api_version": "v1"
  }
}
```

Timestamps are Unix epoch seconds. The plaintext token value is never returned after creation.


### Token Length Limits

For DoS protection, Yuzu enforces maximum token lengths:

| Token type | Max length | Behavior on exceed |
|---|---|---|
| Session tokens (`yuzu_session` cookie) | 64 hex chars | 401 Unauthorized |
| API tokens (Bearer or X-Yuzu-Token) | 256 chars | 401 Unauthorized |

Tokens exceeding these limits are rejected before any cryptographic operations, preventing resource exhaustion attacks.

### Service-Scoped Tokens

Service-scoped tokens are API tokens with an additional `scope_service` field that restricts the token holder to operations within a specific service boundary. These tokens cannot access admin routes and require RBAC to be enabled.

```bash
curl -s -b cookies.txt -X POST http://localhost:8080/api/v1/tokens \
  -H "Content-Type: application/json" \
  -d '{
    "name": "finance-svc-token",
    "scope_service": "finance",
    "expires_at": 1750185000
  }'
```

Service-scoped tokens:
- Cannot access any `/api/v1/admin/*` routes (403 Forbidden)
- Require RBAC to be enabled; rejected if RBAC is disabled (403 Forbidden)
- Must have `ITServiceOwner` role permission for the target operation
- Are scoped to agents tagged with the matching `service` tag

### Revoking a Token

Requires `ApiToken:Delete` RBAC permission. This performs a soft revoke (the token record remains but is marked revoked).

```bash
curl -s -b cookies.txt -X DELETE \
  http://localhost:8080/api/v1/tokens/a1b2c3d4e5f6
```

Returns `200 OK` with:

```json
{
  "data": {
    "revoked": true
  },
  "meta": {
    "api_version": "v1"
  }
}
```

Returns `404` if the token ID is not found. Returns `503 service unavailable` if the server's token store database failed to open at startup — a storage outage is never reported as `404` (see the API Tokens section of the [REST API reference](rest-api.md)).

## JIT Admin Elevation

To reduce **standing** privilege (SOC 2 CC6.3/CC6.6), an operator can hold a non-admin role day-to-day and **activate** admin **just-in-time** for a short, justified window — so a compromised everyday session is not a standing admin session. Two steps:

**1. An admin grants eligibility** (one-time, per operator):

```bash
curl -s -X POST -H "Cookie: yuzu_session=$ADMIN_COOKIE" \
  -H "Content-Type: application/json" -d '{"eligible":true}' \
  https://yuzu.example.com/api/v1/users/alice/elevation-eligibility
```

Eligibility is the per-user `users.elevation_eligible` flag — distinct from holding standing admin, and enumerable for access reviews. An admin **cannot** grant their own eligibility (another admin must). Revoking it (`{"eligible":false}`) immediately ends any elevation the user currently holds.

**2. The eligible operator elevates** when they need admin. A second factor is **mandatory** to elevate, regardless of `--mfa-enforcement` — but which second factor depends on how the operator signed in:

- **Local (password) sessions** must have **MFA enrolled** and are challenged for a fresh **TOTP code** via the shared step-up gate.
- **OIDC/SSO sessions** are NOT challenged for a TOTP code (a durable SSO identity has no local TOTP secret to check against — see "SSO operators" below) — the second factor is the **IdP-attested `amr` claim** captured at login.

```bash
curl -s -X POST -H "Cookie: yuzu_session=$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{"justification":"prod incident #42","duration_secs":600}' \
  https://yuzu.example.com/api/v1/elevate
# -> {"status":"ok","expires_in":598,"expires_at":"2026-07-02T13:10:00Z"}
```

`expires_in` is the TRUE remaining seconds computed after the grant (always `<=` the requested `duration_secs` — it is clamped to `--jit-max-elevation-secs` **and** to the session's own absolute lifetime, so it is never an exact echo of the request), and `expires_at` is the same window as a wall-clock RFC3339 UTC timestamp. The session is now admin for the window (capped by `--jit-max-elevation-secs`, default 1h). It **auto-reverts** when the window lapses, on logout, or on a server restart — the elevation is never persisted. Step down early with `POST /api/v1/elevate/revoke`. Every step (`role.elevation.granted`/`denied`/`revoked`/`expired`, `user.elevation_eligibility.set`) is audited — the `granted` row's detail records which factor was used (`mfa=local_totp` or `mfa=oidc_amr`). Technical invariants: `docs/auth-architecture.md` "JIT admin elevation".

### SSO operators

An OIDC/SSO operator elevates through the same two steps above, with the following differences:

- **Eligibility is granted on the durable, stable principal** — `oidc:<iss>#<sub>` (the IdP-issuer-scoped subject claim, never the display name) — via the **query form** of the eligibility endpoint, `POST /api/v1/users/elevation-eligibility?username=<principal>`, e.g.:

  ```bash
  curl -s -X POST -H "Cookie: yuzu_session=$ADMIN_COOKIE" \
    -H "Content-Type: application/json" -d '{"eligible":true}' \
    'https://yuzu.example.com/api/v1/users/elevation-eligibility?username=oidc:https://idp.example.com/%23sub-4821'
  ```

  The path form (`POST /api/v1/users/{username}/elevation-eligibility`) remains for local usernames only — an SSO principal contains `/` and `#`, which a path segment cannot carry (the server percent-decodes and strips the URL fragment before route matching), so it must use the query form instead.

  The operator must have **logged in at least once** before an admin can grant eligibility — first login auto-provisions a durable row for the principal (`AuthDB::upsert_sso_identity`); granting eligibility against a principal with no row yet **404s** ("user not found"), since the grant is an `UPDATE` against an existing row, not an `INSERT`.
- **The second factor is the IdP-attested `amr` claim**, captured on the OIDC session at login — never a local TOTP challenge. A session created from a login where the IdP did not assert `amr` is denied elevation unconditionally (`403`, "elevation requires an IdP-attested MFA proof"), independent of the `--mfa-enforcement` setting. Disabling `--jit-oidc-amr-elevation` (default enabled) turns OIDC JIT elevation off entirely — an OIDC session cannot fall back to a local TOTP step-up (its step-up challenge is re-authenticating via SSO), so operators must elevate from a local-authenticated session with local TOTP instead.
- **Finding the principal string**: Settings → Users lists every durable SSO identity with an **SSO** badge next to its row; the row's displayed name IS the `oidc:<iss>#<sub>` principal to use in the eligibility-grant URL above.
- **SAML operators cannot elevate today** — SAML carries no `amr`-equivalent claim, so a SAML session fails closed at the same MFA gate a non-MFA'd OIDC session would hit. SAML JIT elevation is a deferred workstream (see `docs/auth-architecture.md` "JIT admin elevation").
- **Cross-protocol identity-source scoping**: an elevation grant is scoped to the identity *source* that earned it, not just the principal string — the check is a **direct equality** between the session's own `auth_source` and the eligible row's `identity_source` (`local`↔`local`, `oidc`↔`oidc`, `saml`↔`saml`), not an "oidc-or-else-local" fallback. A local session can only spend a grant recorded against an `identity_source='local'` row; a SAML session (SAML JIT elevation is not yet provisioned — see below) would need an `identity_source='saml'` row, which no row carries today, so SAML fails closed at this gate too. This closes a theoretical collision where a crafted SAML NameID (or a legacy local row) shares a principal string with a real OIDC identity.

## MCP Tokens

MCP (Model Context Protocol) tokens are API tokens with an additional `mcp_tier` field that controls what the token holder can do through the MCP endpoint (`POST /mcp/v1/`). MCP tokens enable AI models and automation tools to interact with Yuzu's fleet management capabilities via JSON-RPC 2.0.

### Authorization Tiers

| Tier | Access |
|---|---|
| `readonly` | Read-only tools only (list agents, query audit log, check compliance, etc.) |
| `operator` | Read-only tools + tag writes + auto-approved instruction executions |
| `supervised` | All operations, but destructive actions require admin approval via the approval workflow |

Tier enforcement happens *before* RBAC checks. A tier can block an operation even when RBAC would permit it; conversely, if the tier permits but RBAC denies, the request is still blocked. Both layers must allow.

The `supervised` tier marks destructive operations as approval-gated, and the behaviour now depends on the transport. On the MCP `/mcp/v1/` transport these run through the **ticket-then-recall** approval flow: the first call mints a pending approval, and after an admin approves it, a recall carrying the `approval_id` executes the operation. On a non-MCP transport (the REST API) an approval-gated operation is denied with an `auth.approval_required` audit; only Reads and trivially-allowed operations succeed there.

### Creating an MCP Token

MCP tokens are created via the same `POST /api/v1/tokens` endpoint as regular API tokens, with the addition of the `mcp_tier` field. MCP tokens **require** an expiration date, with a maximum lifetime of 90 days.

```bash
curl -s -b cookies.txt -X POST http://localhost:8080/api/v1/tokens \
  -H "Content-Type: application/json" \
  -d '{
    "name": "claude-desktop-readonly",
    "mcp_tier": "readonly",
    "expires_at": 1750185000
  }'
```

```json
{

### MCP Token Restrictions

MCP tokens have the following restrictions:

- Cannot access admin-only routes (user management, settings) — 403 Forbidden regardless of creator's role
- The tier restricts which operations are permitted (`readonly` → read only; `operator` → read + tag writes + execute; `supervised` → all ops with approval workflow)
- If RBAC is enabled, the creator's actual RBAC role applies after the tier check
- If RBAC is disabled, the creator's legacy role (user/admin) applies after the tier check

  "data": {
    "token": "yuzu_Ab3xK9m2...",
    "name": "claude-desktop-readonly"
  },
  "meta": {
    "api_version": "v1"
  }
}
```

The `mcp_tier` field accepts `"readonly"`, `"operator"`, or `"supervised"`. If `expires_at` is omitted or set to `0` for an MCP token, the server rejects the request. Maximum expiration is 90 days from creation.

MCP tokens can also be created via the Settings UI under the API Tokens section, which provides an MCP tier dropdown when creating a new token.

### Using an MCP Token

Pass the token in the `Authorization` header when making JSON-RPC 2.0 requests to the MCP endpoint:

```bash
curl -s -X POST http://localhost:8080/mcp/v1/ \
  -H "Authorization: Bearer yuzu_Ab3xK9m2..." \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": { "name": "list_agents", "arguments": {} },
    "id": 1
  }'
```

### Server-Side Kill Switches

| Flag | Description |
|---|---|
| `--mcp-disable` | Reject all requests to `/mcp/v1/` with an error response |
| `--mcp-read-only` | Allow only read-only MCP tools regardless of the token's tier |

### Audit

Every MCP tool invocation is logged as an audit event with `action: "mcp.<tool_name>"` and includes the `mcp_tool` field on the `AuditEvent` record.


### Audit Log Actions

The following audit actions are emitted for authentication and authorization events:

| Action | Result | Description |
|---|---|---|
| `auth.admin_required` | `denied` | Token blocked from admin route (service-scoped, MCP, or non-admin) |
| `auth.permission_required` | `denied` | Token blocked from permission-gated operation |
| `auth.scoped_permission_required` | `denied` | Token blocked from agent-scoped operation |
| `auth.approval_required` | `denied` | Supervised-tier MCP token blocked from an approval-gated operation **on a non-MCP (REST) transport**. On the MCP `/mcp/v1/` transport there is no such denial — the operation runs through the ticket-then-recall approval flow (the first call mints JSON-RPC `-32006` `ApprovalRequired`; a recall with the approved `approval_id` executes). See `mcp.md`. |
| `auth.login` | `success` | Successful local password login |
| `auth.login_failed` | `failure` | Failed login attempt |
| `auth.logout` | `success` | User-initiated logout |
| `auth.oidc_login` | `success` | Successful OIDC SSO login |
| `auth.oidc_login_failed` | `failure` | Failed OIDC login attempt |
| `auth.saml_login` | `ok` | Successful SAML 2.0 SSO login |
| `auth.saml_login_failed` | `error` | Failed SAML login attempt (missing binding cookie, oversize body, missing SAMLResponse, or signature/audience/expiry/replay validation failure) |

All `denied` results include a `detail` field explaining the reason. Examples per action:
- `auth.admin_required` → `"MCP token blocked from admin route"`, `"service-scoped token blocked from admin route"`, `"non-admin user blocked from admin route"`
- `auth.permission_required` → `"MCP token tier 'readonly' does not allow Execution:Execute"`, `"RBAC denied Execution:Execute"`
- `auth.scoped_permission_required` → `"agent service 'X' does not match token scope 'Y'"`, `"MCP token tier 'readonly' does not allow Tag:Write"`
- `auth.approval_required` → audit detail `"MCP token tier 'supervised' requires approval for Execution:Execute on a non-MCP transport"`, client-facing message `"operation requires approval for this MCP tier on this transport"` — this is the **non-MCP (REST) path** (`auth_routes.cpp`). On the MCP `/mcp/v1/` transport there is no `auth.approval_required` denial: the ticket-then-recall approval flow handles the operation (`mcp_server.cpp`), so the MCP tool call mints `-32006` `ApprovalRequired` and a recall with the approved `approval_id` executes.

### JSON Error Envelope

All authentication and authorization errors use the standard JSON envelope:

```json
{
  "error": {
    "code": 403,
    "message": "service-scoped token does not grant Agent:Execute (ITServiceOwner permission required)"
  },
  "meta": {
    "api_version": "v1"
  }
}
```

HTTP status codes:
- `401 Unauthorized` — No valid authentication provided (missing/invalid token). Also returned when the token store itself is unavailable: authentication fails closed rather than revealing storage state. If valid tokens suddenly return `401`, check `/readyz` for `api_token_store` before rotating credentials.
- `403 Forbidden` — Authentication valid but operation not permitted (scope/tier/role restriction)
- `503 Service Unavailable` — Required backend unavailable: TagStore for scope verification, or the API token store database failed to open at startup (token CRUD routes)

## API Reference Summary

| Method | Endpoint | Auth required | Description |
|---|---|---|---|
| `POST` | `/login` | No | Authenticate with username/password; returns JSON `{"status":"ok"}` + session cookie |
| `POST` | `/logout` | Session | Invalidate current session; returns JSON `{"status":"ok"}` |
| `GET` | `/auth/oidc/start` | No | Begin OIDC PKCE login flow (302 redirect to IdP) |
| `GET` | `/auth/callback` | No | OIDC callback (IdP redirects here; creates session, 302 to `/`) |
| `GET` | `/auth/saml/start` | No | Begin SAML 2.0 SP-initiated login flow (302 redirect to IdP via HTTP-Redirect binding); Linux/macOS only |
| `POST` | `/saml/acs` | No | SAML Assertion Consumer Service — IdP POSTs the response here; validates and creates session; Linux/macOS only |
| `GET` | `/api/v1/me` | Any (session, Bearer, or X-Yuzu-Token) | Current user info and role |
| `POST` | `/api/v1/tokens` | RBAC `ApiToken:Write` | Create a new API token |
| `GET` | `/api/v1/tokens` | RBAC `ApiToken:Read` | List tokens owned by the authenticated user |
| `DELETE` | `/api/v1/tokens/{id}` | RBAC `ApiToken:Delete` | Revoke (soft-delete) an API token |
| `POST` | `/mcp/v1/` | Bearer token with MCP tier | MCP JSON-RPC 2.0 endpoint (22 read-only tools, 3 resources, 4 prompts) |

## Planned Features

| Feature | Phase | Status |
|---|---|---|
| AD/Entra directory sync (LDAP user/group import) | 7.5 | Stub |
