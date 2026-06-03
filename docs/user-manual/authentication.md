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

If a user loses both their authenticator and all 10 recovery codes, MFA must be cleared via direct database surgery on the server host. See `docs/ops-runbooks/auth-db-recovery.md` "Emergency MFA disable" for the procedure (admin force-disable via REST is planned for a future release).

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

Navigate to **Settings > Directory Integration / OIDC SSO** in the dashboard. Enter the issuer URL, client ID, client secret, and admin group ID. Click "Test Connection" to verify discovery, then "Save OIDC Configuration". Changes take effect immediately — no server restart required.

**Option 2: CLI flags**

| Flag | Description |
|---|---|
| `--oidc-issuer` | Issuer URL (e.g., `https://login.microsoftonline.com/{tenant}/v2.0`) |
| `--oidc-client-id` | Application (client) ID from the IdP |
| `--oidc-client-secret` | Client secret (required for Entra/Azure AD web apps) |
| `--oidc-redirect-uri` | Callback URL (auto-computed from the request `Host` header if omitted; must match IdP registration if set explicitly) |
| `--oidc-admin-group` | Entra group object ID that maps to the admin role |
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

If the OIDC user's email or display name matches a local admin account, they are also granted admin regardless of group membership.

> **Note:** Only a single admin group mapping is currently supported via the `--oidc-admin-group` CLI flag. Multi-role group mapping (e.g., mapping different groups to ITServiceOwner or Operator) is planned for a future release and will use the RBAC store's group-scoped role assignments.

### Entra ID Setup Checklist

1. Register an application in Entra ID (Azure Portal > App registrations).
2. Set the redirect URI to `https://yuzu.example.com:8443/auth/callback` (type: Web).
3. Create a client secret under Certificates & secrets.
4. Under Token configuration, add the `groups` optional claim to the ID token.
5. Grant `openid`, `profile`, and `email` API permissions.
6. Pass the tenant-specific issuer URL, client ID, secret, and admin group ID to the Yuzu server flags (`--oidc-issuer`, `--oidc-client-id`, `--oidc-client-secret`, `--oidc-admin-group`).

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

Returns `404` if the token ID is not found.

## MCP Tokens

MCP (Model Context Protocol) tokens are API tokens with an additional `mcp_tier` field that controls what the token holder can do through the MCP endpoint (`POST /mcp/v1/`). MCP tokens enable AI models and automation tools to interact with Yuzu's fleet management capabilities via JSON-RPC 2.0.

### Authorization Tiers

| Tier | Access |
|---|---|
| `readonly` | Read-only tools only (list agents, query audit log, check compliance, etc.) |
| `operator` | Read-only tools + tag writes + auto-approved instruction executions |
| `supervised` | All operations, but destructive actions require admin approval via the approval workflow |

Tier enforcement happens *before* RBAC checks. A tier can block an operation even when RBAC would permit it; conversely, if the tier permits but RBAC denies, the request is still blocked. Both layers must allow.

The `supervised` tier marks destructive operations as approval-gated. Until the Phase 2 approval re-dispatch path lands, supervised-tier writes are blocked on every transport (MCP JSON-RPC and REST API) with `auth.approval_required` audit; only Reads and trivially-allowed operations succeed.

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
| `auth.approval_required` | `denied` | Supervised-tier MCP token blocked from approval-gated operation (Phase 2 re-dispatch not yet implemented) |
| `auth.login` | `success` | Successful local password login |
| `auth.login_failed` | `failure` | Failed login attempt |
| `auth.logout` | `success` | User-initiated logout |
| `auth.oidc_login` | `success` | Successful OIDC SSO login |
| `auth.oidc_login_failed` | `failure` | Failed OIDC login attempt |

All `denied` results include a `detail` field explaining the reason. Examples per action:
- `auth.admin_required` → `"MCP token blocked from admin route"`, `"service-scoped token blocked from admin route"`, `"non-admin user blocked from admin route"`
- `auth.permission_required` → `"MCP token tier 'readonly' does not allow Execution:Execute"`, `"RBAC denied Execution:Execute"`
- `auth.scoped_permission_required` → `"agent service 'X' does not match token scope 'Y'"`, `"MCP token tier 'readonly' does not allow Tag:Write"`
- `auth.approval_required` → `"MCP token tier 'supervised' requires approval for Execution:Execute (Phase 2 not implemented)"`

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
- `401 Unauthorized` — No valid authentication provided (missing/invalid token)
- `403 Forbidden` — Authentication valid but operation not permitted (scope/tier/role restriction)
- `503 Service Unavailable` — Required backend (e.g., TagStore) unavailable for scope verification

## API Reference Summary

| Method | Endpoint | Auth required | Description |
|---|---|---|---|
| `POST` | `/login` | No | Authenticate with username/password; returns JSON `{"status":"ok"}` + session cookie |
| `POST` | `/logout` | Session | Invalidate current session; returns JSON `{"status":"ok"}` |
| `GET` | `/auth/oidc/start` | No | Begin OIDC PKCE login flow (302 redirect to IdP) |
| `GET` | `/auth/callback` | No | OIDC callback (IdP redirects here; creates session, 302 to `/`) |
| `GET` | `/api/v1/me` | Any (session, Bearer, or X-Yuzu-Token) | Current user info and role |
| `POST` | `/api/v1/tokens` | RBAC `ApiToken:Write` | Create a new API token |
| `GET` | `/api/v1/tokens` | RBAC `ApiToken:Read` | List tokens owned by the authenticated user |
| `DELETE` | `/api/v1/tokens/{id}` | RBAC `ApiToken:Delete` | Revoke (soft-delete) an API token |
| `POST` | `/mcp/v1/` | Bearer token with MCP tier | MCP JSON-RPC 2.0 endpoint (22 read-only tools, 3 resources, 4 prompts) |

## Planned Features

| Feature | Phase | Status |
|---|---|---|
| AD/Entra directory sync (LDAP user/group import) | 7.5 | Stub |
