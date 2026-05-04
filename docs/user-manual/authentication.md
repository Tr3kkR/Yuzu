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

On success the response is a `200 OK` with a JSON body `{"status":"ok"}` and a `Set-Cookie` header containing the `yuzu_session` token. The `cookies.txt` file now contains the session cookie. Use it on subsequent requests:

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
