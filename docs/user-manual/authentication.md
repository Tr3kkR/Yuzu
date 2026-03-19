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

| Flag | Description |
|---|---|
| `--oidc-issuer` | Issuer URL (e.g., `https://login.microsoftonline.com/{tenant}/v2.0`) |
| `--oidc-client-id` | Application (client) ID from the IdP |
| `--oidc-client-secret` | Client secret (required for Entra/Azure AD web apps) |
| `--oidc-redirect-uri` | Callback URL (auto-computed from the request `Host` header if omitted; must match IdP registration if set explicitly) |
| `--oidc-admin-group` | Entra group object ID that maps to the admin role |

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

## Planned Features

| Feature | Phase | Status |
|---|---|---|
| AD/Entra directory sync (LDAP user/group import) | 7.5 | Stub |
