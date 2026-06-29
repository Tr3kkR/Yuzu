# Yuzu REST API Reference

This document covers every HTTP endpoint exposed by the Yuzu server. Endpoints are grouped by functional area.

---

## API Versioning

The Yuzu REST API uses path-based versioning. Understanding the distinction between versioned and legacy endpoints is important for building stable integrations.

### Versioned API (`/api/v1/`)

All endpoints under the `/api/v1/` prefix are the **stable, versioned API**. These endpoints:

- Use the standard JSON envelope (`data`, `error`, `meta`, `pagination` fields)
- Return `"api_version": "v1"` in the `meta` object of every response
- Follow consistent error handling with structured error objects
- Are the recommended integration target for all new automation and tooling
- Will maintain backward compatibility within the v1 version; breaking changes will increment to v2

### Legacy API (`/api/` without version prefix)

Endpoints under `/api/` without the `v1` prefix are **legacy endpoints** that predate the versioned API. These endpoints:

- Remain available for backward compatibility
- Do **not** use the standard v1 JSON envelope
- May return inconsistent error formats
- Are **deprecated** and will be removed in a future major release
- Should be migrated to their v1 equivalents where available

### Migration Guidance

When writing new integrations, always use `/api/v1/` endpoints. If you have existing scripts using legacy endpoints, plan to migrate them to v1 equivalents. The [Legacy API Endpoints](#legacy-api-endpoints) section below documents each legacy endpoint and notes where a v1 replacement exists.

### Response Headers

Every API response (versioned and legacy) carries the standard Yuzu HTTP security response headers: `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and `Strict-Transport-Security` (HTTPS only). These headers add roughly 700–900 bytes per response — JSON consumers should expect this overhead. See [HTTP Security Response Headers](security-hardening.md#http-security-response-headers) for details, the full header list, and how to extend the CSP via `--csp-extra-sources` for browser dashboards that integrate with the Yuzu API.

#### `Sec-Audit-Failed` and the behavioural-PII audit posture

Routes that serve per-person behavioural / compliance PII (the `dex.device.view`, `dex.device.app_perf.view`, `guardian.device.view`, and `dex.signal.view` verbs) audit the access **before** serving. If that audit row cannot durably persist (audit DB locked/full, or an allocation failure), the gap is surfaced — never silently swallowed — but the posture differs by surface, by design:

- **REST JSON endpoints fail closed:** they return `503` + `Sec-Audit-Failed: true` and serve **no** data, so a machine integration (CMDB / ServiceNow / agentic worker) never records evidence-less PII as audited. Distinguish this transient, retryable `503` from a non-transient misconfiguration `503` by the presence of the `Sec-Audit-Failed` header.
- **Dashboard HTMX fragments set-and-proceed:** they set `Sec-Audit-Failed: true` but **still render**, so a transient audit hiccup never blanks a human operator's lens.
- **MCP tools set-and-proceed** with an `audit_persisted: false` field in the result (absent on success) — JSON-RPC has no response-header channel.

This is intentional cross-surface behaviour: during an audit-store blip a browsing operator sees data while a wired REST integration receives `503`. Alert on `Sec-Audit-Failed: true` (or `audit_persisted: false`) from any surface as a SOC 2 CC7.2 evidence-gap signal. (Mutating routes such as token/session revoke use the related `audit_emitted` body field — see those endpoints.)

---

## Table of Contents

- [API Versioning](#api-versioning)
- [Authentication](#authentication)
- [JSON Envelope](#json-envelope)
- [REST API v1 Endpoints](#rest-api-v1-endpoints)
  - [Current User](#current-user)
  - [Management Groups](#management-groups)
  - [API Tokens](#api-tokens)
  - [Sessions](#sessions)
  - [Quarantine](#quarantine)
  - [Internal CA](#internal-ca)
  - [RBAC](#rbac)
  - [Tags](#tags)
  - [Definitions](#definitions)
  - [Response Templates](#response-templates)
  - [Audit Log](#audit-log)
  - [Policy Fragments](#policy-fragments)
  - [Policies](#policies)
  - [Compliance](#compliance)
  - [Runtime Configuration](#runtime-configuration)
  - [Custom Properties](#custom-properties)
  - [Webhooks](#webhooks)
  - [Offload Targets](#offload-targets)
  - [Workflows](#workflows)
  - [OpenAPI Spec](#openapi-spec)
  - [Inventory](#inventory)
  - [Execution Statistics](#execution-statistics)
  - [Live-Query Bundles](#live-query-bundles)
  - [Device Tokens](#device-tokens)
  - [Software Deployment](#software-deployment)
  - [License Management](#license-management)
  - [Topology](#topology)
  - [Fleet Statistics](#fleet-statistics)
  - [File Retrieval](#file-retrieval)
  - [Guaranteed State](#guaranteed-state)
- [Legacy API Endpoints](#legacy-api-endpoints)
  - [Commands](#commands)
  - [Agents](#agents)
  - [Help](#help)
  - [Instructions](#instructions)
  - [Instruction Sets](#instruction-sets)
  - [Executions](#executions)
  - [Schedules](#schedules)
  - [Approvals](#approvals)
  - [Audit (Legacy)](#audit-legacy)
  - [Scope Engine](#scope-engine)
  - [Data Export](#data-export)
  - [Responses](#responses)
  - [Tags (Legacy)](#tags-legacy)
  - [Analytics and NVD](#analytics-and-nvd)
  - [SSE Event Stream](#sse-event-stream) — includes `GET /events`, `GET /sse/executions/{id}`, and the agentic `GET /api/v1/events`
  - [Dashboard TAR](#dashboard-tar)
- [MCP (Model Context Protocol)](#mcp-model-context-protocol)
- [Authentication Endpoints](#authentication-endpoints)
- [Health](#health)
- [Metrics](#metrics)

---

## Authentication

Every request must be authenticated using one of three methods:

| Method | Header / Cookie | Example |
|---|---|---|
| Session cookie | `yuzu_session` cookie | Set automatically after `POST /login` |
| Bearer token | `Authorization: Bearer <token>` | `Authorization: Bearer yzt_a1b2c3d4...` |
| X-Yuzu-Token header | `X-Yuzu-Token: <token>` | `X-Yuzu-Token: yzt_a1b2c3d4...` |

Unauthenticated browser requests are redirected to `/login`. Unauthenticated API requests receive a `401 Unauthorized` response.

API tokens are created via `POST /api/v1/tokens` and can be scoped to the creating user's permissions. The raw token value is returned exactly once at creation time.

---

## JSON Envelope

All REST API v1 responses use a standard JSON envelope.

**Success (single object):**

```json
{
  "data": { ... },
  "meta": { "api_version": "v1" }
}
```

**Success (list):**

```json
{
  "data": [ ... ],
  "pagination": {
    "total": 42,
    "start": 0,
    "page_size": 50
  },
  "meta": { "api_version": "v1" }
}
```

**Error:**

```json
{
  "error": {
    "code": 503,
    "message": "human-readable message"
  },
  "meta": { "api_version": "v1" }
}
```

HTTP status codes follow standard conventions: `200` for success, `201` for resource creation, `400` for bad requests, `401` for unauthenticated, `403` for forbidden, `404` for not found, `503` for service unavailable. All error responses include the structured error envelope shown above, with the `code` field matching the HTTP status.

Newer agentic-first surfaces enrich `error` with two optional fields: `correlation_id` (a `req-<hex>` token also echoed on the `X-Correlation-Id` response header, for joining the response to server logs/audit rows) and, on `401`/`403` denials from per-device scoped-permission gates, `permission` — the `"SecurableType:Operation"` the caller was denied (e.g. `"GuaranteedState:Read"`). These fields are **additive**; clients parsing only `code`/`message` are unaffected. They are not yet emitted on every denial path (the admin-only / unscoped gates still return the bare envelope — a tracked follow-up), so automation must treat `correlation_id`/`permission` as present-when-available, not guaranteed.

---

## REST API v1 Endpoints

All endpoints are under the `/api/v1/` prefix.

---

### Current User

#### `GET /api/v1/me`

Returns the authenticated user's identity and role.

**Permission:** Authenticated session (no specific RBAC permission required).

**Response:**

```json
{
  "data": {
    "username": "admin",
    "role": "admin"
  },
  "meta": { "api_version": "v1" }
}
```

---

### Management Groups

Management groups organize agents into a hierarchy for access scoping. Groups can be **static** (manually assigned members) or **dynamic** (membership determined by a scope expression evaluated against agent tags and properties).

#### `GET /api/v1/management-groups`

List all management groups.

**Permission:** `ManagementGroup:Read`

**Response:**

```json
{
  "data": [
    {
      "id": "a1b2c3d4e5f6",
      "name": "EU Production Servers",
      "description": "All production endpoints in EU datacenters",
      "parent_id": "",
      "membership_type": "static",
      "scope_expression": "",
      "created_by": "admin",
      "created_at": 1710849600,
      "updated_at": 1710849600
    },
    {
      "id": "f6e5d4c3b2a1",
      "name": "Windows Desktops",
      "description": "Dynamic group for all Windows endpoints",
      "parent_id": "",
      "membership_type": "dynamic",
      "scope_expression": "os = 'windows'",
      "created_by": "admin",
      "created_at": 1710850000,
      "updated_at": 1710850000
    }
  ],
  "pagination": { "total": 2, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

---

#### `POST /api/v1/management-groups`

Create a new management group.

**Permission:** `ManagementGroup:Write`

**Request body:**

```json
{
  "name": "EU Production Servers",
  "description": "All production endpoints in EU datacenters",
  "parent_id": "",
  "membership_type": "static",
  "scope_expression": ""
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | Yes | Unique group name |
| `description` | string | No | Human-readable description |
| `parent_id` | string | No | ID of parent group (empty for root) |
| `membership_type` | string | No | `"static"` (default) or `"dynamic"` |
| `scope_expression` | string | No | Scope engine expression for dynamic groups |

**Response (201):**

```json
{
  "data": { "id": "a1b2c3d4e5f6" },
  "meta": { "api_version": "v1" }
}
```

---

#### `GET /api/v1/management-groups/{id}`

Get a single group's details including its current members.

**Permission:** `ManagementGroup:Read`

**Response:**

```json
{
  "data": {
    "id": "a1b2c3d4e5f6",
    "name": "EU Production Servers",
    "description": "All production endpoints in EU datacenters",
    "parent_id": "",
    "membership_type": "static",
    "scope_expression": "",
    "created_by": "admin",
    "created_at": 1710849600,
    "updated_at": 1710849600,
    "members": [
      {
        "agent_id": "agent-eu-prod-01",
        "source": "static",
        "added_at": 1710850000
      },
      {
        "agent_id": "agent-eu-prod-02",
        "source": "static",
        "added_at": 1710850100
      }
    ]
  },
  "meta": { "api_version": "v1" }
}
```

---

#### `PUT /api/v1/management-groups/{id}`

Update a management group. Only the fields provided in the request body are changed; omitted fields retain their current values.

**Permission:** `ManagementGroup:Write`

**Request body:**

```json
{
  "name": "EU Production Servers (Renamed)",
  "description": "Updated description",
  "parent_id": "f6e5d4c3b2a1",
  "membership_type": "dynamic",
  "scope_expression": "os = 'linux' AND tag:environment = 'production'"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | No | New group name (must be unique) |
| `description` | string | No | Updated description |
| `parent_id` | string | No | New parent group ID (empty string for root-level) |
| `membership_type` | string | No | `"static"` or `"dynamic"` |
| `scope_expression` | string | No | Scope engine expression for dynamic groups |

**Validation rules:**

- The root group (`000000000000`, "All Devices") cannot be re-parented. Attempting to set `parent_id` on the root group returns `400`.
- **Self-parent:** A group cannot be set as its own parent. Returns `400`.
- **Cycle detection:** The new parent must not be a descendant of the group being updated. Moving a group under one of its own children would create a circular hierarchy and returns `400`.
- **Depth limit:** Re-parenting must not exceed the maximum hierarchy depth of 5 levels. Returns `400` if exceeded.

All validation runs at the `ManagementGroupStore` layer as well as the REST handler, so non-REST administrative callers cannot bypass cycle or depth checks.

**Response:**

```json
{
  "data": { "updated": true },
  "meta": { "api_version": "v1" }
}
```

**Error (400) -- cycle detected:**

```json
{
  "error": "re-parenting would create a cycle",
  "meta": { "api_version": "v1" }
}
```

**Error (400) -- self-parent:**

```json
{
  "error": "group cannot be its own parent",
  "meta": { "api_version": "v1" }
}
```

**Error (400) -- depth exceeded:**

```json
{
  "error": "maximum hierarchy depth (5) exceeded",
  "meta": { "api_version": "v1" }
}
```

**Error (400) -- root group re-parent:**

```json
{
  "error": "cannot re-parent root group",
  "meta": { "api_version": "v1" }
}
```

---

#### `DELETE /api/v1/management-groups/{id}`

Delete a management group. The root group ("All Devices", ID `000000000000`) cannot be deleted and returns `403 Forbidden`. Deleting a group cascade-deletes all child groups, their membership records, and their role assignments.

**Permission:** `ManagementGroup:Delete`

**Response:**

```json
{
  "data": { "deleted": true },
  "meta": { "api_version": "v1" }
}
```

**Error (403) -- root group:**

```json
{
  "error": "cannot delete root group",
  "meta": { "api_version": "v1" }
}
```

---

#### `POST /api/v1/management-groups/{id}/members`

Add an agent to a static management group.

**Permission:** `ManagementGroup:Write`

**Request body:**

```json
{
  "agent_id": "agent-eu-prod-03"
}
```

**Response (201):**

```json
{
  "data": { "added": true },
  "meta": { "api_version": "v1" }
}
```

---

#### `DELETE /api/v1/management-groups/{id}/members/{agent_id}`

Remove an agent from a management group.

**Permission:** `ManagementGroup:Write`

**Response:**

```json
{
  "data": { "removed": true },
  "meta": { "api_version": "v1" }
}
```

---

#### `GET /api/v1/management-groups/{id}/roles`

List role assignments scoped to this management group.

**Permission:** `ManagementGroup:Read`

**Response:**

```json
{
  "data": [
    {
      "group_id": "a1b2c3d4e5f6",
      "principal_type": "user",
      "principal_id": "jane.ops",
      "role_name": "Operator"
    },
    {
      "group_id": "a1b2c3d4e5f6",
      "principal_type": "user",
      "principal_id": "bob.viewer",
      "role_name": "Viewer"
    }
  ],
  "meta": { "api_version": "v1" }
}
```

---

#### `POST /api/v1/management-groups/{id}/roles`

Assign a role to a principal within this management group. Only the `Operator` and `Viewer` roles can be delegated. The caller must be a global Administrator or hold the `ITServiceOwner` role on this group.

**Permission:** Global `ManagementGroup:Write` or `ITServiceOwner` on this group.

**Request body:**

```json
{
  "principal_type": "user",
  "principal_id": "jane.ops",
  "role_name": "Operator"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `principal_type` | string | No | `"user"` (default) or `"group"` |
| `principal_id` | string | Yes | Username or group name |
| `role_name` | string | Yes | `"Operator"` or `"Viewer"` only |

**Response (201):**

```json
{
  "data": { "assigned": true },
  "meta": { "api_version": "v1" }
}
```

**Error (403) -- non-delegatable role:**

```json
{
  "error": "only Operator and Viewer roles can be delegated",
  "meta": { "api_version": "v1" }
}
```

---

#### `DELETE /api/v1/management-groups/{id}/roles`

Remove a role assignment from this management group.

**Permission:** Global `ManagementGroup:Write` or `ITServiceOwner` on this group.

**Request body:**

```json
{
  "principal_type": "user",
  "principal_id": "jane.ops",
  "role_name": "Operator"
}
```

**Response:**

```json
{
  "data": { "unassigned": true },
  "meta": { "api_version": "v1" }
}
```

---

### API Tokens

API tokens provide non-interactive authentication for scripts and automation. Tokens are scoped to the creating user's permissions. The raw token string is returned exactly once at creation time and cannot be retrieved afterward.

**Storage failure:** if the server's token store database failed to open at startup (bad data directory, permissions), all three token endpoints return `503` with message `service unavailable` rather than `404` or an empty list, so automation can distinguish a server-side outage from a missing token. Note that Bearer-token *authentication* against an unavailable token store deliberately fails closed with `401`, not `503` — an automation client seeing unexpected `401`s during an outage should check server health (`/readyz` reports `api_token_store`) before rotating credentials.

#### `GET /api/v1/tokens`

List the current user's API tokens. Raw token values are never returned.

**Permission:** `ApiToken:Read`

**Response:**

```json
{
  "data": [
    {
      "token_id": "a1b2c3d4",
      "name": "CI Pipeline Token",
      "principal_id": "admin",
      "created_at": 1710849600,
      "expires_at": 1742385600,
      "last_used_at": 1710936000,
      "revoked": false
    }
  ],
  "pagination": { "total": 1, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

---

#### `POST /api/v1/tokens`

Create a new API token. The raw token is returned in the response and is never shown again. Store it immediately.

**Permission:** `ApiToken:Write`

**Request body:**

```json
{
  "name": "CI Pipeline Token",
  "expires_at": 1742385600,
  "mcp_tier": "readonly"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | Yes | Human-readable label |
| `expires_at` | integer | No | Unix epoch seconds. `0` or omitted = never expires. **Required** for MCP tokens (max 90 days). |
| `mcp_tier` | string | No | MCP authorization tier: `"readonly"`, `"operator"`, or `"supervised"`. Omit for standard API tokens. When set, `expires_at` is mandatory. |

**Response (201):**

```json
{
  "data": {
    "token": "yzt_a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef12345678",
    "name": "CI Pipeline Token"
  },
  "meta": { "api_version": "v1" }
}
```

> **Warning:** Copy the `token` value immediately. It cannot be retrieved after this response.

---

#### `DELETE /api/v1/tokens/{token_id}`

Revoke an API token. The token becomes immediately unusable.

**Permission:** `ApiToken:Delete`

**Ownership constraint:** A caller with `ApiToken:Delete` may only revoke tokens they created. The global `admin` role is the sole bypass and may revoke any token. Attempting to revoke another user's token returns `404 token not found` — identical to the response for a token that does not exist — so the endpoint cannot be used as an enumeration oracle by a non-owner with `ApiToken:Delete`. Denied attempts are recorded in the audit log with `action=api_token.revoke`, `result=denied`, and `detail=owner=<real owner>` so forensics can distinguish a probe from a legitimate self-revoke.

The same ownership constraint applies to the HTMX dashboard path `DELETE /api/settings/api-tokens/{token_id}`.

**Response:**

```json
{
  "data": { "revoked": true },
  "meta": { "api_version": "v1" }
}
```

**Error (404) -- token not found or not owned by caller:**

```json
{
  "error": {
    "code": 404,
    "message": "token not found"
  },
  "meta": { "api_version": "v1" }
}
```

---

### Sessions

Operator and dashboard sessions are the cookie-based sessions issued by `POST /login`. The endpoints below let an admin force-log-out another user from every device, and let any authenticated principal sign out of every browser at once. They are the SOC 2 CC6.3 (revocation) and CC6.8 (termination) evidence path; both endpoints emit auditable actions distinguishable by SIEM correlation.

The DB primitive (`AuthDB::invalidate_all_sessions`) and the in-memory counterpart already fire when a user is removed (`DELETE /api/settings/users/{username}`) or when their role changes; these REST endpoints expose the same primitive standalone for incident response and operator self-service.

#### `DELETE /api/v1/sessions?username=<name>`

Revoke every active cookie session for a named user. The user remains valid (no role change, no account disable); they simply have to authenticate again to obtain a new session cookie. **API tokens belonging to the user are deliberately NOT revoked** — operators force-logging out a leaked cookie session typically want to leave CI/CD and automation tokens running. Use `DELETE /api/v1/tokens/{token_id}` (or the user's own `DELETE /api/v1/sessions/me`) to revoke those.

**Permission:** `UserManagement:Write`

**Self-target behaviour.** An admin invoking this with their own username is permitted (signing yourself out of every device is recoverable — re-authenticate and you are back), but the audit row is recorded as `session.revoke_all.self` instead of `session.revoke_all` so SIEM rules can split operator self-service from a sibling-admin force-logout. This is a deliberately weaker guard than the `#397/#403` self-target guard on `DELETE /api/settings/users/{username}`, which exists to prevent admin-role self-lockout (an unrecoverable state).

**Example:**

```bash
curl -s -X DELETE \
  -H "Authorization: Bearer $TOKEN" \
  "https://yuzu.example.com/api/v1/sessions?username=alice"
```

**Response (200):**

```json
{
  "data": {
    "username": "alice",
    "revoked": 2,
    "db_persisted": true,
    "audit_emitted": true
  },
  "meta": { "api_version": "v1" }
}
```

`revoked` is the number of in-memory session cookies wiped. `db_persisted` reports whether the AuthDB DELETE for persisted session rows succeeded; when `false`, the audit row is recorded with `result="partial"` and `detail` carries `db_error=true`. A `false` value indicates the operator should retry or restart the server — server restart will otherwise resurrect any persisted rows that were not deleted.

`audit_emitted` reports whether the SOC 2 CC6.6 audit row landed in the audit store. When `false` the response also sets the `Sec-Audit-Failed: true` header — SREs scraping for evidence-integrity gaps should alert on either signal. The revoke side-effect still completes when `audit_emitted=false` (operator's "stop NOW" intent is honoured); only the SOC 2 evidence chain is degraded for that request. This split was introduced in PR #883 (HIGH-2) to close a silent-failure window where a locked audit DB or disk-full condition produced a 200 OK that masqueraded as full evidence.

**Audit:** successful cross-user invocations emit `session.revoke_all` with `target_type=User`, `target_id=<username>`, and `detail=count=<N>` (or `count=<N> db_error=true` on partial failure). When the caller's own username is supplied, the action is `session.revoke_all.self` instead.

The admin route emits two distinct 400 bodies — operators scripting the endpoint should distinguish them.

**Error (400) -- missing `username` query parameter:**

```json
{
  "error": { "code": 400, "message": "username query parameter required" },
  "meta": { "api_version": "v1" }
}
```

**Error (400) -- malformed `username` value:**

```json
{
  "error": { "code": 400, "message": "invalid username format" },
  "meta": { "api_version": "v1" }
}
```

The `username` parameter is validated with the same character set used at user creation (`is_valid_username`). NUL bytes, control characters, and newlines are rejected — passing them through to the SQL bind would silently truncate at the NUL while the audit log records the full string, producing a target/effect mismatch (sec-H1). A 400 with the `invalid username format` message indicates the client has malformed input; retrying with the same value will not succeed.

**Error (403) -- caller lacks `UserManagement:Write`:**

```json
{
  "error": { "code": 403, "message": "forbidden" },
  "meta": { "api_version": "v1" }
}
```

#### `DELETE /api/v1/sessions/me`

Self-revoke "Sign out everywhere". Wipes every cookie session belonging to the authenticated caller AND revokes every API token they own. This is intended as the lost-device recovery flow: every credential bearing the caller's identity is killed in one call.

**Permission:** Any interactive authenticated session (cookie). MCP-tier tokens and service-scoped automation tokens are explicitly rejected with 403 — those credential classes have no other write privilege and accepting them here would create a novel DoS surface against the human owner. Use the dashboard or a fresh password-authenticated session.

**Example:**

```bash
curl -s -X DELETE \
  -H "Cookie: yuzu_session=$COOKIE" \
  "https://yuzu.example.com/api/v1/sessions/me"
```

**Response (200):**

```json
{
  "data": {
    "revoked": 3,
    "api_tokens_revoked": 2,
    "db_persisted": true,
    "audit_emitted": true
  },
  "meta": { "api_version": "v1" }
}
```

The response sets `Set-Cookie: yuzu_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0` so the client side completes the revocation by deleting the cookie from the browser jar. `audit_emitted` and the `Sec-Audit-Failed: true` header have the same semantics as on the admin route above — `false` means the revoke completed but the audit row was lost (locked DB / disk full / pipeline exception), and the SOC 2 CC6.6 evidence chain is degraded for that request.

**Error (403) -- non-interactive credential:**

The caller authenticated with an MCP-tier token (`X-Yuzu-Token` carrying a non-empty `mcp_tier`) or a service-scoped token. The denial is audited as `session.revoke_all.self` with `result=denied`.

```json
{
  "error": {
    "code": 403,
    "message": "self-revoke requires an interactive session, not an API token"
  },
  "meta": { "api_version": "v1" }
}
```

**Audit:** every successful invocation emits `session.revoke_all.self` with `target_type=User`, `target_id=<caller>`, `detail=count=<N> api_tokens_revoked=<M>` (with `db_error=true` appended on partial failure). The dashboard's "Sign out everywhere" button on the operator's own row in Settings → Users uses this endpoint and follows up with a redirect to `/login`.

---

### Users

#### `POST /api/v1/users/{username}/unlock`

Clear a user's account-lockout counter. After `--auth-lockout-threshold` consecutive failed local-password logins an account is temporarily locked (SOC 2 CC6.3 — see the [account-lockout flags](server-admin.md#server-cli-flags) in the server-admin guide). The lock already auto-expires after `--auth-lockout-window-secs`; this endpoint is the operability path for an admin who needs to restore access immediately (e.g. a locked-out VIP who can't wait out the window).

**Permission:** `UserManagement:Write` (plus MFA step-up when MFA is enrolled — parity with `DELETE /api/v1/sessions`).

**Self-target behaviour.** An admin invoking this with their own username is permitted — clearing your own lockout is recoverable. This is the same weaker-than-`#397/#403` guard reasoning as `DELETE /api/v1/sessions`.

**Body:** none.

**Example:**

```bash
curl -s -X POST \
  -H "Cookie: yuzu_session=$COOKIE" \
  "https://yuzu.example.com/api/v1/users/alice/unlock"
```

**Response (200):**

```json
{
  "data": {
    "username": "alice",
    "unlocked": true,
    "audit_emitted": true
  },
  "meta": { "api_version": "v1" }
}
```

`audit_emitted` and the `Sec-Audit-Failed: true` header have the same semantics as the session-revoke routes above — `false` means the unlock completed but the audit row was lost, degrading the CC6.3 evidence chain for that request.

**Errors:** `400` — username empty or malformed (e.g. contains a reserved `:`); `403` — caller lacks `UserManagement:Write` or failed MFA step-up; `500` — the `auth.db` write failed (a best-effort `auth.lockout.cleared`/`error` audit is still attempted); `503` — the lockout subsystem is not wired (no `AuthDB`).

**Audit:** a successful unlock emits `auth.lockout.cleared` with `result=ok`, `target_type=User`, `target_id=<username>`, `detail=admin_unlock`. A failed write emits the same verb with `result=error`. Note that a lockout cleared automatically (no operator action) emits `auth.lockout.cleared` with `result=ok` and `detail=reset_on_successful_login` when the user next logs in successfully; the threshold crossing itself emits `auth.lockout.applied`. These two verbs are the durable CC6.3 evidence; blocked-while-locked attempts are tracked only via the `yuzu_auth_lockout_blocked_total` metric (no per-attempt audit row **or** analytics event) to avoid amplification under a sustained brute-force.

---

### Quarantine

Quarantine isolates a device from receiving commands or participating in normal operations. Quarantined devices remain connected but are blocked from instruction execution.

#### `GET /api/v1/quarantine`

List all currently quarantined devices.

**Permission:** `Security:Read`

**Response:**

```json
{
  "data": [
    {
      "agent_id": "agent-compromised-01",
      "status": "active",
      "quarantined_by": "admin",
      "quarantined_at": 1710849600,
      "whitelist": "10.0.1.50,10.0.1.51",
      "reason": "Suspicious network activity detected"
    }
  ],
  "pagination": { "total": 1, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

---

#### `POST /api/v1/quarantine`

Quarantine a device.

**Permission:** `Security:Execute`

**Request body:**

```json
{
  "agent_id": "agent-compromised-01",
  "reason": "Suspicious network activity detected"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `agent_id` | string | Yes | Target device ID |
| `reason` | string | No | Human-readable reason for quarantine |
| `whitelist` | string | No | Comma-separated IPs still allowed to communicate |

**Response (201):**

```json
{
  "data": { "quarantined": true },
  "meta": { "api_version": "v1" }
}
```

---

#### `DELETE /api/v1/quarantine/{agent_id}`

Release a device from quarantine.

**Permission:** `Security:Execute`

**Response:**

```json
{
  "data": { "released": true },
  "meta": { "api_version": "v1" }
}
```

---

### Internal CA

The server's built-in certificate authority (see `docs/pki-architecture.md`) can
be managed via the **Settings → Internal CA** dashboard panel or the REST
endpoints below. `root` and `crl` are **public** (clients and browsers need
them to establish trust / check revocation before they have a session); the
inventory and revoke endpoints are gated by the `Security` securable.

> Note on `Security` operations: certificate **revocation** uses `Security:Delete`
> (a destructive operation on an issued cert), while device **quarantine** uses
> `Security:Execute`. A custom role scoped to security operations needs both.

#### `GET /api/v1/ca/root`

Download the CA root certificate (PEM) and add it to an OS/browser trust store.
**Public** — no authentication. Returns `Content-Type: application/x-pem-file`,
`Content-Disposition: attachment; filename="yuzu-ca.pem"`,
`Cache-Control: public, max-age=86400`. `404` if no CA root exists.

```bash
curl https://yuzu.example.com/api/v1/ca/root -o yuzu-ca.pem
openssl x509 -in yuzu-ca.pem -noout -fingerprint -sha256
```

#### `GET /api/v1/ca/crl`

Download the current certificate revocation list (DER). **Public** — no
authentication. Returns `Content-Type: application/pkix-crl`,
`Cache-Control: no-cache, must-revalidate`. `503` if no CRL has been published
yet (transient — the server pre-publishes at startup and republishes on each
revocation).

```bash
curl https://yuzu.example.com/api/v1/ca/crl -o yuzu.crl
openssl crl -inform DER -in yuzu.crl -noout -text
```

#### `GET /api/v1/ca/issued`

List certificates issued by the internal CA. **Permission:** `Security:Read`.
Query params `limit` (1–1000, default 200) and `offset` (default 0). The full
certificate PEM and enrollment reference are intentionally omitted.

`meta.has_more` is `true` when more rows exist beyond the current page; when it is,
`meta.next_offset` carries the `offset` to pass for the next page. Iterate until
`has_more` is `false` (do **not** infer end-of-list from `count < limit`).

```json
{
  "items": [
    {
      "serial_hex": "3A4B5C6D...",
      "subject": "agent-prod-01",
      "san": "URI:yuzu://<ca-fp>/agent/agent-prod-01",
      "purpose": "agent",
      "status": "active",
      "not_after": 1780000000,
      "issued_at": 1710849600,
      "issued_by": "agent:agent-prod-01"
    }
  ],
  "count": 1,
  "meta": { "api_version": "v1", "limit": 200, "offset": 0, "has_more": false }
}
```

The MCP `list_issued_certs` tool mirrors this contract (same `has_more` / `next_offset`).

#### `POST /api/v1/ca/revoke`

Revoke a certificate by serial. **Permission:** `Security:Delete`. Revocation
takes effect server-side **immediately** (the mTLS accept gate reads `ca.db`, not
the CRL); the CRL is then republished. Request body (max 64 KB):

```json
{ "serial_hex": "3A4B5C6D...", "reason": "key compromise" }
```

`serial_hex` is required (1–64 hex digits, case-insensitive). Unknown JSON fields
are rejected. Response:

```json
{ "revoked": true, "serial_hex": "3A4B5C6D...", "crl_republished": true, "meta": { "api_version": "v1" } }
```

`crl_republished: false` means the revocation stands (the agent is refused on its
next gRPC call) but the public CRL could not be rebuilt — external CRL consumers
will not see it until the next successful publish. Errors: `400` (missing/invalid
serial, unknown field, bad JSON), `403` (missing `Security:Delete`), `404` (serial
not found or already revoked), `413` (body too large), `503` (CA unavailable).

#### Subordinate-CA (root your CA in an enterprise PKI)

By default Yuzu's CA is a self-signed install root (`trust mode: built-in`). An
enterprise can instead make Yuzu's issuing CA a **subordinate** of its own root,
so every Yuzu-issued certificate chains to the corporate trust anchor. The
issuing **key never changes** — the enterprise signs Yuzu's *existing* public
key — so certificates already issued keep validating across the switch.

Workflow:

1. **Export** Yuzu's CA signing request and have your enterprise root sign it as
   a subordinate CA (the signed cert **must** carry `basicConstraints: CA:TRUE`,
   `keyUsage: keyCertSign, cRLSign`).
2. **Import** the signed intermediate plus the parent chain (enterprise root and
   any intermediates above Yuzu's).

This is also available in **Settings → Internal CA → "Subordinate this CA…"**.

#### `GET /api/v1/ca/root-csr`

Export the install CA's PKCS#10 CSR (PEM), over its existing key, for an
enterprise root to sign. **Permission:** `Security:Read`. The CSR carries only
the CA's public key (already public via `GET /api/v1/ca/root`) and subject — no
secret. Audited (`ca.root_csr.exported`).

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://yuzu.example.com/api/v1/ca/root-csr -o yuzu-ca.csr
# → hand yuzu-ca.csr to your enterprise CA; it returns a signed intermediate.
```

Errors: `403` (missing `Security:Read`), `500` (CSR generation failed), `503`
(CA unavailable).

#### `POST /api/v1/ca/import-chain`

Import the enterprise-signed intermediate + parent chain, switching the issuing
identity to subordinate mode. **Permission:** `Security:Write`. Request body
(max 256 KB):

```json
{
  "intermediate_pem": "-----BEGIN CERTIFICATE-----\n... (Yuzu's key, signed by the enterprise) ...\n-----END CERTIFICATE-----\n",
  "chain_pem": "-----BEGIN CERTIFICATE-----\n... (enterprise root [+ intermediates]) ...\n-----END CERTIFICATE-----\n"
}
```

The server validates that the intermediate (a) is a CA certificate, (b) carries
**this install's** CA public key (proof the enterprise signed the CSR you
exported), and (c) verifies up to the supplied parent chain — then swaps the
issuing cert and re-publishes the CRL under the new issuer. Response:

```json
{ "imported": true, "mode": "subordinate", "crl_republished": true, "meta": { "api_version": "v1" } }
```

Errors: `400` (bad JSON / missing field / unparseable intermediate), `403`
(missing `Security:Write`), `409` (no existing CA to subordinate — generate
default certs first), `422` (intermediate is not a CA / does not carry this CA's
key / does not verify to the chain), `413` (body too large), `500` (validated but
persistence failed), `503` (CA unavailable). A rejected import is audited
`ca.subordinate.imported` with `result=denied`; success with `result=success`.

> **Bring-your-own-leaf** (orthogonal): any surface given an explicit
> `--cert`/`--key`/`--ca-cert` (or `--https-cert`/`--https-key`) flag bypasses
> the internal CA for that surface entirely — unchanged behaviour, supported and
> independent of subordinate mode.

---

### RBAC

Role-Based Access Control endpoints for inspecting roles, permissions, and authorization decisions.

#### `GET /api/v1/rbac/roles`

List all defined roles.

**Permission:** `UserManagement:Read`

**Response:**

```json
{
  "data": [
    {
      "name": "Administrator",
      "description": "Full system access",
      "is_system": true,
      "created_at": 1710849600
    },
    {
      "name": "Operator",
      "description": "Can execute instructions and manage devices",
      "is_system": true,
      "created_at": 1710849600
    },
    {
      "name": "Viewer",
      "description": "Read-only access",
      "is_system": true,
      "created_at": 1710849600
    },
    {
      "name": "ITServiceOwner",
      "description": "Can delegate Operator and Viewer roles within their management groups",
      "is_system": true,
      "created_at": 1710849600
    }
  ],
  "pagination": { "total": 4, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

---

#### `GET /api/v1/rbac/roles/{role_name}/permissions`

List all permissions granted to a role.

**Permission:** `UserManagement:Read`

**Response:**

```json
{
  "data": [
    {
      "securable_type": "ManagementGroup",
      "operation": "Read",
      "effect": "allow"
    },
    {
      "securable_type": "ManagementGroup",
      "operation": "Write",
      "effect": "allow"
    },
    {
      "securable_type": "Tag",
      "operation": "Read",
      "effect": "allow"
    }
  ],
  "meta": { "api_version": "v1" }
}
```

---

#### `POST /api/v1/rbac/check`

Check whether the current user has a specific permission.

**Permission:** Authenticated session (no specific RBAC permission required).

**Request body:**

```json
{
  "securable_type": "ManagementGroup",
  "operation": "Write"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `securable_type` | string | Yes | The resource type to check |
| `operation` | string | Yes | The operation to check (`Read`, `Write`, `Delete`, `Execute`) |

**Response:**

```json
{
  "data": { "allowed": true },
  "meta": { "api_version": "v1" }
}
```

**Securable types:** `ManagementGroup`, `ApiToken`, `Security`, `UserManagement`, `Tag`, `InstructionDefinition`, `AuditLog`

**Operations:** `Read`, `Write`, `Delete`, `Execute`

---

### Tags

Tags are key-value pairs assigned to agents for categorization, scoping, and compliance tracking. Four structured categories are enforced: `role`, `environment`, `location`, and `service`. Custom keys are also supported.

Tag key constraints: max 64 characters, pattern `[a-zA-Z0-9_.:-]`. Tag value constraints: max 448 bytes.

#### `GET /api/v1/tag-categories`

List the structured tag categories and their allowed values.

**Permission:** `Tag:Read`

**Response:**

```json
{
  "data": [
    {
      "key": "role",
      "display_name": "Device Role",
      "allowed_values": ["server", "desktop", "kiosk", "virtual"]
    },
    {
      "key": "environment",
      "display_name": "Environment",
      "allowed_values": ["production", "staging", "development", "test"]
    },
    {
      "key": "location",
      "display_name": "Location",
      "allowed_values": []
    },
    {
      "key": "service",
      "display_name": "Service",
      "allowed_values": []
    }
  ],
  "meta": { "api_version": "v1" }
}
```

Categories with an empty `allowed_values` array accept free-form values.

---

#### `GET /api/v1/tag-compliance`

Identify agents missing required structured tag categories.

**Permission:** `Tag:Read`

**Response:**

```json
{
  "data": [
    {
      "agent_id": "agent-untagged-01",
      "missing_tags": ["role", "environment", "location", "service"]
    },
    {
      "agent_id": "agent-partial-02",
      "missing_tags": ["service"]
    }
  ],
  "meta": { "api_version": "v1" }
}
```

---

#### `GET /api/v1/tags?agent_id=X`

Get all tags for a specific agent.

**Permission:** `Tag:Read`

**Query parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `agent_id` | string | Yes | The agent whose tags to retrieve |

**Response:**

```json
{
  "data": {
    "role": "server",
    "environment": "production",
    "location": "eu-west-1",
    "service": "web-frontend",
    "custom.team": "platform-eng"
  },
  "meta": { "api_version": "v1" }
}
```

---

#### `PUT /api/v1/tags`

Set a tag on an agent. Creates the tag if it does not exist, or updates the value if it does. If the key matches a structured category with allowed values, the value is validated.

**Permission:** `Tag:Write`

**Request body:**

```json
{
  "agent_id": "agent-eu-prod-01",
  "key": "environment",
  "value": "production"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `agent_id` | string | Yes | Target agent |
| `key` | string | Yes | Tag key (max 64 chars, `[a-zA-Z0-9_.:-]`) |
| `value` | string | Yes | Tag value (max 448 bytes) |

**Response:**

```json
{
  "data": { "set": true },
  "meta": { "api_version": "v1" }
}
```

**Error (400) -- invalid value for structured category:**

```json
{
  "error": "invalid value 'bogus' for category 'role'; allowed: server, desktop, kiosk, virtual",
  "meta": { "api_version": "v1" }
}
```

---

#### `DELETE /api/v1/tags/{agent_id}/{key}`

Delete a tag from an agent.

**Permission:** `Tag:Delete`

**Response:**

```json
{
  "data": { "deleted": true },
  "meta": { "api_version": "v1" }
}
```

---

### Definitions

Instruction definitions describe the schema and execution spec for operations that can be sent to agents.

#### `GET /api/v1/definitions`

List all instruction definitions.

**Permission:** `InstructionDefinition:Read`

**Response:**

```json
{
  "data": [
    {
      "id": 1,
      "name": "hardware.cpu-info",
      "description": "Retrieve CPU model, core count, and architecture",
      "plugin": "hardware",
      "action": "cpu-info",
      "version": "1.0.0",
      "created_at": "2025-03-19T12:00:00Z"
    },
    {
      "id": 2,
      "name": "network.interfaces",
      "description": "List all network interfaces with IP addresses",
      "plugin": "network",
      "action": "interfaces",
      "version": "1.0.0",
      "created_at": "2025-03-19T12:00:00Z"
    }
  ],
  "pagination": { "total": 2, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

---

### Response Templates

Named response-view configurations attached to an `InstructionDefinition` — column subset, sort order, and filter presets the dashboard's filter-bar dropdown surfaces (issue #254, Phase 8.2). Storage is the `response_templates_spec` JSON array column on `instruction_definitions`; the `__default__` template is synthesised on read from `spec.result.columns` (or the plugin's column schema) and never persists.

#### `GET /api/v1/definitions/{id}/response-templates`

List all response templates for the definition. The synthesised `__default__` is auto-prepended when no operator template is marked `default`.

**Permission:** `InstructionDefinition:Read`

**Response:**

```json
{
  "data": [
    {
      "id": "__default__",
      "name": "Default",
      "description": "Auto-generated default view derived from the result schema.",
      "columns": ["PID", "Name", "Path", "SHA-1"],
      "filters": [],
      "default": true
    }
  ],
  "pagination": { "total": 1, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

#### `GET /api/v1/definitions/{id}/response-templates/{template_id}`

Fetch a single template. The reserved id `__default__` always returns the synthesised default (even when an operator default exists).

**Permission:** `InstructionDefinition:Read`

#### `POST /api/v1/definitions/{id}/response-templates`

Create a new template. Returns the canonicalised template (with auto-assigned `id` when omitted) and 201.

**Permission:** `InstructionDefinition:Write`

**Body:**

```json
{
  "name": "Failures only",
  "columns": ["Severity", "Title"],
  "sort": {"column": "Severity", "dir": "desc"},
  "filters": [{"column": "Severity", "op": "equals", "value": "high"}],
  "default": false
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | No | Auto-generated if omitted. The reserved id `__default__` is rejected. |
| `name` | string | Yes | Operator-facing label. Max 200 characters. |
| `description` | string | No | Optional longer description. |
| `columns` | array of strings | No | Subset of plugin column names. Empty / omitted means "show all". |
| `sort` | object | No | `{column: <name>, dir: asc\|desc}`. `dir` requires `column`. |
| `filters` | array of objects | No | `{column, op, value}` clauses. `op` ∈ `equals`, `not_equals`, `contains`, `starts_with`, `ends_with`. |
| `default` | boolean | No | At most one operator template may be marked default per definition. |

**Body size cap.** POST and PUT bodies are capped at **64 KiB**. Larger bodies receive a 413 response and a failure-audit emission with `reason=body_too_large` before parsing — preventing operator-tier JSON-bomb DoS against the single-process server.

**Errors:**

| Status | Reason |
|---|---|
| 400 | invalid JSON / missing name / unknown filter op / id collision / multiple default templates / `__default__` as authored id |
| 404 | Definition not found |
| 413 | Body exceeds 64 KiB cap |
| 500 | Persist failure (rare; see server logs) |
| 503 | Service unavailable |

#### `PUT /api/v1/definitions/{id}/response-templates/{template_id}`

Replace the named template in place.

**Permission:** `InstructionDefinition:Write`

Returns 400 when `template_id` is `__default__` (the synthesised default cannot be overwritten). Same 64 KiB body cap as POST.

**Errors:**

| Status | Reason |
|---|---|
| 400 | malformed id / `__default__` reserved / invalid JSON / validation failure |
| 404 | Definition or template not found |
| 413 | Body exceeds 64 KiB cap |
| 500 | Persist failure |
| 503 | Service unavailable |

#### `DELETE /api/v1/definitions/{id}/response-templates/{template_id}`

Remove a template. Returns 400 when `template_id` is `__default__`.

**Permission:** `InstructionDefinition:Write`

**Errors:**

| Status | Reason |
|---|---|
| 400 | malformed id / `__default__` reserved |
| 404 | Definition or template not found |
| 500 | Persist failure |
| 503 | Service unavailable |

**Audit events emitted:** `response_template.create`, `response_template.update`, `response_template.delete` — target type `InstructionDefinition`, target id = definition id, detail = template id (success) or `reason=<r>` (audit-path failure). 4xx branches emit `result=denied`; 500 persist failures emit `result=failure`. See `audit-log.md` for the full reason vocabulary.

---

### Audit Log

Query the server audit trail. All state-changing operations are recorded with the acting principal, action, target, and result.

#### `GET /api/v1/audit`

Query audit events.

**Permission:** `AuditLog:Read`

**Query parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `limit` | integer | No | Max events to return (default 100, max 1000) |
| `principal` | string | No | Filter by acting user |
| `action` | string | No | Filter by action name |

**Response:**

```json
{
  "data": [
    {
      "timestamp": 1710849600,
      "principal": "admin",
      "action": "management_group.create",
      "result": "success",
      "target_type": "ManagementGroup",
      "target_id": "a1b2c3d4e5f6",
      "detail": "EU Production Servers"
    },
    {
      "timestamp": 1710849700,
      "principal": "admin",
      "action": "tag.set",
      "result": "success",
      "target_type": "Tag",
      "target_id": "agent-eu-prod-01:environment",
      "detail": "production"
    },
    {
      "timestamp": 1710849800,
      "principal": "jane.ops",
      "action": "quarantine.enable",
      "result": "success",
      "target_type": "Security",
      "target_id": "agent-compromised-01",
      "detail": "Suspicious network activity detected"
    }
  ],
  "pagination": { "total": 3, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

#### `GET /api/v1/audit/auth-sample`

Pseudo-random **sample** of authentication-surface audit events over an optional
time window — for SOC 2 **CC7.2** sampled-evidence export (auditor pulls a
representative sample of auth activity rather than the full log). Scoped to the
`auth.`, `mfa.`, and `session.` action prefixes (logins, MFA, session
revocation, lockout, admin-gate denials, etc.). Rows are returned in random
order so a bounded `limit` is a sample across the window, not just the latest N.

> **Sampling caveat (read before using as formal evidence).** The sample is
> drawn from at most the **10000 most-recent** matching events in the window.
> When the window holds more than that, the sample is **recency-biased** — it is
> a uniform sample of the newest 10000 events, *not* of the full window. The
> response `sampling` object reports this: `candidates_considered` (pool size the
> sample was drawn from), `scan_cap` (10000), and `recency_capped` (`true` when
> the pool hit the cap). For a uniform sample of a high-volume period, narrow the
> `from`/`to` window so it holds ≤ 10000 events. Samples are also
> **non-reproducible** (no seed) — re-running yields a different draw; the audited
> `audit.auth_sample.exported` row is the chain-of-custody record of what was pulled.

**Permission:** `AuditLog:Read` — note this is deliberately *not* admin-only, so
a dedicated read-only auditor role can pull evidence without full admin
(separation of duties).

The export is itself audited as `audit.auth_sample.exported` (who pulled which
window, and how many rows) so evidence access stays on the audit chain.

**Query parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `from` | integer | No | Window start, epoch seconds, digits only (omit for unbounded) |
| `to` | integer | No | Window end, epoch seconds, digits only (omit for unbounded) |
| `limit` | integer | No | Sample size (default 100, max 1000) |

```bash
curl -s -G \
  -H "Authorization: Bearer $TOKEN" \
  --data-urlencode "from=1717200000" \
  --data-urlencode "to=1719792000" \
  --data-urlencode "limit=50" \
  "https://yuzu.example.com/api/v1/audit/auth-sample" | jq .
```

**Responses:** `200` sampled list — **same envelope and event field set as
`GET /api/v1/audit`** (`timestamp`, `principal`, `action`, `result`,
`target_type`, `target_id`, `detail`); the sample deliberately does **not**
widen what `AuditLog:Read` discloses (no `session_id` / `source_ip`). The
envelope additionally carries a `sampling` object (`candidates_considered`,
`scan_cap`, `recency_capped`). `400` if `from`/`to` are not non-negative
digits, `from > to`, or `limit` is non-integer; `503` if the audit store is
unavailable. If the export's own audit row fails to persist, the response
carries a `Sec-Audit-Failed: true` header (the export still returns).

**Audit action names:**

| Action | Description |
|---|---|
| `audit.auth_sample.exported` | Auth evidence sample pulled via `GET /api/v1/audit/auth-sample`. `target_type=AuditLog`, `target_id=auth-sample`; `detail` carries `from=<epoch-or-0> to=<epoch-or-0> limit=<N> returned=<N>`. `result=success`. |
| `management_group.create` | Group created |
| `management_group.update` | Group updated (rename, re-parent, membership type change) |
| `management_group.delete` | Group deleted |
| `management_group.add_member` | Agent added to group |
| `management_group.remove_member` | Agent removed from group |
| `management_group.assign_role` | Role assigned on group |
| `management_group.unassign_role` | Role removed from group |
| `api_token.create` | API token created |
| `api_token.revoke` | API token revoked. Can carry `result=success` (token was revoked) or `result=denied` (a non-owner without the admin role attempted a cross-user revoke). Denied events include `detail=owner=<real owner>` so forensics can tell a legitimate self-revoke from an enumeration probe. |
| `user.create` | Local account created. `result` ∈ {`success`, `denied`}. Denied detail values: `duplicate_username` (409 — attempted create on an existing name), `weak_password` (400 — fewer than 12 characters). The `role` field is ignored on create — new users always land as `user`. To change role, use the dedicated `POST /api/settings/users/{username}/role` endpoint (audit action `user.role_change`). |
| `user.role_change` | Local account role changed via `POST /api/settings/users/{username}/role`. `result` ∈ {`success`, `denied`, `no_op`}. Denied detail values: `self_role_change_blocked` (403), `invalid_username` (400), `invalid_json` (400), `missing_role` (400), `invalid_role` (400), `user_not_found` (404), `db_failure` (500). `no_op` detail format `same_role={admin\|user}` (200) when the requested role equals the current role — recorded so compliance review can distinguish operator intent from inaction. Success detail format `old_role=user,new_role=admin`. |
| `user.delete` | Local account deleted. `result` ∈ {`success`, `denied`}. Denied detail values: `self_delete_blocked` (403), `invalid_username` (400), `user_not_found` (404). |
| `auth.admin_required` | Centralised denial event emitted by `AuthRoutes::require_admin` on every privileged-endpoint 403. `target_type=endpoint`, `target_id={req.path}`. SOC 2 CC7.2 evidence chain — captures rejected attempts that previously surfaced only in the request log. |
| `auth.lockout.applied` | Account locked after `--auth-lockout-threshold` consecutive failed local-password logins (SOC 2 CC6.3). Emitted **once** at the threshold crossing — not once per blocked attempt (those are tracked only by `yuzu_auth_lockout_blocked_total` to avoid audit flooding). `result=ok` (the lock was applied; the warning severity is carried by the metric + analytics event, not the audit result), `target_type=User`, `detail=threshold=<N> window_secs=<S>`. |
| `auth.lockout.cleared` | Account-lockout counter reset. `result` ∈ {`ok`, `error`}, `target_type=User`. `detail=admin_unlock` for `POST /api/v1/users/{name}/unlock`, or `reset_on_successful_login` when the user's next successful login clears a non-zero counter. |
| `execution.live_subscribe` | Server-Sent Events subscribe to `/sse/executions/{id}`. `result=success`. Emitted on every successful subscribe (no per-session-per-execution dedup currently — see #700). The forensic-grade audit on first-load remains on `/fragments/executions/{id}/detail`'s `execution.detail.view`. |
| `api.v1.events.subscribe` | Agentic-first SSE subscribe to `/api/v1/events?execution_id=<id>` (sprint W5.1). `result=success`. Detail format: `correlation_id=req-<hex-ms>-<hex-seq>` so SIEM rules can join the audit row to the response's `X-Correlation-Id` header. Deliberately separated from `execution.live_subscribe` so the SIEM can distinguish browser-tier vs agentic-worker consumers. Same no-dedup policy (#700). Post-auth denial branches (404 unknown execution / 410 terminal / 503 unavailable) do not audit but write a `spdlog::warn` row carrying the cid and the authenticated principal so an operator can reconstruct what happened without the client surfacing the cid. |
| `instruction.create` | Instruction definition created. `result` ∈ {`success`, `denied`}. Denied detail value: `duplicate_id` (409, explicit `id` already exists). |
| `instruction.scope_resolution_failed` | Emitted at dispatch when a `from_result_set:` reference in the scope cannot be resolved (set absent, TTL-expired, or not owned by the dispatching principal). `result=failure`. Detail format: `INSTRUCTION_SCOPE_RESOLUTION_FAILED command=<command_id> ref=<id-or-alias> reason=...`. Fires on all scoped dispatch paths (generic REST, tracked, MCP) and increments the `yuzu_scope_resolution_failed_total` metric; the dispatch targets zero devices from that set and continues. |
| `bundle.dispatch` | Live-query bundle dispatched via `POST /api/v1/bundles` (ADR-0011). `target_type=Execution`. `result=success` (`target_id=<bundle-… correlation id>`, detail `agent=<id> steps=<n>`) or `result=failure` (dispatch threw — `target_id` empty, detail `agent=<id> error=<…>`). |
| `bundle.<plugin>.<action>` | One step of a live-query bundle, emitted per step at dispatch — the device-access lens. `target_type=Agent`, `target_id=<agent_id>`. `result=dispatched` (reached the agent) or `result=no_agents` (reached zero agents → `dispatch_failed` on collate). A bundle of N steps emits N of these, so it is exactly as auditable as N separate executions (works-council parity). Emitted on **both** the REST and MCP surfaces (the per-step verb is transport-agnostic; the MCP tool-call envelope additionally audits as `mcp.execute_bundle`). |
| `bundle.collate` | Live-query bundle collated via `GET /api/v1/bundles/{id}`. `target_type=Execution`, `target_id=<correlation id>`. `result=success` (detail `complete=0\|1`) or `result=denied` (`not found or not owned` — the 404 covers both an unknown id and a non-owner, so the audit row is where the real reason is recorded). |
| `policy_fragment.create` | Policy fragment created. `result` ∈ {`success`, `denied`}. Denied detail value: `duplicate_name` (409, fragment with the same `name` already exists). |
| `policy.evaluate` | Compliance evaluation forced for a policy via `POST /api/policies/{id}/evaluate`. `result=success`. Detail format `execution_id=<id>`. Note: the `409` rejection (no check instruction / no matching agents) returns without emitting an audit row. |
| `policy.remediate` | Manual remediation triggered via `POST /api/policies/{id}/remediate`. `result` ∈ {`success`, `denied`}. Success detail `execution_id=<id> agents=<n>`; denied detail carries the reason (e.g. fragment defines no `fix` instruction, no non-compliant agents). |
| `quarantine.enable` | Device quarantined |
| `quarantine.disable` | Device released from quarantine |
| `ca.cert.issued` | Internal CA signed a per-agent client certificate at enrollment. `target_type=AgentCertificate`, `target_id=<serial>`, `result=success`. |
| `ca.cert.revoked` | Certificate revoked via `POST /api/v1/ca/revoke`. `target_type=AgentCertificate`, `target_id=<serial>`. `result=success`, or `result=failure` with `detail="serial not found or already revoked"` for an unknown/already-revoked serial. |
| `ca.crl.published` | CRL (re)published after a revocation. `target_type=Security`, `target_id=<serial that triggered it>`. `result=success`, or `result=failure` when the CRL could not be rebuilt/recorded (the revocation still stands; the public CRL is momentarily stale). |
| `ca.root_csr.exported` | The install CA's CSR was exported via `GET /api/v1/ca/root-csr` (subordinate-CA setup). `target_type=CaRoot`, `target_id=root`. `result=success`, or `result=failure` if generation failed. |
| `ca.subordinate.imported` | An enterprise-signed intermediate was imported via `POST /api/v1/ca/import-chain` (or the dashboard wrapper). `target_type=CaRoot`, `target_id=root`. `result=success` on a validated switch to subordinate mode; `result=denied` when the uploaded material is rejected (not a CA / wrong key / does not chain); `result=failure` on a server-side persistence error. `detail` carries `reason=...` on rejection and `via=dashboard` for the panel path. |
| `tag.set` | Tag created or updated |
| `tag.delete` | Tag deleted |

---

### Policy Fragments

Policy fragments are reusable check/fix/postCheck patterns that define compliance checks and auto-remediation actions.

#### `GET /api/policy-fragments`

List all policy fragments.

**Permission:** `Policy:Read`

**Query parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `name` | string | No | Filter by fragment name (substring match) |
| `limit` | integer | No | Maximum results (default 100) |

**Response:**

```json
{
  "fragments": [
    {
      "id": "frag-abc123",
      "name": "ensure-defender-enabled",
      "description": "Verify Windows Defender is active",
      "check_instruction": "security.defender-status",
      "fix_instruction": "security.enable-defender",
      "post_check_instruction": "",
      "created_at": 1710849600
    }
  ]
}
```

---

#### `POST /api/policy-fragments`

Create a new policy fragment from YAML.

**Permission:** `Policy:Write`

**Request body:**

```json
{
  "yaml_source": "apiVersion: yuzu.io/v1alpha1\nkind: PolicyFragment\n..."
}
```

**Response (200):**

```json
{
  "id": "frag-abc123",
  "status": "created"
}
```

**Response (400):** YAML missing required fields, oversized payload, invalid CEL compliance expression. Body is `{"error": "<reason>"}`.

**Response (409):** Returned when a fragment with the same `name` already exists. Body is `{"error": "policy fragment named '<name>' already exists"}`. Audit event recorded as `policy_fragment.create / denied / duplicate_name`. Choose a different name (existing fragments are immutable on rename).

**Response (503):** Policy store not yet initialized.

---

#### `DELETE /api/policy-fragments/{id}`

Delete a policy fragment.

**Permission:** `Policy:Write`

**Response:**

```json
{
  "deleted": true
}
```

---

### Policies

Policies bind fragments to devices via scope expressions, triggers, and management group bindings.

#### `GET /api/policies`

List all policies.

**Permission:** `Policy:Read`

**Query parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `name` | string | No | Filter by policy name (substring match) |
| `fragment_id` | string | No | Filter by fragment ID |
| `enabled_only` | boolean | No | Return only enabled policies |
| `limit` | integer | No | Maximum results (default 100) |

**Response:**

```json
{
  "policies": [
    {
      "id": "pol-xyz789",
      "name": "baseline-security",
      "fragment_id": "frag-abc123",
      "scope_expression": "tag:environment = 'production'",
      "enabled": true,
      "management_groups": ["eu-production"],
      "triggers": [{"type": "interval", "config": {"interval_seconds": 300}}],
      "created_at": 1710849600,
      "updated_at": 1710849600
    }
  ]
}
```

---

#### `POST /api/policies`

Create a new policy from YAML.

**Permission:** `Policy:Write`

**Request body:**

```json
{
  "yaml_source": "apiVersion: yuzu.io/v1alpha1\nkind: Policy\n..."
}
```

**Response (200):**

```json
{
  "id": "pol-xyz789",
  "status": "created"
}
```

---

#### `GET /api/policies/{id}`

Get policy detail including compliance summary.

**Permission:** `Policy:Read`

**Response:**

```json
{
  "policy": {
    "id": "pol-xyz789",
    "name": "baseline-security",
    "fragment_id": "frag-abc123",
    "scope_expression": "tag:environment = 'production'",
    "enabled": true,
    "remediation_available": true,
    "management_groups": ["eu-production"],
    "triggers": [{"type": "interval", "config": {"interval_seconds": 300}}],
    "inputs": [{"key": "severity", "value": "high"}],
    "created_at": 1710849600,
    "updated_at": 1710849600
  },
  "compliance": {
    "compliant": 42,
    "non_compliant": 3,
    "unknown": 5,
    "fixing": 1,
    "error": 0,
    "total": 51
  }
}
```

---

#### `DELETE /api/policies/{id}`

Delete a policy and all associated compliance data.

**Permission:** `Policy:Write`

**Response:**

```json
{
  "deleted": true
}
```

---

#### `POST /api/policies/{id}/enable`

Enable a previously disabled policy.

**Permission:** `Policy:Write`

**Response:**

```json
{
  "status": "enabled"
}
```

---

#### `POST /api/policies/{id}/disable`

Disable a policy, pausing compliance checks.

**Permission:** `Policy:Write`

**Response:**

```json
{
  "status": "disabled"
}
```

---

#### `POST /api/policies/{id}/invalidate`

Invalidate agent-side compliance cache for a specific policy. Resets all agent statuses to `pending`, forcing re-evaluation.

**Permission:** `Policy:Write`

**Response:**

```json
{
  "status": "invalidated",
  "agents_invalidated": 42
}
```

---

#### `POST /api/policies/invalidate-all`

Invalidate compliance cache for all policies across all agents.

**Permission:** `Policy:Write`

**Response:**

```json
{
  "status": "invalidated",
  "total_invalidated": 210
}
```

---

#### `POST /api/policies/{id}/evaluate`

Force an immediate compliance evaluation of a policy, ignoring its interval. The
server dispatches the bound fragment's `check` instruction to the policy's scope
and, once responses arrive (within a short grace window), evaluates the CEL
`check_compliance` per agent and writes `compliant` / `non_compliant` /
`unknown` / `error` to each agent's status — which is what
`GET /api/compliance` and `GET /api/policies/{id}` then report. Evaluation is
asynchronous: this returns immediately with the dispatch `execution_id`; the
verdicts appear a few seconds later.

**Permission:** `Policy:Execute`

**Response (202):**

```json
{
  "status": "dispatched",
  "execution_id": "polchk-a1b2c3d4e5f60718"
}
```

**Response (404):** policy not found. **Response (409):** the policy's fragment
has no `check` instruction, or the policy matches no agents. **Response (503):**
policy evaluation not available.

**Audit:** `policy.evaluate`.

---

#### `POST /api/policies/{id}/remediate`

Manually remediate a policy's non-compliant agents. **Only available when the
bound fragment defines a `fix` instruction** (the `remediation_available` flag
on the policy detail) — this is the operator-gated "would you like to remediate
this?" action; remediation is never automatic. The server marks the targets
`fixing`, dispatches the `fix` instruction, then runs the `postCheck` (falling
back to `check`) and writes the verified post-fix verdict.

**Permission:** `Policy:Execute`

**Request body (optional):**

```json
{
  "agent_ids": ["agent-123", "agent-456"]
}
```

If `agent_ids` is omitted, every agent currently `non_compliant` for the policy
is remediated.

**Response (202):**

```json
{
  "status": "remediating",
  "execution_id": "polchk-9f8e7d6c5b4a3021",
  "agents": 2
}
```

**Response (404):** policy not found. **Response (409):** the fragment defines no
`fix` instruction, or there are no non-compliant agents to remediate.
**Response (503):** policy evaluation not available.

**Audit:** `policy.remediate` (`result` ∈ {`success`, `denied`}).

---

### Compliance

Fleet and per-policy compliance status endpoints.

#### `GET /api/compliance`

Fleet compliance summary across all active policies.

**Permission:** `Policy:Read`

**Response:**

```json
{
  "compliance_pct": 92.5,
  "total_checks": 200,
  "compliant": 185,
  "non_compliant": 8,
  "unknown": 5,
  "fixing": 2,
  "error": 0
}
```

---

#### `GET /api/compliance/{policy_id}`

Per-policy compliance detail with per-agent statuses.

**Permission:** `Policy:Read`

**Response:**

```json
{
  "summary": {
    "compliant": 42,
    "non_compliant": 3,
    "unknown": 5,
    "fixing": 1,
    "error": 0,
    "total": 51
  },
  "agents": [
    {
      "agent_id": "agent-01",
      "status": "compliant",
      "last_check_at": 1710936000,
      "last_fix_at": 0,
      "check_result": "{\"realtime_protection\": true}"
    }
  ]
}
```

---

### Runtime Configuration

Runtime configuration endpoints allow reading and updating server settings without a restart. Only a predefined set of keys can be changed at runtime.

#### `GET /api/config`

Returns current configuration values and any active runtime overrides.

**Permission:** `Infrastructure:Read`

**Response:**

```json
{
  "data": {
    "heartbeat_timeout": 120,
    "response_retention_days": 90,
    "audit_retention_days": 365,
    "auto_approve_enabled": false,
    "log_level": "info"
  },
  "meta": { "api_version": "v1" }
}
```

---

#### `PUT /api/config/:key`

Update a single runtime configuration value. The key must be one of the allowed runtime-configurable keys.

**Permission:** `Infrastructure:Write`

**Allowed keys:**

| Key | Type | Description |
|---|---|---|
| `heartbeat_timeout` | integer | Seconds before an agent is considered offline |
| `response_retention_days` | integer | Days to retain command response data |
| `audit_retention_days` | integer | Days to retain audit log entries |
| `auto_approve_enabled` | boolean | Whether auto-approve rules are active |
| `log_level` | string | Server log verbosity (`trace`, `debug`, `info`, `warn`, `error`) |

**Request body:**

```json
{
  "value": 180
}
```

**Response:**

```json
{
  "data": { "updated": true, "key": "heartbeat_timeout", "value": 180 },
  "meta": { "api_version": "v1" }
}
```

**Error (400) -- invalid key:**

```json
{
  "error": "unknown config key 'foo'; allowed: heartbeat_timeout, response_retention_days, audit_retention_days, auto_approve_enabled, log_level",
  "meta": { "api_version": "v1" }
}
```

---

### Custom Properties

Custom properties are operator-defined key-value pairs on agents, separate from tags. Properties can have schemas that enforce type, allowed values, and validation rules. Properties are available for use in scope expressions via the `props.<key>` prefix.

#### `GET /api/agents/:id/properties`

List all custom properties for a specific agent.

**Permission:** `Infrastructure:Read`

**Response:**

```json
{
  "data": [
    {
      "key": "department",
      "value": "Engineering"
    },
    {
      "key": "cost_center",
      "value": "CC-4200"
    }
  ],
  "meta": { "api_version": "v1" }
}
```

---

#### `PUT /api/agents/:id/properties/:key`

Set or update a custom property value on an agent. If a property schema exists for the key, the value is validated against it.

**Permission:** `Infrastructure:Write`

**Request body:**

```json
{
  "value": "Engineering"
}
```

**Response:**

```json
{
  "data": { "set": true },
  "meta": { "api_version": "v1" }
}
```

**Error (400) -- schema validation failure:**

```json
{
  "error": "value 'bogus' not allowed for property 'department'; allowed: Engineering, Sales, Operations, Support",
  "meta": { "api_version": "v1" }
}
```

---

#### `DELETE /api/agents/:id/properties/:key`

Delete a custom property from an agent.

**Permission:** `Infrastructure:Write`

**Response:**

```json
{
  "data": { "deleted": true },
  "meta": { "api_version": "v1" }
}
```

---

#### `GET /api/property-schemas`

List all property schemas. Schemas define the allowed keys, types, and validation constraints for custom properties.

**Permission:** `Infrastructure:Read`

**Response:**

```json
{
  "data": [
    {
      "key": "department",
      "display_name": "Department",
      "type": "string",
      "allowed_values": ["Engineering", "Sales", "Operations", "Support"],
      "required": false
    },
    {
      "key": "cost_center",
      "display_name": "Cost Center",
      "type": "string",
      "allowed_values": [],
      "required": true
    }
  ],
  "meta": { "api_version": "v1" }
}
```

Schemas with an empty `allowed_values` array accept free-form values.

---

#### `POST /api/property-schemas`

Create or update a property schema. If a schema with the given key already exists, it is replaced.

**Permission:** `Infrastructure:Write`

**Request body:**

```json
{
  "key": "department",
  "display_name": "Department",
  "type": "string",
  "allowed_values": ["Engineering", "Sales", "Operations", "Support"],
  "required": false
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `key` | string | Yes | Property key (unique identifier) |
| `display_name` | string | No | Human-readable label |
| `type` | string | No | Value type: `string` (default), `integer`, `boolean` |
| `allowed_values` | array | No | Restrict values to this set (empty = free-form) |
| `required` | boolean | No | Whether every agent must have this property |

**Response (201):**

```json
{
  "data": { "created": true, "key": "department" },
  "meta": { "api_version": "v1" }
}
```

---

### Webhooks

Webhooks deliver real-time HTTP POST notifications to external systems when events occur in Yuzu (e.g., agent registration, command completion, policy compliance changes).

#### `GET /api/webhooks`

List all configured webhooks.

**Response:**

```json
{
  "webhooks": [
    {
      "id": 1,
      "url": "https://example.com/hooks/yuzu",
      "event_types": ["agent.registered", "command.completed"],
      "enabled": true,
      "created_at": 1710849600
    }
  ]
}
```

#### `POST /api/webhooks`

Create a new webhook subscription.

**Request body:**

```json
{
  "url": "https://example.com/hooks/yuzu",
  "event_types": ["agent.registered", "command.completed", "policy.violation"],
  "secret": "optional-hmac-secret"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `url` | string | Yes | HTTPS endpoint to receive POST notifications |
| `event_types` | array | Yes | Events to subscribe to (see the table below) |
| `secret` | string | No | HMAC-SHA256 secret for payload signing |

**Event types** (the `event_types` filter matches these literal strings):

| Event type | Fired when | Notable payload fields |
|---|---|---|
| `agent.registered` | An agent enrolls or re-enrolls | `agent_id`, `hostname`, `os`, `arch`, `agent_version` |
| `command.completed` / `execution.completed` | An instruction finishes across its targets | command/execution identifiers |
| `policy.violation` | A policy evaluation finds a non-compliant device | policy + device identifiers |
| `dex.blast_radius` | N distinct devices report the same DEX signal `(obs_type, subject)` within the window — thresholds are operator-tunable under Settings → DEX alerts (defaults 5 devices / 15 min; see [DEX fleet incident alerts](dex.md#fleet-incident-alerts-blast-radius)) | `obs_type`, `subject`, `device_count`, `window_seconds` |
| `dex.signal` | A device reports a DEX signal type the operator routed to alerts (Settings → DEX alerts; once per device per hour — see [Routing signals to alerts](dex.md#routing-signals-to-alerts)) | `obs_type`, `subject`, `agent_id` |

If a `secret` is provided, each delivery includes an `X-Yuzu-Signature` header containing the HMAC-SHA256 hex digest of the request body.

#### `DELETE /api/webhooks/{id}`

Delete a webhook by numeric ID.

#### `GET /api/webhooks/{id}/deliveries`

List recent delivery attempts for a webhook. Includes HTTP status code, response time, and any error message for failed deliveries.

**Usage guide:**

1. Create a webhook targeting your SIEM, Slack, or automation endpoint.
2. Subscribe to the event types relevant to your workflow.
3. Optionally set an HMAC secret and verify the `X-Yuzu-Signature` header on receipt.
4. Monitor delivery history via `GET /api/webhooks/{id}/deliveries` to detect failures.

---

### Offload Targets

Response-offload control plane (issue #255, Phase 8.3). Targets are named external HTTP endpoints that receive a copy of `agent.registered` and `execution.completed` events as they fire — heavier-duty than webhooks: typed auth (none / bearer / basic / hmac) and server-side batching for SIEM / data-warehouse ingestion that prefers fewer, larger requests.

A target is identified by a unique `name` so a definition can reference it via `spec.offload.targets` in YAML (see [yaml-dsl-spec.md](../yaml-dsl-spec.md#specoffload)).

All five endpoints require the `Infrastructure` securable type — `Read` for `GET`, `Write` for `POST`/`DELETE`. The `auth_credential` is **never** returned in any response (redacted from `list()` and from `get()`); only the auth_type and shape leak. Audit events: `offload_target.create` (success or denied) and `offload_target.delete`.

#### `GET /api/v1/offload-targets`

List all configured offload targets.

**Response:**

```json
{
  "offload_targets": [
    {
      "id": 1,
      "name": "siem-primary",
      "url": "https://siem.example.com/ingest",
      "auth_type": "bearer",
      "event_types": "execution.completed",
      "batch_size": 50,
      "enabled": true,
      "created_at": 1714501234
    }
  ]
}
```

#### `GET /api/v1/offload-targets/{id}`

Fetch a single target by numeric id. `auth_credential` is redacted. 404 when no such id exists.

#### `POST /api/v1/offload-targets`

Create a new offload target. Returns 201 + `{id, status}` on success, 400 when validation fails (invalid URL scheme, empty `name`, `batch_size < 1`, duplicate `name`).

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | Yes | Unique stable identifier referenced from `spec.offload.targets`. |
| `url` | string | Yes | `http://` or `https://` POST endpoint. |
| `auth_type` | string | No (`none`) | One of `none`, `bearer`, `basic`, `hmac`. |
| `auth_credential` | string | No | Bearer token (Bearer), `user:pass` (Basic), shared secret (Hmac). Never returned by any endpoint. |
| `event_types` | string | No (`*`) | Comma-separated list of event types or `*` for all. Same semantics as webhooks. |
| `batch_size` | int | No (1) | Accumulate up to N events into a single POST body. `1` = no batching. |
| `enabled` | bool | No (true) | When false, no events are dispatched until re-enabled. |

**Auth headers (set per `auth_type`):**

- `none` → no Authorization header.
- `bearer` → `Authorization: Bearer <auth_credential>`.
- `basic` → `Authorization: Basic <base64(user:pass)>`.
- `hmac` → `X-Yuzu-Signature: sha256=<hmac-sha256(auth_credential, body)>`. Mirrors the webhook shape so receivers can share verification code.

Every delivery also carries `X-Yuzu-Event` and `X-Yuzu-Event-Count` headers; batched bodies are JSON of shape `{"events":[…]}`.

#### `DELETE /api/v1/offload-targets/{id}`

Delete a target. Cascades on `offload_deliveries`. Pending events buffered for batching are dropped — operator who deletes the target asked for it.

#### `GET /api/v1/offload-targets/{id}/deliveries`

Recent delivery attempts for a target (default 50, override via `?limit=N`). Each row records `event_type`, `event_count`, `payload`, `status_code`, `delivered_at` (epoch seconds), and `error` (set on connection failure or exception).

**Usage guide:**

1. Register a target — e.g. a generic webhook collector, Datadog Logs HTTP endpoint, Elastic Common Schema ingest URL, or any in-house aggregator that accepts JSON over HTTP(S).
2. Set `event_types` to the events you actually need; `execution.completed` is the typical analytics feed, `agent.registered` for inventory hydration.
3. Tune `batch_size` to your downstream ingestion preference. SIEMs commonly prefer 50–500 per POST; real-time alerting wants `batch_size=1`.
4. Monitor delivery via `GET /api/v1/offload-targets/{id}/deliveries`. Repeated `connection_failed` errors mean the receiver is down or the URL/auth is wrong.

**Validating a new target.** There is no synthetic-test endpoint in this revision. To validate, set `batch_size=1`, run any instruction that produces an `execution.completed` event, then poll `GET /api/v1/offload-targets/{id}/deliveries` for the resulting row.

**Authentication interop — known limitations.**

- **Splunk HEC** uses the non-standard header `Authorization: Splunk <token>`. Yuzu's `bearer` mode emits `Authorization: Bearer <token>`. Splunk HEC will reject these with HTTP 401. Use `auth_type=none` + a Splunk HEC token enabled for "no authentication" (network-layer controls only) or front Splunk with a small reverse proxy that rewrites the header.
- **AWS S3 / EventBridge / Kinesis** require AWS Signature v4 (Sigv4). Yuzu does not generate Sigv4 signatures in this revision; direct PUTs to S3 buckets and EventBridge endpoints **will not work**. Front them with a Sigv4-signing reverse proxy (e.g. `aws-sigv4-proxy`).
- **Azure Monitor / Sentinel** use AAD token flow. Not directly supported. Front with a token-refresh shim.

**Cleartext HTTP warning.** When `url` is `http://` (not `https://`), the entire JSON payload — including potentially sensitive instruction response data (file paths, registry values, software inventory, security findings) — is transmitted in cleartext. Production deployments containing customer endpoint data should use `https://` only. The store accepts `http://` for development convenience and to maintain parity with the webhook precedent.

**Operator trust model.** Any principal with `Infrastructure:Write` can register an offload target pointing at any URL the server can resolve, including RFC1918 / loopback / link-local destinations. There is no URL allowlist or network-egress mitigation in this revision; the trust model is "Infrastructure:Write operators are trusted to choose where data goes." For multi-tenant managed deployments this is a known limitation tracked as a roadmap follow-up.

---

### Workflows

Workflows define multi-step instruction sequences that execute in order against a set of agents. Each step references an instruction definition and can include parameter overrides.

#### `GET /api/workflows`

List all workflows. Supports `?q=<search>` query parameter for name filtering.

**Response:**

```json
{
  "workflows": [
    {
      "id": "abc123",
      "name": "Patch and Reboot",
      "description": "Install patches then reboot if required",
      "steps": [
        { "instruction": "windows-update-install", "parameters": {} },
        { "instruction": "system-reboot", "parameters": { "delay": "60" } }
      ],
      "created_at": 1710849600
    }
  ]
}
```

#### `POST /api/workflows`

Create a workflow from YAML. The request body is the raw YAML text with `Content-Type: text/x-yaml` or `application/json` with a `yaml_source` field.

#### `GET /api/workflows/{id}`

Get a single workflow by ID, including its full step definitions.

#### `DELETE /api/workflows/{id}`

Delete a workflow by ID.

#### `POST /api/workflows/{id}/execute`

Execute a workflow against targeted agents.

**Request body:**

```json
{
  "scope": "os = 'windows' AND tag:environment = 'production'",
  "parameters": {}
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `scope` | string | Yes | Scope expression selecting target agents |
| `parameters` | object | No | Override parameters for workflow steps |

#### `GET /api/workflow-executions/{id}`

Get the status of a running or completed workflow execution, including per-step and per-agent results.

**Usage guide:**

1. Define a workflow with ordered steps (each step maps to an instruction definition).
2. Execute the workflow against a scope expression to target specific agents.
3. Monitor execution progress via `GET /api/workflow-executions/{id}`.
4. Each step runs sequentially; if a step fails on an agent, subsequent steps for that agent are skipped.

---

### OpenAPI Spec

#### `GET /api/v1/openapi.json`

Returns the OpenAPI/Swagger specification for the v1 API as JSON.

**Permission:** None (public endpoint).

**Response:** OpenAPI 3.x JSON document describing all v1 endpoints, schemas, and authentication methods.

---

### Inventory

Inventory data is structured per-plugin telemetry collected from agents and stored server-side.

#### `GET /api/v1/inventory/tables`

List all inventory tables (one per plugin that reports inventory data).

**Permission:** `Inventory:Read`

**Response:**

```json
{
  "data": [
    {
      "plugin": "hardware",
      "agent_count": 142,
      "last_collected": 1711900800
    }
  ],
  "pagination": { "total": 12 },
  "meta": { "api_version": "v1" }
}
```

#### `GET /api/v1/inventory/{plugin}/{agent_id}`

Get inventory data for a specific plugin and agent.

**Permission:** `Inventory:Read`

**Response:**

```json
{
  "data": {
    "agent_id": "agent-001",
    "plugin": "hardware",
    "data": { "cpu_count": 8, "ram_gb": 32 },
    "collected_at": 1711900800
  },
  "meta": { "api_version": "v1" }
}
```

The `data` field contains the plugin-specific structured inventory blob as parsed JSON (or a string if the blob is not valid JSON).

#### `POST /api/v1/inventory/query`

Query inventory data across agents with filters.

**Permission:** `Inventory:Read`

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `agent_id` | string | No | Filter by agent ID |
| `plugin` | string | No | Filter by plugin name |
| `since` | integer | No | Unix timestamp — only records collected after this time |
| `until` | integer | No | Unix timestamp — only records collected before this time |
| `limit` | integer | No | Max results (default 100, max 1000) |

**Response:** List of inventory records matching the query.

#### `POST /api/v1/inventory/evaluate`

Evaluate inventory conditions across agents. Returns agents whose inventory data matches the specified conditions.

**Permission:** `Inventory:Read`

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `agent_id` | string | No | Scope to a single agent |
| `combine` | string | No | `"and"` (default) or `"or"` — how to combine multiple conditions |
| `conditions` | array | Yes | List of condition objects |

Each condition object:

| Field | Type | Description |
|---|---|---|
| `plugin` | string | Plugin name to query |
| `field` | string | JSON field path within the inventory data |
| `op` | string | Operator: `eq`, `neq`, `gt`, `lt`, `gte`, `lte`, `contains` |
| `value` | string | Value to compare against |

**Response:**

```json
{
  "data": [
    {
      "agent_id": "agent-001",
      "match": true,
      "matched_value": "8",
      "plugin": "hardware",
      "collected_at": 1711900800
    }
  ],
  "meta": { "api_version": "v1" }
}
```

#### `GET /api/v1/inventory/software`

Fleet-wide read of the typed installed-software inventory (ADR-0016, `SoftwareInventoryStore`). **Distinct** from the generic `/inventory/*` routes above, which read the legacy blob store. This is the REST sibling of the `query_installed_software` MCP tool — same data, same scope contract.

**Permission:** `Inventory:Read`

**Query parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `name` | string | No | Exact software-name filter |
| `agent_id` | string | No | Exact agent filter |
| `limit` | integer | No | Max rows (default 100, min 1, max 1000) |

Omit both `name` and `agent_id` for a fleet-wide scan.

**Response (200):**

```json
{
  "data": {
    "software": [
      {"agent_id": "agent-001", "name": "Google Chrome", "version": "124.0", "publisher": "Google LLC", "install_date": "2024-01-15"}
    ],
    "count": 1,
    "devices_omitted": 0,
    "result_truncated_by_cap": true
  },
  "meta": { "api_version": "v1" }
}
```

`devices_omitted` is always present (0 when no scope filtering occurred). `result_truncated_by_cap` is present only when `count == limit` and more rows may exist past the cap (keyset pagination is a follow-up, #1634). `audit_persisted: false` is present only when the audit row could not be persisted (set-and-proceed posture — the data is still served, the lost-evidence flag is surfaced honestly).

Results carry a **per-agent management-group drop filter**: out-of-scope devices are dropped and their distinct count returned in `devices_omitted`. A positive `devices_omitted` means matching software exists **outside** your scope — an empty or short result does **not** mean the software is absent fleet-wide. **Scope caveat (ADR-0017):** this confinement is **not yet verified effective** — the endpoint gates on the *global* `Inventory:Read` permission, under which the filter does not narrow results (a confined operator is denied at the gate; a global operator sees all). List-view management-group confinement becomes effective only once the ADR-0017 admit-then-filter gate lands (#1713/#1676 UAT to confirm); until then operator isolation on this surface holds for **per-device** routes only.

**Error responses:**

| Status | Condition |
|---|---|
| 400 | `limit` is not a valid integer |
| 401 | Unauthenticated |
| 403 | Caller lacks `Inventory:Read` |
| 503 | Store unavailable or degraded (A4 envelope with `correlation_id`, `retry_after_ms: 5000`) — **never an empty 200** |

On a `503` the store could not be read; do **not** treat it as "not installed anywhere" (ADR-0016 §7 authoritative reads). A genuine empty result is `200` with `count: 0`.

---

### Execution Statistics

Fleet-wide and per-entity execution metrics.

#### `GET /api/v1/execution-statistics`

Get fleet-wide execution summary.

**Permission:** `Execution:Read`

**Response:**

```json
{
  "data": {
    "total_executions": 15420,
    "executions_today": 230,
    "active_agents": 142,
    "overall_success_rate": 0.973,
    "avg_duration_seconds": 4.2
  },
  "meta": { "api_version": "v1" }
}
```

#### `GET /api/v1/execution-statistics/agents`

Get per-agent execution statistics.

**Permission:** `Execution:Read`

**Query parameters:**

| Param | Type | Description |
|---|---|---|
| `agent_id` | string | Filter to a single agent |
| `since` | integer | Unix timestamp — only executions after this time |
| `limit` | integer | Max results (default 100, max 1000) |

**Response:**

```json
{
  "data": [
    {
      "agent_id": "agent-001",
      "total_executions": 324,
      "success_count": 310,
      "failure_count": 14,
      "success_rate": 0.957,
      "avg_duration_seconds": 3.8,
      "last_execution_at": 1711900800
    }
  ],
  "meta": { "api_version": "v1" }
}
```

#### `GET /api/v1/execution-statistics/definitions`

Get per-definition execution statistics.

**Permission:** `Execution:Read`

**Query parameters:**

| Param | Type | Description |
|---|---|---|
| `definition_id` | string | Filter to a single definition |
| `since` | integer | Unix timestamp — only executions after this time |
| `limit` | integer | Max results (default 100, max 1000) |

**Response:**

```json
{
  "data": [
    {
      "definition_id": "os-info-query",
      "total_executions": 5200,
      "total_agents": 142,
      "success_rate": 0.995,
      "avg_duration_seconds": 1.2
    }
  ],
  "meta": { "api_version": "v1" }
}
```

---

### Execution Visualization

Render an execution's response set as chart-ready JSON, using the `spec.visualization` block configured on the associated `InstructionDefinition` (issue #253). The endpoint is the data source for the dashboard's chart cards and is also suitable for external consumers (Grafana scripted-panel datasources, custom dashboards) that can read JSON over HTTP.

#### `GET /api/v1/executions/{id}/visualization`

**Permission:** `Response:Read`

**Hardening (#1634, partial).** Under a **corrupt or unavailable RBAC store** this endpoint now fails **closed** (returns no rows) rather than exposing the whole fleet via the legacy read fallback. Per-management-group scoping of this endpoint for normal operators is **not yet effective** — a holder of global `Response:Read` currently sees all agents' rows (the per-agent filter is in place but inert under the current global gate; the gate change is tracked under #1634). `rows_capped` (below) is computed on the raw pre-filter result. When rows are dropped (today, the fail-closed path), the success audit detail carries ` scope_dropped=<N>`.

**Path parameters:**

| Param | Description |
|---|---|
| `id` | The response-store key (the `command_id` returned at dispatch time). |

**Query parameters:**

| Param | Type | Required | Description |
|---|---|---|---|
| `definition_id` | string | Yes | ID of the `InstructionDefinition` that holds the `spec.visualization` (or `spec.visualizations`) block. Required because Yuzu keys responses by `command_id`, not by `executions.id` — the caller supplies the link. Must match `[A-Za-z0-9._-]+`. |
| `index` | integer | No | Chart index when the definition declares multiple visualizations. Default `0`. Returns 404 if out of range. |

**Response (200):**

```json
{
  "data": {
    "chart_type": "pie",
    "title": "Service States",
    "labels": ["running", "stopped", "paused"],
    "series": [{ "name": "Count", "data": [42, 7, 1] }],
    "meta": {
      "responses_total": 50,
      "responses_succeeded": 50,
      "responses_failed": 0
    },
    "chart_index": 0,
    "chart_count": 1
  },
  "meta": { "api_version": "v1" }
}
```

`chart_index` and `chart_count` (issue #587) let clients iterate when the definition declares multiple charts. For `datetime_series` charts, `labels` is replaced by `x` (epoch-seconds array) and `"x_axis": "datetime"` is added.

When the underlying response set exceeds the per-request row cap (10000), the response payload includes `"rows_capped": true` and `"rows_cap": 10000` so the client can surface a "showing first N rows" banner.

**Errors:**

| Status | Cause |
|---|---|
| `400` | `definition_id` query parameter not provided, or `index` is not a non-negative integer. |
| `404` | Definition not found, has no `spec.visualization` configured, or the requested `index` is out of range. |
| `500` | The visualization spec parses but cannot be applied (invalid processor / invalid chart type). |
| `503` | Response store or instruction store unavailable. |

**Audit:** every successful and failed render emits an `execution.visualization.fetch` audit event with `target_type=execution`, `target_id=<execution_id>`, `detail=<definition_id> index=<N>` on success (with ` scope_dropped=<N>` appended when out-of-scope agents' rows were dropped), or `<definition_id> reason=<r>` on the failure path.

**Example:**

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://yuzu.example.com/api/v1/executions/cmd-os_info-abc123/visualization?definition_id=crossplatform.service.inspect"
```

See `docs/yaml-dsl-spec.md` § `spec.visualization` for the full configuration schema.

---

### Live-Query Bundles

Fan **one** instruction out into several plugin actions on **one** device and collate the results — server-side async fan-out (ADR-0011). Use this instead of issuing N separate `execute_instruction` / `POST /api/instructions/{id}/execute` calls when you need to refresh a single device (e.g. a ServiceNow CI sync): N round-trips collapse to one dispatch plus one (or a few) polls.

The server expands the bundle into N ordinary plugin commands, each dispatched under one shared `bundle-…` correlation id. **The agent is unchanged — it never sees a "bundle", only ordinary commands.** Dispatch is **async**: it returns immediately, and a slow plugin step never withholds the others. The MCP tools `execute_bundle` / `get_bundle_result` are the exact parity of these two endpoints.

#### `POST /api/v1/bundles`

Dispatch a bundle. Returns the correlation id immediately; poll `GET /api/v1/bundles/{id}` for the collated result.

**Permission:** `Execution:Execute`

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `agent_id` | string | Yes | The single target device — a bundle targets one device. |
| `steps` | array | Yes | 1–32 step objects, executed in request order. Duplicate `(plugin, action)` is allowed (e.g. two `registry/get_value` reads with different params) — each step gets its own command_id and collates back in order. |
| `steps[].plugin` | string | Yes | Plugin name, lowercased `[a-z0-9_]`, ≤ 64 chars. |
| `steps[].action` | string | Yes | Action name, same charset / length rule. |
| `steps[].params` | object | No | String→string parameter map (non-string values are coerced to strings). |

**Response (202 Accepted):**

```json
{
  "data": { "bundle_id": "bundle-1a2b3c4d5e6f7a8b", "agent_id": "agent-001", "expected": 2 },
  "meta": { "api_version": "v1" }
}
```

`bundle_id` is the `bundle-…` correlation id — pass it to `GET /api/v1/bundles/{id}` to collate. It is **not** an `ExecutionTracker` `execution_id`: a bundle is deliberately not a tracked execution, so feeding `bundle_id` into `GET /api/v1/events` / execution-status endpoints returns 404. `expected` is the number of steps dispatched.

**Errors:**

| Status | Cause |
|---|---|
| `400` | Invalid JSON, missing/empty `agent_id`, missing/empty `steps`, more than 32 steps, an unsafe plugin/action identifier, or a param key/value over the size cap (key ≤ 256 B, value ≤ 64 KiB, ≤ 32 params/step). |
| `500` | The authenticated session resolved to an empty principal (a bundle must be attributable to its dispatcher). |
| `503` | Command dispatch or response store unavailable. |

**Audit:** each step emits a `bundle.<plugin>.<action>` event with `target_type=Agent`, `target_id=<agent_id>`, `result=dispatched` (the step reached the agent) or `result=no_agents` (the step reached zero agents — it will read `dispatch_failed` on collate) — the device-access lens, so a bundle is exactly as auditable as the N executions it replaces. One `bundle.dispatch` (`target_type=Execution`) envelope records the dispatch itself (`result=success`, or `result=failure` with the error detail if dispatch threw).

#### `GET /api/v1/bundles/{id}`

Collate a dispatched bundle into a server-grouped result.

**Permission:** `Response:Read`

**Path parameters:**

| Param | Description |
|---|---|
| `id` | The `bundle-…` correlation id returned by `POST /api/v1/bundles`. |

**Response (200):**

```json
{
  "data": {
    "complete": true,
    "received": 2,
    "succeeded": 2,
    "expected": 2,
    "steps": [
      { "plugin": "os_info", "action": "uptime",  "state": "responded", "status": 1, "output": "up 3 days" },
      { "plugin": "os_info", "action": "os_name", "state": "responded", "status": 1, "output": "Windows 11" }
    ]
  },
  "meta": { "api_version": "v1" }
}
```

Steps are returned in **request order** (not arrival order), so duplicate or same-plugin steps stay unambiguous. `state` is one of `pending` (no response yet), `responded` (a response landed), or `dispatch_failed` (the step reached no agent — terminal; it does not hold the bundle open). `status` is the response status enum (`1`=SUCCESS, `2`=FAILURE; `0` is an in-flight RUNNING frame — only meaningful when `state=responded`). `received` counts steps with any response; `succeeded` counts only steps that responded with status SUCCESS. Plugin `output` is transcoded to UTF-8 — any bytes that are not valid UTF-8 (e.g. binary or a non-UTF-8 codepage) are replaced with U+FFFD so the JSON always serializes.

> **`complete` is terminal, NOT success.** A bundle to an **offline device** completes (`complete=true`) with `received=0`, `succeeded=0`, and every step `dispatch_failed`. A caller deciding "did the refresh work" must check `succeeded == expected` (or inspect each `steps[].state`/`status`) — never `complete` alone. Polling `complete` to mark a record refreshed would silently treat an unreachable device as a success.

**Errors:**

| Status | Cause |
|---|---|
| `404` | Bundle not found, **or** the caller did not dispatch it and is not an admin. The two are deliberately indistinguishable (no enumeration oracle); the real reason is recorded in the audit log. |
| `503` | Service unavailable. |

**Audit:** `bundle.collate` (`target_type=Execution`, `target_id=<id>`), `result=success` (carrying `complete=0|1`) or `result=denied` (not found / not owned).

**Notes:**

- A bundle is **not** a tracked execution — it does not appear in the live executions drawer, and `notify_exec_tracker` skips its `bundle-…` correlation id. The collate poll is the sole completion authority.
- v1 bundle state (the step map) is **per-surface and in-memory**: a bundle dispatched over REST is collated over REST (MCP→MCP). A server restart mid-bundle loses the in-flight step map (the responses survive in the response store, but attribution does not), and the caller must re-dispatch. A durable Postgres manifest for HA + cross-surface collation is a committed follow-up (ADR-0011).

**Error handling and retry (for integrators):**

- **Poll cadence:** poll `GET /api/v1/bundles/{id}` with a short backoff (e.g. 1s, 2s, 4s) until `complete` is `true`, then read `succeeded`/`steps`.
- **Manifest TTL ≈ 10 minutes, sliding.** Each successful collate refreshes the window, so a bundle you are actively polling never expires; only an abandoned bundle (no poll for the full window) is swept.
- **A 404 on a poll that previously returned 200** means the manifest expired (you stopped polling past the TTL) **or** the server restarted (in-memory state lost). The correct recovery is to **re-dispatch the bundle** — the already-executed step responses are harmless (idempotent reads). Do not treat the 404 as a hard failure.

**Example:**

```bash
# dispatch
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"agent_id":"agent-001","steps":[{"plugin":"os_info","action":"uptime"},{"plugin":"os_info","action":"os_name"}]}' \
  "https://yuzu.example.com/api/v1/bundles"
# -> {"data":{"bundle_id":"bundle-…","agent_id":"agent-001","expected":2}, ...}

# collate (poll until data.complete == true)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://yuzu.example.com/api/v1/bundles/bundle-1a2b3c4d5e6f7a8b"
```

---

### Device Tokens

Device tokens are scoped authentication tokens that restrict execution to a specific device and instruction definition. Used for unattended agent operations.

#### `GET /api/v1/device-tokens`

List all device tokens.

**Permission:** `DeviceToken:Read`

**Response:**

```json
{
  "data": [
    {
      "token_id": "a1b2c3d4e5f6",
      "name": "Kiosk daily update",
      "principal_id": "admin",
      "device_id": "kiosk-001",
      "definition_id": "windows-update-install",
      "created_at": 1711900800,
      "expires_at": 1714492800,
      "last_used_at": 1711987200,
      "revoked": false
    }
  ],
  "meta": { "api_version": "v1" }
}
```

#### `POST /api/v1/device-tokens`

Create a device-scoped token. The raw token value is returned exactly once at creation time.

**Permission:** `DeviceToken:Write`

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | Yes | Human-readable token name |
| `device_id` | string | No | Restrict token to a specific agent |
| `definition_id` | string | No | Restrict token to a specific instruction definition |
| `expires_at` | integer | No | Unix timestamp for token expiration |

**Response (201):**

```json
{
  "data": { "raw_token": "ydt_a1b2c3d4e5f6..." },
  "meta": { "api_version": "v1" }
}
```

#### `DELETE /api/v1/device-tokens/{id}`

Revoke a device token.

**Permission:** `DeviceToken:Delete`

**Response:**

```json
{
  "data": { "revoked": true },
  "meta": { "api_version": "v1" }
}
```

---

### Software Deployment

Manage software packages and their deployments to agents.

#### `GET /api/v1/software-packages`

List all registered software packages.

**Permission:** `SoftwareDeployment:Read`

**Response:**

```json
{
  "data": [
    {
      "id": "pkg-001",
      "name": "Firefox ESR",
      "version": "115.8.0",
      "platform": "windows",
      "installer_type": "msi",
      "content_hash": "sha256:abcdef...",
      "size_bytes": 58720256,
      "created_at": 1711900800,
      "created_by": "admin"
    }
  ],
  "meta": { "api_version": "v1" }
}
```

#### `POST /api/v1/software-packages`

Register a new software package.

**Permission:** `SoftwareDeployment:Write`

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | Yes | Package name |
| `version` | string | Yes | Package version |
| `platform` | string | No | Target platform (default `"windows"`) |
| `installer_type` | string | No | Installer type (default `"msi"`) |
| `content_hash` | string | No | SHA-256 hash of the installer |
| `content_url` | string | No | Download URL for the installer binary |
| `silent_args` | string | No | Silent install arguments (e.g. `/qn /norestart`). Same validation rules as `verify_command` — max 512 chars, rejects shell metacharacters and control characters. |
| `verify_command` | string | No | Post-install verification command. Max 512 chars. Rejects shell metacharacters (`;` `&` `|` `` ` `` `$` `<` `>` `(` `)`), C0 control characters (newline, tab, etc.), and DEL at REST input time to prevent fleet-RCE via shell injection (#771). Examples that pass: `msiexec /x {GUID} /qn`, `reg query HKLM\Software\App`, `dpkg -s firefox`. |
| `rollback_command` | string | No | Rollback command on failure. Same validation rules as `verify_command`. |
| `size_bytes` | integer | No | Installer file size in bytes |

**Response (201):**

```json
{
  "data": { "id": "pkg-001" },
  "meta": { "api_version": "v1" }
}
```

#### `GET /api/v1/software-deployments`

List software deployments, optionally filtered by status.

**Permission:** `SoftwareDeployment:Read`

**Query parameters:**

| Param | Type | Description |
|---|---|---|
| `status` | string | Filter by status: `pending`, `running`, `completed`, `failed`, `rolled_back` |

**Response:**

```json
{
  "data": [
    {
      "id": "dep-001",
      "package_id": "pkg-001",
      "status": "completed",
      "created_by": "admin",
      "created_at": 1711900800,
      "started_at": 1711901400,
      "completed_at": 1711902000,
      "agents_targeted": 50,
      "agents_success": 48,
      "agents_failure": 2
    }
  ],
  "meta": { "api_version": "v1" }
}
```

#### `POST /api/v1/software-deployments`

Create a new software deployment.

**Permission:** `SoftwareDeployment:Execute`

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `package_id` | string | Yes | ID of the registered software package |
| `scope_expression` | string | No | Scope expression selecting target agents |

**Response (201):**

```json
{
  "data": { "id": "dep-001" },
  "meta": { "api_version": "v1" }
}
```

#### `POST /api/v1/software-deployments/{id}/start`

Start a pending deployment.

**Permission:** `SoftwareDeployment:Execute`

**Response:** `{"data": {"started": true}, "meta": {"api_version": "v1"}}`

#### `POST /api/v1/software-deployments/{id}/rollback`

Roll back a deployment.

**Permission:** `SoftwareDeployment:Execute`

**Response:** `{"data": {"rolled_back": true}, "meta": {"api_version": "v1"}}`

#### `POST /api/v1/software-deployments/{id}/cancel`

Cancel a running or pending deployment.

**Permission:** `SoftwareDeployment:Execute`

**Response:** `{"data": {"cancelled": true}, "meta": {"api_version": "v1"}}`

---

### License Management

Manage Yuzu license entries, seat counts, and alerts.

#### `GET /api/v1/license`

Get the active license details, or `{"status": "none"}` if no license is active.

**Permission:** `License:Read`

**Response:**

```json
{
  "data": {
    "id": "lic-001",
    "organization": "Acme Corp",
    "seat_count": 500,
    "seats_used": 142,
    "issued_at": 1704067200,
    "expires_at": 1735689600,
    "edition": "enterprise",
    "status": "active",
    "days_remaining": 275
  },
  "meta": { "api_version": "v1" }
}
```

#### `POST /api/v1/license`

Activate a license.

**Permission:** `License:Write`

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `organization` | string | Yes | Organization name |
| `seat_count` | integer | Yes | Licensed seat count |
| `edition` | string | No | License edition (default `"community"`) |
| `expires_at` | integer | No | Unix timestamp for license expiration |
| `features_json` | string | No | JSON array of enabled feature flags |
| `license_key` | string | Yes | License activation key |

**Response (201):**

```json
{
  "data": { "id": "lic-001" },
  "meta": { "api_version": "v1" }
}
```

#### `DELETE /api/v1/license/{id}`

Remove a license entry.

**Permission:** `License:Write`

**Response:** `{"data": {"removed": true}, "meta": {"api_version": "v1"}}`

#### `GET /api/v1/license/alerts`

List license alerts (expiration warnings, seat limit approaching, etc.).

**Permission:** `License:Read`

**Query parameters:**

| Param | Type | Description |
|---|---|---|
| `unacknowledged` | flag | If present, return only unacknowledged alerts |

**Response:**

```json
{
  "data": [
    {
      "id": "alert-001",
      "alert_type": "expiration_warning",
      "message": "License expires in 30 days",
      "triggered_at": 1711900800,
      "acknowledged": false
    }
  ],
  "meta": { "api_version": "v1" }
}
```

---

### Topology

#### `GET /api/v1/topology`

Get infrastructure topology data. For full topology rendering, use the HTMX fragment endpoint `/frag/topology-data`. The REST endpoint provides a pointer for external callers.

**Permission:** `Infrastructure:Read`

---

### Fleet Visualization (3D)

The fleet-visualization endpoints expose a single aggregate `fleet_topology.v1` document that the `/viz/fleet` 3D renderer consumes. The endpoint dispatches `tar.fleet_snapshot` to every connected agent on cache miss, aggregates per-agent snapshots into machine cubes + interior process nodes + connection edges, and applies a 60 s LRU-of-2 cache (keyed on `include_vuln`).

#### `GET /viz/fleet`

Browser-facing page that renders the 3D fleet topology. The page itself is auth-gated only; per-request RBAC enforcement happens when the page's JS hits `GET /api/v1/viz/fleet/topology` (see below).

**Permission:** Session auth only (`require_auth`); redirects to `/login` on no session. The `--viz-disable` / `YUZU_VIZ_DISABLE` kill switch disables only the API endpoint, not the page shell — the page continues to load and the `503` from the disabled API surfaces in the browser console.

**Browser requirements:** importmap support is required (Chrome 89+, Firefox 108+, Safari 16.4+, Edge 89+). On unsupported browsers the page detects via `HTMLScriptElement.supports('importmap')` and surfaces a visible error overlay instead of a blank canvas.

**Cache posture:** the response sets `Cache-Control: no-cache, no-store, must-revalidate`. Vendored static assets (Three.js, OrbitControls, yuzu-viz.js) cache for 24 hours; the page itself revalidates on every navigation so a server upgrade cannot leave operators with a stale page that references the new assets.

**Deployment constraint:** the page hard-codes static asset paths (`/static/three.module.min.js`, `/static/three-orbit-controls.js`, `/static/yuzu-viz.js`) and the API path (`/api/v1/viz/fleet/topology`). Reverse-proxy deployments under a sub-path (e.g. `location /yuzu/`) are not currently supported — the absolute paths would 404 against the rewritten origin. Mount Yuzu at the root path of its host or fronting domain.

**Controls:**
- Drag — rotate camera around scene origin (OrbitControls)
- Mouse wheel — dolly in/out (clamped to `[4, 400]` units)
- `W`/`A`/`S`/`D` — pan the view in camera screen space (window-level listener; suppressed when a text-editable target has focus, so typing in a future overlay-panel input does not eat keystrokes)
- **Hover a machine cube body** — surfaces a fixed-position tooltip with the cube's hostname, OS, process count, and connection count. The cube tooltip is shown only when no interior process dot is intersected (process dots are raycasted first; see the process tooltip below). The wireframe outline overlay is excluded from hit-testing. Tooltip follows the cursor with a small offset to avoid flicker.
- **Hover a process dot (interior of a cube)** — surfaces a process tooltip with the process's pid, name, user account, and category. Process dots are raycasted *before* cube meshes so an operator can hover a dot through the translucent cube face and still see process details (otherwise the cube's outer face would always win by ray distance and dots would be unreachable). Agent-controlled fields (name, user, category) are HTML-escaped before render and capped at 256 characters before escaping to bound CPU cost on pathological 1MB cmdline-as-comm payloads.

**Renderer behaviour (PR 6):**

The page renders one translucent cube per fleet machine on a deterministic grid. Per-OS palette: Linux `#f0c674`, macOS/Darwin `#a0a0a0`, Windows `#5294e2`, default `#666666`. Live agents render at opacity `0.18`; stale agents (no response within the 5 s `tar.fleet_snapshot` deadline) render at opacity `0.08` so they remain visible without competing for attention. Hostname labels appear above each cube as `Sprite` text and always face the camera; labels longer than 24 characters truncate with an ellipsis (the full hostname is visible in the hover tooltip). Layout is seeded by an FNV-1a 32-bit hash of `agent_id` so the same fleet renders identically across reloads even when the server returns rows in a different order.

**Renderer behaviour (PR 7):**

Each machine cube contains interior `SphereGeometry` dots, one per process reported in the `processes` array of the topology payload. Dots are coloured by process category using a fixed six-colour palette: system `#6e7681`, browser `#58a6ff`, database `#d29922`, web `#56d364`, runtime `#bc8cff`, other `#8b949e`. Category values in the JSON payload are lowercase strings matching `category_to_string()` in the server's process classifier (`server/core/src/process_category.hpp`); the renderer normalises with `String(category).trim().toLowerCase()` and uses `Object.prototype.hasOwnProperty.call` for the palette lookup so unknown / mixed-case / whitespace-padded values fall through to `other` and prototype keys (`constructor`, `__proto__`) cannot poison the colour pipeline.

Dot positions are deterministic across reloads — `hash(pid|ppid)`-mod-bucket layout inside 78% of the cube's interior volume, with per-process `hash('j|pid')` jitter to break visual stripes. Per-machine processes are attached as a named child group (`yuzu-processes`) of each cube so they orbit and pan with the cube under OrbitControls without synchronisation overhead. To bound the worst-case render cost on heavily-threaded hosts (e.g. JVM thread pools), the renderer soft-caps at **1000 dots per cube**; the cube tooltip's `processes` count still reflects the true total reported by the agent.

Hover-then-tooltip is rAF-throttled — `mousemove` fires up to ~120 Hz on macOS trackpads but the bidirectional raycast (process dots + cube meshes) only runs once per `requestAnimationFrame` tick (~60 Hz) so the dominant CPU cost stays bounded even at large fleets.

To suppress process-level visibility for specific agents (privacy-sensitive hosts, regulated workloads, etc.), set `process_enabled=false` on those agents via `tar.configure` — see [`docs/user-manual/agent-plugins.md`](agent-plugins.md) §TAR for the per-source enable/disable surface. The `tar.fleet_snapshot` action will skip the process collector on those agents and the corresponding cubes will render with no interior dots (cube body and hover tooltip remain functional).

**Browser error handling.** When the JS renderer's fetch to `/api/v1/viz/fleet/topology` fails, the renderer surfaces a visible overlay (`#viz-error.shown`) on the canvas rather than leaving the scene blank. Any previously-rendered cubes are removed before the overlay is shown so the operator does not see "live data" cubes alongside a denial message.

| API response | Overlay message |
|---|---|
| `401` | "Session expired. Please reload the page." |
| `403` | "Access denied. Your role no longer permits viewing the fleet topology." |
| `413` | "Fleet exceeds the configured `machines_max` cap. Ask an administrator to raise `--viz-machines-max` or scope the request via a management group." |
| `503` | "Fleet visualization is currently disabled by an administrator." |
| Other 4xx/5xx | "Failed to fetch fleet topology (HTTP <status>). Try reloading." |
| Network failure | "Cannot reach server: <message>" |
| Truncated JSON / malformed body | "Malformed JSON from server (truncated response or proxy issue): <message>" |
| Schema mismatch | "Unexpected topology schema: <schema>. Reload the page (Ctrl+Shift+R) to pick up the new dashboard." |
| Empty `machines` field (server bug) | "Server returned no machines field. This is a server-side bug; check the server log." |

These overlays are in addition to the standard browser console entry. Previous releases (PR 5 and earlier) left the scene blank on every error condition.

#### `GET /api/v1/viz/fleet/topology`

Returns the full topology as JSON.

**Permission:** `Response:Read`.

**Query parameters**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `include_vuln` | bool (`0`/`1`) | `0` | When `1`, the per-process `worst_severity` and `cve_count` fields are populated from NVD CPE matching. (PR 2 hardening note: this overlay is wired but inert today because the agent payload doesn't carry installed versions; PR 10 of the ladder activates it.) Selects a separate cache slot from the default. |
| `fresh` | bool (`0`/`1`) | `0` | When `1`, the cache slot is invalidated before the get. A separate audit row (`viz.fleet_topology.invalidate`) is emitted. Use sparingly — concurrent `?fresh=1` storms force every dispatch to wait on the single-flight refill. |
| `machines_max` | integer in `[1, 100000]` | `5000` | Soft cap on the number of fleet machines returned. If the materialised snapshot has more than this, the route returns `413` rather than truncating (truncation would mislead operators about which subset they're seeing). |

**Responses**

| Status | When | Body |
|---|---|---|
| `200` | Success | `fleet_topology.v1` JSON envelope (see schema below) |
| `400` | `machines_max` non-numeric, out of `[1, 100000]`, or overflows `int` | `{"error":{"code":400,"message":"..."}, "meta":{"api_version":"v1"}}` |
| `403` | RBAC denied | Standard auth error envelope |
| `413` | Snapshot exceeds `machines_max` | `{"error":{"code":413,"message":"fleet topology exceeds machines_max..."}, "meta":{"api_version":"v1"}}` |
| `503` | Kill switch on (`--viz-disable`) or store unavailable | `{"error":{"code":503,"message":"..."}, "meta":{"api_version":"v1"}}` |

**Schema (`fleet_topology.v1`)**

```json
{
  "schema": "fleet_topology.v1",
  "schema_minor": 3,
  "generated_at": 1715299200,
  "include_vuln": false,
  "machines": [
    {
      "agent_id": "...",
      "hostname": "host-1",
      "os": "linux",
      "local_ips": ["10.0.0.1"],
      "ts": 1715299200,
      "stale": false,
      "processes": [
        {"pid": 1234, "ppid": 1, "name": "postgres", "user": "postgres", "category": "database"},
        {"pid": 5678, "ppid": 1, "name": "psql",     "user": "alice",    "category": "database"}
      ],
      "listeners": [
        {"proto": "tcp", "port": 5432, "pid": 1234, "process_name": "postgres", "local_addr": "0.0.0.0"}
      ],
      "connections": [
        {"proto": "tcp", "src_pid": 1234, "src_addr": "10.0.0.1", "src_port": 5432,
         "dst_addr": "10.0.0.2", "dst_port": 54321, "scope": "internal_fleet",
         "dst_agent_id": "...", "state": "ESTABLISHED"},
        {"proto": "tcp", "src_pid": 1234, "src_addr": "127.0.0.1", "src_port": 5432,
         "dst_addr": "127.0.0.1", "dst_port": 53210, "scope": "local",
         "dst_pid": 5678, "state": "ESTABLISHED"}
      ]
    }
  ]
}
```

`schema_minor` is bumped (not `schema`) on additive evolution; renderers MUST ignore unknown keys.

**`schema_minor` history:**

| Version | Change |
|---|---|
| 1 | Initial shape (PR 2–7) |
| 2 | PR 8 — `dst_pid` (uint32) added to `ConnectionEdge`. Present only on `scope: local` edges with a resolved peer process on the same machine; omitted (not zero) on non-local edges. Unmatched `local` edges (no reciprocal half visible in the same snapshot) are dropped server-side before serialisation, so a `local` edge in the response always carries a non-zero `dst_pid`. Strict-validating consumers pinned to minor version 1 should relax their validator to `minimum: 1` rather than exact-match. |
| 3 | PR 9 — `listeners[]` array added to each `MachineNode`. Each entry is a `ListenerSocket` (`proto`, `port`, optional `pid`, optional `process_name`). LISTEN-state rows continue to appear in `connections[]` during the deprecation window so consumers filtering `connections` by `state: LISTEN` are not broken; a future release will remove them from `connections[]` with a `Breaking` CHANGELOG entry. Strict consumers should migrate to `listeners[]` now. Ingestion path also flipped: agents push `tar.fleet_snapshot` JSON via `HeartbeatRequest.fleet_snapshot_json` every 30 s (PR 10), so cache-miss latency drops from ~800 ms (full agent dispatch) to ~2 ms (in-process map walk). The dispatch path remains as a cold-start fallback. |
| 4 | PR 12 — `ListenerSocket` grows an optional `local_addr` field (the kernel-reported bind address: `0.0.0.0`, `::`, a NIC IP, `127.0.0.1`, etc., bounded server-side at 64 bytes per field). Omitted from the wire envelope when the agent did not populate it (older snapshots). The renderer reads this field and drops loopback-only listeners (`127.0.0.0/8`, `::1`, including bracketed and v4-mapped-in-v6 forms `[::ffff:127.x]`) from the cube-surface socket ring — those sockets are by definition not reachable from any other instance. `0.0.0.0` and `::` survive the filter; specific NIC IPs survive. Strict consumers pinned to `schema_minor == 3` should relax their validator to `minimum: 3`. |

**Audit emissions**

Every request produces a `viz.fleet_topology` row (target_type `FleetTopology`, target_id empty). `?fresh=1` additionally produces a `viz.fleet_topology.invalidate` row immediately before the get. See [Audit Log](audit-log.md) for the full vocabulary.

**Metrics**

- `yuzu_viz_topology_request_seconds` (histogram) — end-to-end request latency on the success path (auth + RBAC + store + serialisation + response).
- `yuzu_viz_topology_fetch_duration_seconds` (histogram) — duration of the inner agent-dispatch path (`tar.fleet_snapshot` fan-out + response aggregation), measured only on cache-miss refills. Use to distinguish slow agent dispatch from slow auth / serialisation. Observed even on fetcher exception so a hung fetcher produces a visible upper-bound observation. (PR 6 / OBS-2.)
- `yuzu_viz_cache_hit_total` / `yuzu_viz_cache_miss_total` (counters).
- `yuzu_viz_oversize_response_total` (counter) — 413 cap-check fires.
- `yuzu_viz_agent_dispatch_timeout_total` (counter) — agents that didn't respond within the 5 s fetcher deadline.
- `yuzu_viz_refill_oversize_drops_total` (gauge) — store-level 256 MiB cap exceeded; refill not cached.
- `yuzu_viz_refill_wait_timeouts_total` (gauge) — single-flight waiters that timed out on the refill.
- `yuzu_viz_refill_waiters_total` (gauge) — single-flight piggyback depth.
- `yuzu_viz_topology_pushed_total{via=direct|gateway}` (counter, PR 10) — agent-pushed `fleet_snapshot.v1` payloads accepted via heartbeat. `via=direct` counts direct-to-server agents; `via=gateway` counts gateway-routed agents. A zero value across both labels after agents have been running for >30 s indicates agents have not upgraded to push-enabled binaries; the server falls back to the dispatch path automatically.
- `yuzu_viz_topology_push_parse_errors_total{via=direct|gateway}` (counter, PR 10) — agent-pushed payloads rejected by the shared parser (oversized > 2 MiB, `processes[]`/`connections[]` exceeding the 4096-row cap, or malformed JSON). A non-zero value indicates agent/server version skew, a corrupt heartbeat, or a compromised agent attempting to inject malformed data. Each rejection also emits a `topology.push.rejected` audit event. The parser also length-clamps every agent-controlled string field (`hostname`, process `name`/`cmdline`/`user`, connection meta strings) — truncation is logged but not counted here.
- `yuzu_viz_topology_push_rejected_total` (gauge) — pushes rejected by the IP-spoof guard because a claimed `local_ip` is owned by a *live* agent (an agent that has pushed within the 5-minute reclaim window). Non-zero signals a spoofing campaign or a NAT/DHCP misconfiguration.
- `yuzu_viz_pushed_cap_evictions_total` (gauge) — `pushed_` map entries evicted because the map hit the 100 000-agent hard cap. The victim is the least-recently-seen agent by *server* receipt time (not the agent-controlled `ts`); each eviction emits a `topology.push.evicted_for_cap` audit event.
- `yuzu_viz_pushed_map_size` (gauge) — current `pushed_` map occupancy; the memory-pressure signal to alert on before evictions begin.

**`fleet_snapshot.v1` (agent-emitted payload).** The `fleet_topology.v1` document above is the server-aggregated shape; the per-agent payload the agent pushes (via `HeartbeatRequest.fleet_snapshot_json`) or returns from a dispatched `tar.fleet_snapshot` is `fleet_snapshot.v1`. Its `schema_minor` is at **2** — the `1 → 2` bump added an optional `connections[].last_seen_seconds_ago` field, emitted only when non-zero, alongside the operator-tunable TAR plugin config key `fleet_snapshot_window_seconds` (default `3600`): connections seen within that window are merged into the snapshot even if not ESTABLISHED at the exact `/proc` sample instant. `fleet_snapshot_window_seconds` is a TAR plugin config key set via `tar.configure`, not a server CLI flag.

**Example**

```bash
curl -H 'Authorization: Bearer <token>' \
     'http://localhost:8080/api/v1/viz/fleet/topology?include_vuln=0&machines_max=2000'
```

#### `GET /fragments/viz/fleet/topology`

Identical data, wrapped in `<script type="application/json" id="viz-data">...</script>` for HTMX-driven swap-and-parse rendering. The `<` characters in JSON strings are escaped (`<\/`) before wrapping so an agent-controlled hostname or `cmdline` containing `</script>` cannot break out of the script element.

**Permission, query params, status codes:** identical to the JSON route above.

**Content-Type:** `text/html; charset=utf-8` (the body is HTML wrapping JSON, not JSON proper).

#### `GET /api/v1/viz/host/<agent_id>/topology`

Returns a single host's topology — one `MachineNode` sliced out of the
current fleet snapshot — for the per-host IPC-graph drill-down page. The
`agent_id` is taken from the path.

**Permission:** `Response:Read`.

**Responses**

| Status | When | Body |
|---|---|---|
| `200` | Success | `host_topology.v1` JSON envelope (see schema below) |
| `404` | No machine with that `agent_id` in the current snapshot | `{"error":{"code":404,"message":"host not found"}, ...}` |
| `403` | RBAC denied | Standard auth error envelope |
| `500` | Topology fetch threw or returned null | `{"error":{"code":500,"message":"..."}, ...}` |
| `503` | Kill switch on (`--viz-disable`) or store unavailable | `{"error":{"code":503,"message":"..."}, ...}` |

**Schema (`host_topology.v1`)**

```json
{
  "schema": "host_topology.v1",
  "schema_minor": 1,
  "generated_at": 1715299200,
  "stale": false,
  "machine": { "agent_id": "...", "hostname": "host-1", "...": "MachineNode — same shape as a fleet_topology.v1 machines[] entry" }
}
```

The `stale` flag is promoted from `machine.stale` to the envelope so a
renderer can decide whether to show a stale banner without reaching into
`machine`. The embedded `machine` object is byte-for-byte the same
`MachineNode` shape served by `/api/v1/viz/fleet/topology`.

**Audit emissions:** every request produces a `viz.host_topology` row
(target_type `HostTopology`, target_id = `agent_id`), with result
`success` / `denied` / `failure` and a detail of `kill_switch`,
`store_null`, `fetch_threw`, `snap_null`, `not_found`, or `fragment=1`.

**Example**

```bash
curl -H 'Authorization: Bearer <token>' \
     'http://localhost:8080/api/v1/viz/host/cedar-01/topology'
```

#### `GET /fragments/viz/host/<agent_id>/topology`

Identical data, wrapped in `<script type="application/json" id="viz-data">...</script>`
for HTMX rendering — same escaping and `Content-Type` posture as
`/fragments/viz/fleet/topology`. Permission and status codes identical to
the JSON route above.

#### `GET /viz/host/<agent_id>`

Browser-facing per-host drill-down page (the 2D Cytoscape IPC graph above
the TAR process tree), opened by double-clicking a cube in `/viz/fleet`.
Auth-gated only (`require_auth`); redirects to `/login` on no session.
The `agent_id` path segment is allow-listed to `[A-Za-z0-9._-]` — any
other character returns `400` — before it is templated into the page
shell. Per-request RBAC is enforced when the page's JS fetches
`/api/v1/viz/host/<agent_id>/topology`.

---

### Fleet Statistics

#### `GET /api/v1/statistics`

Get an aggregated view of fleet execution statistics.

**Permission:** `Infrastructure:Read`

**Response:**

```json
{
  "data": {
    "executions": {
      "total": 15420,
      "today": 230,
      "success_rate": 0.973,
      "avg_duration_seconds": 4.2
    },
    "active_agents": 142
  },
  "meta": { "api_version": "v1" }
}
```

---

### File Retrieval

#### `POST /api/v1/file-retrieval`

Receive file uploads from agents via the `content_dist` plugin's `upload_file` action. This endpoint is typically called by agents, not by operators.

**Permission:** `FileRetrieval:Write`

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `agent_id` | string | Yes | Agent uploading the file |
| `original_path` | string | No | Original file path on the agent |
| `sha256` | string | No | SHA-256 hash of the uploaded content |
| `size` | integer | No | File size in bytes |

**Response:**

```json
{
  "data": {
    "status": "received",
    "bytes": 1048576,
    "agent_id": "agent-001",
    "sha256": "abcdef..."
  },
  "meta": { "api_version": "v1" }
}
```

---

### Guaranteed State

Operator-facing surface for the Guardian (Guaranteed State) policy engine. See [Guaranteed State](guaranteed-state.md) for the feature guide and YAML rule schema. The Windows registry guard is live end-to-end (detect → enforce write-back → event ingest); per-guard fleet compliance aggregation on the `/status` endpoints lands in Guardian PR 4.

**RBAC matrix:**

| Role | Read | Write | Execute | Delete | Approve | Push |
|---|---|---|---|---|---|---|
| Administrator | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| ITServiceOwner | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| PlatformEngineer | ✓ | ✓ | | ✓ | | ✓ |
| Operator | ✓ | | | | | ✓ |
| Viewer | ✓ | | | | | |

Administrator and ITServiceOwner inherit Execute and Approve on `GuaranteedState` from the cross-type CRUD seed loop — those operations have no active Guardian handler today but the grants exist in the DB. PlatformEngineer's grants are explicit (Read/Write/Delete/Push only). `Push` is a Guardian-specific operation (distribute an existing rule set to scoped agents) that separates deploy authority from authoring authority.

#### `GET /api/v1/guaranteed-state/rules`

List all Guaranteed State rules.

- **Permission:** `GuaranteedState:Read`
- **Response:** `data[]` of `GuaranteedStateRule` objects (see OpenAPI schema).
- **5xx:** `503` if the store is unavailable.

#### `POST /api/v1/guaranteed-state/rules`

Create a rule.

- **Permission:** `GuaranteedState:Write`
- **Request body:**

A rule may be authored **structured** (the agent-enforceable form) or **legacy** (`yaml_source` only, stored but not agent-enforced). Supply *either* a `spark`+`assertion` pair *or* a `yaml_source`.

| Field | Type | Required | Description |
|---|---|---|---|
| `rule_id` | string | Yes | Stable operator-chosen id. Must match `[A-Za-z0-9._-]+`. |
| `name` | string | Yes | Human-readable name (unique per server). |
| `spark` | object | Structured | `{type, params}` trigger block, e.g. `{"type":"registry-change"}` or `{"type":"file-change"}`. |
| `assertion` | object | Structured | `{type, params}` desired-state block, e.g. `registry-value-equals`, `file-exists`, `file-hash-equals`. |
| `remediation` | object | No | `{type, params}` — `alert-only` (default) or `enforce`. `params` carries the **resilience policy** (`mode`, `max_attempts`, `backoff_*`, …) and `event_debounce_ms`. |
| `yaml_source` | string | Legacy | Full rule YAML; required only when no structured `spark`+`assertion` is given. The server generates `yaml_source` from the structured form otherwise. |
| `version` | integer | No | Starting version (default `1`). |
| `enabled` | boolean | No | Default `true`. |
| `enforcement_mode` | string | No | `enforce` (default) or `audit`. **Set once at creation — immutable on update** (see PUT below). |
| `severity` | string | No | `low` / `medium` (default) / `high` / `critical`. |
| `os_target` | string | No | Empty (any) or `windows` / `linux` / `macos`. |
| `scope_expr` | string | No | Scope DSL expression selecting target agents. |

The catalog of valid `spark` / `assertion` / `remediation` types and their `params` (including the resilience-policy bounds) is discoverable at [`GET /api/v1/guaranteed-state/schemas`](#get-apiv1guaranteed-stateschemas).

- **Response:** `201` with `data.rule_id`.
- **4xx:** `400` missing required fields, invalid JSON, or an **invalid resilience policy** (e.g. Bounded `max_attempts` < 1, `backoff_initial_ms` > `backoff_max_ms`) — returned as the A4 structured error envelope; `409` on duplicate `rule_id` or duplicate `name`.
- **Audit:** `guaranteed_state.rule.create` (`success` / `denied`).

#### `GET /api/v1/guaranteed-state/rules/{rule_id}`

Fetch a single rule.

- **Permission:** `GuaranteedState:Read`
- **Response:** `data` is a `GuaranteedStateRule` object.
- **4xx:** `404` if the rule does not exist.

#### `PUT /api/v1/guaranteed-state/rules/{rule_id}`

Update a rule. Version is incremented on every successful update regardless of whether any field changed.

- **Permission:** `GuaranteedState:Write`
- **Request body:** Any subset of the create-body fields *except* `enforcement_mode` (absent fields retain their current values). A body carrying structured `spark`/`assertion`/`remediation` blocks **re-authors** the Guard (re-deriving the canonical spec and re-validating the resilience policy) rather than dropping them; a metadata-only body leaves the existing spec intact.
- **`enforcement_mode` is immutable.** A body whose `enforcement_mode` differs from the stored value is rejected with `400` (`enforcement_mode is immutable — create a new Guard for a different posture (Watch vs Enforce)`); a different posture is a different Guard. A no-op echo of the current value is accepted.
- **Response:** `200` with `data.updated = true` and `data.version`.
- **4xx:** `400` invalid JSON, an invalid resilience policy (A4 envelope), or an `enforcement_mode` change; `404` rule not found; `409` on name conflict.
- **Audit:** `guaranteed_state.rule.update`.

#### `DELETE /api/v1/guaranteed-state/rules/{rule_id}`

Delete a rule.

- **Permission:** `GuaranteedState:Delete`
- **4xx:** `404` if the rule does not exist.
- **Audit:** `guaranteed_state.rule.delete`.

#### `POST /api/v1/guaranteed-state/push`

Queue a push of the active rule set to scoped agents. Returns `202 Accepted` — agent delivery is asynchronous. The fan-out is live: the server resolves `scope` to the in-scope agents and delivers each a per-agent filtered rule set (only rules whose `os_target` and `scope_expr` match that agent).

- **Permission:** `GuaranteedState:Push`
- **Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `scope` | string | No | Scope DSL selector. Empty = all agents. |
| `full_sync` | boolean | No | If `true`, agents replace their rule set; otherwise they merge. |

- **Response:** `202` with `data.queued = true`, `data.rules` (server-side rule count), `data.agents` (number of agents the push was dispatched to), `data.scope`.
- **4xx:** `400` if the JSON body is present but not an object.
- **Audit:** `guaranteed_state.push` (`success`). A server-initiated re-push to a lagging agent on heartbeat reconnect is audited separately under `guaranteed_state.reconcile` (principal `system`).

#### `GET /api/v1/guaranteed-state/events`

Query Guaranteed State events (rule violations, remediations, agent sync events).

- **Permission:** `GuaranteedState:Read`
- **Query parameters:** `rule_id`, `agent_id`, `severity`, `limit` (default 100, capped at 1000), `offset` (default 0).
- **Response:** `data[]` of event objects. Each object: `event_id`, `rule_id`, `agent_id`, `event_type`, `severity`, `guard_type`, `guard_category`, `detected_value`, `expected_value`, **`detail_json`**, `remediation_action`, `remediation_success`, `detection_latency_us`, `remediation_latency_us`, `timestamp`. `detail_json` is a structured JSON string: for DEX observations it carries the uniform keys `subject`/`reason`/`symbolic`/`component`/`metric`/`platform` (plus, for `process.crashed`, the legacy `process`/`exception_code`/`faulting_module`); empty string for plain drift events. Per-signal shapes are documented in [`docs/dex-signal-catalog.md`](../dex-signal-catalog.md).
- **4xx:** `400` on non-integer or negative `limit` / `offset`.
- **Ruleless DEX signal observations share this endpoint.** Filter `rule_id=__observation__` to retrieve `event_type=<obs_type>` rows (`process.crashed`, `process.hung`, `service.crashed`, `os.boot`, … — fleet-wide signals recorded independent of any rule; `severity` is a fixed `info`; `expected_value` empty). See [DEX signal observations](guaranteed-state.md#dex-signal-observations) and the [DEX dashboard](dex.md).
- **Audit (behavioral PII):** a query with a non-empty `agent_id` returns that device's signal history (`detail_json` reveals which apps a person runs) and emits a **`dex.device.view`** audit row (`target_type=Agent`, `target_id=<agent_id>`) — the same verb as the dashboard per-device drill-down. **Fail-closed:** the audit fires before the data is serialized; if the audit row cannot persist, the endpoint returns `503` + `Sec-Audit-Failed: true` and serves no data (parity with `GET /api/v1/dex/devices/{id}`). A query with no `agent_id` filter is a bulk operational query, not individually audited, and is unaffected by this gate.

#### `GET /api/v1/guaranteed-state/status`

Fleet-wide status rollup. Returns placeholder counts today; full fleet aggregation lands in Guardian PR 4.

- **Permission:** `GuaranteedState:Read`
- **Response keys:** `total_rules`, `compliant_rules`, `drifted_rules`, `errored_rules` (field names match the agent-side proto `GuaranteedStateStatus`).

#### `GET /api/v1/guaranteed-state/status/{agent_id}`

Per-agent status. Returns placeholder counts today; per-agent aggregation lands in Guardian PR 4.

- **Permission:** `GuaranteedState:Read`
- **Response keys:** `agent_id`, `total_rules`, `compliant_rules`, `drifted_rules`, `errored_rules`.

#### `GET /api/v1/guaranteed-state/device-compliance?baseline={name}&agent_id={id}`

Name-anchored, device-applicable Guardian compliance — the machine-readable sibling of the dashboard Baseline page, built for embedding a device's compliance against a curated Baseline into an external CMDB / ITSM record. Looks the Baseline up by **name** and returns the Guards **actually applicable to the device**, each with that device's last reported verdict.

- **Why name, not id.** An integration pins one stable constant (e.g. `ServiceNow Compliance`) once. Baseline names are unique and survive reseeds/rebuilds, where a `baseline_id` churns — so there is no per-environment id to reconfigure.
- **Permission:** `GuaranteedState:Read`, **per-device scoped** — a global grant passes fleet-wide; otherwise the caller must hold `Read` via a management group the device is in (mirrors the dashboard Guardian device lens, so a group-scoped operator/service account is not locked out of in-scope devices). _Upgrade note:_ a previously **group-scoped** token now receives `403` for devices outside its group(s) — earlier builds gated this route on a flat global check that would have passed them. A **global** `GuaranteedState:Read` token (the documented ServiceNow service-account setup) is unaffected.
- **Audit:** `guardian.device.view` (target type `Agent`) — same verb the dashboard per-device Guardian lens emits, so one SIEM filter catches both surfaces. (Behavioural per-device data.) A scoped-permission **denial** is audited separately at the auth layer as `auth.scoped_permission_required`.
- **Evidence integrity — fail-closed (CC7.2).** This is a behavioural-PII read, so if the `guardian.device.view` audit row cannot persist (locked store, disk-full, or a pipeline exception — including a throwing audit pipeline) the endpoint **refuses to serve**: it returns **`503` + `Sec-Audit-Failed: true`** with an A4 envelope carrying a `retry_after_ms` hint, and **withholds the compliance body** — parity with `GET /api/v1/dex/devices/{id}`. Serving audited per-device compliance while the evidence row is known-lost is exactly what audit-on-open prevents. The `503` is returned **before** the `404`, so an audit outage never reveals baseline existence without durable evidence. A CMDB integration should treat `Sec-Audit-Failed: true` as "retry after the audit subsystem recovers," not a permanent error; an audit-off deployment (no audit callback wired) serves normally. (The realistic failure modes also increment `yuzu_server_audit_emit_failed_total` and log to `spdlog`.) **Blast radius:** because this is the fleet-polled CMDB endpoint and there is no degraded-serve fallback, a *sustained* audit-store outage 503s **every** poll fleet-wide — size audit-store availability for the polling load, and expect a compliance-data blackout (not stale data) for the duration. (Per-route retry jitter to avoid synchronized retries across pollers is a tracked platform-wide hardening, #1647.)
- **Query params:** `baseline` (the Baseline **name**, unique; URL-encode spaces, e.g. `ServiceNow%20Compliance`), `agent_id` (the device). Both required.
- **`400`** if either param is missing, exceeds 256 chars (`auth::kMaxAgentIdLength` — the enrolled-agent-id ceiling, so a valid device id is never falsely rejected), or contains control characters (bytes `< 0x20`); **`403`** if the caller lacks `Read` on the device's scope (checked **before** the baseline lookup, so an out-of-scope caller gets `403` even for an unknown name — no name-existence oracle); **`404`** if no Baseline has that name; **`503`** if the route is misconfigured (its stores or scoped-permission function are unwired — non-transient, do not auto-retry) **or if the baseline store itself faults** (DB locked/corrupt — *retryable*; a transient store fault returns `503`, not the `404` a CMDB would otherwise read as "no such baseline → delete this CI"). The `400`/`404`/`503` bodies use the A4 envelope (`correlation_id`); the `403` is emitted by the shared auth/RBAC layer and carries that layer's denial body, not the A4 envelope (no `correlation_id`; exact shape varies by denial reason — RBAC vs service-scope). For a robust integration, branch on the HTTP `403` status and treat the body as opaque/diagnostic — do not structurally parse it (the `error` field may be a JSON string or an object depending on the denial reason).
- **Response keys:**
  - `baseline` — `{ baseline_id, name, lifecycle }`.
  - `deployed` — `true` when the Baseline's lifecycle is `deployed`. When `false`, `guards` is empty and `total_guards` is `0` — render a "No Baseline Deployed" placeholder.
  - `assessable` — **machine-readable go/no-go.** `true` only when the Baseline is `deployed` **and** at least one applicable Guard has reported (`total_guards > 0`). `false` for a draft Baseline, or a deployed Baseline this device has reported no applicable Guard against (newly-enrolled / offline / all out-of-scope). **When `assessable` is `false`, do not compute or render a compliance percentage** — branch a business rule on this flag instead of reconstructing the `deployed`+`total_guards`+`last_updated` conjunction. It is the machine signal that closes the `0/0` green-wash.
  - `agent_id`.
  - `total_guards`, `compliant`, `drifted`, `errored`, `pending` — counts over the Guards **applicable to this device** (see Semantics + the **compliance-percentage caution** below). Invariant: `total_guards == compliant + drifted + errored + pending`.
  - `snapshot_total` — the Baseline's full deployed-member count (the **superset** across all devices, an upper bound — **not** this device's in-scope count). `total_guards <= snapshot_total`; a gap is expected for a per-machine-scoped Baseline, but a large gap is a cue that this device's coverage may be partial.
  - `last_updated` — the newest `updated_at` across the guards (a "compliance as of" stamp); `null` **only when this device has reported no applicable guard**. A guard the device *did* report contributes its timestamp even if its verdict token is unrecognized (`pending`).
  - `guards[]` — `{ rule_id, name, status, updated_at }` per **applicable** Guard. `status` is `compliant` | `drifted` | `errored` | `pending`; `updated_at` is the ISO-8601 time this device last reported that Guard's verdict, `null` **only when this device has not reported the guard** (a reported guard carries its timestamp even when `status` is `pending`).

**Semantics — device-applicable subset.** One Baseline can carry a **superset** of Guards, each with its own `scope_expr`; the push fan-out arms a **different subset on each machine**. This endpoint returns only the Guards **actually applicable to the device** — the Baseline's `deployed_snapshot` intersected with the Guards the device has reported. A Guard that is out of scope for this device (never armed → never reported) is **absent** (not `pending`), so `total_guards` and `guards[]` reflect *this machine's* applicable set: different machines, querying the **same** Baseline name, legitimately see different Guards. (`pending` therefore means a Guard the device reported with an unrecognized verdict — normally `0`; an elevated `pending` after a partial fleet upgrade can indicate **agent/server version skew** — a newer agent emitting a verdict token this server build does not yet recognize, which upgrading the server resolves. The Guard still carries its real `updated_at` in that case.) Verdicts are the device's last *reported*, Observe-mode state, with no device-liveness fold.

> **Report-driven caveats.** Applicability is inferred from what the device has *reported*, with two consequences: (1) an in-scope Guard on an **offline** device is absent (not `pending`) until it reports — track device online/offline yourself and use `last_updated` for freshness; (2) a Guard that was **re-scoped out and re-deployed** keeps its last reported row, so it lingers on the CI until that row is overwritten or cleared (the forward direction — tag a device so a Guard *starts* applying — appears promptly; the reverse lags). The honest fix for both — evaluating each Guard's `scope_expr` against the device so in-scope-unreported shows `pending` and out-of-scope never shows — is a tracked computed-denominator upgrade.

> ⚠️ **Compliance percentage — do not gate on it (yet).** Because the denominator is *reported* applicable Guards, an in-scope Guard the agent has not yet reported drops **out of** `total_guards` rather than counting against it. So `compliant / total_guards` **over-estimates** compliance — a device reporting 3 of its 10 in-scope Guards, all compliant, reads as **100%** — and it over-estimates worst exactly when Guards are broken or the device is flaky. **Do not gate automated remediation or a CMDB compliance flag on this percentage** until the per-device `scope_expr` computed denominator ships (tracked follow-up). Treat the numbers as advisory: branch on `assessable`, watch the `snapshot_total − total_guards` gap as a partial-coverage cue, and cross-reference `last_updated` and your own device-liveness signal. (The `assessable:false` / `0/0` case below is the *zero*-coverage corner of this same caveat.)

> ⚠️ **Do not rename a referenced Baseline.** This route resolves the Baseline by **name**; renaming a Baseline that an integration pins (e.g. `ServiceNow Compliance`) makes every poll `404` until that integration is reconfigured to the new name — silently, until CIs stop updating. Treat the Baseline name as a **stable external identifier**; see the rename note in [Guaranteed State](guaranteed-state.md).

**Setup.** The Baseline must be **deployed** (a draft returns `deployed: false`), and **member edits appear here only after a re-deploy** rewrites the `deployed_snapshot`. Branch on the **`deployed`** flag (not `total_guards`) to decide "No Baseline Deployed": a deployed Baseline with zero applicable Guards legitimately returns `deployed: true, total_guards: 0`. **Treat `deployed: true` with `total_guards: 0` and `last_updated: null` as _not assessable_, not compliant** — it means no applicable Guard has reported yet (the device is offline / newly-enrolled, or every Guard is out of its scope). Do **not** compute a compliance percentage from a zero denominator, and do not render `0/0` as a pass — an unreachable or dead device would otherwise read as green. Per-machine variation is driven by each Guard's `scope_expr` (tag / OS / group) — see [Guaranteed State](guaranteed-state.md).

**Bulk CMDB sync.** This is a point-in-time, **single-device** read (not a push/subscription). To populate many CI records, poll per-device on a cadence (15–60 min is typical for a CMDB) rather than bursting every CI at once — concurrent fleet-wide polls contend on the same store locks the agent-heartbeat ingest path uses, so a synchronized stampede can delay heartbeat processing.

**Example:**

```bash
curl -s -H "Authorization: Bearer $TOKEN" --get \
  "$YUZU_URL/api/v1/guaranteed-state/device-compliance" \
  --data-urlencode "baseline=ServiceNow Compliance" \
  --data-urlencode "agent_id=$AGENT_ID"
```

```json
{
  "data": {
    "baseline": {"baseline_id": "ab12cd34ef56", "name": "ServiceNow Compliance", "lifecycle": "deployed"},
    "deployed": true,
    "assessable": true,
    "agent_id": "031e63a1-3139-48e6-beb6-50e3db062d0f",
    "total_guards": 3,
    "snapshot_total": 3,
    "compliant": 2, "drifted": 1, "errored": 0, "pending": 0,
    "last_updated": "2026-06-20T13:45:00Z",
    "guards": [
      {"rule_id": "g-fw",  "name": "Windows Firewall on", "status": "compliant", "updated_at": "2026-06-20T13:45:00Z"},
      {"rule_id": "g-rdp", "name": "RDP NLA required",    "status": "drifted",   "updated_at": "2026-06-20T12:30:00Z"},
      {"rule_id": "g-blk", "name": "BitLocker enabled",   "status": "compliant", "updated_at": "2026-06-20T13:44:00Z"}
    ]
  },
  "meta": {"api_version": "v1"}
}
```

#### `GET /api/v1/guaranteed-state/alerts`

Guaranteed State alerts (placeholder; alert aggregation lands in Guardian PR 11).

- **Permission:** `GuaranteedState:Read`
- **Response:** empty list in PR 2.

#### `GET /api/v1/guaranteed-state/schemas`

Guard authoring schema catalog — the static registry of `spark` / `assertion` / `remediation` types with per-type JSON Schemas. Driven by the same param-spec table the server-side validator uses, so the discovery surface and the validator cannot diverge. Drives dynamic authoring forms and agentic clients (the dashboard is one consumer).

- **Permission:** `GuaranteedState:Read`
- **Response:** `200` with `{version, schemas[]}`, each entry `{kind, type, json_schema}`. Includes the discriminated `registry-value-equals` encoding (per `value_type`), the `file-hash-equals` `expected_hash` hex format, and the `service-running` / `service-stopped` assertion schemas (with `service_name` pattern validation mirroring the agent's accepted service-name charset). The catalog is the source of truth for which spark/assertion/remediation types the agent actually implements — author against what it lists.
- **Caching:** carries a content-derived `ETag` and `Cache-Control: public, max-age=300`; a conditional request with `If-None-Match` returns `304 Not Modified`. The catalog is compiled-in, so this endpoint answers even when the rules store is unavailable.

---

### DEX (Digital Employee Experience)

The DEX aggregation endpoints are the machine-readable equivalent of the [DEX dashboard](dex.md): the same store rollups the HTMX fragments render, JSON-shaped for agentic workers. The signal endpoints read the ruleless `__observation__` projection (the same data the [events](#get-apiv1guaranteed-stateevents) endpoint exposes per-row); the perf endpoints aggregate registry heartbeat state at request time. All are gated on the same `GuaranteedState:Read` securable. The signal endpoints accept a `window` query parameter — one of `24h`, `7d`, `30d`, `all` (default `7d`; any other value resolves to `7d`); the perf endpoints are now-views with no window.

**Audit boundary.** The catalogue rollup, per-OS scope and the perf endpoints are aggregates / machine-health telemetry and are **not** audited. The per-signal drill-down returns a most-affected **devices** list (`agent_id`s — behavioral, individual-identifying) and emits a **`dex.signal.view`** audit row (`target_type=ObsType`, `target_id=<obs_type>`) on every call — the same verb as the dashboard per-signal view and consistent with the `agent_id`-filtered events query.

#### `GET /api/v1/dex/signals`

Whole-catalogue rollup — every observation type present in the window.

- **Permission:** `GuaranteedState:Read`
- **Query parameters:** `window`.
- **Response:** `data[]` of `{obs_type, count, distinct_devices, last_seen}`. `obs_type` is the stable machine key (e.g. `process.crashed`, `os.boot`); map your own labels. Not audited.

#### `GET /api/v1/dex/scope`

Per-OS signal coverage — how many distinct observation types each platform reports, with total event count (the live cross-OS coverage the dashboard derives).

- **Permission:** `GuaranteedState:Read`
- **Query parameters:** `window`.
- **Response:** `data[]` of `{platform, distinct_types, total_events}`. Not audited.

#### `GET /api/v1/dex/signals/{obs_type}`

One signal type's drill-down.

- **Permission:** `GuaranteedState:Read`
- **Path parameter:** `obs_type` — must match `[A-Za-z0-9._-]{1,64}`.
- **Query parameters:** `window`; `limit` (caps `subjects[]` and `devices[]`, default 50, clamped to 500).
- **Response (`200`):** an object `{obs_type, subjects[], by_os[], devices[], by_day[]}` where `subjects[]` is `{subject, count, distinct_devices, last_seen}`, `by_os[]` is `{platform, count, distinct_devices}`, `devices[]` is `{agent_id, count, last_seen}`, and `by_day[]` is `{day, count}`. A well-formed `obs_type` with no observations in the window returns `200` with empty arrays (it is a read-model query, not an entity lookup).
- **4xx:** `400` on a malformed `obs_type` or a non-integer / negative `limit`.
- **Audit (behavioral PII):** the `devices[]` array names the `agent_id`s exhibiting this signal, so the endpoint emits **`dex.signal.view`** (`target_type=ObsType`, `target_id=<obs_type>`) before serving — see the audit boundary note above. **Fail-closed:** if the audit row cannot persist, returns `503` + `Sec-Audit-Failed: true` and serves no device list (parity with `GET /api/v1/dex/devices/{id}`).

#### `GET /api/v1/dex/perf/fleet`

Fleet device-performance now-stats — the same numbers as the `yuzu_fleet_perf_*` Prometheus gauges and the `/dex` Performance tab, computed at request time.

- **Permission:** `GuaranteedState:Read`
- **Response:** an object `{cpu_pct, commit_pct, disk_lat_ms, reporting, windows_online}` where each metric is `{avg, p50, p90, max, n}` **or `null`** when no device reported it this cycle (absent, never 0). `reporting` counts devices contributing at least one metric; `windows_online` is the coverage-honest denominator (perf collectors are Windows-only today). Not audited.

#### `GET /api/v1/dex/perf/cohorts`

Fleet-relative performance percentiles per **cohort** — the distinct values of an operator-chosen tag key (see [Cohort benchmarking](dex.md#performance)).

- **Permission:** `GuaranteedState:Read`
- **Query parameters:** `key` — the cohort tag key (`[A-Za-z0-9_.:-]{1,64}`, default `model`).
- **Response:** `{key, floor, cohorts[], available_keys[]}`. Each cohort row is `{cohort, devices, suppressed}` plus, when not suppressed, per-metric stats as in `/perf/fleet`. Cohorts under `floor` (10) reporting devices carry `suppressed: true` with their population and **no stats**; devices without the key form the explicit `cohort: ""` (untagged) residual. `available_keys` lists the fleet's tag keys for picker UIs. `400` on an invalid key. Not audited.

#### `GET /api/v1/dex/perf/cohort-diff`

The direct **A-vs-B** cohort comparison (e.g. `image_type` vanilla vs layered, or `model` X vs Y) — where `/perf/cohorts` benchmarks each cohort against the *fleet*, this diffs two cohorts head-to-head. Closes the cohort-vs-cohort half of the benchmarking residual. *(The fleet-per-app benchmark — per-app perf over time across the fleet — is the separate **app-performance-over-time** surface below: `GET /api/v1/dex/perf/apps` / `app` / `group`, reading the retained Postgres aggregate.)*

- **Permission:** `GuaranteedState:Read`
- **Query parameters:** `key` — the cohort tag key (`[A-Za-z0-9_.:-]{1,64}`, default `model`); `a`, `b` — the two cohort values to compare (**both required**; an empty value is the untagged residual).
- **Response:** `{key, floor, found_a, found_b, a, b, delta_pct}`. `found_a`/`found_b` are `false` when a cohort has no reporting devices (its side is `null`). `a`/`b` are cohort rows `{cohort, devices, suppressed}` plus per-metric stats when not suppressed. `delta_pct` is `{cpu_pct, commit_pct, disk_lat_ms}` where each is A's p50 relative to B's p50 (B the baseline; positive = A higher), or `null` unless **both** cohorts expose that metric (neither suppressed below the 10-device floor). `400` on an invalid key or missing `a`/`b`. Not audited.

#### `GET /api/v1/dex/perf/devices`

The one device list behind every Performance drill: worst devices by a metric (default), the not-reporting complement, or one cohort's members.

- **Permission:** `GuaranteedState:Read`
- **Query parameters:** `metric` (`cpu` / `commit` / `disk_lat`, default `cpu`); `filter=not_reporting` (Windows devices with no perf sample this cycle); `cohort_key` (display key — always resolved, default `model`, so rows carry real cohort values); `cohort_value` (**when present**, restricts to that cohort; an empty value selects the untagged residual); `limit` (default 50, clamped to 500).
- **Response:** `data[]` of `{agent_id, cohort, cpu_pct?, commit_pct?, disk_lat_ms?, fleet_pctile?}`, worst-first by the sort metric (`fleet_pctile` is the device's nearest-rank position among all reported values; omitted when the device did not report the metric). `400` on an invalid `cohort_key` or `limit`. Machine-health telemetry (device state, not behavioral data) — not audited.

### Application performance over time

Per-application CPU / working-set **by version, over the retained window**, across the fleet or one management group — reading the retained Postgres aggregate (B1 per-device daily / B2 fleet rollup), not the live federated device drill. Per-app sampling is opt-in (`procperf_enabled`, off by default); a device contributes only after its first completed UTC midnight. The aggregate surfaces gate `GuaranteedState:Read` and are **not** audited (cohort posture); the per-device drill is behavioural PII and is audited fail-closed (see below). The same shared transform backs these endpoints, the `get_dex_app_perf` / `get_dex_group_app_perf` MCP tools, and the dashboard so the numbers cannot disagree.

> **Percentile + suppression semantics (all three trend endpoints).** Each `points[]` entry's `cpu_p50`/`cpu_p95`/`ws_p50`/`ws_p95` is either `null` (absent — empty population, **not** zero) or `{value, lower_bound}`. `lower_bound: true` means the percentile fell in the open top histogram bucket, so `value` is a **floor** — render it as "≥ value", never an exact quantile. `hist_stale: true` means the row was stamped under a superseded histogram scheme, so percentiles are withheld (the exact mean/max still stand). **Cohort floor:** any `(version, day)` point covering fewer than **10** devices (`kDexCohortFloor`) is suppressed — its stats are withheld and only `device_count` is honest (a sub-floor aggregate would single out an individual). This applies to **both** the fleet and the group endpoints.

#### `GET /api/v1/dex/perf/apps`

The picker: applications that currently have retained fleet data, so a worker discovers which `app=` values are answerable (A2 discoverability).

- **Permission:** `GuaranteedState:Read`
- **Response:** `{apps[], truncated}` where each app is `{app_name, versions, last_day}` (`versions` = distinct retained versions; `last_day` = most recent UTC-midnight epoch day with data). `truncated: true` when the distinct-app set exceeded the picker cap. `503` (with `retry_after_ms`) when the store provider is unwired or the read degrades. Not audited.

#### `GET /api/v1/dex/perf/app`

The fleet trend for one application — one point per `(version, UTC day)` over the B2 window (**up to 180 days**).

- **Permission:** `GuaranteedState:Read`
- **Query parameters:** `app` — **required**, ≤ 512 bytes, no control characters (a `400` otherwise; a NUL would truncate the bound query). `version` — optional; omitted = every version interleaved, each point tagged with its canonicalized `version`; same length/charset rule.
- **Response:** `{app, version, points[]}`. Each point: `{version, day, device_count, suppressed}` plus the full stat fields (`cpu_mean, cpu_max, cpu_p50, cpu_p95, ws_mean, ws_max, ws_p50, ws_p95, hist_stale`) **only when `suppressed` is false** — a sub-floor `(version, day)` point (fewer than 10 devices) carries `device_count` only, the same suppression the group endpoint applies (see the percentile/suppression note above). `400` on a missing/invalid `app` or `version`; `503` on store degrade. Not audited.

#### `GET /api/v1/dex/perf/group`

The same trend shape, aggregated **on-the-fly over one management group's member devices** (B1, **up to 31 days** — shorter than the fleet's 180-day B2 window, so a group series is shorter for the same app).

- **Permission:** `GuaranteedState:Read`. Gated on the **global** permission (like the cohort surface), not the per-device scope gate: the global check excludes management-group-scoped-only principals, so only a fleet-wide-Read caller — who can already compute every fleet/cohort aggregate — reaches it. No cross-operator exposure.
- **Query parameters:** `group_id` — **required**, ≤ 512 bytes, no control characters. `app` — **required**, same rule. `version` — optional, same rule.
- **Response:** `{group_id, app, version, floor, points[]}` where `floor` is the suppression threshold (10). Each point: `{version, day, device_count, suppressed}` plus the full stat fields **only when `suppressed` is false**. An empty/unknown group returns `200` with `points: []` (not a `503`). `400` on a missing/invalid parameter; `503` on store degrade. Not audited.

#### `GET /api/v1/dex/devices/{id}`

Per-device DEX read model — the machine-readable equivalent of the **DEX** lens on the `/device?id=` dashboard page.

- **Permission:** `GuaranteedState:Read`, scoped to the device's management group (a REST worker is held to the same per-device scope as the dashboard lens).
- **Path parameter:** `id` — the agent's `agent_id`.
- **Query parameters:** `window` — one of `24h` / `7d` / `30d` / `all` (default `7d`); an off-enum value is rejected with `400`.
- **Response:** `data` object `{agent_id, window, score, signals[]}` — `score` is the device's DEX experience score (0–100; `-1` = n/a, treat as "no data", **not** a low score); `signals[]` each `{obs_type, count, distinct_devices, last_seen}` for the window. An unknown `agent_id` returns `200` with `score:-1` and empty `signals` (the scope gate, not existence, decides access). `403` when the device is outside the operator's management scope. `503` when the store is unavailable, **or** `503` with header `Sec-Audit-Failed: true` when the audit row cannot persist (see Audit below).
- **Headers:** `X-Correlation-Id` is echoed on **every** response path (matches `/api/v1/events`); the value also appears as `correlation_id` in error bodies.
- **Audit:** emits `dex.device.view` (`target_type=Agent`, `target_id=<agent_id>`, `detail` carries `cid=<correlation_id>`) **before** the behavioral PII is served (audit-on-open). **Fail-closed:** if the audit row cannot persist (audit DB locked/full/corrupt), the endpoint returns `503` + `Sec-Audit-Failed: true` and serves **no** device data — serving audited PII while the evidence row is known-lost is exactly what audit-on-open prevents (SOC 2 CC7.2 / works-council).

#### `GET /api/v1/dex/devices/{id}/app-perf`

One device's retained per-`(app, version, day)` performance history (B1) — the per-device companion to the fleet/group trend. This is behavioural PII (which applications a person runs, over time), so unlike the aggregate endpoints it is scoped + audited fail-closed. This endpoint also backs the `/device` dashboard DEX drill's *Application performance over time* panel (same `dex.device.app_perf.view` verb, dashboard set-and-proceed posture); there is deliberately **no** MCP twin (MCP's set-and-proceed audit posture cannot express this REST fail-closed contract).

- **Permission:** `GuaranteedState:Read`, scoped to the device's management group.
- **Path parameter:** `id` — the agent's `agent_id`.
- **Query parameter:** `app` — optional display filter applied **in memory** to the device's returned rows (not a bound query parameter — the device's retained rows are fetched by `agent_id`, then narrowed by `app`), so there is no length/charset gate or `400` on it. Omitted = every resource-significant app-version on the device.
- **Response:** `data` object `{agent_id, rows[]}` where each row is one retained daily summary `{app_name, version, day, samples, instances_max, cpu_avg, cpu_max, ws_avg_bytes, ws_max_bytes}`. An unknown `agent_id` returns `200` with empty `rows`. `403` outside the operator's scope; `503` when the store is unavailable, or `503` + `Sec-Audit-Failed: true` when the audit row cannot persist (serving **no** data).
- **Headers:** `X-Correlation-Id` echoed on every response path.
- **Audit:** emits `dex.device.app_perf.view` (`target_type=Agent`, `target_id=<agent_id>`, `detail` carries `cid=<correlation_id>`) **before** the PII is served — kept a separate verb from `dex.device.view` / `dex.device.procperf.query` so usage-class reads stay separately countable for works-council evidence. Fail-closed as above.

#### `POST /api/v1/dex/devices/{id}/live`

Dispatches a read-only instruction to the live agent **now** and synchronously returns the result (~20 s). The machine-readable equivalent of the dashboard **"Get live info"** button. **POST, not GET** — it has a side effect (it dispatches a command), so it must not be fired speculatively by prefetchers/proxies/retry libraries.

- **Permission:** `GuaranteedState:Read` **and** `Execution:Execute`, both scoped to the device's management group.
- **Path parameter:** `id` — the agent's `agent_id`.
- **Query parameter:** `kind` — **required**. `uptime` dispatches `os_info/uptime`; `processes` dispatches `processes/list_hashed` (`proc|pid|name|sha256|path`; the SHA-256 is of each on-disk executable, resolved from the kernel, not argv[0], bounded at 512 MiB per image).
- **Dashboard-only kinds:** the dashboard **"Get live info"** grid renders ten additional card kinds (`process_tree`, `services`, `users`, `netconfig`, `arp`, `dns_cache`, `listening`, `connections`, `capture_sources`, `disk`). These are **not yet available on this REST endpoint** — passing any of them returns `400`. REST/JSON parity for all ten is deferred to [#1649](https://github.com/Tr3kkR/Yuzu/issues/1649); to probe e.g. the process tree via REST today, dispatch `processes/list_tree` directly through the async execution surface.
- **Response:** `data` object — `kind=uptime` → `{kind, uptime_display, uptime_seconds}`; `kind=processes` → `{kind, processes[].pid/name/sha256/path}`.
- **Errors:** `400` — `kind` missing/unrecognised. `403` — outside the operator's scope, or missing `Execution:Execute`. `429` — too many concurrent live queries server-wide (back off `retry_after_ms`). `502` — the device reported an error or the query failed. `503` — the device is offline (no connected agent), **or** `503` + `Sec-Audit-Failed: true` when the audit row cannot persist (the command is **not** dispatched — see Audit). `504` — the device did not respond within the timeout (`retry_after_ms`).
- **Headers:** `X-Correlation-Id` is echoed on **every** response path.
- **Audit:** emits `device.live.uptime` or `device.live.processes` (`target_type=Agent`, `target_id=<agent_id>`, `result=requested`, `detail` carries `cid=<correlation_id>`) **before** the command is dispatched — the operator's *request* is the works-council-relevant event, kept separately countable per kind. **Fail-closed:** if the audit row cannot persist, the endpoint returns `503` + `Sec-Audit-Failed: true` and the command is **not** dispatched (no usage-class probe without durable evidence). The dispatch outcome (reached an agent / offline) is carried by the HTTP response, not the audit row; `command_id` is recoverable from the response store / metrics by `cid`.

> **Scope boundary.** This is the **interactive, single-device** probe and is **concurrency-capped server-wide** (over-budget callers get `429`). It is **not** the fleet-scale path — do not fan a synchronous `/live` call out across thousands of devices. To read many devices at once, dispatch the equivalent read-only instruction to a *scope* via the async execution surface and collect results by `execution_id` (the cap deliberately keeps fan-out off this endpoint).

---

### Network

The machine-readable siblings of the `/network` dashboard fragments (A1 — fleet link health must be answerable without scraping HTML). Same render-time aggregation over heartbeat network facts, same `GuaranteedState:Read` gate. **The edge ships facts, never a verdict:** these report measured RTT / retransmit / throughput and *measured co-occurrence* counts, never a causal "it's the network" attribution.

> **Note — cohort parameter naming.** The network surface uses `key` for the cohort tag dimension (empty = no cohort, length-guarded), where the DEX performance surface uses `cohort_key` (validated, defaults to `model`). The difference is intentional and reflects each surface's cohort-resolution model — network cohorting is opt-in, DEX's always resolves. There is no `/api/v1/network/cohorts` endpoint (network has no per-cohort statistical aggregation); discover valid tag keys via the tag API.

#### `GET /api/v1/network/fleet`

Fleet network-quality now-stats — the same numbers as the `yuzu_fleet_net_*` Prometheus gauges and the `/network` Overview cards, computed at request time.

- **Permission:** `GuaranteedState:Read`
- **Response:** an object `{rtt_ms, retrans_pct, throughput_bps, reporting, rtt_reporting, online, cooccurrence}` where each metric is `{avg, p50, p90, max, n}` **or `null`** when no device reported it this cycle (absent, never 0). `reporting` counts devices contributing at least one metric; `rtt_reporting` is the **honest RTT denominator** (smoothed RTT is Linux-only today, so it is smaller than `reporting`); `online` is the total snapshot population. `cooccurrence` is `{degraded, also_device, also_app, network_only}` — counts of net-degraded devices that also show device-perf pressure / app instability (measured co-occurrence, never a cause; dormant until the degraded classification lands). Not audited.

#### `GET /api/v1/network/devices`

The one device list behind every network-quality drill: worst devices by a metric (default), the not-reporting complement, a co-occurrence band, or one cohort's members.

- **Permission:** `GuaranteedState:Read`
- **Query parameters:** `metric` (`rtt` / `retrans` / `throughput`, default `rtt`); `filter=not_reporting` (devices with no network sample this cycle); `cooc` (`device` / `app` / `network_only` / `degraded` — a co-occurrence band over net-degraded devices); `key` (cohort tag key — resolves the per-device cohort value; does not filter by itself); `cohort_value` (**when present**, restricts to that cohort; an empty value selects the untagged residual); `limit` (default 50, clamped to 500).
- **Response:** `data[]` of `{agent_id, platform, cohort, rtt_ms?, retrans_pct?, throughput_bps?, net_degraded, under_pressure, app_unstable, fleet_pctile?}`, worst-first by the sort metric (`under_pressure` / `app_unstable` are the co-occurring facts shown inline for correlation, never a verdict; `fleet_pctile` is the device's nearest-rank position, omitted when it did not report the metric). `400` on an invalid `limit`. Device-aggregate link health (device state, not behavioral data) — not audited.

---

### Patch Management

**`GET /api/patches`** — Query missing/installed patches.

- **Permission:** `Patch:Read`
- **Query params:** `agent_id`, `severity`, `status`, `limit` (default 100)

**`POST /api/patches/deploy`** — Create a patch deployment targeting specific agents.

- **Permission:** `Patch:Write`
- **Request body:**

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `kb_id` | string | Yes | — | KB identifier (format: `KBnnnnnnn`) |
| `agent_ids` | string[] | Yes | — | Target agent IDs |
| `reboot_if_needed` | bool | No | `false` | Reboot agents after patching |
| `reboot_delay_seconds` | int | No | `300` | Seconds to wait before reboot (clamped to 60–86400). A desktop notification warns the user before reboot. |
| `reboot_at` | int64 | No | `0` | Optional epoch timestamp for scheduled reboot. Must be in the future. `0` = use delay instead. |

- **Response (201):** `{"deployment_id": "...", "kb_id": "...", "target_count": N, "status": "pending"}`

> **Note:** Reboot orchestration requires the Yuzu agent to run with root (Linux/macOS) or Administrator (Windows) privileges. If the agent lacks these privileges, the reboot command will fail silently; the patch installation itself will still succeed.

**`GET /api/patches/deployments/:id`** — Deployment details with per-target status.

- **Permission:** `Patch:Read`
- **Response includes:** `reboot_delay_seconds`, `reboot_at`, and per-target `status` (pending, scanning, downloading, installing, verifying, rebooting, completed, failed, skipped, cancelled).

**`GET /api/patches/deployments`** — List deployments (paginated, default limit 50).

- **Permission:** `Patch:Read`

**`POST /api/patches/deployments/:id/cancel`** — Cancel a pending/running deployment.

- **Permission:** `Patch:Write`

---

### Settings — OIDC Configuration

**`POST /api/settings/oidc`** — Save OIDC / Entra ID SSO configuration.

- **Permission:** Admin only
- **Request body (form-encoded):**

| Field | Type | Required | Description |
|---|---|---|---|
| `issuer` | string | Yes | OIDC issuer URL (e.g., `https://login.microsoftonline.com/{tenant}/v2.0`) |
| `client_id` | string | Yes | Application (client) ID from Azure portal |
| `client_secret` | string | No | Client secret value. If empty and a secret already exists, the existing secret is preserved. |
| `redirect_uri` | string | No | Callback URL. If empty, auto-computed from web address/port. |
| `admin_group` | string | No | Entra group object ID for admin role mapping |
| `skip_tls_verify` | string | No | `"true"` to disable TLS cert verification for OIDC endpoints (insecure, dev only) |

- **Response:** Re-rendered Settings fragment (HTMX). Returns toast notification on success.
- **Effect:** Immediately reinitializes the OIDC provider with the new configuration. No server restart required.

**`POST /api/settings/oidc/test`** — Test OIDC discovery connectivity.

- **Permission:** Admin only
- **Request body (form-encoded):** `issuer`, `skip_tls_verify`
- **Response:** HTML feedback span — green on success, red on failure with specific error.

### Settings — Certificate Management

**`POST /api/settings/cert-upload`** — Upload PEM certificate file.

- **Permission:** Admin only
- **Request body (multipart/form-data):** `type` (cert|key|ca), `file` (.pem/.crt/.cer)

**`POST /api/settings/cert-paste`** — Paste PEM certificate content.

- **Permission:** Admin only
- **Request body (form-encoded):**

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | Yes | `cert` (server certificate), `key` (private key), or `ca` (CA certificate) |
| `content` | string | Yes | PEM-encoded content (must contain `-----BEGIN`) |

- **Response:** Re-rendered TLS Settings fragment (HTMX). Returns toast notification on success.
- **Effect:** Writes PEM content to the server cert directory. Key files are set to 0600 permissions. Config is updated immediately; HTTPS cert hot-reload will pick up changes within the polling interval.

---

### Settings — Plugin Code Signing

These endpoints drive the **Settings → Plugin Code Signing** card. The four `/api/settings/plugin-signing/*` routes are admin-only HTMX paths that return fragment HTML; the agent-facing distribution endpoint at `/api/v1/agent/plugin-policy` returns JSON. See *user-manual/agent-plugins.md → Plugin Code Signing* for the operator workflow and *user-manual/server-admin.md → vNEXT* for the upgrade notes.

**`GET /fragments/settings/plugin-signing`** — Render the Plugin Code Signing card fragment.

- **Permission:** Admin only
- **Response (200):** HTML fragment showing status badge (Disabled / Trust bundle loaded / Enforced), bundle metadata (cert count, SHA-256, up to 16 subjects), upload form, require-flag toggle, and Remove button.

**`POST /api/settings/plugin-signing/upload`** — Upload a PEM trust bundle.

- **Permission:** Admin only
- **Request body (multipart/form-data):** `file` (.pem/.crt; max 256 KB)
- **Validation:** the server validates the PEM with OpenSSL on the way in — at least one parsable X.509 certificate must be present, BEGIN/END markers required.
- **Response (200):** Re-rendered fragment, `HX-Trigger: showToast level=success`. Bundle is written atomically to `<cert-dir>/plugin-trust-bundle.pem` (temp + rename).
- **Response (400):** Validation failure. Body: `<span class="feedback-error">Rejected: …</span>`. Audit row emitted with `result=failure`, `target_type=PluginTrustBundle`, detail = the validation error.
- **Response (500):** I/O failure (cannot create cert dir, write tmp file, or rename to destination). Body: `<span class="feedback-error">…</span>`.

**`POST /api/settings/plugin-signing/clear`** — Remove the trust bundle and reset the require flag.

- **Permission:** Admin only
- **Request body:** None (HTMX hx-confirm)
- **Effect:** Two-phase commit — writes `plugin_signing_required=false` to `runtime_config` first, then removes `<cert-dir>/plugin-trust-bundle.pem`. If the DB write fails the file is **not** removed (prevents disk/DB desync) and a 500 is returned.
- **Response (200):** Re-rendered fragment, `HX-Trigger: showToast level=info`. Audit `plugin_signing.bundle.cleared` / `success`.
- **Response (500):** DB write failure. Audit `plugin_signing.bundle.cleared` / `failure` with the store error in `detail`. Bundle file untouched.

**`POST /api/settings/plugin-signing/require`** — Toggle the require-signature flag.

- **Permission:** Admin only
- **Request body (form-encoded):** `required` = `true`/`on` (checkbox checked) or absent (checkbox unchecked, treated as false).
- **Effect:** Writes `plugin_signing_required=<true|false>` to `runtime_config`.
- **Response (200):** Re-rendered fragment, `HX-Trigger: showToast level=success`. Audit `plugin_signing.require.changed` / `success`, `target_type=RuntimeConfig`, `target_id=plugin_signing_required`, `detail=<new_val>`.
- **Response (500):** DB write failure with the store error.

**`GET /api/v1/agent/plugin-policy`** — Distribution endpoint for operator agent-config flows. Returns the current trust bundle PEM and require flag as JSON.

- **Permission:** Admin only. The bundle holds X.509 certificates only (no private keys), but the SHA-256 fingerprint and the trust-anchor identity are operationally sensitive — non-admin token holders are not authorized to see when the trust anchor rotates. Future automatic agent-side fetch will introduce a dedicated agent identity for this endpoint.
- **Stability:** pilot-stable. The path `/api/v1/agent/...` and the JSON response shape may change before the GA `/v1/` contract is finalized; the field set is unlikely to shrink (forward-compatible additions only).
- **Response (200, bundle uploaded):**

  ```json
  {
    "enabled": true,
    "required": false,
    "trust_bundle_pem": "-----BEGIN CERTIFICATE-----\nMIIB…\n-----END CERTIFICATE-----\n",
    "cert_count": 2,
    "sha256": "abc123…"
  }
  ```

- **Response (200, no bundle uploaded):**

  ```json
  {"enabled": false, "required": false, "trust_bundle_pem": ""}
  ```

  (Status is 200, not 404 — "no bundle uploaded" is a normal operational state, not a fetch failure.)

- **Response (500, bundle on disk is unreadable):** standard `/api/v1/*` error envelope.

  ```json
  {"error": {"code": 500, "message": "Trust bundle on disk is unreadable"},
   "meta": {"api_version": "v1"}}
  ```

- **Operator usage:** curl this into a local file on each agent host, then point the agent at that file with `--plugin-trust-bundle`:

  ```bash
  curl -fsSL -H "Authorization: Bearer $YUZU_ADMIN_TOKEN" \
    https://server.example.com:8443/api/v1/agent/plugin-policy \
    | jq -r .trust_bundle_pem > /etc/yuzu/plugin-trust-bundle.pem
  ```

---

### Settings — Multi-Factor Authentication (MFA / TOTP)

These endpoints drive the **Settings → Multi-Factor Authentication** card. They are legacy (no `/v1/` prefix) and return HTMX fragments rather than JSON. All five require an admin session and target `#mfa-section` for swap-in. SOC 2 CC6.6 — see `docs/auth-mfa-design.md`.

**`GET /fragments/settings/mfa`** — Render the MFA card for the logged-in admin.

- **Permission:** Admin only.
- **Response (200):** HTML fragment showing current status (`Not enrolled` / `Enabled` / `Disabled`), recovery codes remaining, and the operative action buttons.

**`POST /api/settings/mfa/init`** — Begin TOTP enrollment.

- **Permission:** Admin only.
- **Effect:** Generates a fresh 20-byte CSPRNG secret and stores it provisionally (`mfa_enrolled_at` stays NULL). Re-running on an already-provisional row rotates the secret; refused if the user is already enrolled (`MfaAlreadyEnrolled` → 200 with error message in the fragment).
- **Response (200):** HTML fragment containing the `otpauth://` URI + base32 secret as a one-time reveal, plus the verify-code form. Response carries `Cache-Control: no-store, private`, `Pragma: no-cache`, and `Referrer-Policy: no-referrer` so browsers / proxies / CDNs cannot retain the material.
- **Audit:** `mfa.enroll.initiated` / `ok` (or `error` on failure).

**`POST /api/settings/mfa/verify`** — Confirm enrollment by submitting the first TOTP code.

- **Permission:** Admin only.
- **Request body (form-encoded):** `code=<6-digit TOTP from authenticator>`.
- **Effect on success:** Sets `mfa_enrolled_at = CURRENT_TIMESTAMP`, advances `mfa_last_counter` to the matched counter (replay defence), generates 10 single-use recovery codes (PBKDF2-SHA256 hashed in `mfa_recovery_codes`).
- **Response (200, success):** HTML fragment with the 10 recovery codes as a one-time reveal (`XXXX-XXXX-XXXX-XXXX`, 80 bits each). Same `Cache-Control: no-store` headers as `init`.
- **Response (200, failure):** Re-renders the verify form with an instruction to wait for the next 30 s code. Provisional row survives so the operator's authenticator app keeps working; the secret is NOT re-revealed.
- **Audit:** `mfa.enroll.verified` + `mfa.recovery_codes.generated` on success; `mfa.enroll.failed` on rejection.

**`POST /api/settings/mfa/recovery-codes`** — Regenerate the 10 recovery codes.

- **Permission:** Admin only. Requires existing enrollment.
- **Effect:** Atomic DELETE + 10×INSERT inside a `BEGIN IMMEDIATE / COMMIT` transaction. All prior codes (consumed and unconsumed) are invalidated.
- **Response (200):** HTML fragment with the fresh 10 codes as a one-time reveal. Same `Cache-Control: no-store` headers.
- **Audit:** `mfa.recovery_codes.generated` / `ok` (detail = `10 codes issued (rotation)`).

**`POST /api/settings/mfa/disable`** — Clear MFA state for the logged-in admin.

- **Permission:** Admin only.
- **Effect:** Atomic UPDATE users (clears `mfa_totp_secret`, `mfa_enrolled_at`; stamps `mfa_disabled_at`) + DELETE `mfa_recovery_codes` inside a `BEGIN IMMEDIATE / COMMIT` transaction. **Self-target guard (PR 3):** while `--mfa-enforcement` protects the caller's role (`required` → all roles; `admin-only` → admins), the disable is refused — the operator cannot strip the MFA that policy requires of them.
- **Response (200):** HTML fragment showing the "Not enrolled" state, or, when the self-target guard fires, the unchanged "Enabled" fragment with an inline "MFA is required by policy" message.
- **Audit:** `mfa.disabled` / `ok` (or `error` on DB failure, or `error` + detail `blocked: mfa_enforcement=<mode>` when the self-target guard refuses the disable).

> **Note — admin force-disable for other users:** the PR 1 endpoints are self-service only. An admin cannot disable another user's MFA via the dashboard or REST in this release; that feature is planned. For emergency lockout recovery use the break-glass procedure in `docs/ops-runbooks/auth-db-recovery.md` § Emergency MFA disable.

---

### Settings — User Management

These endpoints drive the **Settings → Users** tab. They are legacy (no `/v1/` prefix) and return HTMX fragments rather than the standard JSON envelope. All three require an admin session and the dashboard swaps the response body into `#user-section`.

The handler enforces a **self-target guard** on destructive operations: the currently authenticated operator cannot delete or demote their own account, even via a hand-crafted HTTP request that bypasses the dashboard. See `docs/user-manual/server-admin.md` → "Deleting a User" for the operator-side recovery procedure.

**`GET /fragments/settings/users`**

Render the user table fragment.

- **Permission:** Admin only
- **Response (200):** HTML fragment of the user table. The row matching the caller's session username renders an italic `Current user` badge in place of the Remove button. All other rows include an `hx-delete` attribute targeting the DELETE endpoint below.
- **Response (401):** Returned defensively when the admin gate passes but the session cannot be re-resolved (e.g., concurrent logout). The dashboard should redirect to login.
- **Response (500):** Returned when the resolved session has an empty username — defense-in-depth against an upstream auth misconfiguration (e.g., OIDC returning empty `preferred_username`). Server log records the cause.

**`POST /api/settings/users`**

Create a new local account.

> **Breaking change in v0.12.0:** The `role` field is now **ignored**. New users
> are always created as `user`. To assign or change a role use the dedicated
> `POST /api/settings/users/{username}/role` endpoint documented below — this
> closes security finding C1 (privilege escalation via the role parameter on
> create). Operators that scripted user-create with `role=admin` should expect
> the user to land as `user` and explicitly promote via the role endpoint.

- **Permission:** Admin only
- **Request body (form-encoded):**

| Field | Type | Required | Description |
|---|---|---|---|
| `username` | string | Yes | Account name. 1-64 chars, alphanumeric + `.` `_` `-` only. |
| `password` | string | Yes | New password. Minimum 12 characters. |
| `role` | string | (ignored) | Field is parsed but discarded; new users always land as `user`. Documented for backwards-compatibility — scripts that pass `role=admin` will not error, but the field has no effect. |

- **Response (200):** Re-rendered user table fragment with the new account visible. `HX-Trigger: {"showToast":{"message":"User created","level":"success"}}`. Audit event recorded as `user.create / success`.
- **Response (400):** Returned when `username` is invalid, `password` is empty, or password is shorter than 12 characters. Audit `user.create / denied / weak_password` (or `invalid_username`).
- **Response (409):** Returned when `username` already exists. Body is the re-rendered user table fragment with the duplicate-username toast. Audit `user.create / denied / duplicate_username`.
- **Response (401):** Defensive — admin gate passed but session not re-resolvable.
- **Response (500):** Defensive — session resolved with empty username.

**`POST /api/settings/users/:username/role`**

Change the role of an existing user. Dedicated endpoint introduced in
v0.12.0 to give role transitions their own audit chain (governance C1).

- **Permission:** Admin only
- **Request body (JSON):**

```json
{ "role": "admin" }
```

The `role` field must be exactly `admin` or `user`.

- **Response (200) success:** Role changed. Body is the re-rendered user table fragment. `HX-Trigger: {"showToast":{"message":"Role updated","level":"success"}}`. Audit `user.role_change / success` with `detail=old_role=user,new_role=admin` (or vice versa). **All active sessions for the target user are invalidated atomically** — the user must re-authenticate.
- **Response (200) no-op:** Same role requested as already assigned. Body is the re-rendered fragment with `HX-Trigger: {"showToast":{"message":"Role unchanged","level":"info"}}`. Audit `user.role_change / no_op` with `detail=same_role={admin\|user}`.
- **Response (400) invalid request:**
  - `invalid_username` — `:username` fails the allowlist (alphanumeric + `.` `_` `-`, 1-64 chars).
  - `invalid_json` — body is not valid JSON.
  - `missing_role` — body has no `role` field, or `role` is not a string.
  - `invalid_role` — `role` value is not `admin` or `user`.

  Each branch emits `user.role_change / denied / <reason>`.

- **Response (403):** Self-target rejected. Body is the re-rendered fragment with `HX-Trigger: {"showToast":{"message":"Cannot change your own role","level":"error"}}`. Audit `user.role_change / denied / self_role_change_blocked`. To demote yourself, create a second admin, log out, log in as the second admin, and use this endpoint to demote the first.

- **Response (404):** `:username` does not match any persisted user. Audit `user.role_change / denied / user_not_found`.

- **Response (500):** AuthDB write failed. Audit `user.role_change / denied / db_failure`.

**Example — promote `bob` to admin:**

```bash
curl -X POST https://yuzu-server:8080/api/settings/users/bob/role \
  -H "Content-Type: application/json" \
  -H "X-Yuzu-Token: yzt_..." \
  -d '{"role":"admin"}'
```

**`DELETE /api/settings/users/:name`**

Delete the named account.

- **Permission:** Admin only
- **Response (200):** Account deleted. Body is the re-rendered user table fragment. `HX-Trigger: {"showToast":{"message":"User deleted","level":"success"}}`. Audit event recorded as `user.delete / success`.
- **Response (400):** `:name` fails the username allowlist (e.g. contains `$`, `:`, or other disallowed bytes). Audit `user.delete / denied / invalid_username`.
- **Response (404):** `:name` does not match any persisted user. Audit `user.delete / denied / user_not_found`. Returned with a `User not found` toast in the re-rendered fragment.
- **Response (403):** Returned when `:name` matches the caller's own session username — the **self-deletion guard**. Body is the re-rendered user table fragment. Header includes:

  ```
  HX-Trigger: {"showToast":{"message":"Cannot delete your own account","level":"error"}}
  ```

  Audit event recorded as `user.delete / denied / self_delete_blocked`. The rejected attempt is logged at warn level on the server. To delete the account you are signed in as, create a second admin, sign out, sign in as the second admin, then delete the original.

- **Response (401):** Defensive — admin gate passed but session not re-resolvable.
- **Response (500):** Defensive — session resolved with empty username.

| HTTP status | Condition |
|---|---|
| 200 | Account deleted successfully |
| 400 | Username failed the allowlist regex |
| 404 | No persisted user matched `:name` |
| 403 | Target equals the caller's own username (self-delete guard) |
| 403 | Caller is not an admin (rejected by admin gate before handler) |
| 401 | Defensive — admin gate / session callbacks disagree |
| 500 | Defensive — session has empty username |

**Example — attempt self-delete (will be rejected):**
```bash
curl -X DELETE https://yuzu-server:8080/api/settings/users/admin \
  -H "X-Yuzu-Token: yzt_..." \
  -v
# HTTP/1.1 403 Forbidden
# HX-Trigger: {"showToast":{"message":"Cannot delete your own account","level":"error"}}
```

---

## Legacy API Endpoints

The following endpoints are under `/api/` (without the `v1` prefix). They predate the versioned API and remain available for backward compatibility. These endpoints return JSON but do not use the standard v1 envelope.

---

### Commands

#### `POST /api/command`

Send a command to one or more connected agents.

**Request body:**

```json
{
  "plugin": "hardware",
  "action": "cpu-info",
  "agent_ids": ["agent-01", "agent-02"],
  "parameters": {},
  "stagger": 30,
  "delay": 5
}
```

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `plugin` | string | Yes | -- | Target plugin name. |
| `action` | string | Yes | -- | Action within the plugin. |
| `agent_ids` | array of string | No | `[]` | Target agent IDs. Empty = broadcast to all. |
| `parameters` | object | No | `{}` | Key-value parameters passed to the plugin. |
| `scope` | string | No | `""` | Scope expression for device targeting (alternative to `agent_ids`). |
| `stagger` | integer | No | `0` | Max random delay in seconds per agent before execution. Prevents thundering herd on large-fleet dispatch. `0` = no stagger. |
| `delay` | integer | No | `0` | Fixed delay in seconds per agent before execution. Added before the random stagger. `0` = immediate. Total agent wait = `delay` + random(`0`, `stagger`). |

If `agent_ids` is empty or omitted and no `scope` is provided, the command is broadcast to all connected agents.

---

### Agents

#### `GET /api/agents`

List all currently connected agents with their metadata (hostname, OS, IP, connected plugins).

---

### Help

#### `GET /api/help`

Returns a catalog of all available plugins and their supported actions, as reported by connected agents.

---

### Instructions

#### `GET /api/instructions`

List all instruction definitions stored in the server.

#### `GET /api/instructions/{id}`

Get a single instruction definition by ID.

#### `POST /api/instructions`

Create a new instruction definition from JSON. The `id` field is optional —
when omitted the server generates a UUID; when supplied it is validated for
uniqueness against existing definitions.

**Permission:** `InstructionDefinition:Write`

**Response (200):** `{"id": "<id>"}` for the newly-created definition.

**Response (400):** Validation error (missing required field, invalid
`approval_mode`, malformed JSON). Body is `{"error": "<reason>"}`.

**Response (409):** Returned when an explicit `id` is supplied that already
exists in the store. Body is
`{"error": "instruction definition '<id>' already exists"}`.
Audit event recorded as `instruction.create / denied / duplicate_id`. To
update the existing definition use `PUT /api/instructions/{id}`.

**Response (503):** Instruction store not yet initialized.

#### `PUT /api/instructions/{id}`

Update an existing instruction definition.

#### `DELETE /api/instructions/{id}`

Delete an instruction definition.

#### `GET /api/instructions/{id}/export`

Export an instruction definition in a portable format.

#### `POST /api/instructions/import`

Import an InstructionDefinition (JSON envelope). Requires `InstructionDefinition:Write`.

**Signature enforcement** (since #1073 / W7.4 sibling-gap closure): the server rejects unsigned imports by default. Mirrors the [`POST /api/product-packs`](#post-apiproduct-packs) `--allow-unsigned-packs` model — closes the equivalent fleet-RCE surface where an operator with import permission can otherwise publish a definition carrying an arbitrary plugin invocation that dispatches on every targeted agent.

**Signed request body (recommended):**

| Field | Type | Required | Description |
|---|---|---|---|
| `id`, `name`, `type`, `plugin`, `action`, etc. | various | yes | Standard `InstructionDefinition` fields. |
| `yaml_source` | string | yes (when signed) | The verbatim YAML source — this is the signed-content carrier. Every persisted column is derived from it on the canonical path; signing `yaml_source` transitively covers the dispatch. |
| `signature` | string | optional | Hex-encoded Ed25519 signature over `yaml_source`'s bytes. |
| `publicKey` | string | optional | Hex-encoded Ed25519 public key (64 hex chars). |

**Signing rules:**

- `signature` + `publicKey` both present + valid → accepted.
- `signature` + `publicKey` both present + invalid → `400 signature verification failed for instruction — yaml_source may have been tampered with`.
- Exactly one of `signature` / `publicKey` present → `400 instruction-import has incomplete signing metadata — both signature and publicKey must be present together (or both absent)`.
- Neither present, signature enforcement on (default) → `400 instruction-import is unsigned and signature enforcement is enabled (set --allow-unsigned-definitions / YUZU_ALLOW_UNSIGNED_DEFINITIONS=1 to bypass)`.
- Neither present, signature enforcement off → accepted as **unverified** (operator opt-out via [`--allow-unsigned-definitions`](server-admin.md), emits `server.unsigned_definitions_allowed` audit row at startup).

A failed signature ALWAYS rejects, even when enforcement is off — `--allow-unsigned-definitions` only widens the unsigned-path policy, it does not skip crypto on present signatures.

**Audit:** every import attempt emits `instruction.import` with `result=success` on success, `result=denied` on rejection. The `target_id` is the definition's `id` on success; empty on rejection.

#### `POST /api/instructions/yaml`

Store raw YAML source for an instruction definition.

#### `POST /api/instructions/validate-yaml`

Validate YAML against the `yuzu.io/v1alpha1` DSL schema without persisting it.

#### `POST /api/instructions/{id}/execute`

Execute an instruction definition by dispatching it to agents. Requires `Execution:Execute` permission.

**Request body:**
```json
{
  "agent_ids": ["agent-uuid-1"],
  "scope": "",
  "params": {"key": "value"}
}
```

- `agent_ids` (optional) — array of agent IDs to target
- `scope` (optional) — scope expression (e.g., `group:servers`). Empty string + empty `agent_ids` = broadcast
- `params` (optional) — key-value parameters passed to the plugin

**Response (200):**
```json
{
  "command_id": "plugin-hexid",
  "agents_reached": 3,
  "definition_id": "filesystem.exists"
}
```

**Response (202 -- Approval Required):**

Returned when the definition's `approval_mode` is `role-gated` or `always` and the caller does not have direct-execute permission. The execution is queued for approval.

```json
{
  "status": "pending_approval",
  "approval_id": "abc123...",
  "definition_id": "def456..."
}
```

**Errors:** 404 (definition not found), 400 (invalid body), 202 (approval required -- execution queued, not yet dispatched), 403 (workflow blocked by approval-gated instruction and caller lacks execute-bypass permission), 503 (no agents reached or store unavailable).

---

### Instruction Sets

#### `GET /api/instruction-sets`

List all instruction sets.

#### `POST /api/instruction-sets`

Create a new instruction set (a named collection of definitions).

#### `DELETE /api/instruction-sets/{id}`

Delete an instruction set.

---

### Executions

#### `GET /api/executions`

List executions. Accepts `definition_id`, `status`, and `limit` as query parameters.

#### `GET /api/executions/{id}`

Get details of a single execution.

#### `GET /api/executions/{id}/summary`

Get an execution summary (counts of targeted, responded, success, failure agents).

#### `GET /api/executions/{id}/agents`

List agents involved in an execution.

#### `GET /api/executions/{id}/children`

List child executions spawned from a parent execution.

#### `POST /api/executions/{id}/rerun`

Re-execute a previously run instruction with the same parameters and targets.

#### `POST /api/executions/{id}/cancel`

Cancel a running execution.

---

### Schedules

#### `GET /api/schedules`

List schedules. Accepts `definition_id` and `enabled_only` as query parameters.

#### `POST /api/schedules`

Create a recurring schedule for an instruction definition. Supports cron expressions.

#### `DELETE /api/schedules/{id}`

Delete a schedule.

#### `POST /api/schedules/{id}/enable`

Enable or disable a schedule.

---

### Approvals

#### `GET /api/approvals`

List approvals. Accepts `status` and `submitted_by` as query parameters.

#### `GET /api/approvals/pending/count`

Return the count of instructions awaiting approval.

#### `POST /api/approvals/{id}/approve`

Approve a pending instruction execution.

#### `POST /api/approvals/{id}/reject`

Reject a pending instruction execution.

---

### Audit (Legacy)

#### `GET /api/audit`

Query audit events. Accepts `limit`, `principal`, and `action` as query parameters. Functionally equivalent to `GET /api/v1/audit` but without the v1 envelope.

---

### Scope Engine

#### `POST /api/scope/validate`

Validate a scope expression without executing it.

**Request body:**

```json
{
  "expression": "os = 'windows' AND tag:environment = 'production'"
}
```

#### `POST /api/scope/estimate`

Estimate how many agents match a scope expression.

**Request body:**

```json
{
  "expression": "os = 'windows' AND tag:environment = 'production'"
}
```

A `from_result_set:<id-or-alias>` reference in the expression is resolved against the authenticated principal's owned result sets before the estimate is computed (see the [scope DSL §9.3](../yaml-dsl-spec.md)). An alias that resolves to an absent, expired, or unowned set counts as zero members.

---

### Data Export

#### `POST /api/export/json-to-csv`

Convert a JSON result set to CSV format for download.

---

### Responses

#### `GET /api/responses/{id}`

Get command responses for a specific command ID.

#### `GET /api/responses/{id}/aggregate`

Aggregate response data for a command (counts, summaries).

#### `GET /api/responses/{id}/export`

Export response data in CSV format.

**Hardening (#1634, partial).** On a **corrupt or unavailable RBAC store**, these three readers fail **closed** — `GET /api/responses/{id}` and `/export` return no rows; `/aggregate` returns `503` — rather than exposing the whole fleet via the legacy read fallback. Per-management-group scoping of these readers for normal operators is **not yet effective**: a holder of global `Response:Read` sees all agents' rows (the per-agent filter is in place but inert under the current global gate; the gate change is tracked under #1634). Scripted/Grafana consumers of `/aggregate` that start receiving `503`/empty after an upgrade should check `/readyz` and the server log for `RbacStore` open/migrate errors.

---

### Tags (Legacy)

#### `GET /api/tags`

Get tags for an agent. Requires `agent_id` query parameter. Returns tags as an array of `{key, value, source, updated_at}` objects (different format from the v1 envelope).

#### `POST /api/tags/set`

Set a tag on an agent. Request body: `{"agent_id": "...", "key": "...", "value": "..."}`.

#### `POST /api/tags/delete`

Delete a tag from an agent. Request body: `{"agent_id": "...", "key": "..."}`.

#### `POST /api/tags/query`

Query agents that have a specific tag. Request body: `{"key": "...", "value": "..."}`. Returns `{"agents": [...], "count": N}`.

---

### Analytics and NVD

#### `GET /api/me`

Returns current user info (legacy version; prefer `/api/v1/me`).

#### `GET /api/analytics/status`

Returns the status of the analytics event pipeline.

#### `GET /api/analytics/recent`

Returns recent analytics events. Accepts `limit` as a query parameter (default 50).

#### `GET /api/nvd/status`

Returns the status of the NVD (National Vulnerability Database) sync.

#### `POST /api/nvd/sync`

Trigger a manual NVD database sync. Admin only. Runs asynchronously and returns immediately.

#### `POST /api/nvd/match`

Match installed software against known CVEs in the NVD database.

---

### SSE Event Stream

#### `GET /events`

Server-Sent Events stream for real-time dashboard updates. Events include agent connections/disconnections, command responses, and system notifications.

**Example (curl):**

```bash
curl -N -H "Cookie: yuzu_session=abc123" https://yuzu.example.com/events
```

**Event format:**

```
event: agent_connected
data: {"agent_id":"agent-01","hostname":"web-server-01"}

event: command_response
data: {"agent_id":"agent-01","command_id":"cmd-abc","status":"COMPLETED"}
```

#### `GET /sse/executions/{id}`

Per-execution Server-Sent Events stream introduced in v0.12.0. Backs the
inline drawer's live updates on the **Instructions → Executions** tab.

- **Permission:** `Execution:Read` (RBAC) or admin role
- **`{id}`:** the execution id returned by `POST /api/instructions/:id/execute` or visible in the executions list (regex: `[A-Za-z0-9_-]{1,128}`).
- **Content-Type:** `text/event-stream`
- **Headers:** `Cache-Control: no-cache`, `X-Accel-Buffering: no` (so reverse proxies don't buffer the stream into chunks).

**Reconnect / replay:** the server keeps a per-execution ring buffer of up to 1000 events covering ~30 seconds of activity. Browsers' `EventSource` automatically sends `Last-Event-ID` on reconnect; the server replays events whose monotonic id is greater than that value before resuming live publication.

**Event types:**

| Event | Emitted on | Payload (JSON in `data:`) |
|---|---|---|
| `agent-transition` | One per agent state change (`update_agent_status` write) | `AgentExecStatus` snapshot — `agent_id`, `status`, `exit_code`, `duration_ms`, `error` |
| `execution-progress` | Every `refresh_counts` recompute | counts snapshot — `total`, `succeeded`, `failed`, `running`, `pending` |
| `execution-completed` | Crossing the all-agents-responded threshold OR `mark_cancelled` | terminal status — `{"status":"succeeded"\|"completed"\|"cancelled"}`. Client should close the EventSource after this event. |

**Status-code map:**

| HTTP status | Condition |
|---|---|
| 200 | Stream attached; events follow |
| 401 | No session / token |
| 403 | RBAC `Execution:Read` denied |
| 404 | `{id}` does not exist in the execution tracker |
| 410 | Execution is already in a terminal status (succeeded / completed / cancelled / failed). Tells `EventSource` to stop reconnecting. |
| 503 | The per-execution event bus is not configured (test harness opt-out, or a configuration path that omits the bus). Returned at request time so the operator does not silently freeze waiting on a missing publisher. |

**Audit:** every successful subscribe emits one `execution.live_subscribe` audit event (`target_type=Execution, target_id={id}, result=success`). Per-session-per-execution dedup is **not** currently implemented (#700) — operators on the SOC 2 evidence chain receive a row per reconnect; the forensic-grade audit on first-load remains on `/fragments/executions/{id}/detail`'s `execution.detail.view`.

**Example (curl):**

```bash
curl -N -H "Cookie: yuzu_session=abc123" \
  https://yuzu.example.com/sse/executions/exec-abc123
```

**Example output (running execution, two agents, one in progress):**

```
event: agent-transition
id: 1
data: {"agent_id":"a-1","status":"running","exit_code":null,"duration_ms":null}

event: agent-transition
id: 2
data: {"agent_id":"a-1","status":"success","exit_code":0,"duration_ms":4218}

event: execution-progress
id: 3
data: {"total":2,"succeeded":1,"failed":0,"running":1,"pending":0}

event: agent-transition
id: 4
data: {"agent_id":"a-2","status":"success","exit_code":0,"duration_ms":5102}

event: execution-progress
id: 5
data: {"total":2,"succeeded":2,"failed":0,"running":0,"pending":0}

event: execution-completed
id: 6
data: {"status":"succeeded"}
```

#### `GET /api/v1/events`

Agentic-first JSON SSE channel introduced in sprint W5.1 (2026-05-18). This is the sibling of `/sse/executions/{id}` aimed at **external LLM-driven workers** (Claude, GPT, in-house) rather than a browser EventSource. Both routes subscribe to the same per-execution `ExecutionEventBus` and emit the same event taxonomy; the differences are:

- **`/api/v1/events`** wraps every event in a structured JSON envelope so the worker can discriminate events without out-of-band context.
- **A4 error envelope** on every 4xx/5xx — `correlation_id`, optional `retry_after_ms`, optional `remediation`.
- **No fragment rendering** — pure machine-consumable JSON.

The browser-oriented `/sse/executions/{id}` route is preserved for the dashboard drawer and is unchanged.

**Permission:** `Execution:Read`.
**Auth:** Bearer token, `X-Yuzu-Token` header, or session cookie. Same auth surface as every other `/api/v1/*` endpoint.

**Required query parameter:**

| Parameter | Type | Description |
|---|---|---|
| `execution_id` | string `[A-Za-z0-9_-]{1,128}` | Execution to subscribe to. Multi-execution / `?filter=execution_id:X\|agent_id:Y` syntax is sprint W5.2. |

**Optional replay parameters:**

| Parameter | Type | Description |
|---|---|---|
| `since` (query) | integer ≥ 0 | Replay events with `id > since`. Overrides `Last-Event-ID`. Non-integer values silently degrade to 0 (no replay) — mirrors the dashboard sibling. |
| `Last-Event-ID` (header) | string | Browser EventSource auto-reconnect header. Used only when `?since` is absent. |

**Event envelope (every `data:` line):**

```json
{
  "execution_id": "exec-abc",
  "event_id": 12,
  "timestamp_ms": 1716000000000,
  "type": "agent-transition",
  "payload": {"agent_id": "a-1", "status": "success", "exit_code": 0}
}
```

The `type` field is the canonical taxonomy: `agent-transition`, `execution-progress`, `execution-completed` (real bus events) plus three synthetic types the worker should handle:

| Synthetic type | When emitted | Meaning |
|---|---|---|
| `heartbeat` | Every ≤3s of provider idle | Liveness check; `data:` is empty. Workers should ignore. |
| `replay-gap` | First frame on reconnect if the ring buffer has evicted events with `id ≤ since` | Worker missed events `[missing_from..missing_to]` — state may be inconsistent. Payload: `{execution_id, type:"replay-gap", missing_from, missing_to}`. |
| `events-dropped` | Per-connection queue cap (500) was exceeded | A burst of events was dropped from THIS connection (not the bus). Payload: `{execution_id, type:"events-dropped", dropped_count, reason}`. Reconnect with `?since=<last_id>` to re-read what was dropped (subject to the bus ring-buffer window). |

**Status-code map and error envelope:**

| HTTP | Body | Condition |
|---|---|---|
| 200 | SSE stream begins | Stream attached, events follow |
| 400 | A4 envelope | Missing or malformed `execution_id` |
| 401 | (auth layer) | No session / token |
| 403 | (perm layer) | RBAC `Execution:Read` denied |
| 404 | A4 envelope | Execution does not exist |
| 410 | A4 envelope | Execution already terminal |
| 503 | A4 envelope with `retry_after_ms:5000` | Tracker or event bus not initialised (server warmup window) |

A4 envelope shape:

```json
{
  "error": {
    "code": 503,
    "message": "event bus unavailable",
    "correlation_id": "req-184c8a9012-7",
    "retry_after_ms": 5000,
    "remediation": "retry after server warmup; live events are unavailable until the bus is initialised"
  },
  "meta": {"api_version": "v1"}
}
```

**Response headers (always set on 200 and on most error responses):**

| Header | Value | Purpose |
|---|---|---|
| `X-Correlation-Id` | `req-<hex-ms>-<hex-seq>` | Grep token tying the response to the audit row and server-side spdlog rows. Echoed inside the A4 envelope on errors. |
| `Cache-Control` | `no-cache` | Prevents proxy / browser cache buffering. |
| `X-Accel-Buffering` | `no` | Tells nginx and similar proxies not to buffer the SSE stream. |
| `X-Content-Type-Options` | `nosniff` | Belt-and-braces against MIME sniffing. |
| `Sec-Audit-Failed` | `true` (only when audit persist failed) | SOC 2 CC6.6 evidence contract: subscription proceeded even though the audit row failed to persist (matches the PR #883 / W1.1 partial-failure pattern). |

**Audit:** every successful subscribe emits one `api.v1.events.subscribe` audit event (separate verb from the dashboard sibling's `execution.live_subscribe` so SIEM filters can distinguish browser vs agentic consumers). Per-session-per-execution dedup is **not** currently implemented (Deferred-5 / #700); a worker reconnecting frequently generates one row per reconnect.

**Restart behaviour:** the bus is in-process and in-memory. On server restart, every `Last-Event-ID` is invalidated — replays against an event id assigned by a previous process instance return nothing even if the execution is still active. Workers should fall back to `GET /api/v1/executions/<id>` to recover terminal state after a 503 or a long disconnect.

**Example (curl):**

```bash
curl -N \
  -H "Authorization: Bearer $YUZU_TOKEN" \
  -H "Accept: text/event-stream" \
  "https://yuzu.example.com/api/v1/events?execution_id=exec-abc123"
```

**Example output (running execution, A3 envelopes):**

```
id: 1
event: agent-transition
data: {"execution_id":"exec-abc123","event_id":1,"timestamp_ms":1716000000000,"type":"agent-transition","payload":{"agent_id":"a-1","status":"running"}}

id: 2
event: agent-transition
data: {"execution_id":"exec-abc123","event_id":2,"timestamp_ms":1716000002034,"type":"agent-transition","payload":{"agent_id":"a-1","status":"success","exit_code":0,"duration_ms":4218}}

event: heartbeat
data:

id: 3
event: execution-progress
data: {"execution_id":"exec-abc123","event_id":3,"timestamp_ms":1716000005112,"type":"execution-progress","payload":{"total":2,"succeeded":1,"failed":0,"running":1,"pending":0}}

id: 4
event: execution-completed
data: {"execution_id":"exec-abc123","event_id":4,"timestamp_ms":1716000010301,"type":"execution-completed","payload":{"status":"succeeded"}}
```

**Example output (late reconnect — replay-gap envelope):**

```
id: 41
event: replay-gap
data: {"execution_id":"exec-abc123","type":"replay-gap","missing_from":41,"missing_to":118}

id: 119
event: agent-transition
data: {"execution_id":"exec-abc123","event_id":119,"timestamp_ms":...,"type":"agent-transition","payload":{...}}
```

**Known limitations (sprint W5.1 skeleton; tracked as follow-ups):**

- No multi-execution / wildcard subscription — open one connection per execution, or wait for W5.2.
- No per-principal connection cap — operators expecting >10 concurrent agentic subscriptions should size the httplib worker pool accordingly.
- Replay/subscribe race window: a publish that arrives between the `replay_since` and `subscribe` calls is silently lost. A bus-side `subscribe_with_replay` is filed as a follow-up against both this route and the dashboard sibling.
- ~~The MCP `execute_instruction` tool currently returns `command_id`, not `execution_id`~~ — **closed by #1088.** Both the MCP `execute_instruction` tool and REST `POST /api/instructions/{id}/execute` now return `execution_id` alongside `command_id`. The full agentic dispatch-to-observe loop is functional.

---

### Dashboard TAR

#### `POST /api/dashboard/tar-execute`

Execute a TAR warehouse SQL query against targeted agents. Returns HTMX HTML fragments: a `thead` OOB swap with dynamic column headers and sets up an SSE stream for result rows.

**Permission:** `Execution:Execute`

**Request body (form-encoded):**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `sql` | string | Yes | A SELECT query using `$`-prefixed table names (e.g., `$Process_Live`, `$TCP_Hourly`). |
| `scope` | string | No | Target scope. An agent ID, `group:<expression>`, or `__all__` for all agents. Defaults to all connected agents. |

**Example (curl):**

```bash
curl -X POST https://yuzu.example.com/api/dashboard/tar-execute \
  -H "Cookie: yuzu_session=abc123" \
  -d "sql=SELECT name, pid FROM \$Process_Live LIMIT 10" \
  -d "scope=__all__"
```

**Response:** HTMX HTML fragments. The response contains:
1. A `<thead>` element with `hx-swap-oob="innerHTML:#tar-results-head"` containing dynamic column headers derived from the query result schema.
2. An SSE stream setup that delivers result rows as `<tr>` fragments.

**Safety controls:**
- Server-side: validates SELECT-only queries and applies a keyword blocklist (no INSERT, UPDATE, DELETE, DROP, ALTER, CREATE, ATTACH, DETACH, PRAGMA, VACUUM, REINDEX).
- Agent-side: untrusted queries run on a dedicated **read-only** SQLite connection through a `sqlite3` authorizer that permits only `SELECT`/`READ` of registry-known warehouse tables (`$Process_Live`, `$TCP_Hourly`, …) and scalar/aggregate functions. Writes, `ATTACH`, `PRAGMA`, schema-table reads (`sqlite_master`), recursive CTEs, and multi-statement input are denied at prepare time — the read-only connection makes writes structurally impossible regardless of the query text. `$`-prefixed table names are translated only outside string literals and comments, so the executed query always matches the validated form. Queries exceeding 4KB are rejected. A blocked query returns `query rejected: operation or table not permitted`.

#### `GET /tar`

Render the TAR dashboard page. Requires an authenticated session (302 redirect to `/login` otherwise). The page hosts the retention-paused source list, the ad-hoc TAR SQL frame, and the process tree viewer (a per-host process tree reconstructed from the device's local TAR warehouse; see `docs/user-manual/tar.md`).

**Permission:** Session-only (the page itself; embedded fragment endpoints carry their own permission gates — see below).

#### `GET /fragments/tar/retention-paused`

Render an HTML table fragment of the calling operator's most-recent TAR retention scan. Empty-state placeholders distinguish "no scan yet" from "scan returned no paused sources." **Scope caveat (ADR-0017):** this list gates on the *global* `Infrastructure:Read` permission — management-group confinement of this list/fan-out view is **not yet effective** (a confined operator is denied at the global gate rather than shown a narrowed list); when RBAC is disabled the list is the full enrolled fleet. Per-device confinement remains genuine only on the per-device `reenable` endpoint below.

**Permission:** `Infrastructure:Read`.

**Request:** no parameters.

**Response:** HTML fragment.

#### `POST /fragments/tar/retention-paused/scan`

Dispatch a `tar.status` command to the operator's visible-agent set and record the new command_id in the per-username scan slot. The next `GET /fragments/tar/retention-paused` picks up the responses.

**Permission:** `Execution:Execute`. Reading the resulting list still requires only `Infrastructure:Read`, but dispatching a command to the fleet is an Execute action.

**Request:** no parameters. The dispatch gates on the *global* `Execution:Execute` permission; management-group confinement of the dispatch target is **not yet effective** (ADR-0017 — a confined operator is denied at the global gate, not narrowed). When RBAC is disabled, the target is the full enrolled fleet.

**Response:** HTML fragment showing the dispatched-agent count or an empty-state placeholder.

**Audit:** Emits `tar.status.scan` with detail `dispatched to <N> agent(s) in scope`.

#### `POST /fragments/tar/retention-paused/reenable`

Dispatch a single-device `tar.configure` with `<source>_enabled=true`. Per-source independence is preserved — re-enabling `process` does not affect `tcp` / `service` / `user`.

**Permission:** `Execution:Execute`. Per-device RBAC visibility is verified before dispatch; out-of-scope `device_id` values collapse to the same 404 response as not-connected agents (no enumeration oracle).

**Request body (form-encoded):**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `device_id` | string | Yes | The agent ID. Must be in the operator's visible-agent set; otherwise rejected with 404 (same body as not-connected). |
| `source` | string | Yes | One of `process`, `tcp`, `service`, `user`. Other values rejected with 400 to prevent forged form submissions. The retention-paused list covers the always-on four; opt-in sources (`arp`, `dns`, `procperf`, `netqual`, `module`) are enabled/disabled via the **Capture sources** frame (below), not this route. |

**Response:**
- 200 OK with empty body and an `HX-Trigger` toast on success.
- 400 with explanatory body for missing/invalid params.
- 404 with body `Agent not reachable.` for both out-of-scope `device_id` and not-connected agent. Audit detail records the real reason (`scope_violation` vs `agent_not_connected`) server-side.

**Audit:** Emits `tar.source.reenable` with `result=success` and `detail` carrying `device=<id> source=<src>` on success, or `result=failure` with the real rejection reason on rejected attempts.

#### `GET /fragments/tar/capture-sources`

Render the **Capture sources** frame body for `/tar` (ADR-0015): an operator-scoped device picker plus a target the per-source toggle table loads into on host change.

**Permission:** `Infrastructure:Read`.

#### `GET /fragments/tar/capture-sources/load`

Self-re-issuing poll that dispatches `tar.status` + `tar.compatibility` to one selected device and renders the per-source toggle table (enable state, live-row count, per-OS support, category). First call dispatches and returns a polling fragment carrying the two command IDs; subsequent calls (`scmd`/`ccmd`/`n` params) poll until both complete.

**Permission:** `Infrastructure:Read` (scoped to the device) + `Execution:Execute` (the read dispatches a live query). **Audit:** `tar.sources.read` at dispatch.

**Query params:** `device` (agent ID); `scmd`/`ccmd`/`n` (poll continuation, server-supplied).

#### `POST /fragments/tar/capture-sources/push`

Apply staged capture-source enable/disable changes. The dashboard stages toggles client-side; Push dispatches one `tar.configure <source>_enabled=<bool>` per changed source (the accidental-enable guardrail — nothing dispatches until Push).

**Permission:** `Infrastructure:Read` (scoped) + `Execution:Execute`. Source names are validated against a fixed allowlist; values constrained to `on`/`off`.

**Request body (form-encoded):** `device` (agent ID); `changes` (comma-separated `source=on|off`, e.g. `arp=on,dns=on`).

**Audit:** `tar.sources.configure` — **one row per changed source**, `detail` = `<source>_enabled=<bool> command_id=<id>`.

#### `GET /fragments/tar/process-tree/device-net`

Self-re-issuing poll that dispatches read-only `tar.sql` over `$DNS_Live` + `$ARP_Live` to the selected host and renders the device-level **DNS-cache** and **ARP-table** panels embedded in the process-tree pane (ADR-0015). **Device-level, not per-process** (the DNS cache carries no pid).

**Permission:** `Infrastructure:Read` (scoped) + `Execution:Execute`. **Audit:** `tar.dns.read` **and** `tar.arp.read` (distinct verbs — DNS is usage-class PII, separately countable) at dispatch.

**Query params:** `device`; `dcmd`/`acmd`/`n` (poll continuation, server-supplied).

---

## Product Packs

Product packs are bundles of `InstructionDefinition`, `PolicyFragment`, `Policy`, and other content shipped as a single signed multi-document YAML file. Pack signature enforcement is **on by default** (#802 / W7.4) — unsigned packs are rejected at install. See [server-admin.md](server-admin.md) for the `--allow-unsigned-packs` escape hatch and [upgrading.md](upgrading.md) for the pack-signing migration recipe.

#### `POST /api/product-packs`

Install a product pack from a multi-document YAML bundle.

**Permission:** `ProductPack:Write`.

**Request body (form-encoded or multipart):**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `yaml_bundle` | string | Yes | Multi-document YAML; each `---`-separated document is parsed for its `kind:` and delegated to the matching store (`InstructionDefinition` → instructions, `PolicyFragment` → policies, etc.). A `ProductPack` document carries the pack metadata (`name`, `version`, `description`, optional `signature` + `publicKey`). |

**Response:**
- `201 Created` `{"id": "<pack-id>", "status": "installed"}` on success.
- `400 Bad Request` `{"error": "<message>"}` on rejection. Distinct error strings:
  - `pack '<name>' is unsigned and signature enforcement is enabled (set --allow-unsigned-packs / YUZU_ALLOW_UNSIGNED_PACKS=1 to bypass)` — the install was refused because the pack carried no `signature:` field and the server is enforcing signatures (default since #802). Either sign the pack or set the escape-hatch flag.
  - `signature verification failed for pack '<name>' — content may have been tampered with` — the signature was present but did not verify against the supplied public key.
  - `pack '<name>' has signature but no publicKey — cannot verify` — the bundle carried a `signature:` field but no `publicKey:`.
- Other 4xx for malformed YAML, missing required fields, or item-install delegation failures.

**Audit:** Emits `product_pack.install` with `result=success` and `target_id=<pack-id>` on accepted install, or `result=denied` with `target_type=ProductPack`, empty `target_id`, and the rejection message in `detail` on any 400 rejection (closes the SOC 2 CC6.7 logging gap from W7.4 governance).

#### `GET /api/product-packs`

List installed packs.

**Permission:** `ProductPack:Read`.

**Response:** JSON array of `{id, name, version, description, installed_at, verified}` objects.

#### `GET /api/product-packs/:id`

Get a single pack with its items.

**Permission:** `ProductPack:Read`.

**Response:** Single pack JSON object including the `items[]` array (each `{kind, item_id, name}`).

#### `DELETE /api/product-packs/:id`

Uninstall a pack, removing all delegated items.

**Permission:** `ProductPack:Delete`.

**Audit:** Emits `product_pack.uninstall`.

---

## MCP (Model Context Protocol)

The MCP endpoint enables AI models and automation tools to interact with Yuzu via JSON-RPC 2.0. Authentication is via Bearer token with an MCP tier. See [Authentication > MCP Tokens](authentication.md#mcp-tokens) for token creation details.

#### `POST /mcp/v1/`

JSON-RPC 2.0 endpoint for MCP tool calls, resource reads, and prompt requests.

**Permission:** Bearer token with `mcp_tier` set (readonly, operator, or supervised). The tier determines which tools are accessible, enforced before RBAC.

**Request body (tool call):**

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "list_agents",
    "arguments": {}
  },
  "id": 1
}
```

**Response (success):**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "[{\"agent_id\":\"abc-123\",\"hostname\":\"workstation-01\",\"os\":\"windows\",\"status\":\"online\"}]"
      }
    ]
  },
  "id": 1
}
```

**Response (error):**

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32001,
    "message": "MCP is disabled on this server"
  },
  "id": 1
}
```

**Available methods:**

| Method | Description |
|---|---|
| `tools/list` | List available MCP tools for the current tier |
| `tools/call` | Invoke an MCP tool by name with arguments |
| `resources/list` | List available MCP resources |
| `resources/read` | Read an MCP resource by URI |
| `prompts/list` | List available MCP prompts |
| `prompts/get` | Get a prompt template by name |

**Phase 1 tools (22 read-only):**

| Tool | Description |
|---|---|
| `list_agents` | List connected agents with status |
| `get_agent_details` | Detailed info for a specific agent |
| `query_audit_log` | Search audit events with filters |
| `list_definitions` | List instruction definitions |
| `get_definition` | Get a specific instruction definition |
| `query_responses` | Collect responses by `execution_id` (one dispatch) or `instruction_id` |
| `aggregate_responses` | Aggregate response data |
| `query_inventory` | Query inventory data with filters |
| `list_inventory_tables` | List available inventory tables |
| `get_agent_inventory` | Get inventory for a specific agent |
| `get_tags` | Get tags for a device |
| `search_agents_by_tag` | Find agents matching tag criteria |
| `list_policies` | List all policies |
| `get_compliance_summary` | Compliance summary for a device |
| `get_fleet_compliance` | Fleet-wide compliance overview |
| `list_management_groups` | List management groups |
| `get_execution_status` | Status of a specific execution |
| `list_executions` | List recent executions |
| `list_schedules` | List instruction schedules |
| `validate_scope` | Validate a scope expression |
| `preview_scope_targets` | Preview which agents match a scope |
| `list_pending_approvals` | List pending approval requests |

**Additional read-only tools (post-Phase-1).** Beyond the Phase 1 set the server also exposes the DEX signal/perf, network, and inventory read tools. The **application-performance-over-time** tools (this release) are:

| Tool | Description |
|---|---|
| `list_dex_perf_apps` | Applications with retained fleet app-perf data (the picker) |
| `get_dex_app_perf` | Fleet trend for one application, by version, over time |
| `get_dex_group_app_perf` | One management group's app trend (sub-floor-suppressed at 10 devices) |

All three gate `GuaranteedState:Read` and are not audited (cohort posture). The per-device app-perf drill (`GET /api/v1/dex/devices/{id}/app-perf`) is reachable via REST **and** the `/device` dashboard DEX drill (the *Application performance over time* panel), but has **no MCP twin** — its fail-closed audit contract cannot be expressed on MCP's set-and-proceed posture. See the *Application performance over time* REST section above for the shared percentile/suppression semantics.

**Resources:**

| URI | Description |
|---|---|
| `yuzu://server/health` | Server health status |
| `yuzu://compliance/fleet` | Fleet-wide compliance data |
| `yuzu://audit/recent` | Recent audit events |

**Prompts:**

| Name | Description |
|---|---|
| `fleet_overview` | Generate a fleet status overview |
| `investigate_agent` | Investigate a specific agent |
| `compliance_report` | Generate a compliance report |
| `audit_investigation` | Investigate audit trail activity |

**Server-side controls:**

| CLI Flag | Effect |
|---|---|
| `--mcp-disable` | Reject all `/mcp/v1/` requests |
| `--mcp-read-only` | Allow only read-only tools regardless of token tier |

---

## Authentication Endpoints

These endpoints manage user sessions and SSO flows.

#### `POST /login`

Authenticate with username and password.

**Permission:** None (unauthenticated).

**Request body (form-encoded):**

```
username=admin&password=secretpass
```

**Responses:**

| Status | Condition | Body |
|---|---|---|
| `200` + `Set-Cookie: yuzu_session=…` | Credentials valid; user has no MFA enrolled and no enforcement applies | `{"status":"ok"}` |
| `202` (`mfa_required`) | Credentials valid; user **has** TOTP MFA enrolled | `{"status":"mfa_required","mfa_pending_token":"<opaque>","expires_in":120}` — complete the challenge by posting the pending token + TOTP code (or recovery code) to `POST /login/mfa` |
| `202` (`mfa_enrollment_required`) | Credentials valid; user is **un-enrolled** and `--mfa-enforcement` (`admin-only` for admins / `required` for all) requires MFA | `{"status":"mfa_enrollment_required","mfa_pending_token":"<opaque>","otpauth_uri":"otpauth://...","secret_base32":"...","qr_svg":"<inline SVG, or empty>","expires_in":120}` — show the QR/secret and complete enrollment via `POST /login/mfa/enroll` |
| `401` | Invalid credentials | `{"error":{"code":401,"message":"Invalid username or password"}}` |
| `503` | Enforcement applies but `auth.db` is unavailable (fail-closed; no session minted) | `{"error":{"code":503,"message":"MFA enrollment is required but the authentication store is unavailable"}}` |
| `503` | The in-memory pending-challenge map is at capacity (server under a `/login` flood; transient load-shed) | `{"error":{"code":503,"message":"too many pending authentications, retry shortly"}}` — retry after a short back-off; emits `yuzu_auth_mfa_pending_load_shed_total` |

**Distinguish the two 202 variants by the `status` field**: `mfa_required` routes to `POST /login/mfa` (the user already has a secret); `mfa_enrollment_required` routes to `POST /login/mfa/enroll` (the user must enroll first). The `qr_svg` field on the enrollment variant is a server-rendered inline SVG QR code encoding `otpauth_uri` — inject it into the DOM **without** HTML-escaping (it is pure shape geometry, no user content). If `qr_svg` is the empty string, QR encoding failed; fall back to displaying `secret_base32` / `otpauth_uri` for manual entry. The `mfa_pending_token` is a 32-byte hex (64-char) opaque random; its lifetime is `cfg.mfa_login_pending_secs` (default 120 s). The pending state lives in process memory and is lost on server restart, and is not shared across HA replicas without sticky sessions.

#### `POST /login/mfa`

Complete a pending MFA login. Called after receiving HTTP 202 from `POST /login`.

**Permission:** None (unauthenticated — the pending token is the bearer).

**Request body (form-encoded):**

```
mfa_pending_token=<64-hex>&code=<6-digit TOTP or XXXX-XXXX-XXXX-XXXX recovery code>
```

The endpoint distinguishes TOTP from recovery by code shape — exactly 6 ASCII digits is interpreted as TOTP; anything else routes through recovery-code validation. Each pending token allows at most 5 attempts before being invalidated; once invalidated the operator must start over from `POST /login`.

**Responses:**

| Status | Condition | Body |
|---|---|---|
| `200` + `Set-Cookie: yuzu_session=…` | Code accepted | `{"status":"ok"}` |
| `401` | Invalid or expired pending token, or rejected code | `{"error":{"code":401,"message":"Invalid verification code"}}` — the wire body is identical for all failure modes so an attacker cannot distinguish "this pending token is valid; my code was wrong" from "this pending token is unknown." The distinguishing detail is in the audit `detail` column only. |

An enrollment-pending token issued by the `mfa_enrollment_required` branch is **rejected** here (use `POST /login/mfa/enroll`); a login-challenge token is likewise rejected at the enroll endpoint.

#### `POST /login/mfa/enroll`

Complete enforced TOTP enrollment for an un-enrolled user. Called after receiving HTTP 202 `mfa_enrollment_required` from `POST /login` (only reachable under `--mfa-enforcement=admin-only|required`). The `POST /login` 202 already revealed the `otpauth_uri` + `secret_base32` for the user to scan; this endpoint confirms the first code, promotes the provisional secret to enrolled, mints the session, and returns the one-time recovery codes.

**Permission:** None (unauthenticated — the enrollment-pending token is the bearer).

**Request body (form-encoded):**

```
mfa_pending_token=<64-hex>&code=<6-digit TOTP>
```

Only a 6-digit TOTP code is accepted (recovery codes do not exist until enrollment completes). Shares the `is_login` per-IP rate-limit bucket and the 5-attempts-per-pending cap.

**Responses:**

| Status | Condition | Body |
|---|---|---|
| `200` + `Set-Cookie: yuzu_session=…` | Code accepted; enrollment complete, session minted | `{"status":"ok","recovery_codes":["XXXX-XXXX-XXXX-XXXX", … 10 total]}` — revealed **once**; save them |
| `401` | Invalid/expired pending token, wrong token type, malformed or rejected code, or attempts exhausted | `{"error":{"code":401,"message":"Invalid verification code"}}` (uniform body; discriminator in the audit `detail`) |
| `503` | `auth.db` unavailable | `{"error":{"code":503,"message":"auth_db unavailable"}}` |

**Audit:** on success `mfa.enroll.verified` + `mfa.recovery_codes.generated` + `auth.login`; on failure `mfa.enroll.failed`.

#### `POST /login/mfa/stepup`

Refresh a session's MFA proof so the next high-risk REST/Settings mutation is accepted within the `mfa_step_up_window_secs` window (PR 2 of the MFA ladder). Called automatically by the dashboard HTMX layer when a request to a step-up-gated endpoint returns `401 mfa_step_up_required`; programmatic clients invoke it directly.

**Permission:** Existing session cookie (local or OIDC `auth_source`). API token / MCP token principals are step-up-exempt — they receive `400` here ("step-up is for session-cookie callers only — re-issue the API token to refresh MFA proof").

**Request body (form-encoded):**

```
code=<6-digit TOTP or XXXX-XXXX-XXXX-XXXX recovery code>
```

Same strict-shape gate as `POST /login/mfa`: exactly 6 ASCII digits is interpreted as TOTP, anything else as a recovery code. There is no per-request attempts cap (the session is itself the credential and is rate-limited at the server layer via the shared `is_login` bucket).

**Responses:**

| Status | Condition | Body |
|---|---|---|
| `200` | Code accepted; session's `mfa_verified_at` refreshed to now | `{"status":"ok"}` |
| `400` | Missing `code`, or principal is an API/MCP token, or an **OIDC** session (OIDC re-proves via SSO, not local step-up — the body points to `/auth/oidc/start`) | `{"error":{"code":400,"message":"missing code"}}` / `step-up is for session-cookie callers only` / `OIDC sessions re-prove MFA by re-authenticating with the identity provider …` |
| `401` | No session cookie, or rejected code | `{"error":{"code":401,"message":"MFA step-up failed"}}` |
| `503` | `auth_db` unavailable (transient) | `{"error":{"code":503,"message":"auth_db unavailable"}}` |

**Audit verbs:** `mfa.step_up.passed` on success (`detail=method=totp` or `method=recovery`); `mfa.step_up.failed` on each rejection with the rejection reason in `detail`.

**Example:**

```bash
# After a high-risk request returned 401 + mfa_step_up_required, post your
# current TOTP code (or a recovery code) to refresh the session's MFA proof:
curl -s -X POST https://yuzu.example.com/login/mfa/stepup \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --cookie "yuzu_session=<session>" \
  -d "code=123456"
# 200 {"status":"ok"}
```

#### Step-up envelope on high-risk endpoints

The following 11 endpoints return `401` with an MFA step-up envelope when the calling session's `mfa_verified_at` is older than `mfa_step_up_window_secs`:

- `POST /api/v1/tokens` (mint API token)
- `DELETE /api/v1/tokens/{id}` (revoke API token)
- `DELETE /api/v1/sessions` (admin force-logout another user)
- `POST /api/v1/software-packages` (upload software package)
- `POST /api/v1/software-deployments/{id}/start` (start deployment)
- `POST /api/v1/guaranteed-state/rules` (create Guardian rule)
- `PUT /api/v1/guaranteed-state/rules/{id}` (update Guardian rule)
- `DELETE /api/v1/guaranteed-state/rules/{id}` (delete Guardian rule)
- `POST /api/v1/guaranteed-state/push` (fan out Guardian rules)
- `DELETE /api/settings/users/{username}` (delete user)
- `POST /api/settings/users/{username}/role` (change user role)

For **OIDC** sessions the envelope's `challenge_url` is `/auth/oidc/start` (and the remediation points at re-SSO) instead of `/login/mfa/stepup` — an external identity has no local TOTP secret to step up against. An OIDC session whose IdP did not attest MFA at all (no `amr`) passes the gate under `--mfa-enforcement=optional`, but is **gated** (re-SSO) under `required` (or `admin-only` for an admin) — symmetric with a local user being forced to enrol.

Envelope shape:

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

`meta.mfa_step_up_required` is the boolean discriminator that distinguishes this 401 from an "unauthenticated" 401; `meta.challenge_url` tells the client where to re-prove — `/login/mfa/stepup` for local sessions, `/auth/oidc/start` for OIDC sessions. API token / MCP token principals **never see this 401** — the gate skips them entirely (the bearer credential was issued as part of an authenticated session and is itself the step-up).

#### `POST /logout`

Destroy the current session. Clears the `yuzu_session` cookie.

#### `GET /auth/oidc/start`

Begin the OIDC SSO login flow. Redirects to the configured identity provider.

#### `GET /auth/callback`

OIDC callback endpoint. The identity provider redirects here after authentication. Exchanges the authorization code for tokens and creates a local session.

---

## Health

#### `GET /health` (alias: `GET /api/health`)

> **Note:** `/api/health` is an identical alias of `/health`, provided for monitoring integrations that prefix every REST call with `/api/`. Both paths are unauthenticated, exempt from rate limiting, and return the same JSON body. The canonical path is `/health`; use `/api/health` only when your tooling enforces the `/api/` prefix unconditionally. (Restored in v0.12.0 — see issue #620.)
>
> **Note:** `/health` and `/api/health` are intentionally NOT draining-aware (they continue returning 200 during graceful shutdown). For load-balancer health checks that should drain in-flight traffic before stopping, use `/readyz` instead — it returns 503 once the server begins draining.
>
> **Body shape varies by auth.** Unauthenticated callers (the standard monitoring case) get the cheap probe response: `status`, `uptime_seconds`, `agents.online`, `stores.*`, `version`. Authenticated callers additionally get `agents.pending`, `executions.*`, and `system.*` — those fields require SQLite scans and are gated behind a session so an unauthenticated probe flood cannot become a DoS amplification primitive.

Structured JSON health check endpoint. This endpoint is **unauthenticated** and intended for load balancers, monitoring systems, and orchestration tools.

**Permission:** None (unauthenticated). Authenticated callers receive an extended response (see body-shape note above).

**Response:**

```json
{
  "status": "healthy",
  "uptime_seconds": 86400,
  "agents": {
    "online": 42,
    "pending": 3
  },
  "stores": {
    "responses": "ok",
    "audit": "ok",
    "instructions": "ok",
    "policies": "ok",
    "guaranteed_state": "ok",
    "offload_target": "ok",
    "ca": "ok"
  },
  "tls": {
    "default_certs_active": false,
    "ca_fingerprint": "",
    "ca_expires_at": 0
  },
  "executions": {
    "in_flight": 5,
    "completed_last_hour": 120,
    "failed_last_hour": 2
  },
  "version": "0.1.0"
}
```

| Field | Type | Description |
|---|---|---|
| `status` | string | `"healthy"` or `"degraded"` |
| `uptime_seconds` | integer | Server uptime in seconds |
| `agents.online` | integer | Number of currently connected agents |
| `agents.pending` | integer | Number of agents awaiting enrollment approval |
| `stores` | object | Health status of each data store (`"ok"` or `"error"`). Includes `ca` — the internal-CA store (`ca.db`) — which is load-bearing whenever default certs are active; `status` is `"degraded"` if it is down. |
| `tls.default_certs_active` | bool | `true` when running with built-in per-install default certs (replace before production — see security-hardening.md). Unauthenticated so monitoring can detect it. |
| `tls.ca_fingerprint` | string | SHA-256 fingerprint of the active default CA (empty when not on default certs). Public. |
| `tls.ca_expires_at` | integer | Unix timestamp of the default CA's expiry (`0` when not on default certs). |
| `executions.in_flight` | integer | Currently running instruction executions |
| `executions.completed_last_hour` | integer | Executions completed in the past 60 minutes |
| `executions.failed_last_hour` | integer | Executions that failed in the past 60 minutes |
| `version` | string | Server binary version |

The endpoint returns HTTP `200` when healthy and HTTP `503` when degraded.

**Authenticated response:**

When the request includes a valid session cookie, `Authorization: Bearer <token>`, or `X-Yuzu-Token` header, the response includes an additional `system` object with process health telemetry:

```json
{
  "system": {
    "cpu_percent": 12.5,
    "memory_rss_bytes": 134217728,
    "memory_vss_bytes": 536870912,
    "grpc_connections": 42,
    "command_queue_depth": 5
  }
}
```

| Field | Type | Description |
|---|---|---|
| `system.cpu_percent` | float | Server process CPU usage percentage |
| `system.memory_rss_bytes` | integer | Resident set size in bytes |
| `system.memory_vss_bytes` | integer | Virtual memory size in bytes |
| `system.grpc_connections` | integer | Number of connected agent gRPC streams |
| `system.command_queue_depth` | integer | Number of in-flight command executions |

This object is omitted for unauthenticated callers to avoid exposing process internals.

---

## Metrics

#### `GET /metrics`

Prometheus exposition format. Returns all server metrics.

**Example (curl):**

```bash
curl https://yuzu.example.com/metrics
```

**Example output (excerpt):**

```
# HELP yuzu_server_agents_connected Number of currently connected agents
# TYPE yuzu_server_agents_connected gauge
yuzu_server_agents_connected 42

# HELP yuzu_server_grpc_requests_total Total gRPC requests by method and status
# TYPE yuzu_server_grpc_requests_total counter
yuzu_server_grpc_requests_total{method="Register",status="ok"} 156
yuzu_server_grpc_requests_total{method="Heartbeat",status="ok"} 12483

# HELP yuzu_server_command_duration_seconds Command execution duration
# TYPE yuzu_server_command_duration_seconds histogram
yuzu_server_command_duration_seconds_bucket{plugin="hardware",le="0.1"} 89
yuzu_server_command_duration_seconds_bucket{plugin="hardware",le="1.0"} 95
yuzu_server_command_duration_seconds_bucket{plugin="hardware",le="+Inf"} 96
```

**Management group metrics:**

```
# HELP yuzu_server_management_groups_total Total number of management groups
# TYPE yuzu_server_management_groups_total gauge
yuzu_server_management_groups_total 5

# HELP yuzu_server_group_members_total Total members across all management groups
# TYPE yuzu_server_group_members_total gauge
yuzu_server_group_members_total 42
```

**Process health metrics:**

```
# HELP yuzu_server_cpu_usage_percent Server process CPU usage percentage
# TYPE yuzu_server_cpu_usage_percent gauge
yuzu_server_cpu_usage_percent 12.5

# HELP yuzu_server_memory_bytes Server process memory usage in bytes
# TYPE yuzu_server_memory_bytes gauge
yuzu_server_memory_bytes{type="rss"} 134217728
yuzu_server_memory_bytes{type="vss"} 536870912

# HELP yuzu_server_open_connections Number of connected gRPC agent streams
# TYPE yuzu_server_open_connections gauge
yuzu_server_open_connections 42

# HELP yuzu_server_command_queue_depth Number of in-flight command executions
# TYPE yuzu_server_command_queue_depth gauge
yuzu_server_command_queue_depth 5

# HELP yuzu_server_uptime_seconds Server process uptime in seconds
# TYPE yuzu_server_uptime_seconds gauge
yuzu_server_uptime_seconds 86400
```

> **Note:** Process health metrics (CPU, memory, connections, queue depth) are exposed on `/metrics` for all callers. When `--metrics-no-auth` is enabled, this data is accessible to unauthenticated remote clients.

All server metrics use the `yuzu_server_` prefix. Standard labels: `agent_id`, `plugin`, `method`, `status`, `os`, `arch`.
