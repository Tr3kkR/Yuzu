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

---

## Table of Contents

- [API Versioning](#api-versioning)
- [Authentication](#authentication)
- [JSON Envelope](#json-envelope)
- [REST API v1 Endpoints](#rest-api-v1-endpoints)
  - [Current User](#current-user)
  - [Management Groups](#management-groups)
  - [API Tokens](#api-tokens)
  - [Quarantine](#quarantine)
  - [RBAC](#rbac)
  - [Tags](#tags)
  - [Definitions](#definitions)
  - [Audit Log](#audit-log)
  - [Policy Fragments](#policy-fragments)
  - [Policies](#policies)
  - [Compliance](#compliance)
  - [Runtime Configuration](#runtime-configuration)
  - [Custom Properties](#custom-properties)
  - [Webhooks](#webhooks)
  - [Workflows](#workflows)
  - [OpenAPI Spec](#openapi-spec)
  - [Inventory](#inventory)
  - [Execution Statistics](#execution-statistics)
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
  - [SSE Event Stream](#sse-event-stream)
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

**Audit action names:**

| Action | Description |
|---|---|
| `management_group.create` | Group created |
| `management_group.update` | Group updated (rename, re-parent, membership type change) |
| `management_group.delete` | Group deleted |
| `management_group.add_member` | Agent added to group |
| `management_group.remove_member` | Agent removed from group |
| `management_group.assign_role` | Role assigned on group |
| `management_group.unassign_role` | Role removed from group |
| `api_token.create` | API token created |
| `api_token.revoke` | API token revoked. Can carry `result=success` (token was revoked) or `result=denied` (a non-owner without the admin role attempted a cross-user revoke). Denied events include `detail=owner=<real owner>` so forensics can tell a legitimate self-revoke from an enumeration probe. |
| `user.upsert` | Local account created, password changed, or role changed. `result` ∈ {`success`, `denied`}. Denied detail values: `self_role_change_blocked` (403, self attempted role change), `duplicate_username` (409, attempted create on an existing name). |
| `user.delete` | Local account deleted. `result` ∈ {`success`, `denied`}. Denied detail value: `self_delete_blocked` (403, self attempted to delete own account). |
| `instruction.create` | Instruction definition created. `result` ∈ {`success`, `denied`}. Denied detail value: `duplicate_id` (409, explicit `id` already exists). |
| `policy_fragment.create` | Policy fragment created. `result` ∈ {`success`, `denied`}. Denied detail value: `duplicate_name` (409, fragment with the same `name` already exists). |
| `quarantine.enable` | Device quarantined |
| `quarantine.disable` | Device released from quarantine |
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
| `event_types` | array | Yes | Events to subscribe to |
| `secret` | string | No | HMAC-SHA256 secret for payload signing |

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
| `silent_args` | string | No | Silent install arguments |
| `verify_command` | string | No | Post-install verification command |
| `rollback_command` | string | No | Rollback command on failure |
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

Operator-facing surface for the Guardian (Guaranteed State) policy engine. See [Guaranteed State](guaranteed-state.md) for the feature guide, YAML rule schema, and the PR-2 limitation that all rules report `errored` until the agent-side guards land in Guardian PR 3.

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

| Field | Type | Required | Description |
|---|---|---|---|
| `rule_id` | string | Yes | Stable operator-chosen id. Must match `[A-Za-z0-9._-]+`. |
| `name` | string | Yes | Human-readable name (unique per server). |
| `yaml_source` | string | Yes | Full rule YAML (`kind: GuaranteedStateRule`). |
| `version` | integer | No | Starting version (default `1`). |
| `enabled` | boolean | No | Default `true`. |
| `enforcement_mode` | string | No | `enforce` (default) or `audit`. |
| `severity` | string | No | `low` / `medium` (default) / `high` / `critical`. |
| `os_target` | string | No | Empty (any) or `windows` / `linux` / `macos`. |
| `scope_expr` | string | No | Scope DSL expression selecting target agents. |

- **Response:** `201` with `data.rule_id`.
- **4xx:** `400` missing required fields or invalid JSON; `409` on duplicate `rule_id` or duplicate `name`.
- **Audit:** `guaranteed_state.rule.create` (`success` / `denied`).

#### `GET /api/v1/guaranteed-state/rules/{rule_id}`

Fetch a single rule.

- **Permission:** `GuaranteedState:Read`
- **Response:** `data` is a `GuaranteedStateRule` object.
- **4xx:** `404` if the rule does not exist.

#### `PUT /api/v1/guaranteed-state/rules/{rule_id}`

Update a rule. Version is incremented on every successful update regardless of whether any field changed.

- **Permission:** `GuaranteedState:Write`
- **Request body:** Any subset of the create-body fields (absent fields retain their current values).
- **Response:** `200` with `data.updated = true` and `data.version`.
- **4xx:** `400` invalid JSON; `404` rule not found; `409` on name conflict.
- **Audit:** `guaranteed_state.rule.update`.

#### `DELETE /api/v1/guaranteed-state/rules/{rule_id}`

Delete a rule.

- **Permission:** `GuaranteedState:Delete`
- **4xx:** `404` if the rule does not exist.
- **Audit:** `guaranteed_state.rule.delete`.

#### `POST /api/v1/guaranteed-state/push`

Queue a push of the active rule set to scoped agents. Returns `202 Accepted` — agent delivery is asynchronous. In the PR-2 ship of Guardian the fan-out to agents is **not** wired; the endpoint accepts and audits the request so dashboards and SIEM pipelines can be exercised end-to-end. Fan-out lands in Guardian PR 3.

- **Permission:** `GuaranteedState:Push`
- **Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `scope` | string | No | Scope DSL selector. Empty = all agents. |
| `full_sync` | boolean | No | If `true`, agents replace their rule set; otherwise they merge. |

- **Response:** `202` with `data.queued = true`, `data.rules` (server-side rule count), `data.scope`.
- **4xx:** `400` if the JSON body is present but not an object.
- **Audit:** `guaranteed_state.push` (`success`, detail includes `fan_out_deferred_pr3=true` while PR 2 is in effect).

#### `GET /api/v1/guaranteed-state/events`

Query Guaranteed State events (rule violations, remediations, agent sync events).

- **Permission:** `GuaranteedState:Read`
- **Query parameters:** `rule_id`, `agent_id`, `severity`, `limit` (default 100, capped at 1000), `offset` (default 0).
- **Response:** `data[]` of event objects.
- **4xx:** `400` on non-integer or negative `limit` / `offset`.

#### `GET /api/v1/guaranteed-state/status`

Fleet-wide status rollup. PR 2 returns placeholder zeros; fleet aggregation lands in Guardian PR 4.

- **Permission:** `GuaranteedState:Read`
- **Response keys:** `total_rules`, `compliant_rules`, `drifted_rules`, `errored_rules` (field names match the agent-side proto `GuaranteedStateStatus`).

#### `GET /api/v1/guaranteed-state/status/{agent_id}`

Per-agent status. PR 2 placeholder; per-agent aggregation lands in Guardian PR 4.

- **Permission:** `GuaranteedState:Read`
- **Response keys:** `agent_id`, `total_rules`, `compliant_rules`, `drifted_rules`, `errored_rules`.

#### `GET /api/v1/guaranteed-state/alerts`

Guaranteed State alerts (placeholder; alert aggregation lands in Guardian PR 11).

- **Permission:** `GuaranteedState:Read`
- **Response:** empty list in PR 2.

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

Create a new local account, or change the caller's own password.

> **Behavior change in v0.11.0:** Prior versions treated this endpoint as a
> blanket upsert and silently overwrote existing accounts on a duplicate
> POST. As of v0.11.0 the endpoint rejects duplicates with **409** unless
> the request targets the caller's own row (self-password-change is still
> permitted). To update another user's password or role, delete and re-create
> the account.

- **Permission:** Admin only
- **Request body (form-encoded):**

| Field | Type | Required | Description |
|---|---|---|---|
| `username` | string | Yes | Account name. Must be non-empty. |
| `password` | string | Yes | New password. Minimum 12 characters. |
| `role` | string | Yes | `admin` or `user`. |

- **Response (200):** Re-rendered user table fragment with the new account visible. `HX-Trigger: {"showToast":{"message":"User created","level":"success"}}`. Audit event recorded as `user.upsert / success`.
- **Response (400):** Re-rendered fragment with an inline error script. Returned when `username` or `password` is empty.
- **Response (403):** Returned when `username` matches the caller's own session username AND `role` differs from the caller's current role — the **self-demotion guard**. Body is the re-rendered user table fragment. Header includes:

  ```
  HX-Trigger: {"showToast":{"message":"Cannot change your own role","level":"error"}}
  ```

  Audit event recorded as `user.upsert / denied / self_role_change_blocked`. The rejected attempt is logged at warn level. Self-password-change (same username, same role, different password) is **explicitly allowed** and returns 200.

- **Response (409):** Returned when `username` already exists and the request is not a self-password-change. Body is the re-rendered user table fragment. Header includes:

  ```
  HX-Trigger: {"showToast":{"message":"Username already exists","level":"error"}}
  ```

  Audit event recorded as `user.upsert / denied / duplicate_username`.

- **Response (401):** Defensive — admin gate passed but session not re-resolvable.
- **Response (500):** Defensive — session resolved with empty username.

**`DELETE /api/settings/users/:name`**

Delete the named account.

- **Permission:** Admin only
- **Response (200):** Account deleted. Body is the re-rendered user table fragment. `HX-Trigger: {"showToast":{"message":"User deleted","level":"success"}}`. Audit event recorded as `user.delete / success`.
- **Response (403):** Returned when `:name` matches the caller's own session username — the **self-deletion guard**. Body is the re-rendered user table fragment. Header includes:

  ```
  HX-Trigger: {"showToast":{"message":"Cannot delete your own account","level":"error"}}
  ```

  Audit event recorded as `user.delete / denied / self_delete_blocked`. The rejected attempt is logged at warn level on the server. To delete the account you are signed in as, create a second admin, sign out, sign in as the second admin, then delete the original.

- **Response (401):** Defensive — admin gate passed but session not re-resolvable.
- **Response (500):** Defensive — session resolved with empty username.

| HTTP status | Condition |
|---|---|
| 200 | Account deleted successfully (or no-op if `:name` does not exist) |
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

Import instruction definitions from a YAML file.

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
- Agent-side: validates `$`-prefixed table name whitelist, enforces single-statement limit, and rejects queries exceeding 4KB.

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
| `query_responses` | Query instruction responses |
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

Authenticate with username and password. Sets the `yuzu_session` cookie on success.

**Request body (form-encoded):**

```
username=admin&password=secretpass
```

**Success:** Redirect to `/` (dashboard).
**Failure:** Redirect to `/login?error=1`.

#### `POST /logout`

Destroy the current session. Clears the `yuzu_session` cookie.

#### `GET /auth/oidc/start`

Begin the OIDC SSO login flow. Redirects to the configured identity provider.

#### `GET /auth/callback`

OIDC callback endpoint. The identity provider redirects here after authentication. Exchanges the authorization code for tokens and creates a local session.

---

## Health

#### `GET /health`

Structured JSON health check endpoint. This endpoint is **unauthenticated** and intended for load balancers, monitoring systems, and orchestration tools.

**Permission:** None (unauthenticated).

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
    "policies": "ok"
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
| `stores` | object | Health status of each data store (`"ok"` or `"error"`) |
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
