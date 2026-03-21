# Yuzu REST API Reference

This document covers every HTTP endpoint exposed by the Yuzu server. Endpoints are grouped by functional area.

## Table of Contents

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
  "error": "human-readable message",
  "meta": { "api_version": "v1" }
}
```

HTTP status codes follow standard conventions: `200` for success, `201` for resource creation, `400` for bad requests, `401` for unauthenticated, `403` for forbidden, `404` for not found, `503` for service unavailable.

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
- **Cycle detection:** The new parent must not be a descendant of the group being updated. Moving a group under one of its own children would create a circular hierarchy and returns `400`.
- **Depth limit:** Re-parenting must not exceed the maximum hierarchy depth of 5 levels. Returns `400` if exceeded.

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
  "expires_at": 1742385600
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | Yes | Human-readable label |
| `expires_at` | integer | No | Unix epoch seconds. `0` or omitted = never expires. |

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

**Response:**

```json
{
  "data": { "revoked": true },
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
| `api_token.revoke` | API token revoked |
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

Create a new instruction definition from JSON.

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
    "response_store": "ok",
    "audit_store": "ok",
    "tag_store": "ok",
    "policy_store": "ok",
    "custom_properties_store": "ok"
  },
  "executions": {
    "in_flight": 5,
    "completed_last_hour": 120,
    "failed_last_hour": 2
  },
  "version": "0.9.0"
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

All server metrics use the `yuzu_server_` prefix. Standard labels: `agent_id`, `plugin`, `method`, `status`, `os`, `arch`.
