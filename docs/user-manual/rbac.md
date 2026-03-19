# Role-Based Access Control (RBAC)

Yuzu implements granular role-based access control with deny-overrides-allow semantics, scoped permissions via management groups, and support for both built-in and custom roles.

## Enabling RBAC

RBAC is controlled by a global toggle. When disabled, all authenticated users have full access (with a legacy fallback: write/delete/execute/approve operations still require the `admin` session role). When enabled, every API call and UI action is checked against the caller's assigned roles.

Toggle RBAC via the Settings page or the server configuration file:

```cfg
[rbac]
enabled = true
```

## Concepts

| Concept | Description |
|---|---|
| **Principal** | A user or group identity. Matches the authenticated username or an OIDC group claim. |
| **Role** | A named collection of permissions. Can be system-defined or custom. |
| **Securable type** | A category of resource that permissions apply to (e.g., `Infrastructure`, `Tag`). |
| **Operation** | An action on a securable type (`Read`, `Write`, `Delete`, `Execute`, `Approve`). |
| **Permission** | A single `(securable_type, operation, effect)` entry. Effect is `Allow` or `Deny`. |
| **Role assignment** | Binds a principal to a role, optionally scoped to a management group. |

## System Roles

Six roles are created automatically and cannot be deleted:

| Role | Permissions | Use case |
|---|---|---|
| **Administrator** | All 5 operations on all 13 securable types (65 permissions) | Server admins, security team leads |
| **PlatformEngineer** | Full CRUD on InstructionDefinition and InstructionSet; Read on Execution, Schedule, Approval, Tag, AuditLog, Response (14 permissions) | Authors and managers of YAML instruction definitions, sets, and schemas |
| **Operator** | Read/Write/Execute/Delete on InstructionDefinition, InstructionSet, Execution, Schedule, Tag; Read and Approve on Approval; Read on AuditLog and Response (24 permissions) | Day-to-day instruction execution, schedule management, tagging |
| **ApiTokenManager** | Read, Write, Delete on ApiToken (3 permissions) | Create, revoke, and manage API tokens for programmatic access |
| **ITServiceOwner** | All 5 operations on 10 securable types: Infrastructure, InstructionDefinition, InstructionSet, Execution, Schedule, Approval, Tag, AuditLog, Response, ManagementGroup (50 permissions). Excludes UserManagement, Security, ApiToken | Service desk leads, team managers with delegated control over their IT services |
| **Viewer** | Read on 12 securable types (all except Infrastructure) (12 permissions) | Helpdesk staff, auditors, read-only dashboards |

## Securable Types

| Securable type | Description |
|---|---|
| `Infrastructure` | Agent endpoints (query, command, patch) |
| `Tag` | Asset tags applied to devices |
| `InstructionDefinition` | YAML-defined instruction templates |
| `InstructionSet` | Grouped collections of instructions |
| `Execution` | Running or completed instruction instances |
| `Response` | Instruction response data |
| `Schedule` | Cron-style recurring instruction schedules |
| `Approval` | Approval workflow entries |
| `ManagementGroup` | Hierarchical device groups |
| `UserManagement` | User accounts and role assignments |
| `Security` | Security settings (TLS, enrollment) |
| `ApiToken` | API token lifecycle |
| `AuditLog` | Audit event records |

## Operations

| Operation | Typical meaning |
|---|---|
| `Read` | View or list resources |
| `Write` | Create or modify a resource |
| `Delete` | Remove a resource |
| `Execute` | Run an instruction against devices |
| `Approve` | Approve a pending workflow item |

## Permission Resolution

Yuzu evaluates permissions with **deny-overrides-allow**:

1. Collect all roles assigned to the principal (direct user assignments + group assignments).
2. Gather all permissions from those roles for the requested `(securable_type, operation)`.
3. If any permission has effect `Deny`, the request is **denied**.
4. If at least one permission has effect `Allow`, the request is **allowed**.
5. If no matching permission exists, the request is **denied** (implicit deny).

### Scoped Permissions

When a resource belongs to a management group (e.g., a device in "London Servers"), the permission check works in two passes:

1. **Global check** -- roles assigned without a group scope (via the `principal_roles` table) are evaluated first using standard deny-overrides-allow. If the user has a global allow, the request is permitted immediately.
2. **Scoped check** -- the system finds the agent's management group memberships, then collects all ancestor groups (child to root). For every group in this set, it looks up scoped role assignments (stored in the `ManagementGroupStore`) that match the user directly or via RBAC group membership. All matching permissions are evaluated with deny-overrides-allow: any deny returns false; otherwise, if at least one allow is found, the request is permitted.

This means a role scoped to a parent group automatically covers all child groups.

## API Reference

All REST API v1 responses are wrapped in a standard JSON envelope:

```json
{
  "data": ...,
  "meta": { "api_version": "v1" }
}
```

List endpoints add a `pagination` field:

```json
{
  "data": [...],
  "pagination": { "total": 6, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

### Check Permission

Verify whether the current user has a specific permission. Useful for UI feature gating or pre-flight checks in scripts.

**Note:** This endpoint uses `POST`, not `GET`, because it accepts a JSON request body.

```bash
curl -s -b cookies.txt -X POST http://localhost:8080/api/v1/rbac/check \
  -H "Content-Type: application/json" \
  -d '{
    "securable_type": "Infrastructure",
    "operation": "Execute"
  }'
```

```json
{
  "data": {
    "allowed": true
  },
  "meta": { "api_version": "v1" }
}
```

A denied response (the `allowed` field is `false`; no reason string is returned):

```json
{
  "data": {
    "allowed": false
  },
  "meta": { "api_version": "v1" }
}
```

### List Roles

```bash
curl -s -b cookies.txt http://localhost:8080/api/v1/rbac/roles
```

```json
{
  "data": [
    {
      "name": "Administrator",
      "description": "Full access to all operations",
      "is_system": true,
      "created_at": 1710849600
    },
    {
      "name": "PlatformEngineer",
      "description": "Author and manage YAML instruction definitions, sets, and schemas",
      "is_system": true,
      "created_at": 1710849600
    },
    {
      "name": "Operator",
      "description": "Execute and manage instructions, schedules, and tags",
      "is_system": true,
      "created_at": 1710849600
    },
    {
      "name": "ApiTokenManager",
      "description": "Create, revoke, and manage API tokens for programmatic access",
      "is_system": true,
      "created_at": 1710849600
    },
    {
      "name": "ITServiceOwner",
      "description": "Admin control over devices tagged with the same IT Service",
      "is_system": true,
      "created_at": 1710849600
    },
    {
      "name": "Viewer",
      "description": "Read-only access to operational data",
      "is_system": true,
      "created_at": 1710849600
    }
  ],
  "pagination": { "total": 6, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

### Get Role Permissions

```bash
curl -s -b cookies.txt \
  http://localhost:8080/api/v1/rbac/roles/ITServiceOwner/permissions
```

```json
{
  "data": [
    { "securable_type": "Approval", "operation": "Approve", "effect": "allow" },
    { "securable_type": "Approval", "operation": "Delete", "effect": "allow" },
    { "securable_type": "Approval", "operation": "Execute", "effect": "allow" },
    { "securable_type": "Approval", "operation": "Read", "effect": "allow" },
    { "securable_type": "Approval", "operation": "Write", "effect": "allow" },
    { "securable_type": "AuditLog", "operation": "Read", "effect": "allow" },
    { "securable_type": "Infrastructure", "operation": "Read", "effect": "allow" },
    { "securable_type": "Tag", "operation": "Read", "effect": "allow" }
  ],
  "meta": { "api_version": "v1" }
}
```

(Truncated for brevity. The full ITServiceOwner role contains 50 permissions across 10 securable types.)

### Custom Roles (Planned)

Custom roles can be created programmatically via `RbacStore::create_role()` and permissions assigned via `RbacStore::set_permission()`. REST API endpoints for role creation and role assignment are planned but **not yet implemented**. Currently, custom roles must be managed through the HTMX Settings UI or directly via the SQLite database.

**Planned endpoints (not yet available):**

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/rbac/roles` | Create a custom role |
| `POST` | `/api/v1/rbac/roles/{name}/assignments` | Assign a role to a principal |

### Scoped Role Assignments

Scoped role assignments bind a principal to a role within a specific management group. These are stored in the `ManagementGroupStore` (not in the RBAC principal_roles table) and are managed through the management group API:

```bash
# Assign a role scoped to a management group
curl -s -b cookies.txt -X POST \
  http://localhost:8080/api/v1/management-groups/mg_london_office/roles \
  -H "Content-Type: application/json" \
  -d '{
    "principal_type": "user",
    "principal_id": "jane.doe",
    "role_name": "Operator"
  }'
```

## Examples

### Deny a Specific Operation

Prevent a role from deleting infrastructure resources, even if other roles would allow it. This requires creating a custom role with a Deny permission (via the Settings UI or direct database access, since the role creation API is not yet available):

```sql
-- Example: create a deny role directly in the RBAC database
INSERT INTO roles (name, description, is_system, created_at) VALUES ('NoDeletion', 'Explicit deny on infrastructure deletion', 0, strftime('%s','now'));
INSERT INTO role_permissions VALUES ('NoDeletion', 'Infrastructure', 'Delete', 'deny');
```

Assign this role alongside any other roles. Because deny overrides allow, the user will be unable to delete infrastructure resources regardless of their other role assignments.

## API Endpoint Summary

| Method | Endpoint | Description | Status |
|---|---|---|---|
| `POST` | `/api/v1/rbac/check` | Check if current user has a permission | Implemented |
| `GET` | `/api/v1/rbac/roles` | List all roles | Implemented |
| `GET` | `/api/v1/rbac/roles/{name}/permissions` | Get permissions for a role | Implemented |
| `POST` | `/api/v1/rbac/roles` | Create a custom role | Planned |
| `PUT` | `/api/v1/rbac/roles/{name}` | Update a role | Planned |
| `DELETE` | `/api/v1/rbac/roles/{name}` | Delete a custom role | Planned |
| `POST` | `/api/v1/rbac/roles/{name}/assignments` | Assign a role to a principal | Planned |
| `DELETE` | `/api/v1/rbac/roles/{name}/assignments` | Unassign a role | Planned |

## Planned Features

| Feature | Phase | Status |
|---|---|---|
| REST API for role creation and assignment | 3 | Planned |
| OIDC group-to-role auto-mapping refinements | 3 | Stub |
| Role management via Settings UI matrix | 3 | Planned |
