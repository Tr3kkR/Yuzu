# Role-Based Access Control (RBAC)

Yuzu implements granular role-based access control with deny-overrides-allow semantics, scoped permissions via management groups, and support for both built-in and custom roles.

## Enabling RBAC

RBAC is controlled by a global toggle. When disabled, all authenticated users have full access (with a legacy fallback: write/delete/execute/approve operations still require the `admin` session role) — **except** a small, fixed set of reads that require admin regardless of the toggle; see "The authorization topology floor" below. When enabled, every API call and UI action is checked against the caller's assigned roles.

Toggle RBAC via the Settings page or the server configuration file:

```cfg
[rbac]
enabled = true
```

> **Before enabling RBAC in production:** ensure every operator who needs device
> visibility has at least one management-group role assignment. With RBAC
> **disabled**, all authenticated users see the full enrolled fleet. Turning RBAC
> **on** immediately applies role-scoped visibility — a user without a
> management-group role assignment will see **no agents** (including on the TAR
> fleet scan), and the role-grant endpoints themselves require an existing group
> role, which can be a chicken-and-egg lockout. The broadest grant is an
> `ITServiceOwner` role on the root "All Devices" group; see
> [`management-groups.md`](management-groups.md) for the delegation API.

> **Storage (ADR-0041).** RBAC configuration — roles, grants, principal→role
> assignments, groups + membership, and the global `rbac_enabled` flag — lives in
> the server's **PostgreSQL** substrate, schema `rbac_store` (it moved off the
> legacy SQLite `rbac.db` file). It is a single shared database across all server
> replicas, so administer it with one `psql`, not per-node.
>
> **RBAC store integrity (fail-closed / deny-on-degrade).** The `rbac_store`
> substrate fails **closed at boot** — an unreachable PostgreSQL (or an
> unreadable durable `rbac_enabled` flag) makes the server refuse to start,
> rather than serving RBAC-off on a fleet that enabled it. At runtime, an
> authorization read that cannot resolve (pool-acquire timeout, query error)
> **denies** rather than allowing (deny-on-degrade, ADR-0041 — this closes the
> prior "corrupt `rbac.db` fails open" behavior); watch the
> `yuzu_server_rbac_read_degrade_total` metric. In that degraded state, device
> visibility falls back to the role-scoped path for every caller, so agents stop
> appearing in the dashboard list, `/api/agents`, and TAR fleet scans rather than
> the whole fleet being exposed. **The same fail-closed posture covers every
> response/execution reader (#1634, #1712):** `query_responses`, `aggregate_responses`,
> `GET /api/v1/executions/{id}/visualization`, the legacy `GET /api/responses/{id}`
> / `/aggregate` / `/export` surfaces, the dashboard `/fragments/results/…` table,
> and the workflow executions-drawer reader all return **zero rows** (the legacy
> aggregate returns `503`) on a corrupt store rather than reopening the
> cross-operator fleet-wide read. The drawer's **live channel**
> (`GET /sse/executions/{id}`) applies the same predicate per event: on a corrupt
> store it streams **no per-agent transitions at all**, only the execution-wide
> progress/completion frames, which name no agent. So a degraded store looks like "no agents in
> scope" / "no responses" everywhere, never a visibility leak. Check the server
> startup log for `RbacStore` errors, the `/health` store status, and
> `yuzu_server_rbac_read_degrade_total`, then restore PostgreSQL (`rbac_store`)
> availability immediately. (If Grafana panels or scripted aggregate consumers
> show zero rows after an upgrade or restart, check for `RbacStore` open/migrate
> errors first.)
>
> **Note (#1634):** the per-agent filter on these response readers is, under
> *normal* RBAC operation, currently **inert** — a holder of global `Response:Read`
> sees all agents' responses; per-management-group scoping of these reads is not yet
> effective (the gate change is tracked in #1634). Today the filter's only active
> effect is the corrupt-store fail-closed described above.
>
> **MCP `get_agent_details` (#1700):** the per-agent existence/hostname/os probe
> is scoped independently of the response-reader family above — an `agent_id`
> outside the caller's management group renders identically to "Agent not
> found" (never a distinct error), matching `summarize_working_set kind=agent`.
> This closes the targeted probe against a *specific* `agent_id`, and with it
> the tag/inventory disclosure. It is **not** a fleet-wide anonymity guarantee:
> `list_agents` is gated on the same `Infrastructure:Read` securable and still
> enumerates every agent's id, hostname, os and arch. Treat `Infrastructure:Read`
> as fleet-visible until that is scoped too.

## The authorization topology floor (#2376)

Three reads are treated as **authorization topology** rather than ordinary
operational data, and require the `admin` session role no matter how the
`[rbac] enabled` toggle is set:

| Securable:Operation | Surface |
|---|---|
| `AccessReview:Read` | The fleet-wide access-review grant export (SOC 2 CC6.2 evidence), `GET /api/v1/access-reviews*` |
| `UserManagement:Read` | `GET /api/v1/rbac/roles` and the rest of the RBAC role graph |
| `EnginePrincipal:Read` | The engine-principal inventory and grant graph, `GET /api/v1/engine-principals*` and the `list_engine_principals`/`get_engine_principal`/`list_engine_roles` MCP tools |

**Why this exists.** With RBAC **disabled**, the legacy fallback described
above allows any authenticated non-engine session to perform every `Read` —
that includes these three. On a default install (RBAC ships disabled) that
handed a plain `user` session read access to the authorization topology
itself: who holds what role, and the complete access-review grant
population that is supposed to *be* SOC 2 CC6.2 evidence of controlled
access. The floor closes that gap by denying these three reads to a
non-admin whenever the legacy fallback is the branch in effect — never by
changing behavior under a live RBAC grant.

**This does not affect RBAC-enabled deployments beyond the one closed
gap.** The floor only ever engages inside the legacy (RBAC-off) fallback; a
live RBAC branch always answers first when RBAC is enabled and enforced. In
particular, a non-admin holding the seeded `Reviewer` role (`AccessReview:Read`
+ `AccessReview:Attest`) continues to reach the access-review export exactly
as before — the floor never overrides that grant.

**If you are relying on a non-admin reaching one of these three reads on an
RBAC-disabled install,** that access is now denied. The supported remedy is
to enable RBAC and grant the appropriate role rather than to expect a
non-admin session to reach authorization topology while RBAC is off:

- For the access-review export: enable RBAC and assign the built-in
  `Reviewer` role (`AccessReview:Read` + `AccessReview:Attest`).
- For `/rbac/roles`: enable RBAC and grant `UserManagement:Read` (the
  built-in `Viewer` role holds it already).
- For the engine-principal inventory/roles reads: enable RBAC and grant
  `EnginePrincipal:Read` (the built-in `Viewer` role holds it already; a
  **custom** role that was granted `Security:Read` specifically to reach
  these routes must be re-granted `EnginePrincipal:Read` — see "Upgrade
  Notes" in [`server-admin.md`](server-admin.md)).

The floor is deliberately **not configurable** — there is no setting that
widens it back open. It is keyed on `(securable, operation)`, not on route
path, because an MCP tool and a REST route can share the same wire path
(every MCP tool call goes through the single `/mcp/v1/` JSON-RPC endpoint)
while gating different securables; a route-keyed floor could not
distinguish them. A denial from the floor is audited with a distinct reason
(`"topology floor: ..."` on the `auth.permission_required` /
`auth.scoped_permission_required` audit actions, `result=denied`) and
counted in `yuzu_auth_topology_floor_denied_total{permission}`, separate

> **Caveat — this counter is currently noisy (#2829).** Routes that PROBE a second
> permission to decide whether to include part of a response — `GET /api/v1/discover/permissions`,
> its MCP twin, and `GET /api/v1/management-groups/{id}/roles` — run that probe through the same
> auditing permission gate. An ordinary non-admin call therefore increments this counter and writes
> an `auth.permission_required` `denied` row for a permission the caller never asked for. Until
> #2829 lands, do **not** alert on this counter alone as evidence of someone probing the
> authorization topology — correlate with the route in the audit row first.
from an ordinary legacy-fallback denial, so a spike in floored denials is
visible without grepping audit-log text.

See `docs/auth-architecture.md` → "The authorization topology floor
(#2376)" for the full design rationale, and
`docs/security-reviews/authz-topology-floor-2026-08-05.md` for the recorded
decision (including what was deliberately excluded from the floor and why).

## Concepts

| Concept | Description |
|---|---|
| **Principal** | A user or group identity. Matches the authenticated username or an OIDC group claim. |
| **Role** | A named collection of permissions. Can be system-defined or custom. |
| **Securable type** | A category of resource that permissions apply to (e.g., `Infrastructure`, `Tag`). |
| **Operation** | An action on a securable type (`Read`, `Write`, `Delete`, `Execute`, `Approve`, `Push`, `Attest`, `Rotate`). |
| **Permission** | A single `(securable_type, operation, effect)` entry. Effect is `Allow` or `Deny`. |
| **Role assignment** | Binds a principal to a role, optionally scoped to a management group. |

## System Roles

Six roles are created automatically and cannot be deleted:

| Role | Permissions | Use case |
|---|---|---|
| **Administrator** | All 5 CRUD operations on all 23 securable types, plus Push on GuaranteedState, Attest on AccessReview, and Rotate on ApiToken (P2 #11, SOC 2 CC6.3 — self-service human token rotation) (118 permissions) | Server admins, security team leads |
| **PlatformEngineer** | Full CRUD on InstructionDefinition and InstructionSet; Read on Execution, Schedule, Approval, Tag, AuditLog, Response, Inventory; Read/Write/Delete/Push on GuaranteedState | Authors and managers of YAML instruction definitions, sets, and Guardian rules |
| **Operator** | Read/Write/Execute/Delete on InstructionDefinition, InstructionSet, Execution, Schedule, Tag; Read and Approve on Approval; Read on AuditLog, Response, and Inventory; Read and Push on GuaranteedState | Day-to-day instruction execution, schedule management, tagging, and Guardian rule distribution |
| **ApiTokenManager** | Read, Write, Delete, Rotate on ApiToken (4 permissions) | Create, revoke, rotate, and manage API tokens for programmatic access |
| **ITServiceOwner** | All 5 CRUD operations on 18 securable types, plus Push on GuaranteedState (91 permissions). Excludes UserManagement, Security, ApiToken, AccessReview, EnginePrincipal | Service desk leads, team managers with delegated control over their IT services |
| **Viewer** | Read on 21 securable types (all except Infrastructure and AccessReview) (21 permissions) | Helpdesk staff, auditors, read-only dashboards |

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
| `Policy` | Guaranteed State policy fragments and composed policies |
| `DeviceToken` | Agent device-token issuance and revocation |
| `SoftwareDeployment` | Software deployment campaigns |
| `License` | Enterprise license records |
| `FileRetrieval` | File upload and download operations |
| `GuaranteedState` | Guardian (Guaranteed State) policy rules, events, and status |
| `Inventory` | Installed-software inventory synced from endpoints (ADR-0016) |
| `EnginePrincipal` | Engine-principal inventory and fleet-wide grant-graph reads (list/get engine principals, list their assigned roles) — cut away from `Security` (#2376) so this narrower read is not gated by the same broad permission that also covers CA/quarantine/KEK operational reads. See "The authorization topology floor" below. |

## Operations

| Operation | Typical meaning |
|---|---|
| `Read` | View or list resources |
| `Write` | Create or modify a resource |
| `Delete` | Remove a resource |
| `Execute` | Run an instruction against devices |
| `Approve` | Approve a pending workflow item |
| `Push` | Distribute an existing rule set to scoped agents. Consumed **only** by `GuaranteedState` REST handlers and seeded **only** on `GuaranteedState` — separates deploy authority from authoring authority. Present in the operations catalogue so custom roles can adopt it, but the default seeds grant it on `GuaranteedState` alone. |
| `Attest` | Record a reviewer's attestation decision on a periodic access review (SOC 2 CC6.2). Consumed **only** by `AccessReview` REST handlers and seeded **only** on `AccessReview` — gated via the dedicated `AccessReview` securable, never `AuditLog` (see "The authorization topology floor" below). |
| `Rotate` (P2 #11, SOC 2 CC6.3) | Self-service overlap-pair rotation of a human-owned API token. Consumed **only** by `ApiToken` REST/MCP handlers and seeded **only** on `ApiToken`, to the same two roles that already hold `ApiToken:Write` (`Administrator`, `ApiTokenManager`) — deliberately a separate operation from `Write` so a narrower MCP-tier allowance can be granted for rotation without also widening token-mint access. |

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

(Truncated for brevity. The full ITServiceOwner role contains 91 permissions across 18 securable types.)

### Custom Roles (Planned)

Custom roles can be created programmatically via `RbacStore::create_role()` and permissions assigned via `RbacStore::set_permission()`. REST API endpoints for role creation and role assignment are planned but **not yet implemented**. Currently, custom roles must be managed through the HTMX Settings UI or directly against the shared PostgreSQL `rbac_store` schema (see the "Storage (ADR-0041)" callout above — one `psql` session, not a per-node file).

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
-- Example: create a deny role directly against the shared rbac_store schema
-- (psql against the server's PostgreSQL instance — see the "Storage (ADR-0041)"
-- callout above; this is a single shared store, not a per-node SQLite file).
INSERT INTO rbac_store.roles (name, description, is_system, created_at)
  VALUES ('NoDeletion', 'Explicit deny on infrastructure deletion', false, extract(epoch from now())::bigint);
INSERT INTO rbac_store.role_permissions (role_name, securable_type, operation, effect)
  VALUES ('NoDeletion', 'Infrastructure', 'Delete', 'deny');
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
