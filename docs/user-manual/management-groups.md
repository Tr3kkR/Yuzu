# Management Groups

Management groups organize devices into a hierarchy for scoped access control and targeted operations. They support both static membership (manually assigned) and dynamic membership (auto-populated by a scope expression).

## Concepts

| Concept | Description |
|---|---|
| **Management group** | A named container for devices, with optional parent/child relationships. |
| **Static membership** | Agents are explicitly added to or removed from the group by an operator. |
| **Dynamic membership** | A scope expression (e.g., `os = "Windows" AND tag:department = "Finance"`) determines membership. Matching agents are included automatically. |
| **Hierarchy** | Groups can be nested up to 6 levels deep (root + 5 child levels). Role assignments on a parent group cascade to all children. |
| **Service groups** | When a `service` tag is set on an agent, Yuzu auto-creates a `Service: {name}` management group containing all agents with that tag. |

## Hierarchy Example

```
All Devices
  |-- London Office
  |     |-- London Desktops
  |     |-- London Servers
  |-- New York Office
  |     |-- New York Desktops
  |-- Service: SAP
  |-- Service: Exchange
```

A role assignment on "London Office" applies to both "London Desktops" and "London Servers". This avoids duplicating role assignments at every level.

## REST API

All endpoints require authentication (session cookie or API token). Management group operations require appropriate RBAC permissions on the `ManagementGroup` securable type.

### List All Groups

```bash
curl -s -b cookies.txt http://localhost:8080/api/v1/management-groups
```

All list endpoints return a paginated envelope:

```json
{
  "data": [
    {
      "id": "mg_all_devices",
      "name": "All Devices",
      "description": "Root group containing all enrolled agents",
      "parent_id": "",
      "membership_type": "dynamic",
      "scope_expression": "*",
      "created_by": "system",
      "created_at": 1742360400,
      "updated_at": 1742360400
    },
    {
      "id": "mg_london",
      "name": "London Office",
      "description": "Agents in the London office",
      "parent_id": "mg_all_devices",
      "membership_type": "static",
      "scope_expression": "",
      "created_by": "admin",
      "created_at": 1742360400,
      "updated_at": 1742360400
    }
  ],
  "pagination": { "total": 2, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

### Create a Group

#### Static Membership

```bash
curl -s -b cookies.txt -X POST http://localhost:8080/api/v1/management-groups \
  -H "Content-Type: application/json" \
  -d '{
    "name": "London Servers",
    "description": "Production servers in the London data center",
    "parent_id": "mg_london",
    "membership_type": "static"
  }'
```

The `created_by` field is set automatically from the authenticated session.

Returns `201 Created`:

```json
{
  "data": { "id": "a1b2c3d4e5f6" },
  "meta": { "api_version": "v1" }
}
```

#### Dynamic Membership

```bash
curl -s -b cookies.txt -X POST http://localhost:8080/api/v1/management-groups \
  -H "Content-Type: application/json" \
  -d '{
    "name": "All Windows Endpoints",
    "description": "Auto-populated with all Windows agents",
    "parent_id": "mg_all_devices",
    "membership_type": "dynamic",
    "scope_expression": "os = \"Windows\""
  }'
```

The `scope_expression` uses the same syntax as the scope engine. Common operators:

| Expression | Matches |
|---|---|
| `os = "Windows"` | All Windows agents |
| `os = "Linux" AND tag:environment = "production"` | Linux agents tagged as production |
| `tag:department = "Finance" OR tag:department = "Legal"` | Agents in Finance or Legal |
| `NOT tag:decommissioned EXISTS` | Agents without a decommissioned tag |

### Get Group Details

Returns the group metadata plus its current member list.

```bash
curl -s -b cookies.txt \
  http://localhost:8080/api/v1/management-groups/a1b2c3d4e5f6
```

```json
{
  "data": {
    "id": "a1b2c3d4e5f6",
    "name": "London Servers",
    "description": "Production servers in the London data center",
    "parent_id": "mg_london",
    "membership_type": "static",
    "scope_expression": "",
    "created_by": "admin",
    "created_at": 1742360400,
    "updated_at": 1742360400,
    "members": [
      {
        "agent_id": "agent_lon_srv_01",
        "source": "static",
        "added_at": 1742360700
      },
      {
        "agent_id": "agent_lon_srv_02",
        "source": "static",
        "added_at": 1742360700
      }
    ]
  },
  "meta": { "api_version": "v1" }
}
```

Note: The `members` array contains `agent_id`, `source` (either `"static"` or `"dynamic"`), and `added_at` (Unix epoch seconds). It does not include hostname or OS -- use the agent details endpoint for that information.

### Delete a Group

```bash
curl -s -b cookies.txt -X DELETE \
  http://localhost:8080/api/v1/management-groups/a1b2c3d4e5f6
```

Returns `200 OK`:

```json
{
  "data": { "deleted": true },
  "meta": { "api_version": "v1" }
}
```

**Warning:** Deleting a group cascade-deletes all child groups, their membership records, and their role assignments (enforced by foreign key constraints). Member agents themselves are not deleted -- only their group associations are removed. Reassign child groups to a new parent before deleting if you want to preserve them.

### Add a Member

```bash
curl -s -b cookies.txt -X POST \
  http://localhost:8080/api/v1/management-groups/a1b2c3d4e5f6/members \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent_lon_srv_03"
  }'
```

Returns `201 Created`:

```json
{
  "data": { "added": true },
  "meta": { "api_version": "v1" }
}
```

This endpoint is intended for static membership groups. For dynamic groups, membership is controlled by the scope expression and refreshed via `refresh_dynamic_membership`.

### Remove a Member

```bash
curl -s -b cookies.txt -X DELETE \
  http://localhost:8080/api/v1/management-groups/a1b2c3d4e5f6/members/agent_lon_srv_03
```

Returns `200 OK`:

```json
{
  "data": { "removed": true },
  "meta": { "api_version": "v1" }
}
```

Only removes static membership records. Dynamic membership entries (added by scope expression evaluation) are not removed by this endpoint.

## Role Delegation

Management groups serve as the scoping boundary for RBAC. You can assign roles to principals within the context of a specific group, so the permissions only apply to devices in that group (and its children).

### List Role Assignments for a Group

```bash
curl -s -b cookies.txt \
  http://localhost:8080/api/v1/management-groups/mg_london/roles
```

```json
{
  "data": [
    {
      "group_id": "mg_london",
      "principal_type": "user",
      "principal_id": "jane.doe",
      "role_name": "Operator"
    },
    {
      "group_id": "mg_london",
      "principal_type": "group",
      "principal_id": "london-desktop-team",
      "role_name": "Viewer"
    }
  ],
  "meta": { "api_version": "v1" }
}
```

### Add a Role Assignment

Only `Operator` and `Viewer` roles can be delegated via this endpoint. Assigning other roles (e.g., `ITServiceOwner`) returns `403 Forbidden`. The caller must be a global Administrator or hold `ITServiceOwner` on the target group.

```bash
curl -s -b cookies.txt -X POST \
  http://localhost:8080/api/v1/management-groups/mg_london/roles \
  -H "Content-Type: application/json" \
  -d '{
    "principal_type": "user",
    "principal_id": "jane.doe",
    "role_name": "Operator"
  }'
```

Returns `201 Created`:

```json
{
  "data": { "assigned": true },
  "meta": { "api_version": "v1" }
}
```

Jane now has Operator permissions for all devices in "London Office" and its child groups ("London Desktops", "London Servers").

### Remove a Role Assignment

```bash
curl -s -b cookies.txt -X DELETE \
  http://localhost:8080/api/v1/management-groups/mg_london/roles \
  -H "Content-Type: application/json" \
  -d '{
    "principal_type": "user",
    "principal_id": "jane.doe",
    "role_name": "Operator"
  }'
```

Returns `200 OK`:

```json
{
  "data": { "unassigned": true },
  "meta": { "api_version": "v1" }
}
```

The caller must be a global Administrator or hold `ITServiceOwner` on the target group.

## Service Groups

When an agent's `service` tag is set (e.g., via the asset tagging API), Yuzu auto-creates a management group named `Service: {value}`. All agents sharing that service tag are automatically included.

```bash
# Tag an agent with a service
curl -s -b cookies.txt -X POST http://localhost:8080/api/v1/tags \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent_lon_srv_01",
    "key": "service",
    "value": "SAP"
  }'
```

This creates (or updates) the group `Service: SAP` with `agent_lon_srv_01` as a member. The group uses dynamic membership internally with scope expression `tag:service == "SAP"` -- any agent tagged with `service = "SAP"` is included.

## Practical Example: Regional Delegation

Set up a structure where each regional team manages their own devices:

```bash
# 1. Create regional groups (created_by is set from the authenticated session)
curl -s -b cookies.txt -X POST http://localhost:8080/api/v1/management-groups \
  -H "Content-Type: application/json" \
  -d '{"name": "EMEA", "description": "Europe, Middle East, Africa", "membership_type": "static"}'

curl -s -b cookies.txt -X POST http://localhost:8080/api/v1/management-groups \
  -H "Content-Type: application/json" \
  -d '{"name": "APAC", "description": "Asia-Pacific", "membership_type": "static"}'

# 2. Add agents to EMEA (use the id returned by the create call)
curl -s -b cookies.txt -X POST \
  http://localhost:8080/api/v1/management-groups/<emea_group_id>/members \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "agent_london_01"}'

# 3. Delegate Operator to the EMEA team lead
curl -s -b cookies.txt -X POST \
  http://localhost:8080/api/v1/management-groups/<emea_group_id>/roles \
  -H "Content-Type: application/json" \
  -d '{"principal_type": "user", "principal_id": "emea.lead", "role_name": "Operator"}'

# 4. Delegate Viewer to the EMEA helpdesk group
curl -s -b cookies.txt -X POST \
  http://localhost:8080/api/v1/management-groups/<emea_group_id>/roles \
  -H "Content-Type: application/json" \
  -d '{"principal_type": "group", "principal_id": "emea-helpdesk", "role_name": "Viewer"}'
```

Now `emea.lead` can manage all devices in EMEA, and members of the `emea-helpdesk` group can view those devices -- but neither has access to APAC devices.

## API Endpoint Summary

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/management-groups` | List all management groups |
| `POST` | `/api/v1/management-groups` | Create a management group |
| `GET` | `/api/v1/management-groups/{id}` | Get group details and members |
| `DELETE` | `/api/v1/management-groups/{id}` | Delete a management group |
| `POST` | `/api/v1/management-groups/{id}/members` | Add an agent to a static group |
| `DELETE` | `/api/v1/management-groups/{id}/members/{agent_id}` | Remove an agent from a group |
| `GET` | `/api/v1/management-groups/{id}/roles` | List role assignments for a group |
| `POST` | `/api/v1/management-groups/{id}/roles` | Add a role assignment to a group |
| `DELETE` | `/api/v1/management-groups/{id}/roles` | Remove a role assignment from a group |

## Constraints

| Constraint | Value |
|---|---|
| Maximum hierarchy depth | 6 levels (root + 5 child levels). The parent's ancestor count must be < 5. |
| Membership types | `static`, `dynamic` |
| Delegatable roles | Only `Operator` and `Viewer` can be delegated via the roles API |
| Cascade delete | Deleting a group cascade-deletes all children, memberships, and role assignments |
| Dynamic scope syntax | Same as the scope engine (see `docs/yaml-dsl-spec.md` section on scope expressions) |

## Planned Features

| Feature | Phase | Status |
|---|---|---|
| `PUT` endpoint for updating group metadata (name, description, parent, scope) | 3 | Store method exists, no REST route |
| Policy assignment to management groups | 5 | Stub |
| Dynamic membership auto-refresh on schedule | 3 | Stub |
