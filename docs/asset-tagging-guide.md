# Structured Asset Tagging & IT Service Owner Guide

A guide for administrators and IT service owners to classify devices, enforce tag compliance, and delegate scoped access using Yuzu's structured asset tagging system.

**Prerequisites:** A running Yuzu server with at least one enrolled agent. You should be able to log in to the dashboard at `http://localhost:8080` as an admin. All `curl` examples below assume you have an active session cookie — replace `$COOKIE` with your session token.

---

## Overview

Every managed device in Yuzu can carry **tags** — key/value labels that describe what the device is, where it sits, and what it does. Tags are the foundation for targeting devices with scope expressions, enforcing compliance, and delegating access.

Yuzu defines **four structured tag categories** that every device should have:

| Category | Display Name | Allowed Values | Purpose |
|---|---|---|---|
| `role` | Role | Free-form | What the device does (e.g. `web-server`, `build-agent`, `kiosk`) |
| `environment` | Environment | `Dev`, `UAT`, `Production` | Which deployment stage the device belongs to |
| `location` | Location | Free-form | Physical or logical location (e.g. `us-east-1`, `Building 4 Floor 2`) |
| `service` | Service | Free-form | Which IT service owns the device (e.g. `payments`, `hr-portal`) |

Structured categories are enforced at the API layer:
- The **environment** category is restricted to the three allowed values. Setting it to anything else returns an error.
- The other three categories accept any string value (max 448 bytes).
- You can still set arbitrary non-category tags (e.g. `owner:jane`, `ticket:INC-1234`) — those are not validated by the category system.

---

## Setting Tags

### Via the REST API

**Set a tag on a device:**

```bash
curl -s -X PUT http://localhost:8080/api/v1/tags \
  -b "$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent-001",
    "key": "environment",
    "value": "Production"
  }'
```

Response:
```json
{
  "data": { "set": true },
  "meta": { "api_version": "v1" }
}
```

If you try to set `environment` to an invalid value:

```bash
curl -s -X PUT http://localhost:8080/api/v1/tags \
  -b "$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent-001",
    "key": "environment",
    "value": "staging"
  }'
```

Response (400):
```json
{
  "error": "invalid value 'staging' for category 'environment'; allowed: Dev, UAT, Production",
  "meta": { "api_version": "v1" }
}
```

**Read all tags for a device:**

```bash
curl -s "http://localhost:8080/api/v1/tags?agent_id=agent-001" -b "$COOKIE"
```

Response:
```json
{
  "data": {
    "role": "web-server",
    "environment": "Production",
    "location": "us-east-1",
    "service": "payments"
  },
  "meta": { "api_version": "v1" }
}
```

**Delete a tag:**

```bash
curl -s -X DELETE "http://localhost:8080/api/v1/tags/agent-001/location" -b "$COOKIE"
```

### Via the Dashboard

Tags can also be managed through the HTMX dashboard. Navigate to a device's detail page and use the tag editor to add, update, or remove tags. The `environment` dropdown is pre-populated with the three allowed values.

### Via YAML Instruction Definitions

The asset tag operations are defined as formal instruction definitions that can be loaded into the Instruction Engine. The YAML files live in `content/definitions/`:

- `asset_tags.yaml` — four `InstructionDefinition` documents
- `asset_tags_set.yaml` — one `InstructionSet` grouping them

These can be imported via the instruction import API:

```bash
# Import the YAML definitions (server parses and stores them)
curl -s -X POST http://localhost:8080/api/instructions/import \
  -b "$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "device.asset_tags.sync",
    "type": "action",
    "plugin": "asset_tags",
    "action": "sync",
    "description": "Push structured tags to agent",
    "version": "1.0.0"
  }'
```

The four available instruction definitions are:

| Definition ID | Type | Description |
|---|---|---|
| `device.asset_tags.sync` | action | Push current tag values to an agent |
| `device.asset_tags.status` | question | Query the agent's cached tags and sync metadata |
| `device.asset_tags.get` | question | Retrieve a single tag by category key |
| `device.asset_tags.changes` | question | View the tag change history on a device |

---

## Tag Categories Reference

**List all defined categories and their validation rules:**

```bash
curl -s http://localhost:8080/api/v1/tag-categories -b "$COOKIE"
```

Response:
```json
{
  "data": [
    {
      "key": "role",
      "display_name": "Role",
      "allowed_values": []
    },
    {
      "key": "environment",
      "display_name": "Environment",
      "allowed_values": ["Dev", "UAT", "Production"]
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

An empty `allowed_values` array means the category is free-form — any string is accepted. A non-empty array means only those exact values are valid.

---

## Tag Compliance

A device is **compliant** when it has a value set for all four structured categories. The compliance endpoint reports which devices are missing which tags.

### Check compliance via the API

```bash
curl -s http://localhost:8080/api/v1/tag-compliance -b "$COOKIE"
```

Response (devices with gaps only):
```json
{
  "data": [
    {
      "agent_id": "agent-002",
      "missing_tags": ["location", "service"]
    },
    {
      "agent_id": "agent-003",
      "missing_tags": ["role", "environment", "location", "service"]
    }
  ],
  "meta": { "api_version": "v1" }
}
```

A fully compliant fleet returns an empty array: `{"data": []}`.

### Compliance in the Dashboard

The **Settings** page includes a **Tag Compliance** section that shows a summary table:

| Category | Tagged | Missing | % Compliant |
|---|---|---|---|
| Role | 47 | 3 | 94% |
| Environment | 50 | 0 | 100% |
| Location | 45 | 5 | 90% |
| Service | 48 | 2 | 96% |

This table is rendered as an HTMX fragment and updates automatically when tags change.

---

## Agent-Side Tag Awareness

When you set a structured category tag on a device, Yuzu automatically pushes the updated tag state to the agent via the `asset_tags` plugin. Agents do not need to poll — the server pushes changes in real time over the existing gRPC command stream.

### How it works

1. An administrator sets a tag via the REST API or dashboard.
2. If the tag key is one of the four structured categories (`role`, `environment`, `location`, `service`), the server builds a `CommandRequest` targeting the `asset_tags` plugin's `sync` action.
3. The command is sent to the agent over the existing gRPC bidirectional stream.
4. The agent's `asset_tags` plugin stores the tags locally in `<data_dir>/asset_tags.json`, detects changes from the previous state, and logs them.

### Staleness detection

The agent runs a background check thread (default: every 300 seconds, configurable via `asset_tags.check_interval` in the agent config). If no sync has arrived within that window, the local tag cache is marked as **stale**. This flag is visible via the `status` action.

### Agent configuration

The check interval can be tuned in the agent configuration file:

```ini
[asset_tags]
check_interval = 600    # seconds (default: 300, minimum: 30)
```

### Querying agent tag state

You can query the agent's locally cached tags without going through the server:

**Status** — all tags, sync time, and staleness:
```
plugin: asset_tags, action: status
```

Example output:
```
tag|role|web-server
tag|environment|Production
tag|location|us-east-1
tag|service|payments
last_sync|1710849600
stale|false
check_interval|300
change_count|4
```

**Get a single tag:**
```
plugin: asset_tags, action: get, params: {key: "environment"}
```

**View change history:**
```
plugin: asset_tags, action: changes
```

Example output:
```
change|environment||Production|1710849600
change|service|billing|payments|1710852200
total_changes|2
```

Each change record shows: category key, old value, new value, and epoch timestamp.

---

## IT Service Owner Role

The **ITServiceOwner** role is designed for team leads or service managers who need administrative control over devices belonging to their IT service, without requiring global admin privileges.

### What ITServiceOwner can do

ITServiceOwner has permissions across 10 securable types with 5 operations each (50 permissions total):

| Securable Types (allowed) | Operations |
|---|---|
| Device, Tag, InstructionDefinition, InstructionSet, InstructionExecution, Response, Scope, Schedule, Approval, ManagementGroup | Create, Read, Write, Delete, Execute |

| Securable Types (excluded) | Reason |
|---|---|
| UserManagement | Cannot create/modify global users |
| Security | Cannot change TLS settings or enrollment tokens |
| ApiToken | Cannot issue API tokens |

### How scoping works

ITServiceOwner permissions are **scoped to management groups**. When an ITServiceOwner is assigned to a management group, their permissions only apply to devices that are members of that group (or its descendant groups).

The authorization check follows this flow:

```
1. Does the user have a GLOBAL role that permits the operation?
   → Yes: allowed (global roles bypass scoping)
   → No: continue

2. Which management groups is the target device a member of?
   → For each group (and its ancestor groups):
      → Does the user have a group-scoped role that permits the operation?
         → If any group-scoped role grants "deny": denied (deny overrides allow)
         → If any group-scoped role grants "allow": allowed

3. No matching group-scoped role found → denied
```

### Automatic service management groups

When you set a `service` tag on a device, Yuzu automatically creates a **management group** named `Service: <value>` if one doesn't already exist. For example:

- Setting `service=payments` creates group "Service: payments"
- Setting `service=hr-portal` creates group "Service: hr-portal"

These groups use `dynamic` membership — the scope engine can refresh which devices belong to each group based on tag expressions.

This means an ITServiceOwner assigned to "Service: payments" automatically has scoped access to every device tagged with `service=payments`.

### Setting up an IT Service Owner

**Step 1: Tag devices with a service.**

```bash
# Tag several devices as belonging to the "payments" service
for agent in agent-001 agent-002 agent-003; do
  curl -s -X PUT http://localhost:8080/api/v1/tags \
    -b "$COOKIE" \
    -H "Content-Type: application/json" \
    -d "{\"agent_id\": \"$agent\", \"key\": \"service\", \"value\": \"payments\"}"
done
```

This automatically creates the "Service: payments" management group.

**Step 2: Find the management group ID.**

```bash
curl -s http://localhost:8080/api/v1/management-groups -b "$COOKIE"
```

Look for the group named "Service: payments" in the response and note its `id` (a hex string like `a1b2c3d4e5f6`).

**Step 3: Assign the ITServiceOwner role on that group.**

```bash
curl -s -X POST "http://localhost:8080/api/v1/management-groups/$GROUP_ID/roles" \
  -b "$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{
    "principal_type": "user",
    "principal_id": "jane",
    "role_name": "ITServiceOwner"
  }'
```

Now user `jane` has ITServiceOwner permissions over all devices in the "Service: payments" group.

---

## Delegation

IT Service Owners can **delegate** access within their scope. This allows them to grant Operator or Viewer access to team members without involving a global administrator.

### Rules

- Only the **Operator** and **Viewer** roles can be delegated. ITServiceOwner and Administrator cannot be delegated through this API.
- The caller must either be a **global Administrator** or hold the **ITServiceOwner** role on the target management group.
- Delegated roles are scoped to the management group — they do not grant global access.

### Delegate access

```bash
# Jane (ITServiceOwner on "Service: payments") grants Bob Operator access
curl -s -X POST "http://localhost:8080/api/v1/management-groups/$GROUP_ID/roles" \
  -b "$JANE_COOKIE" \
  -H "Content-Type: application/json" \
  -d '{
    "principal_type": "user",
    "principal_id": "bob",
    "role_name": "Operator"
  }'
```

Response (201):
```json
{
  "data": { "assigned": true },
  "meta": { "api_version": "v1" }
}
```

### List role assignments on a group

```bash
curl -s "http://localhost:8080/api/v1/management-groups/$GROUP_ID/roles" -b "$COOKIE"
```

Response:
```json
{
  "data": [
    {
      "group_id": "a1b2c3d4e5f6",
      "principal_type": "user",
      "principal_id": "jane",
      "role_name": "ITServiceOwner"
    },
    {
      "group_id": "a1b2c3d4e5f6",
      "principal_type": "user",
      "principal_id": "bob",
      "role_name": "Operator"
    }
  ],
  "meta": { "api_version": "v1" }
}
```

### Revoke delegated access

```bash
curl -s -X DELETE "http://localhost:8080/api/v1/management-groups/$GROUP_ID/roles" \
  -b "$JANE_COOKIE" \
  -H "Content-Type: application/json" \
  -d '{
    "principal_type": "user",
    "principal_id": "bob",
    "role_name": "Operator"
  }'
```

### Attempting to delegate a forbidden role

```bash
curl -s -X POST "http://localhost:8080/api/v1/management-groups/$GROUP_ID/roles" \
  -b "$JANE_COOKIE" \
  -H "Content-Type: application/json" \
  -d '{
    "principal_type": "user",
    "principal_id": "bob",
    "role_name": "Administrator"
  }'
```

Response (403):
```json
{
  "error": "only Operator and Viewer roles can be delegated",
  "meta": { "api_version": "v1" }
}
```

---

## Scope Expressions with Tags

Tags integrate with Yuzu's scope engine for targeting devices. You can use tag values in scope expressions:

```
tag:environment == "Production"
tag:service == "payments" AND tag:location == "us-east-1"
tag:role == "web-server" OR tag:role == "api-server"
NOT tag:environment == "Dev"
```

This allows you to target instructions, policies, and reports at specific device subsets based on their tags.

---

## REST API Reference

All endpoints require an authenticated session. Permissions listed are the RBAC securable type and operation checked.

### Tag Categories

| Method | Path | Permission | Description |
|---|---|---|---|
| GET | `/api/v1/tag-categories` | Tag:Read | List all structured tag categories and their validation rules |

### Tag Compliance

| Method | Path | Permission | Description |
|---|---|---|---|
| GET | `/api/v1/tag-compliance` | Tag:Read | List devices missing one or more category tags |

### Tags CRUD

| Method | Path | Permission | Description |
|---|---|---|---|
| GET | `/api/v1/tags?agent_id=X` | Tag:Read | Get all tags for a device |
| PUT | `/api/v1/tags` | Tag:Write | Set a tag (body: `agent_id`, `key`, `value`) |
| DELETE | `/api/v1/tags/:agent_id/:key` | Tag:Delete | Remove a tag |

### Management Group Role Delegation

| Method | Path | Permission | Description |
|---|---|---|---|
| GET | `/api/v1/management-groups/:id/roles` | ManagementGroup:Read | List role assignments on a group |
| POST | `/api/v1/management-groups/:id/roles` | ITServiceOwner on group or global Admin | Assign a role (Operator/Viewer) on a group |
| DELETE | `/api/v1/management-groups/:id/roles` | ITServiceOwner on group or global Admin | Remove a role assignment from a group |

### Request/Response Format

All responses use a standard JSON envelope:

```json
// Success
{
  "data": { ... },
  "meta": { "api_version": "v1" }
}

// Error
{
  "error": "description of what went wrong",
  "meta": { "api_version": "v1" }
}

// List with pagination
{
  "data": [ ... ],
  "pagination": { "total": 50, "start": 0, "page_size": 50 },
  "meta": { "api_version": "v1" }
}
```

---

## Worked Example: Onboarding a New Service

This walkthrough shows the end-to-end flow of onboarding the "payments" service with two team members.

### 1. Tag the devices

```bash
# Tag three devices with all four categories
for agent in pay-web-01 pay-web-02 pay-db-01; do
  curl -s -X PUT http://localhost:8080/api/v1/tags -b "$COOKIE" \
    -H "Content-Type: application/json" \
    -d "{\"agent_id\": \"$agent\", \"key\": \"service\", \"value\": \"payments\"}"

  curl -s -X PUT http://localhost:8080/api/v1/tags -b "$COOKIE" \
    -H "Content-Type: application/json" \
    -d "{\"agent_id\": \"$agent\", \"key\": \"environment\", \"value\": \"Production\"}"

  curl -s -X PUT http://localhost:8080/api/v1/tags -b "$COOKIE" \
    -H "Content-Type: application/json" \
    -d "{\"agent_id\": \"$agent\", \"key\": \"location\", \"value\": \"us-east-1\"}"
done

# Set roles individually
curl -s -X PUT http://localhost:8080/api/v1/tags -b "$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "pay-web-01", "key": "role", "value": "web-server"}'

curl -s -X PUT http://localhost:8080/api/v1/tags -b "$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "pay-web-02", "key": "role", "value": "web-server"}'

curl -s -X PUT http://localhost:8080/api/v1/tags -b "$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "pay-db-01", "key": "role", "value": "database"}'
```

### 2. Verify compliance

```bash
curl -s http://localhost:8080/api/v1/tag-compliance -b "$COOKIE" | python -m json.tool
```

All three devices should be absent from the response (meaning they have all four tags set).

### 3. Appoint a service owner

```bash
# Find the auto-created management group
GROUP_ID=$(curl -s http://localhost:8080/api/v1/management-groups -b "$COOKIE" \
  | python -c "import sys,json; groups=json.load(sys.stdin)['data']; print(next(g['id'] for g in groups if g['name']=='Service: payments'))")

# Assign Jane as ITServiceOwner
curl -s -X POST "http://localhost:8080/api/v1/management-groups/$GROUP_ID/roles" \
  -b "$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{"principal_id": "jane", "role_name": "ITServiceOwner"}'
```

### 4. Jane delegates access to her team

Jane logs in and delegates:

```bash
# Jane gives Bob operator access
curl -s -X POST "http://localhost:8080/api/v1/management-groups/$GROUP_ID/roles" \
  -b "$JANE_COOKIE" \
  -H "Content-Type: application/json" \
  -d '{"principal_id": "bob", "role_name": "Operator"}'

# Jane gives Alice viewer access
curl -s -X POST "http://localhost:8080/api/v1/management-groups/$GROUP_ID/roles" \
  -b "$JANE_COOKIE" \
  -H "Content-Type: application/json" \
  -d '{"principal_id": "alice", "role_name": "Viewer"}'
```

### 5. Verify the setup

```bash
# List all role assignments on the group
curl -s "http://localhost:8080/api/v1/management-groups/$GROUP_ID/roles" -b "$COOKIE"
```

```json
{
  "data": [
    { "principal_type": "user", "principal_id": "jane", "role_name": "ITServiceOwner" },
    { "principal_type": "user", "principal_id": "bob", "role_name": "Operator" },
    { "principal_type": "user", "principal_id": "alice", "role_name": "Viewer" }
  ]
}
```

Now:
- **Jane** can manage all devices tagged `service=payments`, run instructions, manage tags, and delegate access.
- **Bob** can execute operations on those devices (but not delegate further).
- **Alice** can view device state and query results (read-only).
- None of them can see or act on devices outside the "payments" service scope.

### 6. Confirm agents received their tags

```bash
# Query an agent's local tag state
curl -s -X POST http://localhost:8080/api/commands \
  -b "$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "pay-web-01",
    "plugin": "asset_tags",
    "action": "status"
  }'
```

Expected output includes:
```
tag|role|web-server
tag|environment|Production
tag|location|us-east-1
tag|service|payments
last_sync|1710849600
stale|false
```

---

## Troubleshooting

### "invalid value for category" error when setting a tag

The `environment` category only accepts `Dev`, `UAT`, or `Production` (case-sensitive). Check your value matches exactly.

### Agent shows `stale|true` in status

The agent hasn't received a tag sync within the check interval (default 300 seconds). This can happen if:
- The agent was offline during the last tag change.
- Network connectivity was interrupted.
- The check interval is set shorter than the normal sync cadence.

The server will push a fresh sync the next time any structured category tag is updated for that device. You can also trigger a manual sync by re-setting any category tag to its current value.

### "forbidden" when delegating a role

The caller must either be a global Administrator or hold ITServiceOwner on the target management group. Also, only Operator and Viewer can be delegated — attempting to delegate ITServiceOwner or Administrator returns a 403.

### Management group not auto-created

Auto-creation only happens when the `service` tag is set. The other three categories (`role`, `environment`, `location`) do not create management groups. If you need groups for those, create them manually via the management groups API.

### Agent doesn't have the asset_tags plugin

The `asset_tags` plugin must be built and placed in the agent's plugin directory (`<libdir>/yuzu/plugins/`). Verify the plugin is loaded by checking the agent's startup logs for `loaded plugin: asset_tags`.
