# Audit Log

Yuzu records every operator action as a structured audit event. The audit log
provides a tamper-evident trail suitable for compliance reporting, incident
investigation, and forwarding to external SIEM platforms such as Splunk or
Elastic.

## Storage

Audit events are persisted in a dedicated SQLite database using WAL
(Write-Ahead Logging) mode for high write throughput without blocking readers.

| Setting | Default | Description |
|---|---|---|
| Retention period | 365 days | Events older than this are deleted by background cleanup |
| Cleanup interval | 1 hour | How often the background thread prunes expired events |

## Event structure

Every audit event contains the following fields:

| Field | Type | Description |
|---|---|---|
| `timestamp` | integer (Unix epoch) | When the event occurred |
| `principal` | string | Username of the operator who performed the action |
| `principal_role` | string | Role of the principal at the time of the action (`admin`, `user`) |
| `action` | string | Dot-notated action identifier (see table below) |
| `target_type` | string | Category of the affected object (`Tag`, `Agent`, `Session`, etc.) |
| `target_id` | string | Identifier of the affected object |
| `detail` | string | Human-readable description or the new value |
| `source_ip` | string | IP address of the client that initiated the request |
| `user_agent` | string | HTTP User-Agent header value |
| `session_id` | string | Session cookie identifier |
| `result` | string | Outcome: `success` or `failure` |

## Logged actions

The following actions are recorded automatically. No operator configuration is
required.

| Action | Target type | When |
|---|---|---|
| `auth.login` | Session | Operator logs in via the dashboard or API |
| `auth.logout` | Session | Operator logs out |
| `auth.login_failed` | Session | Failed login attempt |
| `tag.set` | Tag | A tag is created or updated on an agent |
| `tag.delete` | Tag | A tag is removed from an agent |
| `instruction.execute` | Instruction | An instruction is dispatched to one or more agents |
| `instruction.approve` | Instruction | An instruction pending approval is approved |
| `instruction.deny` | Instruction | An instruction pending approval is denied |
| `enrollment.approve` | Agent | A pending agent enrollment is approved |
| `enrollment.deny` | Agent | A pending agent enrollment is denied |
| `enrollment.token_create` | EnrollmentToken | An enrollment token is generated |
| `settings.update` | Setting | A server setting is changed |
| `rbac.role_assign` | Principal | A role is assigned to a principal |
| `rbac.role_revoke` | Principal | A role is revoked from a principal |
| `management_group.create` | ManagementGroup | A management group is created |
| `management_group.delete` | ManagementGroup | A management group is deleted |
| `management_group.add_member` | ManagementGroup | An agent is added to a management group |
| `management_group.remove_member` | ManagementGroup | An agent is removed from a management group |
| `management_group.assign_role` | ManagementGroup | A role is assigned to a principal on a management group |
| `management_group.unassign_role` | ManagementGroup | A role is unassigned from a principal on a management group |
| `api_token.create` | ApiToken | An API token is generated |
| `api_token.revoke` | ApiToken | An API token is revoked |
| `quarantine.enable` | Security | A device is placed in quarantine |
| `quarantine.disable` | Security | A device is released from quarantine |

## REST API

### GET /api/v1/audit

Query audit events with filtering and pagination. Maximum page size is 1000.

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `limit` | integer | Number of events to return (default 100, max 1000) |
| `principal` | string | Filter by principal username |
| `action` | string | Filter by action (exact match) |

Note: the v1 endpoint supports `principal` and `action` filters only. For
additional filters (`target_type`, `target_id`, `since`, `until`, `offset`),
use the legacy `/api/audit` endpoint.

**Example --- fetch the 20 most recent events:**

```bash
curl -s -b cookies.txt \
  'http://localhost:8080/api/v1/audit?limit=20' | jq .
```

**Response:**

```json
{
  "data": [
    {
      "timestamp": 1710849600,
      "principal": "admin",
      "action": "tag.set",
      "result": "success",
      "target_type": "Tag",
      "target_id": "agent-001:environment",
      "detail": "Production"
    }
  ],
  "pagination": {
    "total": 150,
    "start": 0,
    "page_size": 20
  },
  "meta": {
    "api_version": "v1"
  }
}
```

**Example --- filter by principal and action:**

```bash
curl -s -b cookies.txt \
  'http://localhost:8080/api/v1/audit?principal=admin&action=auth.login&limit=50' | jq .
```

**Example --- find all failed login attempts:**

```bash
curl -s -b cookies.txt \
  'http://localhost:8080/api/v1/audit?action=auth.login_failed' | jq .
```

### GET /api/audit (legacy)

The legacy endpoint supports the full set of query parameters and has no
hard-coded limit cap. New integrations should prefer `/api/v1/audit` once
additional filters are added there.

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `limit` | integer | Number of events to return (default 100, no hard cap) |
| `offset` | integer | Offset for pagination (default 0) |
| `principal` | string | Filter by principal username |
| `action` | string | Filter by action (exact match) |
| `target_type` | string | Filter by target type |
| `target_id` | string | Filter by target identifier |
| `since` | integer | Only events after this Unix timestamp |
| `until` | integer | Only events before this Unix timestamp |

The legacy response envelope differs from v1:

```json
{
  "events": [ ... ],
  "count": 20,
  "total": 150
}
```

The legacy response includes additional fields per event not present in the v1
response: `id`, `principal_role`, `source_ip`.

```bash
curl -s -b cookies.txt \
  'http://localhost:8080/api/audit?limit=5000&principal=admin' | jq .
```

## Dashboard viewer

The Yuzu dashboard includes a built-in audit log viewer accessible from the
navigation menu. The viewer renders audit events as an HTMX-powered table with
live filtering by principal, action, and date range. No additional
configuration is required.

## Retention and cleanup

Audit events are retained for 365 days by default. A background thread runs
every hour and deletes events whose `timestamp` falls outside the retention
window. Deletion is permanent --- there is no soft-delete or archive step.

To preserve audit data beyond the retention window, export events periodically
using the REST API or forward them to an external system (see Planned Features
below).

## Integration patterns

### Export to CSV

Use the JSON-to-CSV export endpoint to convert audit query results into a
downloadable CSV file:

```bash
# 1. Fetch audit events as JSON
curl -s -b cookies.txt \
  'http://localhost:8080/api/v1/audit?limit=1000' | jq '.data' > audit.json

# 2. Convert to CSV
curl -s -b cookies.txt \
  -X POST \
  -H 'Content-Type: application/json' \
  -d @audit.json \
  'http://localhost:8080/api/export/json-to-csv' -o audit.csv
```

### Periodic export with cron

```bash
#!/bin/bash
# /etc/cron.daily/yuzu-audit-export
DATE=$(date +%Y-%m-%d)
curl -s -b /opt/yuzu/cookies.txt \
  "http://localhost:8080/api/v1/audit?limit=1000" \
  | jq '.data' > "/var/log/yuzu/audit-${DATE}.json"
```

### Splunk HTTP Event Collector

Poll the audit API and forward events to Splunk HEC:

```bash
# Fetch recent audit events and forward each to Splunk
curl -s -b cookies.txt \
  'http://localhost:8080/api/v1/audit?limit=100' \
  | jq -c '.data[]' \
  | while read -r event; do
      curl -s -X POST \
        -H "Authorization: Splunk YOUR-HEC-TOKEN" \
        -d "{\"event\": ${event}}" \
        https://splunk.example.com:8088/services/collector/event
    done
```

## Planned features

| Feature | Roadmap | Description |
|---|---|---|
| Event subscriptions / webhooks | Phase 7, Issue 7.12 | Push audit events to external HTTP endpoints in real time |
| System notifications | Phase 7, Issue 7.4 | Alerts for health, capacity, and compliance events |
