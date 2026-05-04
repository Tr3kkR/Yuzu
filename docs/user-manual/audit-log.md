# Audit Log

Yuzu records every operator action as a structured audit event. The audit log
provides a tamper-evident trail suitable for compliance reporting, incident
investigation, and forwarding to external SIEM platforms such as Splunk or
Elastic.

> **Known issue in v0.9.0 (advisory YZA-2026-001):** audit rows for requests
> authenticated via `Authorization: Bearer` or `X-Yuzu-Token` (every MCP tool
> call and every REST automation using an API token) had an empty `principal`
> field. Cookie-authenticated dashboard activity was unaffected. Fixed forward
> in v0.10.0; pre-fix rows are not backfilled. Operators auditing a window that
> spans the v0.9.0 → v0.10.0 boundary should expect a bimodal `principal`
> distribution. See `CHANGELOG.md` for full remediation context.

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
| `session_id` | string | Session cookie identifier (empty for API-token / Bearer / `X-Yuzu-Token` requests, which have no cookie) |
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
| `cert.reload` | TlsCertificate | Certificate hot-reload attempted; detail contains outcome (success or failure reason) |
| `guaranteed_state.rule.create` | GuaranteedState | A Guaranteed State rule is created. On 400 (missing required fields), 409 (rule_id/name conflict), or RBAC rejection, emits `result=denied` with the store error in `detail`. |
| `guaranteed_state.rule.update` | GuaranteedState | A Guaranteed State rule is updated (version is incremented on every successful update). On 404 (rule not found), 400 (invalid JSON body — `detail` is the literal string `"invalid JSON body"`), 409 (name conflict), or RBAC rejection, emits `result=denied`. |
| `guaranteed_state.rule.delete` | GuaranteedState | A Guaranteed State rule is deleted. On 404 or RBAC rejection, emits `result=denied`. |
| `guaranteed_state.push` | GuaranteedState | A push of the active rule set to scoped agents is accepted. `target_id` is empty (pushes are fleet-level, not per-entity); `detail` carries `rules=<N> full_sync=<bool> scope="<sanitised-expr>" fan_out_deferred_pr3=true`. The scope value in `detail` is **sanitised before embedding**: `"` and `\` are backslash-escaped, C0 control bytes (0x00–0x1F, DEL) are dropped. SIEM parsers reconstructing the original scope expression must account for this normalisation — a raw operator input of `env="prod"` appears in the audit as `scope="env=\"prod\""`. The `fan_out_deferred_pr3=true` marker means the REST call is accepted and persisted server-side but agent fan-out is not wired until Guardian PR 3; SIEM rules that infer "rules were delivered to agents" from this event are premature until that flag disappears. Non-object JSON bodies are rejected with `result=denied` and `detail="invalid JSON body"`. |
| `tar.status.scan` | Infrastructure | An operator clicked **Scan fleet** on the TAR dashboard page (`/tar`). A `tar.status` command was dispatched to the operator's visible-agent set. `detail` carries the count of agents the dispatch reached (e.g. `dispatched to 47 agent(s) in scope`). One row per Scan button press; no row on page-load Refresh. |
| `tar.source.reenable` | Infrastructure | An operator clicked **Re-enable** on a row of the TAR retention-paused list and a `tar.configure` command with `<source>_enabled=true` was dispatched to a single device. `detail` carries `device=<id> source=<process|tcp|service|user>` on success. Failures emit `result=failure` with `detail` set to the real reason (`scope_violation source=<src>` for out-of-scope device IDs, `agent_not_connected source=<src>` for connected-but-zero-sent dispatches) so SIEM rules can distinguish a forged-form attempt from a transient connectivity issue — even though the HTTP response body is identical (`Agent not reachable.` 404) for both, to deny enumeration. |
| `execution.visualization.fetch` | Execution | Chart-ready JSON was rendered for an execution's response set via `GET /api/v1/executions/{id}/visualization` (issue #253 / #587). `target_id` is the `command_id`; `detail` carries `<definition_id> index=<N>` on success, or `<definition_id> reason=<r>` on the failure path where `<r>` is one of `missing_definition_id`, `malformed_definition_id`, `definition_not_found`, `no_visualization`, `index_oor`. Permission gate: `Response:Read`. The `command.dispatch` event (above, when emitted from the dashboard) appends `definition_id=<id>` to its `detail` when the dashboard reverse-resolves a chart-bearing definition, so SIEM can join `command.dispatch` to the subsequent `execution.visualization.fetch` by `definition_id`. |
| `plugin_signing.bundle.uploaded` | PluginTrustBundle | An admin uploaded a PEM trust bundle via Settings → Plugin Code Signing. `detail` carries `<N> cert(s), sha256=<hex>` on success. On `result=failure` (PEM validation rejected the input — empty body, missing markers, no parsable cert, hashing failure, etc.) `detail` carries the validation error string. Audit row is emitted on both branches so a SIEM rule on `failure` can detect malformed-upload probing. |
| `plugin_signing.bundle.cleared` | PluginTrustBundle | An admin removed the trust bundle (Settings → Plugin Code Signing → Remove). `detail` carries `file removed` (a file existed and was deleted) or `no file present` (clear was a no-op). Always emits `success` unless the require-flag DB write fails first, in which case `result=failure` and `detail` carries the store error — and the file is **not** removed (two-phase commit prevents the disk/DB-flag desync). |
| `plugin_signing.require.changed` | RuntimeConfig | An admin toggled "Require signed plugins" via Settings. `target_id` is `plugin_signing_required`, `detail` carries the new value (`"true"` or `"false"`). Emitted on every change including no-op idempotent re-saves. |
| `response_template.create` | InstructionDefinition | A response-view template was created via `POST /api/v1/definitions/{id}/response-templates` (issue #254 / Phase 8.2). `target_id` is the definition id; `detail` is the new template id on success, or `reason=<r>` on the audit path. RBAC denials, 400 (malformed id / invalid JSON / validation), 404 (definition not found), and 413 (body too large) emit `result=denied`; 500 (persist failure) emits `result=failure`. Reasons: `malformed_definition_id`, `body_too_large`, `invalid_json`, `definition_not_found`, `validation_failed`, `persist_failure`. Permission gate: `InstructionDefinition:Write`. |
| `response_template.update` | InstructionDefinition | A response-view template was replaced via `PUT /api/v1/definitions/{id}/response-templates/{tid}` (issue #254). `target_id` is the definition id; `detail` is the template id on success, or `reason=<r>` on the audit path. 4xx branches emit `result=denied`; 500 persist failure emits `result=failure`. Reasons: `malformed_id`, `reserved_id`, `body_too_large`, `invalid_json`, `definition_not_found`, `template_not_found`, `validation_failed`, `persist_failure`. Permission gate: `InstructionDefinition:Write`. |
| `response_template.delete` | InstructionDefinition | A response-view template was removed via `DELETE /api/v1/definitions/{id}/response-templates/{tid}` (issue #254). `target_id` is the definition id; `detail` is the deleted template id on success, or `reason=<r>` on the audit path. 4xx branches emit `result=denied`; 500 persist failure emits `result=failure`. Reasons: `malformed_id`, `reserved_id`, `definition_not_found`, `template_not_found`, `persist_failure`. Permission gate: `InstructionDefinition:Write`. |

**Result vocabulary.** Every action above emits `result` as `success` or `denied`. `denied` is used for RBAC rejections and for every 400/404/409 branch where the handler explicitly audits the failure — including Guardian `rule.create` (400 missing fields, 409 conflict), `rule.update` (400 invalid body, 404 not found, 409 conflict), `rule.delete` (404 not found), and `push` (400 non-object body). `failure` appears only on internal errors that the handler does not itself audit. SIEM rules that filter on `result == "success"` will match every completed Guardian mutation including `guaranteed_state.push` (which returns 202 rather than 201/200 because agent fan-out is asynchronous). To surface probe/fuzz traffic on the REST surface, filter on `result == "denied"` scoped to the actions you care about — every mutating branch produces a row.

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
