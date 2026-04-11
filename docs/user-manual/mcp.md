# MCP (Model Context Protocol) Server

Yuzu embeds a Model Context Protocol (MCP) server that allows AI assistants --
such as Claude Desktop, Cursor, or any MCP-compatible client -- to interact with
your fleet management data through natural language. The MCP server exposes
read-only and operational tools over a JSON-RPC 2.0 endpoint, enabling
AI-driven fleet investigation, compliance reporting, and supervised command
execution.

---

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [CLI Flags](#cli-flags)
- [Authorization Tiers](#authorization-tiers)
- [Creating MCP Tokens](#creating-mcp-tokens)
- [Available Tools](#available-tools)
- [Resources](#resources)
- [Prompts](#prompts)
- [Approval Workflow](#approval-workflow)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

---

## Overview

The MCP server is **enabled by default** when the Yuzu server starts. It
registers a single HTTP endpoint at `POST /mcp/v1/` that speaks the
[Model Context Protocol](https://modelcontextprotocol.io/) -- a JSON-RPC 2.0
based protocol designed for AI tool use.

Key characteristics:

- **Protocol**: JSON-RPC 2.0 over HTTP POST.
- **Endpoint**: `POST /mcp/v1/`
- **Protocol version**: `2025-03-26`
- **Authentication**: Same as all Yuzu API endpoints -- session cookie, Bearer
  token, or `X-Yuzu-Token` header.
- **Authorization**: Two layers -- MCP tier (checked first) then RBAC
  (checked second). A token must pass both.
- **Audit**: Every tool invocation is recorded in the audit log with an
  `mcp.<tool_name>` action.
- **Capabilities**: 23 tools, 3 resources, 4 prompts.

The MCP server reuses the same authentication middleware, RBAC engine, and
audit pipeline as the REST API. No separate ports or processes are required.

---

## Quick Start

### 1. Create an MCP token

Use the REST API to create a token with an MCP tier. The `readonly` tier is
the safest starting point.

```bash
curl -s -b cookies.txt -X POST https://localhost:8080/api/v1/tokens \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Claude Desktop - readonly",
    "mcp_tier": "readonly",
    "expires_at": 1750000000
  }'
```

The response includes a `token` field (prefixed `yzt_`). Copy it immediately --
it is shown exactly once.

```json
{
  "data": {
    "token": "yzt_a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef12345678",
    "name": "Claude Desktop - readonly"
  },
  "meta": { "api_version": "v1" }
}
```

### 2. Configure your MCP client

In Claude Desktop, add the following to your MCP server configuration:

```json
{
  "mcpServers": {
    "yuzu": {
      "url": "https://your-yuzu-server:8080/mcp/v1/",
      "headers": {
        "Authorization": "Bearer yzt_a1b2c3d4e5f67890..."
      }
    }
  }
}
```

For other MCP clients, point the transport to the `POST /mcp/v1/` endpoint
and include the Bearer token in the `Authorization` header.

### 3. Start using natural language

Ask your AI assistant questions like:

- "How many agents are connected and what OS are they running?"
- "Show me the compliance status for the disk-encryption policy."
- "Which agents have the tag `environment=production`?"
- "What did the user `admin` do in the last 24 hours?"

The assistant will call the appropriate Yuzu MCP tools and return structured
results.

---

## CLI Flags

| Flag | Environment Variable | Default | Description |
|---|---|---|---|
| `--mcp-disable` | `YUZU_MCP_DISABLE` | `false` | Disable the MCP endpoint entirely. All requests to `/mcp/v1/` return an error. |
| `--mcp-read-only` | `YUZU_MCP_READ_ONLY` | `false` | Restrict MCP to read-only tools only. Write and execute operations are rejected regardless of the token's tier. |

### Examples

Disable MCP entirely (for air-gapped or high-security environments):

```bash
yuzu-server --mcp-disable
```

Or via environment variable:

```bash
export YUZU_MCP_DISABLE=true
yuzu-server
```

Allow MCP but restrict to read-only operations:

```bash
yuzu-server --mcp-read-only
```

---

## Authorization Tiers

MCP tokens use a **tier** system that restricts what operations are available,
independent of the underlying RBAC role. The tier check runs *before* RBAC:
even if the token creator has the Administrator role, a `readonly` tier blocks
all writes.

| Tier | Read | Tag Write/Delete | Execute Instructions | Policy/Security/Group Write | Delete (any) |
|---|---|---|---|---|---|
| `readonly` | Yes | No | No | No | No |
| `operator` | Yes | Yes | Yes (auto-approved) | No | Tags only (via approval) |
| `supervised` | Yes | Yes | Yes (via approval) | Yes (via approval) | Yes (via approval) |

### Tier details

**readonly** -- Safe for dashboards, reporting, and investigation. The AI
assistant can list agents, query inventory, check compliance, read the audit
log, and browse instruction definitions. It cannot make any changes.

**operator** -- Adds the ability to write and delete tags, and to execute
instructions. Instruction executions are auto-approved (they run immediately
without admin approval). Tag deletions still require approval. Suitable for
day-to-day operational use.

**supervised** -- Full access to all operations, but destructive actions
require admin approval before taking effect. This includes:

- Instruction executions
- Any delete operation
- Policy writes
- Security setting writes
- User management writes
- Management group writes

Use the supervised tier for automation pipelines where an AI assistant proposes
changes that a human reviews and approves.

---

## Creating MCP Tokens

MCP tokens are API tokens with an `mcp_tier` field. Create them through the
standard `POST /api/v1/tokens` endpoint.

### Request

```bash
curl -s -b cookies.txt -X POST https://localhost:8080/api/v1/tokens \
  -H "Content-Type: application/json" \
  -d '{
    "name": "AI Fleet Monitor",
    "mcp_tier": "readonly",
    "expires_at": 1750000000
  }'
```

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | Yes | Human-readable label for the token. |
| `mcp_tier` | string | Yes (for MCP) | One of `readonly`, `operator`, or `supervised`. |
| `expires_at` | integer | Yes (for MCP) | Unix epoch seconds. MCP tokens **must** have an expiration. Maximum 90 days from creation. |

### Validation rules

- **Mandatory expiration**: MCP tokens cannot be created without an
  `expires_at` value. The server rejects the request with a `400` error if
  the expiration is missing or zero.
- **Maximum 90 days**: The expiration must be no more than 90 days in the
  future. This ensures regular token rotation.
- **Valid tier**: The `mcp_tier` must be one of `readonly`, `operator`, or
  `supervised`. Any other value is rejected.
- **RBAC permission**: The creating user must have `ApiToken:Write` permission.

### Token format

MCP tokens use the same `yzt_` prefix as standard API tokens. They are
authenticated the same way -- via `Authorization: Bearer <token>` or
`X-Yuzu-Token: <token>` headers.

### Listing and revoking tokens

Use the standard token management endpoints:

```bash
# List all tokens (shows mcp_tier in the response)
curl -s -b cookies.txt https://localhost:8080/api/v1/tokens

# Revoke a token
curl -s -b cookies.txt -X DELETE https://localhost:8080/api/v1/tokens/a1b2c3d4
```

---

## Available Tools

The MCP server exposes 23 tools. Each tool maps to a specific RBAC
securable type and operation. The tier check and RBAC check both must pass
for the tool to execute.

| # | Tool | Description | RBAC Permission |
|---|------|-------------|-----------------|
| 1 | `list_agents` | List all connected agents with hostname, OS, architecture, and version. | `Infrastructure:Read` |
| 2 | `get_agent_details` | Get detailed info for a single agent including tags and inventory. | `Infrastructure:Read` |
| 3 | `query_audit_log` | Query the audit log with filters (principal, action, target, time range). | `AuditLog:Read` |
| 4 | `list_definitions` | List available instruction definitions (filterable by plugin, type, enabled). | `InstructionDefinition:Read` |
| 5 | `get_definition` | Get a single instruction definition with parameter and result schemas. | `InstructionDefinition:Read` |
| 6 | `query_responses` | Query command response data with filters (requires instruction_id). | `Response:Read` |
| 7 | `aggregate_responses` | Aggregate response data (COUNT, SUM, AVG, MIN, MAX) grouped by a column. | `Response:Read` |
| 8 | `query_inventory` | Query inventory data across agents (filterable by agent, plugin). | `Infrastructure:Read` |
| 9 | `list_inventory_tables` | List available inventory data types with agent counts. | `Infrastructure:Read` |
| 10 | `get_agent_inventory` | Get all inventory data for a specific agent. | `Infrastructure:Read` |
| 11 | `get_tags` | Get all tags for a specific agent. | `Tag:Read` |
| 12 | `search_agents_by_tag` | Find agents that have a specific tag key (and optionally value). | `Tag:Read` |
| 13 | `list_policies` | List compliance policies (filterable by enabled status). | `Policy:Read` |
| 14 | `get_compliance_summary` | Get per-policy compliance breakdown (compliant/non-compliant/unknown). | `Policy:Read` |
| 15 | `get_fleet_compliance` | Get fleet-wide compliance percentages across all policies. | `Policy:Read` |
| 16 | `list_management_groups` | List management groups (hierarchical device grouping). | `ManagementGroup:Read` |
| 17 | `get_execution_status` | Check status of a running or completed command execution. | `Execution:Read` |
| 18 | `list_executions` | List recent command executions (filterable by definition, status). | `Execution:Read` |
| 19 | `list_schedules` | List scheduled (recurring) instructions. | `Schedule:Read` |
| 20 | `validate_scope` | Validate a scope expression without executing it. | (none -- always allowed) |
| 21 | `preview_scope_targets` | Show which agents match a scope expression. | `Infrastructure:Read` |
| 22 | `list_pending_approvals` | List pending approval requests (filterable by status, submitter). | `Approval:Read` |
| 23 | `execute_instruction` | Execute a plugin action on agents. Returns a `command_id`; poll results with `query_responses`. | `Execution:Execute` |

> **`execute_instruction` tier behavior:**
> - `readonly` tier: blocked.
> - `operator` tier: executes immediately (auto-approved). If neither `scope` nor `agent_ids` is provided, targets **all** connected agents.
> - `supervised` tier: not yet implemented (returns an error). Use the REST API or dashboard for supervised-tier execution until the approval re-dispatch path is built.

### Tool parameters

Tools accept parameters via the `arguments` object in the `tools/call` request.
Required parameters are validated server-side; missing required fields return a
`-32602 Invalid params` error.

**Examples of key parameters:**

- `agent_id` (string) -- required by `get_agent_details`, `get_agent_inventory`,
  `get_tags`.
- `instruction_id` (string) -- required by `query_responses`.
- `expression` (string) -- required by `validate_scope` and
  `preview_scope_targets`. Uses the Yuzu scope DSL (e.g.,
  `os = "Windows" AND tag:environment = "production"`).
- `limit` (integer) -- optional on most list/query tools. Capped server-side
  (typically 500 or 1000).

---

## Resources

MCP resources provide static or semi-static data that clients can read without
calling a tool. Resources are accessed via the `resources/read` method with a
URI.

| URI | Name | Description | RBAC Permission |
|-----|------|-------------|-----------------|
| `yuzu://server/health` | Server Health | Server health status and count of connected agents. | (none -- always allowed) |
| `yuzu://compliance/fleet` | Fleet Compliance | Fleet-wide compliance overview (total checks, compliant, non-compliant, unknown, percentage). | `Policy:Read` |
| `yuzu://audit/recent` | Recent Audit | Last 50 audit events with timestamp, principal, action, target, and result. | `AuditLog:Read` |

### Example: reading a resource

```json
{
  "jsonrpc": "2.0",
  "method": "resources/read",
  "params": { "uri": "yuzu://server/health" },
  "id": 1
}
```

Response:

```json
{
  "jsonrpc": "2.0",
  "result": {
    "contents": [
      {
        "uri": "yuzu://server/health",
        "mimeType": "application/json",
        "text": "{\"status\":\"ok\",\"agents_connected\":42}"
      }
    ]
  },
  "id": 1
}
```

---

## Prompts

Prompts are pre-built instruction templates that guide the AI assistant toward
common investigation workflows. Clients retrieve prompts via `prompts/list` and
invoke them via `prompts/get`.

| Prompt | Description | Parameters |
|--------|-------------|------------|
| `fleet_overview` | Summarize the fleet: agent count, OS breakdown, compliance status. | (none) |
| `investigate_agent` | Deep-dive on a specific agent: inventory, compliance, recent commands, tags. | `agent_id` (required) |
| `compliance_report` | Generate a compliance report for a specific policy or fleet-wide. | `policy_id` (optional -- omit for fleet-wide) |
| `audit_investigation` | Show all actions by a principal in a given timeframe. | `principal` (required), `hours` (optional, default 24) |

### Example: invoking a prompt

```json
{
  "jsonrpc": "2.0",
  "method": "prompts/get",
  "params": {
    "name": "investigate_agent",
    "agent_id": "agent-web-prod-01"
  },
  "id": 2
}
```

The server returns a `messages` array containing the prompt text, which the AI
assistant uses to guide its tool calls:

```json
{
  "jsonrpc": "2.0",
  "result": {
    "description": "Investigate agent 'agent-web-prod-01': show its inventory, compliance status, recent command results, and tags. Use get_agent_details, get_agent_inventory, get_tags, and query_responses.",
    "messages": [
      {
        "role": "user",
        "content": {
          "type": "text",
          "text": "Investigate agent 'agent-web-prod-01': ..."
        }
      }
    ]
  },
  "id": 2
}
```

---

## Approval Workflow

Operations that modify fleet state are gated by the **approval workflow** when
invoked through MCP. This ensures a human reviews every change an AI assistant
proposes.

### How it works

1. The AI assistant calls a tool that requires approval (e.g., executing an
   instruction on the `supervised` tier).
2. The MCP server creates an **approval request** with status `pending`.
3. The server returns a JSON-RPC error with code `-32006` (`ApprovalRequired`)
   containing the approval ID.
4. The AI assistant can inform the operator that approval is needed.
5. An administrator reviews the request via the dashboard or REST API
   (`GET /api/approvals`, `POST /api/approvals/{id}/approve`,
   `POST /api/approvals/{id}/reject`).
6. Once approved, the operation can be retried.

### What requires approval

The following table shows which operations require approval, by tier:

| Operation | `operator` tier | `supervised` tier |
|-----------|----------------|-------------------|
| Execute instruction | No (auto-approved) | Yes |
| Delete tag | Yes | Yes |
| Delete (any resource) | -- | Yes |
| Write policy | -- | Yes |
| Write security settings | -- | Yes |
| Write user management | -- | Yes |
| Write management group | -- | Yes |

The `readonly` tier cannot perform any of these operations, so approval is
never triggered.

### Monitoring pending approvals

The `list_pending_approvals` tool allows the AI assistant to check the status
of submitted approval requests:

```
"List all pending approvals submitted by the MCP token."
```

Administrators can also see pending approvals in the Yuzu dashboard under the
approval queue.

---

## Security Considerations

### Default-enabled behavior

The MCP server is enabled by default when the Yuzu server starts. If you do
not intend to use AI-assisted fleet management, disable it:

```bash
yuzu-server --mcp-disable
```

### Air-gapped and high-security environments

For networks that do not permit AI assistant connections, disable MCP entirely
using `--mcp-disable` or `YUZU_MCP_DISABLE=true`. When disabled, the
`/mcp/v1/` endpoint rejects all requests with a `-32005` error code.

### Token rotation

MCP tokens are enforced to have a maximum lifetime of 90 days. Establish a
rotation schedule:

- **Recommended**: Create new tokens every 30 days and revoke old ones.
- **Required**: Tokens expire automatically at the `expires_at` time.
- **Best practice**: Use descriptive names (e.g., `"Claude Desktop - prod readonly 2026-Q1"`) to track token purpose and lifecycle.

### Tier selection guidance

| Use Case | Recommended Tier |
|----------|-----------------|
| Read-only dashboards, reporting, investigation | `readonly` |
| Day-to-day operations with AI assistance (tagging, auto-approved executions) | `operator` |
| Automation pipelines with human approval gates | `supervised` |
| Unattended, unsupervised AI access | Not recommended. Use `readonly` at most. |

### Principle of least privilege

- Start with `readonly` and only upgrade to `operator` or `supervised` when
  operationally required.
- The token inherits the RBAC permissions of the user who created it. Create
  MCP tokens from accounts with appropriate (not excessive) permissions.
- Use `--mcp-read-only` as a server-wide safety net if you want to allow
  MCP connections but prevent any write operations regardless of token tier.

### Audit trail

Every MCP tool invocation is logged in the audit trail with action
`mcp.<tool_name>` (e.g., `mcp.list_agents`, `mcp.query_audit_log`). Use the
`query_audit_log` tool or the REST API to review MCP activity:

```bash
curl -s -b cookies.txt \
  'https://localhost:8080/api/v1/audit?action=mcp.&limit=100'
```

---

## Troubleshooting

### 401 Unauthorized

**Symptom**: All MCP requests return HTTP 401.

**Causes**:
- The token is missing, expired, or revoked.
- The `Authorization` header format is wrong. It must be `Bearer <token>` (with
  a space, no colon).
- The token was created with a session that has since expired. The token itself
  is independent of the session -- verify the token's `expires_at` value.

**Fix**: Create a new token via `POST /api/v1/tokens` and update your MCP
client configuration.

### -32005: MCP disabled

**Symptom**: Requests to `/mcp/v1/` return error code `-32005`.

**Cause**: The server was started with `--mcp-disable` or
`YUZU_MCP_DISABLE=true`.

**Fix**: Remove the flag or unset the environment variable and restart the
server.

### -32004: MCP tier does not allow this operation

**Symptom**: A tool call returns error code `-32004`.

**Cause**: The token's MCP tier does not permit the requested operation. For
example, a `readonly` token attempting to execute an instruction.

**Fix**: Create a new token with a higher tier (`operator` or `supervised`),
or use a different tool that is within the current tier's permissions.

### -32006: Approval required

**Symptom**: A tool call returns error code `-32006` with an approval ID.

**Cause**: The operation requires admin approval before it can proceed. This
is expected behavior for destructive operations on `supervised` tier tokens,
and for tag deletions on `operator` tier tokens. Note that `operator` tier
executions are auto-approved and do not trigger this error.

**Fix**: An administrator must approve the request via the dashboard or REST
API. After approval, retry the operation.

### -32003: Permission denied (RBAC)

**Symptom**: A tool call returns error code `-32003`.

**Cause**: The token passes the MCP tier check but fails the RBAC permission
check. The user who created the token does not have the required RBAC
permission for the securable type.

**Fix**: Grant the appropriate RBAC permission to the token creator's
principal, or create a new token from an account with the required permissions.

### -32602: Invalid params

**Symptom**: A tool call returns error code `-32602`.

**Cause**: A required parameter is missing or invalid. For example, calling
`get_agent_details` without `agent_id`, or calling `query_responses` without
`instruction_id`.

**Fix**: Include all required parameters in the `arguments` object. See the
[Available Tools](#available-tools) section for parameter requirements.

### MCP client cannot connect

**Symptom**: The MCP client reports connection errors.

**Causes**:
- The server is not reachable from the client machine.
- HTTPS certificate validation fails (self-signed cert). Add the CA cert to
  your system trust store or configure the client to trust it.
- The URL is wrong. The endpoint is `POST /mcp/v1/` (with trailing slash).

**Fix**: Verify network connectivity, TLS configuration, and the endpoint URL.
Test with curl:

```bash
curl -s -X POST https://your-server:8080/mcp/v1/ \
  -H "Authorization: Bearer yzt_..." \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"ping","id":1}'
```

A successful response:

```json
{"jsonrpc":"2.0","result":{},"id":1}
```
