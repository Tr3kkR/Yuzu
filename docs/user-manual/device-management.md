# Device Management

This guide covers the full device lifecycle in Yuzu: enrolling agents, monitoring connectivity, managing device identity, and performing over-the-air agent updates.

**Prerequisites:** A running Yuzu server. All `curl` examples assume an active admin session cookie in `$COOKIE` -- replace with your session token. The server listens on `http://localhost:8080` by default.

---

## Agent Enrollment

Yuzu uses a three-tier enrollment model. Every agent must register with the server before it can receive instructions. The tier determines how much manual intervention is required.

### Tier 1: Manual Approval

The default enrollment mode. When an agent connects without a token, it enters a **pending queue**. An administrator must explicitly approve or deny the agent before it can participate in the fleet.

**Agent side:**

```bash
yuzu-agent --server server.example.com:50051
```

The agent will attempt registration, receive a "pending" status, and retry periodically until approved.

**Server side (dashboard):** Navigate to **Settings > Pending Agents** to see the queue. Each entry shows the agent's hostname, OS, architecture, and the time it first connected. Click **Approve** or **Deny**.

**Server side (API):**

There is no dedicated JSON API endpoint to list pending agents. Use the HTMX fragment to retrieve the rendered HTML list:

```bash
# List pending agents (returns HTML fragment)
curl -s http://localhost:8080/fragments/settings/pending -b "$COOKIE"
```

```bash
# Approve a pending agent
curl -s -X POST http://localhost:8080/api/settings/pending-agents/agent-001/approve \
  -b "$COOKIE"
```

```bash
# Deny a pending agent
curl -s -X POST http://localhost:8080/api/settings/pending-agents/agent-001/deny \
  -b "$COOKIE"
```

```bash
# Remove a pending agent from the queue entirely
curl -s -X DELETE http://localhost:8080/api/settings/pending-agents/agent-001 \
  -b "$COOKIE"
```

### Tier 2: Pre-Shared Enrollment Tokens

For automated deployments, administrators generate **enrollment tokens** -- time-limited and use-limited secrets that agents present at registration for immediate enrollment without manual approval.

**Generate a token (HTMX -- returns HTML fragment):**

This endpoint is designed for the HTMX dashboard and accepts form-encoded parameters. It returns an HTML fragment containing the token list with the new token's raw value revealed once.

```bash
curl -s -X POST http://localhost:8080/api/settings/enrollment-tokens \
  -b "$COOKIE" \
  -d "label=datacenter-rollout-q1&max_uses=100&ttl_hours=72"
```

The response is an HTML fragment (the updated tokens table). The raw token value is displayed once in the fragment and cannot be retrieved again.

**Generate tokens in batch (JSON API for scripting):**

This endpoint accepts JSON and returns a JSON response, making it suitable for automation and scripting.

```bash
curl -s -X POST http://localhost:8080/api/settings/enrollment-tokens/batch \
  -b "$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{
    "label": "site-deploy",
    "count": 10,
    "max_uses": 50,
    "ttl_hours": 24
  }'
```

Response:

```json
{
  "count": 10,
  "tokens": ["yuzu_enroll_xxx...", "yuzu_enroll_yyy...", "..."]
}
```

**Agent side:**

```bash
yuzu-agent --server server.example.com:50051 \
           --enrollment-token "yuzu_enroll_xxxxxxxxxxxxxxxxxxxxxxxx"
```

The agent includes the token in its `RegisterRequest`. If the token is valid and has remaining uses, enrollment succeeds immediately.

**List active tokens (returns HTML fragment):**

There is no dedicated JSON API endpoint to list enrollment tokens. Use the HTMX fragment:

```bash
curl -s http://localhost:8080/fragments/settings/tokens -b "$COOKIE"
```

**Revoke a token:**

```bash
curl -s -X DELETE http://localhost:8080/api/settings/enrollment-tokens/tok_a1b2c3d4 \
  -b "$COOKIE"
```

Tokens are persisted in `enrollment-tokens.cfg` alongside the server configuration file. They survive server restarts.

### Tier 3: Platform Trust (Planned)

Reserved for future implementation. Proto fields exist for `machine_certificate`, `attestation_signature`, and `attestation_provider` to support Windows certificate store attestation and cloud identity verification. Agents on domain-joined machines or cloud VMs will be able to prove their identity cryptographically without any shared secret.

---

## Auto-Approval Policies

Administrators can configure rules that automatically approve agents matching specific criteria, reducing manual toil for large deployments.

**View current auto-approval policies (dashboard):** Navigate to **Settings > Auto-Approve**.

**Add an auto-approval rule:**

The auto-approve endpoints use form-encoded parameters (designed for the HTMX dashboard) and return HTML fragments.

```bash
curl -s -X POST http://localhost:8080/api/settings/auto-approve \
  -b "$COOKIE" \
  -d "type=hostname_glob&value=web-*.example.com&label=Production+web+servers"
```

This rule automatically approves any agent whose hostname matches the glob pattern `web-*.example.com`.

Supported rule types: `hostname_glob`, `trusted_ca`, `ip_subnet`, `cloud_provider`.

**Set the auto-approve match mode:**

```bash
curl -s -X POST http://localhost:8080/api/settings/auto-approve/mode \
  -b "$COOKIE" \
  -d "mode=any"
```

Supported modes:

| Mode | Behavior |
|---|---|
| `any` | First matching enabled rule auto-approves the agent (default) |
| `all` | All enabled rules must match for auto-approval |

Note: Auto-approval only applies when rules exist and are enabled. When no rules are configured, all agents enter the pending queue regardless of mode. To disable auto-approval entirely, remove or disable all rules.

**Toggle a rule on/off:**

```bash
curl -s -X POST http://localhost:8080/api/settings/auto-approve/0/toggle \
  -b "$COOKIE"
```

**Delete a rule:**

```bash
curl -s -X DELETE http://localhost:8080/api/settings/auto-approve/0 \
  -b "$COOKIE"
```

**View the auto-approve settings fragment (HTMX):**

```bash
curl -s http://localhost:8080/fragments/settings/auto-approve -b "$COOKIE"
```

---

## Device Identity

Every enrolled agent reports identity attributes during registration and heartbeat:

| Field | Description | Example |
|---|---|---|
| `agent_id` | Unique identifier (UUID) | `a3f1c9e2-7b4d-4e8a-9f12-3c5d6e7f8a9b` |
| `hostname` | Machine hostname | `web-prod-01` |
| `os` | Operating system | `windows`, `linux`, `darwin` |
| `arch` | CPU architecture | `x86_64`, `aarch64` |
| `os_version` | OS version string | `Windows 11 Pro 10.0.26200` |
| `agent_version` | Running agent binary version | `0.9.3` |

These fields are used by the [Scope Engine](scope-engine.md) for device targeting and by [Management Groups](management-groups.md) for access scoping.

---

## Viewing Connected Agents

### Dashboard

The **Devices** page shows all enrolled agents with their status (online/offline), OS, hostname, and last heartbeat time. Click any agent row to see its detail page with tags, group membership, and recent activity.

### REST API

**List all agents (legacy endpoint):**

This endpoint does not require authentication. It returns only currently connected agents (those with an active gRPC session).

```bash
curl -s http://localhost:8080/api/agents
```

Response:

```json
[
  {
    "agent_id": "a3f1c9e2-7b4d-4e8a-9f12-3c5d6e7f8a9b",
    "hostname": "web-prod-01",
    "os": "windows",
    "arch": "x86_64",
    "agent_version": "0.9.3"
  }
]
```

Note: This legacy endpoint does not include `status` or `last_heartbeat` fields. It only lists agents with active gRPC streams (implicitly online).

---

## Agent Heartbeat and Session Keepalive

After registration, agents maintain a persistent gRPC bidirectional stream with the server. The heartbeat serves three purposes:

1. **Liveness** -- the server marks agents as offline if no heartbeat is received within the configured timeout.
2. **Metadata refresh** -- agents report updated OS version, IP address, and plugin inventory on each heartbeat.
3. **Command delivery** -- the server uses the open stream to push `CommandRequest` messages to the agent without polling.

Heartbeat interval is configured agent-side (default: 30 seconds). The server's offline threshold is typically 3x the heartbeat interval.

---

## Agent CLI Flags

The full set of agent command-line flags:

| Flag | Description | Default |
|---|---|---|
| `--server` | Server address (`host:port`) | `localhost:50051` |
| `--enrollment-token` | Pre-shared token for Tier 2 enrollment | (none) |
| `--tls-ca` | Path to CA certificate PEM file | (auto-discover) |
| `--tls-cert` | Path to client certificate PEM file | (auto-discover) |
| `--tls-key` | Path to client private key PEM file | (auto-discover) |
| `--cert-store` | Windows certificate store name (e.g. `MY`) | (none) |
| `--cert-subject` | Subject CN match for cert store lookup | (none) |
| `--cert-thumbprint` | SHA-1 thumbprint for cert store lookup (hex) | (none) |
| `--plugin-dir` | Directory containing plugin shared libraries | `./plugins` |
| `--log-level` | Logging verbosity (`trace`, `debug`, `info`, `warn`, `error`) | `info` |

### Windows Certificate Store Integration

On Windows, agents can read their mTLS client certificate and private key directly from the Windows certificate store instead of PEM files on disk. This uses CryptoAPI/CNG (`CertOpenStore`, `CertFindCertificateInStore`, `NCryptExportKey`) and searches the Local Machine store first, falling back to Current User.

**By subject name:**

```bash
yuzu-agent --server server.example.com:50051 \
           --cert-store MY \
           --cert-subject "yuzu-agent"
```

**By thumbprint:**

```bash
yuzu-agent --server server.example.com:50051 \
           --cert-store MY \
           --cert-thumbprint "AB12CD34EF56..."
```

The agent exports the full certificate chain (leaf + intermediates) as PEM in memory. Either `--cert-subject` or `--cert-thumbprint` is required when `--cert-store` is specified.

---

## Over-the-Air Agent Updates

Administrators can upload new agent binaries to the server and promote them to production. Connected agents will download and apply the update automatically.

### Upload a New Binary

**Dashboard:** Navigate to **Settings > Agent Updates** and use the upload form.

**API:**

The upload endpoint accepts multipart form data. The version is derived automatically from the uploaded filename (with common extensions like `.tar.gz`, `.zip`, `.exe`, `.msi`, `.bin` stripped).

```bash
curl -s -X POST http://localhost:8080/api/settings/updates/upload \
  -b "$COOKIE" \
  -F "file=@yuzu-agent-0.9.4-linux-x64.tar.gz" \
  -F "platform=linux" \
  -F "arch=x86_64" \
  -F "rollout_pct=100" \
  -F "mandatory=true"
```

| Field | Required | Description |
|---|---|---|
| `file` | Yes | The agent binary to upload |
| `platform` | Yes | Target platform (`linux`, `windows`, `darwin`) |
| `arch` | Yes | Target architecture (`x86_64`, `aarch64`) |
| `rollout_pct` | No | Rollout percentage, 0--100 (default: `100`) |
| `mandatory` | No | Whether agents must apply this update (`true`/`false`, default: `false`) |

### View Available Updates

```bash
curl -s http://localhost:8080/fragments/settings/updates -b "$COOKIE"
```

### Set Rollout Percentage

The rollout endpoint controls what percentage of eligible agents receive a given update. Set to `100` for full deployment, or use a lower value for staged rollouts.

```bash
curl -s -X POST http://localhost:8080/api/settings/updates/linux/x86_64/0.9.4/rollout \
  -b "$COOKIE" \
  -d "rollout_pct=100"
```

To do a staged rollout, set a lower percentage first and increase it over time:

```bash
# Start with 10% of agents
curl -s -X POST http://localhost:8080/api/settings/updates/linux/x86_64/0.9.4/rollout \
  -b "$COOKIE" \
  -d "rollout_pct=10"
```

### Remove an Uploaded Binary

```bash
curl -s -X DELETE http://localhost:8080/api/settings/updates/linux/x86_64/0.9.4 \
  -b "$COOKIE"
```

---

## Settings Page Route Reference

Most enrollment and device management operations are performed through the HTMX dashboard. The endpoints below are designed for the dashboard (accepting form-encoded parameters and returning HTML fragments), with the exception of the batch token endpoint which accepts and returns JSON.

### HTMX Fragments (Server-Rendered HTML)

| Route | Description |
|---|---|
| `GET /fragments/settings/pending` | Pending agents queue |
| `GET /fragments/settings/tokens` | Enrollment tokens list |
| `GET /fragments/settings/auto-approve` | Auto-approval policies |
| `GET /fragments/settings/updates` | OTA agent updates |

### Action Endpoints

Unless noted, these endpoints accept form-encoded parameters and return HTML fragments (designed for HTMX consumption).

| Method | Route | Description | Format |
|---|---|---|---|
| `GET` | `/api/agents` | List all connected agents (no auth required) | JSON |
| `POST` | `/api/settings/pending-agents/{agent_id}/approve` | Approve a pending agent | HTMX |
| `POST` | `/api/settings/pending-agents/{agent_id}/deny` | Deny a pending agent | HTMX |
| `DELETE` | `/api/settings/pending-agents/{agent_id}` | Remove from pending queue | HTMX |
| `POST` | `/api/settings/enrollment-tokens` | Generate an enrollment token (form-encoded) | HTMX |
| `POST` | `/api/settings/enrollment-tokens/batch` | Generate tokens in batch (JSON in, JSON out) | JSON |
| `DELETE` | `/api/settings/enrollment-tokens/{token_id}` | Revoke a token | HTMX |
| `POST` | `/api/settings/auto-approve` | Add a rule (form: `type`, `value`, `label`) | HTMX |
| `POST` | `/api/settings/auto-approve/mode` | Set match mode (form: `mode=any\|all`) | HTMX |
| `POST` | `/api/settings/auto-approve/{index}/toggle` | Enable/disable a rule | HTMX |
| `DELETE` | `/api/settings/auto-approve/{index}` | Delete a rule | HTMX |
| `POST` | `/api/settings/updates/upload` | Upload an agent binary (multipart) | HTMX |
| `POST` | `/api/settings/updates/{platform}/{arch}/{version}/rollout` | Set rollout percentage (form: `rollout_pct`) | HTMX |
| `DELETE` | `/api/settings/updates/{platform}/{arch}/{version}` | Remove an uploaded binary | HTMX |

---

## Planned Features

### Agent Deployment Jobs (Phase 7.7)

_Not yet implemented._ Server-initiated installer push to deploy the Yuzu agent to new endpoints without manual installation. Will support WinRM, SSH, and GPO-based deployment strategies.

### Device Discovery (Phase 7.18)

_Not yet implemented._ Automated discovery of unmanaged devices via subnet scanning, Active Directory computer object import, and DHCP lease table import. Discovered devices will appear in a "discovered but unenrolled" list with one-click deployment.

### Custom Device Properties (Phase 7.6)

_Not yet implemented._ Administrator-defined key/value properties attached to devices beyond the built-in identity fields and structured tags. Will support typed properties (string, integer, date) with validation rules and scope engine integration.
