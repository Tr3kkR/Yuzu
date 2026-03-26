# Security Hardening Guide

This guide covers hardening Yuzu for production enterprise deployments.

## mTLS Setup

All agent-to-server communication should use mutual TLS. Create a private CA, server certificate, and per-agent certificates.

### 1. Create Certificate Authority

```bash
# Generate CA key and certificate (valid 10 years)
openssl genrsa -out ca.key 4096
openssl req -new -x509 -key ca.key -sha256 -days 3650 \
  -out ca.crt -subj "/CN=Yuzu CA/O=Your Org"
```

### 2. Server Certificate

```bash
# Generate server key and CSR
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
  -subj "/CN=yuzu-server/O=Your Org"

# Sign with CA (include SAN for gRPC)
cat > server-ext.cnf <<EOF
subjectAltName = DNS:yuzu-server,DNS:localhost,IP:127.0.0.1
EOF
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365 -sha256 \
  -extfile server-ext.cnf
```

### 3. Agent Certificates

```bash
# Per-agent certificate (CN should match agent ID)
AGENT_ID="agent-001"
openssl genrsa -out "${AGENT_ID}.key" 2048
openssl req -new -key "${AGENT_ID}.key" -out "${AGENT_ID}.csr" \
  -subj "/CN=${AGENT_ID}/O=Your Org"
openssl x509 -req -in "${AGENT_ID}.csr" -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out "${AGENT_ID}.crt" -days 365 -sha256
```

### 4. Configure

```bash
# Server
yuzu-server --cert server.crt --key server.key --ca-cert ca.crt

# Agent
yuzu-agent --client-cert agent-001.crt --client-key agent-001.key --ca-cert ca.crt
```

On Windows, agents can use the certificate store instead of PEM files:
```bash
yuzu-agent --cert-store MY --cert-subject "agent-001"
```

## Firewall Rules

| Port | Protocol | Direction | Purpose | Restrict To |
|------|----------|-----------|---------|-------------|
| 8080 | TCP | Inbound | Web dashboard + REST API | Admin network |
| 8443 | TCP | Inbound | HTTPS dashboard | Admin network |
| 50051 | TCP | Inbound | Agent gRPC | Agent network |
| 50052 | TCP | Inbound | Management gRPC | Admin network |
| 50055 | TCP | Inbound | Gateway upstream | Gateway hosts only |
| 9568 | TCP | Inbound | Gateway Prometheus | Monitoring network |

**Recommendations:**
- Bind the web dashboard to an internal interface: `--web-address 10.0.0.1`
- Never expose gRPC ports (50051/50052) to the internet
- Use a reverse proxy (nginx, Caddy) for TLS termination on the dashboard

## Least-Privilege Deployment

The systemd service units include security hardening:

```ini
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadOnlyDirectories=/
ReadWritePaths=/var/lib/yuzu /var/log/yuzu /etc/yuzu
```

Run each component under its own system user:
- `yuzu` — server process
- `yuzu-agent` — agent process
- `yuzu-gw` — gateway process

## Secret Management

**Never pass secrets via CLI flags** — they are visible in `ps aux`.

Use environment variables instead:

```bash
# systemd EnvironmentFile
echo 'YUZU_OIDC_CLIENT_SECRET=your-secret' > /etc/yuzu/secrets.env
chmod 600 /etc/yuzu/secrets.env

# Add to systemd unit
# [Service]
# EnvironmentFile=/etc/yuzu/secrets.env
```

Sensitive environment variables:
- `YUZU_OIDC_CLIENT_SECRET` — OIDC client secret
- `YUZU_CLICKHOUSE_PASSWORD` — ClickHouse password
- `YUZU_NVD_API_KEY` — NVD API key

For HashiCorp Vault integration, use a wrapper script that fetches secrets at startup:
```bash
#!/bin/bash
export YUZU_OIDC_CLIENT_SECRET=$(vault kv get -field=secret secret/yuzu/oidc)
exec /usr/local/bin/yuzu-server "$@"
```

## Rate Limiting

Configure API and login rate limits:

```bash
yuzu-server --rate-limit 100 --login-rate-limit 10
```

- `--rate-limit` — Maximum API requests per second per IP (default: 100)
- `--login-rate-limit` — Maximum login attempts per second per IP (default: 10)

Clients exceeding the limit receive `429 Too Many Requests` with a `Retry-After: 1` header.

For additional protection, deploy a reverse proxy with rate limiting:
```nginx
limit_req_zone $binary_remote_addr zone=yuzu_api:10m rate=50r/s;
location /api/ {
    limit_req zone=yuzu_api burst=20 nodelay;
    proxy_pass http://127.0.0.1:8080;
}
```

## Audit Log Forwarding

Configure webhooks to forward audit events to your SIEM:

```bash
# Create a webhook subscription for audit events
curl -X POST http://localhost:8080/api/v1/webhooks \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"url":"https://splunk-hec.example.com:8088/services/collector",
       "events":["audit.*"],
       "headers":{"Authorization":"Splunk YOUR-HEC-TOKEN"}}'
```

Audit events include: `timestamp`, `principal`, `action`, `target_type`, `target_id`, `detail`, `source_ip`.

## Database Security

- SQLite databases use WAL mode for concurrent access
- The TAR database uses `PRAGMA secure_delete = ON` to zero deleted pages
- Protect database files with filesystem permissions: `chmod 600 *.db`
- For encryption at rest, use filesystem-level encryption:
  - Linux: LUKS on the data partition
  - Windows: BitLocker on the data volume
  - Docker: encrypted volumes

## Plugin Allowlist

In production, verify plugin binaries against a SHA-256 allowlist to prevent loading of tampered or unauthorized code:

```bash
# Generate allowlist from verified builds
sha256sum /opt/yuzu/plugins/*.so > /etc/yuzu/plugin-allowlist.txt
chmod 600 /etc/yuzu/plugin-allowlist.txt

# Start agent with allowlist enforcement
yuzu-agent --plugin-allowlist /etc/yuzu/plugin-allowlist.txt
```

Plugins not listed or with a hash mismatch are rejected before any code executes. See [Plugin Allowlist](agent-plugins.md#plugin-allowlist) for details.

## Command Replay Protection

The agent tracks recently-executed `command_id` values per connection and rejects duplicates. This prevents replay attacks where a captured command is retransmitted to re-execute actions.

- The dedup set is reset on each reconnect (new Subscribe stream).
- Uses a double-buffer strategy with 5,000 entries per buffer (10,000 total). When the current buffer fills, the previous buffer is discarded and the current becomes the previous — recently-seen IDs are always protected.
- Replayed commands receive a `REJECTED` response with reason `"command replay rejected: duplicate command_id"`.
- The server generates unique `command_id` values per invocation, so legitimate commands are never affected.

No additional configuration is required — replay protection is always active.

## Device Quarantine

The `quarantine` agent plugin isolates compromised or suspicious devices by blocking all network traffic except the Yuzu server connection. This allows continued management while preventing lateral movement.

### Quarantining a Device

Execute the `quarantine` action from the `quarantine` plugin:

```bash
curl -s -X POST http://localhost:8080/api/v1/executions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "definition_id": "quarantine.quarantine",
    "scope": "agent_id == \"compromised-agent-id\""
  }'
```

The plugin blocks all network traffic except communication with the Yuzu server using platform-native firewalling: `netsh` on Windows, `iptables`/`nftables` on Linux, and `pfctl` on macOS.

### Checking Quarantine Status

```bash
# Execute quarantine.status to check if an agent is isolated
curl -s -X POST http://localhost:8080/api/v1/executions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "definition_id": "quarantine.status",
    "scope": "agent_id == \"agent-id\""
  }'
```

### Releasing a Device

Execute the `unquarantine` action to remove quarantine rules and restore normal network access. You can also use `whitelist` to add exceptions (IP or CIDR range) to the quarantine rules before releasing.

## IOC Checking

The `ioc` plugin supports Indicator of Compromise checking for threat hunting. Execute the `check` action with one or more indicator types to scan an endpoint for signs of compromise.

### Supported Indicator Types

| Type | Description |
|---|---|
| `ip_addresses` | Check active TCP/UDP connections against known-bad IPs |
| `domains` | Check DNS cache and hosts file against known-bad domains |
| `file_hashes` | Scan specified paths for files matching known-bad SHA-256 hashes |
| `file_paths` | Check for the existence of specific suspicious file paths |
| `ports` | Check for processes listening on suspicious ports |

### Running an IOC Check

```bash
curl -s -X POST http://localhost:8080/api/v1/executions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "definition_id": "ioc.check",
    "parameters": {
      "ip_addresses": ["203.0.113.50", "198.51.100.23"],
      "file_hashes": ["e3b0c44298fc1c149afbf4c8996fb924..."],
      "ports": ["4444", "5555"]
    },
    "scope": "tag:env == \"production\""
  }'
```

IOC checks run locally on each endpoint, querying active connections (Windows: `GetExtendedTcpTable`, Linux: `/proc/net/tcp`, macOS: `lsof`), DNS cache, and filesystem state. Results include matched indicators and the source of the match.

## Certificate Inventory

The `certificates` plugin enumerates certificates in system stores for compliance auditing, expiration monitoring, and security review.

### Listing Certificates

Execute the `certificates.list` action to get all certificates with subject, issuer, thumbprint, and expiry date. Use `certificates.details` with a thumbprint parameter for full certificate details including key usage, serial number, and chain information.

### Certificate Deletion

Execute the `certificates.delete` action with a thumbprint parameter to remove a certificate from the system store. This is useful for revoking compromised certificates or cleaning up expired entries.

Platform implementations:
- **Windows:** CryptoAPI (`CertOpenStore`, `CertEnumCertificatesInStore`)
- **Linux:** PEM files in `/etc/ssl/certs/`
- **macOS:** `security find-certificate` CLI

## OIDC Hardening

When using OIDC/Entra ID:
- Set `--oidc-admin-group` to restrict admin access to a specific group
- Use `--session-timeout` to limit session duration
- Configure the OIDC provider to require MFA
- Restrict the app registration to your tenant (single-tenant)
- Rotate the client secret regularly
