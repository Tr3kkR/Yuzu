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

## HTTP Security Response Headers

Yuzu sets six standard security response headers on every HTTP response from the server (dashboard, REST API, MCP, metrics, health probes, error pages). No configuration is required to enable them.

| Header | Value | Purpose |
|---|---|---|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'[; upgrade-insecure-requests]` | Restricts which sources can be loaded by the dashboard. Defends against XSS, clickjacking, and content injection. `upgrade-insecure-requests` is appended only when HTTPS is enabled. The CSP is fully `'self'`-only — no external CDN allowance — because the HTMX runtime is embedded in the server binary and served from `/static/htmx.js` (see below). |
| `X-Frame-Options` | `DENY` | Blocks the dashboard from being embedded in any `<iframe>`. Defense-in-depth alongside CSP `frame-ancestors 'none'`. |
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-type sniffing attacks. Browsers must respect the declared `Content-Type`. |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Sends only the origin (not the full URL with query strings) when navigating cross-origin. Defends against URL-based secret leakage to third-party sites. |
| `Permissions-Policy` | `accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(self), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), usb=(), web-share=(), xr-spatial-tracking=()` | Deny-all baseline for browser feature APIs the dashboard never uses. `fullscreen=(self)` is permitted for same-origin chart libraries. |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | (HTTPS only) Tells browsers to always use HTTPS for this origin for one year. Defends against TLS downgrade attacks. Only sent when `https_enabled` is true, per RFC 6797 §7.2. |

At server startup, the resolved header bundle is logged at INFO level so operators can confirm activation:

```
[info] Security headers active: CSP=277 bytes, HSTS=on, Referrer-Policy="strict-origin-when-cross-origin", Permissions-Policy=315 bytes
```

### Why `'unsafe-inline'` for scripts and styles

The HTMX dashboard uses inline `<script>` blocks, inline `onclick=` event handlers, and inline `<style>` blocks. Tightening to a strict nonce-based CSP would require refactoring all event handlers to `addEventListener` and threading per-request nonces through every HTML render path. This work is tracked separately. The current CSP is restrictive enough to block external script injection while keeping the dashboard functional.

### Embedded HTMX runtime — no external CDN

The HTMX 2.0.4 runtime and the `htmx-ext-sse` extension are compiled into the server binary as static C++ string literals (`server/core/src/static_js_bundle.cpp`) and served from same-origin paths:

- `GET /static/htmx.js` — HTMX core (~51 KB)
- `GET /static/sse.js` — Server-Sent Events extension (~9 KB)

Both responses set `Cache-Control: public, max-age=86400`. The dashboard's `<head>` references them as `<script src="/static/htmx.js">` and `<script src="/static/sse.js">`, so the CSP `script-src` only needs `'self'` — there is no external CDN allowance and **no internet connectivity required** for the dashboard to load. This makes the server suitable for air-gapped deployments out of the box.

If you need to update HTMX, replace the payloads in `server/core/src/static_js_bundle.cpp` and rebuild. The file is split into 14 KB chunks because MSVC's raw string literal limit is 16380 bytes (error C2026) — keep that constraint in mind when re-vendoring.

### Extending CSP for customer environments

Some deployments need to reach additional origins from the dashboard — a customer-hosted CDN, a monitoring beacon (e.g. New Relic, Sentry), an analytics endpoint, or a custom favicon host. Use `--csp-extra-sources` to append additional source-list entries to the `script-src`, `style-src`, `connect-src`, and `img-src` directives:

```bash
yuzu-server \
  --csp-extra-sources "https://cdn.example.com https://beacon.example.com"
```

The argument is a single space-separated string. Each entry is appended to all four directives. To set this via environment variable:

```bash
export YUZU_CSP_EXTRA_SOURCES="https://cdn.example.com https://beacon.example.com"
yuzu-server
```

#### Validation

The flag is validated at startup. The server will refuse to start with a clear error message if the value contains:

- Control bytes (0x00–0x1F except SP/HTAB, plus 0x7F) — these would cause cpp-httplib's header validation to silently drop the entire CSP header.
- Semicolons (`;`) or commas (`,`) — these would inject additional CSP directives.
- Quoted CSP keywords other than the safe allow-list `'self'`, `'none'`, or `'sha256-...'`/`'sha384-...'`/`'sha512-...'`/`'nonce-...'` hash and nonce expressions. Notably `'unsafe-eval'` and `'strict-dynamic'` are **rejected** — operators who genuinely need them must extend the server build and accept the security trade-off.
- Unquoted tokens with stray single quotes (malformed sources).

For example:

```bash
# Rejected at startup with: csp_extra_sources contains forbidden control byte 0x0d at position 18
yuzu-server --csp-extra-sources $'https://ok.example\rInjected'

# Rejected at startup with: csp_extra_sources token "'unsafe-eval'" is not a valid CSP source expression
yuzu-server --csp-extra-sources "'unsafe-eval'"
```

### Behind a reverse proxy

If you deploy Yuzu behind a reverse proxy (nginx, HAProxy, Caddy, Cloudflare) that **also** sets a `Content-Security-Policy` header, the browser will see two CSP headers and apply the **intersection** of both policies — the strictest combined policy wins. This can be confusing when debugging "why is my extra source blocked?" — check both layers. If your proxy sets its own CSP, either:

- Disable the proxy's CSP and let Yuzu's CSP apply, or
- Disable Yuzu's CSP via the proxy's `proxy_hide_header Content-Security-Policy;` directive, or
- Match both policies so the intersection allows what you need.

The same applies to all other security headers — if both layers set them, browsers honor the strictest.

### Verifying headers

Run the dashboard and inspect the response headers in your browser's developer tools (Network tab → click any request → Response Headers), or with `curl`:

```bash
curl -sk -i https://yuzu.example.com:8443/livez \
  | grep -E '^(Content-Security|X-Frame|X-Content|Referrer-Policy|Permissions-Policy|Strict-Transport)'
```

You should see all six headers present on HTTPS responses (and the first five on HTTP responses).

### Bandwidth note

The six security headers add roughly 700–900 bytes per HTTP response depending on whether `--csp-extra-sources` is set. For a fleet that pulls heavily from the REST API (e.g. an analytics pipeline polling `/api/v1/responses` thousands of times per hour), this is a non-trivial increase in egress on metered connections. Plan capacity accordingly. The headers cannot be disabled.

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
