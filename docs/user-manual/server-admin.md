# Server Administration Guide

This document covers Yuzu server deployment, configuration, and ongoing administration. It is intended for operators who install, configure, and maintain the Yuzu server.

---

## Table of Contents

1. [Server CLI Flags](#server-cli-flags)
2. [Configuration Files](#configuration-files)
3. [First-Run Setup](#first-run-setup)
4. [Settings Page](#settings-page)
5. [TLS Configuration](#tls-configuration)
6. [User Management](#user-management)
7. [Agent Enrollment](#agent-enrollment)
8. [OTA Agent Updates](#ota-agent-updates)
9. [RBAC Management](#rbac-management)
10. [Tag Compliance](#tag-compliance)
11. [OIDC SSO Configuration](#oidc-sso-configuration)
12. [Data Storage and Encryption](#data-storage-and-encryption)
13. [Retention Settings](#retention-settings)
14. [Settings API Reference](#settings-api-reference)
15. [Deployment](#deployment)
16. [Windows Service Installation](#windows-service-installation)
17. [Planned Features](#planned-features)

---

## Server CLI Flags

The Yuzu server binary accepts the following command-line flags. All flags are optional; defaults are shown in the table.

| Flag | Default | Description |
|---|---|---|
| `--config` | *(auto)* | Path to `yuzu-server.cfg`. If omitted, uses the default location next to the binary. |
| `--data-dir` | *(config dir)* | Directory for SQLite databases and runtime state files (enrollment tokens, pending agents). Defaults to the parent directory of `--config`. Use this in containerized deployments where the config file is on a read-only mount but databases need a writable volume. The path is resolved to its canonical form at startup (symlinks are followed). Env: `YUZU_DATA_DIR`. |
| `--web-port` | `8080` | HTTP listen port for the dashboard and REST API. |
| `--web-address` | `127.0.0.1` | Web UI bind address. |
| `--no-https` | off | Disable HTTPS (insecure, for development only). HTTPS is **enabled by default**; provide `--https-cert` and `--https-key`, or pass `--no-https` to disable. Env: `YUZU_NO_HTTPS`. |
| `--https-port` | `8443` | HTTPS listen port. |
| `--https-cert` | *(none)* | Path to PEM-encoded TLS certificate file. Required unless `--no-https` is set. |
| `--https-key` | *(none)* | Path to PEM-encoded TLS private key file. Required unless `--no-https` is set. The file must not be world-readable (Unix: `chmod 600`). |
| `--no-https-redirect` | off | When HTTPS is enabled, do not redirect HTTP requests to HTTPS. By default, HTTP requests are redirected. |
| `--no-cert-reload` | off | Disable automatic certificate hot-reload. By default, the server polls cert/key files and hot-swaps the SSL context when they change. Env: `YUZU_NO_CERT_RELOAD`. |
| `--cert-reload-interval` | `60` | Certificate reload polling interval in seconds. Minimum effective interval is 10 seconds. Env: `YUZU_CERT_RELOAD_INTERVAL`. |
| `--metrics-no-auth` | off | Allow unauthenticated `/metrics` access from any IP. By default, remote clients must authenticate; localhost access is always unauthenticated. **Warning:** enabling this exposes fleet composition data (OS, architecture, version counts) to any network client. See [Metrics Security](metrics.md#security-considerations). Env: `YUZU_METRICS_NO_AUTH`. |
| `--csp-extra-sources` | *(none)* | Extra Content-Security-Policy source-list entries appended to `script-src`, `style-src`, `connect-src`, and `img-src`. Space-separated string of host/scheme expressions or whitelisted CSP keywords (`'self'`, `'none'`, `'sha256-...'`, `'sha384-...'`, `'sha512-...'`, `'nonce-...'`). The server **refuses to start** if the value contains control bytes, semicolons, commas, or unsafe CSP keywords like `'unsafe-eval'`. Use to whitelist customer CDNs, monitoring beacons, or analytics endpoints. See [HTTP Security Response Headers](security-hardening.md#http-security-response-headers). Env: `YUZU_CSP_EXTRA_SOURCES`. |
| `--oidc-issuer` | *(none)* | OIDC identity provider issuer URL (e.g., `https://login.microsoftonline.com/{tenant}/v2.0`). |
| `--oidc-client-id` | *(none)* | OIDC application (client) ID. |
| `--oidc-client-secret` | *(none)* | OIDC client secret. |
| `--oidc-redirect-uri` | *(auto)* | OIDC redirect URI. If omitted, auto-computed from the web address and port. Must match the registered redirect in your identity provider. |
| `--oidc-admin-group` | *(none)* | Entra ID group object ID that maps to the admin role. Users in this group are granted admin access on OIDC login. |
| `--oidc-skip-tls-verify` | off | Disable TLS certificate verification for OIDC endpoints. **Insecure — dev only.** Env: `YUZU_OIDC_SKIP_TLS_VERIFY`. |
| `--mcp-disable` | off | Disable the MCP (Model Context Protocol) endpoint entirely. When set, all requests to `/mcp/v1/` are rejected with a JSON-RPC error. Use this in air-gapped or high-security environments where AI integration is not desired. Env: `YUZU_MCP_DISABLE`. |
| `--mcp-read-only` | off | Restrict MCP to read-only tools only. Write and execute operations (Phase 2) are rejected even if the MCP token's tier would normally allow them. Env: `YUZU_MCP_READ_ONLY`. |

### Example

```bash
# HTTP only (development — HTTPS is on by default, must opt out)
./yuzu-server --no-https --web-port 8080

# HTTPS with certificate files (default mode)
./yuzu-server --https-cert /etc/yuzu/server.crt \
  --https-key /etc/yuzu/server.key

# HTTPS with custom cert reload interval (30 seconds)
./yuzu-server --https-cert /etc/yuzu/server.crt \
  --https-key /etc/yuzu/server.key \
  --cert-reload-interval 30

# HTTPS with cert reload disabled
./yuzu-server --https-cert /etc/yuzu/server.crt \
  --https-key /etc/yuzu/server.key \
  --no-cert-reload

# MCP disabled (air-gapped environment)
./yuzu-server --https-cert /etc/yuzu/server.crt \
  --https-key /etc/yuzu/server.key \
  --mcp-disable

# MCP read-only mode (AI can query but not execute)
./yuzu-server --https-cert /etc/yuzu/server.crt \
  --https-key /etc/yuzu/server.key \
  --mcp-read-only

# HTTPS with OIDC SSO
./yuzu-server --https-cert /etc/yuzu/server.crt \
  --https-key /etc/yuzu/server.key \
  --oidc-issuer "https://login.microsoftonline.com/YOUR_TENANT/v2.0" \
  --oidc-client-id "YOUR_CLIENT_ID" \
  --oidc-client-secret "YOUR_SECRET" \
  --oidc-redirect-uri "https://yuzu.example.com:8443/auth/callback"
```

---

## Configuration Files

The server stores its configuration in files located in the **same directory as the `yuzu-server` binary**. These files are created automatically during first-run setup and updated through the Settings page.

| File | Purpose |
|---|---|
| `yuzu-server.cfg` | User credentials. Passwords are stored as PBKDF2 hashes with per-user salts. Never contains plaintext passwords. |
| `enrollment-tokens.cfg` | Enrollment tokens for Tier 2 agent enrollment. Each token has an ID, creation time, expiry, and remaining use count. |
| `pending-agents.cfg` | Queue of agents awaiting manual approval (Tier 1 enrollment). Contains agent ID, hostname, IP, and registration timestamp. |

> **Backup recommendation:** Back up all three `.cfg` files regularly. Losing `yuzu-server.cfg` requires re-running first-run setup. Losing `enrollment-tokens.cfg` invalidates all issued tokens. Losing `pending-agents.cfg` loses the pending approval queue (agents will re-register on next heartbeat).

> **File permissions (Unix):** On Unix systems, the server automatically sets file permissions to `0600` (owner-only read/write) on `yuzu-server.cfg`, `enrollment-tokens.cfg`, and `pending-agents.cfg` after every write. This protects credential hashes and enrollment tokens from being read by other users on the system. No manual `chmod` is required for these files.

---

## First-Run Setup

When the server starts for the first time and no `yuzu-server.cfg` exists, it enters **interactive setup mode** on the terminal. The setup prompts for:

1. **Admin username** -- the initial administrator account.
2. **Admin password** -- entered twice for confirmation. Stored as a PBKDF2 hash.

After setup completes, the server writes `yuzu-server.cfg` and starts normally. Subsequent restarts skip the setup prompt.

> **Headless deployment:** For automated or containerized deployments, pre-create `yuzu-server.cfg` with PBKDF2-hashed password entries before starting the server for the first time. A sample config with default credentials is provided below for quick evaluation.

### Default Credentials (Evaluation Only)

For Docker, automated, and quick-start deployments, the following `yuzu-server.cfg` ships with pre-hashed credentials so the server starts without interactive setup:

| Username | Password | Role |
|---|---|---|
| `admin` | `administrator` | Admin (full access) |
| `user` | `useroperator` | User (read-only) |

> **WARNING: Change these credentials immediately after first login.** These defaults are published in documentation and are not suitable for production. Use the Settings page (User Management) to change passwords and create new accounts. For enterprise deployments, integrate OIDC SSO and disable local accounts.

---

## Settings Page

The Settings page is the primary administrative interface. It is accessible only to users with the **admin** role and is rendered server-side using HTMX.

**URL:** `/settings` (redirects to `/login` if unauthenticated or non-admin)

The Settings page is organized into sections, each loaded as an HTMX fragment. Changes take effect immediately without a server restart unless otherwise noted.

### Sections

| Section | Fragment Route | Description |
|---|---|---|
| TLS Configuration | `/fragments/settings/tls` | Enable/disable HTTPS, upload PEM certificate and key files. |
| User Management | `/fragments/settings/users` | Create and delete local user accounts. |
| Enrollment Tokens | `/fragments/settings/tokens` | Generate and revoke tokens for Tier 2 agent enrollment. |
| Pending Agents | `/fragments/settings/pending` | Approve or deny agents waiting in the Tier 1 approval queue. |
| Auto-Approval Policies | `/fragments/settings/auto-approve` | Define rules for automatically approving agents based on criteria (hostname pattern, IP range, etc.). |
| API Tokens | `/fragments/settings/api-tokens` | Create and revoke bearer tokens for REST API automation. |
| OTA Updates | `/fragments/settings/updates` | Upload agent binaries, view available versions, promote a version to production. |
| Tag Compliance | `/fragments/settings/tag-compliance` | View compliance summary across the fleet based on tag-driven policies. |
| RBAC Management | *(planned -- no fragment yet)* | Enable or disable RBAC enforcement, create and manage roles. RBAC is enforced via `RbacStore` and the `/api/v1/rbac/*` REST API, but has no Settings page fragment yet. |
| OIDC SSO / Directory | `/fragments/settings/directory` | Configure OIDC single sign-on (issuer, client ID, secret, admin group). Editable form with "Test Connection" button. Changes persisted to runtime config and survive restart. |

---

## TLS Configuration

TLS can be configured at startup via CLI flags or at runtime through the Settings page.

### Via CLI Flags

HTTPS is enabled by default. Pass `--https-cert` and `--https-key` at server startup. Use `--no-https` for development without TLS. See [Server CLI Flags](#server-cli-flags).

### Via Settings Page

1. Navigate to **Settings > TLS Configuration**.
2. Toggle **Enable HTTPS**.
3. Upload PEM-encoded certificate and private key files using the **Upload PEM** button, or paste PEM content directly using the **Paste PEM** button.
4. The server begins serving HTTPS on the configured port. By default, HTTP requests are redirected to HTTPS.

### Certificate Requirements

- Format: PEM-encoded.
- The certificate file may contain the full chain (leaf + intermediates).
- The private key must not be password-protected.
- On Unix, the private key file must not be readable by group or others. The server will refuse to start if permissions are too open. Fix with: `chmod 600 /path/to/key.pem`.
- For production, use certificates signed by a trusted CA. Self-signed certificates work but require agents to trust the CA.

### Certificate Hot-Reload

The server automatically detects when HTTPS certificate or key files change on disk and hot-swaps the SSL context **without requiring a restart**. This enables zero-downtime certificate rotation, including automated renewal via ACME/certbot.

**How it works:**

1. The server polls the cert and key file modification times at a configurable interval (default: 60 seconds).
2. When a change is detected, the new files are validated:
   - PEM format is parseable
   - Certificate and private key match
   - Key file permissions are secure (Unix: not group/others-readable)
   - Files are not empty and not larger than 1 MB
3. If validation passes, the SSL context is updated atomically. New connections use the new certificate; existing connections are unaffected.
4. If validation fails, the current certificate is preserved and an error is logged.

**Configuration:**

| Flag | Default | Description |
|---|---|---|
| `--no-cert-reload` | off | Disable automatic hot-reload. Env: `YUZU_NO_CERT_RELOAD`. |
| `--cert-reload-interval` | `60` | Polling interval in seconds. Minimum: 10s. Env: `YUZU_CERT_RELOAD_INTERVAL`. |

**Best practice for atomic file replacement:**

```bash
# Write to temp files first, then move atomically
cp new-cert.pem /etc/yuzu/certs/server.crt.tmp
cp new-key.pem /etc/yuzu/certs/server.key.tmp
chmod 600 /etc/yuzu/certs/server.key.tmp
mv /etc/yuzu/certs/server.crt.tmp /etc/yuzu/certs/server.crt
mv /etc/yuzu/certs/server.key.tmp /etc/yuzu/certs/server.key
```

**Observability:**

- Log messages: `cert-reload: certificate hot-reloaded successfully` or `cert-reload: ... failed`
- Audit events: action `cert.reload` with result `success` or `failure`
- Metrics: `yuzu_server_cert_reloads_total` (counter), `yuzu_server_cert_reload_failures_total` (counter)

**Limitations:**

- **HTTPS only.** gRPC mTLS certificate hot-reload is not supported. Rotating gRPC certificates still requires a server restart.
- The server logs a warning at startup if gRPC TLS is enabled with cert reload: *"gRPC TLS certificate hot-reload is not yet supported."*

---

## User Management

Yuzu supports two built-in roles for local users:

| Role | Permissions |
|---|---|
| `admin` | Full access to all features, including Settings, user management, agent enrollment, and instruction execution. |
| `user` | Read-only access to the dashboard, agent list, and query results. Cannot modify settings or execute instructions. |

### Creating a User

1. Navigate to **Settings > User Management**.
2. Enter a username, password, and select a role.
3. Click **Create User**.

The password is hashed with PBKDF2 before storage. Plaintext passwords are never written to disk.

### Deleting a User

1. Navigate to **Settings > User Management**.
2. Click **Delete** next to the target user.
3. Confirm the deletion.

> **Note:** You cannot delete the last admin account. At least one admin must exist at all times.

---

## Agent Enrollment

Yuzu uses a tiered enrollment model. Each tier provides a different balance of security and convenience.

### Tier 1: Manual Approval

The default enrollment method. No pre-shared token is required.

1. The agent starts and sends a `RegisterRequest` to the server.
2. The server places the agent in the **pending queue**.
3. An admin reviews pending agents in **Settings > Pending Agents**.
4. The admin approves or denies each agent.
5. Approved agents complete registration on their next heartbeat.
6. Denied agents are removed from the queue. They can re-register if restarted.

### Tier 2: Pre-Shared Token

For automated or bulk deployment. Agents present a token at startup for instant enrollment.

**Server side:**
1. Navigate to **Settings > Enrollment Tokens**.
2. Click **Generate Token**.
3. Configure token properties:
   - **Expiry** -- time limit (e.g., 24 hours, 7 days).
   - **Max uses** -- how many agents can use this token (1 for single-device, unlimited for bulk).
4. Copy the generated token string.

**Agent side:**
```bash
./yuzu-agent --enrollment-token "TOKEN_STRING"
```

The agent passes the token in `RegisterRequest.enrollment_token`. If the token is valid and not expired or exhausted, the agent is enrolled immediately.

### Tier 3: Platform Trust (Planned)

Reserved protocol fields (`machine_certificate`, `attestation_signature`, `attestation_provider`) support future integration with:
- Windows certificate store (machine certificates)
- Azure Attestation
- Cloud instance identity documents (AWS, GCP, Azure)

### Auto-Approval Policies

For environments that need something between manual approval and pre-shared tokens, auto-approval policies can automatically approve agents that match defined criteria:

1. Navigate to **Settings > Auto-Approval Policies**.
2. Create a rule with conditions (e.g., hostname matches `prod-web-*`, source IP in `10.0.0.0/8`).
3. Agents matching any active policy are approved automatically at registration time.

---

## OTA Agent Updates

The server can distribute agent binary updates to enrolled endpoints.

### Uploading a New Version

1. Navigate to **Settings > OTA Updates**.
2. Click **Upload** and select the agent binary.
3. The server stores the binary and assigns a version identifier.

### Promoting to Production

1. In the OTA Updates list, locate the uploaded version.
2. Click **Promote** to mark it as the current production version.
3. Agents check for updates on their next heartbeat and download the new binary automatically.

### Managing Versions

- View all uploaded versions with their upload date, size, and promotion status.
- Delete old versions to reclaim storage.
- Only one version can be promoted (active) at a time.

---

## RBAC Management

Role-Based Access Control adds granular permissions beyond the built-in admin/user roles.

### Enabling RBAC

1. Navigate to **Settings > RBAC Management**.
2. Toggle **Enable RBAC**.
3. When RBAC is enabled, the system enforces fine-grained permissions based on assigned roles.

### Built-in vs. Custom Roles

| Aspect | Built-in Roles | Custom Roles (RBAC) |
|---|---|---|
| Granularity | Two roles: admin, user | Per-operation permissions on securable types |
| Assignment | Per-user | Per-principal (users, service accounts, API tokens) |
| Management groups | Not scoped | Permissions can be scoped to management groups |

### Creating a Role

1. Navigate to **Settings > RBAC Management**.
2. Click **Create Role**.
3. Name the role and assign permissions for each securable type and operation.

For the full RBAC model, see `docs/user-manual/rbac.md`.

---

## Tag Compliance

The Tag Compliance section provides a fleet-wide view of compliance based on tag-driven policies.

1. Navigate to **Settings > Tag Compliance**.
2. View the compliance summary showing:
   - Total devices, compliant count, non-compliant count.
   - Breakdown by tag category.
   - Devices missing required tags.

Tag compliance data is also available via the REST API (`GET /api/v1/tag-compliance`) for integration with external dashboards and reporting tools.

---

## OIDC SSO Configuration

Yuzu supports OpenID Connect (OIDC) for single sign-on with external identity providers such as Microsoft Entra ID (Azure AD), Okta, or any OIDC-compliant provider.

### Configuration

OIDC can be configured via CLI flags at startup or through the Settings page:

| Parameter | CLI Flag | Description |
|---|---|---|
| Issuer URL | `--oidc-issuer` | The OIDC discovery endpoint base URL. |
| Client ID | `--oidc-client-id` | Application (client) ID from your identity provider. |
| Client Secret | `--oidc-client-secret` | Client secret for the confidential client flow. |
| Redirect URI | `--oidc-redirect-uri` | Callback URL registered with the identity provider. Must point to the Yuzu server's `/auth/callback` path. |
| Admin Group | `--oidc-admin-group` | Entra ID group object ID that maps to the admin role. |
| Skip TLS Verify | `--oidc-skip-tls-verify` | Disable TLS cert verification for OIDC endpoints (insecure, dev only). Env: `YUZU_OIDC_SKIP_TLS_VERIFY`. |

### Identity Provider Setup

1. Register Yuzu as an application in your identity provider.
2. Set the redirect URI to `https://<yuzu-server>:<port>/auth/callback`.
3. Note the client ID and client secret.
4. Enter these values in the Yuzu Settings page or pass them as CLI flags.

### User Mapping

OIDC-authenticated users are mapped to Yuzu roles based on claims or group membership. The mapping configuration depends on your identity provider and is set in the OIDC section of the Settings page.

---

## Data Storage and Encryption

Yuzu stores persistent data in SQLite databases, including the response store, analytics event store, audit log, and RBAC store. By default, database files are created in the same directory as the `yuzu-server.cfg` config file. Use `--data-dir` to place databases in a separate writable directory (required for containerized deployments where the config file is on a read-only mount).

> **Important: SQLite databases are not encrypted at rest.** The `.db` files contain query results, audit logs, and agent metadata in plaintext on disk. Any user or process with read access to the filesystem can read this data.

### Protecting Data at Rest

Operators must use full-disk encryption to protect Yuzu data at rest:

| Platform | Recommended Solution | Notes |
|---|---|---|
| Linux | dm-crypt / LUKS | Encrypt the partition or volume where Yuzu data resides. Most distributions support LUKS during OS installation. |
| Windows | BitLocker | Enable BitLocker on the drive containing the Yuzu server directory. Requires TPM or startup key. |
| macOS | FileVault | Enable FileVault in System Settings. Encrypts the entire startup volume. |

For containerized deployments (Docker Compose), ensure the host volume backing `server-data` is on an encrypted filesystem.

> **Planned:** A future `--encrypt-db` option will add application-level SQLite encryption using SQLCipher, providing defense-in-depth independent of disk encryption. Track progress in the roadmap (Phase 7).

---

## Retention Settings

The server applies retention policies to stored data to manage disk usage. Retention values are set via CLI flags at startup.

| Data Type | CLI Flag | Default TTL | Description |
|---|---|---|---|
| Instruction responses | `--response-retention-days` | 90 days | Results from executed instructions. Older responses are purged on a daily schedule. |
| Audit log entries | `--audit-retention-days` | 365 days | Records of who did what, when, and on which devices. |

Reducing the TTL frees disk space; increasing it preserves history for compliance.

> **Note:** Retention settings are configured at server startup via CLI flags. There is no Settings page UI or runtime API for changing them yet. A runtime configuration API (Phase 7.3) will allow changing TTLs and other limits without restarting the server.

---

## Settings API Reference

All Settings page operations are backed by REST API routes. These can be called directly for automation.

### Authentication

All API routes require a valid session cookie (obtained via `POST /login`) or, when available, a bearer token. Admin-role sessions are required for all write operations.

### TLS

| Method | Route | Description |
|---|---|---|
| `GET` | `/fragments/settings/tls` | Render the TLS configuration fragment (HTMX). |
| `POST` | `/api/settings/tls` | Update TLS settings (enable/disable, port). |
| `POST` | `/api/settings/cert-upload` | Upload PEM certificate and key files (multipart form). |
| `POST` | `/api/settings/cert-paste` | Paste PEM certificate content (form-encoded). |

### OIDC / Directory

| Method | Route | Description |
|---|---|---|
| `GET` | `/fragments/settings/directory` | Render the OIDC/Directory configuration fragment (HTMX). |
| `POST` | `/api/settings/oidc` | Save OIDC/Entra ID configuration (form-encoded). Persisted to runtime config. |
| `POST` | `/api/settings/oidc/test` | Test OIDC discovery endpoint connectivity. |

### Users

| Method | Route | Description |
|---|---|---|
| `GET` | `/fragments/settings/users` | Render the user management fragment (HTMX). |
| `POST` | `/api/settings/users` | Create a new user. Body: `{ "username", "password", "role" }`. |
| `DELETE` | `/api/settings/users/{username}` | Delete a user by username. |

### Enrollment Tokens

| Method | Route | Description |
|---|---|---|
| `GET` | `/fragments/settings/tokens` | Render the enrollment tokens fragment (HTMX). |
| `POST` | `/api/settings/enrollment-tokens` | Generate a new enrollment token. Body: `{ "expiry", "max_uses" }`. |
| `POST` | `/api/settings/enrollment-tokens/batch` | Generate multiple tokens in one call. Body: `{ "label", "count", "max_uses", "ttl_hours" }`. |
| `DELETE` | `/api/settings/enrollment-tokens/{id}` | Revoke a token by ID. |

### Pending Agents

| Method | Route | Description |
|---|---|---|
| `GET` | `/fragments/settings/pending` | Render the pending agents fragment (HTMX). |
| `POST` | `/api/settings/pending-agents/{id}/approve` | Approve a pending agent. |
| `POST` | `/api/settings/pending-agents/{id}/deny` | Deny a pending agent. |
| `DELETE` | `/api/settings/pending-agents/{id}` | Remove a pending agent from the queue. |

### Auto-Approval Policies

| Method | Route | Description |
|---|---|---|
| `GET` | `/fragments/settings/auto-approve` | Render the auto-approval policies fragment (HTMX). |
| `POST` | `/api/settings/auto-approve` | Create a new auto-approval rule. |
| `POST` | `/api/settings/auto-approve/mode` | Set the auto-approval mode (manual, policy-based). |
| `POST` | `/api/settings/auto-approve/{index}/toggle` | Toggle an auto-approval rule on or off. |
| `DELETE` | `/api/settings/auto-approve/{index}` | Delete an auto-approval rule. |

### API Tokens

| Method | Route | Description |
|---|---|---|
| `GET` | `/fragments/settings/api-tokens` | Render the API tokens management fragment (HTMX). |
| `POST` | `/api/settings/api-tokens` | Create a new API bearer token. Body: `{ "name", "role", "scopes" }`. |
| `DELETE` | `/api/settings/api-tokens/{id}` | Revoke an API token by ID. |

### OTA Updates

| Method | Route | Description |
|---|---|---|
| `GET` | `/fragments/settings/updates` | Render the OTA updates fragment (HTMX). |
| `POST` | `/api/settings/updates/upload` | Upload an agent binary (multipart form). |
| `DELETE` | `/api/settings/updates/{platform}/{arch}/{version}` | Delete an uploaded agent binary. |
| `POST` | `/api/settings/updates/{platform}/{arch}/{version}/rollout` | Promote a version to production rollout. |

### Tag Compliance

| Method | Route | Description |
|---|---|---|
| `GET` | `/fragments/settings/tag-compliance` | Render the tag compliance summary fragment (HTMX). |
| `GET` | `/api/v1/tag-compliance` | Tag compliance summary (JSON, via REST API v1). |

---

## Deployment

Yuzu provides multiple deployment options: Docker Compose for quick setup, systemd units for bare-metal Linux, and a development stack script for local testing.

### Docker Compose

The default Docker deployment runs the server and agent standalone -- no gateway required. For scaled deployments with a gateway, see `docker-compose.full-uat.yml`.

**Files:**

| File | Description |
|---|---|
| `deploy/docker/Dockerfile.server` | Multi-stage build for the Yuzu server binary |
| `deploy/docker/Dockerfile.gateway` | Erlang/OTP build for the gateway node |
| `deploy/docker/docker-compose.yml` | Standalone stack (server + agent + monitoring) |
| `deploy/docker/docker-compose.full-uat.yml` | Gateway deployment (server + gateway + monitoring) |
| `docker-compose.uat.yml` | Self-contained single-file UAT stack pulled from ghcr.io (server + gateway + Prometheus + Grafana + ClickHouse) |

**Usage:**

```bash
cd deploy/docker
docker compose up -d          # start all services
docker compose logs -f        # follow logs
docker compose down           # stop all services
```

**Pinning a specific release with `docker-compose.uat.yml`:**

The top-level UAT compose file parameterises its `ghcr.io/.../yuzu-server` and `yuzu-gateway` tags through `${YUZU_VERSION:-<default>}`. The default tracks the latest published release, but operators testing an earlier or newer image can override at the command line:

```bash
YUZU_VERSION=0.9.0 docker compose -f docker-compose.uat.yml up -d
```

A GitHub Actions check (`scripts/check-compose-versions.sh`) runs as the first step of the release workflow and blocks asset publication if any tracked compose file carries a hardcoded `X.Y.Z` tag or a `${YUZU_VERSION:-...}` default that does not match the release tag — so the default in the checked-in file is guaranteed to match the latest shipped release.

**Exposed ports:**

| Port | Service | Deployment |
|---|---|---|
| 8080 | Web dashboard + REST API | Always |
| 50051 | gRPC (agent connections) | Always -- server in standalone, gateway in scaled |
| 50052 | gRPC (management) | Always |
| 50055 | gRPC (gateway upstream) | Gateway deployments only |
| 50063 | gRPC (gateway command forwarding) | Gateway deployments only |
| 8081 | Gateway health/readiness | Gateway deployments only |
| 9568 | Gateway Prometheus metrics | Gateway deployments only |
| 9090 | Prometheus | Monitoring stack |
| 3000 | Grafana (default login: admin/admin) | Monitoring stack |

**Volumes:** `server-data`, `agent-data`, `prometheus-data`, and `grafana-data` are persisted across container restarts.

### systemd Units

For bare-metal Linux deployments, systemd service files are provided for each component.

**Files:**

| File | Description |
|---|---|
| `deploy/systemd/yuzu-server.service` | Yuzu server unit |
| `deploy/systemd/yuzu-agent.service` | Yuzu agent unit |
| `deploy/systemd/yuzu-gateway.service` | Erlang gateway unit |

**Installation:**

```bash
# Copy binaries
sudo cp builddir/yuzu-server /usr/local/bin/
sudo cp builddir/yuzu-agent /usr/local/bin/

# Create service user
sudo useradd --system --no-create-home yuzu

# Install units
sudo cp deploy/systemd/yuzu-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable yuzu-server
sudo systemctl start yuzu-server
```

**Security hardening:** The systemd units include `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=true`, and `PrivateTmp=true` for defense-in-depth.

### Development Stack Script

The `scripts/start-stack.sh` script starts the full development stack locally (without Docker).

**Components started:**

1. `yuzu-server` -- gRPC on :50051, web on :8080
2. Erlang gateway -- agent gRPC on :50051, metrics on :9568
3. `yuzu-agent` -- connects to gateway on :50051
4. Prometheus -- scraper on :9090
5. Grafana -- dashboards on :3000

**Usage:**

```bash
bash scripts/start-stack.sh          # start all components
bash scripts/start-stack.sh stop     # kill all components
bash scripts/start-stack.sh status   # show running processes and ports
```

---

## Windows Service Installation

On Windows, Yuzu server and agent can be installed as Windows services for automatic startup and recovery. A native Windows service wrapper is planned for a future release; until then, use `sc.exe` or NSSM (Non-Sucking Service Manager).

### Using sc.exe

```cmd
REM Create the Yuzu server service
sc.exe create YuzuServer binPath= "C:\Yuzu\yuzu-server.exe --https-cert C:\Yuzu\certs\server.crt --https-key C:\Yuzu\certs\server.key" start= auto DisplayName= "Yuzu Server"

REM Create the Yuzu agent service
sc.exe create YuzuAgent binPath= "C:\Yuzu\yuzu-agent.exe --server-address yuzu.example.com:50051" start= auto DisplayName= "Yuzu Agent"

REM Set startup type to automatic (delayed start, recommended)
sc.exe config YuzuServer start= delayed-auto
sc.exe config YuzuAgent start= delayed-auto

REM Configure recovery: restart on first, second, and subsequent failures
sc.exe failure YuzuServer reset= 86400 actions= restart/5000/restart/10000/restart/30000
sc.exe failure YuzuAgent reset= 86400 actions= restart/5000/restart/10000/restart/30000

REM Start the services
sc.exe start YuzuServer
sc.exe start YuzuAgent

REM Stop the services
sc.exe stop YuzuServer
sc.exe stop YuzuAgent
```

> **Note:** With `sc.exe`, spaces after `=` are required (e.g., `start= auto`, not `start=auto`). This is a quirk of the `sc.exe` command parser.

### Using NSSM

[NSSM](https://nssm.cc/) provides a more user-friendly wrapper with a GUI configuration dialog.

```cmd
REM Install services
nssm install YuzuServer "C:\Yuzu\yuzu-server.exe"
nssm install YuzuAgent "C:\Yuzu\yuzu-agent.exe"

REM Set arguments
nssm set YuzuServer AppParameters "--https-cert C:\Yuzu\certs\server.crt --https-key C:\Yuzu\certs\server.key"
nssm set YuzuAgent AppParameters "--server-address yuzu.example.com:50051"

REM Configure startup and recovery
nssm set YuzuServer Start SERVICE_DELAYED_AUTO_START
nssm set YuzuAgent Start SERVICE_DELAYED_AUTO_START

REM Configure stdout/stderr logging
nssm set YuzuServer AppStdout "C:\Yuzu\logs\server-stdout.log"
nssm set YuzuServer AppStderr "C:\Yuzu\logs\server-stderr.log"
nssm set YuzuAgent AppStdout "C:\Yuzu\logs\agent-stdout.log"
nssm set YuzuAgent AppStderr "C:\Yuzu\logs\agent-stderr.log"

REM Start the services
nssm start YuzuServer
nssm start YuzuAgent
```

### Service Account

For production deployments, create a dedicated service account with minimal permissions rather than running as `LocalSystem`:

1. Create a local user account (e.g., `YuzuSvc`) with no interactive logon rights.
2. Grant the account read/write access to the Yuzu installation directory and data directory only.
3. Assign the "Log on as a service" right via Local Security Policy (`secpol.msc`).
4. Configure the service to run as this account: `sc.exe config YuzuServer obj= ".\YuzuSvc" password= "PASSWORD"`.

> **Planned:** A native Windows service wrapper (`yuzu-server --install-service`) is planned for a future release, which will handle service registration, recovery configuration, and Event Log integration automatically.

---

## Planned Features

The following server administration features are on the roadmap but not yet implemented.

| Feature | Phase | Description |
|---|---|---|
| Runtime Configuration API | Phase 7 (7.3) | Change retention TTLs, connection limits, and other server parameters via REST API without restarting the server. |
| AD/Entra Integration | Phase 7 (7.5) | Sync users and groups from Active Directory (LDAP) or Microsoft Entra ID. Auto-create Yuzu principals from directory membership. |
| System Health Monitoring | Phase 7 (7.2) | Server-side health dashboard showing memory, CPU, disk, database size, connected agent count, and gRPC stream health. Prometheus metrics for server internals. |
