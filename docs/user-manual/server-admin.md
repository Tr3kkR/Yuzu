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
12. [Retention Settings](#retention-settings)
13. [Settings API Reference](#settings-api-reference)
14. [Planned Features](#planned-features)

---

## Server CLI Flags

The Yuzu server binary accepts the following command-line flags. All flags are optional; defaults are shown in the table.

| Flag | Default | Description |
|---|---|---|
| `--config` | *(auto)* | Path to `yuzu-server.cfg`. If omitted, uses the default location next to the binary. |
| `--web-port` | `8080` | HTTP listen port for the dashboard and REST API. |
| `--web-address` | `127.0.0.1` | Web UI bind address. |
| `--https` | off | Enable HTTPS for the dashboard. Requires `--https-cert` and `--https-key`. |
| `--https-port` | `8443` | HTTPS listen port (used when `--https` is enabled). |
| `--https-cert` | *(none)* | Path to PEM-encoded TLS certificate file. |
| `--https-key` | *(none)* | Path to PEM-encoded TLS private key file. |
| `--no-https-redirect` | off | When HTTPS is enabled, do not redirect HTTP requests to HTTPS. By default, HTTP requests are redirected. |
| `--oidc-issuer` | *(none)* | OIDC identity provider issuer URL (e.g., `https://login.microsoftonline.com/{tenant}/v2.0`). |
| `--oidc-client-id` | *(none)* | OIDC application (client) ID. |
| `--oidc-client-secret` | *(none)* | OIDC client secret. |
| `--oidc-redirect-uri` | *(auto)* | OIDC redirect URI. If omitted, auto-computed from the web address and port. Must match the registered redirect in your identity provider. |
| `--oidc-admin-group` | *(none)* | Entra ID group object ID that maps to the admin role. Users in this group are granted admin access on OIDC login. |

### Example

```bash
# HTTP only (development)
./yuzu-server --web-port 8080

# HTTPS with certificate files
./yuzu-server --https --https-port 8443 \
  --https-cert /etc/yuzu/server.crt \
  --https-key /etc/yuzu/server.key

# HTTPS with OIDC SSO
./yuzu-server --https --https-port 8443 \
  --https-cert /etc/yuzu/server.crt \
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

---

## First-Run Setup

When the server starts for the first time and no `yuzu-server.cfg` exists, it enters **interactive setup mode** on the terminal. The setup prompts for:

1. **Admin username** -- the initial administrator account.
2. **Admin password** -- entered twice for confirmation. Stored as a PBKDF2 hash.

After setup completes, the server writes `yuzu-server.cfg` and starts normally. Subsequent restarts skip the setup prompt.

> **Headless deployment:** For automated deployments, pre-create `yuzu-server.cfg` with a PBKDF2-hashed password entry before starting the server for the first time.

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
| OIDC SSO | *(configured via CLI flags)* | Configure OpenID Connect single sign-on with an external identity provider. OIDC is configured at startup via CLI flags; there is no Settings page fragment for runtime configuration. |
| Directory Integration | *(planned -- no fragment yet)* | AD/Entra ID user and group sync. *(Coming soon -- UI stub only.)* |

---

## TLS Configuration

TLS can be configured at startup via CLI flags or at runtime through the Settings page.

### Via CLI Flags

Pass `--https`, `--https-cert`, and `--https-key` at server startup. See [Server CLI Flags](#server-cli-flags).

### Via Settings Page

1. Navigate to **Settings > TLS Configuration**.
2. Toggle **Enable HTTPS**.
3. Upload PEM-encoded certificate and private key files using the upload form.
4. The server begins serving HTTPS on the configured port. By default, HTTP requests are redirected to HTTPS.

### Certificate Requirements

- Format: PEM-encoded.
- The certificate file may contain the full chain (leaf + intermediates).
- The private key must not be password-protected.
- For production, use certificates signed by a trusted CA. Self-signed certificates work but require agents to trust the CA.

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

### Identity Provider Setup

1. Register Yuzu as an application in your identity provider.
2. Set the redirect URI to `https://<yuzu-server>:<port>/auth/callback`.
3. Note the client ID and client secret.
4. Enter these values in the Yuzu Settings page or pass them as CLI flags.

### User Mapping

OIDC-authenticated users are mapped to Yuzu roles based on claims or group membership. The mapping configuration depends on your identity provider and is set in the OIDC section of the Settings page.

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

## Planned Features

The following server administration features are on the roadmap but not yet implemented.

| Feature | Phase | Description |
|---|---|---|
| Runtime Configuration API | Phase 7 (7.3) | Change retention TTLs, connection limits, and other server parameters via REST API without restarting the server. |
| AD/Entra Integration | Phase 7 (7.5) | Sync users and groups from Active Directory (LDAP) or Microsoft Entra ID. Auto-create Yuzu principals from directory membership. |
| System Health Monitoring | Phase 7 (7.2) | Server-side health dashboard showing memory, CPU, disk, database size, connected agent count, and gRPC stream health. Prometheus metrics for server internals. |
