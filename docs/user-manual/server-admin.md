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
13. [PostgreSQL Substrate](#postgresql-substrate)
14. [Retention Settings](#retention-settings)
15. [Settings API Reference](#settings-api-reference)
16. [Deployment](#deployment)
17. [Windows Service Installation](#windows-service-installation)
18. [Planned Features](#planned-features)

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
| `--no-tls` | off | Disable **all** gRPC TLS (agent listener AND management listener). Plaintext gRPC, no encryption, no peer authentication. **The administrative surface is ungated when this flag is passed.** Intended for local UAT, customer demos, and development. The server emits a multi-line ERROR-level startup banner and a 5-minute recurring reminder when running in this mode. |
| `--cert` | *(none)* | Path to PEM-encoded gRPC server certificate for the **agent listener** (port 50051 by default). Env: `YUZU_CERT`. |
| `--key` | *(none)* | Path to PEM-encoded gRPC server private key for the agent listener. The file must not be world-readable (Unix: `chmod 600`). Env: `YUZU_KEY`. |
| `--no-default-certs` | off | Do **not** auto-generate built-in default certificates on first boot. Restores the legacy refuse-to-start: the server will not start unless `--cert`/`--key` (and `--https-cert`/`--https-key` when HTTPS is enabled) are supplied. Use where operator- or HSM-provided certs are mandatory policy. (Defaults emit a startup banner, the audit actions `server.default_certs_generated` + `server.default_certs_in_use`, and the Prometheus gauge `yuzu_server_default_certs_active`.) Env: `YUZU_NO_DEFAULT_CERTS`. |
| `--ca-dir` | *(platform cert dir)* | Directory for the built-in CA root + default leaf certs (`default-ca.pem`/`.key`, `default-server.pem`, `default-https.pem`, …). Default: `/etc/yuzu/certs` (Linux/macOS), `C:\ProgramData\Yuzu\certs` (Windows). The CA root key is `0600` — back it up (losing it forces a full fleet re-enrollment). Env: `YUZU_CA_DIR`. |
| `--cert-san` | *(none)* | **Repeatable.** Extra Subject Alternative Name to add to *every* auto-generated default leaf (dashboard HTTPS, agent/management gRPC, and gateway), on top of the base `localhost` / `127.0.0.1` / `::1` / `<hostname>`. Forms: `dns:<name>`, `ip:<addr>`, or a bare value (auto-classified as IP vs DNS by shape); a single value may be comma-separated. Use this so the built-in certs validate for a name a client actually dials — e.g. `--cert-san dns:gateway` so an agent reaching the gateway by that service name passes TLS hostname verification, or `--cert-san dns:yuzu.corp.example --cert-san ip:10.0.0.5` for a load-balancer name / VIP. An `ip:` value that is not an IP literal is ignored with a warning. **Ignored** when operator certs are supplied or `--no-default-certs` is set; **changing it does not rotate an existing cert set** — clear `--ca-dir` (or replace the certs) for new SANs to take effect (in a container the cert dir lives in the image layer unless a volume is mounted there, so *recreate* the container — a restart alone won't regenerate). Env: `YUZU_CERT_SAN`. |
| `--ca-cert` | *(none)* | Path to PEM-encoded CA certificate used to verify agent client certificates (full mTLS). Without this, the agent listener has no client-cert verification — `--insecure-skip-client-verify` plus `YUZU_ALLOW_INSECURE_TLS=1` is required to start in that posture. Env: `YUZU_CA_CERT`. |
| `--insecure-skip-client-verify` | off | Allow gRPC TLS without `--ca-cert` (one-way TLS — server cert is presented but client certs are not verified). Applies to BOTH the agent listener and the management listener. **Requires `YUZU_ALLOW_INSECURE_TLS=1` in the environment as a second confirmation** — the server refuses to start without it. Renamed from `--allow-one-way-tls` in v0.12.0; the old name is still accepted with a deprecation warning. |
| `--allow-one-way-tls` | off | **[DEPRECATED]** Renamed to `--insecure-skip-client-verify`. Still accepted for backward compatibility with a startup deprecation warning; will be removed in a future release. |
| `--management-cert` | *(none)* | Optional PEM cert for the **management listener** (port 50052 by default). If unset, the management listener reuses the agent listener's certificate. |
| `--management-key` | *(none)* | Optional PEM key for the management listener. If `--management-cert`/`--management-key` are set without `--management-ca-cert`, the same `--insecure-skip-client-verify` + `YUZU_ALLOW_INSECURE_TLS=1` gate applies. |
| `--management-ca-cert` | *(none)* | Optional CA cert for management client cert verification. Without this (and without `--insecure-skip-client-verify`), the management listener refuses to start. |
| `--trusted-nat-cidr` | *(none)* | Comma-separated (or repeatable) CIDR ranges (IPv4 or IPv6) declaring a trusted NAT boundary for **direct-connect** agents. When an agent's Register and Subscribe source IPs *both* fall within one declared range, a per-session peer-IP mismatch is downgraded from a hard reject to an *advisory* (audit `result="ok" outcome=advisory`; counted on `yuzu_grpc_subscribe_peer_advisory_total`) instead of rejecting the stream. Strict exact-match is the default when absent; mismatches outside every declared range still reject (the stolen-session guard stays intact). Use for fleets behind multi-egress NAT, proxy pools, CG-NAT, or SD-WAN where an agent may egress from different public IPs on its two connections. **Security note:** declaring a range asserts the hosts in it are mutually trusted not to replay each other's sessions; keep ranges as narrow as possible (never `0.0.0.0/0`). Malformed entries are logged and ignored at startup. Env: `YUZU_TRUSTED_NAT_CIDR`. |
| `--nat-trust-mtls-identity` | off | Also downgrade a peer-IP mismatch to advisory when the Subscribe mTLS client identity matches the identity bound at Register (#1128). **SAFE ONLY WITH PER-AGENT CLIENT CERTIFICATES.** With a shared/fleet-wide client cert every identity "matches", turning this into a session-replay bypass (an insider agent could hijack another agent's session from its own IP). Off by default; enable only if each agent presents a unique client certificate. When both `--nat-trust-mtls-identity` and `--trusted-nat-cidr` are configured, mTLS-identity match takes precedence: a session whose mTLS identity matches records `reason=mtls_identity_match` (visible on the audit `detail` and the `yuzu_grpc_subscribe_peer_advisory_total{reason=...}` label), and CIDR containment is not consulted for that session. Enabling the flag emits a `warn`-level startup line — confirm it appears in the boot log so the operator who pulled the lever can sign off on the per-agent-cert posture. Env: `YUZU_NAT_TRUST_MTLS_IDENTITY`. |
| `--https-port` | `8443` | HTTPS listen port. |
| `--https-cert` | *(auto)* | Path to PEM-encoded TLS certificate for the dashboard. **A per-install default cert is auto-generated when omitted** (unless `--no-default-certs`); `--no-https` disables HTTPS entirely. |
| `--https-key` | *(auto)* | Path to PEM-encoded TLS private key. Auto-generated default used when omitted (unless `--no-default-certs`). The file must not be world-readable (Unix: `chmod 600`). |
| `--no-https-redirect` | off | When HTTPS is enabled, do not redirect HTTP requests to HTTPS. By default, HTTP requests are redirected. |
| `--no-cert-reload` | off | Disable automatic certificate hot-reload. By default, the server polls cert/key files and hot-swaps the SSL context when they change. Env: `YUZU_NO_CERT_RELOAD`. |
| `--cert-reload-interval` | `60` | Certificate reload polling interval in seconds. Minimum effective interval is 10 seconds. Env: `YUZU_CERT_RELOAD_INTERVAL`. |
| `--metrics-no-auth` | off | Allow unauthenticated `/metrics` access from any IP. By default, remote clients must authenticate; localhost access is always unauthenticated. **Warning:** enabling this exposes fleet composition data (OS, architecture, version counts) — and, when the cohort metrics export is enabled, **operator tag values** as `cohort` labels — to any network client. See [Metrics Security](metrics.md#security-considerations). Env: `YUZU_METRICS_NO_AUTH`. |
| `--csp-extra-sources` | *(none)* | Extra Content-Security-Policy source-list entries appended to `script-src`, `style-src`, `connect-src`, and `img-src`. Space-separated string of host/scheme expressions or whitelisted CSP keywords (`'self'`, `'none'`, `'sha256-...'`, `'sha384-...'`, `'sha512-...'`, `'nonce-...'`). The server **refuses to start** if the value contains control bytes, semicolons, commas, or unsafe CSP keywords like `'unsafe-eval'`. Use to whitelist customer CDNs, monitoring beacons, or analytics endpoints. See [HTTP Security Response Headers](security-hardening.md#http-security-response-headers). Env: `YUZU_CSP_EXTRA_SOURCES`. |
| `--oidc-issuer` | *(none)* | OIDC identity provider issuer URL (e.g., `https://login.microsoftonline.com/{tenant}/v2.0`). |
| `--oidc-client-id` | *(none)* | OIDC application (client) ID. |
| `--oidc-client-secret` | *(none)* | OIDC client secret. |
| `--oidc-redirect-uri` | *(auto)* | OIDC redirect URI. If omitted, auto-computed from the web address and port. Must match the registered redirect in your identity provider. |
| `--oidc-admin-group` | *(none)* | Entra ID group object ID that maps to the admin role. Users in this group are granted admin access on OIDC login. |
| `--oidc-skip-tls-verify` | off | Disable TLS certificate verification for OIDC endpoints. **Insecure — dev only.** Env: `YUZU_OIDC_SKIP_TLS_VERIFY`. |
| `--mcp-disable` | off | Disable the MCP (Model Context Protocol) endpoint entirely. When set, all requests to `/mcp/v1/` are rejected with a JSON-RPC error. Use this in air-gapped or high-security environments where AI integration is not desired. Env: `YUZU_MCP_DISABLE`. |
| `--mcp-read-only` | off | Restrict MCP to read-only tools only. Write and execute operations (Phase 2) are rejected even if the MCP token's tier would normally allow them. Env: `YUZU_MCP_READ_ONLY`. |
| `--viz-disable` | off | Disable the fleet visualization feature. When set, the REST endpoints (`GET /api/v1/viz/fleet/topology`, `GET /fragments/viz/fleet/topology`, and the per-host drill-down routes) **and** the page shells (`GET /viz/fleet`, `GET /viz/host/<id>`) all return `503`. Tier-before-permission ordering: the kill switch takes effect even for callers who would otherwise fail RBAC. Two pieces of durable evidence that the switch took effect: the startup log line `[VIZ] viz endpoint disabled by configuration`, and a `server.viz_disabled` audit event (`target_type = FleetTopology`) written to the audit store at boot — so an auditor can confirm the disabled state from the audit trail even on a deployment with no viz traffic. Env: `YUZU_VIZ_DISABLE`. |
| `--allow-unsigned-packs` | off | **Dangerous.** Accept product packs at install without an Ed25519 signature. Default is to reject unsigned packs with `pack '<name>' is unsigned and signature enforcement is enabled (set --allow-unsigned-packs / YUZU_ALLOW_UNSIGNED_PACKS=1 to bypass)` (security-by-default since #802 / W7.4). Setting this flag restores the pre-W7.4 behaviour where any operator with pack-upload permission, or a MITM on pack delivery, could install a pack containing arbitrary `InstructionDefinition` or plugin payloads that would execute fleet-wide. Two pieces of durable evidence that the flag is active: a startup log line `[SECURITY] product pack signature enforcement DISABLED by configuration`, and a `server.unsigned_packs_allowed` audit event (`target_type = ProductPack`) written to the audit store at boot. Use only as a temporary migration aid; sign your packs and remove the flag as soon as feasible. Env: `YUZU_ALLOW_UNSIGNED_PACKS`. |
| `--allow-unsigned-definitions` | off | **Dangerous.** Accept `InstructionDefinition` imports via `POST /api/v1/instructions/import` without an Ed25519 signature. Default is to reject unsigned imports with `instruction-import is unsigned and signature enforcement is enabled (set --allow-unsigned-definitions / YUZU_ALLOW_UNSIGNED_DEFINITIONS=1 to bypass)` (security-by-default since #1073 / W7.4 sibling-gap closure). Closes the equivalent fleet-RCE surface that `--allow-unsigned-packs` covers on the ProductPack side: without enforcement, any operator with `InstructionDefinition:Write` (or a MITM on a content sync) can publish a definition that dispatches a malicious plugin invocation on every targeted agent. Durable evidence: startup log line `[SECURITY] instruction-definition signature enforcement DISABLED by configuration` AND a `server.unsigned_definitions_allowed` audit event (`target_type = InstructionDefinition`). Env: `YUZU_ALLOW_UNSIGNED_DEFINITIONS`. |
| `--mfa-enforcement` | `optional` | MFA enforcement mode: `optional` (users may enroll voluntarily; login never requires it), `admin-only` (an admin without MFA must enroll before login completes), or `required` (every role must enroll). Under `admin-only`/`required` an un-enrolled login is redirected through TOTP enrollment (`POST /login/mfa/enroll`) before a session is minted; the server logs an `INFO` line naming the active mode at startup. **Breaking:** earlier releases accepted `admin-only`/`required` as no-ops — if you staged the flag, read `docs/user-manual/upgrading.md` before upgrading (live enforcement begins immediately, and SSO users require an IdP that asserts `amr`). See `docs/user-manual/authentication.md` § Multi-Factor Authentication and `docs/auth-mfa-design.md`. Env: `YUZU_MFA_ENFORCEMENT`. |
| `--mfa-step-up-window-secs` | `300` | Seconds after a successful TOTP proof during which 11 high-risk REST + Settings endpoints (PR2 of the MFA ladder) accept the session as "stepped up" without re-prompting. Set to `0` to disable the gate entirely (emits a startup `WARN`). Env: `YUZU_MFA_STEP_UP_WINDOW_SECS`. |
| `--mfa-login-pending-secs` | `120` | Lifetime of the intermediate `mfa_pending_token` between password success and TOTP submission. The pending state is per-process (lost on restart, not shared across HA replicas without sticky sessions). Env: `YUZU_MFA_LOGIN_PENDING_SECS`. |
| `--mfa-reset <username>` | *(none)* | **Break-glass.** Clears the named user's MFA enrollment and exits **without starting the server** — the recovery path from MFA-enforcement lockout. Writes an `mfa.reset.breakglass` audit row (principal = the OS account that ran the CLI). Requires `--config` + `--data-dir`; no TLS flags needed. See `docs/ops-runbooks/auth-db-recovery.md` § Emergency MFA disable. |
| `--auth-lockout-threshold` | `5` | Consecutive failed **local-password** login attempts before an account is temporarily locked (SOC 2 CC6.3). A locked account returns the **same generic 401** as a bad password — no enumeration/lock-state oracle. Counter resets on a successful login or an admin unlock (`POST /api/v1/users/{name}/unlock`). Scope is local-password only — OIDC/SSO sessions and API tokens are unaffected. Setting `0` **disables** lockout (startup `WARN`) and constitutes a deviation from the CC6.3 hardened baseline — record it as a documented exception on your risk register, do not just flip it. NIST 800-63B §5.2.2 suggests allowing ≥10 attempts where network-layer rate-limiting is also present; raise the threshold accordingly if you front Yuzu with an IP throttle. Env: `YUZU_AUTH_LOCKOUT_THRESHOLD`. |
| `--auth-lockout-window-secs` | `900` | How long an account stays locked after the threshold is crossed. The lock **auto-expires** after this window — it is never permanent, so it cannot be weaponised to permanently deny a legitimate principal; a waited-out user regains a full attempt budget. Env: `YUZU_AUTH_LOCKOUT_WINDOW_SECS`. |
| `--auth-mode` | `standard` | Local-password login policy (SOC 2 CC6.3). `standard` = password login enabled. `sso-only` = **local-password login is disabled fleet-wide** — only OIDC SSO mints a session — so the server **refuses to start** unless OIDC is configured (`--oidc-issuer`). A rejected local login returns the **same generic 401** as a bad password (no oracle) and is counted via the metric `yuzu_auth_local_disabled_total` (metric, not a per-attempt audit row — avoids audit-flood under credential spray). A single `--break-glass-user` is exempt while armed. Env: `YUZU_AUTH_MODE`. |
| `--break-glass-user <username>` | *(none)* | The single local account exempt from `--auth-mode=sso-only`, exempt **only while armed** (see `--break-glass-arm`). Under `sso-only` the server **refuses to start** unless this account exists and has **MFA enrolled** (a break-glass account must carry a second factor). A break-glass login is forced through MFA regardless of `--mfa-enforcement` and writes an `auth.breakglass.login` audit row. Env: `YUZU_BREAK_GLASS_USER`. |
| `--break-glass-window-secs` | `86400` | Seconds the break-glass account stays armed after `--break-glass-arm` (default 24h). The arm **auto-expires** (evaluated lazily at login like the lockout window) — it is never a permanent standing exemption. Env: `YUZU_BREAK_GLASS_WINDOW_SECS`. |
| `--break-glass-arm` | off | **Break-glass.** Arms `--break-glass-user` for the configured window and exits **without starting the server** — the recovery path when the IdP is down under `--auth-mode=sso-only`. Run on the server host as the service account (arming deliberately does **not** require a session). Validates the account (exists + MFA), verifies the audit store is writable **before** arming, and writes an `auth.breakglass.armed` audit row (principal = the OS account that ran the CLI). Requires `--break-glass-user` + `--data-dir`. Refuses (exit non-zero) if any check fails. |
| `--log-file` | *(none)* | Path for explicit on-disk log output. When set, log lines are written to this file in addition to stdout. The directory must be writable by the server's runtime user; if the file or directory cannot be opened the server logs an ERROR but continues to start. Independent of the default platform log path (see [File Logging](#file-logging)). |

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
| `yuzu-server.cfg` | First-boot seed for `auth.db`. Holds the initial admin credential as PBKDF2-SHA256 with a per-user salt. After first boot, `auth.db` is authoritative and this file is no longer read for live state — keep it as the seed for disaster-recovery (re-creating `auth.db` from scratch). |
| `auth.db` | SQLite-backed authentication database. Holds user accounts, sessions, and enrollment tokens with PBKDF2-SHA256 hashed passwords. Created in `--data-dir` on first boot. Mode `0600` on Linux; restricted ACL on Windows. **This is the live source of truth for authentication state from v0.12.0 onwards.** |
| `enrollment-tokens.cfg` | Legacy enrollment-token file (Tier 2). New deployments persist tokens inside `auth.db`; this file remains writable for backwards-compatibility on upgrades from pre-AuthDB releases. |
| `pending-agents.cfg` | Queue of agents awaiting manual approval (Tier 1 enrollment). Contains agent ID, hostname, IP, and registration timestamp. |

> **Backup recommendation:** Back up `auth.db` (use `sqlite3 auth.db ".backup ..."`, NEVER `cp` against a live WAL DB), `yuzu-server.cfg`, the rest of the `--data-dir` SQLite stores (including **`ca.db`** — the internal-CA inventory + CRL history), and **the entire CA/cert directory `--ca-dir`** (`default-ca.key` especially — the per-install CA private key) on the same schedule. Use the SQLite online-backup API for every `.db` file, not `cp`. **Losing `default-ca.key` forces a full fleet re-enrollment** (every agent's cert chains to that root, and the server refuses to silently re-root — see below). Losing `auth.db` AND `yuzu-server.cfg` requires re-running `--first-run-setup` to create a new admin. Losing `auth.db` alone is recoverable — see `docs/ops-runbooks/auth-db-recovery.md`. As server stores migrate to PostgreSQL (ADR-0006), a complete backup also covers the Postgres database — see [PostgreSQL Substrate](#postgresql-substrate) for the `pg_dump`/`pg_restore` procedure and the ADR-0010 restore-pairing invariant.

> **Built-in default certificates — convenience, not production.** With no `--cert`/`--key`/`--https-cert` supplied (and without `--no-default-certs`), the server generates a per-install ECDSA CA + server leaves on first boot so a fresh install is encrypted with zero config. Operational caveats:
> - **10-year, no auto-renewal.** The server leaves do not auto-renew; the `yuzu_server_cert_expiry_timestamp_seconds{cert="default-ca"}` gauge + the `YuzuCertificateExpiringSoon`/`…Critical` alerts (`docs/prometheus/yuzu-alerts.yml`) warn ahead of expiry. **Replace defaults before production rollout** with operator-provided certs (`--cert`/`--key`, `--https-cert`/`--https-key`) or, to rotate the built-in set, clear `--ca-dir` (after backing it up) and restart.
> - **SAN limitation.** Default leaf SANs cover `localhost`, `127.0.0.1`, `::1`, and the boot-time hostname only. Reaching the dashboard/agent listener by a LAN IP or a different FQDN needs operator-provided certs (or DNS that resolves to a covered name). A host rename invalidates the SAN — rotate the certs after renaming.
> - **No silent re-root.** If `ca.db` already holds a CA root but the on-disk certs in `--ca-dir` are missing/corrupt (e.g. a wiped cert dir on a persistent data volume), the server **refuses to start** rather than mint a new CA that would orphan every enrolled agent. Restore `default-*.{pem,key}` from backup (matching the `ca.db` root), or remove `ca.db` too for a deliberate clean re-root.

> **File permissions (Unix):** `auth.db` is created with mode `0600` (owner read/write only); `yuzu-server.cfg`, `enrollment-tokens.cfg`, and `pending-agents.cfg` are also `0600` after every write. No manual `chmod` is required.

> **Windows Defender exclusion:** On Windows production deploys, exclude `auth.db`, `auth.db-wal`, and `auth.db-shm` from real-time scan. See `docs/ops-runbooks/auth-db-recovery.md` for the `Add-MpPreference` commands.

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

## Upgrade Notes

### vNEXT — DEX per-application sampling (`procperf`) is a new opt-in telemetry category

This release adds per-application resource sampling (top-N processes by CPU and
working set, by image name) to the TAR edge warehouse. **It is off by default**
(`procperf_enabled=false`) and collects nothing until an operator opts in — it
is a distinct, usage-class telemetry category subject to works-council / DPA
review, separate from the device-level performance sampling (`perf_enabled`,
on by default, no per-app identity) that shipped in the prior release. To
enable per-app sampling, set `procperf_enabled=true` via a TAR `configure`
instruction (fleet-wide or per-device). The data is image names only (no
command lines), 7-day raw / 31-day hourly retention, and is captured in the
Workstream E data inventory in `docs/enterprise-readiness-soc2-first-customer.md`.
TAR warehouse tables are now also created on every database open, so upgraded
agents need no manual table-creation step. New webhook egress: the `dex.signal`
event (operator-routed signals) — see the security questionnaire note in the
assurance package if you answer data-egress questions.

### vNEXT — `POST /login` returns 202 for MFA-enrolled users (breaking)

Programmatic clients (CI pipelines, health checks, `curl` scripts) that call `POST /login` and treat anything other than `HTTP 200 + {"status":"ok"}` as failure will silently break the first time an authenticating user enrolls in TOTP MFA via Settings → Multi-Factor Authentication. The new response is `HTTP 202` with body `{"status":"mfa_required","mfa_pending_token":"<opaque>","expires_in":120}` — handle this branch by posting `mfa_pending_token` + the 6-digit TOTP code (or a `XXXX-XXXX-XXXX-XXXX` recovery code) to `POST /login/mfa` to mint the session cookie. See `docs/user-manual/authentication.md` § Multi-Factor Authentication for the full flow.

MFA CLI flags: `--mfa-enforcement` (default `optional`; `admin-only`/`required` now **enforce** — see the breaking note in `docs/user-manual/upgrading.md`), `--mfa-step-up-window-secs` (default `300`), `--mfa-login-pending-secs` (default `120`), and the break-glass `--mfa-reset <username>` (clears a locked-out user's MFA and exits, writing an `mfa.reset.breakglass` audit row — see `docs/ops-runbooks/auth-db-recovery.md`). Recovery code format changed from `XXXXX-XXXXX` (50 bits) to `XXXX-XXXX-XXXX-XXXX` (80 bits) — codes printed by earlier PR1 commits remain valid until consumed or regenerated. The break-glass procedure for a user who has lost both their authenticator and all recovery codes — and the recovery path for an operator locked out by an enforcement misconfiguration (SSO IdP not asserting `amr`, or a sole admin who could not enroll) — lives at `docs/ops-runbooks/auth-db-recovery.md`.

### v0.10.0 — API token revocation is owner-scoped

Starting with v0.10.0, non-admin users can no longer revoke API tokens they do not own. A caller holding the `ApiToken:Delete` permission may revoke only tokens whose `principal_id` matches the session's username; the global `admin` role is the sole bypass. Prior releases allowed any holder of `ApiToken:Delete` to revoke any token, which was an IDOR (tracked in GitHub issue #222).

**If your deployment uses a non-admin service account to rotate tokens for other principals** — for example, a shared `ops` role that recycles service-account tokens on a schedule — those rotations will begin receiving `HTTP 404 token not found` after upgrade. To restore the behavior, either:

1. Assign the rotation account the global `admin` role, or
2. Refactor the rotation so each principal owns and rotates its own token.

Option (2) is the recommended long-term posture because it aligns with least-privilege. The same ownership constraint applies to both the REST path `DELETE /api/v1/tokens/{id}` and the HTMX dashboard path `DELETE /api/settings/api-tokens/{id}`. Denied attempts are recorded in the audit log with `action=api_token.revoke`, `result=denied`, and `detail=owner=<real owner>` so operators can distinguish an enumeration probe from a legitimate self-revoke.

Both paths return `HTTP 404 token not found` on a cross-user revoke attempt — identical to the response for a truly-nonexistent token — to prevent the endpoint from being used as an enumeration oracle.

### v0.12.0 — TAR dashboard page + mixed-version agent caveats

The new `/tar` dashboard page (issue #547) surfaces every device × source pair where a TAR collector has been disabled. The page is reachable from the **TAR** entry in the main navigation bar; viewing requires `Infrastructure:Read` and the per-source Re-enable / Scan-fleet actions require `Execution:Execute`.

**Mixed-version rollout caveat.** Agents running a build older than v0.12.0 do not emit the new per-source `paused_at` / `live_rows` / `oldest_ts` lines on `tar.status`. The dashboard renders an em-dash (`—`) for those columns when a pre-v0.12.0 agent appears in a scan result. This is not a server bug — it is an honest "we don't know when this collector was disabled because the agent reporting it pre-dates the field." Operators upgrading the server before the agent fleet should expect the em-dash for any pre-existing paused sources until the agent at the affected device is upgraded. See `docs/user-manual/tar.md` for the full TAR dashboard workflow.

**Per-operator scan state caveat.** Scan results are held in the server's memory keyed by operator username, with a 30-second per-operator cooldown to defend against retry-storms. Restarting the server clears all scan state; operators will see "No scan data yet — click Scan fleet" after a restart and a fresh scan returns within seconds. Persistence across restarts and multi-server coordination land in Phase 15.G operational hardening.

**Audit log additions.** Two new audit actions emit on operator activity: `tar.status.scan` (every Scan-fleet click; `result=success`/`denied`/`failure` with detail) and `tar.source.reenable` (every Re-enable click; `result=success`/`denied`/`failure`). SIEM rules can distinguish forged form submissions from genuine connectivity failures via the `detail=scope_violation` vs `detail=agent_not_connected` distinction even though the HTTP response body is identical (`Agent not reachable.` 404) for both cases — the body identity is load-bearing for the no-enumeration-oracle property.

### vNEXT — Fleet visualization (3D) (`/viz/fleet`)

The fleet-visualization feature ladder lands across the `feat/viz-engine` branch. PRs 1–12 are shipped: agent collector + server store + REST/fragment routes + page scaffold + camera controls + cube renderer + Sprite labels + hover tooltip + interior process nodes coloured by category + intra-cube localhost edges + per-cube listening-socket spheres + cross-machine connection edges + push-based topology ingestion + **three-tier stacked layout, talking-socket dots, curved tube wires, loopback-bind filter (PR 12)**. Remaining ladder PRs add the vulnerability overlay and final polish (LOD, edge bundling, a11y, perf).

**Operator-visible state today (PRs 1–12).** Navigating to `/viz/fleet` shows one translucent cube per fleet machine, **organized into three architectural tiers** — frontend cubes on the top Y plane, applications in the middle plane, databases on the bottom plane. Within each tier, machines fall onto a deterministic per-tier grid (FNV-1a hash on `agent_id`). Live agents render at opacity `0.18`; stale agents (no `tar.fleet_snapshot` push within the staleness threshold) drop to `0.08`. Per-OS palette: Linux `#f0c674`, macOS/Darwin `#a0a0a0`, Windows `#5294e2`. Hostname `Sprite` labels render below each cube. Inside each cube, one `SphereGeometry` dot per process is laid out deterministically (`hash(pid|ppid)`-mod-bucket inside the cube's interior) and coloured from a six-category palette: system `#6e7681`, browser `#58a6ff`, database `#d29922`, web `#56d364`, runtime `#bc8cff`, other `#8b949e`. Each cube's TOP face carries a ring of cream-coloured listening-socket spheres (one per `listeners[]` row) with `:port` labels; **loopback-only listeners (`127.x`, `::1`) are now hidden from the surface** — they aren't reachable from other instances. Each cube's BOTTOM face carries a ring of cool-blue **talking-socket** dots (one per unique outbound `(proto, dst_ip, dst_port)`). **Cross-machine connections render as thick curved tubes** (`THREE.TubeGeometry` along a `CubicBezierCurve3` with vertical end-tangents) that drop from the source's talking dot down/across to the destination's listener sphere. External (off-fleet) destinations render as short grey stub lines with ring markers. Hover order: listener sockets → talking sockets → process dots → edges → cubes. WASD pans, drag rotates, wheel zooms.

**Tier classification heuristic.** `classifyTier` reads `listeners[]` port hints (`DB_PORTS = {3306, 5432, 6379, 27017, 1521, 1433, 9042, 9200, 5984, 8086, 11211}` / `WEB_PORTS = {80, 443, 8080, 8443, 8088}`) plus process-category strings (`'database'`, `'web'`). Priority is **db > web > app**: a host with any DB signal lands on the database tier regardless of whether it also serves web traffic. A host with no DB or web signal defaults to the application tier. **Known limitations:** (a) databases on non-standard ports (e.g. Postgres on 5431 for a sharded cluster) fall through to the application tier unless one of the host's processes is classified as `database` by `process_category.hpp`; (b) `WEB_PORTS` is intentionally narrow — it covers reverse proxies / load balancers / API gateways on ports 80/443/8080/8443/8088 but **not** dev-server defaults (3000/4200/5173/8000), because in a classic three-tier deployment a nodejs/django/vite server listening on those ports is application work, not the front edge. There is no operator-accessible override today; both limitations are tracked as a follow-up issue on function-aware tier classification.

**Why empty cubes show no lines.** Intra-cube edges appear only for processes with *active* loopback socket pairs (e.g. Prometheus scraping node_exporter, a client connected to a local Redis / Postgres). A fresh agent with no inter-process loopback traffic shows process dots but no lines — this is expected, not a bug. Lines appear as workloads generate loopback flows.

**Browser requirements.** The page uses ES module imports resolved through an `<script type="importmap">` declaration. importmap is supported in Chrome 89+, Firefox 108+, Safari 16.4+, and Edge 89+ (all browsers shipped after early 2023). Older browsers receive a visible error overlay on the page rather than a blank canvas — the page detects via `HTMLScriptElement.supports('importmap')` before attempting the module load. **`MeshPhysicalMaterial` cubes additionally require WebGL 2.0**, which is bundled with all browsers in the import-map support floor but can be disabled by enterprise group policy on locked-down terminals. Browsers without WebGL 2 will see the grid but the cubes will fail to render with a black or missing material; verify WebGL 2 is enabled in browser policy before pilot rollout. Operators on enterprise-locked browser configurations that lag 2+ years should test on a representative deployment. **Page weight:** the `/viz/fleet` route pulls three.js (~685 KB), three-orbit (~32 KB), htmx (~51 KB), the yuzu-viz renderer (~84 KB), plus the design-system CSS. Approximate first-load total is ~1.5 MB of JS (uncompressed). For metered-link or low-bandwidth deployments, consider `--viz-disable` as a default and enabling it selectively for ops staff.

**Reverse-proxy deployment constraint.** The page hard-codes static asset paths (`/static/three.module.min.js`, `/static/three-orbit-controls.js`, `/static/yuzu-viz.js`) and the API path (`/api/v1/viz/fleet/topology`). Sub-path proxy deployments (e.g. nginx `location /yuzu/`) are NOT supported — the absolute paths would 404 against the rewritten origin. Mount Yuzu at the root path of its host or a fronting domain.

**Cache posture.** The `/viz/fleet` page response sets `Cache-Control: no-cache, no-store, must-revalidate` so a server upgrade cannot leave operators with a stale page that references the new vendored assets (which themselves cache for 24 hours via `max-age=86400`). The vendored asset bundles are content-addressed by server binary version — a fresh page revalidation after upgrade picks up any bundle changes immediately.

**Kill switch behaviour.** `--viz-disable` / `YUZU_VIZ_DISABLE` disables the **whole feature**: the REST/fragment endpoints, the per-host drill-down routes, **and** the `/viz/fleet` and `/viz/host/<id>` page shells all return `503` (a plain-text "fleet visualization is disabled by an administrator" body). An operator who sets the flag will not see a half-working page. The static asset routes (`/static/yuzu-viz.js` etc.) are not gated — they are inert without the page — so gating them at a reverse proxy is optional, not required. The kill switch is **boot-time only** (seeded from config at startup); there is no runtime toggle, so disabling viz under a live incident requires a server restart.

**Sizing and capacity.** Push-based ingestion holds one `RawAgentSnapshot` per agent in an in-memory `pushed_` map. Per-agent footprint is bounded by the parser caps (4096 processes + 4096 connections per snapshot, ~1–2 MB worst case, typically 5–20 KB). The map is hard-capped at **100 000 agents** (`kPushedMapHardCap`); at the cap, a new agent's push evicts the least-recently-seen entry (LRU by server receipt time) and emits a `topology.push.evicted_for_cap` audit event. Watch `yuzu_viz_pushed_map_size` and alert before it approaches the cap. The store is **in-memory only** — on server restart it is empty until agents re-push (recovery window ≈ one agent push cycle, ~30–60 s); the pull-based dispatch fetcher serves as the cold-start fallback during that window.

**Permission model.** The page route is auth-gated only (`require_auth`); the data fetch at `GET /api/v1/viz/fleet/topology` enforces `Response:Read`. An operator with a session but without `Response:Read` can land on the page (sees the grid and the "Access denied" overlay when the JS fetch fires) but every JSON fetch returns 403. The `viz.fleet_topology` audit row is emitted on the API path, not the page path — auditors querying "who accessed fleet visualization?" should filter on the `FleetTopology` `target_type` (covered in detail in `audit-log.md`).

**Browser-side errors are not server-logged.** WebGL context loss, module-fetch 503, and importmap-resolution failures surface only in the operator's browser console. A future polish PR will add a client-error beacon; today, support engineers diagnosing "viz is blank" reports should ask for a screenshot of the browser console.

**Per-host drill-down (`/viz/host/<agent_id>`).** Double-clicking a cube
opens a new tab with a 2D bipartite IPC graph (processes + sockets,
Cytoscape `cose` layout) above the existing TAR process tree, with
cross-pane select-to-highlight and a resizable splitter. The page route
is auth-gated only; the data fetch (`GET /api/v1/viz/host/<agent_id>/topology`)
enforces `Response:Read` and honours the `--viz-disable` kill switch.
Audit rows are emitted as `viz.host_topology` (`target_type = HostTopology`).
The `agent_id` path segment is allow-listed to `[A-Za-z0-9._-]` before
templating; any other character returns `400`.

**Connection window — `fleet_snapshot_window_seconds` (TAR plugin config).**
`tar.fleet_snapshot` reports not only the connections ESTABLISHED at the
exact `/proc` sample instant but also connections TAR observed recently
in its `tcp_live` warehouse, so short-lived flows still reach the viz.
The look-back window is operator-tunable via the TAR plugin's KV config
key `fleet_snapshot_window_seconds` (default `3600`). It is a TAR plugin
config key, not a server CLI flag — set it through the TAR plugin's
configuration surface. The 60 s sampler still cannot see sub-interval
connections; that needs kernel eventing (tracked separately).

### vNEXT — Agent interval triggers now functional

`yuzu_register_trigger` / `yuzu_unregister_trigger` were previously no-op
stubs — no `TriggerEngine` was instantiated on the agent, so interval
triggers were silently discarded and never fired. As a result the TAR
warehouse `*_live` tables (`tcp_live` and friends) sat permanently empty
in the field, and any plugin that registered an interval trigger had it
silently dropped.

**Upgrade caveat.** After upgrading the **agent** daemon, registered
interval triggers begin firing for the first time. On the first
`collect_fast` cycle (default 60 s) the TAR `*_live` tables start
populating, and operators may see a small increase in per-agent CPU/IO
proportional to the number of registered triggers. Any plugin that
registered an interval trigger expecting the old no-op behaviour will now
have that trigger fire — this is the fix, not a regression. Server-only
upgrades are unaffected; the change is entirely agent-side.

### vNEXT — Plugin code signing (#80)

Plugin signature verification ships in two parts: an agent-side CMS verifier and a server-side Settings UI for managing the trust bundle. **Default behaviour is unchanged** — agents that do not pass `--plugin-trust-bundle` and operators that do not upload a bundle through the new Settings card see identical behaviour to prior releases (allowlist-only, sha256 hash check).

**New on-disk artifact.** `<cert-dir>/plugin-trust-bundle.pem` (Linux/macOS: `/etc/yuzu/certs/plugin-trust-bundle.pem`; Windows: `C:\ProgramData\Yuzu\certs\plugin-trust-bundle.pem`). Server-managed via Settings → Plugin Code Signing. **Back this up alongside `auth.db`.** A backup that captures the SQLite databases but not the cert dir restores `plugin_signing_required=true` (in `runtime_config`) without the trust bundle file — agents fetching the policy will receive a 500 and require-mode agents will reject every plugin until the bundle is restored.

**Cert-dir collision check.** The server now treats this filename as authoritative. If a prior deployment placed an unrelated PEM at this exact path for a different purpose, it will be interpreted as the plugin trust bundle on first read. This is unlikely (the filename was unused before this release) but worth confirming before upgrade. Run `ls <cert-dir>/plugin-trust-bundle.pem` and rename the file if it pre-exists for any other purpose.

**New `runtime_config` key.** `plugin_signing_required` (string `"true"` or `"false"`). Set via the Settings card; reading and writing the key directly via the runtime-config REST surface is supported but not recommended — the Settings UI guarantees the disk-and-DB invariants (two-phase clear, file-presence-equals-enabled).

**New audit actions.** `plugin_signing.bundle.uploaded`, `plugin_signing.bundle.cleared`, `plugin_signing.require.changed` — see `audit-log.md` for the result and detail conventions. SIEM rules already filtering on `success`/`failure`/`denied` will pick these up unchanged; no new vocabulary tokens.

**Operator distribution.** The server hosts the bundle at `GET /api/v1/agent/plugin-policy` (admin-only). Agents are pointed at a local copy via `--plugin-trust-bundle <path>`; the manual workflow today is `curl` + `jq` + write the JSON's `trust_bundle_pem` field to disk on each agent host. Automatic agent-side fetch is a forthcoming change.

**Fleet-suicide caveat.** The Yuzu release pipeline does not yet sign the 44 in-tree plugins under `agents/plugins/`. **Do NOT enable "Require signed plugins" until you have signed every plugin your fleet uses, including the in-tree ones.** Use the transitional mode (bundle uploaded, Require off) during rollout. The Settings card surfaces this warning inline.

### vNEXT — Response templates (#254, Phase 8.2)

Phase 8.2 ships named response-view configurations attached to each `InstructionDefinition`: a column subset, sort order, and filter presets the dashboard's filter-bar **View** dropdown surfaces. The feature is purely additive — operators who never author a template see a synthesised `__default__` view that is byte-identical in behaviour to the prior "show all columns, sort by Agent" default.

**Schema migration.** `instruction_definitions` gains one column: `response_templates_spec TEXT NOT NULL DEFAULT '[]'`. The migration ledger advances from v2 to v3. `ALTER TABLE ADD COLUMN` with a constant default is O(1) in SQLite (metadata-only, no table rewrite); the migration is non-destructive.

**Pre-upgrade snapshot (recommended).** Take a backup of the InstructionStore database before upgrade:

```bash
cp /var/lib/yuzu/instructions.db /var/lib/yuzu/instructions.db.bak
# or, for a hot-running server, use SQLite's online backup:
sqlite3 /var/lib/yuzu/instructions.db ".backup /var/lib/yuzu/instructions.db.bak"
```

**Post-upgrade validation.**

```bash
sqlite3 /var/lib/yuzu/instructions.db \
  "SELECT version FROM schema_meta WHERE store='instruction_store';"
# expected output: 3
```

If the value is `2` instead of `3`, the migration did not run — check the server logs for `MigrationRunner: instruction_store migrated to v3` (or for a `probe-and-stamp failed` line in the InstructionStore section).

**Boot wedge recovery.** A corrupt schema_meta row or a pre-existing `response_templates_spec` column with a missing schema_meta v3 stamp will trip the probe-and-stamp guard, which fails closed (server logs `InstructionStore: probe-and-stamp failed; closing database`). To recover, restore the snapshot or apply the column manually:

```bash
# Stop the server first.
systemctl stop yuzu-server

sqlite3 /var/lib/yuzu/instructions.db \
  "ALTER TABLE instruction_definitions ADD COLUMN response_templates_spec TEXT NOT NULL DEFAULT '[]';"
sqlite3 /var/lib/yuzu/instructions.db \
  "INSERT OR REPLACE INTO schema_meta (store, version, upgraded_at) VALUES ('instruction_store', 3, strftime('%s','now'));"

systemctl start yuzu-server
```

**New audit actions.** `response_template.create`, `response_template.update`, `response_template.delete` — see `audit-log.md` for the failure-reason vocabulary. SIEM rules already filtering on `success`/`denied` will pick these up unchanged.

**Authoring caveats.** The dashboard YAML editor's lightweight line-scanner does not extract `spec.responseTemplates` into the indexed column; author through `POST /api/v1/definitions/import` (JSON envelope) or the REST template endpoints. Imported templates with the reserved `id: __default__` are silently dropped during normalisation.

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
| Multi-Factor Authentication | `/fragments/settings/mfa` | Per-operator TOTP enrollment + recovery codes. Admin-only in this release. Self-service for the logged-in admin only; to clear another (locked-out) user's MFA use the audited break-glass CLI `yuzu-server --mfa-reset <username>` — see `docs/ops-runbooks/auth-db-recovery.md` § Emergency MFA disable. |
| Enrollment Tokens | `/fragments/settings/tokens` | Generate and revoke tokens for Tier 2 agent enrollment. |
| Pending Agents | `/fragments/settings/pending` | Approve or deny agents waiting in the Tier 1 approval queue. |
| Auto-Approval Policies | `/fragments/settings/auto-approve` | Define rules for automatically approving agents based on criteria (hostname pattern, IP range, etc.). |
| API Tokens | `/fragments/settings/api-tokens` | Create and revoke bearer tokens for REST API automation. |
| Plugin Code Signing | `/fragments/settings/plugin-signing` | Upload a PEM trust bundle for agent plugin CMS signature verification, toggle the require-signed-plugins flag, and remove the bundle. The trust bundle persists at `<cert-dir>/plugin-trust-bundle.pem`; the require flag persists in `runtime_config` under key `plugin_signing_required`. Distribution to agents is operator-driven today (curl into a local file referenced by `--plugin-trust-bundle`); automatic agent-side fetch is a forthcoming change. See the user-manual *Agent Plugins → Plugin Code Signing* section. |
| OTA Updates | `/fragments/settings/updates` | Upload agent binaries, view available versions, promote a version to production. |
| Tag Compliance | `/fragments/settings/tag-compliance` | View compliance summary across the fleet based on tag-driven policies. |
| RBAC Management | *(planned -- no fragment yet)* | Enable or disable RBAC enforcement, create and manage roles. RBAC is enforced via `RbacStore` and the `/api/v1/rbac/*` REST API, but has no Settings page fragment yet. |
| OIDC SSO / Directory | `/fragments/settings/directory` | Configure OIDC single sign-on (issuer, client ID, secret, admin group). Editable form with "Test Connection" button. Changes persisted to runtime config and survive restart. |
| Internal CA | `/fragments/settings/ca` | View the built-in Certificate Authority (algorithm, SHA-256 fingerprint, expiry), download the CA certificate + CRL, browse the issued-certificate inventory, and revoke a certificate. `Security:Read` to view, `Security:Delete` to revoke. |
| DEX Alerts | `/fragments/settings/dex-alerts` | Route individual DEX signal types to operator notifications and the `dex.signal` webhook, tune the fleet blast-radius thresholds (min devices / window / cooldown), and set the per-cohort Prometheus gauge **export tag key**. Admin-only; changes apply live (no restart) and are audit-logged (`settings.dex_alerts.routing`, `settings.dex_alerts.blast`, `settings.dex_alerts.cohort_export`). See the user-manual *DEX → Routing signals to alerts* and *DEX → Fleet performance rollup* sections. |

### Revoking an agent certificate from the dashboard

When the server runs its built-in CA, **Settings → Internal CA** lists every
issued certificate. To revoke one (e.g. a decommissioned or compromised agent):

1. Find the agent's row in the inventory (match on **Subject** = `agent_id` or
   the **Serial**).
2. Optionally type a **reason** (e.g. `key compromise`, `decommissioned`) — it is
   stored on the revocation record and audited.
3. Click **Revoke** and confirm. The panel refreshes in place showing the cert as
   *Revoked* and the public CRL is republished automatically.

Revocation takes effect **immediately server-side**: the agent is refused on its
next connection, and any already-open command stream is torn down by the
revocation sweep within ~15s. A revoked agent cannot re-enroll its way back by
deleting its key (re-issuance is refused while the revocation stands). The same
operation is available over REST (`POST /api/v1/ca/revoke`) for automation. The
dashboard action is CSRF-protected and requires `Security:Delete`.

> **Gateway-proxied agents:** revocation is enforced on direct-connect agents
> only — an agent reaching the server through a gateway presents its cert to the
> gateway, not the server, so also disconnect it at the gateway. See
> `docs/auth-architecture.md` "Gateway-proxied agents: revocation scope".

---

## TLS Configuration

The Yuzu server has **two independent TLS surfaces**:

1. **HTTPS** — the dashboard and REST API (port 8443 by default). Configured via `--https-cert` / `--https-key` (or runtime via the Settings page). Disabled with `--no-https`.
2. **gRPC TLS** — the agent listener (port 50051) and the management listener (port 50052). Configured via `--cert` / `--key` / `--ca-cert` (and optionally `--management-cert` / `--management-key` / `--management-ca-cert` for a separate management cert). Disabled entirely with `--no-tls`.

The two surfaces are configured separately and can be in different states (e.g., HTTPS enabled but gRPC TLS disabled for a local UAT against a remote dashboard).

### HTTPS via CLI Flags

HTTPS is enabled by default. Pass `--https-cert` and `--https-key` at server startup. Use `--no-https` for development without TLS. See [Server CLI Flags](#server-cli-flags).

### gRPC TLS via CLI Flags

The recommended posture is **mutual TLS (mTLS)** — the server presents a certificate and verifies a client certificate from each connecting agent:

```bash
./yuzu-server \
  --cert /etc/yuzu/grpc-server.crt \
  --key  /etc/yuzu/grpc-server.key \
  --ca-cert /etc/yuzu/agent-clients-ca.crt
```

If you have not yet stood up a CA for issuing agent client certificates, you have two fallback options:

**Option 1 — One-way TLS** (server cert is presented but client certs are not verified):

```bash
export YUZU_ALLOW_INSECURE_TLS=1   # required as a second confirmation
./yuzu-server \
  --cert /etc/yuzu/grpc-server.crt \
  --key  /etc/yuzu/grpc-server.key \
  --insecure-skip-client-verify
```

This applies to **both** the agent listener and the management listener. The server emits an ERROR-level startup banner and a 5-minute recurring reminder log line for the duration the listener runs in this mode. An audit event with action `server.tls_degraded` is also written every 5 minutes for SOC 2 evidence.

**Option 2 — `--no-tls`** (no encryption, no peer authentication, plaintext gRPC):

```bash
./yuzu-server --no-tls
```

This is the supported posture for **local UAT, customer demos, and development**. The administrative surface is ungated — anyone reachable on port 50052 can issue management RPCs. The server emits a multi-line ERROR-level startup banner and a 5-minute recurring reminder. Do not run `--no-tls` against any network you do not control end-to-end.

### Upgrade note (v0.12.0)

The `--allow-one-way-tls` flag was renamed to `--insecure-skip-client-verify` AND now requires `YUZU_ALLOW_INSECURE_TLS=1` in the environment as a second confirmation. **Existing deployments that pass `--allow-one-way-tls` (or the new flag name) will refuse to start after upgrade until the env var is set.** The old flag name remains accepted with a deprecation warning for one release.

For systemd-managed deployments, add the env var via a drop-in:

```bash
sudo systemctl edit yuzu-server   # creates /etc/systemd/system/yuzu-server.service.d/override.conf
```

```ini
[Service]
Environment="YUZU_ALLOW_INSECURE_TLS=1"
```

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

> **Breaking change in v0.12.0** — the `role` field is **ignored** on
> create. New users are always created as `user`. To grant admin, use
> the **Change Role** button on the user's row, or `POST
> /api/settings/users/{username}/role` programmatically. This is a
> deliberate split (security finding C1): collapsing role assignment
> into the create endpoint allowed a 4xx-on-create + audit-as-success
> pattern that operators couldn't audit cleanly. Each role transition
> now produces a single `user.role_change` audit event with `old_role`
> and `new_role` recorded in the detail field.

### Changing a User's Role

1. Navigate to **Settings > User Management**.
2. Click **Change Role** next to the target user.
3. Pick `admin` or `user` and confirm.

The server emits an audit event on every branch:

| Branch | Audit `result` | Detail |
|---|---|---|
| Role changed | `success` | `old_role=user,new_role=admin` (or vice versa) |
| Same role requested | `no_op` | `same_role=admin` (or `user`) |
| Self-target rejected | `denied` | `self_role_change_blocked` |
| Invalid username | `denied` | `invalid_username` |
| Invalid JSON body | `denied` | `invalid_json` |
| Missing `role` field | `denied` | `missing_role` |
| Invalid role value | `denied` | `invalid_role` |
| User not found | `denied` | `user_not_found` |
| DB write failed | `denied` | `db_failure` |

> **You cannot change your own role.** The endpoint rejects self-target
> with HTTP 403, audited as `denied:self_role_change_blocked`. The same
> motivation as the self-delete guard: prevent an operator from locking
> themselves out via a misclick or scripted demotion.

> **Active sessions are invalidated atomically.** After a successful
> `user.role_change`, every active session for the target user is
> destroyed; the user must re-authenticate to pick up the new role.

### Deleting a User

1. Navigate to **Settings > User Management**.
2. Click **Remove** next to the target user.
3. Confirm the deletion.

> **Note:** You cannot delete your own account. The Users table renders
> the text "Current user" in place of the **Remove** button for the
> currently authenticated operator's row, and the server rejects any
> hand-crafted `DELETE /api/settings/users/<your-username>` request with
> HTTP 403 and a `Cannot delete your own account` toast. This prevents
> a misclick — or a scripted revoke loop — from dropping the only
> credential on the running server and locking every operator out
> until the process is restarted against its on-disk config. To remove
> the account you are signed in as, first create a second admin, log
> out, log in as the second admin, and delete the original.

---

### Force-logging out a user (incident response)

Use this when an account credential is suspected of compromise but the
account itself should remain functional (the user reports a stolen
laptop but still needs to keep working from a clean device, or a
short-lived contractor's badge is being rotated).

1. Navigate to **Settings > User Management**.
2. Click **Revoke sessions** next to the target user.
3. Confirm the blast-radius warning. The user's active dashboard
   sessions end immediately; their account remains intact and they
   can re-authenticate normally.

The audit log records `session.revoke_all` with `target_id=<username>`,
`target_type=User`, and `detail=count=<N>` where N is the number of
in-memory cookie sessions wiped. The action is also surfaced on the
`yuzu_auth_sessions_revoked_total{caller="admin",scope="cookies"}`
Prometheus counter — a sustained spike there is the operator's
automated alert for either a real incident response in progress or
a misbehaving automation script.

> **API tokens are not revoked by this flow.** Use it for a leaked
> session cookie. If the user's API tokens are also implicated, either
> revoke them individually via Settings → API Tokens or instruct the
> user to click **Sign out everywhere** themselves (see below), which
> revokes both cookies and tokens.

> **Verify persistence after a partial failure.** If the response body
> reports `db_persisted: false` (or the audit row shows `result=partial`
> with `db_error=true`), the in-memory wipe succeeded but the
> persisted `auth.db` rows survive. A server restart will resurrect
> those sessions. Either retry the revoke after the DB lock clears, or
> see `docs/ops-runbooks/auth-db-recovery.md` for emergency manual
> revocation via the SQLite CLI.

### Self-service "Sign out everywhere"

Any user — not just admins — can wipe every credential bearing their
identity by clicking the **Sign out everywhere** button on their own
row in Settings → Users. Unlike the admin **Revoke sessions** button,
this revokes BOTH cookie sessions AND every API token the user owns
(the lost-laptop scenario must kill every credential, not just
browser cookies). After the request the page redirects to `/login`
and the response clears the session cookie via `Set-Cookie: Max-Age=0`.

> **MCP-tier and service-scoped tokens cannot self-revoke.** Those
> credential classes have no other write privilege; accepting a
> self-revoke from one would create a novel DoS surface against the
> human owner. The endpoint returns 403 and the audit row records
> `session.revoke_all.self` with `result=denied`. Use the dashboard
> from a password-authenticated session.

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

## PostgreSQL Substrate

The server's storage substrate is **PostgreSQL** (ADR-0006/0007; the agent stays SQLite). As of the cut-over (#1320 PR 3) the server **requires a reachable database at boot and fails closed without one** — it constructs a shared connection pool at startup and, if `--postgres-dsn` / `YUZU_POSTGRES_DSN` is unset or the database is unreachable, **refuses to start and exits non-zero** (no SQLite fallback for the server). There is a distinct `[PG] Refusing to start` log line so the cause is unambiguous in `systemd` / `kubectl` logs.

> **Upgrade action (BREAKING):** before upgrading to this release, provision PostgreSQL and set `YUZU_POSTGRES_DSN`. Docker Compose deployments already bundle the `postgres` service and wire the DSN (no action beyond pulling the new images). Native installs must run the provisioning helper below (or point the DSN at a managed PostgreSQL 16+) **first** — otherwise the upgraded server will not boot. Restore pairing (ADR-0010): a database restore must be paired with the matching `--ca-dir` / key-directory restore.

**Connection-pool sizing.** The server opens up to `--postgres-pool-size` / `YUZU_POSTGRES_POOL_SIZE` connections (default **16**). Each heartbeat persists last-seen with one short-lived lease (≈33/s at 1 000 agents on a 30 s heartbeat — well within 16), and `/viz/fleet` draws one. Raise the size for large fleets (rule of thumb: +1 per ~1 000 agents beyond 5 000, plus headroom per additional Postgres-backed store as they migrate) or for a slow managed-PG link. Tune against the `yuzu_pg_pool_in_use` / `yuzu_pg_pool_size` gauges and the `yuzu_pg_acquire_wait_seconds` histogram (the leading saturation signal); the bundled alert rules (`YuzuPgPoolSaturated`, `YuzuPgAcquireWaitHigh`, `YuzuPgConnectFailing` in `docs/prometheus/yuzu-alerts.yml`) fire before `/readyz` is affected. The heartbeat upsert is best-effort with a 250 ms acquire deadline, so a saturated pool degrades the stale-host display, never the live fleet.

**`endpoint_state` is reconstructible.** The `endpoint_state` schema (last-known offline-host display) is pure cache — the server repopulates it from heartbeats within one cycle (~30 s). A targeted restore may safely omit it; only the secret-bearing schemas and live operational data need the paired key-directory restore above.

### Provisioning a native (non-container) install

Docker Compose deployments get PostgreSQL automatically — every tracked compose bundles a `postgres` service (the `ghcr.io/tr3kkr/yuzu-postgres` image: PostgreSQL 18 + pgvector + first-boot role/database init). Native installs use the provisioning helper instead:

| Install method | Helper location | Invocation |
|---|---|---|
| `.deb` / `.rpm` | `/usr/share/yuzu/scripts/install-server-postgres.sh` | Run automatically (non-fatally) by the package post-install hook |
| Release tarball | `scripts/install-server-postgres.sh` inside the archive | Run manually as root after unpacking |
| Git checkout | `scripts/install-server-postgres.sh` | Run manually as root |

Two modes:

```bash
# Mode 1 — external/managed Postgres: writes the DSN to
# /etc/yuzu/yuzu-server.env (0600), which the systemd unit loads
# via EnvironmentFile=. No local Postgres is touched.
sudo bash install-server-postgres.sh --dsn 'postgresql://yuzu:...@db.example.com:5432/yuzu'

# Mode 2 (default) — local Postgres: provisions the app role + database
# on an already-installed local PostgreSQL 16+ and writes the DSN env file.
# Idempotent — never clobbers an existing role, database, or env file.
sudo bash install-server-postgres.sh
```

The helper is **non-fatal when no local cluster is found** (prints install hints and exits 0) — this posture flips to a hard failure when the server starts requiring the DSN. The app role's credential is freshly random and never shared with the `postgres` superuser. Per-store schemas are *not* created by the helper; the server's migration runner owns those at startup (ADR-0008).

### Backing up PostgreSQL state

The SQLite backup guidance in [Configuration Files](#configuration-files) continues to apply while stores migrate incrementally — during the transition, a complete backup covers **both** the remaining SQLite stores **and** the Postgres database.

Use `pg_dump` (logical, consistent-by-construction — safe against a live database, unlike filesystem copies).

**Native installs** — the DSN lives only in the root-only systemd environment file (`/etc/yuzu/yuzu-server.env`), **not** in interactive shells, so load it first. Then split the password out so it rides the `PGPASSWORD` environment variable instead of the process argv (`/proc/<pid>/cmdline` is world-readable, and the command lands in shell history):

```bash
# Run as root. Assumes the standard helper-written DSN shape
# scheme://user:password@host:port/db.
. /etc/yuzu/yuzu-server.env
export PGPASSWORD="$(printf '%s\n' "$YUZU_POSTGRES_DSN" | sed -E 's!^[a-z]+://[^:/@]*:([^@]*)@.*$!\1!')"
DSN_NOPASS="$(printf '%s\n' "$YUZU_POSTGRES_DSN" | sed -E 's!^([a-z]+://[^:/@]*):[^@]*@!\1@!')"

pg_dump --format=custom --file="yuzu-pg-$(date +%F).dump" "$DSN_NOPASS"
```

**Docker Compose** (reference template — superuser peer auth inside the container; no credential on the host command line):

```bash
docker exec yuzu-postgres pg_dump -U postgres --format=custom yuzu \
  > "yuzu-pg-$(date +%F).dump"
```

Restore with the server stopped, then start the server (the migration runner reconciles schema versions at boot). On a **fresh disaster-recovery target**, the app role and database must exist before `pg_restore` — run `install-server-postgres.sh` (or your managed-DB provisioning) first:

```bash
# Native — same env-file + PGPASSWORD/DSN_NOPASS preamble as the backup recipe
pg_restore --clean --if-exists --no-owner --role=yuzu \
  --dbname="$DSN_NOPASS" "yuzu-pg-YYYY-MM-DD.dump"

# Docker Compose
docker exec -i yuzu-postgres pg_restore --clean --if-exists --no-owner \
  --role=yuzu -U postgres --dbname=yuzu < "yuzu-pg-YYYY-MM-DD.dump"
```

Schedule the dump alongside the existing SQLite/cert-dir backups; verify restores periodically against a scratch database (`createdb yuzu_restore_test && pg_restore --dbname=... `).

### Key management (secrets KEK)

Secret columns in PostgreSQL are **envelope-encrypted app-side** (ADR-0010): each value is sealed under a fresh data-encryption key (DEK), and the DEK is wrapped by the install's key-encryption key (KEK). The KEK is a 32-byte key file generated on first boot (`secrets-kek-v1.key`, mode 0600, in the same key directory as the CA root key — `--ca-dir`, default `/etc/yuzu/certs` on Linux/macOS, `C:\ProgramData\Yuzu\certs` on Windows) and **never enters the database** — `kek_meta` in the `secrets` schema records only non-secret fingerprints (key-check values), which the server verifies against the key files at every boot.

> The encryption machinery ships ahead of its consumers: as of this release **no store writes secret columns yet** — the gated stores (`auth` TOTP secrets, `webhooks`, `offload_targets`, the OIDC client secret) adopt it as each migrates to Postgres. Set your backup procedure up for the pairing below **now** so those migrations don't invalidate it.

**The restore-pairing invariant.** `pg_dump` output and volume snapshots contain **ciphertext and wrapped DEKs only** — a database backup alone recovers no secrets, and a database restore is unusable without the matching keys directory. DB backups and keys-dir backups are a *pair*: back them up on the same schedule, restore them **together**, and keep a separate offline copy of the KEK file exactly like the CA root key. The restore-verification drill must restore both halves and confirm a clean boot — the server checks every registered KEK fingerprint at startup and **fails closed** rather than serving with unreadable secrets. The failure classes below are stable error *prefixes* at the start of the fatal startup message (match the prefix in the message text when writing log-scraping alerts; they are not structured log fields):

| Startup error prefix | Meaning | Recovery |
|---|---|---|
| `kek_unresolvable` | A registered KEK version has no key file. Causes: keys dir older than the DB (backup skew), wrong keys directory, or a second server instance pointed at the same database (unsupported — one KEK per database). | Restore the keys directory from the backup *paired* with this database. |
| `kek_corrupt` | The key file exists but does not match its registered fingerprint (torn/corrupt file or foreign key material — **not** row tamper). | Same: restore the paired keys directory. |
| `provider_failure` | CSPRNG or key-storage failure during KEK generation or check-value computation (first boot / rotation). | Check the keys directory is writable and system entropy is healthy; if a prior first boot crashed, the message names the torn file to delete. |
| `db_error` | Postgres connection/transaction failure during the `secrets` schema migration or `kek_meta` read/write. | Check the DSN and Postgres service health — triage as "DB down", not key loss. |

**Rotation** mints `secrets-kek-v<N+1>` and re-wraps only the small wrapped-DEK header of each stored blob — payloads are untouched, so rotation is cheap, incremental, and interruptible (a crash resumes by re-running the re-wrap; already-rotated rows are detected by the blob header; a crash *before* the new version's fingerprint registers leaves an orphan key file that the next rotation attempt safely adopts). Rotation is complete when no stored blob references the old version (`oldest_kek_version_in_use`); only then may the old version be **retired** — the server refuses to retire a version that is active or still referenced, and records retirement in `kek_meta` as destruction evidence. Do not delete an old KEK file by hand while any backup you intend to honour still contains blobs wrapped under it — a restored backup needs the KEK versions its rows reference. The operator-facing rotation procedure (CLI/REST surface + DR drill cadence) lands with the first secret-bearing store migration and is tracked in #1341.

Decrypt failures are counted per store and failure class as `yuzu_server_secret_decrypt_failures_total{store, failure_class}` (classes: `tag_mismatch`, `kek_unresolvable`, `malformed_blob`, `crypto_failure`) once the codec is wired into a serving store. A sustained non-zero `kek_unresolvable` rate after a deployment or restore is the primary backup-skew alert signal; a single-row `tag_mismatch` is the tamper signal and warrants investigation, not retry.

**Break-glass (KEK permanently lost).** KEK loss is painful, never a total lockout: admin sign-in survives by design (MFA recovery codes are verify-only hashes and need no KEK — sign in with a recovery code and re-enroll TOTP), and every gated secret class is re-enrollable/re-issuable (webhook secrets re-issued, offload credentials re-issued, OIDC client secret re-pasted). The explicit voided-secrets boot flag described in ADR-0010 ships with the first secret-bearing store migration.

---

## Retention Settings

The server applies retention policies to stored data to manage disk usage. Retention values are set via CLI flags at startup.

| Data Type | CLI Flag | Default TTL | Description |
|---|---|---|---|
| Instruction responses | `--response-retention-days` | 90 days | Results from executed instructions. Older responses are purged on a daily schedule. |
| Audit log entries | `--audit-retention-days` | 365 days | Records of who did what, when, and on which devices. |
| Guardian (Guaranteed State) events | `--guardian-event-retention-days` | 30 days | Guaranteed State drift events, remediation events, and agent-sync events written by the Guardian engine. See [Guaranteed State](guaranteed-state.md) for the feature context. |

Reducing the TTL frees disk space; increasing it preserves history for compliance.

> **Note:** All three retention values can also be set via environment variables (`YUZU_RESPONSE_RETENTION_DAYS`, `YUZU_AUDIT_RETENTION_DAYS`, `YUZU_GUARDIAN_EVENT_RETENTION_DAYS`) and can be updated at runtime via `PUT /api/v1/config/<key>` with an `Infrastructure:Write` permission. Runtime updates are persisted via `RuntimeConfigStore` and reflected immediately in the `/api/v1/config` GET response — **but the running store captures its retention value at construction time and does not re-read it, so TTL computation on new inserts continues to use the startup value until the next server restart.** This "takes effect on restart" limitation is shared across all three retention keys and is tracked as issue #483.

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

### DEX Alerts

| Method | Route | Description |
|---|---|---|
| `GET` | `/fragments/settings/dex-alerts` | Render the DEX alerts configuration fragment (HTMX). Admin-only. |
| `POST` | `/api/settings/dex-alerts/routing` | Update the routed signal types. Body: form-encoded `types=<obs_type>` repeated per checked type; values are allow-listed against the signal catalogue. Persisted to `runtime_config` key `dex_alert_routing` (sorted JSON array). Applied live. Audit: `settings.dex_alerts.routing` (detail records the full routed set). |
| `POST` | `/api/settings/dex-alerts/blast` | Update the blast-radius thresholds. Body: `min_devices`, `window_seconds`, `cooldown_seconds` (clamped server-side to `[2,100000]` / `[60,86400]` / `[0,604800]`). Persisted to the `dex_blast_*` keys. Applied live. Audit: `settings.dex_alerts.blast`. |
| `POST` | `/api/settings/dex-alerts/cohort-export` | Set (or clear) the cohort metrics export tag key. Body: `export_key` (tag-key alphabet `[A-Za-z0-9_.:-]`, max 64; empty disables — the default). When set, the per-cohort `yuzu_fleet_perf_cohort_*` Prometheus gauges are published for that key's cohorts (top 50 by population, 10-device floor, `yuzu_fleet_perf_cohort_clipped` makes capping visible). Persisted to `dex_cohort_export_key`. Applied on the next gauge sweep. Audit: `settings.dex_alerts.cohort_export`. |

**New `runtime_config` keys.** All are runtime-set via the DEX Alerts panel and applied live (and re-applied at boot):

| Key | Type | Default | Description |
|---|---|---|---|
| `dex_alert_routing` | JSON array string | `[]` | DEX `obs_type` strings routed to operator notifications + the `dex.signal` webhook. Empty = nothing routed. |
| `dex_blast_min_devices` | integer string | `5` | Blast-radius minimum distinct-device threshold. Clamped `[2, 100000]`. |
| `dex_blast_window_seconds` | integer string | `900` | Blast-radius detection window (seconds). Clamped `[60, 86400]`. |
| `dex_blast_cooldown_seconds` | integer string | `3600` | Blast-radius per-incident re-alert cooldown (seconds). Clamped `[0, 604800]`. |
| `dex_cohort_export_key` | tag-key string | *(empty)* | Tag key whose cohorts export as `yuzu_fleet_perf_cohort_*` Prometheus gauges. Empty = export disabled. Invalid stored values disable the export (fail closed). |

**New audit actions.**

| Action | Emitted when |
|---|---|
| `settings.dex_alerts.routing` | An admin changes the routed signal-type list. Detail records the full new routed set (the runtime-config store keeps no history, so this row is the change-management evidence). |
| `settings.dex_alerts.blast` | An admin changes the blast-radius thresholds (detail records the new min/window/cooldown). |
| `settings.dex_alerts.cohort_export` | An admin sets or clears the cohort metrics export tag key (detail records the new key, or "export disabled"). |
| `dex.device.perf.query` | An operator loads a device performance sparkline panel (DEX device drill-down). Execute-gated; detail records the target agent and command id. |
| `dex.device.procperf.query` | An operator loads a device's per-application panel (usage-class telemetry — deliberately a separate verb from the machine-health `dex.device.perf.query` so usage reads stay separately countable). Execute-gated; detail records the target agent and command id. |

---

## File Logging

Yuzu writes logs to stdout by default. File logging is opt-in via `--log-file`, with a best-effort fallback at the platform default path (`/var/log/yuzu/server.log` on Linux, `C:\ProgramData\Yuzu\logs\server.log` on Windows, `~/Library/Logs/Yuzu/server.log` on macOS).

| Path | Behaviour | Failure mode |
|---|---|---|
| `--log-file <path>` (explicit) | Writes to `<path>` in addition to stdout. | If the file/directory cannot be opened, server logs an ERROR and continues without file logging. |
| Platform default path (implicit) | Writes to the platform default path if it exists and is writable. | If the directory cannot be created or the file cannot be opened, server logs a single INFO line and continues without file logging. The default fallback is best-effort observability, not load-bearing. |

The Docker server image pre-creates `/var/log/yuzu` (mode 0750, owned by the `yuzu` user) so the implicit default path works out of the box. When mounting an external host volume at `/var/log/yuzu`, ensure the host directory is owned by the same UID as the in-container `yuzu` user (verify with `docker exec yuzu-server id yuzu`); a wrong-ownership mount silently degrades to stdout-only logging.

## Health Endpoints

Yuzu exposes four HTTP probe endpoints for orchestrators, load balancers, and monitoring integrations. All four are unauthenticated and exempt from the API rate limiter.

| Path | Use case | Body | Draining-aware |
|---|---|---|---|
| `/livez` | Kubernetes liveness probe — fast check that the HTTP listener is up. | `{"status":"ok"}` | No |
| `/readyz` | Kubernetes readiness probe — covers per-store migration completion AND graceful-shutdown drain. | `{"status":"ready"}` (200), `{"status":"draining"}` (503), or `{"status":"not ready","failed_stores":["api_token_store", ...]}` (503) when a store's database failed to open at startup | **Yes** |
| `/health` | Monitoring dashboards (Prometheus blackbox exporter, Datadog, Nagios). Rich JSON with per-store status, agent counts, execution stats, and version. | Structured JSON — see [REST API: Health](rest-api.md#health). | No |
| `/api/health` | Identical alias of `/health`, provided for monitoring integrations that prefix every REST call with `/api/`. Restored in v0.12.0 (issue #620). | Identical to `/health`. | No |

**Choose the right endpoint for your use case.** Load balancers that should drain in-flight traffic during a rolling deploy MUST use `/readyz` — `/health` and `/api/health` continue returning 200 during shutdown by design (Kubernetes pattern: liveness/health probes are not draining-aware). Aggressive monitoring poll cadences (sub-second) should target `/livez` rather than `/health` to minimise per-probe SQLite touches.

## Deployment

Yuzu provides multiple deployment options: Docker Compose for quick setup, systemd units for bare-metal Linux, and a development stack script for local testing.

### Docker Compose

The default Docker deployment runs the server and agent standalone -- no gateway required. For scaled deployments with a gateway, see `docker-compose.full-uat.yml`.

**Files:**

| File | Description |
|---|---|
| `deploy/docker/Dockerfile.server` | Multi-stage build for the Yuzu server binary |
| `deploy/docker/Dockerfile.gateway` | Erlang/OTP build for the gateway node |
| `deploy/docker/docker-compose.yml` | Build-from-source dev stack (server + agent + monitoring) |
| `deploy/docker/docker-compose.reference.yml` | Copyable deployment template — pulls pinned ghcr.io images, uses a named `server-data` volume, carries inline TLS hardening + backup + rollback commentary. Requires operator hardening (TLS, bind address) before production use. |
| `deploy/docker/docker-compose.full-uat.yml` | Gateway deployment (server + gateway + monitoring) |
| `docker-compose.uat.yml` | Self-contained single-file UAT stack pulled from ghcr.io (server + gateway + Prometheus + Grafana + ClickHouse) |
| `deploy/docker/docker-compose.demo.yml` | Chiselled (FROM scratch) Ubuntu 26.04 sales-demo stack — server + gateway + N agent replicas, release-pinned. Entry point `scripts/start-demo.sh`; see `docs/demo-environment.md`. Not for production (runs `--no-tls` with a baked admin password). |

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
sudo cp build-linux/server/core/yuzu-server /usr/local/bin/
sudo cp build-linux/agents/core/yuzu-agent /usr/local/bin/

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
