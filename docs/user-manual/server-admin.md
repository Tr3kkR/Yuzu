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
12. [SAML 2.0 SP Configuration](#saml-20-sp-configuration)
13. [Data Storage and Encryption](#data-storage-and-encryption)
14. [PostgreSQL Substrate](#postgresql-substrate)
15. [NVD CVE sync](#nvd-cve-sync)
16. [Retention Settings](#retention-settings)
17. [Settings API Reference](#settings-api-reference)
18. [Deployment](#deployment)
19. [Windows Service Installation](#windows-service-installation)
20. [Planned Features](#planned-features)

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
| `--oidc-issuer` | *(none)* | OIDC identity provider issuer URL (e.g., `https://login.microsoftonline.com/{tenant}/v2.0`). Env: `YUZU_OIDC_ISSUER`. |
| `--oidc-client-id` | *(none)* | OIDC application (client) ID. Env: `YUZU_OIDC_CLIENT_ID`. |
| `--oidc-client-secret` | *(none)* | OIDC client secret. Env: `YUZU_OIDC_CLIENT_SECRET`. |
| `--oidc-redirect-uri` | *(auto)* | OIDC redirect URI. If omitted, auto-computed from the web address and port. Must match the registered redirect in your identity provider. Env: `YUZU_OIDC_REDIRECT_URI`. |
| `--oidc-admin-group` | *(none)* | Entra ID group object ID that maps to the admin role. Users in this group are granted admin access on OIDC login. Env: `YUZU_OIDC_ADMIN_GROUP`. (Value is trimmed automatically, same as `--saml-admin-group` — #1830.) |
| `--oidc-skip-tls-verify` | off | Disable TLS certificate verification for OIDC endpoints. **Insecure — dev only.** Env: `YUZU_OIDC_SKIP_TLS_VERIFY`. |
| `--saml-idp-entity-id` | *(none)* | **SAML 2.0 SP.** Entity ID URI of the IdP (must match what the IdP uses in its assertions). Required and validated at startup — omitting it (along with the other four `--saml-*` flags) leaves SAML disabled. Env: `YUZU_SAML_IDP_ENTITY_ID`. |
| `--saml-idp-sso-url` | *(none)* | **SAML 2.0 SP.** IdP's HTTP-Redirect SSO endpoint URL. Env: `YUZU_SAML_IDP_SSO_URL`. |
| `--saml-idp-cert` | *(none)* | **SAML 2.0 SP.** Filesystem path to the IdP's assertion-signing certificate (PEM, max 64 KiB). The cert at this path is the **sole** trusted signing authority — in-document `<KeyInfo>` values are ignored. Env: `YUZU_SAML_IDP_CERT`. |
| `--saml-sp-entity-id` | *(none)* | **SAML 2.0 SP.** Entity ID URI this SP advertises to the IdP in the AuthnRequest. Env: `YUZU_SAML_SP_ENTITY_ID`. |
| `--saml-sp-acs-url` | *(none)* | **SAML 2.0 SP.** Full public URL of the Assertion Consumer Service (`https://<host>/saml/acs`). The IdP must be configured to POST the response to this URL. Env: `YUZU_SAML_SP_ACS_URL`. |
| `--mcp-disable` | off | Disable the MCP (Model Context Protocol) endpoint entirely. When set, all requests to `/mcp/v1/` are rejected with a JSON-RPC error. Use this in air-gapped or high-security environments where AI integration is not desired. Env: `YUZU_MCP_DISABLE`. |
| `--mcp-read-only` | off | Restrict MCP to read-only tools only. Write and execute operations (Phase 2) are rejected even if the MCP token's tier would normally allow them. Env: `YUZU_MCP_READ_ONLY`. |
| `--mcp-no-streaming` | off | Disable the MCP **Streamable HTTP** transport (ADR-1005 Decision 15): no `Mcp-Session-Id` minting, `GET`/`DELETE /mcp/v1/` return `405`, and only plain JSON-RPC POST is served. The spec-required `202` status on notification POSTs still applies. Use where a buffering reverse proxy interferes with streaming. Env: `YUZU_MCP_NO_STREAMING`. |
| `--mcp-allowed-origin` | *(none)* | **Repeatable.** An allowed `Origin` header value (`scheme://host:port`, exact match) for `/mcp/v1/` DNS-rebinding defence. An **absent** `Origin` is always allowed (the endpoint requires a credential); an **empty allowlist rejects any *present* Origin** (secure default) — browser-based MCP clients must be listed explicitly, non-browser clients need no configuration. Env: `YUZU_MCP_ALLOWED_ORIGINS`. |
| `--max-sse-streams` | `128` | **Concurrent held-open SSE responses this server is sized for, across EVERY streaming surface** — `GET /mcp/v1/`, `GET /api/v1/events`, the dashboard executions drawer, and the legacy `/events` stream. The HTTP worker pool is derived *from* this number: cpp-httplib is thread-per-connection, so each held-open response pins one worker for its whole life. That thread burns no CPU, and its resident cost is a fraction of a stack reservation that is virtual and platform-dependent (8 MB on Linux/glibc, 1 MB on Windows, 512 KB for macOS secondary threads). The resident fraction itself is **not yet measured** on our platforms (ADR-0034), so treat the default as a starting point rather than a sizing guarantee until a per-platform baseline exists. Utilisation is `yuzu_http_held_open_responses / yuzu_http_held_open_capacity`. The ceiling is thread-count; see ADR-0034. Env: `YUZU_MAX_SSE_STREAMS`. |
| `--mcp-max-streams-per-principal` | `4` | Max concurrent MCP SSE streams for one principal. An **anti-monopoly policy, not a capacity limit** — capacity is `--max-sse-streams`. Stops a single agentic token taking the channel; does not ration the fleet. Env: `YUZU_MCP_MAX_STREAMS_PER_PRINCIPAL`. |
| `--http-worker-threads` | `0` (derive) | Pin the shared HTTP worker pool by hand. `0` derives it from `--max-sse-streams`, which is what you want. If you set it, the stream target is clamped to what your pool can actually carry (the startup log reports the effective figure). Env: `YUZU_HTTP_WORKER_THREADS`. |
| `--viz-disable` | off | Disable the fleet visualization feature. When set, the REST endpoints (`GET /api/v1/viz/fleet/topology`, `GET /fragments/viz/fleet/topology`, and the per-host drill-down routes) **and** the page shells (`GET /viz/fleet`, `GET /viz/host/<id>`) all return `503`. Tier-before-permission ordering: the kill switch takes effect even for callers who would otherwise fail RBAC. Two pieces of durable evidence that the switch took effect: the startup log line `[VIZ] viz endpoint disabled by configuration`, and a `server.viz_disabled` audit event (`target_type = FleetTopology`) written to the audit store at boot — so an auditor can confirm the disabled state from the audit trail even on a deployment with no viz traffic. Env: `YUZU_VIZ_DISABLE`. |
| `--allow-unsigned-packs` | off | **Dangerous.** Accept product packs at install without an Ed25519 signature. Default is to reject unsigned packs with `pack '<name>' is unsigned and signature enforcement is enabled (set --allow-unsigned-packs / YUZU_ALLOW_UNSIGNED_PACKS=1 to bypass)` (security-by-default since #802 / W7.4). Setting this flag restores the pre-W7.4 behaviour where any operator with pack-upload permission, or a MITM on pack delivery, could install a pack containing arbitrary `InstructionDefinition` or plugin payloads that would execute fleet-wide. Two pieces of durable evidence that the flag is active: a startup log line `[SECURITY] product pack signature enforcement DISABLED by configuration`, and a `server.unsigned_packs_allowed` audit event (`target_type = ProductPack`) written to the audit store at boot. Use only as a temporary migration aid; sign your packs and remove the flag as soon as feasible. Env: `YUZU_ALLOW_UNSIGNED_PACKS`. |
| `--allow-unsigned-definitions` | off | **Dangerous.** Accept `InstructionDefinition` imports via `POST /api/v1/instructions/import` without an Ed25519 signature. Default is to reject unsigned imports with `instruction-import is unsigned and signature enforcement is enabled (set --allow-unsigned-definitions / YUZU_ALLOW_UNSIGNED_DEFINITIONS=1 to bypass)` (security-by-default since #1073 / W7.4 sibling-gap closure). Closes the equivalent fleet-RCE surface that `--allow-unsigned-packs` covers on the ProductPack side: without enforcement, any operator with `InstructionDefinition:Write` (or a MITM on a content sync) can publish a definition that dispatches a malicious plugin invocation on every targeted agent. Durable evidence: startup log line `[SECURITY] instruction-definition signature enforcement DISABLED by configuration` AND a `server.unsigned_definitions_allowed` audit event (`target_type = InstructionDefinition`). Env: `YUZU_ALLOW_UNSIGNED_DEFINITIONS`. |
| `--mfa-enforcement` | `optional` | MFA enforcement mode: `optional` (users may enroll voluntarily; login never requires it), `admin-only` (an admin without MFA must enroll before login completes), or `required` (every role must enroll). Under `admin-only`/`required` an un-enrolled login is redirected through TOTP enrollment (`POST /login/mfa/enroll`) before a session is minted; the server logs an `INFO` line naming the active mode at startup. **Breaking:** earlier releases accepted `admin-only`/`required` as no-ops — if you staged the flag, read `docs/user-manual/upgrading.md` before upgrading (live enforcement begins immediately, and SSO users require an IdP that asserts `amr`). See `docs/user-manual/authentication.md` § Multi-Factor Authentication and `docs/auth-mfa-design.md`. Env: `YUZU_MFA_ENFORCEMENT`. |
| `--mfa-step-up-window-secs` | `300` | Seconds after a successful TOTP proof during which 11 high-risk REST + Settings endpoints (PR2 of the MFA ladder) accept the session as "stepped up" without re-prompting. Set to `0` to disable the gate entirely (emits a startup `WARN`). Env: `YUZU_MFA_STEP_UP_WINDOW_SECS`. |
| `--mfa-login-pending-secs` | `120` | Lifetime of the intermediate `mfa_pending_token` between password success and TOTP submission. The pending state is per-process (lost on restart, not shared across HA replicas without sticky sessions). Env: `YUZU_MFA_LOGIN_PENDING_SECS`. |
| `--mfa-reset <username>` | *(none)* | **Break-glass.** Clears the named user's MFA enrollment and exits **without starting the server** — the recovery path from MFA-enforcement lockout. Writes an `mfa.reset.breakglass` audit row (principal = the OS account that ran the CLI). Requires `--config` + `--data-dir`; no TLS flags needed. See `docs/ops-runbooks/auth-db-recovery.md` § Emergency MFA disable. |
| `--auth-lockout-threshold` | `5` | Consecutive failed **local-password** login attempts before an account is temporarily locked (SOC 2 CC6.3). A locked account returns the **same generic 401** as a bad password — no enumeration/lock-state oracle. Counter resets on a successful login or an admin unlock (`POST /api/v1/users/{name}/unlock`). Scope is local-password only — OIDC/SSO sessions and API tokens are unaffected. Setting `0` **disables** lockout (startup `WARN`) and constitutes a deviation from the CC6.3 hardened baseline — record it as a documented exception on your risk register, do not just flip it. NIST 800-63B §5.2.2 suggests allowing ≥10 attempts where network-layer rate-limiting is also present; raise the threshold accordingly if you front Yuzu with an IP throttle. Env: `YUZU_AUTH_LOCKOUT_THRESHOLD`. |
| `--auth-lockout-window-secs` | `900` | How long an account stays locked after the threshold is crossed. The lock **auto-expires** after this window — it is never permanent, so it cannot be weaponised to permanently deny a legitimate principal; a waited-out user regains a full attempt budget. Env: `YUZU_AUTH_LOCKOUT_WINDOW_SECS`. |
| `--jit-max-elevation-secs` | `3600` | **JIT admin elevation** maximum window (SOC 2 CC6.3/CC6.6). Caps the lifetime of a time-boxed admin elevation activated via `POST /api/v1/elevate`; a request asking for longer is clamped. Range 1–86400 (24h). Eligibility is the per-user `users.elevation_eligible` flag (admin-set via `POST /api/v1/users/<name>/elevation-eligibility`), elevation requires a fresh MFA step-up, and the grant is in-memory per cookie session (auto-reverts on lapse; a restart drops it). API/MCP tokens can never be elevated. Env: `YUZU_JIT_MAX_ELEVATION_SECS`. |
| `--jit-oidc-amr-elevation` / `--no-jit-oidc-amr-elevation` | `true` (enabled) | Whether an OIDC session whose IdP login attested MFA (the `amr` claim, seeding `Session::mfa_verified_at` at `/auth/callback`) can satisfy `POST /api/v1/elevate`'s mandatory second-factor requirement **without** local TOTP enrollment. An OIDC session never consults a local namesake account's TOTP enrollment — a single-factor (no-`amr`) OIDC session is **always** denied regardless of this flag. Pass `--no-jit-oidc-amr-elevation` to disable JIT elevation for OIDC sessions **entirely** — an OIDC session cannot present a local TOTP step-up (its step-up challenge is re-authenticating via SSO, not a TOTP code), so with the flag off an operator must switch to a local-authenticated session with local TOTP to elevate. A one-time INFO log line is emitted at boot when OIDC is configured and this flag is on. ⚠️ **This flag currently has no observable effect** — since the #1837/#1857 identity re-key, an OIDC session is denied JIT elevation at the eligibility gate (its `oidc:<iss>#<sub>` principal has no local `users` row), before the `amr` branch this flag controls is reached; OIDC elevation is restored by #1852. Env: `YUZU_JIT_OIDC_AMR_ELEVATION`. |
| `--session-inactivity-secs` | `0` | **Idle (inactivity) session timeout** (SOC 2 CC6.3). Seconds of inactivity after which an operator **dashboard cookie session** is invalidated server-side — a **sliding** window that resets on each authenticated request, *under* the absolute 8-hour session lifetime. `0` (default) **disables** it (only the absolute lifetime applies — existing deployments are unaffected); a recommended hardened value is `900` (15 min). Scope is cookie sessions only: **API tokens and MCP tokens are never idle-timed-out** (long-lived automation is unaffected); OIDC users simply re-authenticate via SSO. The active window is logged once at boot for evidence; a value ≥ the absolute 8-hour session lifetime (28800s) is accepted but elicits a startup `WARN` (the idle window can never fire before absolute expiry). Env: `YUZU_SESSION_INACTIVITY_SECS`. |
| `--auth-mode` | `standard` | Local-password login policy (SOC 2 CC6.3). `standard` = password login enabled. `sso-only` = **local-password login is disabled fleet-wide** — only OIDC SSO mints a session — so the server **refuses to start** unless OIDC is configured (`--oidc-issuer`). A rejected local login returns the **same generic 401** as a bad password (no oracle) and is counted via the metric `yuzu_auth_local_disabled_total` (metric, not a per-attempt audit row — avoids audit-flood under credential spray). A single `--break-glass-user` is exempt while armed. Env: `YUZU_AUTH_MODE`. |
| `--break-glass-user <username>` | *(none)* | The single local account exempt from `--auth-mode=sso-only`, exempt **only while armed** (see `--break-glass-arm`). Under `sso-only` the server **refuses to start** unless this account exists and has **MFA enrolled** (a break-glass account must carry a second factor). A break-glass login is forced through MFA regardless of `--mfa-enforcement` and writes an `auth.breakglass.login` audit row. Env: `YUZU_BREAK_GLASS_USER`. |
| `--break-glass-window-secs` | `86400` | Seconds the break-glass account stays armed after `--break-glass-arm` (default 24h). The arm **auto-expires** (evaluated lazily at login like the lockout window) — it is never a permanent standing exemption. Env: `YUZU_BREAK_GLASS_WINDOW_SECS`. |
| `--break-glass-arm` | off | **Break-glass.** Arms `--break-glass-user` for the configured window and exits **without starting the server** — the recovery path when the IdP is down under `--auth-mode=sso-only`. Run on the server host as the service account (arming deliberately does **not** require a session). Validates the account (exists + MFA), verifies the audit store is writable **before** arming, and writes an `auth.breakglass.armed` audit row (principal = the OS account that ran the CLI). Requires `--break-glass-user` + `--data-dir`. Refuses (exit non-zero) if any check fails. |
| `--principal-max-concurrency` | `16` | **Engine principals** (ADR-1005 class, PR 4.4). Maximum in-flight requests for a single engine principal at any instant, checked at the server's single pre-routing chokepoint on both REST and MCP. A streaming/SSE request holds its slot for the stream's lifetime, not just until routing hands off. Exceeding it returns HTTP `429`. Human, device-agent, and anonymous traffic is never gated by this cap. See `docs/user-manual/engine-principals.md` "Per-principal quota cap" for tuning guidance. Env: `YUZU_PRINCIPAL_MAX_CONCURRENCY`. |
| `--principal-rate-limit` | `20.0` | **Engine principals** (ADR-1005 class, PR 4.4). Sustained request rate cap (requests/second, token bucket, burst = 2x the configured rate) for a single engine principal. Exceeding it returns HTTP `429`. Independent of `--principal-max-concurrency` — either dimension alone can reject a request. See `docs/user-manual/engine-principals.md` "Per-principal quota cap" for tuning guidance. Env: `YUZU_PRINCIPAL_RATE_LIMIT`. |
| `--log-file` | *(none)* | Path for explicit on-disk log output. When set, log lines are written to this file in addition to stdout. The directory must be writable by the server's runtime user; if the file or directory cannot be opened the server logs an ERROR but continues to start. Independent of the default platform log path (see [File Logging](#file-logging)). |
| `--kek-min-rotate-interval` | `3600` | **KEK rotation runaway/abuse guard (#2530) — NOT a rotation-schedule setting.** A floor on how *frequently* `/api/v1/secrets/kek/rotate` may be attempted at all (seconds), read from `secrets.kek_meta.created_at` on the database server's own clock — cluster-wide and restart-persistent (the only authoritative control; a cheap process-local pre-check that used to sit alongside it was removed as a correctness bug, #2530 G7-S9 — see "Key management (secrets KEK)"). A rotate inside the window gets `429` with an honest `retry_after_ms`. The default is sized to stop looping automation, not to express how often you intend to rotate; **most operators should never change it.** Raising it delays *emergency* re-rotation after a suspected KEK compromise with no bypass (`/rewrap` only resumes an in-progress rotation, it never mints a new version) — do not set it to your rotation *cadence* (e.g. a 90-day quarterly policy), that is a routine rotation followed by a compromise the next day leaving you refused for the next three months. The upper bound (365 days) is a fat-finger sanity ceiling, not an endorsement of setting it that high. **A fresh install's first rotate attempt is refused for up to this interval** — KEK v1 is minted at boot with `created_at = now()`, so the durable clock starts counting down from install time, not from your first rotate call. See "Key management (secrets KEK)" for the full contract. Env: `YUZU_KEK_MIN_ROTATE_INTERVAL`. |
| `--kek-max-live-versions` | `32` | **KEK rotation runaway control (#2530).** Backstop ceiling on the number of non-retired KEK versions; a rotate at or above it gets `409` with no retry hint. There is no retire route (#2525), so raising this above the default is the **supported escape hatch** that keeps rotation usable once an install hits it — a deliberate, logged (`spdlog::warn` at boot) and audited (`server.kek_ceiling_raised`) temporary risk acceptance, not a routine tuning knob; every server sharing the database needs the raised value for the ceiling to lift fleet-wide. See "Key management (secrets KEK)". Env: `YUZU_KEK_MAX_LIVE_VERSIONS`. |

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

### vNEXT — behind a reverse proxy, declare your external origin or CSRF-gated dashboard actions keep failing (#2537)

**Who this affects.** Anyone running the dashboard behind nginx, Envoy, HAProxy, an ALB or
Cloudflare where the proxy **rewrites the `Host` header** rather than passing the client's
value through. Direct access, and proxies configured to preserve `Host`, are unaffected and
need no change.

**The symptom.** Every CSRF-gated dashboard action fails with `403 cross-origin POST refused`
— CA revoke, CA import-chain, the TAR retention-paused re-enable and purge fragments, and the
gated settings POSTs. The dashboard renders fine and reads work; only the destructive actions
fail.

**Why.** The same-site check compares the browser's `Origin` against the server's `Host`. When
the proxy substitutes its own `Host`, those two legitimately differ: the browser says
`https://yuzu.customer.example` while the server sees `yuzu-server:8080`. The check was
correct and the deployment was correct; there was simply no way to tell the server its
external name.

**The fix — declare the external origin:**

```bash
yuzu-server --csrf-trusted-origin https://yuzu.customer.example
# or
YUZU_CSRF_TRUSTED_ORIGIN=https://yuzu.customer.example
```

Repeatable, and a single value may be comma-separated:

```bash
--csrf-trusted-origin https://yuzu.example --csrf-trusted-origin https://yuzu-dr.example
--csrf-trusted-origin "https://yuzu.example,https://yuzu-dr.example"
```

Two accepted forms, and the difference matters:

| Form | Matches |
|---|---|
| `https://yuzu.example` | that host **over https only** — an `http://` Origin for the same host is still refused |
| `yuzu.example` | that host over **either** scheme |

Prefer the scheme-qualified form. It also closes a weaker pre-existing behaviour in the same
check, where `http://h` satisfied a request to `https://h`.

Entries are case-insensitive, may carry a port, and any path is ignored. **Wildcards are not
supported** — `*.example` is accepted by the parser but will never match anything, deliberately.
The reserved token `null` is refused as an entry: it is the serialisation of an *opaque* origin
(sandboxed iframes, redirected cross-origin POSTs, `file://` documents), not a host, so trusting
it would admit all of them at once.

Port handling follows RFC 6454 — a port is dropped only when it is the default **for that entry's
scheme**:

| entry | canonical form | note |
|---|---|---|
| `https://yuzu.example:443` | `https://yuzu.example` | 443 is the https default |
| `http://yuzu.example:80` | `http://yuzu.example` | 80 is the http default |
| `https://yuzu.example:80` | *unchanged* | 80 is **not** the https default, so it is significant |
| `yuzu.example:8443` | *unchanged* | not a default under any scheme |
| `yuzu.example:443` | **rejected** | ambiguous — a bare entry cannot say which scheme's default this is |

The last row is the one to read twice. An earlier version collapsed a bare `yuzu.example:443` to
`yuzu.example`, which then trusted **both** `http://yuzu.example` and `https://yuzu.example` — one
declared origin silently trusting a second, which is the whole defect this canonicalisation exists
to prevent. Guessing `https` would be a guess, and keeping the port would make the entry unmatchable
(the request side canonicalises `https://yuzu.example:443` to `yuzu.example`). So it is refused, and
you write `https://yuzu.example` or `http://yuzu.example` instead.

A bare entry with **no** port is still deliberately loose: `yuzu.example` covers
`https://yuzu.example`, `https://yuzu.example:443`, `http://yuzu.example` and
`http://yuzu.example:80` — but not `https://yuzu.example:80`, which is a different origin.

Entries are also rejected if they are empty, host-less (`:443`), or carry userinfo (`u@host`) — the
last because the request side always fails closed on `@`, so accepting it would put an entry in the
boot log that could never match.

**Rejections are reported.** If any supplied value is refused, the server warns at boot with the
accepted-versus-supplied counts. Before this, an all-invalid config produced boot output identical
to not passing the flag at all, and the first symptom was the same opaque 403 the flag exists to
remove.

**Confirming it took.** The server logs the accepted set once at boot:

```
CSRF same-site gate: accepting 1 operator-declared external origin(s) in addition to the request Host — https://yuzu.customer.example
```

If that line is absent, or lists something other than what your users type into the address
bar, the 403s will continue. It is the fastest diagnosis for a mistyped entry.

**What has NOT changed.** A request whose `Origin` already matches `Host` behaves exactly as
before, so an unproxied deployment sees no difference. Non-browser clients sending neither
`Origin` nor `Referer` (curl, automation) are still admitted by the shared helper, and the two
CA endpoints still treat both-headers-absent as cross-site. Leaving the flag unset is safe: it
means same-host only, which is the previous behaviour.

**Deliberately not implemented: `X-Forwarded-Host` is never consulted.** Reading it would let
anyone able to reach the server's port declare their own external hostname and defeat the CSRF
check outright. Gating it on a trusted-proxy CIDR does not rescue that — on the container
networks the reference composes use, "inside the CIDR" is usually every sibling container, and
the failure mode is silent: the dashboard keeps working while the control is dead. A config
value cannot be set by an attacker, which is why the trust anchor here is a flag and not a
header.

### vNEXT — a device target that was supplied but names nothing is now refused, not widened to the fleet (#2500)

**What changed.** Three REST surfaces treated a targeting argument the caller *supplied* that
resolved to no devices as identical to one they never sent — and "no target named" meant
broadcast. `POST /api/command` with `{"plugin":"service","action":"restart","agent_ids":[1,2,3]}`
restarted the service on **every connected agent** under plain `Execution:Execute`, with no
approval step, and returned a success response. So did `{"agent_ids": []}`, which is what any
device filter that matched nothing produces. Each of these is now `400`.

**What breaks.** Requests that previously succeeded and now fail:

| Endpoint | Shape | Was | Now |
|---|---|---|---|
| `POST /api/command` | `agent_ids` `[]`, non-array, or containing a non-string | broadcast to all | `400` |
| `POST /api/command` | `scope` `""` or non-string | broadcast to all | `400` |
| `POST /api/instructions/{id}/execute` | `agent_ids` `[]`, non-array | broadcast to all | `400` |
| `POST /api/instructions/{id}/execute` | `scope` `""` or non-string | broadcast to all | `400` |
| `POST /api/v1/result-sets/from-*` | `parent_id` empty, non-string, or `null` | searched/dispatched unscoped | `400` |
| `POST /api/policies/{id}/remediate` | `agent_ids` `[]`, non-array, or containing a non-string | remediated **every non-compliant agent** in the policy | `400` |
| `POST /api/policies/{id}/remediate` | `scope` supplied at all | silently ignored, so a narrowing selector remediated every non-compliant agent | `400` — the route selects targets by `agent_ids` only |
| `POST /api/command` | body is not a JSON object | treated as "no target" → broadcast | `400` |
| `POST /api/command` | `plugin`/`action` outside `[A-Za-z0-9_.-]` or over 128 bytes | accepted | `400` |
| `POST /api/instructions/{id}/execute` | body is not a JSON object | treated as "no target" → broadcast | `400` |
| `POST /api/command` | `scope` is `"__all__"` | `400 invalid scope` | dispatches to **all connected agents** |
| `POST /api/v1/result-sets/from-*` | body is not a JSON object | `500` (uncaught type error) | `400` |
| `POST /api/dashboard/execute` | form field `scope=` supplied but EMPTY | broadcast to all | refused, nothing dispatched |
| `POST /api/dashboard/tar-execute` | query param `scope=` supplied but EMPTY | broadcast to all | refused, nothing dispatched |

The two remediation rows matter for the same reason as the rest: on that route an **absent**
`agent_ids` means "every non-compliant agent in this policy", so a supplied selector that named
nothing — or a `scope`, which that route cannot act on — quietly became a fleet-wide *mutating*
remediation. Omitting `agent_ids` entirely still targets every non-compliant agent, unchanged.

The instructions-execute row is the one to read twice: `"scope": "" + empty agent_ids = broadcast`
was **documented** behaviour in `rest-api.md`, so a client written against the published contract
is affected. The `from-*` row covers `from-tar-query`, `from-instruction-result`, `re-eval` and
`from-inventory-query`.

**One thing got LOOSER, not tighter.** `POST /api/command` previously rejected
`"scope": "__all__"` with `400 invalid scope` — the scope parser has no rule for it — while the
sibling instruction-execute route broadcast on the same string. It now broadcasts on both. This
grants no new access: broadcast was already reachable on that route by omitting targeting
entirely, under the same `Execution:Execute`, so `__all__` only gives a name to something a
caller could already do. But if you have a script that sends `__all__` and treats the `400` as a
no-op, it will now dispatch to the fleet.

**What still works, unchanged.** **Omitting both** `agent_ids` and `scope` broadcasts to all
connected agents, on every route. So does an explicit `"scope": "__all__"` — the ground scope kind already
advertised by `/discover/scope-kinds` and by the MCP `execute_instruction` schema. If you have a
client sending `"scope": ""` to mean "everything", change it to omit the field or to send
`"__all__"`; both are supported and neither is deprecated.

**Stored data — narrower than it first looks.** Only requests that **explicitly** send
`"scope": "__all__"` record `scope_expression = "__all__"` on the execution row, and those already
did so before this change. Broadcasting by **omitting both fields** is unchanged and still records
`""` — the execution row is written from the raw request value, before the omitted-means-`__all__`
mapping is applied for dispatch, and the mapped value is never written back. The one practical
change is that the dashboard's "All agents" button now sends `__all__` explicitly, so rows created
that way look different from before. A saved query selecting historical broadcasts by
`scope_expression = ''` still matches everything except dashboard-initiated ones.

**Dashboard users driving the UI in a browser need do nothing** — the Instructions execute
dialog's "All agents" option sends `__all__` instead of an empty string.

**But automation that POSTs the dashboard forms directly does need attention.** As of the
Wave-1 foundations change, `/api/dashboard/execute` and `/api/dashboard/tar-execute`
distinguish an OMITTED `scope` from one SUPPLIED as empty (`scope=`): omitted still means the
whole fleet, but supplied-but-empty is now refused and dispatches to nobody, where it
previously broadcast. If a script builds the form body unconditionally and leaves `scope`
blank when no device is selected, it will stop dispatching — which is the intended outcome,
but a silent one. Send `scope=__all__` to keep the fleet-wide behaviour deliberately.

**Detecting affected clients — and the limit of what is possible.** There is no reliable way to
find them *before* upgrading. The audit trail records the OUTCOME of a dispatch, not the request
shape that produced it: `command.dispatch|success` stores `plugin:action -> N agent(s)` and
`instruction.execute|success` stores `agents=<sent>`, and neither preserves the `agent_ids` or
`scope` the caller actually sent. So a historical broadcast that was deliberate and one that was
an accidentally-widened three-device request are indistinguishable in existing rows. The closest
available pre-upgrade signal is reviewing automation you believe targets a subset for dispatches
whose agent count is suspiciously close to your full fleet size. (The stored detail uses a literal
`\u2192` arrow, not `->`, so match on the agent count rather than the separator.)

After upgrading, refusals are counted by
`yuzu_server_dispatch_target_rejected_total{route,reason}` (all series pre-seeded at boot, so
`absent()` stays meaningful) and audited as `command.dispatch|denied`
(`detail=reason=<reason> <plugin>:<action>`), `instruction.execute|denied`
(`detail=reason=<reason>`) or `result_set.create|denied`
(`detail=reason=<reason> source_kind=<kind>`). The
`YuzuDispatchTargetRejected` alert fires when the 15-minute increase exceeds 3 — deliberately not
on every single refusal, because a rule that pages on one malformed request gets silenced. Use the
audit rows, not the alert, to find individual offenders.

### vNEXT — MCP stream revalidation rides the tick, and the pin-drift alert moves to a new counter

Two operator-visible changes to held-open MCP `GET` SSE streams. Neither changes a
revocation bound: the documented one-tick single-server figure still holds and is now
pinned by tests.

**Credential re-checks are once per tick, and busy streams stop sending heartbeat
filler.** A stream delivering frames continuously previously re-validated its
credential and slid its session TTL on *every frame*; both now run once per ~3 s tick,
and a pass that delivered real frames skips the redundant heartbeat. If anything on
your side counts `event: heartbeat` frames as a liveness signal, key on *any*
delivered frame instead.

**The admission-drift reading moved counters.** `yuzu_mcp_stream_final_unpinned_total`
used to carry the "replay-ring pin accounting has drifted" reading; that reading now
belongs to the new `yuzu_mcp_stream_pin_displaced_total` (the server now displaces the
oldest pinned terminal instead of committing the newest unprotected, which is strictly
less bad). If you alert on `final_unpinned_total > 0`, keep that rule and add the same
rule for `pin_displaced_total` — reference rules for both ship in
`docs/prometheus/yuzu-alerts.yml`, and the response procedure is
`docs/ops-runbooks/mcp-stream-pin-displacement.md` (diagnostic only — no restart).

### vNEXT — engine-principal streams: liveness re-checks are cached, and the outage grace window is measured differently (#2367)

Two operator-visible changes to held-open MCP/SSE streams authenticated by an
**engine** principal. Nothing changes for human or API-token streams.

**Liveness re-checks are cached for 15 seconds.** Every held-open stream
re-validates its credential on each ~3 s heartbeat tick. For engine principals
that check previously read PostgreSQL every tick, which under a connection-pool
brownout was self-amplifying and could starve ordinary request traffic — not
just streaming. It is now served from a short cache, and a store that cannot be
reached is rate-limited rather than re-asked on every tick.

Fresh authorization is unaffected: creating a session and on-behalf-of target
checks still read through on every call, so revoking an engine principal stops
new sessions immediately. On the server handling the revoke, live streams are
still cut on the next tick — the cache is invalidated as part of that write.
Across replicas, a revoke reaches another replica's stream within the 15 s TTL
plus a tick. If your compliance posture quotes a revocation-latency figure for
engine principals, that is the number.

**A stream may now end sooner during a PostgreSQL outage.** The 60 s
indeterminate grace window is now measured from the stream's last
*authoritative* credential confirmation rather than from the moment the outage
was noticed. Previously a stream could ride cached answers and then collect a
full fresh 60 s window on top of them; total survival past a real confirmation
is now bounded by the window itself. In practice a stream can close with
`auth_unavailable` up to ~15 s earlier than before. Clients reconnect and
resume via `Last-Event-ID` as they already do, and durable results remain
fetchable by `execution_id`.

**New observability.** Four metrics
(`yuzu_server_engine_revalidate_cache_hits_total`, `..._misses_total`,
`..._cache_size`, `..._backoff_suppressed_total` — see
[metrics.md](metrics.md)). The last is the brownout signal: it moves only while
the store is unreachable. The server also emits a startup warning when
effective SSE stream capacity exceeds 16x `--postgres-pool-size`; if you see
it, watch `yuzu_pg_acquire_wait_seconds` and `yuzu_pg_pool_in_use` before
raising either.

No configuration changes are required and no flags were added.

### vNEXT — MCP supervised-tier calls now enforce the published input schema pre-approval (#2405)

Approval-gated MCP `tools/call` arguments are now validated against the tool's
published `inputSchema` BEFORE an approval ticket is minted or consumed. Most
callers only fail earlier (junk args that would have failed after admin
approval now answer `-32602` immediately, with no ticket created or burned).

**Previously-succeeding shapes that now break — supervised-tier
`execute_instruction` / `execute_bundle`, plus any approval-gated tool taking
an `integer` parameter:**

- `execute_instruction` / `execute_bundle` with a `params` object containing a
  non-string value (number/bool/array/object) — previously silently
  stringified by the handler after approval. Stringify client-side.
- `execute_bundle` with `steps: []` or more than 32 steps (the schema's
  `minItems`/`maxItems`, matching the handler's own 1–32 bound).
- `execute_instruction` with more than 10 000 `agent_ids`, or any single
  `agent_ids` element longer than 128 bytes.
- `execute_instruction` with `plugin`/`action` longer than 128 bytes, or
  `scope` / a `params` value longer than 8192 bytes. (`execute_bundle`'s
  per-step `plugin`/`action`/`params` carry no length bound and so are
  unaffected by *these* bounds — the non-string rule above still applies to
  them.)
- Any approval-gated tool given an **integral float** where the schema declares
  `integer` — e.g. `mint_engine_credential {"ttl_days": 90.0}` or
  `rotate_engine_credential {"overlap_days": 7.0}`. These previously
  "succeeded" in the worst way: the server ignored the value and silently
  applied the parameter's default. Send a JSON integer (`90`, not `90.0`) —
  note that Python's `json.dumps` emits `90.0` for a float-typed value.

The bound-based rejections above were already the published schema contract
(added in track 2f) but were client-advisory until this change; they are now
enforced on the approval-gated path. **Operator and readonly callers of these
two tools are unchanged** — schema validation runs where `requires_approval` is
true, which for `Execution:Execute` is the supervised tier only, so those
bounds stay advisory on the other tiers (full every-path enforcement is tracked
in #2437). Note the gate keys on the *operation*, not the tier: `delete_tag` is
approval-gated on **operator** as well, so its arguments are validated there
too — it simply carries no length or count bound today, so nothing breaks. Any approval ticket already minted-and-approved for one of the shapes
above becomes unrecallable fail-closed (it is never consumed) and expires on
the normal 7-day approval TTL; re-submit the corrected call for a fresh ticket.

Also note: a recall whose arguments fail schema validation now answers `-32602`
before the ticket is even looked up — clients that pattern-matched `-32003` for
every recall failure should treat `-32602` as "fix the arguments, ticket
untouched". Full detail: `docs/mcp-server.md` "Pre-approval input-schema
validation".

### vNEXT — MCP tool annotations are now truthful; write tools carry `destructiveHint:true` for the first time

Track 2g PR 2. Every MCP tool now advertises the four standard annotation hints
(`readOnlyHint`/`destructiveHint`/`idempotentHint`/`openWorldHint`), generated
from a single-source classification and enforced truthful by a CI cross-check
test. Operator-visible effect: an agentic worker that renders a confirmation
prompt off `destructiveHint` will, for the first time, prompt on the write tools
that previously carried no annotation (`execute_instruction`, `execute_bundle`,
`set_tag`, `delete_tag`, `quarantine_device`, `revoke_certificate`, and more),
and three previously false-safe hints (`confirm_engine_rotation`,
`close_access_review`) are corrected. The hints are **advisory UX only** — the
tier + maker-checker approval gate is unchanged and remains the enforcement.
Because MCP advertises `tools.listChanged:false`, long-lived clients should
reconnect after this deploy to pick up the corrected hints. Not a breaking change
(no previously-working call is rejected). Full detail: `docs/user-manual/mcp.md`
"Available Tools". *(Since superseded for `confirm_engine_rotation`: #2384 added
a required `token_id` argument that pins the confirm to the exact pending
rotation, so its `idempotentHint` is corrected back to `true` — and the new
required argument IS a breaking change for that one unreleased tool/route.)*

### vNEXT — `confirm_engine_rotation` replay-after-resolution is now a terminal error (#2404)

Direct sequel to the `#2384` entry above. A `confirm` (REST
`POST /api/v1/engine-principals/{id}/credentials/confirm` or MCP
`confirm_engine_rotation`) replayed **after the rotation already resolved** — a
network-dropped `200`, a double-submit, or a client racing the auto-revoke
sweep — now returns a **terminal** `409` / MCP `kInvalidParams` (`rotation
already confirmed` / `no rotation in flight ... already the sole active
credential`), instead of the previous retryable `503`. A confirm that finds
**more than two** active credentials likewise now returns a terminal `400`
(was `503`). Only a genuinely-empty read and an unrecognized two-credential
pair stay `503`.

**Not a breaking change** by this file's convention — no previously-succeeding
call is rejected; the first, real confirm still returns `200` identically. But
**worth a glance for any integration that pattern-matches `503 => retry`**: such
a client will now loop forever against a permanently-`503` call under the old
behavior, which is exactly the livelock this fixes — after the upgrade it gets a
terminal `409`/`400` and should stop and (if it genuinely needs a new
credential) call `rotate`, not replay `confirm`. Agentic MCP clients honouring
`idempotentHint:true` get the correct terminal answer automatically. Full
detail: `docs/user-manual/rest-api.md` (confirm error table) and
`docs/user-manual/engine-principals.md`.

### vNEXT — macOS antivirus posture is now probed, not asserted

The `antivirus` plugin's macOS leg previously hardcoded `av|XProtect|active`
without reading anything, and its third-party checks grepped for the wrong
process name. Visible after upgrading agents:

1. **`av|XProtect|<state>` is now a real probe** of the XProtect definition
   bundle: `active` comes with a new `xprotect_version|<n>` row; `unknown`
   means the bundle was unreadable (never assumed active). Third-party EDR/AV
   detected via endpoint-security system extensions emit an additional
   `edr|<bundle id>|<version>` row each. Integrations keying on the old
   always-present `av|XProtect|active` row should treat `unknown` as a signal
   to investigate, not as product-absent.
2. **The `status` action on macOS returns real XProtect data** (definition
   version, freshness, Remediator/MRT versions) instead of
   `status|not_available`. A new darwin-only definition
   `security.antivirus.xprotect_status` exposes it; being a new id, it seeds
   on upgraded installs at next boot (unlike edited descriptions, which reach
   fresh installs only — the amended `security.antivirus.products` text lands
   there alone).
3. **Mixed-fleet blend during rollout:** agents not yet upgraded keep emitting
   the hardcoded XProtect row and process-grep results. Not a server bug; the
   presence of an `xprotect_version` row identifies an upgraded agent.
### vNEXT — macOS firewall `state` now reports the Application Firewall (backend key changed)

The `firewall` plugin's macOS `state` action previously reported the pf packet
filter — which is off by default and unrelated to the Application Firewall a
Mac admin means — so a Mac with the real firewall on could read `disabled`.
Three things are visible after upgrading agents:

1. **The `backend` row value changes from `pf` to `appfirewall`**, and `state`
   now reflects `socketfilterfw --getglobalstate`. Integrations keying on
   `backend|pf` or treating `state` as pf state must switch to the new rows.
   Two additive rows appear: `mode|block_all` (only when block-all is set) and
   `pf|<state>` (the demoted pf signal; `unknown` on agents not running as
   root). `state|unknown` means the check was unreadable — never assumed safe.
2. **Mixed-fleet blend during rollout:** agents not yet upgraded keep emitting
   `backend|pf` + pf-based `state`. Expect both shapes side by side until the
   fleet is fully upgraded — not a server bug; the `backend` row disambiguates
   per device.
3. **Existing installs keep the old definition description.** Bundled
   definitions seed insert-or-skip by id at boot, so the corrected
   `security.firewall.state` description (v1.1.0) lands on fresh installs
   only; upgraded fleets get the corrected *behavior* regardless. To refresh
   the text, delete `security.firewall.state` and re-import it via
   `POST /api/instructions/import` — do not edit it in the dashboard YAML
   editor, which drops the definition's `spec.visualization` on save.
### vNEXT — KEK rotation is now durably rate-limited (#2530) (breaking)

Before this release, `POST /api/v1/secrets/kek/rotate` was rate-limited only by a 5-minute
**process-local** cooldown — cheap, but per-process and restart-clearable, so an install could
in practice rotate roughly every 5 minutes (or more often across a restart, or across several
servers pointed at the same database). This release replaces that with a **durable,
database-backed** rate limit, `--kek-min-rotate-interval` (default `3600` seconds = 1 hour, env
`YUZU_KEK_MIN_ROTATE_INTERVAL`), read from `secrets.kek_meta.created_at` on the database
server's own clock — it survives a restart and is shared cluster-wide by every server pointed at
the same database. **An install that could previously rotate every ~5 minutes can now be
durably refused (`429`) for up to an hour by default.** If your operational tooling or runbooks
assume a short rotation cadence is always available (smoke tests immediately after install,
scripted rotation drills, etc.), review them against the new default before upgrading — a fresh
install's very first rotate attempt is also refused for up to this interval, because KEK v1 is
minted at boot with `created_at = now()`. Lower `--kek-min-rotate-interval` if your operational
model genuinely needs more frequent rotation, but read the "runaway/abuse guard, not a
rotation-schedule setting" caveat in "Key management (secrets KEK)" first — this flag also
bounds how quickly you can rotate in a genuine emergency. See that section and
`docs/prometheus/yuzu-alerts.yml` (group `yuzu-secrets`) for the full contract, the new
`VersionCeiling`/`QueryCanceled`/`ClockAnomaly` failure modes, and the new observability surface.

### vNEXT — API/MCP bearer tokens invalidated on upgrade (ApiTokenStore → Postgres, ADR-0030) (breaking)

The API/MCP bearer-token store moves from SQLite (`api-tokens.db`) to the PostgreSQL substrate as
a **fresh-start cutover with no data migration** — every pre-upgrade API token and MCP token stops
working the instant the new server starts (interactive cookie-session/SSO login is unaffected).
**Re-mint every API/MCP bearer token** after upgrading (`POST /api/v1/tokens`) and update the
credential wherever it is stored; plan a maintenance window and notify automation owners, since all
bearer-token integrations break at once. A boot-time warning names the legacy file (inert,
removable). Full detail + multi-instance caveat: the `## ⚠️ Breaking` section in
`docs/user-manual/upgrading.md` and ADR-0030.

### vNEXT — `GET /mcp/v1/` is a live SSE channel; ALL streaming surfaces now share one worker budget

Track 2f PR 2, plus ADR-0034. Three things change for an operator:

1. **`GET /mcp/v1/` no longer returns `405`.** It is the MCP session's server→client SSE channel (heartbeats, `Last-Event-ID` resume). Nothing publishes onto it yet — `notifications/progress` arrives in the next rung — so a client that never issues a GET is unaffected. Behind a reverse proxy, note these are held-open responses: the server sets `X-Accel-Buffering: no` (nginx honours it); Envoy, HAProxy, ALB and Cloudflare need their own no-buffering opt-out.

2. **Every held-open SSE response now leases from one shared budget** — MCP's GET channel, `GET /api/v1/events`, the dashboard executions drawer, and the legacy `/events` stream. cpp-httplib is thread-per-connection, so each of those pins a worker for its entire life; previously only MCP was counted, which meant the plain-REST reserve was arithmetic rather than a guarantee. A cap hit returns `429` with `Retry-After`; a live stream is never evicted. **This closes a starvation path that existed before MCP streaming shipped at all**: enough dashboard tabs could exhaust the pool and stall plain REST.

3. **The worker pool is derived from `--max-sse-streams` (default 128), not the other way round.** The old default sized itself from httplib's accidental 32-thread pool and yielded 12 streams — on a platform designed for hundreds of agentic clients. A blocked thread burns no CPU; its resident cost is a fraction of a virtual, platform-dependent stack reservation and has not yet been measured (ADR-0034), so the pool is sized for the workload you declare rather than off a per-thread constant. Watch `yuzu_http_held_open_responses / yuzu_http_held_open_capacity`; the ceiling is thread-count, and the durable fix (moving long-lived connections off the thread-per-connection server) is recorded in ADR-0034.

### vNEXT — MCP notification POSTs now answer `202` (was `204`); Streamable HTTP sessions added

The `/mcp/v1/` endpoint gains the MCP-spec **Streamable HTTP** transport (track
2f, PR 1). Three changes are visible to existing clients:

1. **A JSON-RPC *notification* POST (a request with no `id`, e.g.
   `notifications/initialized`) now returns `HTTP 202 Accepted` instead of
   `204 No Content`.** The body stays empty. This is a spec MUST and applies
   regardless of the kill switch below. **Affected:** only a strict client that
   asserts the status is exactly `204` (or asserts an empty-body status other
   than `202`) — the reference clients (mcp-remote, Claude Desktop) treat any
   2xx-with-empty-body as success and are unaffected. Adjust such assertions to
   accept `202`.
2. **`initialize` responses now carry an additive `Mcp-Session-Id` header.**
   Clients that don't use it can safely ignore it (plain-POST flows are
   otherwise byte-identical). Clients that do may present it on later requests;
   an unknown/expired/foreign id returns `404`, at which point the client
   re-initializes (sessions are in-memory, so a server restart has the same
   effect). `DELETE /mcp/v1/` ends a session.
3. **`initialize` now negotiates the protocol revision** instead of always
   returning `2025-03-26`. A client that sends `params.protocolVersion` of a
   *supported* revision (`2025-03-26` or `2025-06-18`) gets that value echoed;
   anything else (including no `protocolVersion`) still returns `2025-03-26`.
   **Affected:** only a newer client that requests `2025-06-18` — a legacy client
   requesting `2025-03-26` (or nothing) sees no change. Negotiation is independent
   of the `--mcp-no-streaming` kill switch.

New CLI flags (all optional):

- `--mcp-no-streaming` (`YUZU_MCP_NO_STREAMING`) — disable the Streamable HTTP
  transport: no session minting, `GET`/`DELETE /mcp/v1/` → `405`, plain
  JSON-RPC POST only. The `202` notification status still applies. Use this if a
  buffering reverse proxy interferes with streaming.
- `--mcp-allowed-origin <value>` (`YUZU_MCP_ALLOWED_ORIGINS`, repeatable) — an
  allowed `Origin` header value (`scheme://host:port`, exact match) for
  DNS-rebinding defence. **An absent `Origin` is always allowed** (the endpoint
  requires a credential); an **empty allowlist rejects any *present* `Origin`**
  (the secure default) — browser-based MCP clients must be allowlisted
  explicitly. Non-browser clients (which send no `Origin`) need no configuration.

### vNEXT — DEX per-application sampling (`procperf`) is a new opt-in telemetry category

This release adds per-application resource sampling (top-N processes by CPU and
working set, by image name) to the TAR edge warehouse. **It is off by default**
(`procperf_enabled=false`) and collects nothing until an operator opts in — it
is a distinct, usage-class telemetry category subject to works-council / DPA
review, separate from the device-level performance sampling (`perf_enabled`,
on by default, no per-app identity) that shipped in the prior release **on
Windows** — on Linux, device-level sampling starts automatically **on upgrade
to this release** (see the upgrade checklist in the user manual's
[Upgrading](upgrading.md) page and the TAR manual's upgrade note; opt out per
host with `perf_enabled=false`). To
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
| Access Reviews | `/fragments/settings/access-reviews` | Periodic access review (SOC 2 CC6.2) convenience panel — pull/download the cross-principal grant export (JSON/CSV), open a new attestation campaign, and record per-grant `attested`/`flagged_revoke` decisions against an open campaign (`/fragments/settings/access-reviews/campaign?id=...`). A view over the same `AuditLog:Read`/`AuditLog:Attest`-gated `/api/v1/access-reviews*` REST API and its MCP twins — not a separate data path. See `docs/auth-architecture.md` "Periodic access reviews". |

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

## SAML 2.0 SP Configuration

Yuzu supports SAML 2.0 SP-initiated single sign-on as an alternative to OIDC for enterprises whose identity infrastructure requires SAML. **Linux and macOS only — SAML is not supported on Windows builds.**

> **HTTPS is required.** The `__Host-yuzu_saml_bind` binding cookie is `Secure`-only and is silently dropped by browsers over plain HTTP. If `--https-cert`/`--https-key` are not configured the server logs an error at startup and leaves SAML disabled (fail-closed).

> **Windows note:** On Windows builds, any SAML flag is logged as an error at startup and SAML is not enabled.

### Configuration

All five flags below must be supplied for correct operation, and all five are validated at startup — a partial set leaves SAML disabled (fail-closed) until every flag is set. The two group→role flags further down are optional and independent of this five-flag gate.

| Flag | Env var | Description |
|---|---|---|
| `--saml-idp-entity-id` | `YUZU_SAML_IDP_ENTITY_ID` | Entity ID URI of the IdP (must match what the IdP uses in assertions). |
| `--saml-idp-sso-url` | `YUZU_SAML_IDP_SSO_URL` | IdP's HTTP-Redirect SSO endpoint URL. |
| `--saml-idp-cert` | `YUZU_SAML_IDP_CERT` | Filesystem path to the IdP's assertion-signing certificate (PEM). The cert at this path is the sole trusted authority; in-document `<KeyInfo>` values are ignored. |
| `--saml-sp-entity-id` | `YUZU_SAML_SP_ENTITY_ID` | Entity ID URI this SP advertises to the IdP in the AuthnRequest. |
| `--saml-sp-acs-url` | `YUZU_SAML_SP_ACS_URL` | Full public URL of the Assertion Consumer Service (`https://<host>/saml/acs`). |

Example startup:

```bash
./yuzu-server \
  --https-cert         /etc/yuzu/server.crt \
  --https-key          /etc/yuzu/server.key \
  --saml-idp-entity-id "https://idp.example.com/saml" \
  --saml-idp-sso-url   "https://idp.example.com/saml/sso" \
  --saml-idp-cert      /etc/yuzu/idp-signing.pem \
  --saml-sp-entity-id  "https://yuzu.example.com" \
  --saml-sp-acs-url    "https://yuzu.example.com/saml/acs"
```

### Role mapping

Two additional, optional flags grant admin access via IdP-attested group
membership — mirroring the OIDC `--oidc-admin-group` mechanism:

| Flag | Env var | Description |
|---|---|---|
| `--saml-group-attribute` | `YUZU_SAML_GROUP_ATTRIBUTE` | `<Attribute Name="...">` in the assertion's `<AttributeStatement>` whose `<AttributeValue>`s are group identifiers. |
| `--saml-admin-group` | `YUZU_SAML_ADMIN_GROUP` | The group value (from `--saml-group-attribute`) that grants `role=admin`. |

A session is `role=admin` only when both flags are set and the assertion's
group list contains an **exact match** for `--saml-admin-group`; otherwise
(including when either flag is left empty, the default) the session is
`role=user`. Group values are read from the same signature-verified assertion
`NameID` is read from, and `NameID`/email/display name are never treated as
group-membership evidence. Changing either flag requires a server restart
(no hot-reload). JIT elevation remains non-functional for SAML users (no
local `users` row in auth.db) regardless of role — a group-mapped admin gets
`role=admin` directly at login, not via the elevation endpoint. Unlike OIDC,
SAML group values are **not** synced into `rbac_store` — group-scoped RBAC
role assignments do not apply to SAML principals (they only feed the
admin-or-user decision above) — deferred pending source-aware group
resolution, see issue #1832.

> **Configuring `--saml-admin-group` against a real IdP:** the value must be
> the exact identifier the IdP puts in the assertion, not a display name —
> Entra ID sends group **object ID GUIDs**, not group names, so configure the
> GUID. Matching is case-sensitive. A user in more than ~150 Entra groups hits
> **"groups overage"**: Entra omits the `groups` claim entirely for that
> assertion (substituting a Graph API link), so such users can never resolve
> to admin via `--saml-admin-group` regardless of actual membership — use a
> dedicated low-membership group for the mapping. At most 64 group values
> from the configured attribute are considered.

### Known limitations in this release

- **MFA step-up:** MFA step-up is not supported for SAML sessions — a SAML session hitting any step-up-gated endpoint receives a 403 regardless of `--mfa-enforcement`. Use `optional` and rely on the IdP to enforce MFA. Avoid `required` for SAML deployments.
- **`--auth-mode=sso-only`:** Requires OIDC configuration. A SAML-only deployment cannot disable local-password login.
- **HA / multi-replica:** Pending AuthnRequest state is in-process. Configure load-balancer sticky sessions (session affinity) on `/auth/saml/start` + `/saml/acs`. Without affinity, approximately `(N−1)/N` of logins fail as unsolicited. OIDC shares this limitation.
- **AuthnRequest signing:** The SP does not sign AuthnRequests. The IdP must accept unsigned requests. If your IdP requires signed AuthnRequests, use OIDC.
- **IdP cert rotation:** Update `--saml-idp-cert` and restart the server. There is no hot-reload.
- **No login-page button:** Navigate directly to `GET /auth/saml/start`; there is no "Sign in with SAML" button on the login page.

See `docs/user-manual/authentication.md` "SAML 2.0 SSO" for the full login flow, capability table, and `docs/auth-architecture.md` "SAML 2.0 SP" for the implementation reference.

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

**Connection-pool sizing.** The server opens up to `--postgres-pool-size` / `YUZU_POSTGRES_POOL_SIZE` connections (default **16**). Each heartbeat persists last-seen with one short-lived lease (≈33/s at 1 000 agents on a 30 s heartbeat — well within 16), and `/viz/fleet` draws one. Raise the size for large fleets (rule of thumb: +1 per ~1 000 agents beyond 5 000, plus headroom per additional Postgres-backed store as they migrate) or for a slow managed-PG link. Tune against the `yuzu_pg_pool_{in_use,open,size}` gauges, the `yuzu_pg_acquire_wait_seconds` histogram (the leading saturation signal), and the `yuzu_pg_{connect_failed,acquire_timeout,unhealthy_discard}_total` counters (`unhealthy_discard` counts pooled connections dropped on a failed health probe); the bundled alert rules (`YuzuPgPoolSaturated`, `YuzuPgAcquireWaitHigh`, `YuzuPgConnectFailing` in `docs/prometheus/yuzu-alerts.yml`) fire before `/readyz` is affected. The heartbeat upsert is best-effort with a 250 ms acquire deadline, so a saturated pool degrades the stale-host display, never the live fleet.

Held-open SSE streams also lease this pool: each re-validates its credential every ~3 s tick. Those reads are cached (60 s for API tokens, 15 s for the engine-principal liveness check), so steady-state cost is proportional to *distinct credentials* rather than to stream count — but the refreshes still land here alongside ordinary traffic, and a stream capacity far above the pool size is the shape that turns a brief pool blip into a correlated stall. The server warns at startup when effective SSE stream capacity exceeds 16x `--postgres-pool-size`. Treat that as a prompt to watch `yuzu_pg_acquire_wait_seconds` and `yuzu_pg_pool_in_use`, not as an instruction to enlarge the pool reflexively — adding connections against an already-struggling database makes matters worse, and lowering the stream capacity is often the better lever.

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

**Rotation** mints `secrets-kek-v<N+1>` and re-wraps only the small wrapped-DEK header of each stored blob — payloads are untouched, so rotation is cheap, incremental, and interruptible (a crash resumes by re-running the re-wrap; already-rotated rows are detected by the blob header; a crash *before* the new version's fingerprint registers leaves an orphan key file that the next rotation attempt safely adopts). The operator-facing surface for this — REST + MCP, the half-committed contract, retirement preconditions, and a DR drill — is below.

#### Rotating the KEK

Three operations, mirrored on REST and MCP so both surfaces answer identically for the same failure:

| REST | MCP tool | Permission | Returns |
|---|---|---|---|
| `POST /api/v1/secrets/kek/rotate` | `rotate_kek` | `Security:Write` | `{new_version, rotation_complete}` |
| `POST /api/v1/secrets/kek/rewrap` | `rewrap_secrets` | `Security:Write` | `{rows_rewrapped}` |
| `GET /api/v1/secrets/kek/status` | `get_kek_status` | `Security:Read` | `{active_version, oldest_in_use, rotation_complete, live_versions, lock_held, lock_holder_pid}` |

All three take no request parameters (an empty body or `{}`; any other field is rejected `400`). `rotate`/`rewrap` are `Security:Write` — on the MCP side that means the supervised-tier approval gate applies, same as every other write tool.

`/status`'s `live_versions`, `lock_held`, and `lock_holder_pid` are #2530
diagnostic fields — see "Diagnosing a stuck KEK op lock" below for what they're
for and how to use them. `live_versions` and `lock_held` are `null` (never a
fabricated `0`/`false`) when the underlying query could not be determined; a
`null` `lock_held` means the lock state is **unknown**, not "not held".
`lock_held`/`lock_holder_pid` report the lock **in the server's own
database** — the query is filtered by `current_database()`, not
cluster-wide, so a same-named advisory lock held by an unrelated tenant
database sharing the same Postgres instance never shows up here.

```bash
# 1. Mint a new version and re-wrap every row under it.
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://yuzu.example.com/api/v1/secrets/kek/rotate

# 2. Confirm completion.
curl -H "Authorization: Bearer $TOKEN" \
  https://yuzu.example.com/api/v1/secrets/kek/status
# → {"active_version":2,"oldest_in_use":2,"rotation_complete":true,
#    "live_versions":2,"lock_held":false,"lock_holder_pid":null,...}
```

`/rotate`'s response deliberately omits a row count (`rotation_complete: true` is the honest signal — see below); call `/rewrap` if you want an actual `rows_rewrapped` number.

> **The half-committed contract — read this before you retry anything.**
> `rotate_kek` mints the new version and then re-wraps every row as one
> operation. If it fails, the response tells you which of two states you are
> in:
> - **A plain failure** (`503`/generic `500`) — nothing changed; safe to
>   retry `/rotate`.
> - **Half-committed** (`500`, message *"KEK rotation did not finish
>   re-wrapping every secret"*) — the new KEK version is **already active**;
>   only the row-by-row re-wrap did not finish. **Call `POST
>   /api/v1/secrets/kek/rewrap` (or the `rewrap_secrets` MCP tool) to
>   resume. Do NOT call `/rotate` again** — it would mint a *second*,
>   spurious new version on top of an already-half-rotated state, not fix
>   anything. `/rewrap` is idempotent and safe to call repeatedly, including
>   once there is genuinely nothing left to do (`rows_rewrapped: 0` is a
>   normal, non-error outcome).
>
> A practical consequence: rotation **attempts** are rate-limited, and a
> *failed* attempt consumes that budget too. That is deliberate — it is
> precisely the retry-on-500 loop above that the limit exists to stop, and
> automation that ignores the half-committed message would otherwise mint a
> fresh, never-retirable KEK version on every retry. `/rewrap` is **not**
> rate-limited, so the correct recovery path is never blocked. Treat a `429`
> on `/rotate` as "you are recovering, use `/rewrap`", not as "try again
> shortly".
>
> **One authoritative rate limit, durable and cluster-wide (#2530; #2530
> G7-S9 removed a second, weaker tier).** An earlier cut of this hardening
> pass added a cheap process-local pre-check (5 minutes, in-memory, no DB
> round trip) alongside the durable control below, to short-circuit an
> obviously-too-soon retry before it cost a query. That pre-check was
> **removed**: its hardcoded 5-minute window could not be configured down
> (an operator setting `--kek-min-rotate-interval` below 5 minutes was still
> refused for the full 5 minutes on that path), and it never populated an
> honest `retry_after_ms`, silently falling back to a fixed value on exactly
> the requests it refused. It was also never the correctness guarantee — it
> was per-process, so servers sharing one database each kept their own
> state, and a restart cleared it. The sole authoritative control today is a
> **durable** rate limit read from `secrets.kek_meta.created_at`, compared
> against the database server's own `now()` in a single statement (so it is
> never comparing an app-host clock to a DB clock):
> `--kek-min-rotate-interval` (seconds, default `3600` = 1h,
> `YUZU_KEK_MIN_ROTATE_INTERVAL`). It survives a restart and is shared
> cluster-wide by every server pointed at the same database. A rotate
> refused by this durable check gets `429` with
> an **honest** `retry_after_ms` computed from that same durable timestamp —
> this is the one failure in this whole surface where a numeric retry hint
> is truthful, because waiting genuinely resolves it. (`retry_after_ms` is a
> `uint32` millisecond count; an unreasonably large configured interval
> **saturates** it at its maximum rather than wrapping, so the hint can only
> ever come out over-long, never falsely short.)
>
> **This is a runaway/abuse guard, not a rotation-schedule setting — do NOT
> set it to your rotation cadence.** It exists to stop a looping caller
> (buggy automation, a compromised token) hammering `/rotate`, not to
> express how often you intend to rotate; the default is sized for that job
> and **most operators should never change it.** Raising it has a sharp,
> real cost: it directly delays *emergency* re-rotation after a suspected
> KEK compromise — the single most time-critical thing this surface exists
> to support — with **no bypass** (`/rewrap` only resumes an
> already-in-progress rotation; it never mints a new version). Set this to,
> say, 90 days to "match" a quarterly rotation policy, and a routine
> rotation followed by a compromise the very next day leaves you refused
> with `429` for the next three months, with no escape short of a restart
> at a lower value **in the middle of the incident**. Rotation *cadence*
> (how often you choose to rotate) and this *minimum spacing* (how often
> you permit rotation to be attempted at all) are different concepts — keep
> them separate. The flag's upper bound (365 days) is a sanity ceiling
> against a fat-fingered value, not a recommendation.
>
> Cluster-wide *correctness* (as opposed to rate limiting) still comes from
> the advisory lock, which reports `409` — see Concurrency below. A second,
> unrelated `409` — the live-version ceiling — is covered right after it.
>
> **Week-one gotcha: a fresh install's FIRST rotate is refused too (#2530
> G7-S7).** KEK v1 is minted at boot with `created_at = now()` — it is a
> `kek_meta` row like any other, so the durable clock above starts counting
> down from **install time**, not from whenever you happen to first call
> `/rotate`. If you install the server and immediately try to rotate as a
> smoke test, you get the same `429` cooldown response an abuse-guard trip
> would produce, with `retry_after_ms` counting down from
> `--kek-min-rotate-interval` (default 1h) minus however long the server has
> been up. This is expected, not a bug — treat a `429` in the first hour
> after a fresh install as "working as designed", not as a signal something
> is wrong with the install.

**Verify completion.** `GET /status` (`get_kek_status`) is the source of
truth: `rotation_complete` is `true` when no stored secret blob still
references a version older than `active_version` — equivalently,
`oldest_in_use` (null when there are no secret rows at all) is `>=
active_version`. This is the ADR-0010 §3 completion signal; don't infer
completion from a lack of errors alone — always confirm with `/status`
after a `/rotate` or `/rewrap` call.

**Concurrency.** `/rotate` and `/rewrap` take a cluster-wide Postgres
advisory lock (`secrets_kek_op`), non-blocking. A second concurrent attempt
gets `409` on REST ("another KEK operation is in progress") or a retryable
MCP error with an honest `retry_after_ms` — that is expected behaviour under
contention, not a fault. Wait for the in-flight operation to finish and
retry. **`GET /status` deliberately never takes this lock** — a status poll
during a long-running rotation would otherwise itself be blocked, which is
the opposite of what a diagnostic endpoint is for; see "Diagnosing a stuck
KEK op lock" below for how `/status` observes lock state without taking it.

**The live-version ceiling — a second, different `409` (#2530).**
`--kek-max-live-versions` (default `32`, `YUZU_KEK_MAX_LIVE_VERSIONS`) caps
the number of non-retired KEK versions. `/rotate` at or above the ceiling
also gets `409` — "the live KEK version ceiling has been reached" — which
reads exactly like the lock-conflict `409` above but means something
different and needs a different response: waiting never clears it (there is
no automatic decay, and no `retry_after_ms` is sent for this one), and
because there is no retire route (#2525), the only way past it is deliberate
operator action.

**Raising `--kek-max-live-versions` above the default is the supported
escape hatch** for that — do it deliberately, as a temporary risk acceptance
pending #2525, not as a routine tuning knob. Setting it above the default:

- logs a `spdlog::warn` at boot naming the configured value and the default;
- emits a `server.kek_ceiling_raised` audit event (`principal="system"`,
  `target_type=Secret`, `target_id=kek`, once the audit store is up) —
  worded as an explicit, temporary risk acceptance, the same posture pattern
  as `--allow-unsigned-packs`/`--allow-unsigned-definitions`.

`--kek-max-live-versions` is a per-process CLI flag, not cluster state — it
is not stored anywhere the cluster shares. If several servers point at the
same database, **every one of them needs the raised value** before the
ceiling genuinely lifts fleet-wide: since `secrets_kek_op` serialises rotate
attempts across the whole cluster, a caller can still land on an un-bumped
server's evaluation of the ceiling and get refused, even after you've raised
it on others.

**Clock-anomaly guard (#2530).** The durable rate limit above depends on
comparing `now()` to `secrets.kek_meta.created_at`, both read from the
*same* Postgres statement precisely so the comparison never crosses an
app-host clock against a DB-host clock. If the newest `kek_meta` row's
`created_at` is future-dated relative to that same `now()`, `/rotate`
refuses immediately with a distinct `503` — "the KEK rotation clock is
untrustworthy" — **not** a `429` cooldown, and with no retry hint at all. A
`429` here would carry a `retry_after_ms` computed from the exact timestamp
that has just been proven untrustworthy, which would be a lie rather than a
hint. **What to actually do:** this means the database server's own clock
(or its NTP sync) is wrong — investigate that, not the KEK subsystem.

**The two skew directions behave DIFFERENTLY — read this before assuming
"it'll clear itself" (#2530 G7-B6).** A **backward** clock skew (the
database server's clock jumps or drifts BACKWARD after the row was minted)
is transient and self-clearing: once the clock reads sanely again relative
to the stored row, `/rotate` proceeds normally on the very next attempt,
with nothing to reset by hand. A **forward** skew — the row was minted
*while* the clock was already ahead (bad NTP source, a VM restore, a
failover to a host whose clock is ahead) — is **not** self-clearing: the
stored `created_at` stays in the future relative to `now()`, and therefore
stays `> now()`, for the ENTIRE skew duration, blocking every `/rotate`
attempt for as long as that lasts. Because the anomaly check runs before
the cooldown and ceiling checks, this refusal has **no bypass at all** — no
flag, no restart, no override — making an emergency re-rotation after a
suspected key compromise impossible until real time catches up to the
stored timestamp.

**Diagnosing which direction you're in.** Both the `503` body and the
server log line report the observed skew **magnitude** — how many seconds
into the future the row is dated — specifically so you can tell "a few
seconds of NTP jitter" (self-clears within moments) from "this row is dated
next year" (does not self-clear on any practical timescale) at a glance,
rather than having to query `kek_meta` by hand to find out. If the reported
magnitude is small (seconds), it is almost certainly ordinary clock jitter
around the `now()`/`created_at` boundary — wait a few seconds and retry. If
it is large (hours, days, or more), treat it as a genuine incident:
1. Confirm the database server's actual wall-clock time and NTP sync status
   directly (not through the application).
2. Correct the clock (or complete the VM restore / failover cutover that
   left it skewed).
3. Once `SELECT now()` on the database server reads a sane time again,
   `/rotate` proceeds normally on the next attempt — there is nothing to
   reset in `kek_meta` by hand.

There is deliberately **no** flag to bypass this check even for a confirmed,
large, persistent forward skew — a code-level escape hatch on a security
guard is a separate design decision with its own review, not something this
hardening pass adds. If a persistent forward skew blocks an emergency
rotation for you in practice, file an issue describing the scenario rather
than working around it by hand-editing `kek_meta.created_at`.

**Query-cancellation classification (#2530).** Any KEK rotate/rewrap/status
Postgres query that is canceled or exceeds `statement_timeout` (SQLSTATE
`57014`) returns a distinct `503` — "a KEK query was canceled or exceeded
its statement timeout" — instead of a generic `500`. Read that phrasing
literally: SQLSTATE `57014` is `query_canceled`, which Postgres also raises
for an administrator's `pg_cancel_backend`, so "timed out" alone would
overclaim what actually happened, and this is **not necessarily transient**
— don't just retry blind. Check, in roughly this order: `statement_timeout`
(is it configured too low for current load?), current database load,
whether an administrator issued a cancel, and the size of the
registered-column rewrap scan (`SecretCodec::registered_columns()` — today
just `auth.users.mfa_totp_secret`; a second registered secret column makes
the unbatched full-column scan a real scale risk, deliberately deferred and
out of scope for this hardening pass — see the trip-wire test named in
`tests/unit/server/test_secret_column_registration_tripwire.cpp`). **If a
`query_canceled` arrives after `/rotate` has already advanced the active
version, it is reported as `HalfCommitted`, not `QueryCanceled`** — the
half-committed contract above always wins, because the operator must still
be told to call `/rewrap`, never to retry `/rotate`.

#### Diagnosing a stuck KEK op lock (#2530)

Before this, a backend wedged holding the `secrets_kek_op` advisory lock
made every KEK operation return `409` forever, with no way to see why and no
documented remedy. `GET /status` (`get_kek_status`) now reports four fields
for exactly this:

| Field | Meaning |
|---|---|
| `live_versions` | Count of non-retired KEK versions. `null` if the count query could not be determined — never a fabricated `0`. |
| `lock_held` | `true` iff `secrets_kek_op` currently has a granted holder **in this server's own database** (the query is filtered by `current_database()`, not cluster-wide). `null` if the holder query could not be determined — **never** a fabricated `false`; a `null` here means the lock state is UNKNOWN, not "not held". |
| `lock_holder_pid` | That holder's Postgres backend pid. **THREE possible states, not two — always read `lock_held` first to disambiguate a `null` pid:** (1) `lock_held: false` → `null`, genuinely unheld; (2) `lock_held: true` with a **non-null** pid → a normal held lock, corroborate it in `pg_stat_activity` (step 2 below); (3) `lock_held: true` with a **`null`** pid → HELD, but the holder's backend pid itself could not be read from `pg_locks` at query time — there is no pid to corroborate with, see step 1's third case below. `lock_held: null` (query itself failed) also reports `lock_holder_pid: null`, but that is a fourth, entirely separate "undetermined" case — do not conflate it with case (1) or (3). |
| `lock_holder_captured_at` | ISO-8601 UTC instant (`YYYY-MM-DDTHH:MM:SSZ`) the `lock_held`/`lock_holder_pid` snapshot above was **taken** — `null` in lockstep with them when undetermined (#2530 H1). This exists so a stale reading is visible as stale rather than authoritative: the longer the gap between this timestamp and the moment you are about to act, the less you should trust that `lock_holder_pid` still names the same backend — Postgres **reuses** pids, so an old-enough reading can now point at a completely unrelated connection. Treat a `lock_holder_captured_at` more than a few seconds in the past as a reason to re-read `/status` (or, before anything irreversible, re-query `pg_locks` directly — see step 3) rather than act on the number in front of you. |

**These are lock-free diagnostic snapshots, not one coordinated read.** Each
is its own `SELECT`, taken at a possibly different instant from the others
and from `active_version`/`oldest_in_use` in the same response — `/status`
still never takes the lock itself (see Concurrency above). **Never derive a
"safe to retire" conclusion from any combination of them** — that is
precisely the #2525 hazard this surface has no retire route for; these
fields add observability, not a new safety guarantee.

**A `null` `lock_held` means UNKNOWN, never "not held" (#2530).** If the
holder query itself fails — the exact scenario a wedged Postgres backend or
substrate outage produces — `lock_held` and `live_versions` come back `null`
rather than the confident-sounding `false`/`0` an earlier version of this
surface fabricated. Treat a `null` `lock_held` as "corroborate before
concluding anything": check `pg_stat_activity` directly and check whether the
Postgres substrate itself is degraded (see the `yuzu-postgres` alerts) before
deciding either way.

**The procedure — follow it in order, do not skip a step:**

1. **Identify the holder.** `GET /status`'s `lock_holder_pid` is the
   Postgres backend pid currently holding `secrets_kek_op` **in this
   database**. Three cases, not two:
   - `lock_held: false` — nothing to diagnose here: a `409` you're
     separately seeing is either a genuinely in-flight operation about to
     finish, or the pid you captured earlier has already released and
     moved on.
   - `lock_held: null` — **do not conclude "not held"**; the holder query
     itself failed. Go straight to `pg_stat_activity` (step 2) and check
     Postgres substrate health before drawing any conclusion.
   - `lock_held: true` with `lock_holder_pid: null` — the lock **is** held,
     but the holder's backend pid could not be read from `pg_locks` at
     query time, so there is no pid to plug into step 2's `WHERE pid =
     <lock_holder_pid>`. Instead, query `pg_locks` directly for any granted
     holder of this lock in the current database and read whatever pid it
     reports at that moment:
     ```sql
     SELECT pid FROM pg_locks
      WHERE locktype = 'advisory' AND classid = 2037545589
        AND objid = (hashtext('secrets_kek_op')::bigint & 4294967295)::oid
        AND granted
        AND database = (SELECT oid FROM pg_database WHERE datname = current_database());
     ```
     If that also returns a null/no pid, retry `/status` once (the pid
     column can be transiently unreadable) before escalating to a DBA
     inspection of `pg_stat_activity` for any session in this database
     holding an advisory lock, since the affected session cannot be
     targeted by pid alone.
2. **Corroborate in `pg_stat_activity` — never act on the pid alone.**
   ```sql
   SELECT pid, state, wait_event_type, wait_event, query, query_start, xact_start
     FROM pg_stat_activity
    WHERE pid = <lock_holder_pid>;
   ```
   A **healthy long rewrap** (a large registered-secrets scan) and a
   **genuinely wedged backend** look identical from `lock_held`/
   `lock_holder_pid` alone — the difference is entirely in what
   `pg_stat_activity` shows. An actively-progressing query with a sensible,
   recent `query_start` is a rewrap doing real work. A backend sitting
   `idle` or `idle in transaction` while still holding the lock, or a
   `query_start`/`xact_start` far older than any registered-column table
   could plausibly take to scan, is the wedge.
3. **Only a DBA terminates it, deliberately, and only after step 2 shows a
   genuine wedge.** **Read this in full before running `pg_terminate_backend`
   on anything.**

   > **The holder is very likely one of YOUR OWN Yuzu servers, mid-rotation
   > — not an intruder or a hung process.** The `secrets_kek_op` lock is held
   > for the ENTIRE `/rotate`/`/rewrap` call, and a large re-wrap (every
   > registered secret row, one query) can legitimately take a long time —
   > holding this lock for 30+ minutes on a big table is EXPECTED, not
   > itself evidence of a wedge. Step 2's `pg_stat_activity` check exists
   > precisely because this gauge and these fields cannot tell "healthy and
   > slow" from "wedged" apart on their own.
   >
   > **Terminating the holder mid-rotation produces exactly the
   > half-committed state this whole feature exists to help you avoid.** If
   > you kill a backend that is genuinely a Yuzu server partway through
   > `/rotate`, the new KEK version it already minted stays active — only
   > the row-by-row re-wrap is interrupted. Recovery is `POST
   > /api/v1/secrets/kek/rewrap` (or the `rewrap_secrets` MCP tool). **Do
   > NOT retry `/rotate`** to "fix" this — see the half-committed contract
   > above; a retried `/rotate` mints a second, spurious KEK version on top
   > of the mess and can never be retired (#2525), it does not undo
   > anything. In other words: the wrong call here does not just fail
   > safely, it creates the exact incident this runbook was written to help
   > you diagnose and avoid.
   >
   > **Before doing anything else, check whether the backend belongs to a
   > Yuzu server, and prefer stopping that server cleanly over killing its
   > backend:**
   > ```sql
   > SELECT pid, application_name, client_addr, client_port, backend_start
   >   FROM pg_stat_activity
   >  WHERE pid = <lock_holder_pid>;
   > ```
   > Match `client_addr`/`client_port` against your known Yuzu server hosts
   > (Yuzu does not currently set `application_name` on its Postgres
   > connections, so expect it blank — do not treat a blank
   > `application_name` as evidence the holder is *not* a Yuzu server). If
   > the pid traces to a live Yuzu server process you can reach, stop that
   > **server** cleanly (its own shutdown path releases the advisory lock
   > through the ordinary `KekOpLockGuard` destructor, the same clean-exit
   > path a completed rotation takes) rather than terminating its Postgres
   > backend out from under it mid-statement.

   If, and only if, step 2 has already shown a genuine wedge (an `idle` /
   `idle in transaction` backend still holding the lock, or a `query_start`/
   `xact_start` implausibly old for any registered-secrets scan) **and**
   the check above could not identify a Yuzu server you can stop cleanly:

   - **Re-confirm the pid is still the granted holder, at the moment you are
     about to act — not from the `/status` reading you captured earlier.**
     `lock_holder_captured_at` tells you how old that reading already is,
     and Postgres reuses backend pids, so a pid that was correct when you
     first read it can now belong to an unrelated connection. Re-run the
     `pg_locks` query from step 1's third case (or `/status` again) and only
     proceed if it still names the same pid:
     ```sql
     SELECT pid FROM pg_locks
      WHERE locktype = 'advisory' AND classid = 2037545589
        AND objid = (hashtext('secrets_kek_op')::bigint & 4294967295)::oid
        AND granted
        AND database = (SELECT oid FROM pg_database WHERE datname = current_database());
     ```
   - Only then does a DBA run `SELECT pg_terminate_backend(<pid>);`
     deliberately — session-scoped advisory locks die with their session, so
     terminating the backend releases the lock. If the target turned out to
     be a Yuzu server after all, be ready to call `/rewrap` afterward — never
     `/rotate`.

**Two more staleness caveats, on top of "these are lock-free snapshots":**
the pid you read can **vanish** (the backend has already exited normally
between your `/status` read and your `pg_stat_activity` query — treat "no
such pid" in step 2 as "already resolved, no action needed", not as an
error) and can be **reused** by an unrelated later connection (Postgres
recycles backend pids). Always corroborate against `pg_stat_activity` in the
same narrow window as the `/status` read that produced the pid — never a pid
captured minutes earlier. `lock_holder_captured_at` (#2530 H1) is what makes
"minutes earlier" checkable instead of assumed: it is the wall-clock instant
the `lock_holder_pid` snapshot was taken, so before acting on a pid you can
see for yourself whether it is fresh or something you should re-read before
trusting.

**Retirement preconditions — and why there is no retire endpoint.** An old
KEK version is only safe to destroy when **both** hold: (1) zero stored
blobs reference it (`GET /status`'s `oldest_in_use` has moved past it), and
(2) no backup you intend to be able to restore still contains rows wrapped
under it — a restored backup needs the KEK version its rows reference, so
you must retain every version referenced by any backup inside your
retention window. That second condition is a policy decision only you can
make; this document will not pick a number for you:

> **Operator decision — set your backup-retention window here:**
> `<SET-ME: e.g. "90 days" / "13 monthly backups" — however long you keep a
> backup you intend to be able to restore>`. Retain every KEK file that
> covers that window. Set this **too short** and a restore from an older
> backup can be permanently undecryptable; set it (or "forever") and you
> simply keep more small key files around — annoying, never unsafe.

Given that, Yuzu deliberately ships **no** retire/decommission route or MCP
tool, even though `SecretCodec::retire_kek` exists internally and is
tested. **#2525 documents a write race that makes exposing it unsafe:**
`SecretCodec::encrypt()` snapshots the active KEK version, releases its
lock, and the *caller* persists the resulting blob afterwards — so a
retirement can pass its "zero references" check and delete the key while an
in-flight write is still about to commit a blob wrapped under exactly that
version, permanently bricking that row. This is not an HA-only hazard; it
reproduces on a single server, and no lock this surface could take would
close it, because ordinary secret writers don't participate in the KEK
operation lock. Advertising a version as "safe to retire" without a safe way
to retire it would be worse than saying nothing.

**Consequence for you: old KEK files accumulate, and that is correct and
safe.** They cost a few dozen bytes each and are exactly what you need to
restore an older backup. **Do not delete a KEK file by hand** — there is no
supported path to determine it's truly safe to remove, and doing so risks
exactly the permanent data loss #2525 describes.

**Audit evidence.** A successful rotation produces **two** audit rows by
design, not a duplicate bug: a system-attributed `kek.rotated` (emitted
inside the codec itself, detail `{"kek_version": <N+1>}`) and an
operator-attributed `kek.rotate` (emitted by the REST route / MCP tool that
invoked it, detail `new_version=<N+1>`). The codec-level event genuinely
cannot know which operator called it — attribution rides the caller's
session, which only the surface that received the request has (ADR-0010,
design review "arch-7") — so an auditor correlating the audit log should
expect the pair, not treat it as a double-count. `rewrap`/`rewrap_secrets`
similarly audits `kek.rewrap` with `rows_rewrapped=<n>`; `GET
/status`/`get_kek_status` is read-only and is not audited (matches the
internal-CA read routes).

Decrypt failures are counted per store and failure class as
`yuzu_server_secret_decrypt_failures_total{store, failure_class}` (classes:
`tag_mismatch`, `kek_unresolvable`, `malformed_blob`, `crypto_failure`).
**This is live as of the auth store's Postgres migration** — the auth store
(`auth.users.mfa_totp_secret`, TOTP secrets) is the first secret-bearing
store to ship, so `store="auth"` is the only label value today. A sustained
non-zero `kek_unresolvable` rate after a deployment or restore is the
primary backup-skew alert signal; a single-row `tag_mismatch` is the tamper
signal and warrants investigation, not retry. Ready-made alert rules for
both are in `docs/prometheus/yuzu-alerts.yml` (group `yuzu-secrets`).

**KEK rotation-runaway metrics (#2530).** Sampled every 15s on the same
background thread that recomputes fleet health (`health_recompute_thread_`),
never synchronously inside the `/metrics` handler itself — so a slow or
unreachable database degrades a *stale* gauge value on the next scrape
rather than stalling or failing the scrape during exactly the incident an
operator needs it for. **The sampler's reads run inside an explicit
transaction with a 500ms `SET LOCAL statement_timeout` (#2530 G7-B4)** — not
just a bounded pool acquire — because this is a SERIAL thread shared with
the security-relevant agent-revocation teardown sweep (and joined before
`pg_pool_.reset()` in `stop()`); an unbounded statement here previously
could hold that shared thread for a long multiple of a healthy pass.

| Metric | Type | Meaning |
|---|---|---|
| `yuzu_server_kek_op_lock_held` | gauge | `1` if `secrets_kek_op` currently has a granted holder **in this server's own database** (filtered by `current_database()`, not cluster-wide), else `0`. |
| `yuzu_server_kek_live_versions` | gauge | Count of non-retired KEK versions. Compare against `yuzu_server_kek_max_live_versions`. |
| `yuzu_server_kek_active_version` | gauge | The KEK version new secrets are currently encrypted under. |
| `yuzu_server_kek_max_live_versions` | gauge | The configured `--kek-max-live-versions` ceiling (#2530 G8-S12). Unlike the three gauges above, this is a **static config value set once at boot**, not sampled from Postgres on the 15s sweep — it stays published even when the KEK substrate itself is never reachable. `yuzu_server_kek_live_versions / yuzu_server_kek_max_live_versions` is the ceiling-proximity ratio the `YuzuKekCeilingApproaching` alert (`docs/prometheus/yuzu-alerts.yml`) fires on at 0.8 — because there is no retire route (#2525), this ceiling is a lifetime cap, and without this alert the first signal is a `409 VersionCeiling` at the moment rotation is needed. |
| `yuzu_server_kek_operations_total{op,outcome}` | counter | Rotate/rewrap/status attempts. `op` is one of `rotate`\|`rewrap`\|`status`; `outcome` is one of `success`, `conflict`, `cooldown`, `ceiling`, `query_canceled`, `clock_anomaly`, `half_committed`, `unavailable`, `internal`. Pre-seeded to 0 for every `{op,outcome}` combination at boot, so an outcome that has never fired reads as a true zero, not absent. |
| `yuzu_server_kek_metrics_unavailable_total` | counter | KEK cluster-state reads that could not reach Postgres (pool acquire failure, statement_timeout, or the substrate never being wired up at all) — see "Diagnosing a stuck KEK op lock" and the `YuzuKekMetricsUnavailable` alert. Short-circuits after the first failed read within a sweep (#2530 G8-S2), so this is at most one increment per 15s sweep. |

**`yuzu_server_kek_oldest_version_in_use` was RETIRED from this sampler
(#2530 G7-B4)** — it was the one query here that is an UNBATCHED
full-column scan (`SecretCodec::oldest_kek_version_in_use`), whose scale
ceiling #2530 explicitly deferred as out of scope (see the registered-column
trip-wire test). Running that scan every 15s instead of only on operator
demand made the deferred problem worse, not better, so it was dropped from
the periodic sweep and the gauge was deleted. `GET /status`'s
`oldest_in_use` field is unaffected — it still computes this value on
demand, which is where a full-column scan belongs.

On a database-read degrade during a sampling pass, every gauge above **HOLDS
its prior published value** rather than publishing a fabricated `0` — a
metric nobody could read is absent, never a false "no KEK versions" /
"lock free" reading during exactly the outage you'd want this for — and
`yuzu_server_kek_metrics_unavailable_total` (counter) is bumped instead, so
a sustained increase there is itself the "these KEK gauges are stale" signal
(this now also fires when the KEK substrate itself — `auth_secret_codec_`/
`pg_pool_` — is unavailable, not only on a query-level degrade, #2530
G7-M1). A ready-made alert for a persistently-held op lock, and a second for
a sustained metrics-unavailable rate, are in `docs/prometheus/yuzu-alerts.yml`
(group `yuzu-secrets`) — see "Diagnosing a stuck KEK op lock" above before
acting on the first one.

**`yuzu_server_kek_operations_total`'s `{op,outcome}` accumulator is
published even when the KEK substrate is unavailable (#2530 G7-M1).** An
earlier cut of this pass published it only from inside the same guard that
gates the Postgres-backed gauges above — which is the EXACT condition under
which every KEK operation records `outcome="unavailable"`, so the counter
went dark precisely when the outcome it exists to show was firing. It is a
pure in-process accumulator read (no DB access), so it now publishes
unconditionally on every sampling pass.

#### DR restore-pairing drill

Run this periodically against a scratch environment, alongside the
PostgreSQL restore-verification drill in [Backing up PostgreSQL
state](#backing-up-postgresql-state) above.

This section is the source of truth for the **rotation** side of key
management. The **recovery** side — per-symptom boot triage, the paired
backup commands, and the post-restore verification that catches a
wrong-keys restore before users are locked out — lives in
`docs/ops-runbooks/auth-db-recovery.md`. Read both before running the drill;
they are deliberately not duplicated.

- **CH-1 — restore the database without the keys directory.** Restore a
  `pg_dump` to a scratch database but deliberately withhold (or point
  `--ca-dir` elsewhere from) the paired keys directory, then start the
  server against it. Expect a **loud, correctly-diagnosed** failure, not
  silence: the server fails closed at boot with a `kek_unresolvable` startup
  error (see the failure-class table above), and any MFA-enrolled user
  cannot complete TOTP login (the secret can't be decrypted) — but password
  login and recovery-code MFA fallback still work, because neither needs
  the KEK (see blast radius below). If you instead see a clean boot, the
  drill has failed — investigate before trusting production restores.
- **CH-2 — backup skew.** Restore a `pg_dump` paired with a keys directory
  from a *different* rotation generation than the dump (e.g. the dump is
  from after a rotation the keys directory predates, or vice versa).
  Watch `yuzu_server_secret_decrypt_failures_total{failure_class}` closely:
  a skew like this can produce a **flood** of `kek_unresolvable` events that
  buries a genuine, low-volume `tag_mismatch` (tamper) signal in the same
  window — alert on the *sustained rate*, not a raw count, and don't
  dismiss a skew incident just because most of the flagged rows turn out to
  be the benign skew case.
- **Quantified blast radius of KEK loss** (permanent, no paired backup
  exists to recover from): every TOTP-enrolled operator loses their TOTP
  secret and must re-enroll — but they are **not locked out**, because MFA
  recovery codes are PBKDF2 verify-only hashes that need no KEK to redeem
  (this is precisely why KEK loss is not a total lockout); sign in with a
  recovery code, then re-enroll TOTP. Password login is entirely unaffected
  (session tokens and password hashes are not KEK-wrapped). Any future
  secret class gated behind the same codec (webhook signing secrets,
  offload-target credentials, the OIDC client secret, once each store
  migrates) would need re-issuing and its downstream reconfigured — there
  is no way to recover the old value.

**Break-glass (KEK permanently lost).** KEK loss is painful, never a total lockout: admin sign-in survives by design (MFA recovery codes are verify-only hashes and need no KEK — sign in with a recovery code and re-enroll TOTP), and every gated secret class is re-enrollable/re-issuable (webhook secrets re-issued, offload credentials re-issued, OIDC client secret re-pasted). The explicit voided-secrets boot flag described in ADR-0010 ships with the first secret-bearing store migration.

---

## NVD CVE sync

The server maintains a local mirror of the NVD (National Vulnerability Database) CVE
catalog, used by the fleet-topology vulnerability overlay. On first boot it runs a
newest-first **backfill** of the full catalog, then switches to periodic freshness
re-checks. Configuration is via CLI flags at startup (each has an env-var equivalent).

| CLI Flag | Env | Default | Description |
|---|---|---|---|
| `--nvd-api-key` | `YUZU_NVD_API_KEY` | *(none)* | NVD API key. Raises the NVD rate limit substantially — the difference between the initial backfill taking minutes versus hours. |
| `--nvd-proxy` | `YUZU_NVD_PROXY` | *(none)* | HTTP proxy URL for egress to `services.nvd.nist.gov`, for deployments with restricted outbound network access. |
| `--nvd-sync-interval` | `YUZU_NVD_SYNC_INTERVAL` | `4` | Freshness re-check cadence, in hours, once the backfill has completed. |
| `--nvd-backfill-years` | `YUZU_NVD_BACKFILL_YEARS` | `8` | How far back (in years) the newest-first backfill walks. `0` = full history. The floor is clamped to NVD's catalog start (1999-01-01) and to a 200-year effective maximum, so no value reaches before the catalog begins. |
| `--no-nvd-sync` | `YUZU_NO_NVD_SYNC` | off | Disable NVD sync entirely. |

> **Note:** the initial backfill makes sustained HTTPS requests to `services.nvd.nist.gov`
> and grows the local NVD database to hundreds of MB. Without an API key it can take hours.
> The backfill is resumable — after a restart it resumes from where it left off rather than
> starting over. Sync progress is observable via `GET /api/nvd/status`
> (`backfill_complete`, `backfill_oldest_published`, `total_cves`).

**Rate-limit and auth-error handling:** HTTP 429 responses are backed off automatically (honouring `Retry-After`, else exponential to a 30-minute cap) and the same page is retried — expect `NVD HTTP 429 … backing off` warnings during a large backfill without an API key; this is expected, not a failure. HTTP 403 means a bad or revoked `--nvd-api-key`: it is logged distinctly and NOT retried — check/rotate the key. Both surface via `yuzu_nvd_sync_failures_total{reason=...}` (see the [metrics reference](metrics.md#nvd-cve-sync-metrics)).

---

## Retention Settings

The server applies retention policies to stored data to manage disk usage. Retention values are set via CLI flags at startup.

| Data Type | CLI Flag | Default TTL | Description |
|---|---|---|---|
| Instruction responses | `--response-retention-days` | 90 days | Results from executed instructions. Older responses are purged on a daily schedule. |
| Audit log entries | `--audit-retention-days` | 365 days | Records of who did what, when, and on which devices. |
| Guardian (Guaranteed State) events | `--guardian-event-retention-days` | 30 days | Guaranteed State drift events, remediation events, and agent-sync events written by the Guardian engine. See [Guaranteed State](guaranteed-state.md) for the feature context. |

Increasing a TTL preserves more history for compliance. **Reducing one does not
reclaim disk retroactively** -- and that is true of all three stores, not just
the audit log. Each stamps `ttl_expires_at` once, at INSERT, from the retention
setting in force at the time (`AuditStore::log`, `ResponseStore::store`,
`GuaranteedStateStore::compute_ttl_epoch`), and nothing ever rewrites it, so
existing rows always age out on their original TTLs. Only rows written after the
change (and, per the #483 note below, after a restart) get the shorter window.

What is specific to the audit log is *how* the expired rows then leave: see the
note below.

> **Audit retention is a floor, not a ceiling.** A cleanup pass declines once
> when it would expire every datable row, and every accepted pass is capped at
> 25,000 rows, so deletion is paced rather than immediate.
>
> One side effect of the shared insert-stamped-TTL scheme is specific to this
> guard and worth knowing: the guard's "is any datable row still alive?"
> horizon is derived from the CURRENT window, so after a reduction the older
> long-TTL rows fall outside it and stop counting as survivors. That makes a
> single declined pass more likely right after the change. It is self-healing --
> see [The retention clock guard](audit-log.md#the-retention-clock-guard).

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

**Stopping a wedged agent (Linux/macOS).** `SIGTERM`/`SIGINT` (`systemctl stop`,
Ctrl-C) triggers a graceful agent stop — plugin shutdown, thread joins, store
close. If that teardown hangs (e.g. the server is unreachable and a drain is
stuck), **send the signal a second time** (`kill -TERM <pid>` again, or a second
Ctrl-C): the agent immediately hard-exits with code 1. This escalation is
deliberate and has **no grace window** — the second signal always force-exits,
even if the first stop was progressing normally — so double-signalling stop
tooling will force-kill healthy agents; send one signal and wait. You no longer
need `SIGKILL` to recover a stuck agent. SQLite state is WAL crash-safe across
the hard exit. On Windows, a second Ctrl-C also terminates promptly (via the
escalation or the CRT's default disposition); the service path (`sc stop`) is
unchanged. If the agent logs `shutdown watcher unavailable` at boot (thread/fd
exhaustion), a hard-exit handler is installed instead: the agent exits promptly
on the FIRST signal, ungracefully — no plugin shutdown, no clean store close.
(A default signal disposition would be discarded by PID 1 in a container, so
the handler is the posture that stays killable.)

**Crash-loop backstop (systemd).** The `yuzu-agent` unit sets `Restart=always` +
`RestartSec=10`, but also `StartLimitIntervalSec=300` + `StartLimitBurst=5` (ADR-0021
rung 7.7a). A Guardian I/O worker wedged past its grace period triggers a `hard_exit()`;
against a *permanently* wedged target (a dead NFS mount, a hung service query) that would
otherwise restart-loop every 10s forever. Instead, after 5 restarts within 300s systemd
puts the unit into `failed` and stops retrying (the device goes dark rather than looping
silently). Recover with `systemctl reset-failed yuzu-agent && systemctl start yuzu-agent`
once the wedged target is resolved. Alert on the `failed` state; the old restart-forever
behaviour hid a crash-looping agent.

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

On Windows, the Yuzu **agent** has a native Windows service wrapper (`yuzu-agent.exe --install-service`); this is what the shipped installer uses, and is the recommended path — see the **Agent: `--install-service`** subsection below. A native wrapper for the Yuzu **server** is still planned for a future release; until then, use `sc.exe` or NSSM (Non-Sucking Service Manager) for the server, as described below.

### Agent: `--install-service` (native, recommended)

```cmd
REM Register the service (binPath is written for you, including the internal
REM --service marker the agent needs to run under the SCM control protocol)
yuzu-agent.exe --install-service

REM Point it at your server / data dir / log file via sc config. binPath= takes a
REM SINGLE value, so the whole "exe + arguments" string must be ONE quoted token,
REM with the quotes around a spaced exe path escaped as \" -- sc.exe does NOT
REM reassemble several quoted segments back into one binPath. Written the other way
REM round (quoting only the exe and leaving the flags bare after it) sc.exe parses
REM --service/--server/... as unknown OPTIONS to sc itself, prints its usage block,
REM and exits 1639 ERROR_INVALID_COMMAND_LINE without touching the service. That is
REM #1468: the shipped installer had exactly that defect, and because Inno ignores
REM [Run] exit codes it failed silently -- the service kept the argument-less binPath
REM --install-service had written, so the agent ran with no --server and fail-closed
REM on TLS. Check your work with `sc qc YuzuAgent`: every flag below must appear.
sc.exe config YuzuAgent binPath= "\"C:\Yuzu\bin\yuzu-agent.exe\" --service --server yuzu.example.com:50051 --data-dir \"C:\ProgramData\Yuzu\" --plugin-dir \"C:\Yuzu\plugins\" --log-file \"C:\Yuzu\logs\yuzu-agent.log\""

sc.exe start YuzuAgent
sc.exe stop YuzuAgent

REM Remove it
yuzu-agent.exe --remove-service
```

The service currently registers to run as **LocalSystem** (unchanged by the #1822 SCM-protocol fix — tracked separately as #1442). Moving it to a least-privilege account requires a manual post-install `sc.exe config obj= "NT SERVICE\YuzuAgent"` plus directory ACLs the installer doesn't set today — see `docs/agent-privilege-model.md` and #1442 for the tracked follow-up, and the [Service Account](#service-account) guidance below (written for the server, but the same `obj=` mechanism applies).

Re-running `--install-service` is idempotent — it updates an existing registration's binPath in place rather than failing with "service already exists", so it's safe to re-run after an upgrade. **It resets binPath to the bare exe + `--service` marker** (the same minimal form shown above), dropping any `--server`/`--data-dir`/`--plugin-dir`/`--log-file` a prior `sc config` had applied — always follow it with `sc.exe config` to restore your runtime args, exactly as the installer's own `[Run]` sequence does (`--install-service` then `sc config` then `sc start`). Recovery actions (3 restarts, 60s apart, resetting after 24h) are configured automatically and fire on both crashes and clean-exit-with-error.

> **Important:** the `--service` flag tells the binary to speak the SCM control protocol (`ServiceMain`/`SetServiceStatus`) instead of running as a console program — it is added automatically by `--install-service` and must be present in any `sc.exe`/manually-crafted binPath for the agent. Omitting it reproduces the pre-fix behavior: `sc start` fails with error 1053. Do **not** add `--service` when wrapping the agent with NSSM (below) — NSSM launches the agent as an ordinary child process, not via the SCM itself, so the agent would try (and fail) to connect to a dispatcher that isn't there.

> **Fleet-upgrade gotcha:** because `--install-service` always resets binPath to the bare minimal form, a silent/unattended re-run of the shipped installer (e.g. an SCCM/Intune package upgrade) that does **not** re-supply the original `/SERVER=`/`/TOKEN=`/`/NOTLS` parameters on that specific invocation will reconfigure the agent back to `localhost:50051` with TLS on — and because the SCM protocol now actually works (post-#1822), the service **starts successfully** against that wrong address instead of failing loudly the way it always did before this fix. The agent goes dark from the fleet with no installer-visible error. Always replay the same install-time parameters on every upgrade run, not just the first install.

**If `sc start YuzuAgent` still fails after this fix:** check the log file first (`{app}\logs\yuzu-agent.log` via the installer; `<data-dir>\yuzu-agent.log` if you configured `--service` manually without `--log-file`) — it has the actual reason. `sc query YuzuAgent`/Event Viewer only distinguish which of three generic buckets: **specific error 1** covers three distinct causes that land on the same code — the agent failed to construct (bad `agent.db`, SQLite/config problem), **or** startup completed but the gRPC channel couldn't be built under the fail-closed TLS posture (missing/unreadable CA or client cert/key, #1303) — including, notably, the exact misconfiguration the fleet-upgrade gotcha above can introduce by silently flipping TLS back on — **or** a mid-life failure: the dispatch thread pool could not be re-created on a reconnect (host out of threads), which previously ended the service silently as a clean stop; **specific error 2** (the agent stopped on its own without a stop/shutdown request — unexpected, check the log for what `run()` returned early on); **specific error 3** (an unhandled exception reached the service dispatcher — check the log for the exception message). None of these three codes carry more detail on their own; the log file is where the actual cause lives.

### Server: sc.exe (native wrapper not yet available)

```cmd
REM Create the Yuzu server service
sc.exe create YuzuServer binPath= "C:\Yuzu\yuzu-server.exe --https-cert C:\Yuzu\certs\server.crt --https-key C:\Yuzu\certs\server.key" start= auto DisplayName= "Yuzu Server"

REM Set startup type to automatic (delayed start, recommended)
sc.exe config YuzuServer start= delayed-auto

REM Configure recovery: restart on first, second, and subsequent failures
sc.exe failure YuzuServer reset= 86400 actions= restart/5000/restart/10000/restart/30000

REM Start / stop the service
sc.exe start YuzuServer
sc.exe stop YuzuServer
```

> **Note:** With `sc.exe`, spaces after `=` are required (e.g., `start= auto`, not `start=auto`). This is a quirk of the `sc.exe` command parser.

### Using NSSM

[NSSM](https://nssm.cc/) provides a more user-friendly wrapper with a GUI configuration dialog. It remains a valid option for the **server** (no native wrapper yet) and for the **agent** if you prefer NSSM's process-monitoring/log-rotation over the native `--install-service` path — just don't pass `--service` to an NSSM-wrapped agent (see the note above).

```cmd
REM Install services
nssm install YuzuServer "C:\Yuzu\yuzu-server.exe"
nssm install YuzuAgent "C:\Yuzu\yuzu-agent.exe"

REM Set arguments (no --service for the NSSM-wrapped agent)
nssm set YuzuServer AppParameters "--https-cert C:\Yuzu\certs\server.crt --https-key C:\Yuzu\certs\server.key"
nssm set YuzuAgent AppParameters "--server yuzu.example.com:50051"

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
