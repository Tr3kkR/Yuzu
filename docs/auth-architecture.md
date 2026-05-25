# Authentication & Authorization — Yuzu Server

Reference for the authentication and authorization features implemented in the Yuzu server. CLAUDE.md keeps only the hard invariants; this document is the implementation history and feature inventory.

## Transport and identity

- **mTLS** for agent ↔ server gRPC connections. Note that a migration from gRPC->QUIC is intended.
- **Windows certificate store integration** — agent can read mTLS client cert + private key from the Windows cert store instead of PEM files. Uses CryptoAPI/CNG (`CertOpenStore`, `CertFindCertificateInStore`, `NCryptExportKey`). Searches Local Machine first, falls back to Current User. Exports full certificate chain (leaf + intermediates) as PEM. CLI flags: `--cert-store MY --cert-subject "yuzu-agent"` or `--cert-thumbprint "AB12..."`.
- **Certificate hot-reload** — HTTPS cert/key PEM files are polled for changes (default 60s interval) and hot-swapped without server restart. Validates PEM parse, cert/key match, and key file permissions before applying. gRPC TLS reload not supported. CLI: `--no-cert-reload`, `--cert-reload-interval`. Audit action: `cert.reload`. Metrics: `yuzu_server_cert_reloads_total`, `yuzu_server_cert_reload_failures_total`.

Certificate setup instructions: `scripts/Certificate Instructions.txt`.

## Login and session management

- **RBAC login** — session-cookie auth with PBKDF2-hashed passwords in `yuzu-server.cfg`. Legacy roles: `admin` (full access) and `user` (read-only). First-run interactive setup prompts for credentials.
- **Login page** — dark-themed, with greyed-out OIDC SSO stub where appropriate. Yuzu does not support Light Mode.
- **Settings page** (admin-only) — TLS toggle, PEM cert upload, user management, enrollment tokens, pending agent approvals, AD/Entra section.
- **Hamburger menu** — upper-right dropdown with Settings, About (popup), and Logout.
- **Auth middleware** — `set_pre_routing_handler` redirects unauthenticated requests to `/login`, returns 401 for API calls.
- **HTMX paradigm** — Settings page uses HTMX for all server interactions; server renders HTML fragments. Vanilla JS reserved only for clipboard copy. Dominant UI pattern going forward.
- **Session revocation REST surface (CC6.3 revocation, CC6.7 disposition, CC6.8 termination).**
  - `DELETE /api/v1/sessions?username=<name>` — admin-only via `UserManagement:Write`. Cookie sessions only; API tokens deliberately not revoked.
  - `DELETE /api/v1/sessions/me` — any interactive authenticated principal. Wipes cookie sessions AND revokes the caller's API tokens (lost-laptop UX). MCP-tier and service-scoped tokens rejected with 403. Response sets `Set-Cookie: yuzu_session=; Max-Age=0` so the client side completes the disposition.
  - Both wrap `AuthManager::invalidate_user_sessions`, which performs the dual-write (AuthDB DELETE first outside `mu_`, then in-memory `sessions_` erase under `mu_`) and returns `RevokeResult { count, db_persisted }`. In-memory wipe runs even if the DB write fails (operator's "stop NOW" intent), but `db_persisted=false` surfaces up so the REST handler audits `result="partial"` with `detail` carrying `db_error=true`. Defence-in-depth: the AuthDB primitive itself validates username (matches sibling `add_user` / `update_role`).
  - Audit actions split for SIEM correlation: `session.revoke_all` (cross-user) vs `session.revoke_all.self` (self via either route, including admin self-target through the admin path). Both use `target_type=User` (project PascalCase convention). `result` ∈ {`success`, `partial`, `denied`}.
  - Prometheus counter `yuzu_auth_sessions_revoked_total{caller, result, scope}` for CC7.2 anomaly detection.
  - Self-target guard distinction (DO NOT CONFLATE WITH `#397/#403`): the existing `#397/#403` self-target guard on `DELETE /api/settings/users/<self>` and role demotion is a hard 403 to prevent admin-role self-lockout (an unrecoverable state). Session revocation self-target is recoverable (re-auth) and is permitted but audited as `.self`. Future refactors must not "fix" the session-revocation self-target into a hard 403.

## Granular RBAC (Phase 3)

- 6 roles, 14 securable types, per-operation permissions, deny-override logic.
- **OIDC SSO** — Full PKCE flow, Entra ID discovery, JWT validation, group-to-role mapping.
- **AD/Entra integration** — Microsoft Graph API for user/group import.

## API tokens and automation

- **API tokens** — Bearer token and `X-Yuzu-Token` header auth for automation. MCP tokens (see `docs/mcp-server.md`) use the same table with mandatory expiration (max 90 days).
- **Ownership-scoped revocation** — `DELETE /api/v1/tokens/{id}` and `DELETE /api/settings/api-tokens/{id}` both require the caller to own the token; the global `admin` role is the sole bypass. Cross-user revoke returns `404 token not found` (identical to unknown-id, to prevent enumeration). Denied attempts are recorded with `result=denied`, `detail=owner=<principal>`. See #222 and `docs/user-manual/server-admin.md` "Upgrade Notes".

## Agent enrollment (3 tiers)

- **Tier 1 (manual approval)** — agents without a token enter a pending queue; admin approves/denies via Settings page. Agents retry and are accepted once approved.
- **Tier 2 (pre-shared tokens)** — admin generates time/use-limited enrollment tokens via the dashboard; agents pass `--enrollment-token <token>` at startup for auto-enrollment.
- **Tier 3 (platform trust)** — proto fields reserved (`machine_certificate`, `attestation_signature`, `attestation_provider`) for future Windows cert store / cloud attestation enrollment.
- **Enrollment token persistence** — tokens stored in `enrollment-tokens.cfg`, pending agents in `pending-agents.cfg` (same directory as `yuzu-server.cfg`).
- **Agent `--enrollment-token` CLI flag** — passes token in `RegisterRequest.enrollment_token`.

## Per-session peer binding and NAT-aware relaxation

`Register` and `Subscribe` are separate gRPC connections correlated by a
`session_id`. To stop a sniffed `session_id` from being replayed from another
host, Subscribe is bound to the Register connection by **two layers**:

- **Peer-IP binding (#826, hardened #1058/#1059)** — Subscribe's source IP must
  equal the IP recorded at Register (or, under `--gateway-mode`, a trusted
  gateway IP). A mismatch increments
  `yuzu_grpc_subscribe_peer_mismatch_total{event="security"}` and emits a
  `session.peer_mismatch` audit row (`result="denied"`).
- **Identity binding (authoritative)** — the `agent_id`↔session binding (#827)
  and, under mTLS, the client-identity binding (#1118,
  `yuzu_grpc_subscribe_identity_mismatch_total`). These are *stronger* than
  source IP.

**NAT-aware relaxation (#1128).** Exact-IP binding false-rejects a legitimate
agent whose Register and Subscribe egress *different* public IPs (multi-egress
NAT, proxy pool, CG-NAT, SD-WAN). Strict exact-match is the **default**; two
**opt-in** accommodations downgrade a mismatch to *advisory* (audit + metric, no
reject) instead:

1. **mTLS-advisory** — when a verified client identity matches the one bound at
   Register, the IP is defence-in-depth only (the identity layer is
   authoritative), so the mismatch is tolerated.
2. **`--trusted-nat-cidr <cidr>[,…]`** (`Config::trusted_nat_cidrs`) — when the
   Register *and* Subscribe IPs both fall inside one operator-declared range
   (analogous to `--gateway-mode`, but for direct-connect NAT).

A mismatch *outside* both accommodations is still a hard reject — the replay
guard is intact, and an empty/malformed extracted IP is always reject (#826:
empty is a mismatch, never a wildcard). A tolerated mismatch emits
`yuzu_grpc_subscribe_peer_advisory_total{event="security",reason=…}` plus a
`session.peer_mismatch` audit row with `result="ok" outcome=advisory`. The pure
decision lives in `AgentServiceImpl::evaluate_peer_binding` (unit-tested);
CIDR containment in `cidr_match.{hpp,cpp}`.

**Gateway origin-IP attribution (#1064).** On the gateway `ProxyRegister` path
the server's transport peer is the *gateway's* IP, so audit rows would
mis-attribute the source (SOC 2 IR-2). `RegisterRequest.gateway_observed_peer`
(an optional, gateway-authoritative, transport-agnostic field — survives the
planned gRPC→QUIC move) carries the agent's origin IP; the server records
`source_ip`=agent origin and `gateway_ip`=transport peer, falling back to the
gateway IP (`origin_observed=false`) when absent. The *direct* Register path
ignores the field (spoof-safe). **Server-side consumption ships now; the
gateway-side population is a follow-up** — today's grpcbox transport can only
source it from `x-forwarded-for` (proxied deployments), and the durable
direct-mode source arrives with the QUIC transport (#376) that owns its socket.

## HTTPS and bind defaults (hard invariants)

- **HTTPS by default** — `https_enabled` defaults to `true`. Operators must provide `--https-cert` and `--https-key`, or use `--no-https` for development. The `--https` flag was replaced with `--no-https`.
- **Secure bind default** — Web UI binds to `127.0.0.1` by default (not `0.0.0.0`). A startup warning is logged if overridden to all interfaces.
- **Metrics auth** — `/metrics` allows unauthenticated access from localhost only. Remote access requires authentication. `--metrics-no-auth` overrides for monitoring infrastructure.
- **Private key permission validation** — Server refuses to start if TLS private key files are group/others-readable on Unix. Uses `std::filesystem::perms` check. Skipped on Windows.
- **CORS on all API endpoints** — CORS headers applied via `set_post_routing_handler` for all `/api/` paths.
- **JSON error envelope** — All error responses use structured `{"error":{"code":N,"message":"..."},"meta":{"api_version":"v1"}}` envelope. Health probes (`/livez`, `/readyz`) use `{"status":"..."}` contract.

## HTTP security response headers (SOC2-C1)

All HTTP responses (dashboard, REST API, MCP, metrics, health probes) carry six headers: `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy` (deny-all baseline for camera/mic/geo/usb/etc.), and `Strict-Transport-Security: max-age=31536000; includeSubDomains` (HTTPS only, per RFC 6797).

The CSP is fully `'self'`-only with no external CDN allowance because the HTMX runtime and SSE extension are embedded in the server binary (`server/core/src/static_js_bundle.cpp`) and served from `/static/htmx.js` and `/static/sse.js` — the dashboard works in air-gapped deployments.

The CSP uses `'unsafe-inline'` for `script-src`/`style-src` because the dashboard has inline `<script>`, `onclick=` handlers, and `<style>` blocks; tightening to nonce-based CSP requires a separate dashboard refactor. `upgrade-insecure-requests` is appended to the CSP only on HTTPS deployments.

Operators can extend the CSP via `--csp-extra-sources "https://cdn.example.com https://beacon.example.com"` (space-separated, validated at CLI parse — control bytes / semicolons / `'unsafe-eval'` are rejected at startup with a clear error). The flag's value is appended to `script-src`/`style-src`/`connect-src`/`img-src` only.

Header construction lives in `server/core/src/security_headers.{hpp,cpp}` (`yuzu::server::security` namespace) — the production server and the unit/integration tests in `tests/unit/server/test_security_headers.cpp` (38 cases) share the same `HeaderBundle::make()`/`apply()` code path. The resolved bundle is logged at INFO at startup so operators can confirm activation: `Security headers active: CSP=N bytes, HSTS=on/off, Referrer-Policy="...", Permissions-Policy=N bytes`.

## Self-target principal-destruction guard (hard invariant, #397/#403/ca-B1)

Any handler that destroys, demotes, or otherwise revokes a principal's privileges MUST reject the case where the URL/form target equals the caller's `session->username` (or differs from `session->role` for upserts that demote). UI suppression alone is insufficient — a hand-crafted HTTP request bypasses the dashboard.

**Load-bearing routes today:**

- `DELETE /api/settings/users/:name` — self-delete
- `POST /api/settings/users` — self-demote via role change

**Pattern requirements:**

1. Compare against `session->username` byte-exact. Fail closed when `session->username.empty()`.
2. Emit `audit_fn_(req, "<noun>.<verb>", "denied", "User", target, "<reason>_blocked")` on the rejection branch — `spdlog::warn` alone breaks the SOC 2 CC7.2 evidence chain.
3. Corresponding fragment renderers must accept the session username and suppress destructive controls on the matching row (see `render_users_fragment(const std::string& current_username)` — no default arg, every caller must pass explicitly so a future caller forgetting it is a compile-time failure rather than a silent UI regression).

**Scaling note:** when the third such handler ships, lift the comparison logic into a helper.

## AuthDB — persistent authentication store (v0.12.0+)

`auth.db` (lives in `--data-dir`) is the v0.12.0 SQLite-backed store for user
accounts, sessions, and enrollment tokens. Replaces the prior in-memory +
on-config-flush model that lost users on every restart (#618, #388, #527).
Operator recovery: `docs/ops-runbooks/auth-db-recovery.md`. Security review
record: `docs/security-reviews/authdb-2026-04-30.md`.

The hard invariants for AuthDB-touching changes (file-mode, migration
pattern, lifetime, config-as-seed-only, role-field ignored, gate-level audit,
cleanup cadence, snapshot-and-release publishing) live in
`.claude/agents/authdb.md` — the AuthDB review agent loads them on any
change to `auth_db.{hpp,cpp}` / `auth_routes.{hpp,cpp}` / `auth_manager.cpp`.
