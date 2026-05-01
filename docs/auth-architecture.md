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
