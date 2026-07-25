---
name: auth-and-authz
description: Authentication & Authorisation control plane for Yuzu — the canonical entry point for any work on RBAC, OIDC SSO, SAML, SCIM, MFA/TOTP, AD/Entra integration, API tokens, session lifecycle, enrollment, and the audit/evidence chain. Use when the user says "/auth-and-authz", "/auth", "/iam", asks to plan or implement an enterprise A&A feature, asks "what's our auth gap to enterprise readiness", asks to audit current auth state against SOC 2 CC6.x / Workstream B, or starts work that touches `auth_*`, `rbac_*`, `oidc_*`, `api_token_*`, `enrollment_*`, or `cert_store.*`. The skill bundles current-state inventory, required-features inventory, gap matrix, the canonical workflow for adding a new A&A feature, and the load order for the routed reference docs.
---

# Authentication & Authorisation skill

The single entry point for any A&A work in Yuzu. Bundles three things:

1. **Current state** — what's shipped today and where it lives.
2. **Required state** — the enterprise/SOC 2 feature set we owe customers.
3. **Gap matrix + workflow** — what's missing and the standard procedure for
   closing a gap.

This skill does NOT replace the routed docs or specialist agents. It tells
you which to load, in which order, and what questions to ask before you
start cutting code.

---

## Usage

```
/auth-and-authz                # default: print gap matrix + suggested next gaps
/auth-and-authz audit          # produce a compliance-ready snapshot of A&A state
/auth-and-authz plan <feature> # plan-only walk-through for a single feature (e.g. SAML, SCIM, TOTP)
/auth-and-authz implement <feature>  # full workflow: plan → governance → implement → test → docs
```

If the user invokes the skill without a subcommand, default to printing the
**gap matrix** (Section 3) and asking which gap they want to work on.

---

## 1. Current state — what's shipped

Authoritative reference: `docs/auth-architecture.md`. Read it before this
skill claims anything is "done."

### Shipped capabilities

| Capability | Status | Source of truth |
|---|---|---|
| Local password auth (PBKDF2-SHA256) | Shipped (v0.10) | `auth.cpp:69` `pbkdf2_sha256()` (OpenSSL `PKCS5_PBKDF2_HMAC` + BCrypt path) |
| Persistent auth store (`auth.db`, SQLite) | Shipped (v0.12) | `auth_db.cpp:222-236` chmod 0600 + L402 `MigrationRunner::run`; agent-doc `.claude/agents/authdb.md` |
| Session-cookie auth (HTMX dashboard) | Shipped | `auth_routes.cpp:43,386` (`extract_session_cookie`, `Set-Cookie: yuzu_session=…`) |
| API tokens — Bearer + `X-Yuzu-Token` | Shipped | `api_token_store.cpp` (store); both header forms parsed at `auth_routes.cpp:108-119` |
| Owner-scoped token revocation (#222) | Shipped | `rest_api_v1.cpp:1058-1082` (owner-vs-admin check at L1060) |
| Granular RBAC — 7 roles (adds `Reviewer`, access-review attestation) × **22** securable types × 7 ops (adds `Attest`, gated via the dedicated `AccessReview` securable — NOT `AuditLog`, see #2225 round 2) | Shipped (Phase 3) | `rbac_store.cpp:260-295` — types: Infrastructure, UserManagement, InstructionDefinition, InstructionSet, Execution, Schedule, Approval, Tag, AuditLog, Response, ManagementGroup, ApiToken, Security, Policy, DeviceToken, SoftwareDeployment, License, FileRetrieval, GuaranteedState, Inventory, AccessReview, SoftwareLicensing; ops: Read/Write/Execute/Delete/Approve/Push/Attest |
| Self-target principal-destruction guard (#397/#403) | Shipped | `settings_routes.cpp:434,1830,2488-2504` (3 call sites); design in `docs/auth-architecture.md` §self-target |
| OIDC SSO — full PKCE flow, Entra discovery, JWT validation | Shipped | `oidc_provider.cpp:189` `generate_code_verifier()`, L194 `compute_code_challenge()`, L385 `code_verifier` post, L766 `/.well-known/openid-configuration` discovery, L542/L623 JWKS fetch + JWT signature verify |
| Directory Sync — AD/Entra users + groups + role mapping via Microsoft Graph v1.0 | Shipped | `directory_sync.cpp:336,509,556,608` calls `https://graph.microsoft.com/v1.0/users`, `/groups`, `/groups/{id}/members`; persisted `directory_group_role_mappings` + `directory_sync_status` tables (`directory_sync.cpp:147`). NOTE: `oidc_provider.cpp:248` only parses the JWT `groups` claim — Graph integration is the separate Directory Sync subsystem. |
| mTLS for agent ↔ server | Shipped | `main.cpp:111` `--ca-cert` flag; peer-cert identity match in `agent_service_impl.cpp:47,354` |
| Windows certificate-store mTLS (CryptoAPI/CNG) — **agent-side only** | Shipped | `agents/core/src/cert_store.cpp:78,84,199-201` (`CertOpenStore`, `NCrypt` CNG export) |
| HTTPS-by-default, secure bind default (127.0.0.1) | Shipped (hard invariant) | `main.cpp:100` 127.0.0.1 default, L216 `--no-https` opt-out; design in `docs/auth-architecture.md` |
| HTTP security headers — six (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) | Shipped (SOC2-C1) | `security_headers.cpp:187-195` (HSTS conditional on HTTPS responses) |
| Cert hot-reload (HTTPS) with audit + metrics | Shipped | `cert_reloader.cpp:31` audit `cert.reload`, L80 watcher loop, L114-191 atomic `SSL_CTX` swap |
| Agent enrollment — pre-shared / platform-trust (auto-approve via attestation_provider) / admin-approval queue (3 tiers) | Shipped | `auth.cpp:717-948` + `agent_service_impl.cpp:67-189` (pre-shared L70, attestation auto-approve L101-136, pending-admin queue L138-189) |
| MCP token issuance + tier-before-RBAC ordering | Shipped | `mcp_server.cpp:556-557,591,599` (tier check at L591 precedes RBAC at L599); design in `docs/mcp-server.md` |
| `auth.admin_required` denied audit on every 403 | Shipped (gate) | `auth_routes.cpp:150` inside `require_admin` |
| Private-key permission validation | Shipped | `cert_reloader.cpp:120` `validate_key_file_permissions()` (helper in `file_utils.hpp`); called at startup from `server.cpp` and on hot-reload |
| Metrics endpoint localhost-only-no-auth | Shipped | `server.cpp:1621` (loopback always unauthenticated; remote behavior toggled by `cfg.metrics_require_auth`) |
| Account lockout after N failed local-password logins | Shipped (SOC 2 CC6.3) | `auth.db` v3 columns + `AuthDB::lockout_status`/`record_failed_login`/`clear_failed_logins` (`auth_db.cpp`); `POST /login` pre-check + record/clear (`auth_routes.cpp`); admin unlock `POST /api/v1/users/<name>/unlock` (`rest_api_v1.cpp`); `--auth-lockout-threshold`/`--auth-lockout-window-secs` (`main.cpp`). Generic-401 (no enum/oracle), auto-expiring window, audit `auth.lockout.applied`/`.cleared`. Ref: `docs/auth-architecture.md` "Account lockout". |
| MFA / TOTP — full ladder (enrollment + login challenge + recovery codes; step-up on 11 high-risk surfaces; enforcement modes + OIDC `amr` short-circuit + login-time enrollment bootstrap) | Shipped (v0.12–v0.13, SOC 2 CC6.6) | `server/core/src/totp.{hpp,cpp}` (RFC 6238 + base32); `AuthDB::mfa_*` accessors; `POST /login` 202-branches + `POST /login/mfa`, `/login/mfa/stepup`, `/login/mfa/enroll` at `auth_routes.cpp`; `require_mfa_step_up` + `amr_asserts_mfa` at `mfa_step_up.{hpp,cpp}`; `--mfa-enforcement` at `main.cpp`; Settings panel + self-target disable guard at `settings_routes.cpp`. Remaining: at-rest TOTP-secret encryption — **mechanism decided by ADR-0010** (SecretCodec envelope encryption at the `auth` store's Postgres migration; the `auth_kv` scaffolding will NOT be used). Full reference: `docs/auth-mfa-design.md`. |
| SCIM v2 provisioning — auto-create/deactivate/reactivate operators from an IdP, plus Groups→role mapping (`/scim/v2/*`, Users and Groups) | Shipped (SOC 2 CC6.2/CC6.7/CC6.8) | `server/core/include/yuzu/server/scim_store.hpp` (storage: `scim_resources`/`scim_tokens` inside `auth.db`, own `"scim"` migration component) + `scim_json.hpp` (JSON codec/discovery) + `scim_routes.{hpp,cpp}` (routes); provenance guard via `AuthDB::set_provisioning_source`/`get_provisioning_source` (`users.provisioning_source`, auth.db migration v7), now also re-checking `role == "user"`. `--scim-admin-group` grants `role=admin` to a SCIM-provisioned user currently in that group (Model A: IdP membership is authoritative, a manual role change is reverted on the next membership recompute). See `docs/auth-architecture.md` "SCIM v2 provisioning". |

---

## 2. Required state — enterprise / SOC 2 readiness

Source of truth: `docs/enterprise-readiness-soc2-first-customer.md`
**Workstream B — Identity, Access, and Administrative Security** (§3.2).
SOC 2 alignment: CC6.1 (logical access), CC6.2 (provisioning), CC6.3
(authentication), CC6.6 (privileged access), CC6.7 (change in role), CC6.8
(termination), CC7.2 (anomalies → audit).

### Required-but-not-yet-shipped feature inventory

| Feature | Workstream B line | SOC 2 link | Gap class |
|---|---|---|---|
| **MFA / 2FA / TOTP — full ladder** (PR 1 enrollment + login challenge; PR 2 step-up on 11 surfaces; PR 3 enforcement modes `admin-only`/`required` + OIDC `amr` short-circuit + login-time enrollment bootstrap; `docs/auth-mfa-design.md`) | "2FA/TOTP for high-risk approvals" | CC6.6 | **SHIPPED — ladder complete; only the at-rest TOTP-secret encryption follow-up remains (mechanism: ADR-0010 SecretCodec, rides the `auth` Postgres migration)** |
| **Hardened-mode local-password disable** | "Disable local-password fallback in hardened mode" | CC6.3 | **SHIPPED** — `--auth-mode=sso-only` (`Config::auth_mode`) disables local-password login fleet-wide (only OIDC mints a session); boot **fails closed** without OIDC. Gate in `auth_routes.cpp` `POST /login` returns the same generic 401 (no oracle); denial is metric-only (`yuzu_auth_local_disabled_total`). See `docs/auth-architecture.md` "Hardened mode". |
| **Break-glass account policy** (constrained, audited, rotated) | "or tightly constrain break-glass account policy" | CC6.6 | **SHIPPED** — `--break-glass-user` exempt from sso-only **only while armed** (`users.break_glass_armed_until`, migration v4, auto-expiring `--break-glass-window-secs` default 24h); **mandatory MFA** enforced fail-closed at boot AND forced at login; armed out-of-band via the host CLI `--break-glass-arm` (audited `auth.breakglass.armed`, OS-principal-attributed); use audits `auth.breakglass.login` + metric `yuzu_auth_break_glass_login_total`. |
| **SAML 2.0 SP** (some enterprises require SAML, not OIDC) | implicit ("SSO enforcement") | CC6.1 | **PARTIAL (thin slice + group→role mapping shipped)** — SP-initiated login (HTTP-Redirect binding), assertion-signature validation against a pinned IdP cert, replay-protected (`InResponseTo` single-use), ephemeral session (`auth_source="saml"`, `role=admin` via exact-match IdP-attested group membership — `--saml-group-attribute`/`--saml-admin-group`, mirrors the OIDC `--oidc-admin-group` guard — else `role=user`), Linux/macOS only. Admins are now reachable via SAML without a local account. Deferred: AuthnRequest signing, AttributeStatement parsing beyond the group attribute, Windows support, IdP-metadata auto-fetch, Settings-UI reconfigure. See `docs/auth-architecture.md` "SAML 2.0 SP". |
| **SCIM v2 provisioning** (auto-provision/deprovision from IdP) | "Periodic access reviews" automation | CC6.2/6.7/6.8 | **SHIPPED (Users + Groups→role mapping)** — `--scim-enable`/`YUZU_SCIM_TOKEN` (preferred over `--scim-token`, which is `ps`-visible; fail-closed: refuses to start without a token, or with `--no-https`); every `/scim/v2/*` route (including discovery) bearer-authed constant-time, its own `scim-service` audit principal. `POST /scim/v2/Users` provisions at the fixed `role=user` (SSO login, discarded local password; reviving a deactivated same-`userName` account rather than `409` — returning-employee reprovision); `PATCH`/`PUT .../{id}` `active:false`/`active:true` deprovisions (soft-delete + session-revoke cascade) / reactivates (lockout cleared, MFA NOT restored). **`userName` must be a slug** (no `@`) — a stock Okta/Entra `userName=email` mapping 400s until remapped. **Provenance guard** (`users.provisioning_source`, auth.db migration v7) makes every deactivate/reactivate/delete/update re-verify `provisioning_source == "scim"` **and** `role == "user"` before mutating, refusing `404` (never `403`) on either mismatch — a locally-created admin, the break-glass account, or a since-promoted former-SCIM account can never be touched by an IdP push. **Groups→role mapping (#2021):** `/scim/v2/Groups` (`POST`/`GET`/`PUT`/`PATCH`/`DELETE`, `displayName`-keyed exact-case match, whitespace-trimmed `--scim-admin-group`, bounded `members[]`, `409` on a `displayName` collision or rename-onto-existing) reuses `resolve_role_from_groups` — a SCIM-provisioned user is `role=admin` **iff** currently a member of `--scim-admin-group`; there is no other field or code path to `role=admin`, so a compromised IdP can elevate only as far as that one configured group. **Model A: IdP membership is authoritative** — a manual dashboard role change on a SCIM account is reverted on the next membership-recomputing event (Group mutation or User reprovision), not on a plain deactivate/restart/flag change; `deprovision_role_ok` is a demote-before-delete ordering gate (blocks deprovisioning a non-`user` account), not a permanent-elevation guarantee. Audit `success`/`failure`/`denied` results incl. new `scim.auth.denied`/`scim.group.*`/`scim.user.role_changed`; metrics `yuzu_scim_requests_total{op,status}` + `yuzu_scim_role_changes_total` + `yuzu_scim_role_change_failures_total` + 3 more (see `docs/auth-architecture.md`). Storage rides `auth.db` (own `"scim"` migration component, a recorded ADR-0006 SQLite exception), not a new store. **Deferred:** native email-`userName` support, `userName` rename, per-route rate-limiting, API-token revocation on user delete/deactivate (pre-existing gap shared with the dashboard's manual disable path), SCIM-token-at-rest encryption. See `docs/auth-architecture.md` "SCIM v2 provisioning". |
| **Just-in-time admin elevation** (time-boxed role promotion + audit) | "Role-based least privilege and separation of duties" | CC6.6 | **SHIPPED** — `POST /api/v1/elevate` (`--jit-max-elevation-secs`); see priority item 9 below |
| **Inactivity session timeout** | "inactivity timeout" | CC6.3 | **SHIPPED** — `--session-inactivity-secs` (default 0 = disabled, opt-in). Sliding idle window enforced in `AuthManager::validate_session` on the in-memory `Session` (monotonic `last_activity_at`), under the absolute 8h lifetime; cookie sessions only (API/MCP tokens exempt). Best-effort throttled `auth.db` mirror via `AuthDB::touch_session_activity`. See `docs/auth-architecture.md` "Inactivity session timeout". |
| **Session revocation REST surface** | "expiration, revocation" | CC6.3 | **SHIPPED** — `DELETE /api/v1/sessions?username=<name>` (admin) + `DELETE /api/v1/sessions/me` (self) in `rest_api_v1.cpp` (audit `session.revoke_all`/`session.revoke_all.self`, step-up, self-target guard), over `AuthDB::invalidate_all_sessions()` |
| **API token rotation workflow** — pair-of-tokens overlap. | "rotation process" | CC6.3 | **PARTIAL — built for engine credentials, not adopted for human tokens.** `ApiTokenStore::rotate_engine_credential`/`confirm_rotation` (`api_token_store.hpp:254`, `pg_advisory_xact_lock`-serialized per principal) ship the §7 overlap-pair design behind `POST /api/v1/engine-principals/{id}/credentials/rotate` + `.../confirm`. Written credential-generic for later human-token adoption; no human-owned token has a `rotate` entry point yet (create + revoke only). See Section 3 item 11. |
| **API token inventory + last-used view** — data layer, Settings → API Tokens dashboard fragment (`render_api_tokens_fragment` in `settings_routes.cpp`), and `GET /api/v1/tokens` REST route all shipped, both surfacing owner/created/last-used columns. | "token inventory" | CC6.6 | **SHIPPED** |
| **Periodic access reviews** (export of role assignments + attestation flow) | "Periodic access reviews with manager/security attestation" | CC6.2 | **SHIPPED** — `GET /api/v1/access-reviews/export?format=json\|csv` (**grant-table-driven**: one row per principal holding a live grant, enumerates `principal_type IN (user, group, engine)` per the engine-principal program, a grant on a principal outside every roster is surfaced as `source="orphan"` rather than dropped (a disabled-but-still-granted user correctly shows `source="user"`, `lifecycle_state="disabled"` instead), CSV formula-injection neutralized, `AccessReview:Read`, self-audited `access_review.exported`, `503` fail-loud never a silent partial export) + `GET /api/v1/access-reviews` (list every campaign, newest-first, capped 500, `AccessReview:Read`, self-audited `access_review.list`) + attestation-campaign lifecycle (`POST /api/v1/access-reviews` freezes the current grant population as `pending` rows; `POST .../{id}/attestations` records `attested`/`flagged_revoke` (UPSERT — overwrites a prior decision) — **flag ≠ revoke, evidence only**; `POST .../{id}/close`; `GET .../{id}` for full state — all `AccessReview:Attest` except the reads). Every route, reads included, structurally denies an engine-classed caller. MCP twins `export_access_review`/`open_access_review`/`record_attestation`/`get_access_review`/`list_access_reviews`/`close_access_review` (JSON only; `record_attestation` is `destructiveHint:true`, the rest `false`). 4 Prometheus metrics (`yuzu_access_review_export_total{format}`, `_export_duration_seconds`, `_campaigns_opened_total`, `_attestations_total{decision}`). Dedicated **`AccessReview` securable** (`Read`+`Attest` ops) + seeded `Reviewer` role (`AccessReview:Read`+`Attest` only) — **round-2 fix**: the first round gated this surface on `AuditLog:Read`/`AuditLog:Attest`, which over-disclosed the full grant population to `Operator`/`PlatformEngineer` (both seeded `AuditLog:Read` for unrelated reasons); the dedicated securable closes that. Born-on-PG `AccessReviewStore` (no prune — evidence persists). Deliberately gated on a **global** `AccessReview:Read`/`Attest`, not the ADR-0017 confinement filter (#2225 — a scoped slice is useless as fleet-wide CC6.2 evidence). Known gap: user rows list direct grants only (group-inherited access is on the group's own row); `last_activity_kind` is `"n/a"` for every user row (`AuthDB` has no last-login read accessor yet). See `docs/auth-architecture.md` "Periodic access reviews" and `docs/security-reviews/access-reviews-2026-07-21.md`. |
| **Account lockout after N failed logins** | implicit (auth hygiene) | CC6.3 | **SHIPPED** — `auth.db` v3 columns (`failed_login_count`/`last_failed_login_at`/`locked_until`) + `AuthDB::lockout_status`/`record_failed_login`/`clear_failed_logins`; `--auth-lockout-threshold`/`--auth-lockout-window-secs`; generic-401 pre-check (no enum/oracle, skips PBKDF2), auto-expiring window w/ fresh budget, admin unlock `POST /api/v1/users/<name>/unlock`; audit `auth.lockout.applied`/`.cleared` + metrics. See `docs/auth-architecture.md` "Account lockout". |
| **Service-account governance** (separate principal type, no human login) | "Privileged access controls" | CC6.6 | **SHIPPED** — the `engine` principal class (ADR-0031), full 4.1–4.5 ladder merged: `EnginePrincipalStore`, no login surface, credential-only auth, overlap-pair rotation, default-deny scoped grants, per-principal quota cap, live `principal_class="engine"` metric. Resolves authority **RBAC-only** (403 RBAC-off/no-grant, 503 store-unavailable) and can never hold admin/built-in/wildcard. Phase 5 (delegation, RFC 8693 token exchange) remains design-only. See Section 3 item 14. |
| **Conditional access** (geo / IP / device posture, optional) | implicit ("MFA requirements") | CC6.1 | **MISSING (P3)** |
| **Sampled auth-log evidence export** for auditors | "sampled auth logs" | CC7.2 | **SHIPPED** — `GET /api/v1/audit/auth-sample` (`rest_api_v1.cpp`); `AuditQuery.action_prefixes` + `random_sample` (`audit_store.{hpp,cpp}`); scoped to `auth.`/`mfa.`/`session.`; `AuditLog:Read`; export audited as `audit.auth_sample.exported` |
| **Self-managed Certificate Authority** — issuer for (a) mTLS server + agent certs and (b) plugin code-signing certs. | implicit ("certificate management lifecycle") | CC6.1 / CC6.7 | **PARTIAL — mTLS half shipped, code-signing half not built.** `CaStore`/`ca.db` (`ca_root`/`ca_issued`/`ca_crl_versions`), root private key behind `KeyProvider` and never in the DB, `sign_agent_csr` as the single shared signer for `Register` + `ProxyRegister` (subject/SAN/EKU server-chosen, CSR ignored), `/api/v1/ca/{root,crl,issued,revoke,root-csr,import-chain}` under `Security:*`, full `ca.*` audit chain. Issuance is enrollment-driven — there is deliberately **no** generic `POST /ca/issue`. Not built: code-signing cert issuance (the `codeSigning` EKU exists at `x509_ca.cpp:296` with no caller), so `--plugin-trust-bundle` still needs an external CA. Doc: `docs/pki-architecture.md`. See Section 3 item 10. |
| **Plugin code-signing trust anchor** — operator-configured PEM trust bundle on the agent, CMS-verify of `<plugin>.sig` against it before `dlopen`. *Trust bundle accepts any X.509 root — Yuzu's self-managed CA (future) or any public CA / operator-internal CA today*. | implicit ("supply-chain integrity") | CC6.1 / CC7.1 | **PARTIAL — verifier shipped, CA upstream pending** |

### Hard invariants that must NOT regress when adding any of the above

These are pulled from `docs/auth-architecture.md` and
`.claude/agents/authdb.md`. Every PR adding a feature in Section 2 above
must check them:

- HTTPS by default; refuse to start without `--https-cert` + `--https-key`
  unless `--no-https` is passed.
- Web UI binds 127.0.0.1 by default; warn at startup if overridden.
- Private-key files must not be group/others-readable on Unix.
- Every error response uses the structured JSON envelope.
- Six security headers on every HTTP response.
- All SQL parameterised; no string interpolation.
- Self-target principal-destruction guard applied to any new
  destructive/demoting endpoint.
- `auth.db` 0600 / restricted ACL at create.
- `MigrationRunner::run` for any new schema migration.
- `unique_ptr<AuthDB>` lifetime spans `Server::create()`.
- `yuzu-server.cfg` is a one-shot first-boot seed, not a live source.
- `POST /api/settings/users` `role` field stays ignored; role changes only
  via the dedicated endpoint.
- `require_admin` emits `auth.admin_required` denied audit on every 403.
- New code never holds `AuthDB::mu_` while publishing to a sibling
  subsystem's bus.

---

## 3. Gap matrix — priority order

Recommended order for closing gaps. Each block stands alone; pick whichever
matches the customer ask.

**Verified against `origin/dev` @ `ef4582be` (2026-07-25)** — every "SHIPPED"
below was re-confirmed by reading the named file/route on that tree, not by
trusting a design doc's status header. Re-stamp this line whenever you revise
the section; a matrix derived from a stale checkout is worse than no matrix
(the 2026-07-25 revision corrected four items that a 571-commit-behind tree had
reported as unbuilt). **P0/P1 item numbers are stable** — commits, PR titles,
and memories cite them (`P0 #3`, `P1 #7`, `P1 #9`). P2 was renumbered 11–14 in
this revision to fix a duplicate `10`.

### Priority 0 — needed for first enterprise customer

1. ~~**MFA / TOTP for admin login + high-risk approvals.**~~ **DONE** —
   the full 3-PR ladder shipped: TOTP enrollment + login challenge +
   recovery codes, step-up on 11 high-risk surfaces, enforcement modes
   (`admin-only`/`required`) with login-time enrollment bootstrap, and the
   OIDC `amr` short-circuit. See `docs/auth-mfa-design.md`. **One tail
   remains, and it is IN FLIGHT, not unstarted:** at-rest TOTP-secret
   encryption rides **PR #2394** (auth + SCIM → Postgres), where
   `users.mfa_totp_secret` becomes a SecretCodec envelope column per ADR-0010
   — auth is the platform's first SecretCodec consumer. The decrypt path is
   **fail-closed**: a decrypt failure must surface as an error, NEVER as "no
   MFA enrolled". The `auth_kv` scaffolding is NOT used and is dropped by that
   migration. Until #2394 merges, TOTP secrets are plaintext columns in
   `auth.db` — say so plainly in any customer security questionnaire.
2. ~~**Account lockout after N failed logins.**~~ **DONE** — `auth.db` v3
   columns (`failed_login_count`/`last_failed_login_at`/`locked_until`) +
   `AuthDB::lockout_status`/`record_failed_login`/`clear_failed_logins`;
   `--auth-lockout-threshold` (default 5, 0 disables) /
   `--auth-lockout-window-secs` (default 900). `POST /login` pre-check returns
   the **same generic 401** as a bad password (no enumeration/oracle, skips
   PBKDF2 on a locked account); the window auto-expires and a waited-out user
   gets a fresh budget. Admin unlock `POST /api/v1/users/<name>/unlock`
   (`UserManagement:Write` + step-up, self-target allowed). Audit
   `auth.lockout.applied`/`.cleared`; metrics `yuzu_auth_lockout_applied_total`
   / `yuzu_auth_lockout_blocked_total`. See `docs/auth-architecture.md`
   "Account lockout".
3. ~~**Hardened-mode local-password disable.**~~ **DONE** — `--auth-mode=sso-only`
   (`YUZU_AUTH_MODE`) disables the local-password path fleet-wide; only OIDC SSO
   mints a session, and the server **refuses to start** without OIDC configured
   (it would otherwise lock everyone out). The `POST /login` gate returns the
   **same generic 401** as a bad password (no enumeration/mode oracle); the
   denial is **metric-only** (`yuzu_auth_local_disabled_total{target}`), NOT a
   per-attempt audit row (anti-flood, matches the lockout-blocked posture).
   Break-glass account: `--break-glass-user` is the single exempt principal,
   exempt **only while armed** (`users.break_glass_armed_until`, migration v4 — a
   future timestamp evaluated in SQL like `locked_until`, so it **auto-expires**;
   `--break-glass-window-secs` default 24h). **Mandatory MFA** is enforced two
   ways: boot fails closed if the break-glass user lacks MFA
   (`break_glass_account_problem`), and at login an un-enrolled break-glass
   account is **hard-denied 403** (`auth.breakglass.denied`) — enrollment is
   never offered (it would defeat the second factor; governance UP-1). Arming is
   an out-of-band **host CLI** op — `yuzu-server --break-glass-arm` (audited
   `auth.breakglass.armed` at `kCritical`, attributed to the kernel OS identity,
   audit-store writable-checked before mutate; mirrors the `--mfa-reset`
   contract) — so it works when the IdP is down. Use is loud: `kCritical`
   `auth.breakglass.login` audit + `yuzu_auth_break_glass_login_total` metric.
   See `docs/auth-architecture.md` "Hardened mode",
   `docs/security-reviews/auth-hardened-mode-2026-06-29.md`, the
   `docs/ops-runbooks/auth-db-recovery.md` arm runbook;
   `tests/unit/server/test_auth_break_glass.cpp` + `test_auth_routes_hardened.cpp`.
4. ~~**Sampled auth-log evidence export.**~~ **DONE** —
   `GET /api/v1/audit/auth-sample?from=...&to=...&limit=N` returns a
   pseudo-random sample of the auth surface (`auth.`/`mfa.`/`session.` action
   prefixes) over an optional window. Gated on **`AuditLog:Read`** (NOT
   `require_admin` — a read-only auditor role can pull evidence without full
   admin; separation of duties), and the export is itself audited as
   `audit.auth_sample.exported`. Backed by `AuditQuery.action_prefixes` +
   `random_sample`. SOC 2 CC7.2. See `docs/security-reviews/auth-sample-export-2026-06-15.md`.
5. ~~**Session revocation REST surface.**~~ **DONE** —
   `DELETE /api/v1/sessions?username=<name>` (admin) + `DELETE /api/v1/sessions/me`
   (self) over `AuthDB::invalidate_all_sessions()`; audit `session.revoke_all`
   / `session.revoke_all.self`, step-up, self-target guard. (The skill matrix
   previously listed this as PARTIAL — it has in fact shipped.)

### Priority 1 — enterprise-friction reducers

6. **SAML 2.0 SP** — thin first slice shipped, **plus group→role mapping**
   (`feat/auth-saml-group-role`). SP-initiated login via HTTP-Redirect
   binding; ACS via HTTP-POST binding. Assertion signature validated against
   the pinned IdP cert (in-document `<KeyInfo>` ignored); XML
   signature-wrapping defended; audience / recipient / expiry validated;
   solicited-only + single-use `InResponseTo` (replay-protected). Sessions are
   ephemeral, `auth_source="saml"`; role is `admin` when the assertion's
   IdP-attested groups (`--saml-group-attribute`) contain the configured
   `--saml-admin-group` (exact match only, parsed from the same
   XSW-verified assertion node as NameID — mirrors the OIDC
   `--oidc-admin-group` guard), else `role=user`. Both flags empty (default)
   reproduces the original all-`role=user` behaviour. **Linux and macOS
   only** — `saml_provider.cpp:10-21` compiles a stub on `_WIN32` and the
   provider reports disabled at startup. **Remaining (next slice), each
   verified unbuilt on `origin/dev`:** AuthnRequest signing
   (`saml_provider.cpp:561` still emits unsigned XML — "HTTP-Redirect binding
   signing is a follow-up"; no `SigAlg` parameter anywhere), AttributeStatement
   parsing beyond `--saml-group-attribute`, Windows support, IdP-metadata
   auto-fetch (all seven `--saml-*` flags are hand-configured), Settings-UI
   reconfigure. This is the **largest single remaining enterprise-friction
   gap** — SAML-only IdPs cannot onboard without it, and a Windows-hosted
   server cannot use SAML at all. See `docs/auth-architecture.md` "SAML 2.0 SP".
7. ~~**SCIM v2 provisioning**~~ **DONE (Users + Groups→role mapping,
   #2021)** — auto-create/deactivate/reactivate users from the IdP over
   `/scim/v2/*` (`--scim-enable`/`--scim-token`, fail-closed without a
   token or without HTTPS). Reuses `auth.db`'s user table (a new
   `provisioning_source` column, migration v7) plus SCIM-owned tables
   (`scim_resources`/`scim_tokens`, plus Group resources/membership rows)
   under their own migration component on the same db file — not a new
   store. Bearer-token auth (constant-time, separate from operator API
   tokens), soft-delete + session-revoke on deactivate, lockout-clear (not
   MFA-restore) on reactivate. The **provenance guard** — every mutating
   call re-verifies `provisioning_source == "scim"` immediately before
   touching the account, refusing `404` (never `403`, no existence oracle)
   on mismatch — is the invariant that makes it safe to point a
   third-party IdP connector at this surface: a local admin or the
   break-glass account can never be deactivated by SCIM — a check also
   re-verifies `role == "user"`, so an operator-elevated former-SCIM
   account is likewise beyond SCIM's reach (this is a **demote-before-delete
   ordering gate**, not a claim the elevation is permanent — see Groups→role
   mapping below). `PUT` triggers the same deactivate/reactivate semantics
   as `PATCH` when `active` flips; a `POST` against a deactivated SCIM
   account's `userName` revives it (returning-employee reprovision) rather
   than `409`ing.
   **`/scim/v2/Groups`** (`POST`/`GET`/`PUT`/`PATCH`/`DELETE`,
   `displayName`-keyed, whitespace-trimmed + exact-case
   `--scim-admin-group` match, bounded `members[]`, `409` on a `displayName`
   collision or rename-onto-existing) grants a SCIM-provisioned user
   `role=admin` **iff** currently a member of the configured admin group,
   via the same `resolve_role_from_groups` SAML/OIDC already use — the
   **only** code path from a SCIM request to `role=admin`. **Model A: IdP
   group membership is authoritative** for a SCIM account's role — a manual
   dashboard role change is reverted on the next event that recomputes that
   user's membership (a Group mutation or User reprovision), not on a plain
   deactivate/restart/`--scim-admin-group` change; a manually-promoted
   admin in no SCIM group is the one residual case Model A does not reach
   (neither reverted nor SCIM-deprovisionable until demoted by hand).
   Audit result values are `success`/`failure`/`denied` (incl. new
   `scim.group.created`/`.updated`/`.deleted` and `scim.user.role_changed`);
   metrics `yuzu_scim_requests_total{op,status}`,
   `yuzu_scim_auth_failures_total`, `yuzu_scim_audit_write_failures_total`,
   `yuzu_scim_provenance_denied_total`, `yuzu_scim_role_changes_total`,
   `yuzu_scim_role_change_failures_total` (the last a hardening-round fix —
   a role-apply failure now gets its own audit `failure` row + metric,
   distinct from the pre-existing audit-write-failure counter).
   **Remaining:** native email-shaped `userName` support (Yuzu usernames
   are slug-only — a stock Okta/Entra `userName=email` mapping 400s until
   the operator remaps it; this is the **highest-friction** of the four for a
   real IdP onboarding), `userName` rename via `PUT`, per-route
   rate-limiting, and **API-token revocation on user delete/deactivate** —
   `scim_routes.cpp` revokes auth sessions only and makes no
   `ApiTokenStore` call, so a deprovisioned operator's Bearer tokens keep
   working. That last one is a **pre-existing gap shared with the dashboard's
   manual disable path**, not SCIM-specific — fix it at the shared
   deactivate seam, not inside SCIM. **Struck from this list (2026-07-25):**
   "SCIM-token-at-rest encryption" — `scim_store.cpp:192,243` stores a
   verify-only `sha256_hex`, which is the ADR-0010-correct posture for a
   bearer credential the server only ever compares. It is not a gap; do NOT
   "fix" it into a SecretCodec envelope. **In flight:** PR #2394 moves this
   storage off `auth.db` onto a born-on-PG `ScimStore` (schema
   `scim_store`); the verify-only hash posture is preserved across that move.
   See `docs/auth-architecture.md` "SCIM v2 provisioning".
8. ~~**Inactivity session timeout**~~ **DONE** — `--session-inactivity-secs`
   (`YUZU_SESSION_INACTIVITY_SECS`, `Config::session_inactivity_secs`), **default
   0 = disabled** (opt-in; existing deployments unaffected; recommended 900).
   Enforced in `AuthManager::validate_session` against the in-memory `Session`
   (the authoritative read path — `auth.db` sessions are v1 dead-writes): a
   **monotonic `steady_clock` `last_activity_at`** is bumped on each
   authenticated touch (sliding window) and the session is rejected + evicted
   once idle past the window, *under* the absolute 8h `kSessionDuration`. Cookie
   sessions only — API/MCP tokens resolve via `synthesize_token_session`, never
   `validate_session`, so they are **never idle-timed-out**. The `auth.db`
   `last_activity_at` mirror is best-effort + throttled (`touch_session_activity`,
   ≤1 write/session/60s, off `mu_`). See `docs/auth-architecture.md` "Inactivity
   session timeout"; `tests/unit/server/test_auth.cpp` `[idle]`.
9. ~~**JIT admin elevation**~~ **DONE** — `POST /api/v1/elevate` `{justification,
   duration_secs}` promotes the caller's **effective role** to admin for a
   bounded window (`--jit-max-elevation-secs`, default 1h), then auto-reverts.
   Eligibility = the per-user `users.elevation_eligible` flag (auth.db migration
   v5, admin-set via `POST /api/v1/users/<name>/elevation-eligibility`; keyed on
   a `users` row, which OIDC login does not create — a federated identity needs
   one provisioned first), distinct from standing admin and enumerable for
   access reviews. Gated on eligibility + **mandatory MFA enrollment**
   (unconditional — elevation is the privilege boundary) + a fresh MFA step-up;
   the grant audit is fail-closed, revoking eligibility ends active elevations,
   and self-grant is blocked. A local session's factor is local TOTP; an OIDC
   session with an IdP-MFA (`amr`) proof satisfies this WITHOUT local
   enrollment, per `--jit-oidc-amr-elevation` (default true) — an OIDC session
   never consults a local namesake account's TOTP enrollment, and
   `--no-jit-oidc-amr-elevation` blocks OIDC sessions from elevating entirely
   (they cannot present a local TOTP step-up).
   `auth::effective_role(session)` (admin while
   `now < elevated_until`) is honoured by `require_admin` + the permission gates;
   the window is monotonic `steady_clock`, in-memory per **cookie** session
   (restart/logout drops it; API/MCP tokens can never elevate). Audits
   `role.elevation.{granted,denied,revoked,expired}` + `user.elevation_eligibility.set`;
   `POST /api/v1/elevate/revoke` for step-down. Passive expiry is now audited
   too — lazily, at the `AuthRoutes::resolve_session` cookie chokepoint on the
   operator's next authenticated request after the window lapses (no
   background reaper); a session already at/past its own absolute lifetime is
   rejected `401` rather than granted a zero-length window (dead-window guard).
   See `docs/auth-architecture.md` "JIT admin elevation";
   `tests/unit/server/test_auth_jit_elevation.cpp`.
10. **Self-managed Certificate Authority** — **mTLS half SHIPPED;
    code-signing half NOT BUILT.** The matrix previously listed this whole
    item as MISSING; that was stale by the entire PKI ladder (#1237–#1244).
    Routed doc: `docs/pki-architecture.md`.

    **Shipped (mTLS):** `CaStore` over `ca.db` with `ca_root` / `ca_issued` /
    `ca_crl_versions` (`ca_store.cpp:157-195`). The root **private key is
    never in the DB** — `ca_root` holds an opaque `key_ref` and the key lives
    behind `KeyProvider` (`key_provider.{hpp,cpp}`), which is the seam an
    HSM/PKCS#11 provider plugs into later. `sign_agent_csr` (`x509_ca.hpp`)
    is the **single shared signer** for both direct `Register` and gateway
    `ProxyRegister`, with subject/SAN/EKU **server-chosen and the CSR's own
    values ignored**. Revoke is serial-scoped. REST (`ca_routes.cpp`):
    `GET /api/v1/ca/root`, `GET /ca/crl`, `GET /ca/issued` (`Security:Read`),
    `POST /ca/revoke` (`Security:Delete`), plus `GET /ca/root-csr` and
    `POST /ca/import-chain` for the subordinate-CA flow — and dashboard twins
    under `/api/settings/ca/`. Audit: `ca.cert.issued`, `ca.cert.revoked`,
    `ca.cert.reissue_blocked`, `ca.crl.published`, `ca.root_csr.exported`,
    `ca.subordinate.imported`.

    **Note the shape difference from the original design above:** there is
    **no generic `POST /api/v1/ca/issue`**. Issuance is enrollment-driven
    through `sign_agent_csr` on the agent-registration path — deliberately, so
    the server chooses every field of every cert it signs. Do not add an
    operator-facing "issue me a cert for X" route without re-deciding that.

    **Remaining — plugin code-signing issuance.** `x509_ca.hpp:95` carries a
    `code_signing` flag and `x509_ca.cpp:296` emits the `codeSigning` EKU, but
    **nothing sets it** — there is no route, no CLI, and no caller. So today
    an operator wanting to sign their own plugins must still bring an external
    CA for `--plugin-trust-bundle` (`agents/core/src/main.cpp:394`). The
    verifier (issue #80) is already format-agnostic and needs no change; the
    work is a gated issuance surface plus the operator workflow. This closes a
    UX gap, not a security gap.

### Priority 2 — long-tail polish

11. **API token rotation workflow — engine credentials SHIPPED, human tokens
    NOT ADOPTED.** The overlap-pair state machine designed in
    `docs/auth-engine-principals-design.md` §7 is built and live:
    `ApiTokenStore::rotate_engine_credential` / `confirm_rotation`
    (`api_token_store.hpp:254`), serialized by a `pg_advisory_xact_lock` per
    principal, surfaced at `POST /api/v1/engine-principals/{id}/credentials/rotate`
    and `.../confirm`. It was deliberately written **credential-generic** so
    human operator tokens can adopt it unchanged. **Nothing has:** no
    `rotate` entry point exists for a human-owned token — only create +
    revoke. This is the cheapest remaining CC6.3 win, because the hard part
    (the concurrency-safe state machine and its replay semantics, hardened by
    #2384/#2404) already exists and is in production use.
12. ~~**API token inventory view.**~~ **DONE** — `render_api_tokens_fragment`
    (Settings → API Tokens, `settings_routes.cpp`) and `GET /api/v1/tokens`
    (`rest_api_v1.cpp`) both surface owner / created / last-used columns from
    `api_token_store.cpp:325-345`. (The skill matrix previously listed this
    as PARTIAL — it has in fact shipped.)
13. ~~**Periodic access-review export**~~ **SHIPPED** — `GET
    /api/v1/access-reviews/export?format=json|csv` (grant-table-driven,
    orphan grants surfaced, CSV-safe) plus `GET /api/v1/access-reviews`
    (list campaigns) and the attestation-campaign lifecycle (`POST
    /api/v1/access-reviews` + `.../attestations` + `.../close` + `GET
    .../{id}`); MCP twins `export_access_review`/`open_access_review`/
    `record_attestation`/`get_access_review`/`list_access_reviews`/
    `close_access_review`. Enumerates `principal_type IN (user, group,
    engine)` — unblocked by the engine-principal program landing first, per
    the original note. See `docs/auth-architecture.md` "Periodic access
    reviews".
14. ~~**Service-account principal type**~~ **SHIPPED — the full 4.1–4.5
    ladder is merged** (the matrix previously said "DESIGNED, not yet built";
    that was stale). The `engine` principal class per ADR-0031: dedicated
    `EnginePrincipalStore`, **no login surface**, credential-only auth,
    overlap-pair rotation, default-deny scoped grants. Ladder as merged —
    **4.1** `ApiTokenStore` → Postgres + `principal_kind` seam (#2188);
    **4.2** the principal class itself — store, RBAC resolution, audit
    attribution, `engine:` namespace-collision guard that fails **closed** at
    boot (#2192/#2202); **4.3** the operator lifecycle surface — REST
    `/api/v1/engine-principals` + `{id}/credentials{,/rotate,/confirm}` +
    `{id}/roles` + `{id}/transfer-owner`, MCP twins, console, and the
    no-admin auditor (#2194/#2284); **4.4** per-principal quota cap
    (#2309, closed #1973 — gate decision extracted into
    `principal_quota_gate.hpp`); **4.5** `principal_class="engine"` as a live
    `yuzu_http_requests_total` label value (#2342), which required the
    *resolved* `principal_kind` and so could not be done from presentation
    (`principal_class.hpp:77`).

    **Hard invariants (from `.claude/routed-concerns.md`, do not regress):**
    an engine principal resolves authority **RBAC-only** — never the pre-RBAC
    legacy path, never the service-scoped fallback (403 when RBAC is off or
    no grant, 503 when the store is unavailable) — and can **NEVER** hold
    admin, a built-in role, or a wildcard grant (`validate_assignment`'s
    `dangerous`-class gate).

    **Remaining: Phase 5 (delegation).** RFC 8693 token exchange and
    write-back are still design-only, as is 2c's Decision-14 confinement
    choice; both consume `docs/auth-engine-principals-design.md` as their
    reference. Post-ship hardening issues are open — **#2454** (a global
    revoke generation disables the liveness cache for *all* principals during
    write churn), **#2466**/**#2406** (REST engine-principal routes are silent
    on audit-store failure, unlike their MCP twins), **#2343**
    (consolidate the engine-session discriminator onto `Session::is_engine()`),
    **#2374** (regression test for MCP stream revocation).

### Priority 3 — defer

15. **Conditional access policies** (geo / IP / device posture) — large
    scope, niche customer ask. Defer until specifically requested.

---

### Open hardening backlog (tracked issues, not features)

Not gaps in the feature matrix — accepted debt on shipped surfaces. Ranked by
what a security reviewer would flag first:

- **#2376 — sensitive grant-graph reads fall open to any authenticated user
  when RBAC is off.** The only item here that is an *authorization* defect,
  and it bites in the **default** deployment posture (RBAC off). Same failure
  class as #2202. Fix before the cosmetic items below.
- **#2396** — login availability is hard-coupled to Postgres: a transient blip
  takes authentication down with no retry or degrade. The direct cost of
  ADR-0006 fail-closed; worth an explicit decision rather than drift.
- **#2395** — KEK rotation runbook + rewrap flow for SecretCodec columns.
  Lands with, or immediately after, PR #2394 — a first SecretCodec consumer
  with no rotation story is an audit finding waiting to happen.
- **#2397** — Postgres auth recovery runbook + sweep of the SQLite-era auth
  docs (`docs/ops-runbooks/auth-db-recovery.md` still assumes a file).
- **#2399** — MFA store robustness: TOTP counter double-use window +
  recovery-code store-error handling.
- **#2401** — `yuzu_auth_secret_unavailable_total` lacks the cardinality to
  tell a retry storm from a uniform outage (CC7.2 evidence quality).
- **#2398** — extract a shared `build_auth_stack()`; `main.cpp` and
  `server.cpp` duplicate the PgPool → FileKeyProvider → SecretCodec → AuthDB
  construction chain, so a wiring fix has to be made twice.
- **#2375** — access reviews cannot distinguish a deprovisioned/terminated
  principal from a temporarily-disabled one in `lifecycle_state`.
- **#2407** — server-wide HTTP request-body size cap (bodies are read before
  auth). Not auth-specific, but the auth surface is where it is reachable
  pre-authentication.

---

## 4. Standard workflow for adding an A&A feature

For every feature in Section 3:

1. **Read first.** In order:
   - This skill (current file) for the gap framing.
   - `docs/auth-architecture.md` for the existing auth surface and hard
     invariants.
   - `docs/enterprise-readiness-soc2-first-customer.md` §3.2 for the
     enterprise/SOC 2 framing.
   - `.claude/agents/authdb.md` if the feature touches `auth.db`.
   - `docs/mcp-server.md` if the feature touches the MCP surface.

2. **Plan.** Produce a short plan covering:
   - Schema changes (must use `MigrationRunner`).
   - REST surface additions and the RBAC permission required.
   - Audit actions (always emit on the `require_admin` gate side and on
     every state mutation).
   - Self-target guard implications (does this destroy/demote a principal?).
   - Test plan: unit (`tests/unit/`), integration if it touches multiple
     stores, a puppeteer smoke if it touches the dashboard.

3. **Implement** with a single PR per feature. Drive every change through
   `MigrationRunner` for schema, `HeaderBundle::make()`/`apply()` for any
   header touch, `require_admin` for the admin gate, and parameterised SQL
   throughout.

4. **Test.** Run `/test --quick` before commit. The
   `tests/unit/test_auth_db.cpp` and `test_auth_routes.cpp` patterns are the
   reference.

5. **Governance.** Run `/governance dev..HEAD` before pushing — Gate 2
   (security-guardian + docs-writer mandatory deep-dive) plus the AuthDB
   review agent (`.claude/agents/authdb.md`) for any `auth_db.*` touch.
   CRITICAL/HIGH findings block merge.

6. **Docs.** docs-writer always picks up the user-manual + REST API
   updates during Gate 2; verify the change is in the findings report
   and ship the doc edit in the same PR (or the immediate follow-up).

7. **Compliance evidence.** For features that close a SOC 2 control gap,
   add an entry to `docs/security-reviews/` for the change record. The
   compliance-officer agent will catch this in Gate 6.

---

## 5. Cross-references

- **Routed reference doc:** `docs/auth-architecture.md`
- **Engine principals & delegation design (ADR-1005 item 2b):**
  `docs/auth-engine-principals-design.md` — third principal class, scoped
  role assignments, RFC 8693 delegation, credential rotation/lifetime
  ceilings; the most detailed reference for the token-rotation and
  service-account-governance gaps in the matrix above.
- **AuthDB review agent:** `.claude/agents/authdb.md`
- **Security review agent:** `.claude/agents/security-guardian.md`
- **MCP token + tier policy:** `docs/mcp-server.md`
- **Enterprise readiness plan:** `docs/enterprise-readiness-soc2-first-customer.md`
- **SOC 2 evidence pattern:** `docs/security-reviews/*` and audit-log
  emission via `audit_store.cpp`.
- **Operator runbook:** `docs/ops-runbooks/auth-db-recovery.md`.
