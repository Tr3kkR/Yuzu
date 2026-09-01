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
| Granular RBAC — 7 roles (adds `Reviewer`, access-review attestation) × **23** securable types × **8** ops (adds `Attest`, gated via the dedicated `AccessReview` securable — NOT `AuditLog`; the rationale lives in **#2324**, the access-reviews PR, not #2225, which is the governance-gate-check PR that ran alongside it — and `Rotate`, P2 #11 SOC 2 CC6.3, ApiToken-specific self-service human-token rotation, seeded only to `Administrator`/`ApiTokenManager`, deliberately distinct from `Write`) | Shipped (Phase 3 + P2 #11) | `rbac_store.cpp:260-295,397` — types: Infrastructure, UserManagement, InstructionDefinition, InstructionSet, Execution, Schedule, Approval, Tag, AuditLog, Response, ManagementGroup, ApiToken, Security, Policy, DeviceToken, SoftwareDeployment, License, FileRetrieval, GuaranteedState, Inventory, AccessReview, SoftwareLicensing, EnginePrincipal (#2376 — cut away from the over-broad Security:Read); ops: Read/Write/Execute/Delete/Approve/Push/Attest/Rotate |
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
| SCIM ↔ OIDC/SAML identity linkage + credential revoke on deprovision (ADR-2001) | OIDC: Shipped PR1+PR2+PR3 (SOC 2 CC6.8). SAML: Shipped PR4a+PR4b (SOC 2 CC6.8) | Login-time link (`oidc::link_oidc_login_to_scim`, `ScimStore::identity_links`/`--oidc-scim-link-claim`, default `sub`, allow-list `{sub,oid}`) + deprovision-time revoke across slug + every linked `oidc:` principal (`deprovision_revoke.{hpp,cpp}`, `oidc_principal.hpp`), credentials-first, fail-closed on non-persist. D1 (`yuzu_scim_deprovision_role_refused_with_active_link_total` + `scim.user.deprovision_role_refused_with_link` audit, `result=failure` — AuditStore has no severity column, so the ADR's "kCritical audit" language is realized as an *optional* `Severity::kCritical` AnalyticsEvent gated on analytics collection being enabled, never the audit row itself) covers an externally-elevated SCIM admin (#2021 guard still applies; a human must revoke that identity's tokens manually). D2 (`yuzu_scim_deprovision_unlinked_total`) covers a federated user who logged in but no link formed (misconfigured `--oidc-scim-link-claim`, or an IdP whose `externalId` shares no claim with any OIDC token Yuzu trusts — genuinely unrevocable via SCIM in that case); login records BOTH the `sub` and `oid` observation candidates (`oidc_login_observations`, keyed `(iss,sub,claim_name)`), so D2 reliably fires on a misconfigured link-claim (an `externalId` matching the *other*, unconfigured claim is still detected). Revocation is durable within ~60s (`ApiTokenStore` validate-cache TTL), not instant. Two residuals: (a) the migration-v3 partial-unique index on `scim_resources.external_id` is fail-closed — a server carrying a pre-existing duplicate non-empty `external_id` refuses to boot (dedup pre-upgrade, see `docs/user-manual/server-admin.md` Upgrade Notes); (b) a login racing an in-flight deprovision (TOCTOU) — now closed by the shipped PR3 deny-at-login (`ScimStore::linked_resource_active` + `oidc_login_denied_deprovisioned`, `auth.oidc.deprovisioned_denied` audit): re-login after a *completed* deprovision is fully closed, the in-flight microsecond race narrowed (not eliminated) by a post-mint re-check. **SAML (PR4a+PR4b):** the same shape, keyed on the stable `saml:<entity_id>#<NameID>` principal (`saml::saml_principal_id`, `saml_principal.hpp`), a dedicated `saml_identity_links` table (`ScimStore` migration v4, `saml_scim_link.{hpp,cpp}`), and a link forming ONLY for a stable NameID Format (`persistent`/SAML-1.1 `emailAddress` — never `transient`/unspecified, `saml::is_linkable_name_id_format`); since SAML mints no API/MCP tokens, deprovision-revoke for a SAML principal is session-invalidation only. **PR4b (#3066, the SAML analogue of PR3) SHIPPED** — `ScimStore::saml_linked_resource_active` (the SAML analogue of `linked_resource_active`, same LEFT-join/fail-closed/orphan-reprovision tri-state) + `saml::saml_login_denied_deprovisioned`, wired as a primary pre-mint check and a post-mint re-check in `/saml/acs`, exactly mirroring OIDC's two call sites; denies redirect to the byte-identical `/login?error=saml`, audit `auth.saml.deprovisioned_denied`, metric `yuzu_auth_saml_deprovisioned_denied_total`. Same honest scope as OIDC's PR3: re-login after a *completed* SAML deprovision is fully closed; the in-flight microsecond race is narrowed (not eliminated) by the post-mint re-check, and — since SAML mints no tokens — a slipped session is bounded by its own TTL rather than the ~60s token-cache window. See `docs/auth-architecture.md` "SCIM ↔ OIDC identity linkage for deprovision" + "SAML ↔ SCIM identity linkage" and `docs/adr/2001-scim-oidc-identity-linkage.md` (incl. its SAML addendum, item 8). |

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
| **SAML 2.0 SP** (some enterprises require SAML, not OIDC) | implicit ("SSO enforcement") | CC6.1 | **PARTIAL (thin slice + group→role mapping + AuthnRequest signing shipped)** — SP-initiated login (HTTP-Redirect binding), assertion-signature validation against a pinned IdP cert, replay-protected (`InResponseTo` single-use), ephemeral session (`auth_source="saml"`, `role=admin` via exact-match IdP-attested group membership — `--saml-group-attribute`/`--saml-admin-group`, mirrors the OIDC `--oidc-admin-group` guard — else `role=user`), Linux/macOS only (Windows *server* is out of scope — not a targeted server platform — so SAML-on-Windows-server is a NON-GAP, not remaining work). Admins are now reachable via SAML without a local account. **AuthnRequest signing has since SHIPPED** — optional `--saml-sp-key` (RSA-only PEM) signs AuthnRequests over the Redirect binding (RSA PKCS#1v1.5+SHA-256), fail-closed on a bad/non-RSA key, unsigned-by-default otherwise. Deferred: AttributeStatement parsing beyond the group attribute, IdP-metadata auto-fetch, Settings-UI reconfigure. (Windows-*server* support is deliberately out of scope, NOT deferred — see the item-6 note below.) **SCIM linkage + deprovision-revoke has since SHIPPED (ADR-2001 PR4a+PR4b, incl. deny-at-login)** — see the "SCIM ↔ OIDC/SAML identity linkage" row in Section 1 above. See `docs/auth-architecture.md` "SAML 2.0 SP". |
| **SCIM v2 provisioning** (auto-provision/deprovision from IdP) | "Periodic access reviews" automation | CC6.2/6.7/6.8 | **SHIPPED (Users + Groups→role mapping)** — `--scim-enable`/`YUZU_SCIM_TOKEN` (preferred over `--scim-token`, which is `ps`-visible; fail-closed: refuses to start without a token, or with `--no-https`); every `/scim/v2/*` route (including discovery) bearer-authed constant-time, its own `scim-service` audit principal. `POST /scim/v2/Users` provisions at the fixed `role=user` (SSO login, discarded local password; reviving a deactivated same-`userName` account rather than `409` — returning-employee reprovision); `PATCH`/`PUT .../{id}` `active:false`/`active:true` deprovisions (soft-delete + session-revoke cascade) / reactivates (lockout cleared, MFA NOT restored). **`userName` must be a slug** (no `@`) — a stock Okta/Entra `userName=email` mapping 400s until remapped. **Provenance guard** (`users.provisioning_source`, auth.db migration v7) makes every deactivate/reactivate/delete/update re-verify `provisioning_source == "scim"` **and** `role == "user"` before mutating, refusing `404` (never `403`) on either mismatch — a locally-created admin, the break-glass account, or a since-promoted former-SCIM account can never be touched by an IdP push. **Groups→role mapping (#2021):** `/scim/v2/Groups` (`POST`/`GET`/`PUT`/`PATCH`/`DELETE`, `displayName`-keyed exact-case match, whitespace-trimmed `--scim-admin-group`, bounded `members[]`, `409` on a `displayName` collision or rename-onto-existing) reuses `resolve_role_from_groups` — a SCIM-provisioned user is `role=admin` **iff** currently a member of `--scim-admin-group`; there is no other field or code path to `role=admin`, so a compromised IdP can elevate only as far as that one configured group. **Model A: IdP membership is authoritative** — a manual dashboard role change on a SCIM account is reverted on the next membership-recomputing event (Group mutation or User reprovision), not on a plain deactivate/restart/flag change; `deprovision_role_ok` is a demote-before-delete ordering gate (blocks deprovisioning a non-`user` account), not a permanent-elevation guarantee. Audit `success`/`failure`/`denied` results incl. new `scim.auth.denied`/`scim.group.*`/`scim.user.role_changed`; metrics `yuzu_scim_requests_total{op,status}` + `yuzu_scim_role_changes_total` + `yuzu_scim_role_change_failures_total` + 3 more (see `docs/auth-architecture.md`). Storage rides `auth.db` (own `"scim"` migration component, a recorded ADR-0006 SQLite exception), not a new store. **Deferred:** native email-`userName` support, `userName` rename, per-route rate-limiting, and **not** SCIM-token-at-rest encryption — struck as a non-gap (2026-07-25): `scim_store.cpp:192,243` stores a verify-only SHA-256, the ADR-0010-correct posture for a bearer credential the server only ever compares. Do NOT "fix" it into a SecretCodec envelope. **API-token revocation on user delete/deactivate has since SHIPPED (ADR-2001)** — see the "SCIM ↔ OIDC identity linkage + credential revoke on deprovision" row in Section 1 above for the honest scope (D1/D2 residuals, ~60s window, PR3 deny-at-login not shipped). See `docs/auth-architecture.md` "SCIM v2 provisioning" and Section 3 item 7. |
| **Just-in-time admin elevation** (time-boxed role promotion + audit) | "Role-based least privilege and separation of duties" | CC6.6 | **SHIPPED** — `POST /api/v1/elevate` (`--jit-max-elevation-secs`); see priority item 9 below |
| **Inactivity session timeout** | "inactivity timeout" | CC6.3 | **SHIPPED** — `--session-inactivity-secs` (default 0 = disabled, opt-in). Sliding idle window enforced in `AuthManager::validate_session` on the in-memory `Session` (monotonic `last_activity_at`), under the absolute 8h lifetime; cookie sessions only (API/MCP tokens exempt). Best-effort throttled `auth.db` mirror via `AuthDB::touch_session_activity`. See `docs/auth-architecture.md` "Inactivity session timeout". |
| **Session revocation REST surface** | "expiration, revocation" | CC6.3 | **SHIPPED** — `DELETE /api/v1/sessions?username=<name>` (admin) + `DELETE /api/v1/sessions/me` (self) in `rest_api_v1.cpp` (audit `session.revoke_all`/`session.revoke_all.self`, step-up, self-target guard), over `AuthDB::invalidate_all_sessions()` |
| **API token rotation workflow** — pair-of-tokens overlap. | "rotation process" | CC6.3 | **SHIPPED for both principal kinds on both REST and MCP.** Engine credentials: `ApiTokenStore::rotate_engine_credential`/`confirm_rotation` (`api_token_store.hpp:254`) behind `POST /api/v1/engine-principals/{id}/credentials/rotate` + `.../confirm` (REST + MCP). Human-owned tokens: `ApiTokenStore::rotate_token`/`confirm_token_rotation` (`api_token_store.hpp:397,417`) behind `POST /api/v1/tokens/{id}/rotate` + `.../confirm` AND the `rotate_api_token`/`confirm_api_token_rotation` MCP twins — a deliberately **token-keyed** state machine (≤2 active per `rotation_group`, not per principal), self-service only, lifetime-neutral, gated on the dedicated `ApiToken:Rotate` operation on both transports. See Section 3 item 11. |
| **API token inventory + last-used view** — data layer, Settings → API Tokens dashboard fragment (`render_api_tokens_fragment` in `settings_routes.cpp`), and `GET /api/v1/tokens` REST route all shipped, both surfacing owner/created/last-used columns. | "token inventory" | CC6.6 | **SHIPPED** |
| **Periodic access reviews** (export of role assignments + attestation flow) | "Periodic access reviews with manager/security attestation" | CC6.2 | **SHIPPED** — `GET /api/v1/access-reviews/export?format=json\|csv` (**grant-table-driven**: one row per principal holding a live grant, enumerates `principal_type IN (user, group, engine)` per the engine-principal program, a grant on a principal outside every roster is surfaced as `source="orphan"` rather than dropped (a disabled-but-still-granted user correctly shows `source="user"`, `lifecycle_state="disabled"` instead), CSV formula-injection neutralized, `AccessReview:Read`, self-audited `access_review.exported`, `503` fail-loud never a silent partial export) + `GET /api/v1/access-reviews` (list every campaign, newest-first, capped 500, `AccessReview:Read`, self-audited `access_review.list`) + attestation-campaign lifecycle (`POST /api/v1/access-reviews` freezes the current grant population as `pending` rows; `POST .../{id}/attestations` records `attested`/`flagged_revoke` (UPSERT — overwrites a prior decision) — **flag ≠ revoke, evidence only**; `POST .../{id}/close`; `GET .../{id}` for full state — all `AccessReview:Attest` except the reads). Every route, reads included, structurally denies an engine-classed caller. MCP twins `export_access_review`/`open_access_review`/`record_attestation`/`get_access_review`/`list_access_reviews`/`close_access_review` (JSON only; `record_attestation` is `destructiveHint:true`, the rest `false`). 4 Prometheus metrics (`yuzu_access_review_export_total{format}`, `_export_duration_seconds`, `_campaigns_opened_total`, `_attestations_total{decision}`). Dedicated **`AccessReview` securable** (`Read`+`Attest` ops) + seeded `Reviewer` role (`AccessReview:Read`+`Attest` only) — **round-2 fix**: the first round gated this surface on `AuditLog:Read`/`AuditLog:Attest`, which over-disclosed the full grant population to `Operator`/`PlatformEngineer` (both seeded `AuditLog:Read` for unrelated reasons); the dedicated securable closes that. Born-on-PG `AccessReviewStore` (no prune — evidence persists). Deliberately gated on a **global** `AccessReview:Read`/`Attest`, not the ADR-0017 confinement filter (#2225 — a scoped slice is useless as fleet-wide CC6.2 evidence). Known gap: user rows list direct grants only (group-inherited access is on the group's own row); `last_activity_kind` is `"n/a"` for every user row (`AuthDB` has no last-login read accessor yet). See `docs/auth-architecture.md` "Periodic access reviews" and `docs/security-reviews/access-reviews-2026-07-21.md`. |
| **Account lockout after N failed logins** | implicit (auth hygiene) | CC6.3 | **SHIPPED** — `auth.db` v3 columns (`failed_login_count`/`last_failed_login_at`/`locked_until`) + `AuthDB::lockout_status`/`record_failed_login`/`clear_failed_logins`; `--auth-lockout-threshold`/`--auth-lockout-window-secs`; generic-401 pre-check (no enum/oracle, skips PBKDF2), auto-expiring window w/ fresh budget, admin unlock `POST /api/v1/users/<name>/unlock`; audit `auth.lockout.applied`/`.cleared` + metrics. See `docs/auth-architecture.md` "Account lockout". |
| **Service-account governance** (separate principal type, no human login) | "Privileged access controls" | CC6.6 | **SHIPPED** — the `engine` principal class (ADR-0031), full 4.1–4.5 ladder merged: `EnginePrincipalStore`, no login surface, credential-only auth, overlap-pair rotation, per-principal quota cap, live `principal_class="engine"` metric. Resolves authority **RBAC-only** (403 RBAC-off/no-grant, 503 store-unavailable). **Grants are default-deny but FLEET-WIDE ONLY** — `PrincipalRole` has no per-assignment scope field, and management-group-scoped engine assignment is *rejected* pending ADR-0017/Phase 5 (`rest_api_v1.cpp:1951-1955`). **Literal** admin/built-in roles are structurally barred (`kEngineDisallowedRoles` + the `is_system` check in `assign_role`); a *custom* role granted unrestricted permissions is auditor-**detected**, not prevented — by design (`rbac_store.cpp:1195-1200`). Phase 5 (delegation, RFC 8693 token exchange) remains design-only. See Section 3 item 14. |
| **Conditional access** (geo / IP / device posture, optional) | implicit ("MFA requirements") | CC6.1 | **MISSING (P3)** |
| **Sampled auth-log evidence export** for auditors | "sampled auth logs" | CC7.2 | **SHIPPED** — `GET /api/v1/audit/auth-sample` (`rest_api_v1.cpp`); `AuditQuery.action_prefixes` + `random_sample` (`audit_store.{hpp,cpp}`); scoped to `auth.`/`mfa.`/`session.`; `AuditLog:Read`; export audited as `audit.auth_sample.exported` |
| **Self-managed Certificate Authority** — issuer for (a) mTLS server + agent certs and (b) plugin code-signing certs. | implicit ("certificate management lifecycle") | CC6.1 / CC6.7 | **PARTIAL — mTLS half shipped, code-signing half not built.** `CaStore`/`ca_store` (Postgres schema, ADR-0053; `ca_root`/`ca_issued`/`ca_crl_versions`), root private key behind `KeyProvider` and never in the DB, `sign_agent_csr` (the `ServerImpl` chokepoint, `server.cpp:8124` — **not** a function in `x509_ca.hpp`, which declares `pki::sign_csr`) as the single shared signer for `Register` + `ProxyRegister` (subject/SAN/EKU server-chosen, CSR ignored), full `ca.*` audit chain. **Route permissions are NOT uniformly `Security:*`** — `GET /ca/root` and `GET /ca/crl` are **PUBLIC by design** (login-exempt at `web_utils.hpp:237`; clients need the root to trust the install and it is already in the TLS handshake), `/ca/issued` + `/ca/root-csr` are `Security:Read`, `/ca/revoke` is `Security:Delete`, `/ca/import-chain` is `Security:Write`. Issuance is enrollment-driven — there is deliberately **no** generic `POST /ca/issue`. Not built: code-signing cert issuance (the `codeSigning` EKU exists at `x509_ca.cpp:296` with no caller), so `--plugin-trust-bundle` still needs an external CA. Doc: `docs/pki-architecture.md`. See Section 3 item 10. |
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
status below was re-confirmed by reading the named file/route on that tree,
not by trusting a design doc's status header. Re-stamp this line whenever you
revise the section; a matrix derived from a stale checkout is worse than no
matrix (this revision corrected four items that a 571-commit-behind tree had
reported as unbuilt).

**Item 11 re-verified 2026-08-10, targeted, not wholesale** — against
`feat/auth-human-token-rotation` @ `e1bf2d86` (a pre-merge integration
branch off `origin/dev`, not yet on `dev`), by reading
`api_token_store.{hpp,cpp}`, `rest_api_v1.cpp`, and `mcp_server.cpp`
directly (the human arm's REST routes exist; `grep`ing `mcp_server.cpp` for
`rotate_token`/`confirm_token_rotation` **now finds** the `rotate_api_token`
and `confirm_api_token_rotation` tool handlers calling into the store — the
MCP twins have merged code, per the SHIPPED status on this surface below).
Cited by SYMBOL, deliberately not by line number: this stamp has now been
stale twice — once claiming the grep returned nothing after the twins
shipped, then once citing line numbers the named grep does not return — and
a citation that rots on every unrelated edit above it is worse than no
citation, because it reads as verified. This does **not** re-verify the
other items in this section — their last wholesale check remains the
`ef4582be` stamp above.

**Item 7 (SCIM) re-verified 2026-08-12, targeted, not wholesale** — against
`feat/auth-token-revoke-on-deprovision` @ `f1b9e508` (a pre-merge branch off
`origin/dev` @ `e458871c`, not yet on `dev`), by reading `scim_routes.cpp`
(D1/D2 detectors, the new `scim.user.deprovision_role_refused_with_link`
audit action and `emit_scim_critical_event`), `deprovision_revoke.{hpp,cpp}`,
`oidc_principal.hpp`, `scim_store.hpp` (`identity_links`,
`find_unique_active_by_external_id`, `observation_matches`), `auth_routes.cpp`
(login-time `link_oidc_login_to_scim` call), `settings_routes.cpp` (the
dashboard-delete revoke seam), and `main.cpp` (`--oidc-scim-link-claim`
flag/allow-list) directly — the "API-token revocation on user
delete/deactivate" gap struck from item 7's Remaining list above SHIPPED
per this read, with the two named residuals (D1/D2) confirmed against the
code, not assumed from the ADR. This does **not** re-verify the other items
in this section.

**Two standing cautions, learned from this revision's own review:**

1. **A "SHIPPED" status is not a licence to describe the control loosely.**
   The first cut of this revision fixed four false-MISSING claims and, in
   doing so, introduced two false-SHIPPED ones — engine grants described as
   "scoped" (they are fleet-wide only) and a `dangerous`-class gate that does
   not exist. Overstating a control is worse than understating it: these cells
   get copied into security questionnaires. When a control is partial, say
   which half shipped.
2. **Line-number anchors decay faster than status.** Statuses here were
   re-verified wholesale; a few individual `file:line` anchors were carried
   over unchecked and two were wrong. Treat an anchor as a hint, and re-grep
   the symbol before relying on it.

**P0/P1 item numbers are stable** — commits, PR titles, and memories cite them
(`P0 #3`, `P1 #7`, `P1 #9`). P2 was renumbered 11–14 in this revision to fix a
duplicate `10`; the one live cross-reference to the old numbering
(`docs/security-reviews/access-reviews-2026-07-21.md`) was updated with it.

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
   only — and this is a deliberate NON-GAP, not remaining work: running the
   Yuzu *server* on Windows is out of scope (Windows endpoints still run the
   agent). Do not plan a Windows-server SAML port.** `saml_provider.cpp:10-21`
   compiles a stub on `_WIN32` and the
   provider reports disabled at startup. **AuthnRequest signing has since
   SHIPPED (`feat/auth-saml-authnrequest-signing`):** optional
   `--saml-sp-key`/`YUZU_SAML_SP_KEY` (RSA-only PEM path) signs
   SP-initiated AuthnRequests over the HTTP-Redirect binding with RSA
   PKCS#1 v1.5 + SHA-256 (`SigAlg`/`Signature` query params); left unset,
   AuthnRequests stay unsigned (backward-compatible default). Fails closed —
   an unreadable/over-permissioned/oversized/malformed/non-RSA key disables
   SAML entirely at boot rather than silently falling back to unsigned
   requests; a per-request signing failure fails `/auth/saml/start` rather
   than emit an unsigned redirect. **Remaining (next slice), each verified
   unbuilt on `origin/dev`:** AttributeStatement parsing beyond
   `--saml-group-attribute`, IdP-metadata auto-fetch (the
   remaining `--saml-*` flags are hand-configured), Settings-UI reconfigure.
   State it accurately: the shipped slice *does* complete a full
   SP-initiated login (signed or unsigned, per configuration)
   (`test_saml_provider.cpp:997-1040`), and admins are reachable via SAML
   (Section 1). The real absences are narrower — metadata
   fetch, attributes beyond the group claim, and the Settings UI. **Windows
   is NOT among them:** running the *server* on Windows is out of scope, so
   SAML being Windows-server-only is a non-gap rather than remaining work (the
   Windows *agent* on managed endpoints is unaffected). See
   `docs/auth-architecture.md` "SAML 2.0 SP".
   **SCIM linkage + deprovision-revoke has since SHIPPED for SAML too**
   (ADR-2001 PR4a+PR4b — do NOT list it as a gap): a SAML login now mints its
   session on a stable `saml:<entity_id>#<NameID>` principal, forms a
   durable link to a SCIM resource when the NameID's Format is stable
   (`persistent`/SAML-1.1 `emailAddress` — never `transient`), and a SCIM
   deprovision now revokes that linked SAML session (SAML has no API tokens
   to revoke). **PR4b (#3066), the SAML deny-at-login backstop, has since
   SHIPPED too** — a deprovisioned SAML identity is now refused at
   `/saml/acs` the same way OIDC's PR3 refuses `/auth/callback`, closing the
   re-authenticate-and-mint-a-fresh-session window for the completed-
   deprovision case (the in-flight race is narrowed, not eliminated by
   construction, exactly as for OIDC). See the "SCIM ↔ OIDC/SAML identity
   linkage" row above and `docs/auth-architecture.md` "SAML ↔ SCIM identity
   linkage" for the honest scope.
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
   real IdP onboarding), `userName` rename via `PUT`, and per-route
   rate-limiting. **Struck from this list (2026-07-25):**
   "SCIM-token-at-rest encryption" — `scim_store.cpp:192,243` stores a
   verify-only `sha256_hex`, which is the ADR-0010-correct posture for a
   bearer credential the server only ever compares. It is not a gap; do NOT
   "fix" it into a SecretCodec envelope. **In flight:** PR #2394 moves this
   storage off `auth.db` onto a born-on-PG `ScimStore` (schema
   `scim_store`); the verify-only hash posture is preserved across that move.
   See `docs/auth-architecture.md` "SCIM v2 provisioning".
   **API-token revocation on user delete/deactivate has since SHIPPED
   (ADR-2001) — do NOT list it as a gap.** Deprovision now revokes the SCIM
   slug's tokens AND every OIDC identity durably linked to it at login
   (`--oidc-scim-link-claim`, default `sub`; Entra needs `oid`), for both
   the SCIM seam and the dashboard's manual delete. **This is a covered
   control with two NAMED, monitored residuals, not "complete" flatly:** (1)
   a SCIM slug elevated to admin outside SCIM still blocks the #2021
   deprovision guard, so its linked identity's tokens are NOT auto-revoked
   — `yuzu_scim_deprovision_role_refused_with_active_link_total` +
   `scim.user.deprovision_role_refused_with_link` (`result=failure`; the
   *audit* row itself carries no severity — `AuditEvent` has no severity
   column — the ADR's "kCritical" language is realized only as an optional
   `AnalyticsEvent` gated on analytics collection being enabled, never as a
   property of the audit row) — a human must terminate that identity
   manually; (2) an IdP whose SCIM `externalId` shares no claim value with
   any OIDC token Yuzu trusts cannot be linked at all — surfaced via
   `yuzu_scim_deprovision_unlinked_total` (D2), never silently. Revocation
   is durable within `ApiTokenStore`'s ~60s validate-cache window, not
   instant. **The OIDC deny-at-login backstop (ADR-2001 §4/PR3) has
   SHIPPED** — a deprovisioned linked identity is refused at OIDC login
   (`ScimStore::linked_resource_active` + `oidc_login_denied_deprovisioned`).
   Read the scope precisely (do NOT flatten to "CC6.8 complete"): re-login
   against an *already-completed* deprovision is fully closed; a login racing
   an *in-flight* deprovision is narrowed by a post-mint re-check (not
   eliminated by construction). See `docs/auth-architecture.md` "SCIM ↔ OIDC
   identity linkage for deprovision" and `docs/adr/2001-scim-oidc-identity-linkage.md`.
   **SAML gained the same coverage via PR4a+PR4b** (SAML addendum to the
   same ADR): a stable `saml:<entity_id>#<NameID>` session principal
   (`saml_principal.hpp`), a dedicated `saml_identity_links` table (`ScimStore`
   migration v4), link formation gated on a stable NameID Format only
   (never `transient`), deprovision-revoke of the linked SAML session (SAML
   mints no tokens, so there is nothing else to revoke), and **PR4b (#3066)
   deny-at-login, SHIPPED** — `ScimStore::saml_linked_resource_active` +
   `saml::saml_login_denied_deprovisioned`, the identical
   primary-check/post-mint-re-check shape OIDC's PR3 uses, closing the
   re-authenticate-and-mint-a-fresh-session window for a *completed*
   deprovision the same way; a login racing an *in-flight* deprovision is
   narrowed by the post-mint re-check, not eliminated by construction — the
   same scope statement as the OIDC line above. See
   `docs/auth-architecture.md` "SAML ↔ SCIM identity linkage" and the ADR's
   SAML addendum (item 8).
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
    item as MISSING; that was stale by the entire PKI ladder (#1237–#1244 —
    an inclusive range with one hole: #1242 is an MCP prompt-argument fix,
    not PKI).
    Routed doc: `docs/pki-architecture.md`.

    **Shipped (mTLS):** `CaStore` over the `ca_store` Postgres schema (ADR-0053,
    migrated off SQLite `ca.db`) with `ca_root` / `ca_issued` /
    `ca_crl_versions`. The root **private key is
    never in the DB** — `ca_root` holds an opaque `key_ref` and the key lives
    behind `KeyProvider` (`key_provider.{hpp,cpp}`), which is the seam an
    HSM/PKCS#11 provider plugs into later. `sign_agent_csr` (`x509_ca.hpp`)
    is the **single shared signer** for both direct `Register` and gateway
    `ProxyRegister`, with subject/SAN/EKU **server-chosen and the CSR's own
    values ignored**. Revoke is serial-scoped. REST (`ca_routes.cpp`):
    `GET /api/v1/ca/root` and `GET /ca/crl` are **PUBLIC by design** —
    login-exempt at `web_utils.hpp:237`, because a client needs the root to
    trust the install and it is already presented in the TLS handshake
    (`docs/pki-architecture.md:112-113` documents this). The gated ones are
    `GET /ca/issued` + `GET /ca/root-csr` (`Security:Read`), `POST /ca/revoke`
    (`Security:Delete`), and `POST /ca/import-chain` (`Security:Write`) — plus
    dashboard twins under `/api/settings/ca/`. Do not describe this surface as
    uniformly `Security:*`: the public posture is correct, but overstating it
    is the wrong direction to be wrong on a security questionnaire. Audit: `ca.cert.issued`, `ca.cert.revoked`,
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

11. ~~**API token rotation workflow — engine credentials SHIPPED, human
    tokens NOT ADOPTED.**~~ **HUMAN TOKENS: STORE CORE + REST + MCP ALL
    SHIPPED (full REST/MCP parity).** Engine-credential
    rotation was already SHIPPED (`ApiTokenStore::rotate_engine_credential`/
    `confirm_rotation`, `api_token_store.hpp:254`, `POST
    /api/v1/engine-principals/{id}/credentials/rotate`/`.../confirm`) — see
    item 14 below. Human-owned tokens now have their **own**, deliberately
    different, token-keyed state machine (a principal-keyed copy of the
    engine arm would have been wrong — a human holds N concurrent unrelated
    tokens, an engine principal holds one):
    `ApiTokenStore::rotate_token`/`confirm_token_rotation`
    (`api_token_store.hpp:397,417`), serialized on the same
    `pg_advisory_xact_lock(hashtext(principal_id))` the engine arm and the
    T12 sweep use, enforcing a ≤2-active ceiling **per `rotation_group`**,
    never per principal. **Shipped:** the store core, `POST
    /api/v1/tokens/{id}/rotate`/`.../confirm` AND the MCP twins
    (`rotate_api_token`/`confirm_api_token_rotation`) (self-service only,
    gated on `ApiToken:Rotate` — a dedicated operation distinct from the
    `ApiToken:Write` create/list/revoke axis and from `Security:Write` —
    no admin bypass, wrong-owner indistinguishable from nonexistent,
    lifetime-neutral with no caller-exposed override), kind-discriminated
    telemetry (`yuzu_api_token_rotation_*`/`yuzu_api_token_confirm_total`,
    both surfaces incrementing the same symbol), and a 33-case `[human]`
    adversarial regression suite. Full design record:
    `docs/auth-architecture.md` "Human API-token rotation";
    `docs/mcp-server.md` "Human API-token rotation tools"; evidence chain:
    `docs/security-reviews/human-token-rotation-2026-08-10.md` (records a
    caught-in-review, now-shipped-as-adjudicated privilege-escalation
    finding on the MCP-side RBAC allowance that drove the `ApiToken:Rotate`
    split, a SEPARATE governance-caught-before-merge authority-inheritance
    fix on `rotate_token` itself, and three pre-existing follow-up issues
    it surfaced — `#2943`/`#2944`/`#2945` — none of which are defects in
    the shipped human-token surface itself).
12. ~~**API token inventory view.**~~ **DONE** — `render_api_tokens_fragment`
    (Settings → API Tokens, `settings_routes.cpp`) and `GET /api/v1/tokens`
    (`rest_api_v1.cpp`) both surface owner / created / last-used columns from
    `api_token_store.cpp:516-549` (`list_tokens` — the earlier `:325-345`
    anchor pointed at validate-cache logic, not the columns). (The skill
    matrix previously listed this
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
    overlap-pair rotation, default-deny grants. Ladder as merged —
    **4.1** `ApiTokenStore` → Postgres + `principal_kind` seam (#2188);
    **4.2** the principal class itself — store, RBAC resolution, audit
    attribution, `engine:` namespace-collision guard that fails **closed** at
    boot (#2192/#2202); **4.3** the operator lifecycle surface — REST
    `/api/v1/engine-principals` + `{id}/credentials{,/rotate,/confirm}` +
    `{id}/roles` + `{id}/transfer-owner`, MCP twins, console, and the
    no-admin auditor (#2194/#2284); **4.4** per-principal quota cap
    (#2309 — gate decision extracted into `principal_quota_gate.hpp`.
    **#2309's "closes #1973" did NOT auto-close it — #1973 is `security`-labelled
    and so protected from automated closure. It was CLOSED deliberately on
    2026-08-07 after an independent human verification against `dev` (per
    `docs/agents/issue-standard.md` §5.1, the closure path for a `security`
    issue)**; the production-enablement interlock ("the cap must exist before any
    engine principal is enabled in production") is discharged); **4.5**
    `principal_class="engine"` as a live
    `yuzu_http_requests_total` label value (#2342), which required the
    *resolved* `principal_kind` and so could not be done from presentation
    (`principal_class.hpp:77`).

    **Hard invariants (do not regress) — stated precisely, because the
    routing-table wording overstates two of them:**

    - **Authority resolution is RBAC-only** — never the pre-RBAC legacy path,
      never the service-scoped fallback (403 when RBAC is off or there is no
      grant, 503 when the store is unavailable). This one is exact.
    - **Grants are FLEET-WIDE ONLY.** `PrincipalRole` carries no per-assignment
      scope field; a management-group-scoped engine assignment is *rejected*
      (`rest_api_v1.cpp:1951-1955`, asserted by
      `test_engine_principal_integration.cpp:522-548`). Scoped engine
      confinement is ADR-0017 PR-A / Phase 5 work. **Do not describe engine
      grants as "scoped"** — in Yuzu "scoped" is ADR-0017 confinement, a
      control that does not exist here yet.
    - **Literal admin/built-in roles are structurally barred**, via
      `kEngineDisallowedRoles` in `validate_assignment` plus the `is_system`
      check in `assign_role`. **There is no `dangerous`-class gate** — that
      phrase belongs to Guardian's `dangerous_enforce_in_spec` and was
      mis-transcribed onto this function. A *custom* (`is_system=0`) role
      granted unrestricted permissions is **auditor-detected, not prevented**,
      and that is deliberate: `rbac_store.cpp:1195-1200` explicitly refuses to
      enumerate "dangerous" permission combinations because doing so is
      "trivially bypassable and falsely advertises completeness". Claiming an
      engine can NEVER hold a wildcard grant is exactly that false
      advertisement. (`CLAUDE.md` / `.claude/routed-concerns.md` carry the
      overstated wording — tracked in #2485.)

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
what a security reviewer would flag first. (Reconciled against `dev`
2026-09-01: **#1973** engine-principal interlock, **#2376** grant-graph
topology floor, **#2396** login/PG-degrade, **#2395** KEK rotation, **#2397**
auth-recovery docs, **#2399** MFA-store robustness — TOTP counter double-use,
shipped #3764 — and **#2407** pre-auth body cap have all landed and are dropped
from this list.)

- **#3777** — the concurrent-enroll / disable-race MFA-enrollment loser is
  audited as a generic "code rejected" (and a benign concurrent `mfa_disable`
  trips a false "store unavailable" 503 + secret-unavailable degrade metric +
  kCritical audit). Give `MfaAlreadyEnrolled` its own audit branch at the route
  consumers — the only item here that is a live audit-fidelity (CC7.2) defect.
  Follow-up from #3762.
- **#3779** — concurrent `mfa_regenerate_recovery_codes` orphans the earlier
  code set (last-writer-wins on an explicit, user-initiated regenerate — the
  same class as the enrollment orphan #3762 closed, but arguably acceptable
  semantics). Decide deliberately: serialize it, or document the last-writer
  contract. Follow-up from #3762.
- **#2401** — `yuzu_auth_secret_unavailable_total` lacks the cardinality to
  tell a retry storm from a uniform outage (CC7.2 evidence quality).
- **#2375** — access reviews cannot distinguish a deprovisioned/terminated
  principal from a temporarily-disabled one in `lifecycle_state` (CC6.2).
- **#2398** — extract a shared `build_auth_stack()`; `main.cpp` and
  `server.cpp` duplicate the PgPool → FileKeyProvider → SecretCodec → AuthDB
  construction chain, so a wiring fix has to be made twice.
- **#3783** — nightly TSan leg for the live-PG MFA concurrency regressions
  (`test_auth_db_pg.cpp`) — test-hardening; the concurrency guards are checked
  by inspection today. Follow-up from #3762.

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
