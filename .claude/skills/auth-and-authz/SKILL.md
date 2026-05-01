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
| Local password auth (PBKDF2-SHA256) | Shipped (v0.10) | `auth.cpp`, `auth_db.cpp` |
| Persistent auth store (`auth.db`, SQLite) | Shipped (v0.12) | `.claude/agents/authdb.md`, `auth_db.cpp` |
| Session-cookie auth (HTMX dashboard) | Shipped | `auth_routes.cpp` |
| API tokens — Bearer + `X-Yuzu-Token` | Shipped | `api_token_store.cpp` |
| Owner-scoped token revocation (#222) | Shipped | `auth_routes.cpp` |
| Granular RBAC — 6 roles × 14 securable types × per-op | Shipped (Phase 3) | `rbac_store.cpp` |
| Self-target principal-destruction guard (#397/#403) | Shipped | `docs/auth-architecture.md` §self-target |
| OIDC SSO — full PKCE flow, Entra discovery, JWT validation | Shipped | `oidc_provider.cpp` |
| AD/Entra group-to-role mapping via Microsoft Graph | Shipped | `oidc_provider.cpp` (group import) |
| mTLS for agent ↔ server | Shipped | `cert_store.cpp` |
| Windows certificate-store mTLS (CryptoAPI/CNG) | Shipped | `cert_store.cpp` |
| HTTPS-by-default, secure bind default (127.0.0.1) | Shipped (hard invariant) | `docs/auth-architecture.md` |
| HTTP security headers (CSP, HSTS, frame, referrer, permissions) | Shipped (SOC2-C1) | `security_headers.{hpp,cpp}` |
| Cert hot-reload (HTTPS) with audit + metrics | Shipped | `cert_store.cpp` |
| Agent enrollment — manual / pre-shared / platform-trust (3 tiers) | Shipped | `enrollment_token_store.cpp` |
| MCP token issuance + tier-before-RBAC ordering | Shipped | `docs/mcp-server.md` |
| `auth.admin_required` denied audit on every 403 | Shipped (gate) | `auth_routes.cpp` `require_admin` |
| Private-key permission validation | Shipped | `cert_store.cpp` |
| Metrics endpoint localhost-only-no-auth | Shipped | `auth.cpp` |

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
| **MFA / 2FA / TOTP for high-risk approvals** | "2FA/TOTP for high-risk approvals" | CC6.6 | **MISSING** |
| **Hardened-mode local-password disable** | "Disable local-password fallback in hardened mode" | CC6.3 | **MISSING** |
| **Break-glass account policy** (constrained, audited, rotated) | "or tightly constrain break-glass account policy" | CC6.6 | **MISSING** |
| **SAML 2.0 SP** (some enterprises require SAML, not OIDC) | implicit ("SSO enforcement") | CC6.1 | **MISSING** |
| **SCIM v2 provisioning** (auto-provision/deprovision from IdP) | "Periodic access reviews" automation | CC6.2/6.8 | **MISSING** |
| **Just-in-time admin elevation** (time-boxed role promotion + audit) | "Role-based least privilege and separation of duties" | CC6.6 | **MISSING** |
| **Inactivity session timeout** (currently expiry-only) | "inactivity timeout" | CC6.3 | **PARTIAL** |
| **Session revocation API** (kill all sessions for a user) | "expiration, revocation" | CC6.3 | **PARTIAL** |
| **API token rotation workflow** (UI-driven, with overlap window) | "rotation process" | CC6.3 | **PARTIAL** |
| **API token inventory + last-used view** | "token inventory" | CC6.6 | **PARTIAL** |
| **Periodic access reviews** (export of role assignments + attestation flow) | "Periodic access reviews with manager/security attestation" | CC6.2 | **MISSING** |
| **Account lockout after N failed logins** | implicit (auth hygiene) | CC6.3 | **MISSING** |
| **Service-account governance** (separate principal type, no human login) | "Privileged access controls" | CC6.6 | **MISSING** |
| **Conditional access** (geo / IP / device posture, optional) | implicit ("MFA requirements") | CC6.1 | **MISSING (P3)** |
| **Sampled auth-log evidence export** for auditors | "sampled auth logs" | CC7.2 | **MISSING** |

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

### Priority 0 — needed for first enterprise customer

1. **MFA / TOTP for admin login + high-risk approvals.** Standard `oath-toolkit`
   compatible; secret generation + QR enrollment + step-up flow on
   privileged endpoints. Schema additions land via `MigrationRunner`. New
   audit actions: `mfa.enroll`, `mfa.verify`, `mfa.step_up.required`,
   `mfa.step_up.passed`.
2. **Account lockout after N failed logins.** Simple: per-user counter +
   timestamp in `auth.db`, reset on success, configurable threshold. Audit:
   `auth.lockout.applied`, `auth.lockout.cleared`. Closes a basic
   credential-stuffing surface.
3. **Hardened-mode local-password disable.** New CLI flag
   `--auth-mode=sso-only`; `auth_routes.cpp` rejects local-password login
   with a clear message and logs `auth.local_disabled`. Break-glass account
   policy: a single named principal exempt from the flag, with mandatory
   MFA + 24h auto-disable + every action logged at `critical`.
4. **Sampled auth-log evidence export.** New REST endpoint
   `GET /api/v1/audit/auth-sample?from=...&to=...&limit=N` admin-only,
   gated by `require_admin`, returning a pseudo-random sample. SOC 2 CC7.2
   evidence chain.

### Priority 1 — enterprise-friction reducers

5. **SAML 2.0 SP** with metadata exchange + signed assertion validation.
   Mirrors OIDC's group-to-role mapping. Same enforcement surface as OIDC.
6. **SCIM v2 provisioning** — auto-create/disable users from the IdP.
   Reuses `auth.db` user table; new endpoint surface under `/scim/v2/`
   with bearer-token auth (separate from operator API tokens).
7. **Inactivity session timeout** — extend session validation with a
   `last_activity_ts` write on each authenticated request; expire when
   `now - last_activity_ts > inactivity_window`. Configurable per
   deployment.
8. **Session revocation** — `DELETE /api/v1/sessions?user=<name>` admin-only;
   wipes all sessions for the named principal. Audit:
   `session.revoke_all`. Self-target guard applies (admin can't lock
   themselves out).
9. **JIT admin elevation** — `POST /api/v1/elevate` accepting a justification
   + duration; promotes the caller's effective role for the window, audits
   `role.elevation.requested|granted|expired`. Returns to base role on TTL.

### Priority 2 — long-tail polish

10. **API token rotation workflow** — pair-of-tokens overlap window in the
    dashboard; "Rotate" creates a new token while the old keeps working
    until the operator confirms cutover.
11. **API token inventory view** — last-used timestamp, IP, owner; surface
    in Settings → API Tokens with sortable columns.
12. **Periodic access-review export** — JSON/CSV of `(user, role, last_login)`
    triples plus an attestation upload endpoint.
13. **Service-account principal type** — distinct from human users, no
    login surface, only token auth, mandatory rotation.

### Priority 3 — defer

14. **Conditional access policies** (geo / IP / device posture) — large
    scope, niche customer ask. Defer until specifically requested.

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
- **AuthDB review agent:** `.claude/agents/authdb.md`
- **Security review agent:** `.claude/agents/security-guardian.md`
- **MCP token + tier policy:** `docs/mcp-server.md`
- **Enterprise readiness plan:** `docs/enterprise-readiness-soc2-first-customer.md`
- **SOC 2 evidence pattern:** `docs/security-reviews/*` and audit-log
  emission via `audit_store.cpp`.
- **Operator runbook:** `docs/ops-runbooks/auth-db-recovery.md`.
