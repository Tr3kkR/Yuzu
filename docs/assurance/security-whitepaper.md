# Yuzu Security Whitepaper

<!-- yuzu:anchor release=v0.13.0 -->

**Audience:** a prospective customer's security reviewer performing technical
due diligence (Workstream G, `docs/enterprise-readiness-soc2-first-customer.md`
§3.7). **Every claim in the body below describes `v0.13.0`, the latest
tagged release, and is verifiable at that tag** (`git show
v0.13.0:<path>`) — this whitepaper adds no new controls and asserts
nothing that isn't already true in the codebase or an existing doc at that
release. **Controls that exist only on `dev`-HEAD (not yet released) are
not described in the body at all — they are collected in the "Not in
v0.13.0" appendix at the end of this document**, each with its own
machine-checkable marker, so a reviewer evaluating `v0.13.0` can read the
body straight through without separately cross-referencing a banner.

**Last updated:** 2026-09-11. Re-review this document whenever any cited
source doc materially changes, or whenever a new release is tagged (the
appendix's "planned" items may have shipped by then — re-verify against
your own tag, do not assume this document has been updated for it).

**Threat model status.** No platform-level threat model exists in the
repository; domain threat models exist for authentication/MFA
(`docs/auth-mfa-design.md` §Threat model), secrets-at-rest (ADR-0010
§Threat model) and PKI (`docs/pki-architecture.md`). Read this document's
security claims against those domain models, not against a single unified
threat model this repository does not yet have.

---

## 1. Architecture and trust boundaries

Yuzu is a three-tier control plane: **Server** (REST API v1, HTMX dashboard,
Instruction Engine, Policy Engine, Scheduler) → **Gateway** (optional
Erlang/OTP fan-out tier for command relay at scale) → **Agent** (per-endpoint
daemon executing a stable-C-ABI plugin host). Transport is gRPC/Protobuf,
**encrypted on every hop, but not uniformly mutually authenticated** — see
the per-hop table below. Full component reference, data flows, and design
rationale: `docs/architecture.md`.

**Per-hop transport authentication (`docs/pki-architecture.md` "M1 posture —
upstream mutual TLS"):**

| Hop | Mode | Notes |
|---|---|---|
| Agent → Server (direct-connect) | Mutual TLS | Per-agent client leaf certificate required. |
| Agent → Gateway (`:50051`) | **One-way TLS** (server-authenticated only) | No client cert required, so an unenrolled agent can still bootstrap through a gateway; agent identity is app-layer (`gateway_observed_peer`), not transport-layer, on this hop. |
| Gateway → Server upstream (`:50055`, `GatewayUpstream`) | Mutual TLS | Both peers hold CA-issued certs. |
| Server → Gateway management (`:50063`, command fan-out) | Strict mutual TLS, **CA-scoped only — no server-identity pinning** | The privileged command plane; requires a client cert issued by the install CA. **Residual at `v0.13.0` (#1314 M-1):** peer verification authenticates to the *CA*, not to the server's identity, so *any* holder of *any* CA-issued cert passes — including an enrolled agent's own leaf+key extracted from its data directory, another agent's stolen leaf, or the `default-gateway` leaf. Keep `:50063` on a network only the server can reach. |

<!-- yuzu:claim id=mgmt-plane-ca-scoped-mtls status=shipped evidence=docs/pki-architecture.md#Residual (#1314 M-1) -->
<!-- yuzu:claim id=mgmt-plane-spki-pin status=planned evidence=gateway/apps/yuzu_gw/src/yuzu_gw_authz.erl#check_mgmt_peer -->
"Mutual TLS between every hop" would overclaim the agent→gateway leg —
correct only for direct-connect agents and the two gateway↔server hops. An
SPKI peer pin binding `:50063` to the server's own key is **not in
`v0.13.0`** — see the appendix.

<!-- yuzu:claim id=postgres-substrate-mandatory status=shipped evidence=server/core/src/server.cpp#no PostgreSQL DSN -->
**Storage substrate split (ADR-0006):** `--postgres-dsn`/`YUZU_POSTGRES_DSN`
is mandatory — the server **fails closed at boot** (refuses to start, no
SQLite fallback) if it is unset or unreachable, and several server stores
(offline-endpoint tracking, pre-flight runs, deployment runs, vulnerability
findings, software/device inventory, app-performance rollups) are already
PostgreSQL-backed at this release. **Many server stores are not yet
migrated at `v0.13.0` — among them `auth`, `ca_store`, and audit, which
remain SQLite files (`auth.db`, `ca.db`, `audit.db`) pending their own
migration, alongside other still-SQLite stores such as RBAC, management
groups, and API tokens** (see the
appendix for what changes once each does; `docs/ops-runbooks/auth-db-recovery.md`
covers the `auth` case operationally). The agent stays SQLite regardless
(local, per-endpoint, federated edge warehouse — no shared multi-tenant
database on the endpoint side). See ADR-0006/0007/0008/0012 and
`docs/postgres-store-playbook.md`.

A Patroni-managed HA PostgreSQL profile with automatic failover, and a
second server replica, are both **not shipped at `v0.13.0`** — see the
appendix.

## 2. Cryptography

### 2.1 Public-key infrastructure

Every Yuzu install auto-generates a per-install internal Certificate
Authority on first boot (no external PKI required) and serves the dashboard,
REST API, and every gRPC listener over TLS/mTLS out of the box by default.
**Correction:** `--no-tls`/`--no-https` opt-out flags do exist in the server
binary (`main.cpp`) — the accurate claim is that the **shipped image `CMD`s
omit them** (#1314, "Distribution flip"), so a default `docker run`/compose
deployment gets TLS without the operator doing anything, while an operator
who explicitly passes `--no-tls`/`--no-https` gets a loud startup warning
banner but is not prevented from disabling it (a deliberate posture for
local UAT/demo/dev work — see `docs/pki-architecture.md`). Agent enrollment
<!-- yuzu:claim id=ca-store-sqlite status=shipped evidence=server/core/src/ca_store.cpp#sqlite3 -->
issues per-agent leaf certificates signed by that CA; the CA root **private
key is never stored in the database** — CA metadata, issued-cert inventory,
and CRL version history live in a local **SQLite `ca.db` file at this
release** (ADR-0053 plans a PostgreSQL migration — see appendix), with the
key itself behind a `KeyProvider` abstraction holding only an opaque
`key_ref` regardless of which database backs the metadata.
Full design, the `sign_agent_csr` chokepoint shared by direct and
gateway-proxied enrollment, revocation semantics, and the enterprise
CA-subordination path (Settings → Internal CA → "Subordinate this CA"):
`docs/pki-architecture.md`.

**Known deployment caveat:** the gateway command-fan-out topology's internal
composes are not TLS end-to-end on every leg by default (see the per-hop
table in §1 — the agent→gateway hop is one-way TLS by design, not mutual) —
do not internet-expose the agent gRPC port (`:50051`) directly; see
`docs/pki-architecture.md`'s own operational warning.

### 2.2 Secrets at rest

<!-- yuzu:claim id=secretcodec-substrate-shipped status=shipped evidence=server/core/src/pg/secret_codec.hpp#SecretCodec -->
Local passwords (PBKDF2, in `auth.db`) and API tokens (SHA-256, in the
SQLite API-token store) are stored as verify-only hashes, never as
recoverable secrets. The envelope-encryption substrate — `SecretCodec`,
wrapping a per-secret DEK under a KEK obtained through a pluggable
`KeyProvider`/`KekProvider` seam — **ships in the `v0.13.0` binary but has
no production consumer at this release**: no store at this tag encrypts a
column with it (the PostgreSQL-backed stores that exist at this release
hold no secrets — e.g. `offline_endpoint_store.hpp` and
`vuln_finding_store.hpp` each state in their header that they carry no
secrets and no `SecretCodec` envelope). **In particular, the MFA TOTP
secret in the still-SQLite `auth.db` is plaintext at rest at this release**
(the `0600` file mode is its only protection today) — see
`docs/ops-runbooks/auth-db-recovery.md` and the appendix below for the
planned encryption. Design and threat model:
`docs/adr/0010-secrets-at-rest-envelope-encryption.md`.

## 3. Authentication and authorization

### 3.1 Session and login

<!-- yuzu:claim id=session-cookie-attrs status=shipped evidence=server/core/src/auth_routes.cpp#session_cookie_attrs -->
<!-- yuzu:claim id=session-inactivity-timeout status=shipped evidence=server/core/src/main.cpp#--session-inactivity-secs -->
Session-cookie authentication with PBKDF2-hashed local passwords, or SSO.
Session cookies ship `HttpOnly; SameSite=Lax`, plus `Secure` whenever HTTPS
is enabled (`AuthRoutes::session_cookie_attrs`, `server/core/src/auth_routes.cpp`)
— **shipped**, not planned. Absolute session lifetime is 8 hours; a sliding
**inactivity (idle) timeout** (`--session-inactivity-secs`) additionally
expires a cookie session after a configurable idle period — **shipped at
this release, but sessions themselves are in-memory only** (see below):
the idle clock does not survive a restart at `v0.13.0` because nothing
about a session does. Cross-restart durability of the idle clock (and of
the session itself) is a `dev`-only property — see the appendix.

### 3.2 SSO — OIDC and SAML

OIDC SSO for production admin access, with an optional hardened mode
(`--auth-mode=sso-only`) that disables local-password login except a
tightly-scoped break-glass account (`docs/auth-architecture.md` "Hardened
mode (sso-only) + break-glass"). A separate SAML 2.0 Service Provider
implementation covers IdPs that require it (`docs/auth-architecture.md`
"SAML 2.0 SP" — configuration, login flow, group→role mapping, MFA
enforcement interaction, AuthnRequest signing, IdP signing-certificate
rotation).

**Known residual (#1836):** an IdP-side group removal propagates to Yuzu
RBAC on the user's *next* SSO login, not immediately — a live session or
already-issued token retains prior roles until re-authentication. Manual
mitigation: forced session revocation (below). Tracked, not silently
omitted from this document.

### 3.3 SCIM provisioning

SCIM v2 **user** provisioning and deprovisioning (a deprovision soft-deletes
the account and cascades session revocation), fail-closed configuration, and
a provenance guard: SCIM may only mutate accounts SCIM itself provisioned
and only while they are still floor-privilege, so an IdP push can never
deactivate a locally-created admin or the break-glass account. **At
`v0.13.0` this is a users-only slice** — SCIM Groups and group→role mapping
are not implemented (every SCIM-provisioned account is the fixed `user`
role; OIDC and SAML have their own group→role mapping). **Known residual
(SOC 2 CC6.8):** at this release a deprovision (via SCIM or the dashboard)
revokes the account's cookie sessions but not its **API tokens** — the
token path resolves the principal without checking the account is still
active — and does not sever a linked OIDC/SAML identity. Manually revoke a
departing operator's API tokens. The deprovision revoke seam (ADR-2001) is
`dev`-only — see the appendix. Full reference: `docs/auth-architecture.md`
"SCIM v2 provisioning".

### 3.4 MFA

TOTP-based MFA for privileged actions, JIT (just-in-time) admin elevation
gated behind an MFA proof with a bounded elevation window, and MFA
enforcement layered on top of SAML SSO login. Full reference:
`docs/auth-architecture.md` "MFA / TOTP", "JIT admin elevation".

### 3.5 RBAC and management groups

<!-- yuzu:claim id=rbac-store-sqlite status=shipped evidence=server/core/src/rbac_store.cpp#sqlite3 -->
<!-- yuzu:claim id=authorize-list-read-docs-only status=planned evidence=server/core/src/authz_gates.cpp#authorize_list_read -->
Role-based access control with a granular permission model
(`docs/user-manual/rbac.md`) and hierarchical management groups that scope
an operator's visibility/authority to a confined subset of the fleet
(`docs/user-manual/management-groups.md`). `RbacStore` is a **SQLite
`rbac.db` file at this release** (ADR-0041 plans a PostgreSQL migration —
see appendix); a bare global `require_permission` on a list route is a
known-inert pattern for a confined operator. Degradation is split at this
release: if `rbac.db` fails to load, the RBAC toggle stays at its compiled
default (off, `rbac_store.hpp:184`), so `require_permission` takes the
legacy path, where any authenticated session may Read and mutations require
admin (`auth_routes.cpp:466-480`). That is effectively fail-open for
reads. The management-group confinement fallback fails CLOSED on a
load-failed store (#1498, `rbac_store.cpp:600-603`), and a per-request
permission lookup against an unopened store denies (`rbac_store.cpp:1268`). **The admit-then-filter `authorize_list_read`
chokepoint (ADR-0017) is a documented design target, not yet implemented
in code at `v0.13.0`** — `authorize_list_read`/`authz_gates.cpp` do not
exist at this tag (confirmed: `git grep -l authorize_list_read v0.13.0`
matches only `docs/` and `CLAUDE.md`, no source file). At this release,
list-shaped reads rely on the bare-global-permission pattern described
above for every route, with the same confined-operator caveat that applies
fleet-wide, not only to the unmigrated handful the `dev`-HEAD chokepoint
still has open. See the appendix for the `dev`-HEAD state of this
chokepoint.

### 3.6 API tokens and service automation

<!-- yuzu:claim id=service-scope-itserviceowner-ceiling status=shipped evidence=server/core/src/auth_routes.cpp#lacks ITServiceOwner permission -->
<!-- yuzu:claim id=service-scope-default-deny status=planned evidence=server/core/src/service_scope_policy.hpp#kServiceScopeGlobalSafe -->
<!-- yuzu:claim id=human-token-rotation status=planned evidence=server/core/src/api_token_store.hpp#rotate_token -->
Bearer API tokens for automation, with an optional expiry (`expires_at`,
`0` = never; MCP tokens carry a mandatory expiry of at most 90 days) and
ownership-scoped revocation (only the token's owner, or the global `admin`
role, can revoke it). There is **no built-in rotation primitive at
`v0.13.0`** — rotating a token means minting a new one and revoking the old.

**Service-scoped tokens at `v0.13.0` are confined by a permission
*ceiling*, not a default-deny.** A service-scoped token is refused outright
when RBAC is disabled and on admin routes; otherwise a request passes if the
`ITServiceOwner` role holds the requested `(securable, operation)` pair. On
per-device routes the target agent's `service` tag must also match the
token's service — **but on fleet-wide (non-per-device) routes the ceiling
check is the only gate**, so a service-scoped token can read fleet-wide data
for any pair `ITServiceOwner` holds, unfiltered by service. Full reference:
`docs/auth-architecture.md` "API tokens and automation". Service-scope
default-deny confinement and self-service token rotation are **not in
`v0.13.0`** — see the appendix.

### 3.7 Account lockout

Failed-login threshold triggers an account lockout (SOC 2 CC6.3); subsequent
attempts against a locked account are metric-only (not individually
audit-logged) to prevent audit-log flooding during a sustained brute-force,
while the initial lock and any admin unlock/self-clear are each a discrete
audited event. `docs/auth-architecture.md` "Account lockout".

### 3.8 Secure-deployment configuration required — the shipped defaults are permissive

**Every control described in §3.1-3.7 above exists in the codebase, but four
of them ship OFF or at their weakest setting by default.** A fresh,
unconfigured install is not the hardened posture this whitepaper otherwise
describes — a customer's security reviewer should treat the defaults below
as the *out-of-box* starting point, not the assured configuration, and
confirm each has been explicitly flipped before relying on the
corresponding control.

| Default (out-of-box) | Config field (`server.hpp`) | Flip it with | Effect of the default |
|---|---|---|---|
| Idle session timeout **disabled** | `session_inactivity_secs{0}` | `--session-inactivity-secs` / `YUZU_SESSION_INACTIVITY_SECS` (recommended `900` = 15 min) | Only the absolute 8-hour session lifetime applies — a forgotten, unlocked browser tab stays authenticated for up to 8 hours, not 15 minutes. |
| MFA enforcement **optional** | `mfa_enforcement{"optional"}` | `--mfa-enforcement admin-only\|required` | MFA is available for self-service enrollment but not required at login — an operator account can go unenrolled indefinitely. |
| Local-password login **enabled** (no SSO-only enforcement) | `auth_mode{"standard"}` | `--auth-mode sso-only` (requires OIDC configured first — refuses to start otherwise) | Any operator can authenticate with a local password instead of going through the configured IdP, bypassing IdP-side conditional-access policy. |
| RBAC **disabled** | `rbac_store.cpp`'s first-boot seed, `rbac_enabled='false'` | Settings page toggle, or `yuzu-server.cfg`'s `[rbac]\nenabled = true` | Every authenticated user has full fleet-wide access (with a legacy fallback requiring the `admin` session role for write/delete/execute/approve) — no per-role or per-management-group scoping until explicitly turned on. See `docs/user-manual/rbac.md`'s own pre-enable checklist (a lockout risk if flipped without first granting a management-group role). |

None of these defaults are a defect in the sense of a bug — each is a
documented, intentional choice that keeps a fresh install bootable and
usable without a mandatory IdP/MFA/RBAC setup wizard. But a CAIQ/security
review that reads §3.1-3.7 as "these controls are active" without checking
this table would be wrong for any deployment that has not explicitly
reconfigured all four.

## 4. Audit trail and evidence chain

Every operator action is recorded as a structured audit event suitable for
compliance reporting and SIEM export (`docs/user-manual/audit-log.md`).
**Correction — "tamper-evident" overclaims today:** the audit store is
append-only **by policy** (no update/delete API surface for a row's
content), not cryptographically tamper-evident — there is no hash chain or
signature over the row sequence that would let a reviewer *prove* a row was
not altered or removed out-of-band (e.g. a direct database edit by someone
holding PostgreSQL access). Treat this as an access-control/operational
control (who can reach the database), not a cryptographic integrity
guarantee, until a hash-chain or equivalent mechanism ships.

<!-- yuzu:claim id=audit-store-sqlite status=shipped evidence=server/core/src/audit_store.cpp#sqlite3_prepare_v2 -->
<!-- yuzu:claim id=rest-audit-fail-closed status=shipped evidence=server/core/src/rest_audit.hpp#emit_behavioral_audit -->
**At `v0.13.0` the audit store is the legacy SQLite `audit.db`** — the
PostgreSQL migration (ADR-0040) has not landed yet (see appendix for what
changes once it does). The `rest_audit.hpp` `emit_behavioral_audit`
chokepoint and its `503`/`Sec-Audit-Failed` fail-hard behaviour on
behavioural-PII REST reads are **already shipped at this release**,
independent of which database backs the store — **not** a blanket
guarantee across every ingress: dashboard HTML routes and MCP tool calls are
"set-and-proceed" on an audit-write failure (the request completes even if
the audit row did not persist), a different posture from REST's fail-closed
one.

<!-- yuzu:claim id=audit-retention-unguarded status=shipped evidence=server/core/src/audit_store.cpp#DELETE FROM audit_events WHERE ttl_expires_at > 0 AND ttl_expires_at < ? -->
<!-- yuzu:claim id=audit-retention-clock-guard status=planned evidence=common/include/yuzu/audit_retention_rules.hpp#classify -->
**Audit retention at `v0.13.0` is not clock-guarded and not capped.** Each
row's expiry (`ttl_expires_at`) is stamped at insert from the retention
window (365 days by default, `audit_retention_days`); a background thread
(`AuditStore::run_cleanup`, hourly by default) runs a single uncapped
`DELETE FROM audit_events WHERE ttl_expires_at > 0 AND ttl_expires_at < ?`
bound to the server host's `system_clock`. **Residual:** a forward jump of
the server host's wall clock deletes audit evidence early — every row whose
expiry falls inside the jump is removed in one pass, with no cap, no
anomaly detection, and no alertable signal. Keep the server host on
reliable, monitored time sync, and export/forward audit events to an
external system if the evidence window must survive such an event. A
clock-guarded, capped retention sweep is **not in `v0.13.0`** — see the
appendix. See
`docs/ops-runbooks/slo.md` §4 for the write-success SLO built on the audit
write path, and `docs/enterprise-readiness-soc2-first-customer.md` §3.5 for the
full data-inventory table (retention windows per store).

**Metric-is-the-signal, audit-row-is-the-evidence:** every security-relevant
event pairs a Prometheus counter (for real-time SIEM/alerting via the
existing Prometheus→SIEM receiver pattern) with an audit row (for forensic
detail) — see `docs/observability-conventions.md`.

## 5. Reliability and operational readiness

Five SLOs (`/readyz` availability, command dispatch latency, agent heartbeat
freshness, audit write success, PostgreSQL substrate degrade events), each
backed by a metric verified present in the codebase and — where one ships —
the exact Prometheus alert that **fires** on it (not "pages" — no
Alertmanager ships; see `docs/ops-runbooks/slo.md`'s own correction on this
point, governance sre3-1): `docs/ops-runbooks/slo.md`
(one caveat on "verified present": the `/readyz`-availability proxy,
`up{job="yuzu-server"}`, is a Prometheus **scrape** metric, not a metric
Yuzu itself emits — verified present in the *scrape config*, not in
`server/core/src`, unlike the other four). Note also that
`docs/ops-runbooks/slo.md` does not exist at `v0.13.0` — its citations are
pinned to a post-tag `dev` commit; the metrics its five SLOs rely on are
present at the tag, but not every alert it names is (e.g.
`YuzuServerRestartLoop` is absent from the tag's
`docs/prometheus/yuzu-alerts.yml`). **Backup/restore drills were
executed against this procedure (not merely described) — but the
transcripts, and the corrected version of `docs/operations/disaster-recovery.md`
they validate, do not ship on this branch/PR at all.** This document's own
copy of `docs/operations/disaster-recovery.md` is the unmodified,
pre-fix `origin/dev` version (reverted as part of a PO decision to split
assurance-evidence work from DR-procedure work into independently-reviewable
PRs) — treat every claim about what the DR procedure does, how long it
takes, or what it was proven to do as **not applicable to this checkout**.
The actual drill transcripts (four attempts total, RTO/RPO figures, every
defect found and how each was fixed and verified), the corrected
procedure, and the corrected `scripts/yuzu-backup.sh`/`yuzu-restore.sh`
are tracked in **issue #4135** — not part of this document's or this
branch's documentation set.

**Not shipped at `v0.13.0` (see appendix): the HA-Postgres/Patroni profile
and its measured failover figures, and a second server replica (ADR-2002
Phase B).** Single-node PostgreSQL and a single server process are what
this release actually runs.

**Planned, not yet shipped at any tag:** a direct `/readyz`-content
availability probe (today's proxy is Prometheus scrape health of the
`/metrics` endpoint, not a dedicated blackbox probe of `/readyz` itself —
untracked; proposed, see `docs/ops-runbooks/slo.md` §1's correction,
neither #2956 nor #2459 names this gap); a scheduled (cron/systemd-timer)
backup job (today's procedure is a documented manual/scriptable command,
not an automatically-scheduled one, and this branch's copy carries none of
the fixes tracked in issue #4135). **This document does not present the
five-SLO set as clean evidence of outage detection** — `docs/ops-runbooks/slo.md`
states, and this document defers to it, that a total server/Postgres
outage makes every one of the five metrics go absent rather than bad, and
an absent series computes as budget-not-burned; the missing `up == 0`
dead-man's-switch rule that would catch this is tracked as **#4290** and
not yet shipped.

## 6. Supply chain integrity

Every release ships a verifiable supply-chain bundle: Sigstore `cosign`
signatures over the checksum manifest and every Docker image, SLSA v1.0
build provenance attestations (verifiable via `gh attestation verify`), and
SBOMs in both CycloneDX and SPDX formats for every platform archive and
container image. Full verification walkthrough (including a copy-pasteable
end-to-end verification script) and an explicit SOC 2 / NIST SSDF control
mapping (CC6.8 integrity of software, CC7.1 change-management traceability,
NIST SSDF PS.3 provenance): `docs/user-manual/release-verification.md`.

## 7. Data handling and retention

Server-side data inventory (which store, what it holds, retention window,
clock-guard coverage) and agent-side edge-warehouse retention (`tar.db`,
federated per-device, ADR-0004) are tabulated in full in
`docs/enterprise-readiness-soc2-first-customer.md` §3.5, including an honest
accounting of retention-guard coverage — at `v0.13.0` the audit, response,
and guaranteed-state/DEX-observation retention passes are all bare
wall-clock `DELETE`s (no clock guard, no cap); guarded passes are
`dev`-only. Behavioral telemetry (DEX)
carries its own PII posture and works-council/co-determination discussion in
the same section — do not summarise that surface without reading it, the
distinctions are load-bearing for a EU-works-council conversation.

## 8. Agentic / MCP surface

The MCP (Model Context Protocol) surface — the mechanism by which an
agentic/AI operator drives Yuzu — carries the same tier-before-RBAC
ordering, kill switches, and audit pattern as every other ingress:
`docs/mcp-server.md`.

<!-- yuzu:claim id=mcp-destructive-hint status=planned evidence=server/core/src/mcp_server.cpp#destructiveHint -->
**Machine-readable tool safety metadata is not in place at `v0.13.0`.**
`docs/agentic-first-principle.md` invariant A5 (standard MCP annotations
including a truthful `destructiveHint`, bounded input and typed output
schemas, honest `retry_after_ms`) was added on 2026-07-11 as a *proposed*
architectural rule that applies forward from adoption, with the existing
tool backlog left to a later backfill. That document's own survey at the
tag records the state: `destructiveHint`/`idempotentHint` are absent from
every tool (destructive tools signal danger in prose only), most core tools
carry no annotations or output schema, and `retry_after_ms` is hardcoded
null on the MCP tool gate. An agentic client must not rely on annotations to
detect a destructive tool at this release. **The spec-compliant MCP Streamable HTTP transport (session
ids, GET SSE channel, `notifications/progress`) is a `dev`-only addition —
`v0.13.0` has the older, non-session MCP transport only.** See the
appendix.

## 9. Headless platform posture (ADR-1005)

**Not in `v0.13.0` — see the appendix.** ADR-1005 was accepted 2026-09-07,
two months after the `v0.13.0` tag; nothing in this section applies to
that release.

---

## Not in v0.13.0 — planned for a future release

**Everything below describes `dev`-HEAD (this checkout), not the
installed release most readers have.** Re-verify against your own tag
before relying on any of it (`git cat-file -e <your-tag>:<path>`,
`git show <your-tag>:<path>` for a substring) — this appendix is not
re-checked every time a new release cuts.

<!-- yuzu:claim id=ha-postgres-patroni status=planned evidence=docs/user-manual/ha-postgres.md#Patroni -->
- **HA-Postgres profile (ADR-2002, Patroni-managed 3-node topology with
  automatic failover).** `docs/user-manual/ha-postgres.md` does not exist
  at `v0.13.0`. At `dev`-HEAD this is available (not the default
  single-node deployment) with measured failover RTO ~30-40 seconds and
  RPO=0 while a synchronous standby holds (`quorum3` durability profile).
  A second server replica (raising the single-replica 99.5%/30d
  availability target to 99.9%/30d) is a further, separate, still-planned
  step (ADR-2002 Phase B) not shipped even at `dev`-HEAD.
- **SPKI peer pin on the gateway management plane (`:50063`, #1422).**
  `v0.13.0`'s mgmt listener is strict mTLS scoped to the install CA only —
  any CA-issued leaf passes (§1). At `dev`-HEAD (landed 2026-09-02,
  `gateway/apps/yuzu_gw/src/yuzu_gw_authz.erl`) the listener's `auth_fun`
  additionally pins the peer to the SubjectPublicKeyInfo of the server's own
  key (`{yuzu_gw, mgmt_peer_pins}`) and requires the `serverAuth` EKU, which
  agent leaves never carry; it fails closed on empty or unresolvable pins,
  and the gateway refuses to boot a network-reachable mgmt listener without
  that posture unless explicitly acknowledged as a lab rig. See
  `docs/pki-architecture.md` at `dev`-HEAD.
- **Clock-guarded, capped audit retention (#2360).** `v0.13.0` runs a single
  uncapped wall-clock `DELETE` (§4). At `dev`-HEAD (landed 2026-07-26, then
  carried onto PostgreSQL by ADR-0040) the retention sweep is clock-guarded
  and capped — it declines a pass it cannot trust rather than risk
  over-deleting, and every decline/anomaly is an alertable signal
  (`docs/ops-runbooks/audit-store-clock-guard.md`, which does not exist at
  `v0.13.0`).
- **Service-scoped API-token default-deny, and self-service human token
  rotation.** At `v0.13.0` service-scoped tokens are bounded only by the
  `ITServiceOwner` ceiling on fleet-wide routes, and there is no rotation
  primitive (§3.6). At `dev`-HEAD a `(securable, operation)` pair must
  additionally clear the seeded-empty `kServiceScopeGlobalSafe` allow-list
  (`server/core/src/service_scope_policy.hpp`) — so a service-scoped token
  cannot reach any fleet-wide pair until explicitly allow-listed — and
  human-owned tokens gain overlap-pair rotation
  (`ApiTokenStore::rotate_token`/`confirm_token_rotation`). See
  `docs/auth-architecture.md` "Service-scoped token fleet-wide confinement"
  and "Human API-token rotation" at `dev`-HEAD; neither section exists at
  `v0.13.0`.
- **SCIM ↔ OIDC/SAML identity-link revoke on deprovision (ADR-2001, SOC 2
  CC6.8).** At `v0.13.0` a deprovision revokes the account's cookie
  sessions only — not its API tokens, and not a linked OIDC/SAML identity
  (§3.3). At `dev`-HEAD a single revoke seam
  (`server/core/src/deprovision_revoke.cpp`) also revokes the account's API
  tokens (`revoke_for_principal`) and those of its linked identities;
  `docs/adr/2001-scim-oidc-identity-linkage.md` records the scope and its
  known residuals.
- **MCP tool safety annotations (A5 backfill, ADR-1005 track 2g).** At
  `v0.13.0` `destructiveHint`/`idempotentHint` are absent from every MCP
  tool (§8). At `dev`-HEAD, `docs/agentic-first-principle.md`'s 2026-08-20
  survey records every tool carrying the four standard spec annotations
  (truthfulness cross-checked by a dedicated test) and an `outputSchema`,
  with remaining items in a tracked residual state.
- **`CaStore` PostgreSQL migration (ADR-0053).** `v0.13.0` uses a SQLite
  `ca.db` file; `dev`-HEAD moves CA metadata, issued-cert inventory, and
  CRL version history into the `ca_store` PostgreSQL schema. The key
  material itself is unaffected either way (always behind `KeyProvider`,
  never in either database).
- **`AuditStore` PostgreSQL migration (ADR-0040).** `v0.13.0` uses a
  SQLite `audit.db` file; `dev`-HEAD moves it to PostgreSQL with no
  SQLite fallback (construction fails closed). The `rest_audit.hpp`
  fail-closed write behaviour described in §4 above is unaffected either
  way — it predates and does not depend on this migration.
- **`RbacStore` PostgreSQL migration (ADR-0041) and the `authorize_list_read`
  admit-then-filter chokepoint (ADR-0017).** `v0.13.0` uses a SQLite
  `rbac.db` file and has no `authorize_list_read` implementation anywhere
  in source (confirmed: `git grep -l authorize_list_read v0.13.0` matches
  only documentation). At `dev`-HEAD, `RbacStore` is PostgreSQL-backed and
  list-shaped reads on **migrated routes** go through the chokepoint — this
  is policy for new work, not complete coverage of every existing route
  even at `dev`-HEAD (`docs/auth-architecture.md` names the still-unmigrated
  handful, tracked #3526/#3528).
- **`ManagementGroupStore` PostgreSQL migration (ADR-0042).** `v0.13.0`'s
  management groups are SQLite-backed; a substantial rewrite lands at
  `dev`-HEAD (712 insertions/486 deletions in `management_group_store.cpp`
  alone, `git diff --shortstat v0.13.0 18057b6b1`).
- **`SessionStore` (durable, PostgreSQL-backed operator sessions, HA
  WS-1/1a, ADR-2002 §4).** `server/core/src/session_store.hpp` does not
  exist at all in `v0.13.0`. At `dev`-HEAD, sessions (including the idle
  inactivity clock from §3.1 above) write-through to PostgreSQL and
  survive a restart, crash, or replica failover — the opposite of
  `v0.13.0`'s in-memory-only behaviour. This reverses long-standing
  operator guidance about what a restart accomplishes for emergency
  session revocation; see `docs/ops-runbooks/auth-db-recovery.md`'s "Not
  in v0.13.0" section for the corrected, honestly-caveated guidance
  (including the known gap in outage-time containment, tracked **#4283**)
  and `docs/user-manual/server-admin.md`'s Upgrade Notes for the
  operator-facing warning.
<!-- yuzu:claim id=authdb-postgres status=planned evidence=server/core/src/auth_db.cpp#auth.users -->
- **`AuthDB` PostgreSQL migration (ADR-0006 Update 2026-07-16).**
  `v0.13.0` keeps operator accounts, password hashes, MFA enrollment, and
  SCIM state in the SQLite `auth.db`. At `dev`-HEAD `AuthDB` is
  PostgreSQL-backed (schema `auth`; `ScimStore` moves to schema
  `scim_store`) with **fresh-start, no backfill**: the legacy `auth.db` is
  never read on upgrade, so a first boot against an empty `auth.users`
  re-seeds the config-file admin and existing accounts, roles, and MFA
  enrollments are lost (SCIM self-heals on the IdP's next sync). Plan the
  upgrade accordingly — see `docs/ops-runbooks/auth-db-recovery.md`'s "Not
  in v0.13.0" section.
- **Envelope-encrypted MFA secrets (ADR-0010, applied to `auth`).**
  `v0.13.0`'s `mfa_totp_secret` column is plaintext, `0600`-file-protected
  only, and `SecretCodec` has no production consumer at that tag (§2.2
  above). At `dev`-HEAD `mfa_totp_secret` is `SecretCodec`'s first
  production consumer, and MFA readers fail closed on a decrypt failure
  rather than reading as "not enrolled". This also means a Postgres dump
  alone stops being a complete backup — see
  `docs/ops-runbooks/auth-db-recovery.md`'s appendix for the KEK-pairing
  backup procedure this introduces.
- **MCP Streamable HTTP transport** (`mcp_transport.hpp`, `mcp_session.hpp`,
  ADR-1005 execution-plan Decision 15 / track 2f) — neither file exists in
  `v0.13.0`. At `dev`-HEAD this session-lifecycle + transport pre-check
  layer (in-memory, principal-bound session ids, GET SSE channel,
  `notifications/progress`) is implemented (`docs/mcp-server.md` "Phase
  2.5"); Track 2f's Phase 3 (further hardening) remains planned even at
  `dev`-HEAD.
- **ADR-1005 headless platform posture.** Accepted 2026-09-07 (#4099),
  `dev`-only — no tagged release carries it. Its Decisions are
  prospective (govern new/changed capabilities from acceptance forward,
  do not retroactively condemn grandfathered surfaces); the on-behalf-of
  rejection at every ingress except the four health-probe paths is an
  Interim rule binding immediately on acceptance. Phase 7 (the NVD-sync
  strangler re-home) has not started. Full policy:
  `docs/adr/1005-headless-platform-use-case-engines.md`; phase status:
  `docs/adr-1005-execution-plan.md`.

**This list reflects what this review found, not a certified-complete
diff.** When in doubt about any OTHER claim in the body above, check the
codebase at your installed tag rather than assume it holds.

## Sources cited in this document

`docs/architecture.md` · `docs/pki-architecture.md` ·
`docs/adr/0010-secrets-at-rest-envelope-encryption.md` ·
`docs/auth-architecture.md` ·
`docs/adr/2001-scim-oidc-identity-linkage.md` ·
`docs/security-reviews/inactivity-timeout-2026-06-30.md` ·
`docs/user-manual/rbac.md` · `docs/user-manual/management-groups.md` ·
`docs/user-manual/audit-log.md` ·
`docs/ops-runbooks/audit-store-clock-guard.md` ·
`docs/ops-runbooks/slo.md` ·
`docs/user-manual/ha-postgres.md` ·
`docs/user-manual/release-verification.md` ·
`docs/enterprise-readiness-soc2-first-customer.md` §3.5 ·
`docs/mcp-server.md` · `docs/agentic-first-principle.md` ·
`docs/adr/1005-headless-platform-use-case-engines.md` ·
`docs/adr-1005-execution-plan.md` · `docs/observability-conventions.md`.

See `docs/assurance/shared-responsibility-matrix.md` for the companion
Yuzu-vs-operator-vs-infrastructure-provider control matrix.
