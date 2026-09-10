# Yuzu Security Whitepaper

**Audience:** a prospective customer's security reviewer performing technical
due diligence (Workstream G, `docs/enterprise-readiness-soc2-first-customer.md`
§3.7). **Every claim below cites the repo document it summarises** — this
whitepaper adds no new controls and asserts nothing that isn't already true
in the codebase or an existing doc. Where a control is **planned, not
shipped**, that is stated explicitly; overclaiming a gap is worse than
disclosing one to this audience.

**Last updated:** 2026-09-07. Re-review this document whenever any cited
source doc materially changes (its own change-log/date is the trigger).

**Version anchor.** This document describes Yuzu at `dev` @ `d295db964`
(2026-09-07) unless a claim is explicitly marked otherwise. **The latest
tagged release is v0.13.0** (2026-07-11), which **predates** several
controls this document describes as shipped — every item below verified by
`git log`/`git diff v0.13.0..d295db964 -- <file>`, not asserted from
memory:

- The PostgreSQL-backed audit store (ADR-0040) — v0.13.0's audit trail is
  still the legacy SQLite `audit.db` (§3.5/§4/§7).
- The `CaStore` PostgreSQL migration (ADR-0053) — v0.13.0 still uses
  `ca.db` (§2.1, matrix "CA / key custody").
- The `RbacStore` PostgreSQL migration (ADR-0041) (§3.5, matrix "RBAC
  configuration").
- **The `ManagementGroupStore` PostgreSQL migration (ADR-0042)** — a
  substantial rewrite between v0.13.0 and this anchor (826 insertions/533
  deletions in `management_group_store.cpp` alone); v0.13.0's management
  groups are SQLite-backed (§3.5's management-group scoping claims).
- **`SessionStore` (durable, PostgreSQL-backed operator sessions, HA
  WS-1/1a, ADR-2002 §4)** — `server/core/src/session_store.hpp` does not
  exist at all in v0.13.0 (confirmed: `git cat-file -e
  v0.13.0:server/core/src/session_store.hpp` fails). A v0.13.0 deployment's
  sessions are in-memory only and do NOT survive a restart — the opposite
  of what `docs/ops-runbooks/auth-db-recovery.md`'s corrected guidance
  states for `dev`-HEAD (§3.1's "Durable operator sessions" claim is
  dev-only).
- **MCP Streamable HTTP transport** (`mcp_transport.hpp`, `mcp_session.hpp`,
  ADR-1005 execution-plan Decision 15 / track 2f) — neither file exists in
  v0.13.0 (same `git cat-file -e` check). §8's "is live" claim is dev-only;
  a v0.13.0 deployment has the older, non-session MCP transport only.

A reviewer evaluating a specific deployed version should confirm which of
these have shipped in that build rather than assume dev-HEAD posture.
ADR-1005 (§9) is accepted as of 2026-09-07 (#4099) but is itself a
`dev`-only fact at this writing — it has not yet reached a tagged release
either.

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
| Server → Gateway management (`:50063`, command fan-out) | Strict mutual TLS + SPKI peer pin | The privileged command plane; admits only CA-issued client certs pinned to the server's own key. |

"Mutual TLS between every hop" would overclaim the agent→gateway leg —
correct only for direct-connect agents and the two gateway↔server hops.

**Storage substrate split (ADR-0006):** the server's control-plane state
lives in PostgreSQL — the server **fails closed at boot** (refuses to start,
no SQLite fallback) if `--postgres-dsn`/`YUZU_POSTGRES_DSN` is unset or
unreachable. The agent stays SQLite (local, per-endpoint, federated edge
warehouse — no shared multi-tenant database on the endpoint side). See
ADR-0006/0007/0008/0012 and `docs/postgres-store-playbook.md`.

**Optional HA profile:** a Patroni-managed three-node PostgreSQL topology
with automatic failover is available (`docs/user-manual/ha-postgres.md`) —
measured failover RTO **~30-40 seconds** (correction: a prior revision of
this document said "~15-40s", which matched no source in this repo; the
cited doc's own "What you get" section states "~30-40 seconds" from its
failover smoke test). **This is a different mechanism, and a different
number, from the restore-from-backup RTO in §5 below** — failover promotes
a standby without rebuilding the server (seconds); restore-from-backup
rebuilds from a backup file (minutes) — do not conflate the two. RPO=0
while a synchronous standby holds (`quorum3` durability profile, the
shipped default). This is **available, not the default single-node
deployment**; see `docs/ops-runbooks/slo.md` §1 for how the
server-listener SLO differs from this database-layer figure.

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
issues per-agent leaf certificates signed by that CA; the CA root **private
key is never stored in the database** — CA metadata, issued-cert inventory,
and CRL version history live in the `ca_store` PostgreSQL schema (ADR-0053;
migrated from the legacy `ca.db` SQLite file — see this document's version
anchor above for which builds still use the SQLite form), with the key
itself behind a `KeyProvider` abstraction holding only an opaque `key_ref`.
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

Application secrets (credentials, tokens, key material) are never a plain
Postgres column: each is either a verify-only hash (passwords, API tokens)
or an envelope-encrypted blob via `SecretCodec`, wrapping a per-secret DEK
under a KEK obtained through a pluggable `KeyProvider`/`KekProvider` seam.
Design and threat model: `docs/adr/0010-secrets-at-rest-envelope-encryption.md`.

## 3. Authentication and authorization

### 3.1 Session and login

Session-cookie authentication with PBKDF2-hashed local passwords, or SSO.
Session cookies ship `HttpOnly; SameSite=Lax`, plus `Secure` whenever HTTPS
is enabled (`AuthRoutes::session_cookie_attrs`, `server/core/src/auth_routes.cpp`)
— **shipped**, not planned. Absolute session lifetime is 8 hours; a sliding
**inactivity (idle) timeout** (`--session-inactivity-secs`) additionally
expires a cookie session after a configurable idle period, durably mirrored
to the session store so the idle clock survives a restart or replica
failover — **shipped** (`docs/security-reviews/inactivity-timeout-2026-06-30.md`,
`server/core/src/session_store.hpp` `last_activity_ms`). See
`docs/auth-architecture.md` "Durable operator sessions" for the full
mechanism.

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

SCIM v2 user/group provisioning and deprovisioning, fail-closed
configuration, a provenance guard preventing a SCIM-originated write from
silently overriding an SSO-linked identity's own role assignment, and
group→role mapping. Full reference: `docs/auth-architecture.md` "SCIM v2
provisioning".

### 3.4 MFA

TOTP-based MFA for privileged actions, JIT (just-in-time) admin elevation
gated behind an MFA proof with a bounded elevation window, and MFA
enforcement layered on top of SAML SSO login. Full reference:
`docs/auth-architecture.md` "MFA / TOTP", "JIT admin elevation".

### 3.5 RBAC and management groups

Role-based access control with a granular permission model
(`docs/user-manual/rbac.md`) and hierarchical management groups that scope
an operator's visibility/authority to a confined subset of the fleet
(`docs/user-manual/management-groups.md`). `RbacStore` is PostgreSQL-backed
(ADR-0041); a bare global `require_permission` on a list route is a
known-inert pattern for a confined operator and fails open if the RBAC
store is unreadable/degraded. List-shaped reads (fleet-wide queries, not
single-resource lookups) are **required** to go through the admit-then-filter
`authorize_list_read` chokepoint (ADR-0017) on **migrated** routes — this is
policy for all new work, not yet complete coverage of every existing route:
`docs/auth-architecture.md` names a handful of fleet-wide reads not yet on
this chokepoint (`GET /api/v1/execution-statistics/agents` and the workflow
executions LIST fragment, tracked #3526; `/fragments/results` additionally
has no audit trail at all, tracked #3528). See `docs/auth-architecture.md`
"Granular RBAC (Phase 3)" and "The authorization topology floor (#2376)" for
the full migrated/unmigrated inventory — do not cite this control as
covering every list route without checking that inventory first.

### 3.6 API tokens and service automation

Scoped, expiring API tokens with a rotation process and fleet-wide
service-scope default-deny confinement (a service-scoped token cannot reach
a `(securable, operation)` pair until explicitly allow-listed). Full
reference: `docs/auth-architecture.md` "API tokens and automation", "Human
API-token rotation".

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
guarantee, until a hash-chain or equivalent mechanism ships. As of ADR-0040
the audit store is PostgreSQL-backed with **no SQLite fallback**
(construction fails closed). **The `503`/`Sec-Audit-Failed` fail-hard write
behaviour is scoped to behavioural-PII REST reads specifically** (the
`rest_audit.hpp` `emit_behavioral_audit` chokepoint) — **not** a blanket
guarantee across every ingress: dashboard HTML routes and MCP tool calls are
"set-and-proceed" on an audit-write failure (the request completes even if
the audit row did not persist), a different posture from REST's fail-closed
one. Reads deny on degrade for the REST audit query surface (`503`, never a
false-empty response). A clock-guarded, capped retention sweep bounds how
fast the evidence table can drain even under a forward clock jump on the
PostgreSQL host — the guard
declines a pass it cannot trust rather than risk over-deleting, and every
decline/anomaly is itself an alertable signal
(`docs/ops-runbooks/audit-store-clock-guard.md`). See
`docs/ops-runbooks/slo.md` §4 for the write-success SLO built on this
control, and `docs/enterprise-readiness-soc2-first-customer.md` §3.5 for the
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
`server/core/src`, unlike the other four). **Backup/restore drills were
executed against this procedure (not merely described) — but the
transcripts, and the corrected version of `docs/operations/disaster-recovery.md`
they validate, do not ship on this branch/PR at all.** This document's own
copy of `docs/operations/disaster-recovery.md` is the unmodified,
pre-fix `origin/dev` version (reverted as part of a PO decision to split
assurance-evidence work from DR-procedure work into independently-reviewable
PRs) — treat every claim about what the DR procedure does, how long it
takes, or what it was proven to do as **not applicable to this checkout**.
For the actual drill transcripts (four attempts total, RTO/RPO figures,
every defect found and how each was fixed and verified), the corrected
procedure, and the corrected `scripts/yuzu-backup.sh`/`yuzu-restore.sh`:
see PR `po/dr-procedure` (`docs/ops-runbooks/restore-drill-2026-09.md`,
`docs/ops-runbooks/dr-procedure-drill-2026-09.md`). The optional
HA-Postgres profile's separately-measured failover figures (an unrelated,
already-shipped mechanism, not affected by the DR-procedure split):
`docs/user-manual/ha-postgres.md`.

**Planned, not yet shipped:** a direct `/readyz`-content availability probe
(today's proxy is Prometheus scrape health of the `/metrics` endpoint, not a
dedicated blackbox probe of `/readyz` itself — untracked; proposed, see
`docs/ops-runbooks/slo.md` §1's correction, neither #2956 nor #2459 names
this gap); a second
server replica (ADR-2002 Phase B) to raise the single-replica 99.5%/30d
availability target to 99.9%/30d; a scheduled (cron/systemd-timer) backup
job (today's procedure is a documented manual/scriptable command, not an
automatically-scheduled one, and this branch's copy carries none of the
`po/dr-procedure` fixes — see that PR for the corrected version and its
gap list).

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
accounting of which retention guards are fully clock-guarded-and-capped
today versus still on a bare wall-clock `DELETE`. Behavioral telemetry (DEX)
carries its own PII posture and works-council/co-determination discussion in
the same section — do not summarise that surface without reading it, the
distinctions are load-bearing for a EU-works-council conversation.

## 8. Agentic / MCP surface

The MCP (Model Context Protocol) surface — the mechanism by which an
agentic/AI operator drives Yuzu — carries the same tier-before-RBAC
ordering, kill switches, and audit pattern as every other ingress:
`docs/mcp-server.md`. Tool annotations (destructive-hint truthfulness,
bounded input/output schemas, honest `retry_after_ms`) are a machine-verifiable
contract, not prose-only documentation — `docs/agentic-first-principle.md`
invariant A5. **Correction — shipped, not planned:** a spec-compliant MCP
**Streamable HTTP transport** — the session-lifecycle + transport pre-check
half of ADR-1005 execution-plan Decision 15 / track 2f (in-memory,
principal-bound session ids, GET SSE channel, `notifications/progress`) —
**is live** (`server/core/src/mcp_transport.hpp`, `mcp_session.hpp`;
`docs/mcp-server.md` "Phase 2.5 (Implemented — MCP Streamable HTTP
transport, track 2f PR 1 + PR 2)"). Track 2f's Phase 3 (further hardening
beyond PR 1/PR 2) remains planned — see `docs/mcp-server.md` for the
current boundary between what has shipped and what hasn't within this
track.

## 9. Headless platform posture (ADR-1005)

**ADR-1005 is accepted (2026-09-07, #4099)** — as of the version anchor
above, this is a `dev`-only fact; it has not reached a tagged release (see
the version anchor at the top of this document). **Its requirement is
prospective, not a present-tense universal claim about every existing
capability:** on acceptance, its Decisions govern *new and changed*
capabilities from the acceptance date forward — that a capability be
reachable by an authenticated external principal via both versioned REST
**and** MCP (or a recorded exception in the ADR-1005 ledger), no UI-only
capability surface — and do **not** retroactively condemn the surfaces the
ADR itself records as grandfathered as of acceptance. On-behalf-of header
assertions are rejected at every ingress except the four health-probe
paths (so a header-stamping proxy cannot crash-loop the server) — this
Interim rule binds immediately on acceptance, unlike the prospective
Decisions above. **Phase 7 (the NVD-sync strangler re-home) has not
started** — do not represent that migration as complete or in-flight to a
reviewer. Full policy: `docs/adr/1005-headless-platform-use-case-engines.md`
(see its grandfather-clause enumeration for what is exempted and why);
current phase status: `docs/adr-1005-execution-plan.md`.

---

## Sources cited in this document

`docs/architecture.md` · `docs/pki-architecture.md` ·
`docs/adr/0010-secrets-at-rest-envelope-encryption.md` ·
`docs/auth-architecture.md` ·
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
