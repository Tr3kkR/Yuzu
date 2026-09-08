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
controls this document describes as shipped: the PostgreSQL-backed audit
store (ADR-0040 — v0.13.0's audit trail is still the legacy SQLite
`audit.db`), the `CaStore` PostgreSQL migration (ADR-0053), and the
`RbacStore` PostgreSQL migration (ADR-0041). A reviewer evaluating a
specific deployed version should confirm which of these have shipped in
that build rather than assume dev-HEAD posture. ADR-1005 (§9) is accepted
as of 2026-09-07 (#4099) but is itself a `dev`-only fact at this writing —
it has not yet reached a tagged release either.

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
measured failover RTO ~15-40s, RPO=0 while a synchronous standby holds
(`quorum3` durability profile, the shipped default). This is **available,
not the default single-node deployment**; see
`docs/ops-runbooks/slo.md` §1 for how the server-listener SLO differs from
this database-layer figure.

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
the exact Prometheus alert that pages on it: `docs/ops-runbooks/slo.md`. A
backup/restore drill was executed (not merely described) against the
documented `pg_dump`/`pg_restore`/`tar` procedure, with measured RTO/RPO and
a row-count/audit-chain integrity check post-restore:
`docs/ops-runbooks/restore-drill-2026-09.md`. The optional HA-Postgres
profile's separately-measured failover figures:
`docs/user-manual/ha-postgres.md`.

**Planned, not yet shipped:** a direct `/readyz`-content availability probe
(today's proxy is Prometheus scrape health of the `/metrics` endpoint, not a
dedicated blackbox probe of `/readyz` itself — tracked #2956); a second
server replica (ADR-2002 Phase B) to raise the single-replica 99.5%/30d
availability target to 99.9%/30d; a scheduled (cron/systemd-timer) backup
job (today's procedure is a documented manual/scriptable command, not an
automatically-scheduled one — see `docs/ops-runbooks/restore-drill-2026-09.md`
"Gaps found").

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
invariant A5. **Planned:** a first-class MCP session concept (in-memory,
principal-bound, TTL/caps, revocation cuts live streams) via ADR-1005
execution-plan track 2f — not shipped as of this writing.

## 9. Headless platform posture (ADR-1005)

Every capability is required to be reachable by an authenticated external
principal via both versioned REST **and** MCP (or a recorded exception in
the ADR-1005 ledger) — there is no UI-only capability surface, and
on-behalf-of header assertions are rejected at every ingress except the four
health-probe paths (so a header-stamping proxy cannot crash-loop the
server). Full policy: `docs/adr/1005-headless-platform-use-case-engines.md`;
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
`docs/ops-runbooks/restore-drill-2026-09.md` ·
`docs/user-manual/ha-postgres.md` ·
`docs/user-manual/release-verification.md` ·
`docs/enterprise-readiness-soc2-first-customer.md` §3.5 ·
`docs/mcp-server.md` · `docs/agentic-first-principle.md` ·
`docs/adr/1005-headless-platform-use-case-engines.md` ·
`docs/adr-1005-execution-plan.md` · `docs/observability-conventions.md`.

See `docs/assurance/shared-responsibility-matrix.md` for the companion
Yuzu-vs-operator-vs-infrastructure-provider control matrix.
