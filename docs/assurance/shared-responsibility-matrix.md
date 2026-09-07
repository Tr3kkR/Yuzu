# Shared Responsibility Matrix

Workstream G (Customer Assurance), `docs/enterprise-readiness-soc2-first-customer.md`
§3.7. Yuzu is self-hosted software, not a managed SaaS — nearly every control
area below is a **shared** responsibility, split between what the Yuzu
software does automatically, what the operator (the customer running Yuzu)
must configure or execute, and what the underlying infrastructure provider
(cloud platform, on-prem datacenter, or managed-service vendor) is
responsible for. Every row cites the doc backing the claim; no cell asserts
a control this repo does not actually implement.

**Legend:** ● = full responsibility · ◐ = shared/partial · — = not
applicable to this party. "Planned" in a cell means not shipped yet — see
the cited doc for status.

| Control area | Yuzu (software) | Operator (self-hosting customer) | Infrastructure provider (cloud/on-prem host) | Source |
|---|:---:|:---:|:---:|---|
| **Network transport encryption (TLS/mTLS)** | ● Auto-generates a per-install CA and serves dashboard/REST/gRPC over TLS/mTLS with no opt-out | ◐ Decide whether to trust/replace the auto-generated CA; front the dashboard with a reverse proxy if desired; keep `:50051` off the public internet (composes stay plaintext internally pending PR5b) | ◐ Network ACLs/firewalling/VPC boundary that the "don't expose :50051" guidance depends on | `docs/pki-architecture.md` |
| **CA / key custody** | ● Root private key never stored in the app database (behind `KeyProvider`); CA metadata + CRL versions live in `ca.db` | ◐ Choose/operate the `KeyProvider` backend for production (HSM, cloud KMS, or the default); back up the certs volume alongside every database backup (paired restore requirement) | ◐ HSM/KMS availability and its own access control, if used as the `KeyProvider` backend | `docs/pki-architecture.md`, `docker-compose.reference.yml` header |
| **Secrets-at-rest encryption** | ● Envelope encryption (`SecretCodec`) for every stored secret; never a plaintext DB column | ◐ Operate the KEK provider (`KeyProvider`/`KekProvider`); a Postgres dump alone is unusable without the paired keys directory | — | `docs/adr/0010-secrets-at-rest-envelope-encryption.md` |
| **Host OS patching / hardening** | — | ● Patch the OS, container runtime, and Docker/Podman engine hosting Yuzu | ◐ Underlying hypervisor/hardware patching (cloud) or none (on-prem, fully operator-owned) | — |
| **PostgreSQL substrate — provisioning & patching** | ◐ Ships a reference Postgres image + compose service for convenience; fully supports pointing at an external/managed instance instead | ● Choose and operate the Postgres instance (bundled or external/managed); apply Postgres security patches on the bundled path | ◐ Managed-Postgres provider (if used) owns patching/backups of the underlying service | `docker-compose.reference.yml` header, ADR-0006 |
| **PostgreSQL substrate — HA / failover** | ◐ Ships an optional Patroni-managed 3-node profile with measured automatic-failover RTO/RPO | ● Choose whether to deploy the HA profile vs. single-node; size the quorum | ◐ Underlying compute/storage availability the HA profile assumes | `docs/user-manual/ha-postgres.md` |
| **Backup execution** | ◐ Documents the exact `pg_dump`/`pg_restore`/`tar` procedure and provides `scripts/yuzu-backup.sh`/`yuzu-restore.sh` for the SQLite/config half | ● Schedule and run backups (**no automatic cron/systemd-timer ships today** — this is a documented manual/scriptable procedure, not an automated one); store backups off-host; test restores periodically | ◐ Storage durability for wherever backups are written | `docs/ops-runbooks/restore-drill-2026-09.md` "Gaps found" #1 |
| **Restore execution & DR** | ◐ Procedure is documented and has been executed once against a disposable rig with measured timings (this repo's own drill) | ● Execute the restore when needed; own the RTO/RPO the operator's own backup cadence delivers | ◐ Infrastructure to stand the restored stack back up on | `docs/ops-runbooks/restore-drill-2026-09.md` |
| **Server-listener availability (`/readyz`)** | ◐ Single process today; SLO target reflects that (99.5%/30d) — a second-replica HA posture is planned (ADR-2002 Phase B), not shipped | ● Deploy behind a load balancer / process supervisor for restart-on-crash; monitor the proposed dead-man's-switch alert once wired | ◐ Compute availability the process runs on | `docs/ops-runbooks/slo.md` §1 |
| **RBAC configuration** | ● Enforces the permission model, management-group scoping, and the admit-then-filter list-read chokepoint (ADR-0017) at every gated route | ● Define roles, management-group hierarchy, and grant assignments for their own organization | — | `docs/user-manual/rbac.md`, `docs/user-manual/management-groups.md` |
| **SSO / identity federation (OIDC, SAML, SCIM)** | ● Implements OIDC/SAML SP + SCIM provisioning, group→role mapping, provenance guard, deprovision propagation | ● Configure and operate the IdP itself (Okta, Entra, etc.); own the IdP-side group membership that Yuzu maps from; re-authenticate sessions after an IdP-side revoke to close the #1836 propagation-delay window | ◐ IdP uptime/availability (a third-party SaaS, out of Yuzu's or the operator's direct control) | `docs/auth-architecture.md` §§3.2-3.3 |
| **MFA enrollment & enforcement** | ● Implements TOTP MFA + JIT elevation mechanics | ● Decide which actions require MFA step-up; enroll admin accounts | — | `docs/auth-architecture.md` "MFA / TOTP" |
| **Agent deployment & enrollment** | ● Per-agent mTLS issuance, enrollment tiers, stable C-ABI plugin host | ● Deploy the agent package/bundle to managed endpoints; approve/deny enrollment per fleet policy | ◐ Endpoint OS/hardware the agent runs on | `docs/architecture.md`, `docs/pki-architecture.md` |
| **Monitoring / alert response** | ◐ Ships 61 Prometheus alert rules + 1 recording rule (`docs/prometheus/yuzu-alerts.yml`); the observability overlay in this change is the first shipped stack that actually evaluates them (#2857) | ● Wire an Alertmanager (**not shipped by this repo** — routing is entirely the operator's to build) and staff the on-call rotation that responds to a page | ◐ Alerting egress (email/Slack/PagerDuty integration) is whatever the operator's Alertmanager sends to | `docs/prometheus/yuzu-alerts.yml`, `deploy/docker/docker-compose.observability.yml` |
| **Incident response process** | — | ● Own the detection→triage→containment→customer-communication→postmortem lifecycle | — | `docs/enterprise-readiness-soc2-first-customer.md` §3.4 |
| **Supply-chain verification** | ● Signs (`cosign`), attests (SLSA v1.0), and SBOMs (CycloneDX + SPDX) every release artifact | ◐ Actually run the verification steps before deploying a new release (the tooling is provided, the choice to invoke it in a deploy pipeline is the operator's) | — | `docs/user-manual/release-verification.md` |
| **Audit log retention & export** | ● Clock-guarded, capped retention sweep; fail-hard writes, deny-on-degrade reads | ● Decide `audit_retention_days` for their compliance window; export/forward to an external SIEM if required | — | `docs/user-manual/audit-log.md`, `docs/ops-runbooks/audit-store-clock-guard.md` |
| **Data residency / hosting location** | — | ● Choose where to deploy Yuzu (self-hosted software has no inherent data-residency constraint of its own) | ● Physical/regional location of the chosen infrastructure | — |
| **Vulnerability management (of Yuzu itself)** | ● Dependabot/OpenSSF scorecard program on the codebase; signed releases | ◐ Apply updates promptly; subscribe to release notes/security advisories | — | `docs/user-manual/release-verification.md` |

## Notes for the reviewer

- This matrix intentionally does not claim Yuzu is a managed service — every
  "Operator" column entry reflects that self-hosting carries real
  operational responsibility, which is the honest answer for this product
  shape.
- Any cell not backed by a "Source" citation above is a general shared-hosting
  responsibility (host patching, incident process, data residency) rather
  than something specific to Yuzu's implementation — flagged with `—` in the
  Yuzu column rather than invented.
- See `docs/assurance/security-whitepaper.md` for the narrative version of
  the controls summarised here.
