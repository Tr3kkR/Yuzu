# Enterprise Readiness Plan: SOC 2 Type II + First Large Enterprise Customer

**Version:** 1.0  
**Date:** 2026-04-04  
**Audience:** Engineering, Security, Product, Operations, GTM, Executive Leadership

---

## 1) Executive Summary

Yuzu has strong product depth (agent/server/gateway architecture, RBAC, policy engine, OTA, and broad plugin coverage), but SOC 2 Type II and enterprise procurement require controls and evidence beyond feature completeness. This plan defines the capabilities, process controls, artifacts, and timeline needed to:

1. Pass a SOC 2 Type II audit window.
2. Successfully onboard and support a first large enterprise customer.

**Guiding principle:** Prioritize controls and evidence pipelines that satisfy both SOC 2 and real enterprise customer security reviews, so every investment serves both outcomes.

---

## 2) Outcomes and Success Criteria

## 2.1 SOC 2 Type II Outcomes

- Audit scope and system description finalized.
- Control set implemented across Security, Availability, and Confidentiality trust criteria (minimum), with optional Processing Integrity where required.
- Evidence collection automated for at least 80% of recurring controls.
- Clean internal readiness assessment and successful external audit period completion.

## 2.2 First Enterprise Customer Outcomes

- Security questionnaire and architecture review passed.
- Customer-required controls (SSO, least privilege, auditability, encryption, incident response) demonstrably in place.
- Production onboarding completed with documented runbooks and named escalation paths.
- Contractual security commitments (SLAs/SLOs, incident notification, vulnerability remediation windows) accepted and operationalized.

---

## 3) Strategic Workstreams

## 3.1 Workstream A — Governance, Risk, and Compliance (GRC)

### Deliverables

- **Control framework:** SOC 2 control matrix mapped to owners, systems, and evidence sources.
- **Risk register:** Product and operational risks ranked by likelihood/impact with mitigations and review cadence.
- **Policy set:** Security policy suite (access control, change management, incident response, vendor management, backup/DR, secure SDLC).
- **Audit evidence index:** Single source listing each control, evidence artifact, generation cadence, and owner.

### Implementation Steps

1. Define audit boundary and in-scope systems.
2. Select GRC tooling (or structured repo + ticket workflow if lightweight).
3. Appoint control owners (Engineering, Security, IT, People, Legal).
4. Establish monthly control health reviews.

---

## 3.2 Workstream B — Identity, Access, and Administrative Security

### Target State

- SSO enforcement for admin users.
- Role-based least privilege and separation of duties.
- MFA requirements for privileged actions.
- Periodic access reviews with manager/security attestation.

### Required Features / Controls

- Enforce OIDC SSO for production admin access.
- Disable local-password fallback in hardened mode (or tightly constrain break-glass account policy).
- Add **2FA/TOTP for high-risk approvals** (aligned with roadmap hardening).
- Session management controls: expiration, revocation, inactivity timeout, secure cookie attributes.
- API token governance: scoped permissions, expiration defaults, rotation process, token inventory.

### Evidence

- SSO configuration records, role assignment exports, access review sign-offs, and sampled auth logs.

---

## 3.3 Workstream C — Application and Infrastructure Security

### Target State

- Secure-by-default deployment profile.
- Defense-in-depth for data-in-transit, data-at-rest, and supply chain.
- Measurable vulnerability management lifecycle.

### Required Features / Controls

- TLS/mTLS enforcement in production profiles.
- Security headers baseline (CSP, frame protections, strict transport settings where applicable).
- Hardened deployment templates (systemd/container) with least privilege and filesystem protections.
- Dependency and image scanning gates in CI.
- Signed release artifacts and provenance attestation.
- Formal secure coding standard + threat modeling for high-risk subsystems.

### Evidence

- CI security scan logs, release signing attestations, config baselines, and change approvals.

---

## 3.4 Workstream D — Reliability, Availability, and Operational Readiness

### Target State

- Predictable service reliability with enterprise-grade runbooks and incident response.
- Demonstrated recovery objectives (RTO/RPO).
- On-call coverage and escalation protocols.

### Required Features / Controls

- SLO definitions for API availability, command dispatch latency, and job success rates.
- Alerting and escalation for SLO burn, error spikes, and capacity thresholds.
- Backup/restore automation plus periodic restore drills.
- Incident response lifecycle: detection, triage, containment, customer communications, postmortem.
- Capacity plans for 1k/5k/10k+ agents and documented scaling decision points.

### Evidence

- Monitoring dashboards, incident tickets/postmortems, backup logs, restore drill reports.

---

## 3.5 Workstream E — Data Governance and Privacy

### Target State

- Clear data classification and retention policy tied to product settings.
- Customer-facing transparency about what is collected, retained, and exported.

### Required Features / Controls

- Data inventory by table/store/event type.
- Retention defaults and customer-configurable retention policies with enforcement checks.
- Documented deletion workflows and verification procedures.
- Encryption and key management requirements for sensitive data stores.

### Evidence

- Data flow diagrams, retention configs, deletion run records, and quarterly data governance reviews.

### Data Inventory — server-side SQLite stores

| Store | File | Data class | Retention | Deletion mechanism | Configurable via |
|---|---|---|---|---|---|
| Audit trail | `audit.db` | Operator activity (security-relevant) | 365 days | `AuditStore::run_cleanup` thread — `DELETE … WHERE ttl_expires_at < now` | `audit_retention_days` |
| Response store | `responses.db` | Agent command results | 90 days | `ResponseStore` cleanup thread (TTL at insert) | `response_retention_days` |
| Guaranteed-state rules | `guaranteed-state.db` (`guaranteed_state_rules`) | Rule definitions (configuration) | Indefinite — lifecycle via explicit delete | REST DELETE / `delete_rule` | n/a |
| Guaranteed-state events | `guaranteed-state.db` (`guaranteed_state_events`) | Drift/remediation telemetry (high-volume operational) | **30 days default** | `GuaranteedStateStore::run_cleanup` thread — `DELETE … WHERE ttl_expires_at > 0 AND ttl_expires_at < now` | `guardian_event_retention_days` |
| Analytics events | ClickHouse / JSONL | Telemetry + usage | Customer-controlled (external sink) | Sink-side retention | `clickhouse_*`, `analytics_jsonl_path` |

Retention numbers are inline defaults; every store exposes a `retention_days` constructor argument so a customer can tighten them without a code change. `retention_days = 0` disables the reaper (intended for forensic freezes; requires a compensating manual-export process to avoid unbounded growth).

The Guardian events table is sized for **~10k events/s during a fleet-wide incident** (design doc §9.1), i.e. ~864M rows/day. The 30-day default is the retention/recovery trade-off: long enough to correlate an incident across the standard forensic window, short enough to keep steady-state disk under ~25GB per million endpoints at typical drift rates. Tenants with longer forensic SLAs should raise `guardian_event_retention_days` _and_ provision storage — the product does not auto-trim disk.

---

## 3.6 Workstream F — Secure SDLC and Change Management

### Target State

- Every production change is traceable, reviewed, tested, and auditable.

### Required Features / Controls

- Branch protection and mandatory code review.
- Required CI checks (build/test/security scans) before merge.
- Change ticket linkage for release-impacting modifications.
- Release checklist with rollback strategy and approvals.
- Segregation between development, staging, and production environments.

### Evidence

- PR review records, CI logs, deployment approvals, and release notes/change tickets.

---

## 3.7 Workstream G — Customer Assurance Package (Enterprise Sales Enablement)

### Deliverables

- Security whitepaper and architecture overview.
- Standard CAIQ-style questionnaire responses.
- Pen-test executive summary and remediation statement.
- DPA/security addendum templates.
- Shared responsibility matrix (vendor vs customer responsibilities).

### First-Customer Readiness Milestones

1. Technical due-diligence packet ready.
2. Security review Q&A runbook and owners assigned.
3. Pilot onboarding playbook (networking, certs, SSO, agent rollout).
4. Executive escalation path and customer success governance cadence.

---

## 4) SOC 2 Type II Control Implementation Backlog

## 4.1 Priority 0 (0–30 days)

- Finalize SOC 2 scope, system boundaries, and control owners.
- Ratify core policies and approval workflows.
- Establish evidence repository structure and naming conventions.
- Enforce mandatory review + CI gates on all production-bound code.
- Define incident severity model and notification SLAs.

## 4.2 Priority 1 (31–90 days)

- Implement MFA/step-up auth for privileged approvals.
- Complete security headers and hardened deployment baseline.
- Integrate vulnerability scanning with remediation SLA tracking.
- Run first tabletop incident response exercise.
- Execute first documented backup restore drill.

## 4.3 Priority 2 (91–180 days)

- Run operational metrics program against formal SLOs.
- Complete external penetration test and close critical findings.
- Validate high-scale customer deployment architecture.
- Launch customer trust center artifacts and standard security packet.

## 4.4 Priority 3 (Audit window)

- Freeze control design changes (unless risk-critical).
- Monitor control performance and evidence completeness weekly.
- Perform internal pre-audit and remediation sprint.
- Complete audit period and respond to auditor requests quickly.

---

## 5) First Enterprise Customer Plan (Go-to-Production)

## 5.1 Pre-Sales to Contract

- Complete security questionnaire and architecture deep dive.
- Confirm mandatory integrations (IdP, SIEM, ticketing, endpoint rollout tooling).
- Agree shared security responsibility and data-handling terms.
- Define commercial and operational SLAs.

## 5.2 Pilot Phase

- Deploy to non-production tenant/environment.
- Validate SSO, RBAC, logging, and approval flows end-to-end.
- Run controlled command/compliance/policy workflows at target scale subset.
- Joint success criteria with customer IT/SecOps leads.

## 5.3 Production Rollout

- Phased rollout with rollback checkpoints.
- Daily health reviews during initial launch window.
- Weekly governance meeting (engineering + security + customer success).
- 30/60/90-day value and risk review.

---

## 6) Metrics and Readiness Scorecard

## 6.1 Control Health KPIs

- % controls implemented vs planned.
- % controls with automated evidence.
- % evidence artifacts generated on schedule.
- # open high/critical audit readiness gaps.

## 6.2 Security and Reliability KPIs

- Mean time to remediate critical vulnerabilities.
- MFA adoption coverage for privileged users.
- Incident MTTR and recurrence rate.
- SLO attainment (%).

## 6.3 Enterprise Customer KPIs

- Security review turnaround time.
- Time to pilot completion.
- Time to production acceptance.
- # post-launch escalations in first 90 days.

---

## 7) RACI (Condensed)

- **Security Lead:** Control design, risk register, audit coordination.
- **Engineering Lead:** Feature/control implementation, SDLC controls, reliability.
- **DevOps/SRE:** Infrastructure hardening, observability, DR drills, on-call.
- **Product:** Prioritization and customer requirement alignment.
- **Customer Success / Sales Engineering:** Enterprise onboarding execution and stakeholder management.
- **Legal/Finance:** Contractual security terms and compliance vendor management.

---

## 8) Immediate Next 10 Actions

1. Nominate control owners and publish SOC 2 scope memo.
2. Open an “Enterprise Readiness” epic with workstream sub-epics.
3. Baseline current control coverage against SOC 2 criteria.
4. Define production-hardening profile and default secure configuration.
5. Implement privileged-action MFA requirement.
6. Stand up evidence automation jobs (access reviews, CI outputs, backups, vulnerability reports).
7. Author incident response and customer notification playbooks.
8. Schedule first tabletop + restore drill.
9. Prepare standard security questionnaire responses and architecture packet.
10. Select target design-partner customer and execute a controlled pilot plan.

---

## 9) Appendix — Suggested Artifacts to Maintain

- SOC 2 control matrix and evidence index.
- Network/data-flow diagrams and trust boundaries.
- Secure configuration baseline (server/agent/gateway).
- Incident response runbook + communications templates.
- Backup/restore runbook and drill history.
- Access review records and privileged access logs.
- Change management and release approval records.
- Vulnerability management reports and remediation logs.

