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
- Session management controls: revocation **shipped** (`DELETE /api/v1/sessions` admin force-logout, `DELETE /api/v1/sessions/me` self-revoke including API tokens; audit actions `session.revoke_all` / `session.revoke_all.self`; Prometheus counter `yuzu_auth_sessions_revoked_total`). Expiration in place via the existing 8-hour cookie max-age. Inactivity timeout and explicit secure-cookie-attribute review remain open.
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
| DEX observations (projection) | `guaranteed-state.db` (`guardian_observations`) | **Behavioral telemetry / PII** — per-device reliability signals (103-type catalogue: app crashes/hangs, boot/resume durations, service/network/identity failures; `docs/dex-signal-catalog.md`). Keyed by `agent_id` → device → person; the per-device history reveals which applications a person runs. | **Lockstep with parent events** — the projection row carries the SAME `ttl_expires_at` as its source event and is reaped in the same cleanup pass; a projection can never outlive its source row | Same `GuaranteedStateStore::run_cleanup` pass — parallel `DELETE FROM guardian_observations WHERE ttl_expires_at > 0 AND ttl_expires_at < now` | `guardian_event_retention_days` (one knob governs both — by design, so event and projection retention cannot diverge) |
| PKI cert inventory | `ca.db` (`ca_root`, `ca_issued`, `ca_crl_versions`) | Internal-CA cert inventory + revocation/CRL state (security-relevant). CA root **private key is NOT stored here** — it is a 0600 file referenced by an opaque `key_ref`. | Indefinite — cert records must outlive the cert for audit | None by design (revocation flips `status`; no reaper) | n/a |
| Analytics events | ClickHouse / JSONL | Telemetry + usage | Customer-controlled (external sink) | Sink-side retention | `clickhouse_*`, `analytics_jsonl_path` |
| Fleet visualization cache | `FleetTopologyStore` (in-memory) | Aggregated `tar.fleet_snapshot` topology — per-machine process records (pid, ppid, process name, OS user, category) and connection edges | **60 s TTL, LRU-of-2 cache slots** (one per `include_vuln` value) | Time-based eviction in-process; never persisted to disk | `--viz-disable` to disable entirely; `tar.configure process_enabled=false` per-agent to suppress process collection upstream |
| Threat-graph recommendations *(proposed, capability §28.9)* | `recommendations.db` | Agentic-AI-produced hardening suggestions awaiting operator action; carries customer_id, generator id, target node/edge keys, rationale, status (open / accepted / dismissed / applied) | Indefinite while open; **90 days default** after dismissed/applied | `RecommendationStore::run_cleanup` thread (planned) — `DELETE … WHERE status IN ('dismissed','applied') AND closed_at < now - retention` | `recommendation_retention_days` |
| VirusTotal hash cache *(proposed, capability §28.8)* | `virustotal_cache.db` | Rate-limited SHA-256 → verdict lookup cache; verdict, scanned_at, engine_hits JSON | **7 days default** | TTL at insert; opportunistic eviction on lookup | `virustotal_cache_ttl_days` |

#### Agent-side edge warehouse (`tar.db`, per device — federated, ADR-0004)

Most device telemetry stays **on the endpoint** in the TAR edge warehouse and is queried on demand (operator SQL, the `/dex` device-perf panel) rather than centralised. The performance tiers added in this release:

| Store / tier | Table | Data class | Default | Retention | Configurable via |
|---|---|---|---|---|---|
| Device performance | `$Perf_Live` / `$Perf_Hourly` | Device-level resource telemetry — CPU %, memory/commit %, disk latency/throughput, network B/s. **No per-application or per-user identity.** | **On** (`perf_enabled=true`) | 7 d raw / 31 d hourly | `perf_enabled`, `perf_interval_seconds` |
| Per-application performance | `$ProcPerf_Live` / `$ProcPerf_Hourly` | **Usage-class telemetry** — top-N applications by CPU + working set, **by image name** (no command lines, no user attribution). Reveals which applications run on a device → works-council-relevant. | **Off (opt-in)** (`procperf_enabled=false`) | 7 d raw / 31 d hourly | `procperf_enabled`, `perf_interval_seconds` |
| Process activity | `$Process_Live` / `$Process_Hourly` / `_Daily` / `_Monthly` | **Behavioral telemetry (PII)** — every process start/stop with image **name**, pid/ppid, exit code, and (live capture only) the owning **user**. **No command lines** (Windows ETW + the privacy posture). Reveals per-user process activity → works-council-relevant. | **On** (`process_enabled=true`) | 100 000-row raw cap (row-capped, **not** time-based — see note); count rollups carry the long tail (24 h / 31 d / 12 mo) | `process_enabled` (row cap not yet operator-tunable — tracked follow-up) |
| Software install/uninstall | `$Software_Live` / `$Software_Daily` / `$Software_Monthly` | **Asset-management + limited PII.** Install/remove/upgrade *events* — app name, version, publisher. The **machine scope** (`scope=machine`, HKLM) carries no personal identity (asset/vuln-inventory data). The **per-user scope** (`scope=user`, Windows) carries the OS **profile name** in the `user` column alongside that user's installed apps → personal data, works-council-relevant. The `_Daily`/`_Monthly` rollups aggregate per `(name, scope)` and drop the username (no PII in the rollup tiers). Names/versions/publisher only — no command lines, no usage/launch data. | **On** (`software_enabled=true`) | 5 000-row raw cap (row-capped; `$Software_Live` carries the per-user `user` column) / 31 d daily / 12 mo monthly | `software_enabled`, `software_interval`, `software_max_hive_mounts` (single per-host toggle bundles machine + user scope — a per-scope toggle is a tracked follow-up, same pattern as the process per-category toggle) |
| DNS resolver cache (ADR-0015) | `$DNS_Live` / `$DNS_Hourly` | **Usage-class telemetry** — device DNS resolver-cache state (resolved domain names + record type/data/TTL). **Device-level — no per-process / per-user attribution** (the cache carries no pid). Reveals which domains a host resolved → works-council-relevant. Cache-only reads (`DNS_QUERY_NO_WIRE_QUERY`), never a wire query. | **Off (opt-in)** (`dns_enabled=false`) | 5 000-row raw cap / 24 h hourly | `dns_enabled` (Windows-only today; Linux/macOS planned) |
| ARP / neighbour table (ADR-0015) | `$ARP_Live` / `$ARP_Hourly` | Network topology — IP↔MAC bindings per interface (Layer-2 adjacency for ARP-spoofing forensics). **No per-user / per-process identity** — lower sensitivity than DNS. | **Off (opt-in)** (`arp_enabled=false`) | 5 000-row raw cap / 24 h hourly | `arp_enabled` (Windows-only today; Linux/macOS planned) |
| Boot-window process trace | `procboot.etl` (kernel AutoLogger file, Windows) | Boot-window process start/stop, **names-only, no user**. Source for the one-time boot backfill into `$Process_Live`. | Configured by the production installer (`advanced` component) and the dev install script | Circular 16 MB file (not `retention_days`-governed); removed on uninstall (installer `[UninstallRun]` + dev script), which also stops the running session | `process_enabled` gates the backfill insert; file lifecycle via the installer / `install-agent-user.ps1` |

These tiers are device-local; raw rows never leave the endpoint except via an operator-initiated, permission-gated query (the `/dex` device-perf panel runs a live `$Perf_Hourly` query, Execute-gated and audited `dex.device.perf.query`). The perf tiers use `RetentionType::kTimeBased`; **`$Process_Live` uses `RetentionType::kRowCount` (100 000 rows)** — see the retention-control caveat below.

Retention numbers are inline defaults; time-based stores expose a `retention_days` constructor argument so a customer can tighten them without a code change (`retention_days = 0` disables the reaper — intended for forensic freezes; requires a compensating manual-export process to avoid unbounded growth). **Exception: `$Process_Live` is row-capped, not time-based, and the cap is not yet operator-configurable** — on a busy endpoint 100 000 rows can be days of history; making the process raw cap (or its conversion to time-based retention) operator-tunable is a tracked follow-up so the per-category retention commitment holds for process data too. The **`$DNS_Live` / `$ARP_Live`** tiers (ADR-0015) are likewise row-capped (5 000) on the Live tier with a time-based 24 h Hourly tier; the DNS-cache PII erasure path today is **disable the source (`dns_enabled=false`) + ring-wrap / Hourly reaper** (no dedicated per-subject DELETE) — and since DNS rows are device-level with no pid, they are not subject-attributable, so a per-subject DSAR maps to the device, not an individual. A dedicated DSAR/erase path is the same tracked roadmap gap noted below.

The fleet visualization cache (`FleetTopologyStore`) is the highest-resolution endpoint telemetry surfaced in the dashboard. It holds at most two snapshots in memory at any time (single-flight refill, no SQLite persistence) and each snapshot is invalidated 60 seconds after the agent dispatch completes; restarting the server purges all cached topology. Process-level fields (`name`, `user`, `category`) are agent-controlled strings rendered after HTML escape and length clamp; the `category` field is computed server-side from a typed enum (`process_category.hpp`) so agents cannot inject arbitrary palette keys. Privacy-sensitive customers can suppress process collection on specific agents via `tar.configure process_enabled=false` (the corresponding cubes in the visualization render with no interior dots) or disable the whole feature with `--viz-disable` / `YUZU_VIZ_DISABLE`.

The Guardian events table is sized for **~10k events/s during a fleet-wide incident** (design doc §9.1), i.e. ~864M rows/day. The 30-day default is the retention/recovery trade-off: long enough to correlate an incident across the standard forensic window, short enough to keep steady-state disk under ~25GB per million endpoints at typical drift rates. Tenants with longer forensic SLAs should raise `guardian_event_retention_days` _and_ provision storage — the product does not auto-trim disk.

### Behavioral telemetry (DEX) — PII posture and works-council / co-determination

The DEX read model (`guardian_observations` + the `/dex` dashboard) is the first surface where Yuzu telemetry is **identifiably behavioral**: a device's signal history reveals which applications a person runs and when they fail. In jurisdictions with employee co-determination — Germany (§87(1)(6) BetrVG), Austria, the Netherlands (WOR), France (CSE), the Nordics — the works council's right is triggered by a system's **capability** to monitor behavior or performance, not by the operator's intent. The controls below are therefore deliberate design decisions, documented here as the evidence base for the DPA/security addendum (workstream G) and customer privacy review:

- **Minimisation at the edge (collection time, not display time).** The agent's catalogue extractors never read user content from events that carry it: DNS queried hostnames (browsing behavior), print document names and owners, profile/logon/VPN/RDP usernames, RDP client addresses, file paths under user profiles (image paths, ESENT database paths, inaccessible-file paths, boot-degradation paths), Defender detection paths and detection users, AAD error-message texts (can embed UPNs), and .NET stack frames are **dropped on the device** — what is never extracted can never be exfiltrated, subpoenaed, or mis-scoped. Each drop is pinned by a `[privacy]`-tagged unit test. **Process/application names ARE collected** — they are the irreducible core of a reliability signal — and are the reason the per-device view is classified PII even though no username field exists in the store.
- **Per-application *performance* sampling (`procperf`) is a separate legal basis, and ships OFF by default.** The reliability justification above covers crash/hang/failure *events*. Continuous per-application CPU + working-set sampling (the `$ProcPerf_*` edge-warehouse tiers, 30 s cadence) is **performance/usage monitoring of which applications a person runs and how heavily** — not a reliability signal, and not covered by that basis. It is therefore opt-in (`procperf_enabled=false`), image-names-only, and is the candidate collector for the per-category collection toggle (first roadmap gap below). Device-level performance (`$Perf_*`, no per-app identity) is a distinct, lower-sensitivity category and stays on by default. Enabling `procperf` for an EU workforce should be treated as a works-council co-determination trigger.
- **Software install/uninstall (`software`) is asset-management class, on by default; the per-user scope carries limited PII.** Recording install/remove/upgrade *events* (app name, version, publisher — no command lines, no launch/usage data) is asset-management and vulnerability-relevance data, the same lower-sensitivity class as the on-by-default Services and User-session sources — distinct from `procperf`'s continuous usage sampling, which is why this source is on by default rather than opt-in. The **machine scope** carries no personal identity. The **per-user scope** (Windows `scope=user`) carries the OS profile name alongside that user's installed apps → personal data; this is analogous to the `user` column on the on-by-default `$User_Live` source. A single per-host `software_enabled` toggle disables the whole source (existing rows stay queryable); a **per-scope toggle** (machine vs user, to satisfy a works-council deployment that wants machine asset inventory without individual-identifying per-user data) is a tracked follow-up, the same gap as the process per-category toggle. The `_Daily`/`_Monthly` rollups drop the username (aggregate per `(name, scope)`), so the long-tail tiers carry no per-user PII; `responses.db` is an erasure source for software query results, same as the per-app panel (F3 DSAR path must include it).
- **Aggregate-by-default, individual-by-exception.** The `/dex` headline is a fleet rollup. The per-device drill-down (the individual-identifying view) is separately permission-gated (`GuaranteedState:Read`) and **every open is audit-logged** (`dex.device.view` in `audit.db`, 365-day retention) — access transparency for the individual-level read path. **The individual read path has two channels with identical gating and audit:** the `/device` dashboard DEX lens AND the machine-readable REST endpoints `GET /api/v1/dex/devices/{id}` (emits `dex.device.view`) and `POST /api/v1/dex/devices/{id}/live` (emits `device.live.uptime` / `device.live.processes`, `result=requested`, audited **before** dispatch). Both REST endpoints are **fail-closed**: a non-persistable audit row returns `503` + `Sec-Audit-Failed: true` and serves no PII / dispatches no probe. Both channels are in the data inventory for this read path, so a Workstream-E review of "what can trigger an individual behavioral read" must list REST, not only the dashboard.
- **The machine-health audit exemption (named policy decision, F2a 2026-06-12; extended to the network surface N1 2026-06-15).** Aggregate fleet-performance and cohort-benchmarking reads (the `/dex` Performance tab, `GET /api/v1/dex/perf/{fleet,cohorts,devices}`, the matching MCP tools) **and the fleet network-quality reads** (`GET /api/v1/network/{fleet,devices}`, the MCP tools `get_network_fleet` / `list_network_devices`, and the `/network` dashboard fragments) are **deliberately not per-read audited**: they carry no behavioral history, no event detail, no `detail_json` — only device-state telemetry (CPU/commit/disk levels; device-aggregate RTT/retransmit/throughput link health) and operator tag values, which are not individually-identifying behavioral data. The audited boundary is unchanged: the individual device *behavioral* view (`dex.device.view`), the machine-health *device query* (`dex.device.perf.query`), and the usage-class per-application panel (`dex.device.procperf.query` — whose result polls require the audited dispatch's `command_id`, so no usage-class read escapes the count). **Compensating control:** un-audited REST reads on these machine-health surfaces are covered at the web-server access-log layer (request path, principal, status, timestamp); the MCP path additionally emits the generic `mcp.<tool>` audit event per invocation. **Accepted residual risk:** a principal holding `GuaranteedState:Read` can enumerate fleet topology and cohort (e.g. location) membership without a per-read SIEM trail — accepted for the machine-health class because `GuaranteedState:Read` is an access-reviewed role and the compensating controls above apply; this is not new (it predates N1 for DEX-perf and the `/network` fragments). This paragraph is the citable policy line for CC7.2 evidence reviews.
- **Per-app names transit the server response store.** When an operator runs the per-application panel, the device's reply (per-application image names — usage-class) is persisted in `responses.db` under the standard response retention (`response_retention_days`, default 90 d) — i.e. longer than the 31-day on-device tier. The data-inventory row for `responses.db` carries this annotation, and the future F3 DSAR path must include `responses.db` as an erasure source alongside `guardian_observations.detail_json`.
- **Device live-snapshot reads transit the server response store (extends the per-app note).** The device-page **Get live info** cards dispatch read-only queries whose replies persist in `responses.db` under the same retention. Several carry usage-class behavioral PII: the **process tree** (`device.live.process_tree` — process names + parent→child graph + SHA-256 + per-process remote connection endpoints), **active connections** (`device.live.connections`), **logged-in users** (`device.live.users`), and the **DNS resolver cache** (`device.live.dns_cache`). The machine-health cards (uptime/services/adapters/ARP/listening/capture-sources) carry no individually-identifying data. The F3 DSAR/erasure path must treat all four usage-class `device.live.*` categories as `responses.db` erasure sources; each dispatch is per-read audited under its own verb (works-council separately-countable).
- **Operator tag values are a data category (classification: operator-defined, variable sensitivity).** Tags drive scoping AND, since F2a, the opt-in per-cohort Prometheus export, where the chosen key's **values become metric labels** scraped by external monitoring stacks. Risk-register entry: tag values of variable sensitivity may flow to third-party monitoring if cohort export is enabled (mitigations: opt-in + admin-gated + audited key changes + the floor/cap bounds + documented key-selection guidance in `metrics.md`/the Settings panel).
- **Lockstep retention.** Projection rows inherit the parent event's TTL and are reaped in the same cleanup pass (single operator knob, `guardian_event_retention_days`); 30-day default.
- **Deploy-time opt-out.** `--dex-disable` / `YUZU_AGENT_DEX_DISABLE` prevents the observer from ever arming — no DEX signal telemetry is collected on that endpoint, and the heartbeat tags are omitted so fleet rollups reflect genuine state.
- **Named roadmap gaps (required before EU-works-council deployments; tracked, not yet built):** per-category collection toggles (fleet-wide and per-management-group), a kill switch for the individual-identifying drill-down, a pseudonymization mode (device IDs not resolvable to a person except by a narrow role), operator-set per-store retention exposed in the dashboard rather than via constructor argument, a **dedicated `DEX:Read` securable** (today the per-device behavioral view is gated on `GuaranteedState:Read`, which also covers Guardian config reads — separating them lets a least-privilege access review grant DEX behavioral access as its own decision; the audit log per individual open is the compensating control until then), and a **targeted per-subject deletion (DSAR) path** (bulk TTL alone does not satisfy a subject-access erasure request in GDPR-adjacent jurisdictions; `detail_json` on the source events would support a future backfill/erase script).

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
