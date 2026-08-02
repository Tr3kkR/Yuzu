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
- **Residual (#1836):** OIDC IdP-group→RBAC deprovisioning (#1832) propagates on the user's **next SSO login**, not immediately on IdP-side group removal — a live session/cookie or an already-issued token retains its prior roles until re-authentication. Session revocation (above) is the operator's manual mitigation in the interim; automatic mid-session role re-check is tracked in #1836.
- **UCE surface (forward ref):** the use-case-engine host inherits SSO transitively through this server's OIDC (`docs/uce-host-requirements.md` §4.6/NF-9 — Yuzu-as-identity-provider). This **doubles #1836's blast surface**: a stale IdP group also gates UCE artifact-minting until the operator's Yuzu session is force-revoked or the ≤5-min artifact TTL / NF-9(d) liveness floor expires, and it adds a second login-event stream **outside** the server's audit perimeter (`uce-host-requirements.md` NF-6). An access-control reviewer working from this section must follow NF-9 for the second surface.

### Evidence

- SSO configuration records, role assignment exports, access review sign-offs, and sampled auth logs.

**Addendum — machine-identity resource-bounding (CC6.6, PR 4.4).** Engine
principals (ADR-1005 class) are already least-privilege by construction —
default-deny RBAC resolution, structurally barred from admin/built-in/
wildcard roles (see the `engine_principal_store.*` row in `CLAUDE.md`) — and
PR 4.4 adds the complementary resource-bounding control: a per-principal
in-flight concurrency cap and request-rate cap enforced at the server's
single pre-routing chokepoint, so a compromised or malfunctioning engine
principal cannot exhaust server capacity via unbounded concurrent or
high-rate requests. Credit this pairing (least-privilege identity +
bounded-resource machine credential) as a CC6.6 control for any privileged/
machine-identity access review. See `docs/user-manual/engine-principals.md`
"Per-principal quota cap" for the operator-facing reference.

**Addendum — engine-credential rotation confirm pinning (CC6.1/CC6.3, #2384).**
The overlap-pair rotation's maker-checker confirm step is pinned to the exact
credential being confirmed: the confirm call (REST and MCP) requires the
successor `token_id` the rotate response returned, a stale or mismatched id is
rejected with no state change, and the success audit row records
`token_id=<confirmed id>` — binding the attestation evidence to one specific
credential. This closes a rotation-confirm replay hazard (a blind retry of an
old confirm landing after a second rotation started could previously revoke
that later rotation's still-live credential). Credit as a CC6.3
credential-rotation control with per-credential attestation evidence; the
operator-facing flow is `docs/user-manual/engine-principals.md` §4 and the
audit contract is the `engine_principal.credential.confirm` row in
`docs/user-manual/audit-log.md`.

**Addendum — engine-principal revocation latency for LIVE streams (CC6.2, #2367).**
Answering "how quickly is a revoked machine identity cut off?" now has three
distinct figures, and they should be quoted separately:

- **New sessions and new delegations: immediate.** Session synthesis and the
  REST/MCP on-behalf-of target checks read the principal store authoritatively
  on every call. A revoked engine principal cannot obtain a new session or a
  new delegation at any point after the revoke commits.
- **Live held-open streams, same server: next heartbeat tick (~3 s).** The
  per-tick liveness re-check is served from a 15 s cache, but the revoking
  server invalidates that cache synchronously as part of the revoke write.
- **Live held-open streams, other replicas: bounded by the 15 s cache TTL plus
  a tick.** The cache is per-process, so a peer replica honours its own entry
  until it expires. This is the same class of residual property the 60 s API
  token cache already carries, and is the figure to quote for a multi-replica
  deployment.

These figures apply to streams authenticated by an **engine** principal.
Streams authenticated by an ordinary API token have a *different, currently-open*
profile: a token-cache hit is still treated as a fresh confirmation, so for
those the cache residency and the outage grace window can still add — the
non-additive guarantee below is engine-specific (pre-existing, tracked as
#2447). Do not generalise the engine figures to all streams when answering a
questionnaire.

An auth store that is *unreachable* is deliberately not treated as a
revocation (it would cut every stream on the fleet at once); such streams ride
a bounded grace window and then close with a distinct `auth_unavailable`
reason. For engine streams that window is measured from the last authoritative
confirmation, so cached answers cannot extend total survival beyond it. Credit
as a CC6.2 revocation control with the bounds above; the operator-facing
reference is `docs/mcp-server.md` "Revocation." and the upgrade note in
`docs/user-manual/server-admin.md`.

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
- MCP tool dispatch validates its internal authorization-registration tables at startup and refuses to boot on drift, rather than silently serving an under-governed tool (fail-closed on internal misconfiguration; #2383).

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
| Audit trail | `audit.db` | Security-relevant activity: operator actions, plus agent enrolment, fleet-topology events and background schedule execution | 365 days (a **floor**, not a ceiling - deletion is paced, never retroactive) | `AuditStore::cleanup_once` on the `run_cleanup` thread - clock-guarded and capped (#2360): the pass declines and warns when it would expire every datable row, when the persisted clock reading is unusable, or when the gap since the previous pass exceeds a fixed 7 days (a clock jump OR an outage that long - elapsed time cannot separate them), and deletes at most 25,000 rows per pass, oldest first. The decision rule is `classify()` plus the fact construction in `AuditStore::cleanup_once`, pinned by an exhaustive truth table and store-level tests; operator triage is `docs/user-manual/audit-log.md#the-retention-clock-guard`. **Closed #2579: an ABSENT stored reading is now a decline trigger when rows are already expired** - bringing it in line with the TAR guard below, which gates the same way (both require rows to be already expired; neither fires on a fresh install). The surviving differences are scope and accounting: TAR decides per warehouse TABLE, this per database, and this counts to its own series rather than the shared decline counter. Such a pass declines once, warns and anchors the reading, then proceeds - counted by `..._retention_bootstrap_declines_total`, kept separate from the clock-anomaly series because it asserts only that nothing can yet be ruled out. Previously it deleted unremarked, so a server upgraded to schema v3 while its clock was already skewed forward could lose expired rows with no decline and no counter; there is no reliable retrospective test for whether a given database was affected, and the loss is not recoverable without a backup predating it. This is the one row in this table where "clock-guarded" carries a documented exception, and it applies to the SOC 2 control record itself. `ttl_expires_at` is stamped at INSERT and never rewritten, so changing the setting does not re-date existing rows. Series (seven counters plus one gauge): `yuzu_server_audit_clock_anomaly_skips_total`, `..._retention_bootstrap_declines_total` (#2579, counted apart because it makes no claim about the clock), `..._cleanup_failed_total`, `..._retention_cap_reached_total`, `..._rows_deleted_total`, `..._retention_persist_failed_total`, plus the two LIVENESS signals `..._retention_passes_total` and `..._retention_last_pass_unixtime` - every other counter here is silence-means-healthy, so these are what distinguish a quiet healthy store from a reaper that stopped running. | `audit_retention_days` |
| Response store | `responses.db` | Agent command results | 90 days | `ResponseStore` cleanup thread (TTL at insert). **Not yet clock-guarded** - see the note below the table. | `response_retention_days` |
| Guaranteed-state rules | `guaranteed-state.db` (`guaranteed_state_rules`) | Rule definitions (configuration) | Indefinite — lifecycle via explicit delete | REST DELETE / `delete_rule` | n/a |
| Guaranteed-state events | `guaranteed-state.db` (`guaranteed_state_events`) | Drift/remediation telemetry (high-volume operational) | **30 days default** | `GuaranteedStateStore::run_cleanup` thread — `DELETE … WHERE ttl_expires_at > 0 AND ttl_expires_at < now` | `guardian_event_retention_days` |
| DEX observations (projection) | `guaranteed-state.db` (`guardian_observations`) | **Behavioral telemetry / PII** — per-device reliability signals (114-type display catalogue — 110 Windows event-log types + 4 poll-derived; app crashes/hangs, boot/resume durations, service/network/identity/power/driver failures; authoritative count in `docs/dex-signal-catalog.md`). Keyed by `agent_id` → device → person; the per-device history reveals which applications a person runs. | **Lockstep with parent events** — the projection row carries the SAME `ttl_expires_at` as its source event and is reaped in the same cleanup pass; a projection can never outlive its source row | Same `GuaranteedStateStore::run_cleanup` pass — parallel `DELETE FROM guardian_observations WHERE ttl_expires_at > 0 AND ttl_expires_at < now` | `guardian_event_retention_days` (one knob governs both — by design, so event and projection retention cannot diverge) |
| PKI cert inventory | `ca.db` (`ca_root`, `ca_issued`, `ca_crl_versions`) | Internal-CA cert inventory + revocation/CRL state (security-relevant). CA root **private key is NOT stored here** — it is a 0600 file referenced by an opaque `key_ref`. | Indefinite — cert records must outlive the cert for audit | None by design (revocation flips `status`; no reaper) | n/a |
| Analytics events | ClickHouse / JSONL | Telemetry + usage | Customer-controlled (external sink) | Sink-side retention | `clickhouse_*`, `analytics_jsonl_path` |
| Fleet visualization cache | `FleetTopologyStore` (in-memory) | Aggregated `tar.fleet_snapshot` topology — per-machine process records (pid, ppid, process name, OS user, category) and connection edges | **60 s TTL, LRU-of-2 cache slots** (one per `include_vuln` value) | Time-based eviction in-process; never persisted to disk | `--viz-disable` to disable entirely; `tar.configure process_enabled=false` per-agent to suppress process collection upstream |
| Threat-graph recommendations *(proposed, capability §28.9)* | `recommendations.db` | Agentic-AI-produced hardening suggestions awaiting operator action; carries customer_id, generator id, target node/edge keys, rationale, status (open / accepted / dismissed / applied) | Indefinite while open; **90 days default** after dismissed/applied | `RecommendationStore::run_cleanup` thread (planned) — `DELETE … WHERE status IN ('dismissed','applied') AND closed_at < now - retention` | `recommendation_retention_days` |
| VirusTotal hash cache *(proposed, capability §28.8)* | `virustotal_cache.db` | Rate-limited SHA-256 → verdict lookup cache; verdict, scanned_at, engine_hits JSON | **7 days default** | TTL at insert; opportunistic eviction on lookup | `virustotal_cache_ttl_days` |


**Audit capacity ceiling (Workstream D + G).** The paced drain above is a fixed 25,000 rows per hourly pass, which is a sustained ceiling of roughly **6.9 audit events/second** (~600,000 rows/day). Above that rate expiry outruns deletion and `audit.db` grows without bound; `yuzu_server_audit_retention_cap_reached_total` is the signal. At the 365-day default this is also a **storage** commitment on the order of 219M rows / ~44 GB at the ceiling. The DRAIN-RATE ceiling is an engineering constant, not configuration, so a prospect whose audit rate exceeds it needs a scoping conversation rather than a settings change. The storage figure is an ESTIMATE built on an assumed ~200 bytes/row and varies with principal, action and detail length -- quote the rate as a limit, the size as an order of magnitude. Derivation and the caveats on the size estimate: `docs/user-manual/audit-log.md` ("Capacity").

### Data Inventory — server-side PostgreSQL stores (ADR-0006/0008)

As of the Postgres substrate flip (ADR-0006), born-on-Postgres stores are the
server's primary data home and carry the same data-classification obligations as
the SQLite table above. Each new server store registers here.

| Store | Schema (PostgreSQL) | Data class | Retention | Deletion mechanism | Configurable via |
|---|---|---|---|---|---|
| Per-application performance, centralized (B1) | `app_perf_daily_store` (`app_perf_daily`) | **Usage-class telemetry** — per-device daily app-performance summary: `(app image name, version, UTC day)` with CPU/working-set averages + peaks + a sample count. The centralized projection of the on-device `$ProcPerf_*` tiers (below), shipped by the `app_perf` daily-sync source. **Names-only — no command lines, no user attribution, no SID/username/user-path.** Same legal class as `$ProcPerf_*` and a step *more* exposing than installed-software (it reveals not just which apps are present but how heavily each runs over time, device-attributable via `agent_id`) → **works-council co-determination-relevant** (capability to monitor; BetrVG §87(1)(6)) and personal data under GDPR if treated as such on personally-assigned devices. Resource-significant (procperf top-N) app-versions only — not a complete usage census. | **31-day** rolling retention — `apply_daily` prunes rows older than 31 UTC days per agent on each sync (`AppPerfDailyStore::kRetentionDays`). A device that stops reporting retains ≤31 days, then ages out; `delete_agent` clears on removal. | Per-agent prune is automatic (time-based). **Whole-device decommission purge is WIRED** (ADR-0024) — `AppPerfDailyStore::delete_agent` is fanned by the `AgentDecommission` cascade behind the audited **`DELETE /api/v1/sle/agents/{id}`** route, so a decommissioned device's rows are durably erased and the store reports its committed delete status (a rolled-back delete is reported failed, never a false erasure). **Row-level / per-subject DSAR (Art. 17) erasure remains unwired** — the cascade is whole-device only; that residual gap is #1666. | **`procperf_enabled=false`** (per-app collection opt-in — no procperf data → no B1 data) **and** `--inventory-disable` / `YUZU_AGENT_INVENTORY_DISABLE` (the daily-sync master switch). Windows + Linux-fed today (Linux rows carry `version=''` and are kernel 15-char comms, which may include kernel-thread names — system infrastructure, not user-app usage); macOS planned. |
| Per-application performance, fleet aggregate (B2) | `app_perf_fleet_store` (`app_perf_fleet`) | **Fleet-aggregate** app performance per `(app, version, UTC day)` — device count, CPU/working-set sums + maxima, and a per-bucket device-count histogram (the trend/regression substrate). **Carries NO `agent_id` — no per-device attribution.** It is a derived aggregate over the fleet, not individually-identifying, so it is materially LOWER sensitivity than B1 (above) and not individually works-council-relevant on its own. (Collection is still gated upstream: it is derived from B1, so `procperf_enabled=false` / `--inventory-disable` empties it.) | **180-day** retention — the roll-up thread prunes `day < now − 180d`. | Time-based prune (automatic). No per-device purge applies (no device dimension); a DSAR erase targets B1, not this aggregate. | Derived — gated upstream by B1's `procperf_enabled` + `--inventory-disable`. |
| Generic plugin inventory | `inventory_store` (`inventory_data`) | Device-attributable (`agent_id`) per-plugin JSON blobs for sources not promoted to a typed store. **Sensitivity is plugin-dependent**: custom plugins may collect identifiers, configuration, paths, or other customer-defined data, so this store must not be represented as categorically non-PII or secret-safe. Typed `installed_software`, `app_perf`, `device_ci`, and `software_licensing` sources are excluded and remain under their own securables. | **Current-state only** — each `(agent_id, plugin)` report replaces the prior blob; no time-based reaper, so a device that stops reporting retains its last state. | Whole-device purge is WIRED through `AgentDecommission`. During the one-release rollback window `InventoryStore::delete_agent` erases both PostgreSQL and retained `inventory.db`, and reports failure unless both commit. If failed-backfill recovery moves the file aside, ADR-0037 classifies that copy as an operator-managed backup requiring manual subject erasure, recorded purge evidence, and removal within the same one-release boundary. No row-level/per-subject DSAR API (#1666). | `--inventory-disable` / `YUZU_AGENT_INVENTORY_DISABLE` disables daily inventory collection; individual custom-plugin collection is governed by that plugin's own configuration. |
| Installed-software inventory | `software_inventory_store` (`inventory_state`, `installed_software`) | Installed-software **asset inventory** per device — name, version, publisher, install date — collected by the agent daily-sync framework (ADR-0016). **Machine-scope; no end-user PII** — per-user enumeration is deliberately *not* used (ADR-0016 §8): no logged-in-user attribution, no usernames. **Lower behavioral sensitivity than the process-performance tiers** (no run-time, no CPU/memory attribution). **However:** the data is device-attributable (`agent_id`), and on **personally-assigned devices** installed-software enumeration may still be **works-council co-determination-relevant** under national law (e.g. BetrVG §87(1)(6)) — co-determination is triggered by the *capability to monitor*, not by username presence, the same basis on which `$ProcPerf_Live` (above) ships opt-in. Consult works-council counsel before deploying in EU collective-bargaining jurisdictions; an erasure obligation (GDPR Art. 17) attaches if the data is treated as personal in such a deployment. | **Current-state only** — each sync *replaces* the device's rows; there is **no time-based reaper**. Last-known state is retained after a device stops reporting (mirrors the offline-endpoint posture); `inventory_state.last_seen` marks activity. | **Per-device purge is WIRED** (ADR-0024). `SoftwareInventoryStore::delete_agent` is fanned by the `AgentDecommission` cascade behind the audited **`DELETE /api/v1/sle/agents/{id}`** route (scoped `SoftwareLicensing:Delete` **and** `Inventory:Delete` **and** `GuaranteedState:Delete` — a conjunction over every securable the cascade erases through; audit-before-erase fail-closed), so a decommissioned device's rows are durably erased with truthful per-store committed status. Stale-device exclusion remains a query-time `last_seen` filter, not a delete — an *aged-out* device that was never decommissioned keeps its rows. **Row-level / per-subject DSAR (Art. 17) erasure is still unwired** — the cascade erases a whole device, not one subject's rows (tracked in #1666). | **`--inventory-disable` / `YUZU_AGENT_INVENTORY_DISABLE`** (agent deploy-time opt-out — collect nothing); no per-store retention knob yet (#1666) |
| Device configuration-item (CI) inventory | `device_inventory_store` (`device_ci`) | Device hardware/OS identity — manufacturer, model, **serial number**, **system UUID**, BIOS, CPU/RAM, **primary + all MAC addresses**, NIC count, OS name/version/build, architecture. Collected by the agent daily-sync framework (ADR-0016 source #3), 1:1 per agent (current-state only). **Machine-scope** (no username/SID/user-path), but serial/system_uuid/primary_mac are **stable device-persistent identifiers** — personal data under GDPR when a device is person-assigned, and works-council co-determination-relevant on the *capability* to track a device (and by association its user) over time, regardless of per-user data (ADR-0016). **Operator-visible** via the `/inventory` Devices tab (list columns + per-device CI panel) — both reads gate on `Inventory:Read` and audit at the **behavioural-PII tier** (`emit_behavioral_audit`, `Sec-Audit-Failed` on persist failure): `inventory.devices` (fleet list, gated on the global `Inventory:Read`; per-device confinement is *designed for, not yet verified effective* — the ADR-0017 admit-then-filter gate hasn't landed for Inventory list reads (tracked under PR-D), the same inert-list-scoping class as the confinement caveat below) and `inventory.device.ci` (per-device drill, scoped at the gate, three-state found/absent/degraded). | **Current-state only** — each sync *replaces* the device's row; no time-based reaper. | **Per-device purge is WIRED** (ADR-0024) — `DeviceInventoryStore::delete_agent` is fanned by the same `AgentDecommission` cascade behind **`DELETE /api/v1/sle/agents/{id}`** as `software_inventory_store` above. **Row-level / per-subject DSAR (Art. 17) erasure remains unwired** (#1666). | **`--inventory-disable` / `YUZU_AGENT_INVENTORY_DISABLE`** (agent deploy-time opt-out); no per-store retention knob yet (#1666). |
| Offline-endpoint state | `offline_endpoint_store` (schema `endpoint_state`) | Per-device last-heartbeat / liveness state (machine-health; no PII). Drives stale-flagging of aged-out hosts in `/viz/fleet` so they are flagged rather than silently vanishing at the 60 s TTL. Device-attributable (`agent_id`). | Current-state upsert per heartbeat; **no reaper** (aged hosts are flagged, not deleted — kept by design). | None wired — this store is **not** in the ADR-0024 decommission cascade (aged hosts are flagged, not deleted, by design), so the per-device purge gap still stands here (#1545/#1666). | n/a |
| Pre-flight run results | `preflight_run_store` (`runs`, `run_device`) | `/auto` pre-flight check **configuration + results** — device scope, the per-device pass/fail/warn check grid, summary counts. **Operational / machine-health**: asset-inventory-class facts (free disk, OS version, reboot state, target-app version). Device-attributable (`agent_id` / `hostname`); no end-user PII, no behavioral telemetry. | **14-day rolling** — best-effort `prune_older_than` on the background pre-flight runner thread; owner can also delete a run. | Owner-scoped `delete_run` (manual) + time-based prune (automatic). No wired DSAR / decommission purge (the platform #1666 gap). | No per-store retention knob. |
| Deployment run state | `deployment_run_store` (`deployments`, `deployment_device`) | The `/auto` deploy stage — artifact delivery spec (download **URL**, filename, expected **SHA-256**, install args) + per-device deployment execution state (step, exit code, error, hostname, OS). **Operational / machine-health**: device-attributable (`agent_id` / `hostname`); no end-user PII, no behavioral telemetry. The artifact URL/args are operator-supplied and may carry internal infrastructure detail (file-server host, paths). | **14-day rolling** — best-effort `prune_older_than` piggy-backed on the pre-flight runner thread; owner can also delete a deployment. | Owner-scoped `delete_deployment` (manual) + time-based prune (automatic). No wired DSAR / decommission purge (#1666). | No per-store retention knob. |
| Software-licensing detection inventory | `software_licensing_store` (`agent_license_state`, `agent_licenses`) | Detected **software-licence** facts per device — per detected product: product, vendor, version, `license_type`, channel, status, `expiry_at`, `confidence`, and `exe_hints`, collected by the new **`software_licensing`** daily-sync source (ADR-0024). **Deliberately deviates from ADR-0016's machine-scope / no-PII posture on exactly two fields** (Decision 11, maintainer-signed-off): per-user licence surfaces (loaded per-user `HKU` hives + per-profile licence files, e.g. JetBrains / Adobe) emit **`user_scope=user`** + **`user_ref`**. `user_ref` is **pseudonymous personal data** — default mode `hash` is a per-agent keyed-HMAC pseudonym `HMAC-SHA256(k_agent, profile)` truncated to 16 hex (**personal data under GDPR Recital 26**; a per-device pseudonym, **not** anonymisation), never a SID / email / directory identity. Machine-scope licence rows are asset-class; the two per-user fields are the only personal data. Device-attributable (`agent_id`) and, on person-assigned devices, works-council co-determination-relevant on the capability to attribute software to an individual. | **Current-state only** — each sync **full-replaces** the device's rows (raw-blob hash-skip suppresses re-send while nothing changes); **no time-based reaper**. `agent_license_state.first_seen` / `last_seen` are **server receipt times** and mark activity. | Flipping the identifier knob to **`--license-scan-user-ref=omit`** purges `user_ref` **within one 24 h sync cycle** for syncing agents (offline agents on reconnect) — the knob-flip full-replace is the usable erasure path today. The **agent-decommission cascade** (`AgentDecommission` fanning `SoftwareLicensingStore::delete_agent` across all five per-agent stores, built by ADR-0024) is **LIVE**, triggered by **`DELETE /api/v1/sle/agents/{id}`**: gated on the per-device scoped `SoftwareLicensing:Delete` **and** `Inventory:Delete` **and** `GuaranteedState:Delete` conjunction (the cascade's blast radius spans all three securables), **audit-before-erase fail-closed** (an attempt row that cannot persist means no erasure — 503 + `Sec-Audit-Failed`, because an unaudited erasure destroys its own evidence), and honest per-store outcomes (each `delete_agent` returns committed status, so a rolled-back store is reported `Failed` → HTTP 500, never a false `decommissioned:true`; the cascade is idempotent, so re-issue the DELETE). This is the wired GDPR Art. 17 whole-device erasure path. **No row-level erasure API — stated gap** (the cascade erases a whole device, not one subject's rows). | **`--inventory-disable` / `YUZU_AGENT_INVENTORY_DISABLE`** (source-level opt-out — collect nothing) **and** **`--license-scan-user-ref`** (`collect` / `hash` / `omit`, default `hash`; `omit` suppresses the identifier but not the per-user probe, `collect` sends raw profile names). |
| Product registry (software catalog) | `product_registry_store` (`products`, `product_aliases`) | Server-derived **software-product catalog** — normalised product identity (`norm_key`, vendor, title, edition, platform) plus raw-name→product **aliases** that back licence and entitlement matching (ADR-0024). **No device attribution and no PII** — a normalisation / reference table derived from detected product names, carrying **no `agent_id`** and no per-user data. | **Indefinite** — catalog reference data; soft product keys are re-resolved every evaluator cycle (matcher improvements self-heal), so rows are lifecycle-managed by matching, not a reaper. | None by design (reference data; no `agent_id` dimension, so no per-device / DSAR purge applies — explicit DELETE is the only disposal, matching the PKI cert-inventory convention above). | n/a — populated only while the `software_licensing` source is active (gated upstream by `--inventory-disable`). |

Every PostgreSQL store in this table fails **closed** on an unreachable database (ADR-0007 — the server refuses to boot), and is gated into `/readyz` and `/healthz`. Beyond boot, `software_inventory_store` reads are **authoritative** (ADR-0016 §7): a transient query-time degradation after a healthy boot (pool-acquire timeout, query error) surfaces as a `kInternalError` from `query_installed_software` (and a `503` A4 envelope from the REST sibling `GET /api/v1/inventory/software`), never a successful empty result — so a fleet vulnerability query can never read a transient backend hiccup as "installed nowhere". **Both read channels (MCP + REST) carry a per-agent management-group drop filter** (out-of-scope device rows are dropped and the drop is audited — a distinct `denied` event with the dropped-device count). **However, this confinement is NOT yet verified effective and must NOT be cited as an affirmative CAIQ / CC6.1 answer for fleet list reads:** both channels gate on the *global* `Inventory:Read` permission, and under that global gate the per-agent filter does not narrow results (a management-group-confined operator is denied at the gate before the filter runs; a global operator's filter is a no-op) — the same inert-list-scoping class documented in **ADR-0017**. List-view management-group confinement is *designed for* here but becomes effective only once the ADR-0017 admit-then-filter gate lands and the #1713/#1676 UAT confirms it. Until then, treat operator read isolation on this surface as **per-device-only**, and answer the CAIQ confidentiality question for fleet list reads as "designed, not yet verified" — not affirmative. **Per-device decommission erasure is now wired** for the five stores in the ADR-0024 `AgentDecommission` cascade (`inventory`, `software_inventory`, `app_perf_daily`, `device_inventory`, `software_licensing`) via the audited `DELETE /api/v1/sle/agents/{id}`. What **#1666** still tracks is the residue: **row-level / per-subject DSAR erasure** (the cascade is whole-device only) and the per-agent stores *outside* the cascade — `offline_endpoint_store` (**#1545**), `preflight_run_store`, `deployment_run_store`. For a device that ages out without being decommissioned, `last_seen` remains the canonical "is this device still active" filter for asset-management counts.

**Daily-sync PII carve-out (ADR-0024 Decision 11).** The ADR-0016 daily-sync framework was specified **machine-scope / no-end-user-PII**, and the `installed_software` and `device_ci` rows above still hold to that (no usernames, no per-user attribution — those statements remain true). The **`software_licensing` source deliberately deviates** — and only that source: at the owner's explicit direction it probes per-user licence surfaces, so its records may carry `user_scope=user` + a pseudonymous `user_ref` (see the `software_licensing_store` row above). This is a contained, **maintainer-signed-off** deviation confined to **two fields on this one source**. Default `hash` mode keeps `user_ref` pseudonymous (still personal data under **GDPR Recital 26**); `--license-scan-user-ref=omit` suppresses the identifier; `--inventory-disable` turns the source off entirely. It does **not** relax the machine-scope posture of any other daily-sync source (installed-software, device-CI, app-performance). Full per-surface disclosure — exactly what is probed on Windows / Linux / macOS, and the honest limits of the `hash` pseudonym — is in [`docs/user-manual/software-licensing.md`](user-manual/software-licensing.md), the works-council-reviewable transparency evidence.

#### UCE host stores (`engines/`, own PostgreSQL — separate deployable, ADR-1005)

Use-case-engine (UCE) modules run in a **separately-deployed host** with **its
own PostgreSQL database, never the server's connection pool** (ADR-1005 plan
Decision 11). Data a UCE re-serves or derives sits **outside the server's audit
perimeter** (ADR-1005 Decision 5), so the UCE host carries its own
audit/compliance controls for it. **Topology (2026-07-12, accepted trade-off):
the UCE data layer is a separate database on the server's own PostgreSQL
*instance* — not a separate instance — with a dedicated role/grants, cross-database
access forbidden and mechanically revoked, and TLS-only remote access from the UCE
VM (full design + isolation mechanics: `docs/uce-deployment-topology-design.md`);
so this row's "separate database" MUST NOT be read as instance-level isolation
for CAIQ/CC6.1 purposes.** This row registers the derived store here for
inventory completeness. Entries are **forward-declared** — the store ships at the
vuln module's store-ship milestone (requirements: `docs/uce-host-requirements.md` §7 + F-12, exec-plan
item 2c) — following the `recommendations.db` *(proposed)* precedent above.

**Confinement maturity caveat (same posture as the server-store note at the top
of this section):** the findings-view management-group confinement this store
depends on (`uce-host-requirements.md` §6) resolves through the ADR-0017
admit-then-filter chokepoint, which is **chartered but unbuilt today** — so
findings-view operator confinement is **designed, not yet verified effective**,
and MUST NOT be cited as an affirmative CAIQ / CC6.1 answer until M3(d) verifies
it (`uce-host-requirements.md` F-5/F-15). The same "designed, not verified"
caveat applies to the **operator login / SSO surface** (`uce-host-requirements.md`
NF-9, Verify = "stack ADR (T2b) / security-guardian" — not yet built): "UCE
inherits Yuzu SSO" MUST NOT be cited as an affirmative CAIQ/CC6.x answer until
T2b ships and security-guardian signs off. There is no collection-level off-switch
row for this store because the UCE vuln module is itself a **separately-deployed,
opt-in artifact** — a customer without works-council sign-off simply does not
stand it up; the only per-store knob is retention.

| Store | Schema (PostgreSQL) | Data class | Retention | Deletion mechanism | Configurable via |
|---|---|---|---|---|---|
| Vulnerability findings (UCE vuln module) *(forward-declared — exec-plan 2c commitment; ships at the module's store-ship milestone, F-12)* | UCE host PostgreSQL (own database; table names settled at store-ship / stack ADR) | **Derived vulnerability findings — sensitive security data, device-attributable.** Per-device CVE exposure (`agent_id` × CVE × matched product/version, with severity/exploitability). Enumerates the fleet's exploitable attack surface, so treated as **more sensitive than the installed-software inventory it derives from** — a breach discloses what is *attackable*, not merely what is installed. **No direct username/SID** (machine-scope source, ADR-0016 §8), but device-attributable and therefore **personal data under GDPR when the device is person-assigned** — hence the subject-erasure path in the deletion column; device-attributability keeps the works-council capability-to-monitor posture of its source. Sits **outside the server audit perimeter** (ADR-1005 Decision 5) — governed by the UCE host's own controls. | Open findings retained **while current** (superseded/refreshed each sync cycle); resolved/superseded findings **90 days default** (mirrors `recommendations.db`). | Module-owned resolved-finding reaper **and device-decommission purge, both wired at the store-ship milestone**, plus a **subject-erasure (DSAR/Art. 17) path** distinct from decommission and a **legal-hold-aware reaper** (`uce-host-requirements.md` F-14) — explicitly not inheriting the #1666 unwired-decommission gap the server inventory stores carry. | `vuln_findings_resolved_retention_days` *(name provisional; final at store-ship)* |

> **Retention-guard coverage is partial, deliberately.** On the server, only the audit trail is clock-guarded and capped (#2360); on the agent, the TAR edge warehouse is (#2361 - see the retention note under the agent-side section below). The response store and the Guardian-event store still issue a bare `DELETE ... WHERE ttl_expires_at < now` driven by the server's wall clock, so a forward clock step can empty either in one statement. They are lower-stakes than the evidence trail (operational telemetry, not the SOC 2 control record) and are queued for the same treatment in #2508. An auditor reading this table should not infer that "clock-guarded" applies to every row in it. **Nor that "clock-guarded" means fully guarded in every state:** until #2579 the audit trail's own guard had no missing-anchor trigger, so a server upgraded to schema v3 while its clock was ALREADY skewed forward could delete expired rows with no decline and no counter. That is now closed - such a pass declines once and anchors the reading. The honest answer to "can the audit trail be silently truncated?" is therefore **not on a current build; yes on a build predating #2579, under a forward-skewed clock at upgrade** - and there is no reliable retrospective test to confirm whether a given database was affected, nor recovery without a backup predating the pass.


#### Agent-side edge warehouse (`tar.db`, per device — federated, ADR-0004)

Most device telemetry stays **on the endpoint** in the TAR edge warehouse and is queried on demand (operator SQL, the `/dex` device-perf panel) rather than centralised. The performance tiers added in this release:

| Store / tier | Table | Data class | Default | Retention | Configurable via |
|---|---|---|---|---|---|
| Device performance | `$Perf_Live` / `$Perf_Hourly` | Device-level resource telemetry — CPU %, memory/commit %, disk latency/throughput, network B/s. **No per-application or per-user identity.** | **On** (`perf_enabled=true`) | 7 d raw / 31 d hourly | `perf_enabled`, `perf_interval_seconds` |
| Per-application performance | `$ProcPerf_Live` / `$ProcPerf_Hourly` | **Usage-class telemetry** — top-N applications by CPU + working set, **by image name** (no command lines, no user attribution). Reveals which applications run on a device → works-council-relevant. | **Off (opt-in)** (`procperf_enabled=false`) | 7 d raw / 31 d hourly | `procperf_enabled`, `perf_interval_seconds` |
| Process activity | `$Process_Live` / `$Process_Hourly` / `_Daily` / `_Monthly` | **Behavioral telemetry (PII)** — every process start/stop with image **name**, pid/ppid, exit code, and (live capture only) the owning **user**. **No command lines** (Windows ETW + the privacy posture). Reveals per-user process activity → works-council-relevant. | **On** (`process_enabled=true`) | 100 000-row raw cap (row-capped, **not** time-based — see note); count rollups carry the long tail (24 h / 31 d / 12 mo) | `process_enabled` (row cap not yet operator-tunable — tracked follow-up) |
| Software install/uninstall | `$Software_Live` / `$Software_Daily` / `$Software_Monthly` | **Asset-management inventory — no PII.** Install/remove/upgrade *events* — app name, version, publisher. **Machine scope only** (HKLM Uninstall, 64-bit + WOW6432Node): an event is the host's installed software, never attributed to a Windows profile, so there is **no `user`/profile-name column and no personal data** (asset / vuln-inventory data, like `service`). The `_Daily`/`_Monthly` rollups aggregate per `name`. Names/versions/publisher only — no command lines, no usage/launch data. | **Off (opt-in)** (`software_enabled=false`) | 5 000-row raw cap / 31 d daily / 12 mo monthly | `software_enabled`, `software_interval` |
| DNS resolver cache (ADR-0015) | `$DNS_Live` / `$DNS_Hourly` | **Usage-class telemetry** — device DNS resolver-cache state (resolved domain names + record type/data/TTL). **Device-level — no per-process / per-user attribution** (the cache carries no pid). Reveals which domains a host resolved → works-council-relevant. Cache-only reads (`DNS_QUERY_NO_WIRE_QUERY`), never a wire query. | **Off (opt-in)** (`dns_enabled=false`) | 5 000-row raw cap / 24 h hourly | `dns_enabled` (Windows-only today; Linux/macOS planned) |
| ARP / neighbour table (ADR-0015) | `$ARP_Live` / `$ARP_Hourly` | Network topology — IP↔MAC bindings per interface (Layer-2 adjacency for ARP-spoofing forensics). **No per-user / per-process identity** — lower sensitivity than DNS. | **Off (opt-in)** (`arp_enabled=false`) | 5 000-row raw cap / 24 h hourly | `arp_enabled` (Windows-only today; Linux/macOS planned) |
| Per-connection TCP quality (ADR-0020) | `$NetQual_Live` / `$NetQual_Boot` | **Usage-class telemetry** — per-ESTABLISHED-connection RTT/jitter/loss + lifetime retrans/segs context, joined to the owning process (image name only). **Only a coarse destination CLASS** (`remote_bucket`: loopback/private/public/unknown) is stored — the raw remote address/host is dropped at the collector edge and never persisted. Linux (`inetdiag`) + Windows (`estats`, **elevated-only**; non-elevated records nothing, `netqual_capture_method=none`). `$NetQual_Boot` adds one since-boot host-wide counter row per boot (no per-connection/per-process attribution). Reveals per-app connection quality → works-council-relevant, same class as `$ProcPerf_*`. | **Off (opt-in)** (`netqual_enabled=false`) | 100 000-row raw cap (Live) / 400-row cap (Boot) | `netqual_enabled` |
| Connectivity transitions (ADR-0020) | `$NetConn_Live` | **Usage-class / behavioral-adjacent** — OS-logged network + Wi-Fi connect/disconnect and internet-capability changes, as **closed enum tokens + numeric reason codes only** (action/channel/category/capability/iface_kind/reason_code). **No SSID, BSSID, profile name, interface GUID, MAC, or address is ever extracted.** Device-level (no pid/user). The *timing* of connect/disconnect events is a presence/working-hours proxy → **works-council co-determination-relevant** (capability to monitor). Windows (`wevtapi`, EvtQuery over NetworkProfile/NCSI/WLAN-AutoConfig); the first read **retroactively** backfills OS-retained history from before enablement, bounded by `netconn_lookback_seconds` (default 7 days; **`0` = forward-only, no retrospective read**). | **Off (opt-in)** (`netconn_enabled=false`) | 20 000-row raw cap | `netconn_enabled`, `netconn_lookback_seconds` (retroactive reach / off) |
| Boot-window process trace | `procboot.etl` (kernel AutoLogger file, Windows) | Boot-window process start/stop, **names-only, no user**. Source for the one-time boot backfill into `$Process_Live`. | Configured by the production installer (`advanced` component) and the dev install script | Circular 16 MB file (not `retention_days`-governed); removed on uninstall (installer `[UninstallRun]` + dev script), which also stops the running session | `process_enabled` gates the backfill insert; file lifecycle via the installer / `install-agent-user.ps1` |

These tiers are device-local; raw rows never leave the endpoint except via an operator-initiated, permission-gated query (the `/dex` device-perf panel runs a live `$Perf_Hourly` query, Execute-gated and audited `dex.device.perf.query`). The perf tiers use `RetentionType::kTimeBased`; **`$Process_Live` uses `RetentionType::kRowCount` (100 000 rows)** — see the retention-control caveat below.

Retention numbers are inline defaults; time-based stores expose a `retention_days` constructor argument so a customer can tighten them without a code change (`retention_days = 0` disables the reaper — intended for forensic freezes; requires a compensating manual-export process to avoid unbounded growth). **Exception: `$Process_Live` is row-capped, not time-based, and the cap is not yet operator-configurable** — on a busy endpoint 100 000 rows can be days of history; making the process raw cap (or its conversion to time-based retention) operator-tunable is a tracked follow-up so the per-category retention commitment holds for process data too. The **`$DNS_Live` / `$ARP_Live`** tiers (ADR-0015) are likewise row-capped (5 000) on the Live tier with a time-based 24 h Hourly tier; the DNS-cache PII erasure path today is **disable the source (`dns_enabled=false`) + ring-wrap / Hourly reaper** (no dedicated per-subject DELETE) — and since DNS rows are device-level with no pid, they are not subject-attributable, so a per-subject DSAR maps to the device, not an individual. A dedicated DSAR/erase path is the same tracked roadmap gap noted below.

**Every retention number above is a floor, not a ceiling** (#2361). The reaper runs on the 900 s `tar.rollup` tick, and is now clock-guarded and paced:

- **Time-based tiers are clock-guarded.** Before deleting, each table is probed for whether the cutoff would expire *every* datable row it holds. If it would, the pass declines that table once and records the decline, rather than emptying a forensic window in one statement because the endpoint's clock jumped. A reading persisted in `tar_config` (`retention_guard_last_pass`) makes the guard survive agent restarts; a stored reading that is ahead of the current clock AT ALL, or a jump of more than 30 days between passes, is itself treated as implausible; a pass that finds NO stored reading (the first after an agent upgrade or restore) also declines, once, and is the one trigger that does not spend the latch (the 24 h slack is a separate rule, and applies to row timestamps, not to the stored reading). **The guard paces deletion, it does not block it:** after the one declined pass the latch releases the table to the capped delete below, so a genuinely wrong clock still drains its backlog at 5 000 rows/table/tick. What the guard buys is a recorded decline and the time to notice, not indefinite preservation.
- **Both tier kinds are paced.** A single pass deletes at most 5 000 rows per table, time-based and row-capped alike. A large backlog (a long-powered-off laptop, or an upgrade that lowers a retention setting) drains over successive rollup ticks instead of one multi-second write transaction. Rows therefore survive past their nominal window while the backlog drains - deliberately, and bounded by the tick rate.
- **The evidence surface is the `tar status` action**, since the agent has no `/metrics` endpoint. It emits `retention_guard_declines_total|<n>` and `retention_guard_failures_total|<n>` on every call (including zeros, so an old agent is distinguishable from a healthy one) plus a `retention_guard|<table>|<n>` / `retention_guard_failed|<table>|<n>` line for each affected table. A non-zero *failures* total means retention has stopped for that table - a probe or delete is erroring - and must be read together with the declines total, not instead of it. **These counters are in-memory and reset on agent restart, and are not aggregated fleet-wide today**; reading them is a per-device query.
- **Failure mode with a retention consequence:** if a retention transaction cannot be rolled back and the endpoint's database is left mid-transaction, the agent closes the `tar.db` write connection rather than reporting durable writes it will lose. TAR collection and retention both stop until the agent is restarted; historical rows stay readable through the separate read-only connection (`tar sql`), and `tar status` reports `error|...` followed by `storage_state|offline`. **While an endpoint is in that state its retention commitment is not being met** - nothing is deleted until it restarts. There is no automatic recovery today (tracked follow-up).

The fleet visualization cache (`FleetTopologyStore`) is the highest-resolution endpoint telemetry surfaced in the dashboard. It holds at most two snapshots in memory at any time (single-flight refill, no SQLite persistence) and each snapshot is invalidated 60 seconds after the agent dispatch completes; restarting the server purges all cached topology. Process-level fields (`name`, `user`, `category`) are agent-controlled strings rendered after HTML escape and length clamp; the `category` field is computed server-side from a typed enum (`process_category.hpp`) so agents cannot inject arbitrary palette keys. Privacy-sensitive customers can suppress process collection on specific agents via `tar.configure process_enabled=false` (the corresponding cubes in the visualization render with no interior dots) or disable the whole feature with `--viz-disable` / `YUZU_VIZ_DISABLE`.

The Guardian events table is sized for **~10k events/s during a fleet-wide incident** (design doc §9.1), i.e. ~864M rows/day. The 30-day default is the retention/recovery trade-off: long enough to correlate an incident across the standard forensic window, short enough to keep steady-state disk under ~25GB per million endpoints at typical drift rates. Tenants with longer forensic SLAs should raise `guardian_event_retention_days` _and_ provision storage — the product does not auto-trim disk.

### Behavioral telemetry (DEX) — PII posture and works-council / co-determination

The DEX read model (`guardian_observations` + the `/dex` dashboard) is the first surface where Yuzu telemetry is **identifiably behavioral**: a device's signal history reveals which applications a person runs and when they fail. In jurisdictions with employee co-determination — Germany (§87(1)(6) BetrVG), Austria, the Netherlands (WOR), France (CSE), the Nordics — the works council's right is triggered by a system's **capability** to monitor behavior or performance, not by the operator's intent. The controls below are therefore deliberate design decisions, documented here as the evidence base for the DPA/security addendum (workstream G) and customer privacy review:

- **Minimisation at the edge (collection time, not display time).** The agent's catalogue extractors never read user content from events that carry it: DNS queried hostnames (browsing behavior), print document names and owners, profile/logon/VPN/RDP usernames, RDP client addresses, file paths under user profiles (image paths, ESENT database paths, inaccessible-file paths, boot-degradation paths), Defender detection paths and detection users, AAD error-message texts (can embed UPNs), and .NET stack frames are **dropped on the device** — what is never extracted can never be exfiltrated, subpoenaed, or mis-scoped. Each drop is pinned by a `[privacy]`-tagged unit test. **Process/application names ARE collected** — they are the irreducible core of a reliability signal — and are the reason the per-device view is classified PII even though no username field exists in the store.
- **Per-application *performance* sampling (`procperf`) is a separate legal basis, and ships OFF by default.** The reliability justification above covers crash/hang/failure *events*. Continuous per-application CPU + working-set sampling (the `$ProcPerf_*` edge-warehouse tiers, 30 s cadence) is **performance/usage monitoring of which applications a person runs and how heavily** — not a reliability signal, and not covered by that basis. It is therefore opt-in (`procperf_enabled=false`), image-names-only, and is the candidate collector for the per-category collection toggle (first roadmap gap below). Device-level performance (`$Perf_*`, no per-app identity) is a distinct, lower-sensitivity category and stays on by default. Enabling `procperf` for an EU workforce should be treated as a works-council co-determination trigger.
- **Software install/uninstall (`software`): machine-scope asset-management class, no PII, off by default.** Recording install/remove/upgrade *events* (app name, version, publisher — no command lines, no launch/usage data) is asset-management and vulnerability-relevance data, the same lower-sensitivity class as the Services and User-session sources — distinct from `procperf`'s continuous usage sampling. The source is **machine scope only** (Windows HKLM Uninstall, 64-bit + WOW6432Node): an event is the host's installed software, never attributed to a Windows profile, so there is **no `user`/profile-name column and no personal data**. It nonetheless ships **off by default** (`software_enabled=false`) — the cautious posture for a new capture source — and an operator enables it per host (existing rows stay queryable on disable). The `_Daily`/`_Monthly` rollups aggregate per `name`. Because the source carries no per-user identity, it raises no works-council per-user concern; `responses.db` still retains software query results (machine-scope app names) under the standard response retention.
- **Per-connection network quality (`netqual`) + connectivity transitions (`netconn`): usage-class, off by default, with a novel *retroactive-reach* consideration (ADR-0020).** `$NetQual_Live` records per-connection RTT/jitter/loss joined to the owning app (image name only; the destination is reduced to a coarse `remote_bucket` class — the raw address is never stored) — the same usage-class posture as `$ProcPerf_*`, and on Windows it needs an **elevated agent** (non-elevated records nothing, `netqual_capture_method=none`). `$NetConn_Live` records OS-logged network/Wi-Fi connect/disconnect and internet-capability changes as **closed enum tokens + numeric reason codes only** — no SSID/BSSID/profile/GUID/MAC/address. Both are device-level (no per-user column). **The distinct consideration** vs the forward-looking sources above: enabling `netconn` (and the `$NetQual_Boot` baseline) triggers a one-shot **retrospective** read that ingests OS-retained history from **before TAR — or the agent — existed on the box** (up to `netconn_lookback_seconds`, default 7 days). On a person-assigned device the *timing* of network/Wi-Fi transitions is a presence/working-hours proxy — behavioral personal data under GDPR even with identifiers stripped — so collecting a window that predates the monitoring notice is a distinct lawfulness/transparency (GDPR Art. 13-14) and co-determination question. Mitigations: both sources ship **off by default**; the retroactive reach is operator-configurable and can be set to **`netconn_lookback_seconds=0`** (forward-only, no pre-notice read) where retrospective collection is not lawful; enum-tokens-only storage. **Enabling `netconn` for an EU/co-determination workforce should be raised with the works-council/DPO before enablement**, and the retroactive window set per that agreement (ADR-0020 privacy note).
- **Aggregate-by-default, individual-by-exception.** The `/dex` headline is a fleet rollup. The per-device drill-down (the individual-identifying view) is separately permission-gated (`GuaranteedState:Read`) and **every open is audit-logged** (`dex.device.view` for the device history, and `dex.observation.view` for the per-event detail panel — which records the event's obs_type so usage-class opens stay separately countable — both in `audit.db`, 365-day retention) — access transparency for the individual-level read path. **The individual read path has two channels with identical gating and audit:** the `/device` dashboard DEX lens AND the machine-readable REST endpoints `GET /api/v1/dex/devices/{id}` (emits `dex.device.view`) and `POST /api/v1/dex/devices/{id}/live` (emits `device.live.uptime` / `device.live.processes`, `result=requested`, audited **before** dispatch). Both REST endpoints are **fail-closed**: a non-persistable audit row returns `503` + `Sec-Audit-Failed: true` and serves no PII / dispatches no probe. Both channels are in the data inventory for this read path, so a Workstream-E review of "what can trigger an individual behavioral read" must list REST, not only the dashboard.
- **Guardian per-device compliance is a third behavioral-read channel (`guardian.device.view`).** `GET /api/v1/guaranteed-state/device-compliance?baseline={name}&agent_id={id}` (the ServiceNow/CMDB CI-sync read) returns a named device's per-Guard compliance verdicts — individually-identifying behavioral data — gated on per-device-scoped `GuaranteedState:Read` and **audit-logged on every open** as `guardian.device.view` (`audit.db`, 365-day retention), the same verb the `/device` dashboard Guardian lens emits (one SIEM filter covers both surfaces). **Fail-closed:** a non-persistable audit row returns `503` + `Sec-Audit-Failed: true` and serves no compliance PII (CC7.2), with `503` returned **before** `404` (no name-existence oracle without durable evidence). It belongs in the Workstream-E "what can trigger an individual behavioral read" inventory alongside the `dex.device.view` channels above.
- **Device configuration-item (CI) inventory is a fourth behavioral-adjacent read channel (`inventory.device.ci`, and `inventory.devices` for the fleet-list variant).** The `/inventory` Devices tab's CI columns + per-device CI panel (serial, system UUID, primary/all MAC addresses, BIOS/CPU/RAM, OS version — device-persistent identifiers, ADR-0016) are gated on `Inventory:Read` and audited at the same behavioural-PII tier (`emit_behavioral_audit`) as `dex.device.view`/`guardian.device.view`. Unlike those two, the fleet-list variant (`inventory.devices`) audits a BULK read (the whole roster it renders in one event, not per-device) — see the Data Inventory row above for the full classification. It belongs in the same Workstream-E "individual behavioral read" inventory as the `dex.device.view`/`guardian.device.view` channels.
- **Software-licensing per-agent drill is a fifth individual-identifying read channel (`sle.agent.view`).** `GET /api/v1/sle/agents/{id}` (the SLE single-agent licence drill, ADR-0024) returns a named device's detected licence rows — **including per-user `user_ref` pseudonyms** wherever per-user surfaces were probed — individually-identifying personal data (GDPR Recital 26). The SLE fleet-aggregate surfaces (`/sle/summary`, `/sle/licenses`) are **not built in-server at all** — they are the SAM use-case-engine module's interpretation surface (ADR-0024 / ADR-1005). The one in-server per-agent drill takes the **ancestor-aware per-device scoped `SoftwareLicensing:Read` gate from day one** (403 outside scope — the `device_routes` precedent; it is Decision 11's privacy-verification surface, so it gets real confinement immediately) and is **audit-logged on every open** as `sle.agent.view` at the behavioural-PII tier (`emit_behavioral_audit`, `audit.db`, 365-day retention). **Fail-closed:** a non-persistable audit row returns `503` + `Sec-Audit-Failed: true` and serves no licence PII (CC7.2). It belongs in the same Workstream-E "individual behavioral read" inventory as the `dex.device.view` / `guardian.device.view` / `inventory.device.ci` channels above.
- **The machine-health audit exemption (named policy decision, F2a 2026-06-12; extended to the network surface N1 2026-06-15; extended to app-performance-over-time aggregates 2026-06-28).** Aggregate fleet-performance and cohort-benchmarking reads (the `/dex` Performance tab, `GET /api/v1/dex/perf/{fleet,cohorts,devices}`, the matching MCP tools), **the application-performance-over-time aggregates** (`GET /api/v1/dex/perf/{apps,app,group}`, the MCP tools `list_dex_perf_apps` / `get_dex_app_perf` / `get_dex_group_app_perf`, and the `/fragments/dex/perf/{apps,app}` dashboard fragments), **and the fleet network-quality reads** (`GET /api/v1/network/{fleet,devices}`, the MCP tools `get_network_fleet` / `list_network_devices`, and the `/network` dashboard fragments) are **deliberately not per-read audited**: they carry no behavioral history, no event detail, no `detail_json`, no `agent_id` — only device-state / app-aggregate telemetry (CPU/commit/disk levels; per-app CPU/working-set by version; device-aggregate RTT/retransmit/throughput link health) and operator tag values, which are not individually-identifying behavioral data. **The app-perf aggregates additionally apply a cohort floor on read** (`kDexCohortFloor`, 10 devices) to **both** the fleet (`/perf/app`) and group (`/perf/group`) surfaces: any `(version, day)` point covering fewer than 10 devices is suppressed to a count only, so a niche app run by a handful of devices cannot expose a single operator's exact CPU/memory (singling-out) even without an `agent_id`. The audited per-app *individual* path remains the per-device drill `dex.device.app_perf.view` (above). The audited boundary is unchanged: the individual device *behavioral* view (`dex.device.view`), the machine-health *device query* (`dex.device.perf.query`), and the usage-class per-application panel (`dex.device.procperf.query` — whose result polls require the audited dispatch's `command_id`, so no usage-class read escapes the count). **Compensating control:** un-audited REST reads on these machine-health surfaces are covered at the web-server access-log layer (request path, principal, status, timestamp); the MCP path additionally emits the generic `mcp.<tool>` audit event per invocation. **Accepted residual risk:** a principal holding `GuaranteedState:Read` can enumerate fleet topology and cohort (e.g. location) membership without a per-read SIEM trail — accepted for the machine-health class because `GuaranteedState:Read` is an access-reviewed role and the compensating controls above apply; this is not new (it predates N1 for DEX-perf and the `/network` fragments). This paragraph is the citable policy line for CC7.2 evidence reviews.
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
- Forward pointer: the MCP surface gains a session concept (in-memory only, principal-bound ≥128-bit ids, TTL/caps, revocation cuts live streams) via ADR-1005 execution-plan Decision 15 / track 2f — fold its security pre-commitments into the questionnaire/whitepaper once 2f ships.

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
