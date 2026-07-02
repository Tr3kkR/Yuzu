# Capability & Industry Best-in-Class Review

**Version:** 1.0 | **Date:** 2026-07-02 | **Status:** Draft

## What this document is

A review of `docs/capability-map.md` (v3.0, 2026-03-30) against the mid-2026 industry landscape — commercial UEM/endpoint-management platforms, DEX vendors, security/DFIR platforms with endpoint-management overlap, and open-source projects — plus a maturity and viability assessment of the overall Yuzu vision and ranked recommendations.

It extends two predecessor documents rather than replacing them:

- `docs/enterprise-parity-plan.md` (2026-03-30) — single-peer parity analysis and the Phase 8–16 plan. Still the execution reference for those phases; its market framing is superseded by Part 3 here.
- `docs/capability-agentic-audit-2026-05.md` (2026-05-01) — the feature-presence vs production-quality honesty framework and the A1–A4 agentic invariants. This review re-verifies its top findings two months on (see §2.4).

Conventions: this committed edition **anonymizes competitors** per the `enterprise-parity-plan.md` convention and omits external source URLs; the named, fully-cited edition is maintained locally (deliberately untracked, commercially sensitive — ask the operator). All external claims were researched live on 2026-07-02 across four parallel workstreams (commercial UEM, DEX, security/DFIR, open source). Internal claims carry file/commit citations. This review makes recommendations only; it implements nothing.

---

## 1. Executive Summary

**The capability map is unusable as a strategy document in its current state.** It is stale in both directions: 619 commits landed since its date, shipping whole domains it doesn't mention (DEX, network quality, device pages, inventory daily-sync, `/auto`, internal PKI, the Postgres substrate) and completing items it marks not-started (Guardian guards, TOTP/MFA, TAR dashboard), while items it marks Done carry material caveats (policy evaluation was dead code until June; list-read RBAC confinement is one-chokepoint-deep; scale is proven at 10K, not the 100K+ the tier language implies). The headline "75% done" should not be quoted anywhere. Part 2 is the full corrections ledger.

**Maturity verdict:** the core control loop, security architecture, and engineering process are genuinely strong — unusually so for the project's age. What is missing is not features but *enterprise floor*: connectors (0%), HA (none), SCIM (none), attestations (in progress), scale proof (10K), and — least visible internally, most visible to buyers — **content** (66 definitions vs a patch-content veteran's 500K+ pre-built remediation units, no third-party patch catalog, no CIS/NIST packs riding Guardian). Meanwhile the planning corpus conceals a real strategic pivot: roadmap Phases 9–14 (the 2026-03 parity plan) sit at 0% while all 619 commits went to differentiators. The pivot was probably right; it has never been written down.

**Viability verdict: viable, validated, and time-boxed.** Live industry research confirms three Yuzu mechanisms have **no shipping equivalent anywhere**: Guardian's kernel-event-latency offline enforcement of operator-defined state; TAR's persistent on-device queryable event warehouse; and an embedded, RBAC/audit-governed, full-platform MCP surface. Two more are near-unique (`/auto`'s cohort-paired deploy evidence; the k-anonymity cohort floor for behavioral PII). But the 2026-03 claim "no commercial peer has an MCP equivalent" is **dead** — a major ITSM platform and a major automation platform ship GA MCP servers, three endpoint vendors ship experimental first-party ones, and the real-time category leader GA'd its proprietary agentic platform in June 2026. What remains true, verified: *no commercial vendor ships a GA, first-party, full-platform MCP server that can query + command + enforce in endpoint management* — the exact slot Yuzu occupies architecturally, with a write surface that has been one-tool-deep for two months while the window closes. Estimated window: 12–24 months.

**Top recommendations** (full list and sequencing in Part 6): re-baseline the map and write the pivot down (R1); finish the MCP write surface and claim "first GA governed full-platform MCP" while it is still claimable (R2); break the island with an ITSM/CMDB integration (R3); turn Guardian into a scoreable compliance product by shipping CIS/NIST content on the unique mechanism (R4). The through-line: the differentiator lead is already validated — the next two quarters should make the platform *purchasable*.

---

## 2. Corrections Ledger — the capability map vs reality

> **Re-baseline applied 2026-07-02:** capability-map.md v4.0 now incorporates this ledger (statuses corrected, domains 32–38 added, summary tables generated from entry statuses). This Part documents the pre-baseline state as found.

The capability map is dated 2026-03-30. **619 first-parent commits** have landed on `dev` since (2026-07-02), and the current release train is **v0.13.0-rc6**. The map is stale in both directions: it *understates* shipped capability (whole domains missing) and *overstates* maturity (items marked Done that carry known hardening gaps). The headline "172/228 done (75%)" should not be quoted in any external material until re-baselined.

### 2.1 Understated — mapped as Not Started / Partial but shipped

| Map entry | Map status | Actual state (2026-07-02) | Evidence |
|---|---|---|---|
| §31.2 Event Guards (Windows) | ❌ Not implemented | Registry guard (`guard_registry`), file guard (`guard_file`), and service guard (`guard_service`, SCM `NotifyServiceStatusChange`) are live, with enforce mode gated by the single `dangerous_enforce_in_spec` chokepoint | `agents/core/src/guard_registry.cpp`, `guard_file.cpp`, `guard_service.cpp`; CLAUDE.md "Guard types & the enforce-safety gate" |
| §31.3 Condition Guards | ❌ Not implemented | Service run-state guard shipped cross-platform via `make_service_guard()` factory | `guard_systemd.hpp` factory |
| §31.4 Event Guards (Linux) | ❌/T3 | `SystemdServiceGuard` shipped (sd-bus `ActiveState` watch, observe-only in v1) | `agents/core/src/guard_systemd.{hpp,cpp}`; merge `83005562` |
| §31.6 State Evaluator & Remediation | ❌ | Enforce-mode remediation live for registry/file/service with the dangerous-enforce denylist; Baseline deploy model (`deployed_snapshot`, Push-gated) governs what reaches agents | `server/core/src/baseline_store.{hpp,cpp}`; `guardian_rule_spec.cpp` |
| §31.9 Dashboard & Approval Workflow | ❌ | Guardian dashboard + Baseline draft/deployed lifecycle shipped; enforcement set changes gated behind `Push` (re-deploy rewrites snapshot) | `guardian_page_ui.cpp`; `docs/guardian-baseline-model.md` |
| §31.7 Audit Journal | 🔶 Partial | Agent-side journal + `guardian_ingest` shipped; the entire DEX observation layer rides on this ingest path | `guardian_ingest`; `docs/dex-signal-catalog.md` |
| §28.4 TAR Dashboard Page | 🔶 In progress | Shipped: retention frame + typed-confirmation source purge (15.A), SQL frame (15.D), process-tree viewer (15.H), capture-sources toggle frame, device DNS-cache/ARP panels, Chrome-IR end-to-end (15.F) | merges `3954acaf` (#1781), `26900eb6` (#1551), `ce2d401e` (#1773), `fea192d9` (#1575) |
| §28.3 Response Offloading | ❌ Not implemented | **Internal contradiction** — the same feature is marked ✅ Done at §20.7 (shipped: `OffloadTargetStore`, typed auth, batching) | `capability-map.md` §20.7 vs §28.3 |
| §28.7 Fleet Topology 3D Viz | 🔶 In progress | PR ladder 1–7 merged to dev 2026-05-15 (`cb2dfa1`); remaining rungs tracked as issues #1018–#1021 | PR #1032 |
| §18.10 Two-Factor Authentication | ❌ Not implemented | TOTP shipped (`totp.hpp`, enrollment in Settings) plus session **MFA step-up** for high-risk handlers (SOC 2 CC6.6 ladder PR1/PR2) | `server/core/src/totp.hpp`, `mfa_step_up.{hpp,cpp}` |
| §1.1 Gap: "Tier 3 server-side certificate validation not implemented" | Gap note | Superseded by the full internal-PKI ladder: built-in CA, per-agent mTLS (CSR at enrollment → server-signed leaf), revocation + CRL, CA REST + dashboard, subordinate-CA import, TLS-by-default images | `docs/pki-architecture.md`; merges `15894892` (#1314), `5fd44332` (#1332) |
| §15.2 Gap: "No advanced query language" | Gap note | `inventory_eval` shipped (map §15.4 already says so — another internal inconsistency); plus the ADR-0016 daily-sync tier gives normalized, typed, queryable software + device-CI inventory | `docs/adr/0016-agent-daily-sync-framework.md`; merges `8854ab56`, `e571b157`, `18033a3d` |
| §24.8 MCP Server | ✅ 22 tools | ~59 tools registered today (DEX perf twins, TAR, inventory, executions); `execute_instruction` is a tracked-execution producer (#1088) | `server/core/src/mcp_server.cpp` (59 `kTools` entries) |
| §26/§27 Inventory Repositories / Software Catalog | ❌ 0/9 items | Partially real via a different route than the parity plan envisioned: server-recomputed canonical software inventory (`SoftwareInventoryStore`), fleet catalogue rollup (`software_catalog_rollup`), device-CI store, `/inventory` dashboard, `Inventory` RBAC securable. Multi-*source* consolidation (connector-fed) remains absent | merge `18033a3d` (#1759); `software_catalog_rollup.*` |
| §22.9 Database Sharding | ❌ | Strategy superseded: the server storage substrate is now PostgreSQL (ADR-0006/0008/0012); scale-out is a Postgres story, not SQLite partitioning | merges `7add7a70` (F3 flip), `5564adc2` (SecretCodec) |

### 2.2 Missing domains — shipped capability with no map entry at all

These are not gaps in delivery; they are gaps in the map. Together they represent roughly a quarter of the platform's current surface:

1. **DEX (Digital Employee Experience)** — the largest unmapped area. 110-signal ruleless observation catalogue (`dex_signal_catalog.*`) with edge privacy filtering and per-type rate caps; Windows poll-and-latch + Linux collector batches; sustained perf-breach hysteresis; fleet **blast-radius incident detection** with webhook alerting and per-signal operator routing; continuous device/app performance telemetry (`$Perf_*`, `$ProcPerf_*`); **app-performance-over-time** (per-device daily → fleet aggregates with version-stratified frozen-bucket histograms, 180d); cohort-paired **before/after upgrade evidence** (`/auto` Verify); works-council-conscious cohort floors (`kDexCohortFloor`) and audit-on-open. Merges: `1121a99d` (#1707), `3c8c9ce2` (#1727), `50c18e0e` (#1463), `3e3d71c1` (#1760). Docs: `docs/dex-signal-catalog.md`, `docs/user-manual/dex.md`.
2. **Network quality (`/network`)** — measurement-first device/link health: interval retransmit rate, RTT, throughput; netlink `INET_DIAG` on Linux, `GetIfTable2`/`GetTcpStatisticsEx` on Windows; per-OS fleet gauges. Merges: `44970337` (#1441), `6ef2ddda` (#1473). Doc: `docs/user-manual/network.md`.
3. **Device pages + live snapshot** — shared `/devices` + `/device` entity surface with Device info / DEX / Guardian lenses and "Get live info" (dispatch-and-poll card grid incl. process tree with live-connection join by PID). Merges: `f59e4b20` (#1522), `da45e267` (#1585), `a7026d79` (#1549). Doc: `docs/user-manual/device-management.md`.
4. **Agent daily-sync inventory framework (ADR-0016)** — phase-spread, hash-skip daily push of per-source endpoint state; sources: installed software, app-perf, device CI (hardware/OS identity). The platform's answer to inventory freshness at fleet scale.
5. **`/auto` operator automation surface** — Pre-flight readiness (cohort go/no-go grid, background runner), **Deploy** (stage+execute on the go-cohort with three-layer execute-once CAS guarantees), **Verify** (cohort-paired app-perf comparison). Merges: `aceae7df` (#1720), `3e3d71c1` (#1760). Doc: `docs/user-manual/preflight.md`.
6. **Internal PKI / CA** — see §2.1 (§1.1 row); a full certificate-authority subsystem is a capability domain in its own right (root + subordinate modes, per-agent identity, CRL, revocation).
7. **PostgreSQL server substrate** — ADR-0006/0008/0010/0012 program: pooled libpq substrate, fail-closed boot, envelope-encrypted secrets at rest (`SecretCodec`, KEK/DEK), migration ladder for ~28 stores. An architecture-tier capability the map's SQLite-era §22 does not describe.
8. **Executions-history ladder + agentic SSE** — `command_id → execution_id` correlation, `/api/v1/events` JSON SSE (the first surface satisfying agentic invariants A3+A4), executions drawer. Doc: `docs/executions-history-ladder.md`.
9. **Behavioral-PII access-audit framework** — the `rest_audit.hpp` chokepoint (#1647): fail-closed 503 on REST PII routes when the audit row cannot persist, `Sec-Audit-Failed` signalling, per-kind audit verbs. A works-council/GDPR compliance differentiator with no map representation.
10. **Agent privilege model** — dedicated service accounts (`_yuzu`/`yuzu`/`NT SERVICE\YuzuAgent`), narrow sudoers/LSA privilege matrices, install scripts. Doc: `docs/agent-privilege-model.md`.
11. **TAR forensic warehouse expansion** — gap-free process streaming (Windows ETW `3bb81fc7`, macOS Endpoint Security `bcaf8603`), module loads (`6034e48b`, `bcb4fc59`), software install/uninstall events (`1f1aac04`), ARP/DNS sources (ADR-0015), per-connection network-quality tier. The map's §28 frames TAR as "response visualization"; it is now a forensics/inventory domain.
12. **Deployment experience** — compose wizard with PKI defaults + Postgres provisioning (`80b07e80`, `b4a62f40`), TLS-by-default images, chiselled (distroless) containers, release verification. Enterprise-readiness surface absent from the map.

### 2.3 Overstated — marked Done but carrying material caveats

| Map entry | Caveat |
|---|---|
| §16.2 Policy Evaluation and Enforcement (✅) | The check→verdict→status path was **dead code** until the `PolicyEvaluator` background thread was wired (2026-06); authored policies did not actually evaluate on cadence before that. Now real, but the map marked it Done throughout. |
| §18.3/§18.4 Granular RBAC + group-scoped roles (✅) | Management-group confinement of **list/fan-out reads** is not yet effective platform-wide; ADR-0017's admit-then-filter gate exists at one chokepoint (World A) and every new list route must adopt it. Response reads are flat `Response:Read` (systemic gap, ruling 2026-06-23, #1634). |
| §22.5 Gateway / Scale-Out (✅) | Tested to 10K+ agents in CT suites; no 100K-class production evidence. The single-server fan-out and Postgres pool are the current ceiling factors. |
| §22.10 High Availability (❌ — correctly) | Still absent, but now *reachable*: the Postgres substrate makes standard HA (managed PG, replicas) possible; no failover orchestration exists. |
| §9.4 Vulnerability Scanning (✅ T1) | Plugin + NVD sync are real; the matcher is first-generation. The modern-engine redesign exists as a hardened spike + design doc (PR #1206, `docs/vuln-scan-engine-design.md`) and is not merged. CPE-matching quality is below commercial VM products. |
| Foundation/Advanced "100%" | Per the map's own caveat and the 2026-05 audit: feature-presence, not hardening. Known §-level gaps (configurable heartbeat, diagnostics bundle, runtime plugin install) remain. |
| Platform skew | Windows depth ≫ Linux ≫ macOS. Registry/file guards are Windows-only (no-op elsewhere); macOS event guards gated on the Endpoint Security entitlement; FileVault/LUKS status absent (§9.3 gap stands); Windows DEX poll richer than Linux; macOS thinnest overall. `docs/os-capability-matrix.md` is the honest per-OS snapshot. |

### 2.4 The 2026-05 audit's top gaps — two months on

| Audit finding (2026-05-01) | State 2026-07-02 |
|---|---|
| MCP write surface is one tool (5 write tools security-mapped, undispatched) | **Unchanged** — `mcp_server.cpp` still says "Security-mapped but no dispatch yet (Issue 13.5)". The read surface grew to ~59 tools; the write gap persists. |
| Dashboard fragments HTML-only, no JSON negotiation (A1) | Largely unchanged; new REST siblings shipped for device/DEX surfaces (#1549 agentic REST), but `/fragments/*` content negotiation has not landed broadly. |
| No discovery surface beyond `tools/list` + OpenAPI (A2) | Unchanged — Phase 17.1 introspection endpoints not started. |
| Connector Framework 0% (deal-blocking) | **Unchanged** — zero connector code. The `guardian-servicenow-compliance` PRs (#1600/#1623) are Guardian compliance-evidence REST endpoints for external pull, not a connector. |
| Software Catalog & License Compliance 0% | Partially moved via ADR-0016 (canonical software inventory + catalogue rollup); entitlements/licensing still absent. |

---

## 3. Domain-by-Domain Industry Benchmark

Rather than walking all 31 map domains individually, this part groups them into capability clusters and rates Yuzu against the **best-in-class commercial bar** and the **best-in-class open-source bar** per cluster: `AHEAD` / `PARITY` / `BEHIND` / `ABSENT`. All external claims researched live 2026-07-02; vendors anonymized in this edition (full citations in the local named edition).

### 3.1 Real-time fleet query & orchestration (map §2, §19, §20)

**Commercial bar: the real-time category leader.** Peer-to-peer linear-chain relay; vendor-claimed query-and-return from 500K endpoints in <15 seconds (a verified public-sector test: <15s simple / <60s complex across ~150K endpoints); architecture published in a peer-reviewed database-conference paper. Comparators are materially slower: the patch-content veteran's live query polls at 300s default; the dominant OS vendor's multi-device query runs against *already-harvested* inventory (≤48h latency). **OSS bar: the leading open-core device-management project** (osquery-based) — sub-30-second live queries fleet-wide.

**Yuzu: PARITY (architecture) / BEHIND (proof).** Persistent gRPC streams put dispatch-and-stream latency in the seconds class, with scope targeting, staggering, approvals, and result aggregation that match or exceed the OSS bar. But the largest tested fleet is 10K (gateway CT suites) and there is no published latency-at-scale benchmark. Against the category leader the honest claim is "same interaction class, unproven at their scale."

### 3.2 Patch, software distribution & the content ecosystem (map §7, §8, §13)

**Commercial bar:** the OS vendor's **hotpatching** — quarterly baseline reboot + no-reboot security updates = 4 mandatory reboots/year, default-on for eligible enterprise Win11; a cloud-patch vendor's 630+-app third-party catalog, P2P distribution, and 200-endpoints-free tier; a breadth-focused UEM suite's 850–1,100-app catalog; the patch-content veteran's **500,000+ pre-built remediation units** across ~100 OSes; AI-driven patch-risk scoring (community-sentiment analysis of updates pre-rollout) at a leading RMM. **OSS bar:** a German-public-sector Windows-deployment workhorse; Chocolatey-based deployment in the source-available RMM; the open-core leader paywalls patching.

**Yuzu: PARITY (machinery) / ABSENT (content).** `PatchManager` orchestration, deployment CAS guarantees, `/auto` rings-with-evidence are structurally competitive — the category leader's deployment rings with entry/exit criteria are the closest commercial analog to `/auto`, and Yuzu's verify stage is *more* evidence-driven. But the competition's moat is **content**: Yuzu ships 66 instruction definitions and zero third-party patch catalog. Every mature platform's value is the tested content library, refreshed continuously. This is the largest un-narrated gap in the platform.

### 3.3 Policy enforcement & guaranteed state (map §16, §31)

**Commercial bar:** the category leader's enforcement product (CIS benchmark import, DISA STIG, drift enforcement) + a UEM vendor's "Continuous Compliance" (April 2026 — patch drift auto-remediated outside maintenance windows); Apple's **declarative device management** (devices autonomously apply and report state; Apple removes legacy MDM update commands in OS 27, making declarative the platform-native model — the Apple-management leader's blueprint model is the exemplar); the same vendor's compliance-benchmarks product (NIST macOS Security Compliance Project built in: benchmark → enforcement → audit-ready evidence). **Security-side bar:** detection at kernel-event speed is table stakes (OSS SIEM FIM via inotify/ReadDirectoryChangesW, osquery evented tables, OSS DFIR ETW/eBPF) — but *enforcement* is cloud-round-trip rules or poll-and-converge everywhere.

**Yuzu: AHEAD (mechanism — validated unique) / BEHIND (coverage + content).** The research conclusion is unambiguous: *"kernel-event-latency enforcement of arbitrary operator-defined registry/file/service state — resident on the agent, working offline/pre-login — has no direct equivalent among the products surveyed."* Guardian's design point is real differentiation, not marketing. The caveats: Windows event-guard coverage is 3 of 4 designed APIs, Linux is observe-only, macOS absent; and there is **no compliance content** riding the mechanism (no CIS/NIST packs), while three major vendors sell benchmark-to-evidence pipelines. A unique engine with no content library is a demo, not a product. Note also a **naming collision**: the real-time category leader now ships a product also named "Guardian" (a zero-day advisory service).

### 3.4 Inventory, connectors & the enterprise fabric (map §15, §25–§27)

**Commercial bar:** connector ecosystems — ServiceNow service-graph connectors, a UEM vendor's 1,000+-connector iPaaS, and (May 2026) a jointly-sold autonomous-IT bundle between the category leader and ServiceNow. The RFP bar has moved from data sync to **embedding actions in agentic ITSM workflows** (vendor AI agents running inside ServiceNow's agentic framework; remote actions embedded in the incident view). **OSS bar:** GitOps + webhook/API surfaces.

**Yuzu: ABSENT.** Zero connector code. ADR-0016 daily-sync gives excellent *first-party* inventory (normalized software, device CI, catalogue rollup — arguably better-engineered than most agent-sourced inventory), and Guardian compliance-evidence REST endpoints (#1600/#1623) give external systems a pull surface. But there is no ITSM/CMDB/patch-source sync in either direction. Three internal documents across 15 months (parity plan, audit, this review) have now called this the #1 enterprise gap; the external research confirms ServiceNow integration is the RFP constant. An endpoint platform that cannot feed the CMDB is an island.

### 3.5 Forensics, DFIR & historical telemetry (map §28.4–.5, TAR)

**Commercial bar:** the leading EDR — cloud telemetry graph searchable to 90 days (tier-priced), interactive remote response for hands-on-keyboard work, containment that survives reboots and severed cloud links; a second major EDR's on-agent event correlation into attack stories + VSS rollback; a SecOps-cloud startup's flat **1-year full telemetry retention included at every tier**. **OSS bar: the leading OSS DFIR platform** — declarative-query hunts across 10K clients per modest server, raw-artifact forensic reach (MFT/USN/prefetch), eBPF/ETW eventing, offline collector.

**Yuzu: AHEAD (model — validated unique) / BEHIND (hunt UX + artifact library).** Research conclusion: *"a persistent queryable on-device event warehouse — retention bounded by local disk, zero-egress until queried, intact for offline endpoints — is not the shipping model of any product surveyed."* The market splits between cloud lakes (retention as the pricing lever) and query-on-demand of OS residue (the OSS DFIR tool's client buffer is a transmit queue, not a warehouse; osquery's event store expires by design). TAR is a genuine fourth model with a distinct economic story (zero egress until asked, no per-GB retention tax, offline-intact). What Yuzu lacks against the OSS DFIR bar: a hunt/artifact library (its artifact corpus is the accumulated DFIR community knowledge), fleet-wide hunt orchestration UX, and raw-artifact reach beyond the captured event stream.

### 3.6 Security posture & vulnerability management (map §9)

**Commercial bar:** risk-based prioritization is the standard — exploit-activity + CISA-KEV + asset-criticality scoring with 100+ intelligence feeds; AI-driven VM with patch-confidence scoring; universal scanner-import paths. **OSS bar:** the OSS SIEM (agent inventory × CVE content) and the open-core leader's premium tier (EPSS/CVSS/CISA KEV).

**Yuzu: BEHIND.** `vuln_scan` + NVD sync is a first-generation matcher (the modern-engine redesign is an unmerged spike, PR #1206); no EPSS/KEV/exploit-intelligence enrichment, no risk-scored remediation queue, no scanner-import path. The posture plugins (AV/firewall/encryption/IOC/quarantine) are competitive for *status collection*; the gap is the vulnerability lifecycle (audit P3 18.1 remains correct). Quarantine hardening note from research: the OSS DFIR platform's quarantine ships a connectivity self-test that rolls back isolation if the server is unreachable — a pattern worth adopting.

### 3.7 DEX — Digital Employee Experience (unmapped domain)

**Commercial bar.** The category is post-consolidation and AI-saturated in 2026 (Gartner's 2026 DEX MQ names four Leaders). The bars that matter:

- **Composite experience scoring is the de facto standard** — 0–100 daily score with per-dimension subscores; at the leading pure-play, **sentiment from in-product surveys is half the score**; an observability vendor's DEX product benchmarks scores against industry peers.
- **Remediation loops, not scores, are what enterprises buy** — the unambiguous 2025–26 market signal: one DEX vendor reports **14M automated fixes/week** and is renaming the category "Autonomous Endpoint Management"; another reports 250M automation steps in 2025; autonomous remediation was the rationale for the category's $720M acquisition.
- **Signal breadth beyond the endpoint**: collaboration-call quality subscores, synthetic availability probing, web/SaaS transaction timing, session replay at 1-second telemetry resolution, sentiment micro-surveys, and the new 2025–26 class: **AI-adoption/shadow-AI telemetry**, GPU/NPU utilization.
- **AI/agentic wave**: an employee-facing autonomous "personal IT agent" (Jan 2026); causal-inference reasoning over 15-second telemetry with **headless MCP + A2A integration** (the only named MCP surface among DEX vendors); remediation systems that learn from outcomes.
- **Commoditization pressure from below**: the dominant OS vendor folds its advanced endpoint analytics (anomaly detection incl. **paired before/after t-tests**, battery health, resource perf, device query) into its enterprise license bundle in 2026 — DEX-grade analytics becomes a default entitlement.

**Where Yuzu stands.**

| Aspect | Rating | Assessment |
|---|---|---|
| Endpoint signal collection (110-signal catalogue, perf/app-perf telemetry) | PARITY (breadth) / BEHIND (fusion) | The ruleless catalogue + hourly perf + per-app daily rollups are credible vs any vendor's *endpoint-local* telemetry. Missing signal classes best-in-class covers: sentiment/surveys, collaboration-call quality, synthetics, web/SaaS timing, network path. |
| Experience scoring | ABSENT | Yuzu deliberately has no composite score. Defensible for an ops-evidence product; indefensible if selling "DEX" — every buyer expects a score as the executive KPI. |
| Before/after upgrade evidence (`/auto` Verify) | **AHEAD** | The only close precedents: one vendor's manual analyst change-validation workflow and the OS vendor's paired t-tests (an automated anomaly detector). **Nobody ships a deploy-pipeline-integrated, cohort-paired evidence artifact** — Yuzu's assess→act→verify chain is genuinely novel. |
| Privacy engineering | **AHEAD (unique)** | **No vendor publicly documents a cohort-size aggregation floor (k-anonymity-style) as a product feature** — Yuzu's `kDexCohortFloor` + audit-on-open + edge privacy drops are a works-council story nobody else tells. The leading pure-play publishes the only comparable model (4 irreversible anonymization tiers, GDPR tooling) and it lacks the floor. |
| Automated remediation loop | BEHIND | Yuzu has all the primitives (signals → blast-radius alerts → instructions → Guardian) but no detect→diagnose→auto-fix loop product. The market has decided this is the product. |
| Fleet incident detection (blast radius) | PARITY-ish | N-distinct-device correlation + webhooks is a credible first take; the OS vendor's correlated-group detection (by app version/driver/build) is the richer bar. |

### 3.8 Agentic / AI-operator surface (map §24.8–.10)

This is the cluster the whole vision rides on, so the finding is stated carefully.

**The 2026-03 claim "MCP server — commercial peers have no equivalent" is dead.** The 12 months to mid-2026 saw MCP go mainstream across IT ops: a major ITSM platform's **MCP server is GA** in every AI SKU, governed by an AI control tower (identity-verified, permission-scoped, audited, metered — the governance reference bar); a major automation platform's **MCP server is GA** (read-only/read-write modes, RBAC-inherited); a SecOps-cloud startup ships a ~278-tool MCP server + hosted endpoint with auth inheriting the human permission model, agents-run-on-frontier-LLM workspaces, and "spawn an AI agent" as a detection response action — the closest architectural cousin to Yuzu's agentic-first thesis, in SecOps; the leading EDR's MCP server is in public preview with MCP framed as the substrate of its agentic-security strategy.

**Within endpoint management proper, the slot is still open — barely.** The UEM research verdict: *"as of 2026-07-02, no commercial vendor ships a GA, first-party, full-platform MCP server through which an external AI operator can query + command + enforce."* What exists: the Apple-management leader's ~50-tool labs-grade MCP hub (no releases cut); a cloud-patch vendor's experimental server (explicitly not production-grade); the open-core leader's experimental first-party server. The real-time category leader's answer is a **proprietary agentic platform — GA June 2026** — the strongest "AI operates the platform" story (ambient agents observe the fleet; the platform plans/executes multi-step workflows with human approval gates) but *not MCP*; the OS vendor's answer is metered in-console assistant agents; others are community-MCP-only or roadmap-stage.

**Yuzu: AHEAD (architecture) / BEHIND (its own bar).** Yuzu's MCP server is embedded in-product with tier-before-RBAC ordering, mandatory token expiry, kill switches, per-tool audit — precisely the "embedded + governed" combination the research identifies as rare (most shipping MCP servers are thin REST-wrapper sidecar processes). ~59 tools is a competitive read surface. But: the write surface is still effectively **one tool** (the five Issue-13.5 write tools remain undispatched two months after the audit flagged them), A2 discovery endpoints don't exist, and fragment parity (A1) is unimplemented. Yuzu is ahead of an industry that is closing fast, while standing still on the exact axis of its thesis.

**Adjacent new category (2026): governing AI/MCP *on* endpoints.** The Apple-management leader GA'd an AI-governance product (OS-level control of which MCP servers may run on a device); the open-core leader ships shadow-AI inventory tables; the category leader detects rogue MCP servers; the OS vendor manages MCP servers as endpoint objects in its agent registry. Every serious endpoint vendor now treats AI tooling on devices as inventory-and-control objects. Yuzu has the exact infrastructure (TAR, inventory sync, DEX signal catalogue) to enter this category cheaply — and does not.

### 3.9 Identity & enterprise access (map §18)

**The 2026 RFP floor** (triangulated across buyer guides + the inaugural Gartner Endpoint Management Tools MQ, Jan 2026): SSO (SAML/OIDC) + MFA + **SCIM auto-provisioning with same-day deprovisioning**; SOC 2 Type II + ISO 27001 up front (even SMB-tier vendors have both); FedRAMP as a public-sector line item; RBAC scoping + **multi-tenancy**; data residency / sovereign editions (two vendors launched EU sovereign editions in 2025–26).

**Yuzu: PARITY (mechanisms) / BEHIND (floor items).** OIDC/PKCE, Entra sync, TOTP + MFA step-up, API tokens, group-scoped RBAC are real. Missing floor items: SCIM (roadmapped in Workstream B, not started), service-account principals (audit 17.4), multi-tenancy (absent, and MSP/mid-market channels require it), formal SOC 2 Type II attestation (program exists, evidence pipeline in flight). Also note one UEM vendor's trust collapse (16 CISA-KEV entries since 2024; a ~12% drop in its claimed Fortune-100 count) — evidence that *secure-by-design posture is now a selection criterion*, which favors Yuzu's fail-closed engineering culture if it can be third-party-attested.

### 3.10 Scale, HA & deployment model (map §22)

**The market consolidated hard to SaaS-only** — the OS vendor's UEM is SaaS-only; a major UEM spin-out EOLs on-prem in April 2027; the RMM/cloud-patch cohort is 100% SaaS; the Apple-management leader is cloud-first. Remaining self-hostable enterprise options: the OS vendor's legacy on-prem suite, one breadth-focused UEM suite, and one CVE-burdened on-prem UEM. The research's phrase: **"on-prem/self-hosted capability is increasingly a differentiator by scarcity."** Scale bars: 175K/primary site (legacy on-prem suite); ~2M devices for a single customer (UEM spin-out); 35M endpoints platform-wide (category leader).

**Yuzu: AHEAD (self-host ergonomics) / BEHIND (HA + scale proof).** TLS-by-default images, compose wizard with Postgres + PKI provisioning, chiselled containers, and zero-external-dependency architecture make Yuzu's self-host experience *better* than the surviving on-prem incumbents — and the sovereignty/works-council/air-gap market that SaaS consolidation orphans is a real, underserved segment (especially European). But: no HA/failover story, 10K-proven scale, and most stores still mid-migration to the Postgres substrate that makes both fixable.

---

## 4. Maturity Assessment

The 2026-05 audit introduced the two-bar framing — **feature presence** vs **production quality** — and this review keeps it. On feature presence Yuzu is remarkably broad for its age; on production quality it is uneven in ways that matter differently for different buyers.

### 4.1 What is genuinely mature (hardened, tested, operationally proven)

- **The core control loop** — enroll → heartbeat → dispatch → stream responses → persist → query/aggregate — has soaked through UAT rigs, demo environments, a three-platform CI matrix, sanitizer/coverage nightlies, and a per-PR governance pipeline (8 gates, 13 reviewers) that has demonstrably caught CRITICAL vulnerabilities pre-merge. This loop is the platform's oldest surface and its most trustworthy.
- **Security architecture** is ahead of typical OSS-project maturity: internal CA with per-agent mTLS, TLS-by-default images, envelope-encrypted secrets at rest (ADR-0010), fail-closed postures as an explicit design vocabulary (store construction, audit-before-PII, boot probes), dedicated agent service accounts, behavioral-PII audit chokepoint, MFA step-up on privileged handlers. SOC 2 workstreams (A–G) are actively tracked and enforced at governance Gate 6.
- **Engineering process** — adversarial reviews, chaos injection, a durable test-runs DB, per-OS build discipline, an ADR culture (17+ ADRs) — is the strongest maturity signal. Process maturity of this kind is what lets the breadth keep compounding without collapsing.

### 4.2 What is functional but not yet enterprise-proven

- **Scale.** Gateway CT suites prove 10K+ agents; nothing proves 100K. The Postgres substrate (the right move for scale) flipped only weeks ago; most of the ~28 server stores are still SQLite awaiting migration up the ladder. Fleet-wide claims should be phrased as "designed for, tested to 10K."
- **HA/DR.** No failover story. Postgres makes managed-HA *possible*; nothing orchestrates it. A single-server control plane is acceptable for mid-market pilots, disqualifying for large-enterprise RFPs.
- **Authorization depth.** RBAC breadth is real, but management-group confinement of list/fan-out reads is effective at one chokepoint (ADR-0017) and response reads remain flat (#1634). For multi-team enterprises this is the difference between "has RBAC" and "can safely delegate."
- **Guardian.** The engine, wire protocol, baseline lifecycle, and three guard types are live — but Windows event-guard coverage is 3 of the 4 designed kernel APIs (WFP/ETW guards pending), Linux is observe-only, macOS is absent. The headline claim ("real-time guaranteed state") is *provable in demo, partial in coverage*.
- **Agentic surface.** The MCP read surface (~59 tools) is arguably the best in the industry (see Part 3), but the write surface is still effectively one tool; A1/A2 invariants (fragment JSON parity, introspection endpoints) remain unimplemented two months after the audit flagged them. The agentic-first thesis is ahead of the market in design and behind its own bar in completeness.

### 4.3 Platform skew

Windows is the deep platform (registry/file guards, ETW streaming, WMI, per-user hives, DEX poll breadth); Linux is competent but observe-only where it matters (Guardian enforce); macOS is the thin edge (ES entitlement-gated streaming, no FileVault status, no event guards). This mirrors where enterprise fleets are, so it is a defensible sequencing — but sales material must not imply parity. `docs/os-capability-matrix.md` is the honest per-OS record and should be generated from code metadata before it drifts (its own stated durable fix).

### 4.4 The strategic drift the map conceals

Roadmap Phases 9–14 — the 2026-03 parity plan's core (connectors, software catalog/licensing, consumer model, remaining agent caps, 2FA*, scale features) — sit at **0%** while ~619 commits shipped elsewhere (DEX, TAR, PKI, Postgres, `/auto`, inventory sync, device pages). (*2FA in fact shipped, unrecorded — §2.1.) This was not drift by accident; it was a real strategic pivot from **parity** ("match the commercial peer feature-for-feature") to **differentiation** (agentic-first + DEX + edge forensics + real-time enforcement). The pivot is defensible — Part 5 argues it is correct — but no strategy document records it, so the capability map, parity plan, and actual investment now describe three different products. That inconsistency, not any individual gap, is the biggest maturity defect of the *planning corpus*.

---

## 5. Vision Viability

**Verdict: the vision is viable, sharper than it was in March — and now time-boxed.**

### 5.1 Three mechanisms survived adversarial market comparison as genuinely unique

1. **Guardian's enforcement model** — operator-defined desired state enforced at kernel-event latency, agent-resident, offline/pre-login. No surveyed product (EDR, SIEM, config management, UEM) ships this; the market substitutes cloud-round-trip response rules or poll-and-converge.
2. **TAR's on-device queryable warehouse** — a fourth telemetry model the market doesn't offer, with a distinct economic story against cloud-lake retention pricing (90-day tiers and 14-day defaults are the norm; the one 1-year-flat outlier proves retention is the industry's pricing lever).
3. **The embedded, governed, full-platform MCP surface** — the exact slot the UEM research found open ("no commercial vendor ships a GA, first-party, full-platform MCP server that can query + command + enforce"), with Yuzu's tier/kill-switch/audit governance matching the ITSM-platform-defined governance bar rather than the thin-wrapper pattern.

Two more are near-unique: `/auto`'s cohort-paired before/after deploy evidence (only one vendor's manual workflow and the OS vendor's anomaly t-tests come close) and the works-council privacy engineering (no vendor documents a k-anonymity cohort floor).

### 5.2 The agentic-first thesis is being validated by the market — which is the threat

Everything the thesis predicted is happening: the category leader rebuilt its story around a proprietary agentic platform ("ambient agents observe the fleet"); a DEX vendor renamed its category to Autonomous Endpoint Management; a SecOps startup built "agents operate, not advise" with approval scoping; Gartner made "Autonomous Endpoint Management" a scored use case in the inaugural Endpoint Management MQ. Yuzu was architecturally early. But incumbents are executing the *proprietary* version of the thesis with data moats (recommendation confidence scores computed from cross-customer change telemetry Yuzu will never have) — Yuzu's defensible variant is the **open** one: any LLM, any framework, self-hosted, governed, inspectable. That is exactly the unoccupied ground the OSS research named: *"a fully-open (non-paywalled) platform combining real-time enforcement, patch/deploy, and an embedded, RBAC/audit-native MCP operator surface across Windows/Linux/macOS."* The only OSS project converging on the same surface — now heavily funded, with weekly releases — paywalls enforcement and deployment; its MCP is experimental. The window in which "first GA, governed, full-platform MCP endpoint management" is claimable is plausibly 12–24 months.

### 5.3 Structural risks, ranked

1. **The island problem.** Zero connectors, while the RFP bar moved past data-sync to agentic-ITSM embedding. Internally flagged three times over 15 months; still 0%. This is the single largest threat to enterprise viability — every other gap can be sequenced, this one blocks deals by itself.
2. **The content desert.** The patch-content veteran ships 500K+ remediation units; suites ship 1,100 patchable apps; the Apple-management leader ships NIST benchmarks as product; a patch vendor ships 432 vetted automation units. Yuzu ships 66 definitions and no third-party patch catalog, no CIS/NIST packs. Mechanisms without content libraries demo well and deploy poorly. This is also the moat *hardest for a small team to build* — it is continuous editorial work, not engineering — and the strongest argument for community/ecosystem strategy.
3. **Scale and HA proof.** "Designed for 100K, proven at 10K, no failover" is disqualifying above mid-market. The Postgres substrate makes both addressable; neither is addressed.
4. **Sustainability shape.** The OSS research's failure patterns — single-maintainer heroics, corporate-steward squeeze (two config-management communities forked or fled in 2025) — and success pattern (clean stable license boundary, paywall enforcement-adjacent features, ride a commodity upstream, relentless cadence) both read as warnings for a project with Yuzu's bus factor. The engineering-process maturity (§4.1) partially compensates; a stated license/monetization boundary does not yet exist.
5. **Convergence squeeze.** EDR is eating IT-ops content from above (the leading EDR sells IT-ops on the security sensor: "no separate endpoint-management agent"); enterprise-license bundling is commoditizing analytics from below (the OS vendor folds its UEM suite into E3/E5 in July 2026). The defensible position is precisely the parts of Yuzu the giants structurally can't copy: self-hosted/sovereign, open, works-council-conscious, model-agnostic agentic.
6. **Platform skew vs platform trend.** Apple is forcing declarative device management (legacy MDM update commands removed in OS 27, fall 2026); Yuzu's macOS story is its thinnest and has no MDM/DDM plane at all. Acceptable for Windows-fleet beachheads; a ceiling on "full capability set" claims.

### 5.4 Bottom line

Yuzu at v0.13.0-rc is a credible platform for **mid-market Windows-weighted fleets (≤10K endpoints) that want self-hosted, sovereign, AI-operable endpoint management** — a real and underserved segment the SaaS consolidation is actively orphaning. It is not yet credible for large-enterprise RFPs (connectors, HA, SCIM, attestations, content). The differentiators are real, validated, and — unusually for a project this age — mostly *shipped rather than promised*. The strategy risk is not the vision; it is sequencing: every quarter spent deepening differentiators while the connector/content/HA floor stays unbuilt narrows the window in which the differentiators are unique.

---

## 6. Recommendations

Ranked. Effort: S (≤1 sprint), M (2–4 sprints), L (quarter+).

**R1 (S) — Re-baseline the capability map and record the pivot.** Mechanical: re-tally against §2 of this review; fix the §28.3/§20.7 contradiction; add domains for DEX, network quality, device pages, inventory sync, `/auto`, PKI, Postgres substrate; correct §31/§18.10/§28. Strategic: write the one-page note that says out loud what §4.4 documents — the project pivoted from parity to differentiation — so map, parity plan, and investment stop describing three different products. Adopt the `os-capability-matrix` durable fix (generate status from machine-readable sources) so the map stops rotting between manual audits.

**R2 (S–M) — Finish the agentic write surface before the window closes.** Issue 13.5 (five undispatched MCP write tools) + A2 discovery endpoints + A4 error-envelope completion. This is the cheapest high-leverage work in the backlog: it converts "ahead of the industry in architecture" into the claimable first — **the first GA-quality, first-party, governed, full-platform MCP server in endpoint management**. Every month of delay, another vendor graduates an experimental server. Pair with a benchmarkable demo (an LLM operator executing a full assess→act→verify loop through MCP) — nobody else can run that demo today.

**R3 (L) — Break the island: ServiceNow first.** One bidirectional connector (CMDB service-graph-style publish + incident-context pull), designed so the *mechanism* (connector registry, sync engine, credential store per parity-plan Phase 9.1) generalizes. Rationale: ServiceNow integration is the RFP constant; Guardian's compliance-evidence endpoints (#1600/#1623) already gesture at this demand. Consider the agentic twist: Yuzu's MCP surface inside ServiceNow's agentic framework may be a cheaper, more differentiated first integration than classic CMDB sync — evaluate both before committing.

**R4 (M–L) — Turn Guardian into a compliance product with content.** (a) Complete the Windows guard set (WFP + ETW guards, PRs 3–17 ladder) and Linux enforce; (b) ship **CIS/NIST benchmark packs** as signed ProductPacks riding Guardian + the policy engine, with audit-evidence export — the "benchmark → enforcement → evidence" pipeline is the exemplar pattern and nothing in the Windows/Linux cross-platform space does it with kernel-latency enforcement. This converts the validated-unique mechanism into something an RFP can score, and it feeds the SOC 2 story. Also: check the "Guardian" name against the category leader's same-named product before external marketing hardens.

**R5 (M) — Publish a scale proof-point.** A reproducible 50–100K-agent benchmark (gateway fan-out + Postgres substrate; synthetic agents are fine and are how vendors do it) with the honest methodology published. Without it, §3.1's "same interaction class as the category leader" is unfalsifiable; with it, Yuzu is the only platform in its class publishing reproducible numbers. Sequence after the Postgres migration ladder reaches the hot-path stores.

**R6 (S) — Enter the endpoint-AI-governance category.** MCP-server/AI-tool inventory as a daily-sync source (ADR-0016 pattern; the open-core leader's shadow-AI tables are the reference), shadow-AI signals in the DEX catalogue (two DEX vendors validated the class in 2025–26), optional Guardian rule for unapproved MCP servers. Small work, ready-made infrastructure, and it makes Yuzu simultaneously an *operator* of AI and a *governor* of AI — a narrative no incumbent currently combines.

**R7 (S–M) — Close the DEX table-stakes gaps deliberately.** (a) Ship the survey/sentiment primitive (map §14.4–.6 — the `interaction` plugin is 80% of the way there); sentiment is half the score at the leading DEX pure-play and Yuzu cannot credibly wear the DEX label without it. (b) Decide *explicitly* whether to build a composite experience score or position "evidence, not scores" as the differentiator — either is defensible; drifting into the category without deciding is not.

**R8 (M) — Enterprise identity floor.** SCIM provisioning + service-account principals (audit 17.4) + document the multi-tenancy position (even if the answer is "single-tenant by design, here's the MSP deployment pattern"). These are pass/fail RFP rows, not features.

**R9 (S) — Positioning hygiene.** Rewrite the differentiation claims this review corrects: "MCP — no equivalent" → "the only *embedded, governed, full-platform* MCP surface, and first to GA" (once R2 lands); lead with self-hosted/sovereign/works-council positioning (the market vacated it — on-prem EOLs and sovereign editions validate the demand, and one vendor's CVE record is the cautionary tale Yuzu's fail-closed culture answers); state the license/monetization boundary publicly before adoption makes any later change look like the rug-pulls the OSS community punishes.

### Suggested sequencing

R1, R2, R9 immediately (they are cheap and time-sensitive); R3 and R4 as the next two quarters' major workstreams (they attack the two structural risks that block enterprise deals); R5–R8 slotted opportunistically behind them. The through-line: **stop widening the differentiator lead — it is already validated — and spend the next two quarters making the platform purchasable.**
