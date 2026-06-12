# DEX BRD Coverage Map — Aternity-Replacement Requirements vs. Yuzu

**Source:** `Business Requirements Document_IO_EUO_Aternity_Replacement_v1.0` (Main tab,
rows 5–152, 23 category blocks). The `Scenarios` tab was not captured — re-assess this
map when it is.
**Scope decision (2026-06-12):** Windows first. macOS keeps riding along where the
existing collector already covers a row; Linux follows the catalogue pattern later.
**Status:** living document — update verdicts as workstream slices land. Issue/PR
references go in the Plan column as work starts.

**Decision log (2026-06-12 grilling session):**
- Driver is a live opportunity: build **real capability breadth first**, PoC
  second; a written RFP response is NOT a deliverable.
- **User-facing interaction is out for now**: D2 (reboot nudge) dropped, F4
  (survey campaigns / sentiment) deferred with it. Passive observation (usage
  metering) stays in.
- Breadth ≠ shallow: every slice ships robust and properly implemented.
- **Works council is a design consideration, not a gate**: W0 keeps its
  all-categories scope when built, but no longer blocks B — usage metering
  ships behind a simple default-off flag and W0 retrofits the toggle framework
  later.
- Failed logons (row 67): build **counts-only** — DEX needs the rate, not
  forensics; per-event detail is a future SIEM-class feature.
- Landing: commit the current pile on `feat/guardian-process-crash`, stack each
  new slice as its own branch on top; governance runs at PR-to-dev time.
- Build order: D3 → D5 → E1 → A1 → A3 → A4 → A2 → F1 → B → A5/E2 → C0 spike.

## How to read this

| Verdict | Meaning |
|---|---|
| **Covered** | Shipping today; the BRD fulfilment criterion is substantively met on Windows |
| **Partial** | Some of the row works today; the gap and its plan are noted |
| **Planned** | Not present today; assigned to a workstream slice below |
| **Stretch** | Planned but genuinely hard / research-grade; sequenced last in its workstream |
| **Deferred** | Acknowledged, no workstream assigned; revisit after the planned waves |
| **Descoped** | Deliberately not pursuing (see Descope register §3 — includes rationale) |

Row numbers are the BRD's own (Main tab). Plan references (A1, B2, D1…) point to §4.

---

## 1. Row-level coverage

### Cat 1 — Multi Platform Support (rows 5–12)

| Row | Target | Verdict | Basis |
|---|---|---|---|
| 5 | Windows | **Covered** | Agent + 103-signal DEX catalogue + Guardian + 44 plugins |
| 6 | Mac | **Partial** | macOS DEX collector shipped (~10/11 headings unprivileged); plugin coverage narrower than Windows |
| 7 | Linux | Planned | journald collector follows the catalogue pattern (`docs/dex-signal-catalog.md`); agent itself already runs on Linux |
| 8 | iOS | **Descoped** | No mobile agent — §3 |
| 9 | Android | **Descoped** | No mobile agent — §3 |
| 10 | Windows Servers | **Covered** | Same agent; per-channel arming isolation handles server SKU channel differences |
| 11 | Linux Servers | Planned | With row 7 |
| 12 | Storage Servers | **Descoped** | Appliance OSes out of scope — §3 |

### Cat 2 — Device & Endpoint Performance Metrics (rows 13–21)

| Row | Requirement | Verdict | Basis / plan |
|---|---|---|---|
| 13 | CPU utilization (real-time + historical + alerts) | Planned | **A1** sampling, **A3** threshold→observation, **A4** rollup |
| 14 | Memory utilization | Planned | A1/A3/A4 (failure event `memory.exhausted` already live) |
| 15 | Disk I/O latency & throughput | Planned | A1 (PhysicalDisk counters); failure events `disk.error`/`disk.port_reset` already live |
| 16 | Network latency & packet loss | Planned | **E1** active probes; A1 carries interface counters |
| 17 | GPU utilization | Planned | **A5** (GPU Engine counters) |
| 18 | NPU utilization | Stretch | A5 — Windows NPU counter surface is immature; detect presence via hardware inventory first |
| 19 | CPU throttling (incl. cause + duration) | **Partial** | `hw.cpu_throttled` (Kernel-Processor-Power 37) live; occurrence + firmware cause, no duration. Duration → A1 trend overlay |
| 20 | Disk size & utilization (+ low-space alert) | **Covered** (D1, 2026-06-12) | Size via hardware plugin `disks`; low-space alert via `storage.low` Windows state poll (`dex_win_poll`) — thresholds identical to macOS |
| 21 | Battery health (cycles, capacity, degradation) | **Covered** (D1, 2026-06-12) | IOCTL battery query (DesignedCapacity / FullChargedCapacity / CycleCount) → `hw.error` subject=battery below 80% of design; degradation *trend* over time → A-wave |

### Cat 3 — Application Usage & Performance Metrics (rows 22–34)

| Row | Requirement | Verdict | Basis / plan |
|---|---|---|---|
| 22 | App-specific resource consumption (open Q: granularity) | Planned | **A2** top-N per-process sampling. Granularity answer: 30 s sampling cadence edge-side, raw stays on-device (federated model answers the 15 s/1 min/5 min question better than ship-everything) |
| 23 | Single/multi-thread CPU monitoring | **Partial** | processes plugin reports per-process thread counts on demand; per-core attribution → A5 stretch |
| 24 | GPU & NPU per-app requirement | Stretch | A5 |
| 25 | Application performance (vague row) | **Partial** | Covered by the union of crash/hang/error signals today + A2 metrics when they land |
| 26 | Performance tuning | **Partial** | Measurement (A2) + remediation (instruction engine / Guardian) is the platform answer |
| 27 | Application error rates (+ spike alerting) | **Partial** | WER `process.crashed`, `.NET 1026`, `app.error_popup`, SideBySide/COM/activation failures all live; *rates with spike alerting* needs A2 denominators + **D3** fleet anomaly framing |
| 28 | App hang events (incl. duration) | **Partial** | `process.hung` live (Application Hang 1002). Event carries no duration — honest limitation; duration → C-wave ETW work |
| 29 | App crashes — foreground vs background (RFP Q) | **Covered** | Strong answer today: `app.error_popup` (Application Popup 26) = the dialog the user actually saw; `process.crashed` without paired popup = silent/background. Crash type + faulting module + per-device impact all in `/dex` |
| 30 | App usage pattern analysis | Planned | **B1/B2** usage metering + **B4** analytics |
| 31 | Java usage (version, time, parent apps) (RFP Q) | Planned | **B5** — TAR process births already record java/javaw launches + parent; add version enrich + report |
| 32 | App anomalies + blast radius | Planned | **D3** — N distinct devices emitting same (obs_type, subject) in window → alert. Projection already supports the GROUP BY |
| 33 | Application auto discovery | **Covered** | installed_apps plugin (installed) + TAR process births (actually-running) |
| 34 | Foreground vs background app time | Planned | **B1** foreground tracker |

### Cat 4 — End User Experience Metrics (rows 35–41)

| Row | Requirement | Verdict | Basis / plan |
|---|---|---|---|
| 35 | Application launch time | Stretch | **C1** — needs an ETW collector (catalogue doc already flags this class); no event-log source exists |
| 36 | User logon/logoff duration | **Partial** | `logon.slow_subscriber` (Winlogon 6005/6006) names culprits; TAR session events give logon/logoff timestamps. Full measured duration → **C2** |
| 37 | Machine boot & shutdown time | **Covered** | `os.boot` (ms metric, every boot, trendable) + `os.shutdown` + `shutdown.degraded` |
| 38 | Session responsiveness score | Planned | **F2** composite over A-wave metrics (derived/secondary score — accepted framing for DEX, unlike Guardian) |
| 39 | Screen refresh latency | Stretch | C3 — ETW/DWM research-grade |
| 40 | Input latency | Stretch | C3 — same |
| 41 | Application responsiveness (menus, renders) | Stretch | C3 — no generic Windows mechanism; honest RFP answer is per-app instrumentation doesn't exist in any agent-based tool without app cooperation |

### Cat 5 — Network & Connectivity (rows 42–51)

| Row | Requirement | Verdict | Basis / plan |
|---|---|---|---|
| 42 | Bandwidth usage (device + app) | Planned | Device-level: **A1** interface counters. Per-app: **E3** stretch |
| 43 | VPN / gateway latency | **Partial** | `network.vpn_failed` (failure) live; latency → **E1** probes targeting the gateway |
| 44 | Network jitter | Planned | **E1** — stddev over repeated probes |
| 45 | RTT to key (configurable) resources | Planned | **E1** |
| 46 | Connection drops per session | **Partial** | `network.wifi_drop`, `session.rdp_disconnected`, TAR connection diffs live; per-session attribution loose |
| 47 | Intel Wi-Fi / Thunderbolt analytics | **Descoped** | §3 |
| 48 | Real-time call/video insights (Teams/Zoom QoS) | **Descoped** | §3 |
| 49 | Per-app network metrics | Stretch | **E3** (ETW TCPIP / WFP accounting — heavy) |
| 50 | Device discovery (network inventory) | **Covered** | discovery plugin |
| 51 | Latency across network paths | Planned | **E1** multi-target probes |

### Cat 6 — Mobile Experience Monitoring (rows 52–58)

All seven rows **Descoped** — no mobile agent, no plans (§3).

### Cat 7 — User Behaviour and Adoption (rows 59–65)

All rows **Planned (B-wave)**, behind a default-off flag until W0 retrofits the
toggle framework — see §5 works-council note.

| Row | Requirement | Plan |
|---|---|---|
| 59 | Active/idle time per user/session | B1 (GetLastInputInfo active/idle classification) |
| 60 | Most used applications | B2/B4 |
| 61 | Session duration trends | B2 (TAR session events already record logon/logoff) |
| 62 | Simultaneous sessions per user | **Partial today** — TAR user-session collector sees concurrent sessions; needs a server-side per-user view (B4) |
| 63 | User productivity impact scores | Stretch — composite over B data; privacy-sensitive framing required |
| 64 | Click-to-render | Stretch (C3 class) |
| 65 | User interaction analysis | Stretch — B data + explicit works-council sign-off; aggregate-only by default |

### Cat 8 — Risk and Compliance (rows 66–70)

| Row | Requirement | Verdict | Basis / plan |
|---|---|---|---|
| 66 | Unauthorized app usage | **Partial** | installed_apps inventory + scope/tag queries today; "approved/prohibited" software tags = capability map §27.4 → **B4** |
| 67 | Failed logon attempts | Planned | **D4 (decided 2026-06-12: build, counts-only)** — scheduled Security-log 4625 counts per device (no usernames/IPs); DEX needs the rate, not forensics — per-event detail is a future SIEM-class feature. Needs the agent privilege-model procedure (Event Log Readers) |
| 68 | Shadow IT detection | **Partial** | TAR network events (remote hosts) + B-wave usage data; SaaS catalogue matching Deferred |
| 69 | Vulnerability detection | **Covered** | vuln_scan plugin |
| 70 | Policy compliance violations | **Covered** | Policy engine (PolicyEvaluator) + Guardian baselines — core platform strength |

### Cat 9 — Remote Support (rows 71–75)

| Row | Requirement | Verdict | Basis / plan |
|---|---|---|---|
| 71 | Remote desktop connection | **Descoped** | §3 |
| 72 | File transfer | **Partial** | content_dist (push w/ hash verify) + filesystem plugin (read/pull). No interactive session transfer — acceptable without row 71 |
| 73 | Remote troubleshooting | **Covered** | diagnostics, processes, event_logs, script_exec, netstat, services plugins + MCP agentic operation — arguably stronger than incumbent click-tools |
| 74 | Quick insights via browser plugin | Deferred | A browser extension over the REST API is plausible; not a wave-1 priority |
| 75 | Session recording | **Descoped** | Falls with row 71; audit log covers operator-action accountability — §3 |

### Cat 10 — Virtual Infrastructure (rows 76–86)

All eleven rows **Descoped** (§3) except:

| Row | Note |
|---|---|
| 81 | Session disconnects: `session.rdp_disconnected` live — keep as incidental coverage |
| 82 | Session crashes: generic crash signals apply inside a VDI guest |

The agent runs fine *inside* VDI guests; what's descoped is hypervisor/broker/vROps/Citrix/thin-client integration.

### Cat 11 — Integrations (rows 87–90)

| Row | Requirement | Verdict | Basis / plan |
|---|---|---|---|
| 87 | ITSM integration (ServiceNow named) | **Partial / SNOW descoped** | Generic outbound webhooks (HMAC-signed, filtered, delivery log) are live; ServiceNow-native connector descoped (§3) — webhook→SNOW middleware is the supported path |
| 88 | API availability | **Covered** | REST v1 + MCP server (the differentiator: agentic workers are first-class) |
| 89 | Teams/Zoom comms with end users | Deferred | interaction plugin (notify/message_box/survey) is the on-device channel today; Teams messaging bridge deferred |
| 90 | Webhooks for automated incident creation | **Covered** | WebhookStore: event filters, HMAC signing, async delivery, history |

### Cat 12 — Self-Healing & Remediation (rows 91–97)

| Row | Requirement | Verdict | Basis / plan |
|---|---|---|---|
| 91 | Scripting (PowerShell/bash, error handling, pre/post validation) | **Covered** | Instruction engine: YAML definitions, script_exec, content staging w/ hash verify, response capture. Secure credential mgmt: partial — ADR-0010 secrets-at-rest + content-signing roadmap |
| 92 | Custom monitoring scripts | **Covered** | InstructionDefinitions + trigger engine (interval, file change, service status, event log, registry, startup) |
| 93 | Self-healing workflows (monitor + remediate combos) | **Partial** | Guardian enforce (registry/file/service, safety-gated) = real-time self-heal for its guard types; policy engine remediation is operator-gated by design. Workflow *composition* UX → **F5** |
| 94 | Runbooks + multi-layer decision trees | Deferred | The agentic answer (MCP-driven runbooks executed by an agentic worker) is stronger than a visual tree builder; revisit after F-wave |
| 95 | Offline remediation (queue vs execute on reconnect) | **Partial** | Strong story: agent-side triggers + Guardian + KV state all keep working disconnected; staged content executes offline. Server-initiated work queues and delivers on reconnect. Document this explicitly (F5) |
| 96 | Self-healing policies for common issues | **Partial** | Policy engine + Guardian baselines exist; needs a shipped content pack of common-issue remediations (F5) |
| 97 | Out-of-band remediations | Deferred | Undefined in BRD (blank row) — seek clarification |

### Cat 13 — Performance Benchmarking (rows 98–104)

| Row | Requirement | Verdict | Basis / plan |
|---|---|---|---|
| 98 | Overall device benchmarking | Planned | **A4/F2** — fleet-relative percentiles (the Aternity model), not synthetic benchmark suites |
| 99 | Hardware benchmarking | Planned | Same — cohort comparison by hardware model via tags/props |
| 100 | Software benchmarking | Planned | Same, per-app once A2 lands |
| 101 | Boot time | **Covered** | `os.boot` ms metric, trendable |
| 102 | Login/logout times | **Partial** | See row 36 — C2 |
| 103 | Baseline vanilla vs layered image | Planned | **F2** cohort comparison (tag the vanilla cohort, diff distributions) — needs A-wave data |
| 104 | Boot components & contribution | **Covered** | `boot.degraded_app/driver/service/device` (Diag-Perf 101/102/103/109) — per-component ms attribution, real-record verified |

### Cat 14 — Application Usage Benchmarking (rows 105–107)

| Row | Requirement | Verdict | Plan |
|---|---|---|---|
| 105 | Usage analytics | Planned | B2/B4 |
| 106 | Usage patterns (incl. last-used) | Planned | B2 (last-used timestamp is a named BRD ask — cheap from TAR process events) |
| 107 | Time to launch | Stretch | C1 |

### Cat 15 — Security and Privacy (rows 108–113)

| Row | Requirement | Verdict | Basis / plan |
|---|---|---|---|
| 108 | SSO via SAML 2.0 | **Descoped (SAML)** | OIDC SSO + TOTP + MFA step-up live; Entra works over OIDC. SAML-specifically: descoped per 2026-06-12 decision (§3) |
| 109 | Entra ID integration | **Covered** | Via OIDC; conditional-access nuances are IdP-side |
| 110 | GDPR (RTBF + show-my-data) | Planned | **F3** — edge minimisation already removes most personal data at source; RTBF delete + per-device data view + retention config to build |
| 111 | Remote action signing | **Partial** | mTLS + RBAC + audit chain today; content authenticity/signing is a tracked roadmap item (upload-and-verify content) |
| 112 | Encryption at rest & in transit | **Covered** | In transit: mTLS everywhere (per-agent certs, internal CA). At rest: secrets envelope-encrypted (ADR-0010); DB-at-rest is a deployment concern (documented) |
| 113 | Granular role/action-based access | **Covered** | RBAC: principals, roles, securable types, per-operation permissions, management-group scoping |

### Cat 16 — Endpoint Management (rows 114–117)

| Row | Requirement | Verdict | Basis / plan |
|---|---|---|---|
| 114 | Endpoint configuration push | **Covered** | Instruction engine + registry/services/firewall/bitlocker/network_config plugins + Guardian baselines |
| 115 | Device & driver monitoring (RFP Q) | **Partial** | `hw.device_start_failed`, `boot.degraded_driver`, `display.driver_reset` live; driver *inventory* (versions, outdated) → small planned win, **D5** |
| 116 | Dynamic device groups (RFP Q) | **Covered** | Scope engine (expression trees, tags, props, OS) + scope walking + management groups — re-evaluates as device facts change; stronger than incumbents |
| 117 | Policy management | **Covered** | Policy engine + Guardian |

### Cat 17 — Reporting & Observability (rows 118–127)

| Row | Requirement | Verdict | Basis / plan |
|---|---|---|---|
| 118 | Centralised single pane | **Covered** | Dashboard (dark-theme HTMX), `/dex`, TAR, fleet viz |
| 119 | Crash detection | **Covered** | Crash family signals + `/dex` drill-downs |
| 120 | Crash logging | **Covered** | Guardian event store + projection; full historical query |
| 121 | Root cause analysis | **Partial** | Faulting module/exception code = RCA entry point; deep RCA is the agentic-worker story (MCP read tools) |
| 122 | Real-time monitoring | **Covered** | SSE event bus, live dashboards |
| 123 | Dashboard customisation | Deferred | Server-rendered fixed layouts + filters; a custom dashboard builder is contrary to the product's HTMX-first design — revisit on demand |
| 124 | Real-time alerts on thresholds | Planned | **A3** (breach→observation) + **F1** (alert routing config) |
| 125 | App non-usage data for license harvesting (RFP Q) | Planned | **B4** — capability map §27.5 reclamation candidates |
| 126 | Integration with monitoring tools | **Covered** | Prometheus-native `/metrics` |
| 127 | Data aggregation & granularity | **Partial** | Response store aggregation + TAR scope-walking SQL + federated edge model; A-wave adds the numeric dimension |

### Cat 18 — Intelligent Service Desk & AI (rows 128–138)

Strategic framing: Yuzu is agentic-first — the control plane is designed for an LLM
operator (MCP tools, A1–A4 invariants, machine-readable errors). The BRD's −80% / −70%
/ −60% KPIs are *agentic-worker outcomes*, not features of a ticket rules engine.

| Row | Requirement | Verdict | Basis / plan |
|---|---|---|---|
| 128 | Automated ticketing (−80% manual) | **Partial** | Webhook-driven incident creation live (generic); rules = webhook event filters; SNOW-native descoped |
| 129 | Ticket categorisation | **Partial** | Agentic answer: MCP read tools give an agentic worker full context to categorise; no built-in ITSM taxonomy |
| 130 | Ticket prioritisation | **Partial** | Same — plus D3 blast-radius gives the impact signal |
| 131 | AI-powered automation (−70%) | **Partial** | MCP execute tools + instruction engine, RBAC/audit-gated |
| 132 | Predictive analysis | Deferred | Needs A-wave trend history first; revisit post-A |
| 133 | Performance optimisation | **Partial** | Measure (A) + remediate (instructions/Guardian) loop |
| 134 | Proactive issue resolution (−60%) | **Partial** | Guardian enforce + policy engine + agentic workers |
| 135 | Automated diagnostics | **Covered** | diagnostics plugin + MCP — an agentic worker runs full diagnostic sweeps today |
| 136 | Proactive alerts (+ raise ticket) | **Partial** | Notifications + webhooks + SSE live; metric thresholds → A3/F1 |
| 137 | Crash/down detection + blast radius (RFP Q) | Planned | **D3** |
| 138 | Real-time end-user recommendations (reboot nudge etc.) | Deferred | Was **D2** — dropped 2026-06-12 (user-facing interaction out for now); machinery (`os.uptime_report` + interaction plugin) exists when revisited |

### Cat 19 — Employee Sentiment (rows 139–143)

| Row | Requirement | Verdict | Basis / plan |
|---|---|---|---|
| 139 | Sentiment analysis | Deferred | F4 deferred 2026-06-12 (user-facing interaction out for now); survey machinery exists when revisited |
| 140 | Sentiment tracking over time | Deferred | With F4 |
| 141 | Actionable insights | Deferred | With F4 (the DEX-correlation idea — "sentiment dipped where crash rate rose" — stays noted) |
| 142 | User feedback collection | **Partial** | interaction plugin `input`/`survey` actions live; campaign orchestration deferred with F4 |
| 143 | Survey capability | **Partial** | Same — agent-side done; server-side campaign/schedule/aggregate deferred with F4 |

### Cat 20 — Sustainability (rows 144–147)

| Row | Requirement | Verdict | Basis / plan |
|---|---|---|---|
| 144 | Power usage (machine/user) | Deferred | SRUM/E3 energy estimation is a plausible source (battery-powered devices); revisit post-B (SRUM also serves usage metering) |
| 145 | CPU power (idle kW/h + regional pricing) | Deferred | Same source; pricing overlay is reporting-layer |
| 146 | GPU power | Deferred | Same |
| 147 | Cradle-to-grave ESG | **Descoped** | §3 |

### Cat 21 — User Experience (row 148)

| Row | Requirement | Verdict | Basis |
|---|---|---|---|
| 148 | Desktop client to view/manage | Deferred | The web dashboard is the surface; no native desktop client planned |

### Cat 22 — Capacity Planning (rows 149–150)

| Row | Requirement | Verdict | Basis |
|---|---|---|---|
| 149 | VDI configuration recommendations (RFP Q) | **Descoped** | VDI cluster — §3 |
| 150 | Persona determination (RFP Q) | **Descoped** | Works-council collision: persona inference from behavioural data is a surveillance capability we will not build speculatively — §3 |

### Cat 23 — Automated Test Capabilities (rows 151–152)

| Row | Requirement | Verdict | Basis |
|---|---|---|---|
| 151 | Synthetic monitoring (RFP Q) | **Descoped** | §3 — note E1 probes provide light synthetic *network* checks, not synthetic user transactions |
| 152 | Load testing | **Descoped** | §3 |

---

## 2. Scorecard (Windows scope, 2026-06-12 baseline)

| Verdict | Rows (approx.) |
|---|---|
| Covered today | 31 |
| Partial today | 27 |
| Planned (A–F waves) | 28 |
| Stretch | 11 |
| Deferred | 10 |
| Descoped | 41 |

After waves D + A + B + E land, the projected position is ~75 covered/partial-strong of
the ~107 non-descoped rows, with the residual concentrated in the C-wave (experience
timing) and stretch items every vendor finds hard.

---

## 3. Descope register (decided 2026-06-12)

Recorded so the trade-off survives; each needs an explicit decision to reopen.

| Item | BRD rows | Rationale |
|---|---|---|
| Mobile (iOS/Android) monitoring | 8–9, 52–58 | No mobile agent; an entire product line, not a gap |
| Storage-server appliances | 12 | Niche OS targets outside the agent's platform set |
| VDI / hypervisor integrations (vROps, Citrix, brokers, host density, Elux/Unicon thin clients) | 76–80, 83–86, 149 | Whole product line; the agent works *inside* VDI guests, which we keep. **Risk note:** the BRD's environment is VDI-heavy — this descope should be communicated, not hidden |
| Remote desktop + session recording | 71, 75 | Different product category (remote access); remote *diagnostics* (row 73) is covered and is the stronger story |
| Intel Wi-Fi / Thunderbolt vendor analytics | 47 | Vendor-proprietary telemetry, narrow value |
| Teams/Zoom call-quality telemetry | 48 | Requires vendor API integrations (Microsoft CQD / Zoom dashboard), not endpoint telemetry; revisit only as a server-side connector |
| Synthetic transaction monitoring + load testing | 151–152 | Different discipline (test tooling); E1 network probes give the useful slice |
| ESG cradle-to-grave | 147 | Supply-chain data, not endpoint telemetry |
| Persona determination | 150 | Works-council surveillance collision (capability triggers co-determination, not intent) |
| **SAML 2.0** (OIDC stays) | 108 | Per 2026-06-12 decision; OIDC covers Entra SSO in practice |
| **ServiceNow-native connector** (generic webhooks stay) | 87, part of 136 | Per 2026-06-12 decision; webhook→ITSM middleware is the supported integration path |

---

## 4. Delivery plan — workstreams and slices

Sequencing (revised 2026-06-12): **D3 → D5 → E1 → A1 → A3 → A4 → A2 → F1 → B →
A5/E2 → C0 spike** — cheap real rows first, then the perf foundation
device-level before per-process depth; W0 retrofits when it earns its slot.
Each slice is a small branch stacked on `feat/guardian-process-crash`, governed
at PR-to-dev time.

### D — Quick wins (start immediately)

| Slice | Content | BRD rows | Notes |
|---|---|---|---|
| **D1** | **Windows state-poll collector** (`dex_win_poll`): `storage.low` parity (fixed-drive free-space poll, ≥90% full or <5 GiB) + battery health (`hw.error` subject=battery when FullCharged/Designed <80%, via IOCTL_BATTERY). Poll-and-latch (emit on transition), mirrors the proven macOS IOKit-poll pattern. Zero server change — both obs_types already in the display catalogue | 20, 21 | **SHIPPED 2026-06-12** — agent suite green (526 cases); live-fire pending a real low-disk/degraded-battery specimen |
| ~~D2~~ | ~~Reboot-nudge content pack~~ | 138 | **Dropped 2026-06-12** — user-facing interaction out for now |
| D3 | Blast-radius alerting: server-side detector — N distinct devices, same (obs_type, subject), sliding window → NotificationStore + webhook event | 32, 137, 27 | Pure server; projection query exists |
| D4 | Failed-logon counts: scheduled Security-log 4625 counts per device (no usernames/IPs) | 67 | **Decided 2026-06-12: build counts-only**; needs agent privilege-model procedure |
| D5 | Driver inventory action (wmi/hardware plugin): installed driver list w/ versions + date | 115 | Small plugin addition |

### A — Continuous device performance telemetry (the foundation)

Architecture: raw samples stay on-device in the TAR edge warehouse (federated model,
ADR-0004 — answers the BRD granularity question better than ship-everything);
threshold *breaches* ride the existing DEX observation wire (new `perf.*` obs_types —
zero proto change); fleet aggregates roll up via heartbeat status_tags + server
recompute (the established agent-metrics surface).

| Slice | Content | BRD rows |
|---|---|---|
| A1 | TAR perf sampler: PDH counters — CPU %, memory committed/available, disk latency + throughput, per-interface network bytes; 30 s cadence; `perf_samples` table + retention | 13–16, 42, 127 |
| A2 | Top-N per-process samples (CPU + working set, top 10 per tick) with cmdline redaction reuse | 22, 27 |
| A3 | Threshold→observation: hysteresis/latch breach detection → `perf.cpu_sustained`, `perf.memory_pressure`, `perf.disk_latency_high` observations (rate-capped, alert-routable like every other signal) | 13–15, 124 |
| A4 | Fleet rollup: heartbeat aggregate piggyback + server recompute → Prometheus gauges + `/dex` device drill-down sparklines (federated TAR query) | 98–100, 126 |
| A5 | GPU Engine counters; NPU best-effort | 17, 18, 24 |

### W0 — Telemetry collection controls (deprioritised 2026-06-12: retrofit, not gate)

Works council is a design consideration to bear in mind, not a show-stopper —
W0 no longer blocks B. When built, the scope decision stands: toggles cover ALL
categories including the already-shipping collectors.

| Slice | Content |
|---|---|
| W0.1 | Per-category collection toggles (dex_signals / perf_sampling / app_usage / tar_lifecycle / security_counts), server-set, agent-enforced at collector arm level; app_usage defaults **off** |
| W0.2 | Settings UI + REST + audit of toggle changes (works-council evidence trail) |

Until W0 lands, B ships behind a simple default-off config flag.

### B — App usage metering + software catalog/licensing (default-off flag until W0 retrofits)

| Slice | Content | BRD rows |
|---|---|---|
| B1 | Foreground/session tracker: low-cadence GetForegroundWindow + GetLastInputInfo poll → `app_usage_sessions` (app, fg seconds, active vs idle) in TAR | 34, 59 |
| B2 | On-device daily per-app rollups: launches (TAR process births), fg time, last-used | 30, 60, 61, 106 |
| B3 | Server software catalog store (capability map §27.1 — Postgres per ADR-0006) + usage rollup ingestion | 105 |
| B4 | License/usage views: most-used, unused/rarely-used, reclamation candidates; approved/prohibited software tags | 60, 66, 125 |
| B5 | Java usage report (process births + file-version enrich + parent process) | 31 |

### E — Network measurement (alongside B)

| Slice | Content | BRD rows |
|---|---|---|
| E1 | Probe module: ICMP/TCP RTT + DNS resolve timing to operator-configured targets, scheduled; jitter = stddev; results trend in response store | 16, 43–45, 51 |
| E2 | Wi-Fi signal quality poll + interface counters surfacing (with A1) | 46, 42 |
| E3 | Per-app network accounting (ETW TCPIP) | 49 — stretch |

### C — Experience timing collectors (ETW; research-first)

| Slice | Content | BRD rows |
|---|---|---|
| C0 | Spike: ETW feasibility for app-launch-time (process start → first foreground) + logon phase timing; NFR cost assessment | — |
| C1 | App launch time collector (if C0 proves viable) | 35, 107 |
| C2 | Logon duration measurement | 36, 102 |
| C3 | Input/render latency | 39–41, 64 — stretch, last |

### F — Reporting, alerting & sentiment polish

| Slice | Content | BRD rows |
|---|---|---|
| F1 | Alert routing config: which observation types / thresholds notify + webhook | 124, 136 |
| F2 | Fleet-relative benchmarking views (percentiles by cohort/tag; vanilla-vs-layered cohort diff) + session responsiveness composite | 38, 98–100, 103 |
| F3 | GDPR: RTBF delete + per-device data view + operator-set retention + pseudonymization | 110 |
| F4 | ~~Survey campaigns + sentiment trends~~ — **deferred 2026-06-12** with the user-facing-interaction decision | 139–143 |
| F5 | Self-healing content pack + offline-remediation documentation + workflow composition UX | 93, 95, 96 |

---

## 5. Standing notes

- **Works council (recalibrated 2026-06-12):** a design consideration to bear in
  mind and retrofit, not a gate. B-wave usage metering ships behind a default-off
  flag; W0 toggles, aggregate-first views, and the individual-view kill switch
  arrive when W0 lands. Keep collectors *toggle-ready* (clean arm/disarm seams)
  so the retrofit stays cheap.
- **"Real-time + historical with alerting"** (the BRD's universal qualifier) decomposes
  on our architecture as: real-time = observation wire + SSE; historical = edge
  warehouse (raw) + server rollups (fleet); alerting = A3 breach observations + F1
  routing. Use this framing in vendor responses.
- **Dashboard work** in F2 coordinates with the approved `/dex` mockup set
  (docs/mockups/dex-*.html) — don't fork the design.
- **Open BRD items to chase:** the uncaptured `Scenarios` tab; clarification on row 97
  (OoB remediations, blank in source); row 103's exact "build machine" baseline target.
