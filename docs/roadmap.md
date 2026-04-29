# Yuzu Development Roadmap

**Version:** 2.0 | **Date:** 2026-03-30

This roadmap transforms Yuzu from a functional agent/server framework into a full-featured enterprise endpoint management platform. Work is organized into 7 phases, each building on the previous. Every item is a GitHub issue.

## GitHub Issue Index

| Phase | Issue | # | Title | Status |
|-------|-------|---|-------|--------|
| **0** | 0.1 | [#146](https://github.com/Tr3kkR/Yuzu/issues/146) | HTTPS for Web Dashboard | Done |
| | 0.2 | [#147](https://github.com/Tr3kkR/Yuzu/issues/147) | Agent OTA Update Management | Done |
| | 0.3 | [#148](https://github.com/Tr3kkR/Yuzu/issues/148) | Secure Temp File Creation in Filesystem Plugin | Done |
| | 0.4 | [#150](https://github.com/Tr3kkR/Yuzu/issues/150) | SDK Utility Functions (JSON/Table Conversion) | Done |
| | 0.5 | [#152](https://github.com/Tr3kkR/Yuzu/issues/152) | Complete Foundation Partial Items | Done |
| **1** | 1.1 | [#166](https://github.com/Tr3kkR/Yuzu/issues/166) | Server-Side Response Persistence (SQLite) | Done |
| | 1.2 | [#167](https://github.com/Tr3kkR/Yuzu/issues/167) | Response Filtering, Pagination, and Sorting | Done |
| | 1.3 | [#168](https://github.com/Tr3kkR/Yuzu/issues/168) | Response Aggregation Engine | Done |
| | 1.4 | [#169](https://github.com/Tr3kkR/Yuzu/issues/169) | Audit Trail System | Done |
| | 1.5 | [#170](https://github.com/Tr3kkR/Yuzu/issues/170) | Device Tagging System | Done |
| | 1.6 | [#171](https://github.com/Tr3kkR/Yuzu/issues/171) | Scope Expression Engine and Device Filtering | Done |
| | 1.7 | [#172](https://github.com/Tr3kkR/Yuzu/issues/172) | CSV and JSON Data Export | Done |
| **2** | 2.1 | [#149](https://github.com/Tr3kkR/Yuzu/issues/149) | Instruction Definitions | Done |
| | 2.2 | [#151](https://github.com/Tr3kkR/Yuzu/issues/151) | Instruction Sets (Grouping and Organization) | Done |
| | 2.3 | [#153](https://github.com/Tr3kkR/Yuzu/issues/153) | Instruction Scheduling | Done |
| | 2.4 | [#155](https://github.com/Tr3kkR/Yuzu/issues/155) | Instruction Approval Workflows | Done |
| | 2.5 | [#158](https://github.com/Tr3kkR/Yuzu/issues/158) | Instruction Hierarchies and Follow-Up Workflows | Done |
| | 2.6 | [#160](https://github.com/Tr3kkR/Yuzu/issues/160) | Instruction Progress Tracking and Statistics | Done |
| | 2.7 | [#163](https://github.com/Tr3kkR/Yuzu/issues/163) | Instruction Rerun and Cancellation | Done |
| | 2.8 | [#205](https://github.com/Tr3kkR/Yuzu/issues/205) | Error Code Taxonomy (1xxx-4xxx) | Done |
| | 2.9 | [#206](https://github.com/Tr3kkR/Yuzu/issues/206) | Concurrency Enforcement (5 Modes) | Done |
| | 2.10 | [#207](https://github.com/Tr3kkR/Yuzu/issues/207) | YAML Authoring UI (Form + CodeMirror) | Done |
| | 2.11 | [#208](https://github.com/Tr3kkR/Yuzu/issues/208) | Legacy Command Shim | Done |
| | 2.12 | [#209](https://github.com/Tr3kkR/Yuzu/issues/209) | Structured Result Envelope | Done |
| **3** | 3.1 | [#154](https://github.com/Tr3kkR/Yuzu/issues/154) | Granular RBAC System | Done |
| | 3.2 | [#156](https://github.com/Tr3kkR/Yuzu/issues/156) | Management Groups | Done |
| | 3.3 | [#157](https://github.com/Tr3kkR/Yuzu/issues/157) | Token-Based API Authentication | Done |
| | 3.4 | [#159](https://github.com/Tr3kkR/Yuzu/issues/159) | OIDC / SSO Integration | Done |
| | 3.5 | [#161](https://github.com/Tr3kkR/Yuzu/issues/161) | REST / HTTP Management API (v1) | Done |
| | 3.6 | [#162](https://github.com/Tr3kkR/Yuzu/issues/162) | Device Quarantine (Network Isolation) | Done |
| | 3.7 | [#164](https://github.com/Tr3kkR/Yuzu/issues/164) | IOC Checking | Done |
| | 3.8 | [#165](https://github.com/Tr3kkR/Yuzu/issues/165) | Certificate Inventory and Management | Done |
| | 3.9 | [#210](https://github.com/Tr3kkR/Yuzu/issues/210) | Scope DSL Extensions (MATCHES, EXISTS, len, startswith) | **Done** |
| **4** | 4.1 | [#173](https://github.com/Tr3kkR/Yuzu/issues/173) | Agent-Side Key-Value Storage | Done |
| | 4.2 | [#174](https://github.com/Tr3kkR/Yuzu/issues/174) | HTTP Download and Upload (Agent-Initiated) | Done |
| | 4.3 | [#177](https://github.com/Tr3kkR/Yuzu/issues/177) | Content Staging and Execution | Done |
| | 4.4 | [#181](https://github.com/Tr3kkR/Yuzu/issues/181) | Agent Sleep and Stagger Control | Done |
| | 4.5 | [#184](https://github.com/Tr3kkR/Yuzu/issues/184) | Trigger Framework (Agent-Side) | Done |
| | 4.6 | [#189](https://github.com/Tr3kkR/Yuzu/issues/189) | Desktop User Interaction (Windows) | Done |
| | 4.7 | [#193](https://github.com/Tr3kkR/Yuzu/issues/193) | Agent Logging and Remote Log Retrieval | Done |
| | 4.8 | [#212](https://github.com/Tr3kkR/Yuzu/issues/212) | service.set_start_mode Cross-Platform Primitive | Done |
| **5** | 5.1 | [#175](https://github.com/Tr3kkR/Yuzu/issues/175) | Policy Rules and Fragments | Done |
| | 5.2 | [#176](https://github.com/Tr3kkR/Yuzu/issues/176) | Policy Assignment and Deployment | Done |
| | 5.3 | [#178](https://github.com/Tr3kkR/Yuzu/issues/178) | Compliance Dashboard and Statistics | Done |
| | 5.4 | [#179](https://github.com/Tr3kkR/Yuzu/issues/179) | Policy Cache Invalidation and Force Re-Evaluation | Done |
| | 5.5 | [#211](https://github.com/Tr3kkR/Yuzu/issues/211) | CEL Adoption for Policy Compliance Expressions | Done |
| **6** | 6.1 | [#180](https://github.com/Tr3kkR/Yuzu/issues/180) | Registry Plugin (Read/Write/Enumerate) | Done |
| | 6.2 | [#182](https://github.com/Tr3kkR/Yuzu/issues/182) | Per-User Registry Operations | Done |
| | 6.3 | [#183](https://github.com/Tr3kkR/Yuzu/issues/183) | WMI Query and Method Invocation | Done |
| | 6.4 | [#186](https://github.com/Tr3kkR/Yuzu/issues/186) | Per-User Application Inventory | Done |
| | 6.5 | [#188](https://github.com/Tr3kkR/Yuzu/issues/188) | File System Advanced Operations | Done |
| | 6.6 | [#192](https://github.com/Tr3kkR/Yuzu/issues/192) | Registry Change Trigger | Done |
| **7** | 7.1 | [#185](https://github.com/Tr3kkR/Yuzu/issues/185) | Gateway Node Implementation | Done |
| | 7.2 | [#187](https://github.com/Tr3kkR/Yuzu/issues/187) | System Health Monitoring and Statistics | Done |
| | 7.3 | [#190](https://github.com/Tr3kkR/Yuzu/issues/190) | Runtime Configuration API | Done |
| | 7.4 | [#191](https://github.com/Tr3kkR/Yuzu/issues/191) | System Notifications | Done |
| | 7.5 | [#194](https://github.com/Tr3kkR/Yuzu/issues/194) | Active Directory / Entra Integration | Done |
| | 7.6 | [#195](https://github.com/Tr3kkR/Yuzu/issues/195) | Custom Properties on Devices | Done |
| | 7.7 | [#196](https://github.com/Tr3kkR/Yuzu/issues/196) | Agent Deployment Jobs | Done |
| | 7.8 | [#197](https://github.com/Tr3kkR/Yuzu/issues/197) | Patch Deployment Workflow | Done |
| | 7.9 | [#198](https://github.com/Tr3kkR/Yuzu/issues/198) | Product Packs (Bundled Definitions) | Done |
| | 7.10 | [#199](https://github.com/Tr3kkR/Yuzu/issues/199) | User Sessions and Group Membership Plugins | Done |
| | 7.11 | [#200](https://github.com/Tr3kkR/Yuzu/issues/200) | Advanced User Interaction (Surveys, DND) | Done |
| | 7.12 | [#201](https://github.com/Tr3kkR/Yuzu/issues/201) | Event Subscriptions (Webhooks) | Done |
| | 7.13 | [#213](https://github.com/Tr3kkR/Yuzu/issues/213) | ProductPack Ed25519 Trust Chain and Verification | Done |
| | 7.14 | [#214](https://github.com/Tr3kkR/Yuzu/issues/214) | Workflow Primitives (if, foreach, retry) | Done |
| | 7.15 | [#215](https://github.com/Tr3kkR/Yuzu/issues/215) | WiFi Network Enumeration | Done |
| | 7.16 | [#216](https://github.com/Tr3kkR/Yuzu/issues/216) | Wake-on-LAN Support | Done |
| | 7.17 | [#217](https://github.com/Tr3kkR/Yuzu/issues/217) | Inventory Table Enumeration and Item Lookup | Done |
| | 7.18 | [#218](https://github.com/Tr3kkR/Yuzu/issues/218) | Device Discovery (Unmanaged Endpoints) | Done |
| | 7.19 | [#235](https://github.com/Tr3kkR/Yuzu/issues/235) | Timeline Activity Record (TAR) | Done |
| | 7.20 | [#236](https://github.com/Tr3kkR/Yuzu/issues/236) | MCP Server (Model Context Protocol) Phase 1 | Done |
| **8** | 8.1 | [#253](https://github.com/Tr3kkR/Yuzu/issues/253) | Response Visualization Engine | **Done** |
| | 8.2 | [#254](https://github.com/Tr3kkR/Yuzu/issues/254) | Response Templates | Open |
| | 8.3 | [#255](https://github.com/Tr3kkR/Yuzu/issues/255) | Response Offloading (Data Export Streams) | Open |
| **9** | 9.1 | [#256](https://github.com/Tr3kkR/Yuzu/issues/256) | Connector Framework (Core) | Open |
| | 9.2 | [#257](https://github.com/Tr3kkR/Yuzu/issues/257) | Inventory Repository Model | Open |
| | 9.3 | [#258](https://github.com/Tr3kkR/Yuzu/issues/258) | SCCM / ConfigMgr Connector | Open |
| | 9.4 | [#259](https://github.com/Tr3kkR/Yuzu/issues/259) | Intune Connector | Open |
| | 9.5 | [#260](https://github.com/Tr3kkR/Yuzu/issues/260) | ServiceNow Connector | Open |
| | 9.6 | [#261](https://github.com/Tr3kkR/Yuzu/issues/261) | WSUS Connector | Open |
| | 9.7 | [#262](https://github.com/Tr3kkR/Yuzu/issues/262) | CSV / File Upload Connector | Open |
| | 9.8 | [#263](https://github.com/Tr3kkR/Yuzu/issues/263) | Inventory Consolidation & Normalization | Open |
| **10** | 10.1 | [#264](https://github.com/Tr3kkR/Yuzu/issues/264) | Software Catalog Store | Open |
| | 10.2 | [#265](https://github.com/Tr3kkR/Yuzu/issues/265) | Software Usage Tracking | Open |
| | 10.3 | [#266](https://github.com/Tr3kkR/Yuzu/issues/266) | License Entitlements & Compliance | Open |
| | 10.4 | [#267](https://github.com/Tr3kkR/Yuzu/issues/267) | Software Tags | Open |
| **11** | 11.1 | [#268](https://github.com/Tr3kkR/Yuzu/issues/268) | Consumer Application Registration | Open |
| | 11.2 | [#269](https://github.com/Tr3kkR/Yuzu/issues/269) | Event Source Management | Open |
| | 11.3 | [#270](https://github.com/Tr3kkR/Yuzu/issues/270) | PowerShell Module | Open |
| | 11.4 | [#271](https://github.com/Tr3kkR/Yuzu/issues/271) | Python SDK | Open |
| **12** | 12.1 | [#272](https://github.com/Tr3kkR/Yuzu/issues/272) | Mapped Drive History | Open |
| | 12.2 | [#273](https://github.com/Tr3kkR/Yuzu/issues/273) | Printer Inventory | Open |
| | 12.3 | [#274](https://github.com/Tr3kkR/Yuzu/issues/274) | Port Scanning | Open |
| | 12.4 | [#275](https://github.com/Tr3kkR/Yuzu/issues/275) | NetBIOS Lookup | Open |
| | 12.5 | [#276](https://github.com/Tr3kkR/Yuzu/issues/276) | Open Windows Enumeration | Open |
| | 12.6 | [#277](https://github.com/Tr3kkR/Yuzu/issues/277) | Directory Hash (Recursive) | Open |
| | 12.7 | [#278](https://github.com/Tr3kkR/Yuzu/issues/278) | Survey Dialog | Open |
| | 12.8 | [#279](https://github.com/Tr3kkR/Yuzu/issues/279) | Do-Not-Disturb Mode | Open |
| | 12.9 | [#280](https://github.com/Tr3kkR/Yuzu/issues/280) | Active Response Tracking | Open |
| | 12.10 | [#281](https://github.com/Tr3kkR/Yuzu/issues/281) | Patch Inventory Event Generation | Open |
| | 12.11 | [#282](https://github.com/Tr3kkR/Yuzu/issues/282) | Application Whitelisting | Open |
| | 12.12 | [#283](https://github.com/Tr3kkR/Yuzu/issues/283) | Inventory Replication (Delta Sync) | Open |
| | 12.13 | [#284](https://github.com/Tr3kkR/Yuzu/issues/284) | Binary Resource Distribution | Open |
| **13** | 13.1 | [#285](https://github.com/Tr3kkR/Yuzu/issues/285) | 2FA for Instruction Approval (TOTP) | Open |
| | 13.2 | [#286](https://github.com/Tr3kkR/Yuzu/issues/286) | Composable Instruction Chains | Open |
| | 13.3 | [#287](https://github.com/Tr3kkR/Yuzu/issues/287) | Process / Sync Logging UI | Open |
| | 13.4 | [#288](https://github.com/Tr3kkR/Yuzu/issues/288) | Dashboard Branding | Open |
| | 13.5 | [#289](https://github.com/Tr3kkR/Yuzu/issues/289) | MCP Phase 2 (Write Tools) | Open |
| **14** | 14.1 | [#290](https://github.com/Tr3kkR/Yuzu/issues/290) | P2P Content Distribution | Open |
| | 14.2 | [#291](https://github.com/Tr3kkR/Yuzu/issues/291) | Multi-Gateway Topology | Open |
| | 14.3 | [#292](https://github.com/Tr3kkR/Yuzu/issues/292) | Database Sharding (Response Partitioning) | Open |
| | 14.4 | [#293](https://github.com/Tr3kkR/Yuzu/issues/293) | vCenter Connector | Open |
| | 14.5 | [#294](https://github.com/Tr3kkR/Yuzu/issues/294) | Additional Connectors (BigFix, O365, Oracle) | Open |
| | 14.6 | [#295](https://github.com/Tr3kkR/Yuzu/issues/295) | High Availability (Active-Passive) | Open |
| **15** | 15.A | [#547](https://github.com/Tr3kkR/Yuzu/issues/547) | TAR dashboard page shell + retention-paused source list | **In progress — PR-A.A shipped** (paused_at + status extension + dashboard page + Scan + Re-enable; purge action + persistence pending) |
| | 15.B | [#548](https://github.com/Tr3kkR/Yuzu/issues/548) | Result-set store + REST API (composable scope, the differentiator) | Open |
| | 15.C | [#549](https://github.com/Tr3kkR/Yuzu/issues/549) | Scope-engine `from_result_set:` + dashboard chip + sidebar + breadcrumb | Open |
| | 15.D | [#550](https://github.com/Tr3kkR/Yuzu/issues/550) | TAR SQL frame: relocate, scope-walking-aware, "save as result set" | Open |
| | 15.E | [#551](https://github.com/Tr3kkR/Yuzu/issues/551) | YAML DSL `fromResultSet:` + `definition_store` validation + spec amendment | Open |
| | 15.F | [#552](https://github.com/Tr3kkR/Yuzu/issues/552) | Reference walkthrough integration test (Chrome IR end-to-end) | Open |
| | 15.G | [#553](https://github.com/Tr3kkR/Yuzu/issues/553) | Operational hardening — live re-eval, GC sweep, Prometheus + audit polish | Open |
| | 15.H | [#554](https://github.com/Tr3kkR/Yuzu/issues/554) | TAR process tree viewer (seed snapshot + reconstruction from `process_live`) | Open (gated on agent service-install hardening) |
| **16** | 16.A | [#555](https://github.com/Tr3kkR/Yuzu/issues/555) | System Guardian — Windows-first delivery (PRs 1-15 per implementation plan) | **In progress** (PRs 1-2 shipped) |
| | 16.B | [#556](https://github.com/Tr3kkR/Yuzu/issues/556) | System Guardian — Linux delivery (inotify, netlink, D-Bus, audit, sysctl) | Open (gated on 16.A soak) |
| | 16.C | [#557](https://github.com/Tr3kkR/Yuzu/issues/557) | System Guardian — macOS delivery (Endpoint Security, fseventsd, launchd) | Open (gated on 16.A + 16.B soak + ES entitlement) |

## Current Status

| Phase | Done | Open | Total | Progress |
|-------|:----:|:----:|:-----:|----------|
| 0: Foundation | 5 | 0 | 5 | 100% |
| 1: Data Infrastructure | 7 | 0 | 7 | 100% |
| 2: Instruction System | 12 | 0 | 12 | 100% |
| 3: Security & RBAC | 9 | 0 | 9 | 100% |
| 4: Agent Infrastructure | 8 | 0 | 8 | 100% |
| 5: Policy Engine | 5 | 0 | 5 | 100% |
| 6: Windows Depth | 6 | 0 | 6 | 100% |
| 7: Scale & Integration | 20 | 0 | 20 | 100% |
| 8: Visualization & Response Experience | 1 | 2 | 3 | 33% |
| 9: Connector Framework & Multi-Source Inventory | 0 | 8 | 8 | 0% |
| 10: Software Catalog & License Compliance | 0 | 4 | 4 | 0% |
| 11: Consumer Model & Platform Extensibility | 0 | 4 | 4 | 0% |
| 12: Remaining Agent Capabilities | 0 | 13 | 13 | 0% |
| 13: Security Hardening & Operational Polish | 0 | 5 | 5 | 0% |
| 14: Scale & Enterprise Readiness | 0 | 6 | 6 | 0% |
| 15: TAR Dashboard & Scope Walking | 0 | 8 | 8 | 0% |
| 16: System Guardian — Real-Time GS | 0 | 3 | 3 | 0% |
| **Total** | **73** | **53** | **126** | **58%** |

**Scaffolded** means DDL/structs/stubs exist but business logic is not wired. See `docs/Instruction-Engine.md` for Phase 2 scaffold details.

---

## Phase 0: Foundation Completion

*Close the remaining Foundation-tier gaps. These are prerequisites for production use.*

### Issue 0.1: HTTPS for Web Dashboard :white_check_mark:
**Capability:** 18.9 | **Scope:** Server | **Status:** Done

`httplib::SSLServer` with OpenSSL support (`-DCPPHTTPLIB_OPENSSL_SUPPORT`). CLI flags: `--https`, `--https-port` (default 8443), `--https-cert`, `--https-key`, `--no-https-redirect`. HTTP-to-HTTPS 301 redirect server. Secure cookie flag when HTTPS enabled. Settings UI has TLS configuration section.

**Files:** `server/core/src/server.cpp` (lines 2531-2560, 4412-4462), `server/core/meson.build` (OpenSSL dep)

### Issue 0.2: Agent OTA Update Management :white_check_mark:
**Capability:** 1.4 | **Scope:** Agent + Server | **Status:** Done

`CheckForUpdate`/`DownloadUpdate` RPCs in agent.proto. Full updater implementation with hash verification and platform-specific self-update.

**Files:** `agents/core/src/updater.cpp`, `proto/yuzu/agent/v1/agent.proto` (lines 29-33, 130-157)

### Issue 0.3: Secure Temp File Creation in Filesystem Plugin :white_check_mark:
**Capability:** 10.12 | **Scope:** Plugin | **Status:** Done

`yuzu_create_temp_file()` and `yuzu_create_temp_dir()` in SDK with secure permissions (POSIX 0600/0700, Windows owner-only DACL). Filesystem plugin exposes `create_temp` and `create_temp_dir` actions.

**Files:** `sdk/include/yuzu/plugin.h` (lines 207-244), `agents/plugins/filesystem/src/filesystem_plugin.cpp`

### Issue 0.4: SDK Utility Functions (JSON/Table Conversion) :white_check_mark:
**Capability:** 24.6 | **Scope:** SDK | **Status:** Done

`yuzu_table_to_json()`, `yuzu_json_to_table()`, `yuzu_split_lines()`, `yuzu_generate_sequence()`, `yuzu_free_string()` implemented in plugin.h C ABI.

**Files:** `sdk/include/yuzu/plugin.h` (lines 153-206)

### Issue 0.5: Complete Foundation Partial Items :white_check_mark:
**Capabilities:** 1.8, 4.5, 10.3 | **Scope:** Agent + Plugins | **Status:** Done

- **1.8** `connection_info` action: server address, TLS status, session ID, gRPC channel state, reconnect count, latency, uptime.
- **4.5** `dns_cache` action: Windows `DnsGetCacheDataTable`, Linux systemd-resolved query.
- **10.3** `offset`/`limit` parameters on filesystem `read` action (1-based line offset, configurable max).

**Files:** `agents/plugins/diagnostics/src/diagnostics_plugin.cpp`, `agents/plugins/network_config/src/network_config_plugin.cpp`, `agents/plugins/filesystem/src/filesystem_plugin.cpp`

---

## Phase 1: Server-Side Data Infrastructure

*Build the server-side systems that all advanced features depend on: persistent response storage, device metadata, audit logging, and a query language.*

### Issue 1.1: Server-Side Response Persistence (SQLite) :white_check_mark:
**Capabilities:** 20.2, 20.4 | **Scope:** Server | **Status:** Done

SQLite with WAL mode, `StoredResponse` struct, configurable TTL retention (default 90 days), background cleanup thread.

**Files:** `server/core/src/response_store.hpp`, `server/core/src/response_store.cpp`

### Issue 1.2: Response Filtering, Pagination, and Sorting :white_check_mark:
**Capability:** 20.2 | **Scope:** Server | **Status:** Done

`ResponseQuery` struct with agent_id, status, time range (since/until), limit/offset pagination. Exposed via `GET /api/responses/{instruction_id}` with query parameters.

**Files:** `server/core/src/response_store.hpp`, `server/core/src/response_store.cpp`, `server/core/src/server.cpp`

### Issue 1.3: Response Aggregation Engine
**Capability:** 20.3 | **Scope:** Server

Server-side aggregation of response data. Support group-by columns with `count`, `sum`, `min`, `max` operations. Aggregation definitions are attached to instruction definitions (when those exist) or specified ad-hoc. Return aggregated results alongside raw data.

**Files:** `server/core/src/response_store.cpp`, `proto/yuzu/server/v1/management.proto`

### Issue 1.4: Audit Trail System :white_check_mark:
**Capability:** 21.2 | **Scope:** Server | **Status:** Done

`AuditStore` with SQLite WAL backend. `AuditEvent` struct: timestamp, principal, principal_role, action, target_type, target_id, detail, source_ip, user_agent, session_id, result. Query with filtering and pagination. Default 365-day retention.

**Files:** `server/core/src/audit_store.hpp`, `server/core/src/audit_store.cpp`, `server/core/src/server.cpp`

### Issue 1.5: Device Tagging System :white_check_mark:
**Capabilities:** 3.10, 3.6, 3.7 | **Scope:** Server + Agent | **Status:** Done

`TagStore` with SQLite backend. `DeviceTag` struct: agent_id, key, value, source (agent/server/api), updated_at. Validation: key max 64 chars `[a-zA-Z0-9_.:-]`, value max 448 bytes. Agent tag sync from heartbeat. `agents_with_tag()` for scope queries. Device criticality (3.6) and location (3.7) implemented as special-purpose tags.

**Files:** `server/core/src/tag_store.hpp`, `server/core/src/tag_store.cpp`, `agents/plugins/tags/src/tags_plugin.cpp`

### Issue 1.6: Scope Expression Engine and Device Filtering :white_check_mark:
**Capabilities:** 19.3, 2.2, 2.11 | **Scope:** Server | **Status:** Done

494-line recursive-descent parser. 9 operators: `==`, `!=`, `LIKE`, `<`, `>`, `<=`, `>=`, `IN`, `CONTAINS`. AND/OR/NOT combinators, wildcard LIKE matching, case-insensitive comparison, max nesting depth 10. `AttributeResolver` callback for evaluation. Target estimation via `GET /api/target/estimate`.

**Files:** `server/core/src/scope_engine.hpp`, `server/core/src/scope_engine.cpp`, `server/core/src/server.cpp`

### Issue 1.7: CSV and JSON Data Export
**Capabilities:** 20.5, 24.5 | **Scope:** Server

Export response data and inventory as CSV or JSON. Support:
- Export specific instruction responses by ID
- Export inventory data by plugin
- Generic JSON-to-CSV conversion endpoint
- Stream large exports to avoid memory pressure

**Files:** `server/core/src/server.cpp`, new `server/core/src/data_export.cpp`

---

## Phase 2: Instruction System

*Transform ad-hoc commands into a governed instruction lifecycle. YAML-defined instruction definitions with typed parameter and result schemas, executed through the existing `CommandRequest` wire protocol, tracked by `ExecutionTracker`, stored by `ResponseStore`, and audited by `AuditStore`. See `docs/Instruction-Engine.md` for the full architectural blueprint and `docs/yaml-dsl-spec.md` for the YAML specification.*

### Issue 2.1: Instruction Definitions
**Capability:** 2.6 | **Scope:** Server + Proto

YAML-first InstructionDefinitions (see `docs/yaml-dsl-spec.md` Section 3). Each definition stored with `yaml_source` column (verbatim YAML, source of truth) plus denormalized columns for efficient queries. Features:
- **Content model:** `apiVersion: yuzu.io/v1alpha1`, `kind: InstructionDefinition`, `metadata` + `spec` + `status`
- **Type:** `question` (read-only) or `action` (may modify state)
- **Execution spec:** plugin, action, concurrency mode (per-device/per-definition/per-set/global:N/unlimited), stagger
- **Parameter schema:** JSON Schema subset — type (string, boolean, int32, int64, datetime, guid), required, validation (maxLength, pattern, enum, min/max)
- **Result schema:** Typed columns (bool, int32, int64, string, datetime, guid, clob) with aggregation config (groupBy + operations)
- **Approval mode:** auto (default for questions), role-gated (default for actions), always
- **Compatibility:** minAgentVersion, requiredPlugins — server-side pre-dispatch check
- **Legacy command shim:** Auto-generate definitions from plugin descriptors on server startup (Section 15 of Instruction-Engine.md)

CRUD via REST API. Import/export as YAML and JSON.

**Files:** `server/core/src/instruction_store.hpp`, `server/core/src/instruction_store.cpp`, `server/core/src/server.cpp`

### Issue 2.2: Instruction Sets (Grouping and Organization)
**Capability:** 2.7 | **Scope:** Server

InstructionSets are the **permission boundary** (see `docs/yaml-dsl-spec.md` Section 4). Users execute definitions within sets; authors publish to sets; approvers approve set-governed actions. Sets declare:
- `contents` — list of InstructionDefinition IDs, PolicyFragment IDs, workflow templates
- `permissions` — executeRoles, authorRoles, approveRoles
- `defaults` — approvalMode, responseRetentionDays, targetEstimationRequiredAbove
- `publishing` — signed flag, visibility (org/public)

CRUD via management API. RBAC system (Phase 3) binds `Principal + Role + SecurableType(InstructionSet) + Operation`.

**Files:** `server/core/src/instruction_store.hpp`, `server/core/src/instruction_store.cpp`

### Issue 2.3: Instruction Scheduling
**Capability:** 2.9 | **Scope:** Server

`ScheduleEngine` evaluates due schedules on a background thread (60-second tick). Schedule model:
- frequency_type (daily, weekly, monthly, interval)
- interval_minutes for sub-day granularity
- time_of_day, day_of_week, day_of_month for calendar schedules
- scope_expression for device targeting (evaluated by `ScopeEngine`)
- requires_approval flag — creates approval record instead of immediate dispatch
- next/last execution tracking, execution_count

Dispatches via the same `CommandRequest` path. CRUD via management API.

**Files:** `server/core/src/schedule_engine.hpp`, `server/core/src/schedule_engine.cpp`, `server/core/src/server.cpp`

### Issue 2.4: Instruction Approval Workflows
**Capability:** 2.10 | **Scope:** Server

`ApprovalManager` implements approval gating per Instruction-Engine.md Section 6.1 `spec.approval.mode`:
- `auto` — questions auto-approved, no gate
- `role-gated` — actions require approval from a user with an approveRole on the InstructionSet
- `always` — all executions require explicit approval

Rules: submitter cannot approve own actions. Approval record includes submitted_by, reviewed_by, review_comment, scope_expression. On approval, dispatch proceeds automatically. On rejection, execution is marked rejected with comment.

**Files:** `server/core/src/approval_manager.hpp`, `server/core/src/approval_manager.cpp`, `server/core/src/server.cpp`

### Issue 2.5: Instruction Hierarchies and Follow-Up Workflows
**Capability:** 2.8 | **Scope:** Server

`Execution.parent_id` tracks parent-child relationships. Follow-up instructions dispatched using parent's response data as input. `ExecutionTracker.get_children()` enables drill-down. Previous-result filtering: server extracts columns from parent response, passes as parameters to child definition.

**Files:** `server/core/src/execution_tracker.hpp`, `server/core/src/execution_tracker.cpp`

### Issue 2.6: Instruction Progress Tracking and Statistics
**Capabilities:** 2.12, 1.9 | **Scope:** Server + Agent

`ExecutionTracker` maintains per-execution aggregate status per Instruction-Engine.md Section 9.3:
- `Execution` struct: agents_targeted, agents_responded, agents_success, agents_failure
- `AgentExecStatus` struct: per-agent dispatched_at, first_response_at, completed_at, exit_code, error_detail
- `ExecutionSummary` with progress_pct
- Aggregate status: succeeded, completed (≥minSuccessPercent), failed, timed_out, cancelled, partial

Error codes follow the 4-category taxonomy (1xxx plugin, 2xxx transport, 3xxx orchestration, 4xxx agent).

**Files:** `server/core/src/execution_tracker.hpp`, `server/core/src/execution_tracker.cpp`, `server/core/src/server.cpp`

### Issue 2.7: Instruction Rerun and Cancellation
**Capability:** 2.13 | **Scope:** Server + Agent

- **Rerun:** `ExecutionTracker.create_rerun()` — clone execution with same params/scope, set `rerun_of`, optionally target only failed agents
- **Cancel:** `ExecutionTracker.mark_cancelled()` — set status=cancelled, send cancel signal to agents via heartbeat flag or new `CancelCommand` message

**Files:** `server/core/src/execution_tracker.hpp`, `server/core/src/execution_tracker.cpp`, `server/core/src/server.cpp`, `agents/core/src/agent.cpp`

### Issue 2.8: Error Code Taxonomy (1xxx-4xxx)
**Scope:** Server + Agent

Implement the 4-category error code taxonomy from `docs/Instruction-Engine.md` Section 9: 1xxx plugin, 2xxx transport, 3xxx orchestration, 4xxx agent. Each code has defined retry semantics. Per-definition `minSuccessPercent` determines aggregate execution status.

**Files:** `server/core/src/execution_tracker.hpp`, `server/core/src/execution_tracker.cpp`, `agents/core/src/agent.cpp`, `proto/yuzu/common/v1/common.proto`

### Issue 2.9: Concurrency Enforcement (5 Modes)
**Scope:** Server + Agent

Implement 5 concurrency modes from `docs/Instruction-Engine.md` Section 10: `per-device` (agent-side, default), `per-definition` (server-side), `per-set` (agent-side), `global:<N>` (server-side semaphore), `unlimited`. Agent maintains in-memory lock set; server uses `concurrency_locks` SQLite table.

**Files:** `agents/core/src/agent.cpp`, `server/core/src/execution_tracker.cpp`, `server/core/src/instruction_store.cpp`

### Issue 2.10: YAML Authoring UI (Form + CodeMirror)
**Scope:** Server

Extend `instruction_ui.cpp` with form mode (input fields, parameter/result builders) and YAML mode (CodeMirror 6 editor, server-side validation). Import/export endpoints. Follows HTMX fragment pattern. Design: `docs/Instruction-Engine.md` Section 11.

**Files:** `server/core/src/instruction_ui.cpp`, `server/core/src/instruction_store.cpp`, `server/core/src/server.cpp`

### Issue 2.11: Legacy Command Shim
**Scope:** Server

Auto-generate InstructionDefinitions from plugin descriptors (`YuzuPluginDescriptor.actions[]`). Bridges ad-hoc commands into the governed pipeline with open-schema parameters. CLI tool: `yuzu-admin generate-definitions`. Design: `docs/Instruction-Engine.md` Section 15.

**Files:** New `server/core/src/legacy_shim.cpp`, `server/core/src/instruction_store.cpp`, `server/core/src/server.cpp`

### Issue 2.12: Structured Result Envelope
**Scope:** Server + Agent

Implement the canonical `InstructionResult` envelope from `docs/Instruction-Engine.md` Section 18. Typed columns (bool, int32, int64, string, datetime, guid, clob) with structured rows. Prerequisite for workflow chaining, policy evaluation, and typed data export.

**Files:** `server/core/src/response_store.hpp`, `server/core/src/response_store.cpp`, `server/core/src/execution_tracker.cpp`, `agents/core/src/agent.cpp`

---

## Phase 3: Security, RBAC, and Access Control

*Enterprise authentication, granular permissions, and security response capabilities.*

### Issue 3.1: Granular RBAC System
**Capability:** 18.3 | **Scope:** Server

Replace the two-role system with a full RBAC model:
- **Principals:** Users or groups with unique IDs
- **Roles:** Named permission containers (built-in + custom)
- **Securable types:** Categories of protected resources (InstructionSet, Policy, Security, Infrastructure, etc.)
- **Operations:** Per-securable-type actions (Read, Write, Execute, Delete, Approve, etc.)
- **Permissions:** Bind role + securable type + operation + allowed/denied

CRUD for all entities via management API and Settings UI. RBAC can be globally enabled/disabled. System roles cannot be deleted.

**Files:** `server/core/src/auth.cpp`, new `server/core/src/rbac.cpp`, `server/core/src/settings_ui.cpp`, `proto/yuzu/server/v1/management.proto`

### Issue 3.2: Management Groups
**Capabilities:** 19.4, 18.4, 16.3 | **Scope:** Server

Hierarchical device groups for scoping access, policies, and operations:
- Static membership (manual device assignment) or dynamic (scope expression evaluation)
- Nested hierarchy (parent/child groups)
- Role assignments scoped to management groups (Principal + Role + ManagementGroup triple)
- Policies assigned to management groups
- All list/query endpoints filter results by the caller's group visibility

CRUD via management API and dashboard UI.

**Files:** New `server/core/src/management_groups.cpp`, `server/core/src/server.cpp`, `server/core/src/rbac.cpp`, `proto/yuzu/server/v1/management.proto`

### Issue 3.3: Token-Based API Authentication
**Capability:** 18.7 | **Scope:** Server

API tokens for programmatic access alongside session cookies:
- Generate long-lived tokens with optional expiry
- Per-token scope (all operations, or restricted to specific instruction sets)
- Token passed via `Authorization: Bearer <token>` header or custom `X-Yuzu-Token` header
- Token CRUD in Settings UI (admin) and via management API
- Rate limiting per token

**Files:** `server/core/src/auth.cpp`, `server/core/src/server.cpp`, `server/core/src/settings_ui.cpp`

### Issue 3.4: OIDC / SSO Integration
**Capability:** 18.5 | **Scope:** Server

Replace the greyed-out SSO stub with a real OIDC flow:
- Configure IdP (issuer URL, client ID, client secret, redirect URI)
- Authorization code flow with PKCE
- Map OIDC claims to Yuzu principals and roles
- Session creation after successful OIDC authentication
- Support multiple IdPs (future)

**Files:** `server/core/src/auth.cpp`, `server/core/src/login_ui.cpp`, `server/core/src/server.cpp`, `server/core/src/settings_ui.cpp`

### Issue 3.5: REST / HTTP Management API (v1)
**Capability:** 24.3 | **Scope:** Server

Formalize the existing HTTP endpoints into a versioned REST API at `/api/v1/`:
- All entity CRUD follows consistent patterns: `GET /api/v1/{entity}`, `GET /api/v1/{entity}/{id}`, `POST /api/v1/{entity}`, `PUT /api/v1/{entity}/{id}`, `DELETE /api/v1/{entity}/{id}`, `POST /api/v1/{entity}/search`
- Search endpoint accepts filter expression tree, sort, start, pageSize
- JSON request/response bodies
- Authentication via session cookie or API token
- OpenAPI/Swagger spec generation

**Files:** `server/core/src/server.cpp`, new `server/core/src/rest_api.cpp`

### Issue 3.6: Device Quarantine (Network Isolation)
**Capabilities:** 9.6, 9.9 | **Scope:** Plugin + Server

New `quarantine` plugin:
- **QuarantineDevice:** Modify routing tables/hosts file to restrict networking to management channel only. Disable IPv6. Accept whitelist IPs.
- **UnquarantineDevice:** Restore original network config. Optional reboot.
- **GetQuarantineStatus:** Return current quarantine state.
- **ModifyQuarantineWhitelist:** Add IPs to whitelist of quarantined device.

Server-side: track quarantine state per device, history, and whitelist. Dashboard indicator for quarantined devices.

**Files:** New `agents/plugins/quarantine/`, `server/core/src/server.cpp`

### Issue 3.7: IOC Checking
**Capability:** 9.7 | **Scope:** Plugin

New `ioc` plugin or add to existing `security`-related plugin:
- **CheckSimpleIoc:** Match IP ranges, IP addresses, ports, domains, and file hashes against local endpoint state. Multiple parameters OR'd together.
- File spec checks done live; network checks use historical connection data (configurable lookback window, default 7 days).
- Cross-platform where data sources exist (Windows primary, Linux/macOS best-effort).

**Files:** New `agents/plugins/ioc/`

### Issue 3.8: Certificate Inventory and Management
**Capability:** 9.8 | **Scope:** Plugin

New `certificates` plugin:
- **GetCertificates:** Enumerate certificates in system stores. Return subject, issuer, thumbprint, dates, serial number, store name.
- **DeleteCertificates:** Remove certificate by thumbprint from specified store.
- Windows: CryptoAPI certificate store enumeration. Linux: `/etc/ssl/certs`. macOS: Keychain.

**Files:** New `agents/plugins/certificates/`

### Issue 3.9: Scope DSL Extensions (MATCHES, EXISTS, len, startswith)
**Scope:** Server

Add 4 operators to `scope_engine.cpp`: `MATCHES` (regex), `EXISTS` (tag presence), `len()` (string length), `startswith()` (prefix check). Parser architecture supports these without structural changes — add `TokenType` variants and `CompOp` cases. Design: `docs/Instruction-Engine.md` Section 8.2.

**Files:** `server/core/src/scope_engine.hpp`, `server/core/src/scope_engine.cpp`, `tests/unit/`

---

## Phase 4: Agent Infrastructure

*Agent-side capabilities that enable advanced features: persistent storage, content distribution, triggers, and user interaction.*

### Issue 4.1: Agent-Side Key-Value Storage :white_check_mark:
**Capabilities:** 23.1, 23.3 | **Scope:** Agent SDK + Plugin | **Status:** Done

Add persistent key-value storage to the agent, backed by the existing `agent.db` SQLite database:
- **Storage.Set:** Store a named table (overwrite or append with max row limit)
- **Storage.Get:** Retrieve by name
- **Storage.List:** List all table names
- **Storage.Delete:** Remove a table
- **Storage.Check:** Test if table exists

Expose via plugin SDK (new `yuzu_ctx_storage_*` functions in `plugin.h`) and as a built-in `storage` plugin.

**Files:** `sdk/include/yuzu/plugin.h`, `sdk/include/yuzu/plugin.hpp`, `agents/core/src/agent.cpp`, new `agents/plugins/storage/`

### Issue 4.2: HTTP Download and Upload (Agent-Initiated) :white_check_mark:
**Capabilities:** 13.3, 13.4, 10.13 | **Scope:** Plugin + Agent | **Status:** Done

New `http` plugin or extend agent core:
- **HttpGetFile:** Download file from URL with hash/size verification. Support both server content channel and external URLs. Return temp file path (cleaned up after instruction).
- **HttpPost:** Send data to external endpoint. Support custom headers, content types, authorization. Return status code and response body.
- **FileUpload:** Upload file from endpoint to server (reverse of HttpGetFile). Streaming upload for large files.

**Files:** New `agents/plugins/http_client/`, `server/core/src/server.cpp` (file receive endpoint)

### Issue 4.3: Content Staging and Execution :white_check_mark:
**Capabilities:** 13.1, 13.2 | **Scope:** Agent + Server | **Status:** Done

Server-to-agent content distribution:
- **Stage:** Server pushes content manifest, agent downloads files to local staging directory. Verify integrity via hash.
- **StageAndExecute:** Download to temp directory, execute command, clean up. Return exit code and output.

Server side: content repository for hosting files, manifest generation, and download tracking.

**Files:** New `agents/plugins/content_dist/`, `server/core/src/server.cpp` (content hosting endpoints)

### Issue 4.4: Agent Sleep and Stagger Control :white_check_mark:
**Capability:** 1.6 | **Scope:** Agent | **Status:** Done

- **Sleep:** Server instructs agent to pause for N seconds (testing/maintenance).
- **Stagger:** Agent introduces random delay (0 to N seconds) before executing an instruction, preventing thundering herd on broadcast. Configurable default stagger range.

Implement as built-in agent behavior (not a plugin), triggered by fields in `CommandRequest`.

**Files:** `agents/core/src/agent.cpp`, `proto/yuzu/agent/v1/agent.proto`

### Issue 4.5: Trigger Framework (Agent-Side) :white_check_mark:
**Capabilities:** 17.1-17.6 | **Scope:** Agent SDK + Agent Core | **Status:** Done

Add a trigger evaluation engine to the agent:
- **Plugin SDK extension:** New `yuzu_register_trigger` function in `plugin.h` for plugins to register trigger handlers.
- **Trigger types:**
  - `interval`: Timer-based (configurable seconds/minutes/hours, min 30s)
  - `file_change`: Filesystem watcher (inotify on Linux, FSEvents on macOS, ReadDirectoryChangesW on Windows)
  - `directory_change`: Recursive directory monitoring
  - `service_status_change`: React to service start/stop/crash (Windows SCM, systemd on Linux)
  - `event_log`: React to Windows Event Log entries matching XPath filter
  - `agent_startup`: Fire on agent boot
- **Debouncing:** Configurable debounce window to coalesce rapid events.
- **Trigger templates:** Server-defined trigger configurations pushed to agents.

Triggers invoke a callback (plugin action + params) when they fire. Used by the policy engine.

**Files:** `sdk/include/yuzu/plugin.h`, `sdk/include/yuzu/plugin.hpp`, `agents/core/src/agent.cpp`, new `agents/core/src/trigger_engine.cpp`

### Issue 4.6: Desktop User Interaction (Windows) :white_check_mark:
**Capabilities:** 14.1-14.3 | **Scope:** Plugin | **Status:** Done

New `interaction` plugin (Windows-only initially):
- **ShowNotification:** Toast notification (Information/Warning/Error) with configurable timeout. Returns immediately.
- **ShowAnnouncement:** Modal dialog with description, optional icon, choices, and default buttons (Later/Dismiss). Sync or async.
- **ShowQuestion:** Yes/No dialog with customizable button text. Sync or async.
- Async mode: returns immediately, response delivered via topic when user interacts.
- Target specific user session or all sessions.

**Files:** New `agents/plugins/interaction/`

### Issue 4.7: Agent Logging and Remote Log Retrieval :white_check_mark:
**Capability:** 1.7 | **Scope:** Agent + Plugin | **Status:** Done

Extend the `diagnostics` plugin:
- **GetKeyFiles:** Return paths to config, executable, log, data directory, temp directory.
- **SetLogLevel:** Dynamically change agent log level without restart.
- **GetLog:** Retrieve last N lines of agent log (or by time range). Stream large logs.

**Files:** `agents/plugins/diagnostics/src/diagnostics_plugin.cpp`, `agents/core/src/agent.cpp`

### Issue 4.8: service.set_start_mode Cross-Platform Primitive :white_check_mark:
**Scope:** Plugin | **Status:** Done

Add `set_start_mode` action to the `services` plugin. Parameters: `serviceName`, `mode` (automatic/manual/disabled/masked). Cross-platform: Windows `ChangeServiceConfigW`, Linux `systemctl enable/disable/mask`, macOS `launchctl enable/disable`. `masked` maps to `disabled` with warning on non-Linux. Returns previous/new/effective mode. Design: `docs/Instruction-Engine.md` Section 16.

**Files:** `agents/plugins/services/src/services_plugin.cpp`

---

## Phase 5: Policy Engine and Compliance

*Desired-state policies with trigger-based evaluation and auto-remediation.*

### Issue 5.1: Policy Rules and Fragments :white_check_mark:
**Capabilities:** 16.1, 16.2 | **Scope:** Server + Agent | **Status:** Done

Core policy engine:
- **Fragments:** Reusable compliance check/fix code blocks. Each fragment defines a check instruction (evaluate state) and optional fix instruction (remediate). Parameters are configured when rules are created.
- **Rules:** Bind a fragment to one or more triggers. Rule types: Check (evaluate only) or Fix (evaluate + remediate). Status codes: Received, CheckErrored, CheckFailed, CheckPassed, FixErrored, FixPassed, FixFailed.
- **Agent-side evaluation:** Rules evaluate on trigger fire, agent startup, and initial receipt. De-bounce prevents rapid re-evaluation.
- **Server-side management:** CRUD for fragments and rules via management API.

**Files:** New `server/core/src/policy_engine.cpp`, `agents/core/src/agent.cpp`, `proto/yuzu/agent/v1/agent.proto` (policy push/status RPCs)

### Issue 5.2: Policy Assignment and Deployment :white_check_mark:
**Capabilities:** 16.3, 16.8 | **Scope:** Server | **Status:** Done

- Policies are assigned to management groups (from Issue 3.2)
- Changes accumulate as pending; admin explicitly deploys
- Deployment compiles the policy document, hashes it, and pushes to agents
- Agents pull policy on next connection or receive push notification
- Pending changes review UI in dashboard

**Files:** `server/core/src/policy_engine.cpp`, `server/core/src/server.cpp`, dashboard UI updates

### Issue 5.3: Compliance Dashboard and Statistics :white_check_mark:
**Capabilities:** 16.4, 16.5 | **Scope:** Server | **Status:** Done

- Device compliance status per policy and per rule
- Fleet-wide compliance posture summary (% compliant, % non-compliant, % unknown)
- Rule evaluation history (chronological log with status changes)
- Effectiveness metrics: time to compliance, remediation success rate
- Dashboard UI: compliance tab with drill-down from fleet → policy → rule → device

**Files:** `server/core/src/policy_engine.cpp`, `server/core/src/dashboard_ui.cpp`, `server/core/src/server.cpp`

### Issue 5.4: Policy Cache Invalidation and Force Re-Evaluation :white_check_mark:
**Capabilities:** 16.7 | **Scope:** Agent + Server | **Status:** Done

- **Invalidate:** Reset agent's policy to empty; agent re-downloads on next connection.
- **ForceStatusReport:** Schedule a full compliance status report on next agent restart.
- Expose both as actions dispatchable from the dashboard.

**Files:** `agents/core/src/agent.cpp`, `server/core/src/server.cpp`

### Issue 5.5: CEL Adoption for Policy Compliance Expressions :white_check_mark:
**Scope:** Server | **Status:** Done
**Depends on:** 5.1

Adopt [Common Expression Language (CEL)](https://github.com/google/cel-spec) for typed policy evaluation. CEL handles `spec.compliance.expression`, `spec.fix.when`, and `spec.rollout.condition` — typed evaluation that the scope DSL cannot do. The scope DSL stays for device targeting. abseil is already a transitive dep via gRPC, making cel-cpp a natural addition. Design: `docs/Instruction-Engine.md` Section 8.3.

**Files:** `vcpkg.json`, new `server/core/src/cel_evaluator.cpp`, `server/core/src/policy_engine.cpp`

---

## Phase 6: Windows Platform Depth

*Registry, WMI, per-user operations, and Windows-specific advanced capabilities.*

### Issue 6.1: Registry Plugin (Read/Write/Enumerate) :white_check_mark:
**Capabilities:** 12.4-12.6 | **Scope:** Plugin | **Status:** Done

New `registry` plugin (Windows-only):
- **GetValue:** Read registry value by hive/subkey/name. Return name, type, data.
- **SetValue:** Write registry value. Support REG_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_EXPAND_SZ, REG_MULTI_SZ.
- **DeleteKey / DeleteValue:** Remove registry keys or values.
- **KeyExists / ValueExists:** Check existence.
- **EnumerateKeys / EnumerateValues:** Recursive listing.

All operations support HKLM, HKCU, HKCR, HKU hives.

**Files:** New `agents/plugins/registry/`

### Issue 6.2: Per-User Registry Operations :white_check_mark:
**Capability:** 12.7 | **Scope:** Plugin | **Status:** Done

Extend the registry plugin with per-user variants:
- Load each user's NTUSER.DAT hive
- Enumerate/get/set/delete across all user hives
- Dedicated methods: `EnumerateUserKeys`, `GetUserValues`, `SetUserValues`, `DeleteUserKey`, `DeleteUserValues`

**Files:** `agents/plugins/registry/src/registry_plugin.cpp`

### Issue 6.3: WMI Query and Method Invocation :white_check_mark:
**Capabilities:** 12.1, 12.2 | **Scope:** Plugin | **Status:** Done

New `wmi` plugin (Windows-only):
- **RunWmiQuery:** Execute WQL query against any WMI namespace. Return structured tabular results.
- **RunWmiInstanceMethod:** Call instance method on a WMI object.
- **RunWmiStaticMethod:** Call static method on a WMI class.
- COM initialization with proper cleanup. Structured output (not raw PowerShell text).

**Files:** New `agents/plugins/wmi/`

### Issue 6.4: Per-User Application Inventory :white_check_mark:
**Capability:** 7.5 | **Scope:** Plugin | **Status:** Done

Extend `installed_apps` plugin:
- Enumerate per-user installations from HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall for each user profile.
- Distinguish system-wide from user-specific installs in output.

**Files:** `agents/plugins/installed_apps/src/installed_apps_plugin.cpp`

### Issue 6.5: File System Advanced Operations :white_check_mark:
**Capabilities:** 10.7-10.10, 10.14, 10.15 | **Scope:** Plugin | **Status:** Done

Extend the `filesystem` plugin:
- **GetFilePermissions:** ACL enumeration (Windows DACL, POSIX permissions)
- **GetDigitalSignature:** Authenticode/codesign verification (Windows WinVerifyTrust, macOS codesign)
- **GetVersionInfo:** PE version resource extraction (Windows)
- **FindAndReplace / FindAndDelete / WriteText / AppendText:** Text file manipulation operations
- **FindFileBySizeAndHash:** Locate files matching both size and hash criteria
- **FindDirectoryByName:** Find directories by name pattern

**Files:** `agents/plugins/filesystem/src/filesystem_plugin.cpp`

### Issue 6.6: Registry Change Trigger :white_check_mark:
**Capability:** 17.5 | **Scope:** Agent | **Status:** Done

Add `registry_change` trigger type to the trigger framework (Issue 4.5):
- Monitor HKLM or HKCR subkeys using Windows Registry change notification APIs
- Optional recursive monitoring of subkeys
- Used by the policy engine to react to registry modifications

**Files:** `agents/core/src/trigger_engine.cpp`

---

## Phase 7: Scale, Integration, and Advanced Features

*Multi-node architecture, external integrations, and remaining advanced/future capabilities.*

### Issue 7.1: Gateway Node Implementation
**Capability:** 22.5 | **Scope:** Erlang gateway (`gateway/`)

The Erlang gateway (`gateway/`) implements the command fanout plane. Core proxy
functionality (Register, Subscribe, Heartbeat batching, Inventory, StreamStatus)
is implemented. See `docs/erlang-gateway-blueprint.md`.

Remaining work:
- Proxy agent registrations to upstream server — **done**
- Batch heartbeats (reduce connection count on server) — **done**
- Proxy subscribe streams — **done**
- Report stream status to upstream — **done**
- Gateway handles local TLS termination — **done**
- Deploy at branch offices to reduce WAN traffic

**Files:** `gateway/` (Erlang/OTP, rebar3), `proto/yuzu/gateway/v1/gateway.proto`, `server/core/src/server.cpp` (GatewayUpstream handlers)

### Issue 7.1.1: Gateway Adjacency, Load Shedding, and Latency-Based Redistribution
**Capability:** 22.5 | **Scope:** Erlang gateway (`gateway/`)
**Depends on:** 7.1

Implement cluster-aware agent redistribution so gateway nodes can dynamically
balance agent load based on measured latency and node capacity:

- **Adjacency table** — each node tracks peer agent count, CPU/memory, inter-node RTT, drain state
- **Load shedding** — shed agents via GOAWAY when overloaded, draining, or rebalancing for a new node; rate-limited to prevent reconnection storms
- **Agent absorption** — accept reconnecting agents; optionally pull agents from overloaded peers
- **Latency-based redistribution** — measure agent↔node RTT from heartbeats, compute affinity scores, migrate agents to lower-latency peers when improvement exceeds threshold
- **Stability** — cooldown window and hysteresis to prevent oscillation
- **Telemetry** — adjacency updates, shed/absorb counts, migration decisions exposed as Prometheus metrics

**Design:** `docs/erlang-gateway-blueprint.md` § "Gateway Adjacency and Latency-Based Agent Redistribution"

**Files:** `gateway/apps/yuzu_gw/src/yuzu_gw_cluster.erl` (new), `gateway/apps/yuzu_gw/src/yuzu_gw_agent.erl`, `gateway/apps/yuzu_gw/src/yuzu_gw_telemetry.erl`

### Issue 7.2: System Health Monitoring and Statistics
**Capabilities:** 22.1, 22.6, 22.2 | **Scope:** Server

- **Health endpoint:** CPU, memory, connection counts, queue depths, per-component health
- **Statistics:** High-level (connected devices, in-flight instructions, pending approvals) and detailed (per-definition execution counts, response rates)
- **Topology:** Map of server nodes, gateways, and agent counts
- Expose via REST API and dashboard UI

**Files:** `server/core/src/server.cpp`, new `server/core/src/system_health.cpp`

### Issue 7.3: Runtime Configuration API
**Capability:** 22.4 | **Scope:** Server

Expose server configuration via REST API (no restart required for supported settings):
- `MaxInstructionTtlMinutes`, `MaxResponseTtlMinutes`, `MaxSimultaneousInFlightInstructions`
- Heartbeat interval range
- Session timeout
- NVD sync interval

Read-only for most settings initially; writable for operational tuning params.

**Files:** `server/core/src/server.cpp`, REST API endpoints

### Issue 7.4: System Notifications
**Capability:** 21.3 | **Scope:** Server

Server-generated alerts for:
- System health warnings (high CPU, low disk, connection limits approaching)
- License expiry warnings
- Agent enrollment surge
- Per-instruction and per-component notifications

Notification store with CRUD, filtering, and search. Dashboard notification bell.

**Files:** New `server/core/src/notifications.cpp`, `server/core/src/dashboard_ui.cpp`

### Issue 7.5: Active Directory / Entra Integration
**Capability:** 18.6 | **Scope:** Server

Replace the greyed-out AD/Entra section:
- LDAP/LDAPS connection to AD
- Import users and security groups as principals
- Map AD group membership to Yuzu roles
- Periodic sync for membership changes
- Entra ID (Azure AD) support via Microsoft Graph API

**Files:** `server/core/src/auth.cpp`, `server/core/src/settings_ui.cpp`, new `server/core/src/directory_sync.cpp`

### Issue 7.6: Custom Properties on Devices
**Capability:** 19.6 | **Scope:** Server

Extensible typed metadata on devices:
- **Custom property types:** Define name, data type (string, int, bool, datetime), validation
- **Custom property values:** Set/get per device
- Usable in scope expressions for targeting
- CRUD via management API and dashboard

**Files:** `server/core/src/server.cpp`, `proto/yuzu/server/v1/management.proto`

### Issue 7.7: Agent Deployment Jobs
**Capability:** 19.7 | **Scope:** Server

Server-initiated agent installation on discovered endpoints:
- Store installer binaries per OS/arch
- Create deployment jobs targeting IP/FQDN lists with credentials
- Job management: status tracking, cancellation, retry
- Supported OS enumeration

**Files:** New `server/core/src/deploy.cpp`, `server/core/src/server.cpp`

### Issue 7.8: Patch Deployment Workflow
**Capabilities:** 8.3-8.8 | **Scope:** Plugin + Server

New `patch` plugin and server-side patch management:
- **Plugin (agent-side):** Deploy patch (download + install), get status, test patch server connection, restart with notification
- **Server-side:** Patch metadata retrieval (KB details, severity, supersedence), per-device compliance tracking, fleet-wide compliance dashboard, deployment orchestration with reboot control

**Files:** New `agents/plugins/patch/`, `server/core/src/server.cpp`

### Issue 7.9: Product Packs (Bundled Definitions)
**Capability:** 22.8 | **Scope:** Server

Import/export bundles of instruction definitions, policy fragments, trigger templates:
- ZIP format containing definition files
- Upload via management API or dashboard
- Automatic instruction set creation
- Version tracking and conflict resolution

**Files:** `server/core/src/instruction_store.cpp`, `server/core/src/server.cpp`

### Issue 7.10: User Sessions and Group Membership Plugins
**Capabilities:** 6.2-6.5 | **Scope:** Plugin

Extend the `users` plugin:
- **GetPrimaryUser:** Heuristic-based primary user detection (most frequent login, console owner)
- **GetLocalGroupMembers:** Enumerate members of local groups (Administrators, Remote Desktop Users, etc.)
- **GetInboundConnectionHistory:** Login/logout and RDP session audit trail
- **GetActiveSessions:** RDP, console, SSH sessions with state

**Files:** `agents/plugins/users/src/users_plugin.cpp`

### Issue 7.11: Advanced User Interaction (Surveys, DND)
**Capabilities:** 14.4-14.6 | **Scope:** Plugin

Extend the `interaction` plugin (Issue 4.6):
- **ShowSurvey:** Multi-question form with customizable choices, icons, free-text option, and response aggregation. Unique survey names prevent repeat display. Response validity period.
- **SetDoNotDisturb:** Suppress notifications for N minutes.
- **GetActiveResponses:** List pending survey/question responses.

**Files:** `agents/plugins/interaction/src/interaction_plugin.cpp`

### Issue 7.12: Event Subscriptions (Webhooks)
**Capabilities:** 21.4, 21.5, 16.6 | **Scope:** Server

Push events to external systems:
- Webhook endpoints (HTTP POST with event payload)
- Event source configuration (which events trigger notifications)
- Management-group-scoped subscriptions
- Policy compliance change events
- Retry with exponential backoff

**Files:** New `server/core/src/event_subscriptions.cpp`, `server/core/src/server.cpp`

### Issue 7.13: ProductPack Ed25519 Trust Chain and Verification
**Scope:** Server
**Depends on:** 7.9

Implement Ed25519-based signing, 3-level key hierarchy (org root → signing key → manifest), and verification pipeline for ProductPacks. `tar.zst` format with `manifest.json` (per-file SHA-256), `manifest.sig`, `signing-key.der`. JSON revocation list. Server config: `require_signed`, `allow_self_signed`, `trust_store_path`. Self-signing CLI for dev. Design: `docs/Instruction-Engine.md` Section 13.

**Files:** New `server/core/src/pack_signing.cpp`, `server/core/src/instruction_store.cpp`, `server/core/src/server.cpp`

### Issue 7.14: Workflow Primitives (if, foreach, retry)
**Scope:** Server
**Depends on:** 2.5, 2.12

Server-side orchestration: `workflow.if` (branch on expression), `workflow.foreach` (iterate result rows, dispatch child per row), `workflow.retry` (retry with backoff). Compose existing InstructionDefinitions — no new execution semantics. Uses `Execution.parent_id` for linking. Design: `docs/Instruction-Engine.md` Section 7.9.

**Files:** New `server/core/src/workflow_engine.cpp`, `server/core/src/execution_tracker.cpp`, `server/core/src/instruction_store.cpp`

### Issue 7.15: WiFi Network Enumeration
**Capability:** 4.6 | **Scope:** Plugin

List visible SSIDs (signal, security, channel, BSSID) and saved WiFi profiles. Windows: WlanAPI. Linux: NetworkManager D-Bus / `nmcli`. macOS: CoreWLAN.

**Files:** `agents/plugins/network_config/src/network_config_plugin.cpp` or new `agents/plugins/wifi/`

### Issue 7.16: Wake-on-LAN Support
**Capability:** 4.7 | **Scope:** Plugin + Server

Send WoL magic packets from server or agent (peer wake for same-subnet). Check WoL adapter status. Windows: WMI. Linux: `ethtool`. macOS: `pmset`.

**Files:** `agents/plugins/network_actions/src/network_actions_plugin.cpp`, `server/core/src/server.cpp`

### Issue 7.17: Inventory Table Enumeration and Item Lookup
**Capabilities:** 15.3, 15.4 | **Scope:** Agent SDK + Server

`inventory.list_tables` — enumerate available data sources per plugin. `inventory.query` — query a table with optional filter, column subset, limit. Plugins declare tables via SDK. Server caches and exposes via REST.

**Files:** `sdk/include/yuzu/plugin.h`, `agents/core/src/agent.cpp`, `server/core/src/server.cpp`

### Issue 7.18: Device Discovery (Unmanaged Endpoints)
**Capability:** 19.5 | **Scope:** Plugin + Server

Discover unmanaged endpoints via agent-assisted subnet scanning (ARP, mDNS, ICMP), AD/DHCP import, or CSV upload. Server reconciles against registered agents: managed, unmanaged, or stale. Dashboard coverage view with deployment link (Issue 7.7).

**Files:** New `agents/plugins/discovery/`, new `server/core/src/device_discovery.cpp`, `server/core/src/server.cpp`

### Issue 7.20: MCP Server (Model Context Protocol) Phase 1 :white_check_mark:
**Capabilities:** 24.8, 24.9, 24.10 | **Scope:** Server | **Status:** Done
**Depends on:** 3.3, 3.5

Embedded MCP server at `POST /mcp/v1/` using JSON-RPC 2.0 transport. Enables AI models (e.g., Claude Desktop) to query fleet status and investigate endpoints. Phase 1 delivers 22 read-only tools, 3 resources, and 4 prompts. Three authorization tiers (readonly, operator, supervised) enforced before RBAC. MCP tokens use the existing API token system with an `mcp_tier` column and mandatory expiration (max 90 days). Kill switch: `--mcp-disable`, `--mcp-read-only`. Settings UI section with enable/disable and read-only toggles. Audit logging on every tool call (`action: "mcp.<tool_name>"`).

**Files:** `server/core/src/mcp_server.hpp`, `server/core/src/mcp_server.cpp`, `server/core/src/mcp_jsonrpc.hpp`, `server/core/src/mcp_policy.hpp`, `server/core/src/server.cpp`, `server/core/src/settings_ui.cpp`

---

## Phase 8: Visualization & Response Experience

*Make collected data actionable with charts, templates, and processing pipelines.*

### Issue 8.1: Response Visualization Engine :white_check_mark:
**Capabilities:** 20.6 (partial), new | **Scope:** Server | **Status:** Done

Server-side chart rendering for instruction responses. `spec.visualization` (singular) or `spec.visualizations` (canonical plural for multi-chart) on `InstructionDefinition`. Five chart types (`pie`, `bar`, `column`, `line`, `area`) × three processors (`single_series`, `multi_series`, `datetime_series`) with camelCase fields (`labelField`, `valueField`, `seriesField`, `xField`, `yField`, `maxCategories`, `valueLabel`); snake_case forms accepted as deprecated aliases. REST: `GET /api/v1/executions/{id}/visualization?definition_id=<id>&index=<N>` gated on `Response:Read`. Dashboard auto-renders a chart deck above the results table by reverse-resolving the dispatched `(plugin, action)` to a chart-bearing definition (`InstructionDefinition:Read` required for chart to appear). Renderer is Apache ECharts 5 (vendored at `server/core/vendor/echarts.min.js`, served at `/static/echarts.min.js`) wrapped by a thin adapter at `/static/yuzu-charts.js` that maps the visualization payload onto ECharts options and reads Yuzu design tokens (`--mds-color-chart-*`) for theming, so re-skinning Yuzu re-skins every chart with no JS rebuild. Engine row cap 10 000 with `rows_capped: true` flag; label cardinality cap 10 000.

Six demo charts ship as default examples — `content/definitions/visualization_demo_set.yaml` (`InstructionSet demo.visualization.fleet-posture`) and `content/packs/visualization-demo-pack.yaml` (`ProductPack pack.demo.visualization`) — covering vulnerability severity (the headline pie), Defender real-time protection, disk encryption protection state, firewall state per profile (multi-series column), certificate issuer breakdown (top-N + Other), and OS distribution.

**Files:** `server/core/src/visualization_engine.{hpp,cpp}`, `server/core/src/charts_js_bundle.cpp`, `server/core/src/instruction_store.{hpp,cpp}` (visualization_spec column + MigrationRunner v2), `server/core/src/rest_api_v1.cpp`, `server/core/src/dashboard_routes.{hpp,cpp}`, `docs/yaml-dsl-spec.md` § `spec.visualization`, `docs/user-manual/instructions.md` § Response Visualization, plus `tests/unit/server/test_visualization_engine.cpp` and `tests/unit/server/test_rest_visualization.cpp`.

### Issue 8.2: Response Templates
**Capability:** 20.6 | **Scope:** Server | **Status:** Open
**Depends on:** 8.1

Named response view configurations:
- Column selection, sort order, filter presets stored per InstructionDefinition in `spec.responseTemplates`
- Default template auto-generated from result schema
- Template CRUD via REST API
- Dashboard: template selector dropdown in execution results view

**Files:** `server/core/src/instruction_store.cpp`, `server/core/src/rest_api_v1.cpp`

### Issue 8.3: Response Offloading (Data Export Streams)
**Capability:** 20.7 | **Scope:** Server | **Status:** Open

Configure external HTTP endpoints to receive response data in real time:
- `OffloadTarget` model: URL, auth (bearer/basic/HMAC), event filter, batch size
- Fire-and-forget delivery on background thread (reuse WebhookStore pattern)
- Per-instruction override: `spec.offload.target` in YAML
- REST: `GET/POST/DELETE /api/v1/offload-targets`

**Files:** New `server/core/src/offload_target_store.cpp`, `server/core/src/rest_api_v1.cpp`

---

## Phase 9: Connector Framework & Multi-Source Inventory

*Federate inventory data from external management systems. Core enterprise integration capability.*

### Issue 9.1: Connector Framework (Core)
**Capability:** new | **Scope:** Server | **Status:** Open

Pluggable connector architecture for bidirectional data sync with external systems:
- `ConnectorStore` (SQLite): connector type, name, config (encrypted credentials), schedule, status
- `ConnectorEngine`: background sync with pluggable connector implementations
- Connector interface:
  ```cpp
  class Connector {
  public:
      virtual std::string type() const = 0;
      virtual SyncResult sync(const ConnectorConfig& config, InventoryRepository& repo) = 0;
      virtual ConnectionTestResult test(const ConnectorConfig& config) = 0;
  };
  ```
- Sync lifecycle: NotStarted → Pending → InProgress → Completed/Failed/Cancelled
- REST: `GET/POST/PUT/DELETE /api/v1/connectors`, `POST .../sync`, `POST .../test`
- Dashboard: Connectors page in Settings with add/edit/delete/test/sync actions

**Files:** New `server/core/src/connector_store.cpp`, `server/core/src/connector_engine.cpp`, `server/core/src/settings_routes.cpp`

### Issue 9.2: Inventory Repository Model
**Capability:** new | **Scope:** Server | **Status:** Open
**Depends on:** 9.1

Named repositories for partitioned inventory data:
- `RepositoryStore` (SQLite): named repositories per type (inventory, compliance, entitlement)
- Default repository created on first boot (cannot be deleted)
- Connectors bound to repositories; multiple connectors per repository
- Consolidation, deduplication, normalization pipeline
- Repository types: Inventory, Compliance, Entitlement (extensible)
- REST: `GET/POST/PUT/DELETE /api/v1/repositories`

**Files:** New `server/core/src/repository_store.cpp`, `server/core/src/rest_api_v1.cpp`

### Issue 9.3: SCCM / ConfigMgr Connector
**Capability:** new | **Scope:** Server | **Status:** Open
**Depends on:** 9.1

SQL query against ConfigMgr database:
- Hardware inventory (Win32_ComputerSystem, Win32_OperatingSystem, etc.)
- Software inventory (installed applications, MSI packages)
- User/device associations
- Patch compliance data
- Configuration: database server, instance, auth (Windows/SQL login)

**Files:** New `server/core/src/connectors/sccm_connector.cpp`

### Issue 9.4: Intune Connector
**Capability:** new | **Scope:** Server | **Status:** Open
**Depends on:** 9.1

Microsoft Graph API integration (`/deviceManagement/managedDevices`):
- Device inventory (hardware, OS, compliance state)
- Installed applications
- Configuration profiles and compliance policies
- OAuth2 client credentials flow (reuse DirectorySync Graph client)

**Files:** New `server/core/src/connectors/intune_connector.cpp`

### Issue 9.5: ServiceNow Connector
**Capability:** new | **Scope:** Server | **Status:** Open
**Depends on:** 9.1

ServiceNow REST API (Table API) integration:
- CMDB CI records (cmdb_ci_computer, cmdb_ci_server)
- Incidents and change requests (optional)
- User/group import
- OAuth2 or basic auth

**Files:** New `server/core/src/connectors/servicenow_connector.cpp`

### Issue 9.6: WSUS Connector
**Capability:** new | **Scope:** Server | **Status:** Open
**Depends on:** 9.1

SQL query against WSUS database:
- Update approval status
- Per-device patch compliance
- Update metadata (KB, severity, classification)
- Configuration: database server, instance, auth

**Files:** New `server/core/src/connectors/wsus_connector.cpp`

### Issue 9.7: CSV / File Upload Connector
**Capability:** new | **Scope:** Server | **Status:** Open
**Depends on:** 9.1

Import inventory data from structured files:
- Parse TSV/CSV with configurable column mapping
- Upload via REST API or dashboard file picker
- Validation and error reporting per row
- Scheduling support for automated file ingestion from watched directories

**Files:** New `server/core/src/connectors/file_upload_connector.cpp`

### Issue 9.8: Inventory Consolidation & Normalization
**Capability:** new | **Scope:** Server | **Status:** Open
**Depends on:** 9.2

Multi-source inventory cleanup pipeline:
- Deduplication by device identity (hostname + MAC + serial)
- Software normalization: vendor/title/version canonicalization
- Hardware normalization: processor model mapping, VM detection
- Consolidation reports: matched vs. unmatched, normalization coverage percentage
- Runs after each connector sync or on-demand via REST

**Files:** New `server/core/src/inventory_consolidation.cpp`, `server/core/src/repository_store.cpp`

---

## Phase 10: Software Catalog & License Compliance

*Normalized software identification for license management and compliance reporting.*

### Issue 10.1: Software Catalog Store
**Capability:** new | **Scope:** Server | **Status:** Open
**Depends on:** 9.8

Canonical software registry:
- `CatalogStore` (SQLite): normalized software entries (vendor, title, version, edition, platform)
- Catalog import from CSV/JSON
- Manual curation UI: merge duplicates, set canonical names, mark as ignored
- Automatic matching: raw inventory entries linked to catalog entries by fuzzy title/vendor
- REST: `GET/POST/PUT /api/v1/catalog/software`, `POST /api/v1/catalog/software/match`

**Files:** New `server/core/src/catalog_store.cpp`, `server/core/src/rest_api_v1.cpp`

### Issue 10.2: Software Usage Tracking
**Capability:** new | **Scope:** Agent + Server | **Status:** Open
**Depends on:** 10.1

Agent-side application usage metering:
- New `software_usage` agent plugin
- Track application launches, cumulative run time, last-used timestamp
- Categorize: Used (30d), Rarely Used (90d), Unused (>90d), Unreported
- Report via ReportInventory RPC
- Server-side aggregation: per-title usage across fleet
- Dashboard: usage summary with reclamation candidates

**Files:** New `agents/plugins/software_usage/`, `server/core/src/catalog_store.cpp`

### Issue 10.3: License Entitlements & Compliance
**Capability:** new | **Scope:** Server | **Status:** Open
**Depends on:** 10.1

License compliance calculation:
- Entitlement records: product, purchased_seats, license_type (per-device/per-user/site/enterprise)
- Compliance calculation: installed_count vs. entitled_count
- Over/under-licensed reporting per product
- REST: `GET/POST/PUT/DELETE /api/v1/entitlements`
- Dashboard: license compliance summary with drill-down

**Files:** New `server/core/src/entitlement_store.cpp`, `server/core/src/rest_api_v1.cpp`

### Issue 10.4: Software Tags
**Capability:** new | **Scope:** Server | **Status:** Open
**Depends on:** 10.1

Server-side tags on software catalog entries:
- Tag software titles for categorization (e.g., "approved", "prohibited", "eval")
- Used for Management Group rules ("devices with software tagged X")
- REST: `GET/POST/DELETE /api/v1/catalog/software/{id}/tags`
- Dashboard: tag management in catalog view

**Files:** `server/core/src/catalog_store.cpp`, `server/core/src/management_group_store.cpp`

---

## Phase 11: Consumer Model & Platform Extensibility

*Formalize third-party integration and provide client libraries for automation.*

### Issue 11.1: Consumer Application Registration
**Capability:** 24.4 | **Scope:** Server | **Status:** Open

Formal model for external systems consuming Yuzu data:
- `ConsumerStore` (SQLite): name, URL, max_concurrent_instructions, offload_target, enabled
- Consumers get scoped API tokens with rate limits
- Custom data field for consumer-specific metadata
- Consumer deploy: push instruction definitions and policies to specific consumers
- REST: `GET/POST/PUT/DELETE /api/v1/consumers`
- Dashboard: Consumers page in Settings

**Files:** New `server/core/src/consumer_store.cpp`, `server/core/src/settings_routes.cpp`

### Issue 11.2: Event Source Management
**Capability:** 21.5 | **Scope:** Server | **Status:** Open

Configure which system events generate notifications and webhook deliveries:
- Event source categories: agent_lifecycle, execution, compliance, security, system
- Per-category enable/disable with severity threshold
- Granular event type selection within each category
- REST: `GET/PUT /api/v1/event-sources`
- Dashboard: Event Sources section in Settings

**Files:** New `server/core/src/event_source_config.cpp`, `server/core/src/webhook_store.cpp`, `server/core/src/notification_store.cpp`

### Issue 11.3: PowerShell Module
**Capability:** 24.7 (partial) | **Scope:** External | **Status:** Open

`Yuzu.Management` PowerShell module wrapping REST API v1:
- Cmdlets: `Connect-YuzuServer`, `Get-YuzuAgent`, `Send-YuzuInstruction`, `Get-YuzuCompliance`, `Get-YuzuAuditLog`, `New-YuzuSchedule`, etc.
- Authentication: API token via `Connect-YuzuServer -Server <url> -Token <token>`
- Tab completion for instruction names, agent IDs, scope attributes
- Published to PowerShell Gallery

**Files:** New `sdk/powershell/`

### Issue 11.4: Python SDK
**Capability:** 24.7 (partial) | **Scope:** External | **Status:** Open

`yuzu-sdk` Python package wrapping REST API v1:
- Async support via httpx
- Typed models (dataclasses or Pydantic)
- Convenience methods: `client.agents.list()`, `client.instructions.execute()`, etc.
- Published to PyPI

**Files:** New `sdk/python/`

---

## Phase 12: Remaining Agent Capabilities

*Close all 19 "Not Started" items from the capability map to reach 100% coverage.*

### Issue 12.1: Mapped Drive History
**Capability:** 3.8 | **Scope:** Agent Plugin | **Status:** Open

New actions in `users` plugin: `mapped_drives`, `mapped_drive_history`.
- Windows: WMI `Win32_MappedLogicalDisk` + Event Log 4624/4634 for historical connections
- Returns: drive_letter, remote_path, username, timestamp, direction (inbound/outbound)

**Files:** `agents/plugins/users/src/users_plugin.cpp`

### Issue 12.2: Printer Inventory
**Capability:** 3.9 | **Scope:** Agent Plugin | **Status:** Open

New action in `hardware` plugin: `printers`.
- Windows: `EnumPrinters` API. Linux: CUPS `lpstat`. macOS: `lpstat`
- Returns: name, driver, port, status, shared, default, network/local

**Files:** `agents/plugins/hardware/src/hardware_plugin.cpp`

### Issue 12.3: Port Scanning
**Capability:** 4.11 | **Scope:** Agent Plugin | **Status:** Open

New action in `discovery` plugin: `scan_ports`.
- Parameters: target_ips (comma-separated), ports (range notation: "22,80,443,8000-8100")
- Non-blocking connect with configurable timeout (default 2s)
- Returns: ip, port, status (open/closed/filtered), service_guess

**Files:** `agents/plugins/discovery/src/discovery_plugin.cpp`

### Issue 12.4: NetBIOS Lookup
**Capability:** 4.9 | **Scope:** Agent Plugin | **Status:** Open

New action in `discovery` plugin: `netbios_lookup`.
- Parameters: ip_addresses (comma-separated)
- Send NetBIOS Name Query (UDP 137) and parse response
- Returns: ip, netbios_name, domain, mac_address

**Files:** `agents/plugins/discovery/src/discovery_plugin.cpp`

### Issue 12.5: Open Windows Enumeration
**Capability:** 5.5 | **Scope:** Agent Plugin | **Status:** Open

New action in `interaction` plugin: `list_windows` (Windows-only).
- `EnumWindows` + `GetWindowText` + `GetWindowThreadProcessId`
- Returns: hwnd, title, process_name, pid, visible, minimized

**Files:** `agents/plugins/interaction/src/interaction_plugin.cpp`

### Issue 12.6: Directory Hash (Recursive)
**Capability:** 10.11 | **Scope:** Agent Plugin | **Status:** Open

New action in `filesystem` plugin: `hash_directory`.
- Recursive SHA-256 of all file contents, sorted by relative path for deterministic output
- Returns: directory_hash, file_count, total_bytes, elapsed_ms

**Files:** `agents/plugins/filesystem/src/filesystem_plugin.cpp`

### Issue 12.7: Survey Dialog
**Capability:** 14.4 | **Scope:** Agent Plugin | **Status:** Open

Extend `interaction` plugin: `survey` action.
- Multi-question form: text input, single-choice, multi-choice, rating scale
- Windows: WinForms-style dialog. Linux: zenity --forms. macOS: osascript
- Unique survey name prevents repeat display. Response validity period.
- Returns: structured JSON response with question_id → answer mapping

**Files:** `agents/plugins/interaction/src/interaction_plugin.cpp`

### Issue 12.8: Do-Not-Disturb Mode
**Capability:** 14.5 | **Scope:** Agent Plugin | **Status:** Open

Extend `interaction` plugin: `set_dnd` / `get_dnd_status` actions.
- Suppress all notifications/dialogs for configurable duration
- Persisted in agent KV storage (survives restart)
- Returns: active (bool), expires_at (timestamp)

**Files:** `agents/plugins/interaction/src/interaction_plugin.cpp`

### Issue 12.9: Active Response Tracking
**Capability:** 14.6 | **Scope:** Agent Plugin | **Status:** Open

Extend `interaction` plugin: `list_pending` action.
- Returns all outstanding surveys/questions awaiting user input
- Includes: interaction_id, type, prompt, issued_at, timeout_at

**Files:** `agents/plugins/interaction/src/interaction_plugin.cpp`

### Issue 12.10: Patch Inventory Event Generation
**Capability:** 8.9 | **Scope:** Agent Plugin | **Status:** Open

Extend `windows_updates` plugin: `generate_inventory_events` action.
- Emit structured events for each installed/missing patch
- Feed into AnalyticsEventStore for SIEM/compliance integration
- Event format: patch_kb, status (installed/missing), severity, agent_id, timestamp

**Files:** `agents/plugins/windows_updates/src/windows_updates_plugin.cpp`

### Issue 12.11: Application Whitelisting
**Capability:** 9.10 | **Scope:** Agent Plugin | **Status:** Open

New `app_control` plugin:
- Windows: AppLocker policy query/modification via WMI or PowerShell
- Linux: fapolicyd rules (if available)
- Actions: `get_policy`, `add_rule`, `remove_rule`, `get_blocked_events`

**Files:** New `agents/plugins/app_control/`

### Issue 12.12: Inventory Replication (Delta Sync)
**Capability:** 15.5 | **Scope:** Agent + Server | **Status:** Open

Agent-side inventory cache with delta sync:
- Agent-side: inventory cache in SQLite KV store, track hash of last-sent inventory per plugin
- Server-side: track per-agent sync state (last_sync_at, inventory_hash)
- Only send changed inventory since last sync, reducing bandwidth for large fleets

**Files:** `agents/core/src/agent.cpp`, `server/core/src/inventory_store.cpp`

### Issue 12.13: Binary Resource Distribution
**Capability:** 22.7 | **Scope:** Server | **Status:** Open

Server-side resource registry for versioned binary blobs:
- Resource model: name, version, platform, hash, size, upload_at
- Agents pull resources by name + version with SHA-256 hash verification
- Used by instructions that need supporting files (scripts, configs, tools)
- REST: `GET/POST/DELETE /api/v1/resources`, `GET /api/v1/resources/{name}/{version}/download`

**Files:** New `server/core/src/resource_store.cpp`, `server/core/src/rest_api_v1.cpp`

---

## Phase 13: Security Hardening & Operational Polish

*Close remaining security gaps and improve operational UX.*

### Issue 13.1: 2FA for Instruction Approval (TOTP)
**Capability:** new | **Scope:** Server | **Status:** Open

TOTP (RFC 6238) second factor on instruction approval:
- Per-user TOTP secret stored encrypted in auth store
- QR code enrollment via Settings UI
- Approval endpoint requires `totp_code` parameter when 2FA is enabled for the user
- Fallback: email-based one-time code (requires SMTP configuration)
- Configurable: per-user opt-in or system-wide enforcement

**Files:** `server/core/src/approval_manager.cpp`, `server/core/src/auth.cpp`, `server/core/src/settings_routes.cpp`

### Issue 13.2: Composable Instruction Chains
**Capability:** new | **Scope:** Server | **Status:** Open
**Depends on:** 7.14 (Workflow Primitives)

Server-side multi-step instruction composition extending the WorkflowEngine:
- Variables from previous steps available via `${step_name.field}` interpolation
- CEL conditions for conditional step execution
- Result row iteration via `foreach` for fan-out patterns
- Provides composable instruction chaining without requiring an agent-side scripting language

**Files:** `server/core/src/workflow_engine.cpp`, `server/core/src/execution_tracker.cpp`

### Issue 13.3: Process / Sync Logging UI
**Capability:** new | **Scope:** Server | **Status:** Open

Dashboard page at `/monitoring` with operational log views:
- Tabs: Connector Sync Log, Scheduled Executions, Infrastructure Log
- Reuse existing AuditStore with category filtering
- HTMX fragments with 30s auto-refresh
- Status indicators, filtering by action type / status / time range

**Files:** New `server/core/src/monitoring_ui.cpp`, `server/core/src/dashboard_routes.cpp`

### Issue 13.4: Dashboard Branding
**Capability:** new | **Scope:** Server | **Status:** Open

White-label customization for enterprise deployments:
- `BrandingConfig`: logo_url, product_name, primary_color, accent_color
- Stored in RuntimeConfigStore (safe keys)
- Settings UI: branding section with live preview
- CSS variables for theme customization, applied globally

**Files:** `server/core/src/css_bundle.cpp`, `server/core/src/settings_routes.cpp`, `server/core/src/runtime_config_store.cpp`

### Issue 13.5: MCP Phase 2 (Write Tools)
**Capabilities:** 24.8 (extension) | **Scope:** Server | **Status:** Open
**Depends on:** 7.20 (MCP Phase 1)

6 write/execute tools for the MCP server:
- `set_tag`, `delete_tag` — device tag management
- `execute_instruction` — dispatch instruction to agents (operator/supervised tiers)
- `approve_request`, `reject_request` — approval workflow actions (supervised tier)
- `quarantine_device` — network isolation (supervised tier)
- Approval workflow integration for destructive operations
- SSE streaming for execution progress

**Files:** `server/core/src/mcp_server.cpp`, `server/core/src/mcp_policy.hpp`

---

## Phase 14: Scale & Enterprise Readiness

*Features needed for very large deployments (>100K devices) and enterprise-grade resilience.*

### Issue 14.1: P2P Content Distribution
**Capability:** 13.5 | **Scope:** Agent | **Status:** Open

Agent mesh for peer content sharing within subnets:
- Leader election via mDNS/broadcast within subnet
- Content announce/request protocol over UDP
- Cache management: LRU eviction, configurable max size
- Falls back to server download when no peers have content
- Bandwidth throttling to avoid network saturation

**Files:** New `agents/core/src/p2p_mesh.cpp`, `agents/plugins/content_dist/src/content_dist_plugin.cpp`

### Issue 14.2: Multi-Gateway Topology
**Capability:** 22.5 (extension) | **Scope:** Gateway + Server | **Status:** Open
**Depends on:** 7.1, 7.1.1

Server supports multiple concurrent gateway registrations:
- Gateway affinity: agents assigned to nearest gateway via latency probing
- Gateway failover: agents reconnect to alternate gateway on primary failure
- Topology view shows all gateways with agent counts and health status

**Files:** `server/core/src/agent_registry.cpp`, `server/core/src/gateway_service_impl.cpp`, `gateway/apps/yuzu_gw/src/yuzu_gw_cluster.erl`

### Issue 14.3: Database Sharding (Response Partitioning)
**Capability:** new | **Scope:** Server | **Status:** Open

Time-partitioned response storage for high-throughput environments:
- Response data partitioned by time (monthly SQLite files)
- Automatic file rotation and TTL cleanup
- Query router spans partitions transparently
- Reduces WAL contention for high-throughput response collection

**Files:** `server/core/src/response_store.cpp`

### Issue 14.4: vCenter Connector
**Capability:** new | **Scope:** Server | **Status:** Open
**Depends on:** 9.1

VMware vSphere API integration:
- Sync: VMs, ESXi hosts, datastores, clusters, resource pools
- VM-to-agent correlation via hostname or UUID
- Virtual summary reporting (physical hosts, guest count, density)

**Files:** New `server/core/src/connectors/vcenter_connector.cpp`

### Issue 14.5: Additional Connectors (BigFix, O365, Oracle)
**Capability:** new | **Scope:** Server | **Status:** Open
**Depends on:** 9.1

Extend the connector framework with additional integrations:
- **BigFix**: REST API integration for inventory and patch compliance sync
- **Office 365**: Microsoft Graph API for license and usage data
- **Oracle LMS**: Database query for Oracle deployment facts and licensing

**Files:** New `server/core/src/connectors/bigfix_connector.cpp`, `server/core/src/connectors/o365_connector.cpp`, `server/core/src/connectors/oracle_connector.cpp`

### Issue 14.6: High Availability (Active-Passive)
**Capability:** new | **Scope:** Server | **Status:** Open

Active-passive failover for server resilience:
- Shared SQLite over network filesystem (NFS/SMB) or replicated storage
- Heartbeat between primary and standby servers
- Automatic failover on primary health check failure
- Gateway re-registration on failover event

**Files:** New `server/core/src/ha_manager.cpp`, `server/core/src/server.cpp`

---

## Phase 15: TAR Dashboard & Scope Walking

*The differentiating operator experience. Composable scope from previous query results, surfaced in the dashboard and the YAML DSL, anchored on a dedicated TAR page that puts retention awareness, ad-hoc SQL, and process-tree forensics under one roof. The reference end-to-end walkthrough is the Chrome IR scenario in `docs/scope-walking-design.md` §10.*

### Issue 15.A: TAR Dashboard Page Shell + Retention-Paused Source List
**Capability:** new | **Scope:** Server (dashboard + REST) + TAR plugin (status extension) | **Status:** In progress

New `/tar` page off the main dashboard nav. First frame is the retention-paused source list — directly enabled by the issue #539 retention guard. Per-source `<source>_paused_at` timestamp added to `tar.status`, server aggregates per-device responses, dashboard renders a sortable filterable table with one-click re-enable and a typed-confirmation purge. Independent re-enable per source (the #539 invariant).

**Files:** `server/core/src/dashboard_routes.cpp`, `server/core/src/dashboard_ui.cpp`, `agents/plugins/tar/src/tar_plugin.cpp`, new `tests/unit/server/test_tar_dashboard_*`. Design: `docs/tar-dashboard.md` §3.

### Issue 15.B: Result-Set Store + REST API
**Capability:** new (foundational) | **Scope:** Server | **Status:** Open

`result_set_store.cpp` with new `result_sets.db`. Schema per `docs/scope-walking-design.md` §3 — immutable lineage edges, TTL with pin override, source payload JSON for live re-eval. REST: `POST /api/v1/result-sets`, `from-inventory-query`, `from-tar-query`, `from-instruction-result`, `GET .../{id}`, `.../{id}/members`, `.../{id}/lineage`, `pin` / `unpin` / `re-eval`, `DELETE`. Audit hooks per §9.

**Files:** new `server/core/src/result_set_store.{cpp,hpp}`, new `server/core/src/result_set_routes.cpp`, `migration_runner.cpp`. Design: `docs/scope-walking-design.md` §3, §6, §9.

### Issue 15.C: Scope Engine `from_result_set:` + Dashboard Chip + Sidebar + Breadcrumb
**Capability:** 1.6 (extension) | **Scope:** Server | **Status:** Open
**Depends on:** 15.B

Scope Engine grammar gains `from_result_set:<id-or-alias>` as a third short-circuit kind alongside `__all__` and `group:<name>`. Composes with attribute predicates via `AND`/`OR`/`NOT`. Dashboard sidebar lists active result sets (last_used_at then created_at DESC); chain breadcrumb above every query frame mirrors `parent_id` walks; scope chip surfaces in TAR / inventory / instruction frames.

**Files:** `server/core/src/scope_engine.{cpp,hpp}`, `server/core/src/dashboard_routes.cpp`, `server/core/src/dashboard_ui.cpp`. Design: `docs/scope-walking-design.md` §4, §8.

### Issue 15.D: TAR SQL Frame — Relocate, Scope-Walking-Aware, Save-as-Result-Set
**Capability:** new | **Scope:** Server | **Status:** Open
**Depends on:** 15.A, 15.B, 15.C

Relocate the existing `/fragments/tar-sql` route onto the TAR dashboard page. Wire scope-chip resolution to `from_result_set:` (15.C). Add "Save as result set" affordance on the results pane — server creates a new result set with `source_kind=tar_query`, members = union of agents that returned ≥1 row by default. Default name is `tar-<5-char-sql-hash>`.

**Files:** `server/core/src/dashboard_routes.cpp`, `server/core/src/agent_service_impl.cpp` (TAR result envelope to carry the producing agent IDs explicitly). Design: `docs/tar-dashboard.md` §4.

### Issue 15.E: YAML DSL `fromResultSet:` + `definition_store` Validation + Spec Amendment
**Capability:** new | **Scope:** Server (DSL) | **Status:** Open
**Depends on:** 15.B, 15.C

`scope:` block in `InstructionDefinition`, `InstructionSet`, `Policy` gains `fromResultSet:` as a mutually-exclusive (or composable-with-`selector:`) form. Validation: `fromResultSet + assignment.managementGroups` rejected at YAML load; `fromResultSet` requires `assignment.mode = static`. Resolution at instruction *invocation* time, not load time. Spec section in `docs/yaml-dsl-spec.md`.

**Files:** `server/core/src/definition_store.cpp`, `server/core/src/policy_store.cpp`, `docs/yaml-dsl-spec.md`. Design: `docs/scope-walking-design.md` §7.

### Issue 15.F: Reference Walkthrough — Chrome IR End-to-End Integration Test
**Capability:** new (regression net) | **Scope:** Tests | **Status:** Open
**Depends on:** 15.B, 15.C, 15.D, 15.E

`tests/integration/test_chrome_ir_chain.cpp` drives the full §10 walkthrough against a live UAT stack with synthetic agents. Asserts: each step's audit row carries `parent_result_set_id` and `result_result_set_id`; the resulting lineage chain is complete; pinning prevents mid-incident GC; the final un-quarantine + watch step terminates cleanly. The reference test for end-to-end correctness — when this passes, scope walking is real.

**Files:** `tests/integration/test_chrome_ir_chain.cpp`, supporting fixtures in `scripts/uat/synthetic-fleet.sh`. Design: `docs/scope-walking-design.md` §10.

### Issue 15.G: Operational Hardening — Live Re-Eval, GC Sweep, Prometheus + Audit Polish
**Capability:** new | **Scope:** Server | **Status:** Open
**Depends on:** 15.B

Live re-eval (`POST /api/v1/result-sets/{id}/re-eval`); background GC sweep every 5 min; per-operator 10K result-set quota + 50 pin cap with `429 RESULT_SET_QUOTA` / `409 PIN_LIMIT`; Prometheus metrics (`yuzu_result_sets_total`, `yuzu_result_sets_alive`, `yuzu_result_set_resolve_seconds` histogram, GC counter, quota-rejection counter); audit polish on every state transition.

**Files:** `server/core/src/result_set_store.cpp`, `server/core/src/result_set_routes.cpp`, `server/core/src/server.cpp`. Design: `docs/scope-walking-design.md` §3.3, §9.

### Issue 15.H: TAR Process Tree Viewer
**Capability:** new (forensic) | **Scope:** TAR plugin + Server (renderer) | **Status:** Open (gated on agent service-install hardening readiness)

`tar.process_tree` agent action walks `/proc` (Linux), `CreateToolhelp32Snapshot` + `Process32FirstW`/`NextW` (Windows), `proc_listallpids` + `proc_pidinfo(PROC_PIDTBSDINFO|PIDPATHINFO)` (macOS). Stores tagged `action='seed'` rows in `process_live` per PID. Server reconstructs the tree by replaying seed + subsequent `started` / `stopped` events from `process_live`. Renderer: collapsible nested `<details>` / `<summary>` for v1, no graph library. Time-slicing via `?as_of=<ts>`. Honest "tree as observed since <seed_ts>" badge; orphan reparenting shown as it would be in a live `ps`. Cmdline redaction reuses `tar_plugin.cpp` `load_redaction_patterns`.

Data quality depends on the agent running from boot/install and being tamper-resistant — that hardening pillar is the parallel Guardian PR ladder (`docs/yuzu-guardian-windows-implementation-plan.md` and successors). The viewer ships with honest "observation window" badging; the hardening track does not block this issue.

**Files:** `agents/plugins/tar/src/tar_plugin.cpp` (new `do_process_tree`), new `agents/plugins/tar/src/tar_process_tree_collector.{cpp,hpp}` (cross-platform walks), `server/core/src/dashboard_routes.cpp` (renderer), new `server/core/src/tar_process_tree_reconstruct.{cpp,hpp}`. Design: `docs/tar-dashboard.md` §5.

---

## Phase 16: System Guardian — Real-Time Agent-Side Guaranteed State

*The headline parity feature against the leading commercial endpoint-management platforms' real-time enforcement engines. PolicyStore (Phase 5) covers server-side compliance evaluation on a 5-minute poll; this phase covers the **kernel-event-driven, microsecond-latency, pre-login-active, fully-offline-capable** agent-side enforcement that makes guaranteed state operationally true rather than approximately true. Without Phase 16, "policy engine equivalent" overclaims — a 5-minute window is unacceptable for security-sensitive settings (firewall ports, registry-backed posture, EDR running). Design: `docs/yuzu-guardian-design-v1.1.md` (architecture), `docs/yuzu-guardian-windows-implementation-plan.md` (Windows-first 17-PR delivery ladder).*

### Issue 16.A: System Guardian — Windows-first delivery
**Capability:** 31.1, 31.2, 31.3, 31.6, 31.7, 31.8, 31.9, 31.10 | **Scope:** Agent (Windows) + Server | **Status:** In progress (PRs 1-2 shipped)
**GitHub:** [#555](https://github.com/Tr3kkR/Yuzu/issues/555)

End-to-end Windows enforcement using kernel-backed user-mode APIs:
- **Event guards (~0 ms latency)** — RegNotifyChangeKeyValue (Registry Guard), NotifyServiceStatusChange (SCM Guard), FwpmFilterSubscribeChanges0 (WFP Guard), OpenTrace + ProcessTrace with session pooling (ETW Guard).
- **Condition guards (configurable interval)** — Process Guard (hybrid ETW + ToolHelp32), Software Guard (Registry Uninstall + WMI), Compliance Guard (Event Log + WMI), WMI Guard (arbitrary query).
- **Pre-login activation** — agent service `SERVICE_AUTO_START` + `FailureActions`; `GuardianEngine::start_local()` runs before Register RPC.
- **Offline capable** — policy cached in `kv_store.db` `__guardian__` namespace; enforcement continues when server is unreachable.
- **Operator surface** — `/guaranteed-state` dashboard page (rule list + event timeline + kernel-wiring health), HTMX rule editor, approval workflow via existing `ApprovalManager`, MCP read-only tools, HMAC rule signing with `CredWrite`/`CredRead` key storage, quarantine integration via WFP block-all filter at weight 65535.

PRs 1-2 (proto, server store, agent scaffolding, REST + dispatch hook) shipped. PRs 3-15 in `docs/yuzu-guardian-windows-implementation-plan.md`. 14 prerequisite issues already filed (#452-#457, #477-#479, #483, #485, #487, #488, #491).

**Files (anticipated):** `proto/yuzu/guardian/v1/guaranteed_state.proto` (shipped), `server/core/src/guaranteed_state_store.{hpp,cpp}` (shipped), `agents/core/src/guardian_engine.{hpp,cpp}` (shipped), `agents/core/src/guard_*.{hpp,cpp}` (PR 3+), `agents/core/src/state_evaluator.{hpp,cpp}`, `agents/core/src/remediation_engine.{hpp,cpp}`, `agents/core/src/guard_audit.{hpp,cpp}`, `server/core/src/dashboard_guaranteed_state.{hpp,cpp}` (PR 4).

### Issue 16.B: System Guardian — Linux delivery
**Capability:** 31.4, 31.6 (Linux) | **Scope:** Agent (Linux) | **Status:** Open
**Depends on:** 16.A soak | **GitHub:** [#556](https://github.com/Tr3kkR/Yuzu/issues/556)

Linux equivalents of Windows event guards: Inotify Guard (`inotify_add_watch`), Netlink Guard (`NETLINK_KOBJECT_UEVENT`), D-Bus Guard (`org.freedesktop.systemd1` signals), Audit Guard (`auditd` consumer for syscall-level assertions), Sysctl Guard (`/proc/sys` watch + write remediation). Linux-specific assertion types (`config-file-key-equals`, `kernel-param-equals`, `selinux-mode-enforcing`). Remediation methods: systemd D-Bus service control, atomic file rewrite, `sysctl -w`, package install/remove via dpkg/rpm.

**Why gated on Windows soak:** the architectural primitives (state evaluator, remediation engine, resilience strategies, audit journal) are platform-agnostic — only the guard implementations are platform-specific. Building Linux before Windows soak risks discovering a primitive-level bug that the Windows track would have caught first.

**Files:** new `agents/core/src/guard_inotify.{cpp,hpp}`, `guard_netlink.{cpp,hpp}`, `guard_dbus.{cpp,hpp}`, `guard_audit_linux.{cpp,hpp}`, `guard_sysctl.{cpp,hpp}` (all Linux-only); `agents/core/meson.build` Linux block adding `libdbus-1`, `libaudit` deps.

### Issue 16.C: System Guardian — macOS delivery
**Capability:** 31.5, 31.6 (macOS) | **Scope:** Agent (macOS) | **Status:** Open
**Depends on:** 16.A + 16.B soak, Endpoint Security entitlement | **GitHub:** [#557](https://github.com/Tr3kkR/Yuzu/issues/557)

macOS equivalents using Apple's Endpoint Security (ES) framework — *requires the `com.apple.developer.endpoint-security.client` entitlement*, which Apple grants per-bundle-ID after Developer Program enrolment and notarisation review (typically 4-8 weeks). Without ES the macOS surface is reduced to FSEvents Guard (`fseventsd` consumer) + Launchd Guard (plist polling + `launchctl` poll). macOS-specific assertion types (`plist-key-equals`, `launchd-service-running`, `xprotect-version-current`, `gatekeeper-enabled`). Remediation: plist serialisation + atomic write, `launchctl bootstrap`/`bootout`, `spctl --master-enable`.

**Entitlement gating** is tracked out-of-band in the customer-facing release-readiness doc; the issue ships in two phases — degraded surface first (FSEvents + Launchd, no ES), full surface when entitlement lands.

**Files:** new `agents/core/src/guard_endpoint_security.{cpp,hpp}` (macOS, ES-entitlement-gated), `guard_fsevents.{cpp,hpp}` (macOS), `guard_launchd.{cpp,hpp}` (macOS).

---

## Open Decisions

| # | Issue | Topic | Status |
|---|-------|-------|--------|
| D1 | [#251](https://github.com/Tr3kkR/Yuzu/issues/251) | License key generation and signing strategy | **Open** — Options: signed keys (offline), license server (online), or hybrid. Blocks production use of capability 22.3. |
| D2 | [#252](https://github.com/Tr3kkR/Yuzu/issues/252) | CEL is a custom subset, not full Common Expression Language | **Open** — Current evaluator covers basic comparisons. Full CEL (cel-cpp) needed for enterprise policy expressions. |

## Future Phase (T3 Items — Not Scheduled)

These capabilities are tracked but not yet scheduled. Each will become a GitHub issue when prioritized.

| # | Capability | Notes |
|---|-----------|-------|
| 4.10 | ARP scanning | Active subnet discovery (partially covered by `discovery` plugin `scan_subnet`) |
| 12.3 | WMI namespace enumeration | WMI discovery (partially covered by `wmi` plugin configurable namespace) |
| 22.3 | License management | Seat count, expiry, feature entitlements (LicenseStore exists; key generation strategy TBD — see D1) |
| 23.2 | Remote key-value access | Cross-agent storage access |

---

## Dependency Graph

```
Phase 0–7 (All Done)
  └── Foundation → Data Infrastructure → Instruction System → Security/RBAC
      → Agent Infrastructure → Policy Engine → Windows Depth → Scale & Integration

Phase 8 (Visualization & Response Experience)
  ├── 8.1 Visualization Engine ── builds on ResponseStore + InstructionStore
  ├── 8.2 Response Templates ──── requires 8.1
  └── 8.3 Response Offloading ─── independent (reuses WebhookStore pattern)

Phase 9 (Connector Framework)
  ├── 9.1 Connector Core ──────── independent (new subsystem)
  ├── 9.2 Repository Model ────── requires 9.1
  ├── 9.3–9.7 Connectors ─────── require 9.1 (all independent of each other)
  └── 9.8 Consolidation ──────── requires 9.2

Phase 10 (Software Catalog)
  ├── 10.1 Catalog Store ──────── requires 9.8 (normalized inventory data)
  ├── 10.2 Usage Tracking ─────── requires 10.1
  ├── 10.3 Entitlements ───────── requires 10.1
  └── 10.4 Software Tags ─────── requires 10.1

Phase 11 (Consumer Model)
  ├── 11.1 Consumer Registration ── independent
  ├── 11.2 Event Sources ──────── independent (extends WebhookStore + NotificationStore)
  ├── 11.3 PowerShell Module ──── independent (wraps REST API)
  └── 11.4 Python SDK ─────────── independent (wraps REST API)

Phase 12 (Agent Capabilities)
  ├── 12.1–12.6 ─── independent plugin extensions (no cross-deps)
  ├── 12.7–12.9 ─── extend interaction plugin (sequential within plugin)
  ├── 12.10 Patch Events ──────── extends windows_updates plugin
  ├── 12.11 App Whitelisting ──── new plugin (independent)
  ├── 12.12 Inventory Delta ───── extends agent core + InventoryStore
  └── 12.13 Resource Distribution ── independent (new server store)

Phase 13 (Security & Polish)
  ├── 13.1 2FA / TOTP ─────────── extends ApprovalManager
  ├── 13.2 Instruction Chains ─── requires 7.14 Workflows
  ├── 13.3 Monitoring UI ──────── independent (new dashboard page)
  ├── 13.4 Branding ───────────── independent (CSS + RuntimeConfigStore)
  └── 13.5 MCP Phase 2 ───────── requires 7.20 MCP Phase 1

Phase 14 (Scale & Enterprise)
  ├── 14.1 P2P Content ────────── independent (agent-side mesh)
  ├── 14.2 Multi-Gateway ──────── requires 7.1 + 7.1.1
  ├── 14.3 DB Sharding ────────── extends ResponseStore
  ├── 14.4 vCenter Connector ──── requires 9.1
  ├── 14.5 Additional Connectors ── requires 9.1
  └── 14.6 High Availability ──── independent (new subsystem)

Cross-phase dependencies:
  Phase 10 ──→ Phase 9.8 (catalog needs normalized inventory)
  Phase 13.2 ──→ Phase 7.14 (chains extend workflows)
  Phase 14.4–14.5 ──→ Phase 9.1 (connectors need framework)
```

---

## Recommended Execution Order

Phases 0–7 are complete. For the remaining phases, execution order is based on enterprise value and dependencies:

1. **Phase 8** — Visualization & response experience (immediate UX impact, small scope). 8.1 Response Visualization Engine done; six demo charts ship in `content/definitions/visualization_demo_set.yaml` and `content/packs/visualization-demo-pack.yaml`. 8.2 Response Templates and 8.3 Response Offloading remain.
2. **Phase 9** — Connector framework (largest enterprise gap, enables Phases 10, 14.4–14.5)
3. **Phase 10** — Software catalog & license compliance (builds on 9.8 normalization)
4. **Phase 12** — Remaining agent capabilities (closes capability map to 100%, parallelizable)
5. **Phase 11** — Consumer model & SDKs (platform extensibility, parallelizable with 12)
6. **Phase 13** — Security hardening & polish (2FA, branding, MCP write tools)
7. **Phase 14** — Scale & enterprise readiness (P2P, multi-gateway, HA — large deployment needs)
8. **Phase 15** — TAR dashboard + scope walking (composable scope from previous query results — the product differentiator). 8-step PR ladder; PR-A (TAR page + retention-paused list) is in flight. Full design in `docs/tar-dashboard.md` and `docs/scope-walking-design.md`. Reference walkthrough: Chrome IR.
9. **Phase 16** — System Guardian (real-time agent-side guaranteed state). The headline parity feature against the leading commercial endpoint-management platforms' real-time enforcement engines. Windows-first 17-PR ladder per `docs/yuzu-guardian-windows-implementation-plan.md`; PRs 1-2 shipped, PR 3+ open. Linux + macOS phases gated on Windows soak. Without this phase, "policy engine equivalent" overclaims.

---

## Issue Summary

| Phase | Issues | Capabilities Covered |
|-------|:------:|:-------------------:|
| 0: Foundation | 5 | 7 |
| 1: Data Infrastructure | 7 | 12 |
| 2: Instruction System | 12 | 10 |
| 3: Security & RBAC | 9 | 12 |
| 4: Agent Infrastructure | 8 | 14 |
| 5: Policy Engine | 5 | 6 |
| 6: Windows Depth | 6 | 13 |
| 7: Scale & Integration | 20 | 24 |
| 8: Visualization & Response Experience | 3 | 3 |
| 9: Connector Framework | 8 | 8 |
| 10: Software Catalog | 4 | 4 |
| 11: Consumer Model | 4 | 4 |
| 12: Agent Capabilities | 13 | 13 |
| 13: Security & Polish | 5 | 5 |
| 14: Scale & Enterprise | 6 | 6 |
| 15: TAR Dashboard & Scope Walking | 8 | 8 |
| 16: System Guardian (Real-Time GS) | 3 | 10 |
| **Total** | **126** | **159** |

Plus 4 future-tier items tracked but not scheduled. The remaining capabilities are covered by existing "Done" implementations.
