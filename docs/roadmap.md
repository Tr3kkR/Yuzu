# Yuzu Development Roadmap

**Version:** 1.2 | **Date:** 2026-03-18

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
| | 2.8 | [#205](https://github.com/Tr3kkR/Yuzu/issues/205) | Error Code Taxonomy (1xxx-4xxx) | Open |
| | 2.9 | [#206](https://github.com/Tr3kkR/Yuzu/issues/206) | Concurrency Enforcement (5 Modes) | Open |
| | 2.10 | [#207](https://github.com/Tr3kkR/Yuzu/issues/207) | YAML Authoring UI (Form + CodeMirror) | Open |
| | 2.11 | [#208](https://github.com/Tr3kkR/Yuzu/issues/208) | Legacy Command Shim | Open |
| | 2.12 | [#209](https://github.com/Tr3kkR/Yuzu/issues/209) | Structured Result Envelope | Open |
| **3** | 3.1 | [#154](https://github.com/Tr3kkR/Yuzu/issues/154) | Granular RBAC System | Done |
| | 3.2 | [#156](https://github.com/Tr3kkR/Yuzu/issues/156) | Management Groups | Open |
| | 3.3 | [#157](https://github.com/Tr3kkR/Yuzu/issues/157) | Token-Based API Authentication | Open |
| | 3.4 | [#159](https://github.com/Tr3kkR/Yuzu/issues/159) | OIDC / SSO Integration | Done |
| | 3.5 | [#161](https://github.com/Tr3kkR/Yuzu/issues/161) | REST / HTTP Management API (v1) | Open |
| | 3.6 | [#162](https://github.com/Tr3kkR/Yuzu/issues/162) | Device Quarantine (Network Isolation) | Open |
| | 3.7 | [#164](https://github.com/Tr3kkR/Yuzu/issues/164) | IOC Checking | Open |
| | 3.8 | [#165](https://github.com/Tr3kkR/Yuzu/issues/165) | Certificate Inventory and Management | Open |
| | 3.9 | [#210](https://github.com/Tr3kkR/Yuzu/issues/210) | Scope DSL Extensions (MATCHES, EXISTS, len, startswith) | Open |
| **4** | 4.1 | [#173](https://github.com/Tr3kkR/Yuzu/issues/173) | Agent-Side Key-Value Storage | Open |
| | 4.2 | [#174](https://github.com/Tr3kkR/Yuzu/issues/174) | HTTP Download and Upload (Agent-Initiated) | Open |
| | 4.3 | [#177](https://github.com/Tr3kkR/Yuzu/issues/177) | Content Staging and Execution | Open |
| | 4.4 | [#181](https://github.com/Tr3kkR/Yuzu/issues/181) | Agent Sleep and Stagger Control | Open |
| | 4.5 | [#184](https://github.com/Tr3kkR/Yuzu/issues/184) | Trigger Framework (Agent-Side) | Open |
| | 4.6 | [#189](https://github.com/Tr3kkR/Yuzu/issues/189) | Desktop User Interaction (Windows) | Open |
| | 4.7 | [#193](https://github.com/Tr3kkR/Yuzu/issues/193) | Agent Logging and Remote Log Retrieval | Open |
| | 4.8 | [#212](https://github.com/Tr3kkR/Yuzu/issues/212) | service.set_start_mode Cross-Platform Primitive | Open |
| **5** | 5.1 | [#175](https://github.com/Tr3kkR/Yuzu/issues/175) | Policy Rules and Fragments | Open |
| | 5.2 | [#176](https://github.com/Tr3kkR/Yuzu/issues/176) | Policy Assignment and Deployment | Open |
| | 5.3 | [#178](https://github.com/Tr3kkR/Yuzu/issues/178) | Compliance Dashboard and Statistics | Open |
| | 5.4 | [#179](https://github.com/Tr3kkR/Yuzu/issues/179) | Policy Cache Invalidation and Force Re-Evaluation | Open |
| | 5.5 | [#211](https://github.com/Tr3kkR/Yuzu/issues/211) | CEL Adoption for Policy Compliance Expressions | Open |
| **6** | 6.1 | [#180](https://github.com/Tr3kkR/Yuzu/issues/180) | Registry Plugin (Read/Write/Enumerate) | Open |
| | 6.2 | [#182](https://github.com/Tr3kkR/Yuzu/issues/182) | Per-User Registry Operations | Open |
| | 6.3 | [#183](https://github.com/Tr3kkR/Yuzu/issues/183) | WMI Query and Method Invocation | Open |
| | 6.4 | [#186](https://github.com/Tr3kkR/Yuzu/issues/186) | Per-User Application Inventory | Open |
| | 6.5 | [#188](https://github.com/Tr3kkR/Yuzu/issues/188) | File System Advanced Operations | Open |
| | 6.6 | [#192](https://github.com/Tr3kkR/Yuzu/issues/192) | Registry Change Trigger | Open |
| **7** | 7.1 | [#185](https://github.com/Tr3kkR/Yuzu/issues/185) | Gateway Node Implementation | Open |
| | 7.2 | [#187](https://github.com/Tr3kkR/Yuzu/issues/187) | System Health Monitoring and Statistics | Open |
| | 7.3 | [#190](https://github.com/Tr3kkR/Yuzu/issues/190) | Runtime Configuration API | Open |
| | 7.4 | [#191](https://github.com/Tr3kkR/Yuzu/issues/191) | System Notifications | Open |
| | 7.5 | [#194](https://github.com/Tr3kkR/Yuzu/issues/194) | Active Directory / Entra Integration | Open |
| | 7.6 | [#195](https://github.com/Tr3kkR/Yuzu/issues/195) | Custom Properties on Devices | Open |
| | 7.7 | [#196](https://github.com/Tr3kkR/Yuzu/issues/196) | Agent Deployment Jobs | Open |
| | 7.8 | [#197](https://github.com/Tr3kkR/Yuzu/issues/197) | Patch Deployment Workflow | Open |
| | 7.9 | [#198](https://github.com/Tr3kkR/Yuzu/issues/198) | Product Packs (Bundled Definitions) | Open |
| | 7.10 | [#199](https://github.com/Tr3kkR/Yuzu/issues/199) | User Sessions and Group Membership Plugins | Open |
| | 7.11 | [#200](https://github.com/Tr3kkR/Yuzu/issues/200) | Advanced User Interaction (Surveys, DND) | Open |
| | 7.12 | [#201](https://github.com/Tr3kkR/Yuzu/issues/201) | Event Subscriptions (Webhooks) | Open |
| | 7.13 | [#213](https://github.com/Tr3kkR/Yuzu/issues/213) | ProductPack Ed25519 Trust Chain and Verification | Open |
| | 7.14 | [#214](https://github.com/Tr3kkR/Yuzu/issues/214) | Workflow Primitives (if, foreach, retry) | Open |
| | 7.15 | [#215](https://github.com/Tr3kkR/Yuzu/issues/215) | WiFi Network Enumeration | Open |
| | 7.16 | [#216](https://github.com/Tr3kkR/Yuzu/issues/216) | Wake-on-LAN Support | Open |
| | 7.17 | [#217](https://github.com/Tr3kkR/Yuzu/issues/217) | Inventory Table Enumeration and Item Lookup | Open |
| | 7.18 | [#218](https://github.com/Tr3kkR/Yuzu/issues/218) | Device Discovery (Unmanaged Endpoints) | Open |

## Current Status

| Phase | Done | Open | Total | Progress |
|-------|:----:|:----:|:-----:|----------|
| 0: Foundation | 5 | 0 | 5 | 100% |
| 1: Data Infrastructure | 7 | 0 | 7 | 100% |
| 2: Instruction System | 7 | 5 | 12 | 58% |
| 3: Security & RBAC | 2 | 7 | 9 | 22% |
| 4: Agent Infrastructure | 0 | 8 | 8 | 0% |
| 5: Policy Engine | 0 | 5 | 5 | 0% |
| 6: Windows Depth | 0 | 6 | 6 | 0% |
| 7: Scale & Integration | 0 | 19 | 19 | 0% |
| **Total** | **21** | **50** | **71** | |

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

### Issue 4.1: Agent-Side Key-Value Storage
**Capabilities:** 23.1, 23.3 | **Scope:** Agent SDK + Plugin

Add persistent key-value storage to the agent, backed by the existing `agent.db` SQLite database:
- **Storage.Set:** Store a named table (overwrite or append with max row limit)
- **Storage.Get:** Retrieve by name
- **Storage.List:** List all table names
- **Storage.Delete:** Remove a table
- **Storage.Check:** Test if table exists

Expose via plugin SDK (new `yuzu_ctx_storage_*` functions in `plugin.h`) and as a built-in `storage` plugin.

**Files:** `sdk/include/yuzu/plugin.h`, `sdk/include/yuzu/plugin.hpp`, `agents/core/src/agent.cpp`, new `agents/plugins/storage/`

### Issue 4.2: HTTP Download and Upload (Agent-Initiated)
**Capabilities:** 13.3, 13.4, 10.13 | **Scope:** Plugin + Agent

New `http` plugin or extend agent core:
- **HttpGetFile:** Download file from URL with hash/size verification. Support both server content channel and external URLs. Return temp file path (cleaned up after instruction).
- **HttpPost:** Send data to external endpoint. Support custom headers, content types, authorization. Return status code and response body.
- **FileUpload:** Upload file from endpoint to server (reverse of HttpGetFile). Streaming upload for large files.

**Files:** New `agents/plugins/http_client/`, `server/core/src/server.cpp` (file receive endpoint)

### Issue 4.3: Content Staging and Execution
**Capabilities:** 13.1, 13.2 | **Scope:** Agent + Server

Server-to-agent content distribution:
- **Stage:** Server pushes content manifest, agent downloads files to local staging directory. Verify integrity via hash.
- **StageAndExecute:** Download to temp directory, execute command, clean up. Return exit code and output.

Server side: content repository for hosting files, manifest generation, and download tracking.

**Files:** New `agents/plugins/content_dist/`, `server/core/src/server.cpp` (content hosting endpoints)

### Issue 4.4: Agent Sleep and Stagger Control
**Capability:** 1.6 | **Scope:** Agent

- **Sleep:** Server instructs agent to pause for N seconds (testing/maintenance).
- **Stagger:** Agent introduces random delay (0 to N seconds) before executing an instruction, preventing thundering herd on broadcast. Configurable default stagger range.

Implement as built-in agent behavior (not a plugin), triggered by fields in `CommandRequest`.

**Files:** `agents/core/src/agent.cpp`, `proto/yuzu/agent/v1/agent.proto`

### Issue 4.5: Trigger Framework (Agent-Side)
**Capabilities:** 17.1-17.6 | **Scope:** Agent SDK + Agent Core

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

### Issue 4.6: Desktop User Interaction (Windows)
**Capabilities:** 14.1-14.3 | **Scope:** Plugin

New `interaction` plugin (Windows-only initially):
- **ShowNotification:** Toast notification (Information/Warning/Error) with configurable timeout. Returns immediately.
- **ShowAnnouncement:** Modal dialog with description, optional icon, choices, and default buttons (Later/Dismiss). Sync or async.
- **ShowQuestion:** Yes/No dialog with customizable button text. Sync or async.
- Async mode: returns immediately, response delivered via topic when user interacts.
- Target specific user session or all sessions.

**Files:** New `agents/plugins/interaction/`

### Issue 4.7: Agent Logging and Remote Log Retrieval
**Capability:** 1.7 | **Scope:** Agent + Plugin

Extend the `diagnostics` plugin:
- **GetKeyFiles:** Return paths to config, executable, log, data directory, temp directory.
- **SetLogLevel:** Dynamically change agent log level without restart.
- **GetLog:** Retrieve last N lines of agent log (or by time range). Stream large logs.

**Files:** `agents/plugins/diagnostics/src/diagnostics_plugin.cpp`, `agents/core/src/agent.cpp`

### Issue 4.8: service.set_start_mode Cross-Platform Primitive
**Scope:** Plugin

Add `set_start_mode` action to the `services` plugin. Parameters: `serviceName`, `mode` (automatic/manual/disabled/masked). Cross-platform: Windows `ChangeServiceConfigW`, Linux `systemctl enable/disable/mask`, macOS `launchctl enable/disable`. `masked` maps to `disabled` with warning on non-Linux. Returns previous/new/effective mode. Design: `docs/Instruction-Engine.md` Section 16.

**Files:** `agents/plugins/services/src/services_plugin.cpp`

---

## Phase 5: Policy Engine and Compliance

*Desired-state policies with trigger-based evaluation and auto-remediation.*

### Issue 5.1: Policy Rules and Fragments
**Capabilities:** 16.1, 16.2 | **Scope:** Server + Agent

Core policy engine:
- **Fragments:** Reusable compliance check/fix code blocks. Each fragment defines a check instruction (evaluate state) and optional fix instruction (remediate). Parameters are configured when rules are created.
- **Rules:** Bind a fragment to one or more triggers. Rule types: Check (evaluate only) or Fix (evaluate + remediate). Status codes: Received, CheckErrored, CheckFailed, CheckPassed, FixErrored, FixPassed, FixFailed.
- **Agent-side evaluation:** Rules evaluate on trigger fire, agent startup, and initial receipt. De-bounce prevents rapid re-evaluation.
- **Server-side management:** CRUD for fragments and rules via management API.

**Files:** New `server/core/src/policy_engine.cpp`, `agents/core/src/agent.cpp`, `proto/yuzu/agent/v1/agent.proto` (policy push/status RPCs)

### Issue 5.2: Policy Assignment and Deployment
**Capabilities:** 16.3, 16.8 | **Scope:** Server

- Policies are assigned to management groups (from Issue 3.2)
- Changes accumulate as pending; admin explicitly deploys
- Deployment compiles the policy document, hashes it, and pushes to agents
- Agents pull policy on next connection or receive push notification
- Pending changes review UI in dashboard

**Files:** `server/core/src/policy_engine.cpp`, `server/core/src/server.cpp`, dashboard UI updates

### Issue 5.3: Compliance Dashboard and Statistics
**Capabilities:** 16.4, 16.5 | **Scope:** Server

- Device compliance status per policy and per rule
- Fleet-wide compliance posture summary (% compliant, % non-compliant, % unknown)
- Rule evaluation history (chronological log with status changes)
- Effectiveness metrics: time to compliance, remediation success rate
- Dashboard UI: compliance tab with drill-down from fleet → policy → rule → device

**Files:** `server/core/src/policy_engine.cpp`, `server/core/src/dashboard_ui.cpp`, `server/core/src/server.cpp`

### Issue 5.4: Policy Cache Invalidation and Force Re-Evaluation
**Capabilities:** 16.7 | **Scope:** Agent + Server

- **Invalidate:** Reset agent's policy to empty; agent re-downloads on next connection.
- **ForceStatusReport:** Schedule a full compliance status report on next agent restart.
- Expose both as actions dispatchable from the dashboard.

**Files:** `agents/core/src/agent.cpp`, `server/core/src/server.cpp`

### Issue 5.5: CEL Adoption for Policy Compliance Expressions
**Scope:** Server
**Depends on:** 5.1

Adopt [Common Expression Language (CEL)](https://github.com/google/cel-spec) for typed policy evaluation. CEL handles `spec.compliance.expression`, `spec.fix.when`, and `spec.rollout.condition` — typed evaluation that the scope DSL cannot do. The scope DSL stays for device targeting. abseil is already a transitive dep via gRPC, making cel-cpp a natural addition. Design: `docs/Instruction-Engine.md` Section 8.3.

**Files:** `vcpkg.json`, new `server/core/src/cel_evaluator.cpp`, `server/core/src/policy_engine.cpp`

---

## Phase 6: Windows Platform Depth

*Registry, WMI, per-user operations, and Windows-specific advanced capabilities.*

### Issue 6.1: Registry Plugin (Read/Write/Enumerate)
**Capabilities:** 12.4-12.6 | **Scope:** Plugin

New `registry` plugin (Windows-only):
- **GetValue:** Read registry value by hive/subkey/name. Return name, type, data.
- **SetValue:** Write registry value. Support REG_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_EXPAND_SZ, REG_MULTI_SZ.
- **DeleteKey / DeleteValue:** Remove registry keys or values.
- **KeyExists / ValueExists:** Check existence.
- **EnumerateKeys / EnumerateValues:** Recursive listing.

All operations support HKLM, HKCU, HKCR, HKU hives.

**Files:** New `agents/plugins/registry/`

### Issue 6.2: Per-User Registry Operations
**Capability:** 12.7 | **Scope:** Plugin

Extend the registry plugin with per-user variants:
- Load each user's NTUSER.DAT hive
- Enumerate/get/set/delete across all user hives
- Dedicated methods: `EnumerateUserKeys`, `GetUserValues`, `SetUserValues`, `DeleteUserKey`, `DeleteUserValues`

**Files:** `agents/plugins/registry/src/registry_plugin.cpp`

### Issue 6.3: WMI Query and Method Invocation
**Capabilities:** 12.1, 12.2 | **Scope:** Plugin

New `wmi` plugin (Windows-only):
- **RunWmiQuery:** Execute WQL query against any WMI namespace. Return structured tabular results.
- **RunWmiInstanceMethod:** Call instance method on a WMI object.
- **RunWmiStaticMethod:** Call static method on a WMI class.
- COM initialization with proper cleanup. Structured output (not raw PowerShell text).

**Files:** New `agents/plugins/wmi/`

### Issue 6.4: Per-User Application Inventory
**Capability:** 7.5 | **Scope:** Plugin

Extend `installed_apps` plugin:
- Enumerate per-user installations from HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall for each user profile.
- Distinguish system-wide from user-specific installs in output.

**Files:** `agents/plugins/installed_apps/src/installed_apps_plugin.cpp`

### Issue 6.5: File System Advanced Operations
**Capabilities:** 10.7-10.10, 10.14, 10.15 | **Scope:** Plugin

Extend the `filesystem` plugin:
- **GetFilePermissions:** ACL enumeration (Windows DACL, POSIX permissions)
- **GetDigitalSignature:** Authenticode/codesign verification (Windows WinVerifyTrust, macOS codesign)
- **GetVersionInfo:** PE version resource extraction (Windows)
- **FindAndReplace / FindAndDelete / WriteText / AppendText:** Text file manipulation operations
- **FindFileBySizeAndHash:** Locate files matching both size and hash criteria
- **FindDirectoryByName:** Find directories by name pattern

**Files:** `agents/plugins/filesystem/src/filesystem_plugin.cpp`

### Issue 6.6: Registry Change Trigger
**Capability:** 17.5 | **Scope:** Agent

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

---

## Future Phase (T3 Items — Not Scheduled)

These capabilities represent competitive parity with the most mature platforms. They are tracked but not scheduled into the current roadmap. Each will become a GitHub issue when prioritized.

| # | Capability | Notes |
|---|-----------|-------|
| 3.8 | Mapped drive history | Windows lateral movement analysis |
| 3.9 | Printer inventory | Asset tracking |
| 4.9 | NetBIOS/name lookup | Legacy reverse lookup |
| 4.10 | ARP scanning | Active subnet discovery |
| 4.11 | Port scanning | Service discovery |
| 5.5 | Open windows enumeration | Desktop interaction |
| 8.9 | Patch inventory events | SIEM integration |
| 9.10 | Application whitelisting | Endpoint security product integration |
| 10.11 | Directory hash | Integrity verification |
| 12.3 | WMI namespace enumeration | WMI discovery |
| 13.5 | Peer-to-peer content distribution | P2P caching with agent mesh |
| 15.5 | Inventory replication | Agent-side cache with delta sync |
| 20.6 | Response templates | Pre-defined response formats |
| 20.7 | Response offloading | Route responses to external HTTP endpoints |
| 22.3 | License management | Seat count, expiry, feature entitlements |
| 22.7 | Binary resource distribution | Versioned binary distribution |
| 23.2 | Remote key-value access | Cross-agent storage access |
| 24.4 | Consumer registration | External system data feeds |
| 24.7 | SDK libraries | Client libraries for third-party integration |

---

## Dependency Graph

```
Phase 0 (Foundation)
  └── No dependencies; can start immediately

Phase 1 (Data Infrastructure)
  ├── 1.1 Response Store ─── prerequisite for ──→ 1.2 Filtering, 1.3 Aggregation
  ├── 1.5 Device Tags ───── prerequisite for ──→ 1.6 Scope Engine
  └── 1.6 Scope Engine ──── prerequisite for ──→ Phase 2 (Scheduling, Targeting)

Phase 2 (Instruction System)
  ├── Requires: Phase 1 (response store, scope engine)
  ├── 2.1 Definitions ───── prerequisite for ──→ 2.2 Sets, 2.3 Scheduling, 2.5 Hierarchies
  ├── 2.4 Approvals ─────── prerequisite for ──→ 2.3 Scheduling (approval gates)
  ├── 2.8 Error Codes ───── independent (can retrofit any time)
  ├── 2.9 Concurrency ───── independent (can retrofit any time)
  ├── 2.10 YAML UI ──────── requires 2.1 Definitions
  ├── 2.11 Legacy Shim ──── requires 2.1 Definitions
  └── 2.12 Result Envelope ─ prerequisite for ──→ 5.5 CEL, 7.14 Workflows

Phase 3 (Security & RBAC)
  ├── 3.1 RBAC ──────────── prerequisite for ──→ 3.2 Management Groups
  ├── 3.2 Mgmt Groups ──── prerequisite for ──→ Phase 5 (Policy Assignment)
  ├── 3.5 REST API ──────── can start after Phase 1
  └── 3.9 Scope DSL Ext ─── independent (extends 1.6 Scope Engine)

Phase 4 (Agent Infrastructure)
  ├── 4.5 Triggers ──────── prerequisite for ──→ Phase 5 (Policy Engine)
  ├── 4.1 Storage ───────── prerequisite for ──→ 4.5 Triggers (state), 3.6 Quarantine (state)
  ├── 4.2 HTTP Client ───── prerequisite for ──→ 4.3 Content Staging
  └── 4.8 set_start_mode ── independent (services plugin extension)

Phase 5 (Policy Engine)
  ├── Requires: Phase 3 (Mgmt Groups), Phase 4 (Triggers, Storage)
  ├── 5.1 Rules ─────────── prerequisite for ──→ 5.2 Assignment, 5.3 Dashboard, 5.5 CEL
  └── 5.5 CEL ─────────────  requires 5.1 Rules + 2.12 Result Envelope

Phase 6 (Windows Depth)
  ├── Can start any time after Phase 0
  └── 6.6 Registry Trigger ── requires Phase 4.5 (Trigger Framework)

Phase 7 (Scale & Integration)
  ├── Most items can start after Phase 3
  ├── 7.1.1 Gateway Adjacency ── requires 7.1 Gateway
  ├── 7.9 Product Packs ── requires Phase 2.1 (Instruction Definitions)
  ├── 7.13 Pack Trust Chain ── requires 7.9 Product Packs
  ├── 7.14 Workflows ────── requires 2.5 Hierarchies + 2.12 Result Envelope
  └── 7.18 Device Discovery ── complements 7.7 Agent Deployment Jobs
```

---

## Recommended Execution Order

For maximum value delivery, interleave phases based on dependencies:

1. **Phase 0** — Complete all foundation gaps (small scope, high impact)
2. **Phase 1** — Server data infrastructure (enables everything else)
3. **Phase 4.1** — Agent storage (quick win, enables later phases)
4. **Phase 3.1** — Granular RBAC (enterprise blocker)
5. **Phase 2.1-2.2** — Instruction definitions and sets (core value)
6. **Phase 3.2** — Management groups (scoping)
7. **Phase 3.5** — REST API (external integration)
8. **Phase 6.1** — Registry plugin (high demand)
9. **Phase 2.3-2.4** — Scheduling and approvals
10. **Phase 4.5** — Trigger framework
11. **Phase 5** — Policy engine (flagship differentiator)
12. **Phase 4.6** — User interaction
13. **Phase 4.2-4.3** — Content distribution
14. **Phase 7** — Scale and remaining features

---

## Issue Summary

| Phase | Issues | Capabilities Covered |
|-------|:------:|:-------------------:|
| 0: Foundation | 5 | 7 |
| 1: Data Infrastructure | 7 | 12 |
| 2: Instruction System | 7 | 10 |
| 3: Security & RBAC | 8 | 12 |
| 4: Agent Infrastructure | 7 | 14 |
| 5: Policy Engine | 4 | 6 |
| 6: Windows Depth | 6 | 13 |
| 7: Scale & Integration | 12 | 21 |
| **Total** | **56** | **95** |

Plus 19 future-tier items tracked but not scheduled = **114 of 139** capabilities addressed.

The remaining 25 capabilities are covered by existing "Done" implementations that need no further work.
