# Yuzu Capability Map

**Version:** 1.2 | **Date:** 2026-03-20 | **Status:** Draft

---

## How to Read This Document

Each capability is rated on two axes:

**Implementation Status**
| Icon | Status | Meaning |
|:----:|--------|---------|
| :white_check_mark: | **Done** | Implemented and functional |
| :large_orange_diamond: | **Partial** | Some coverage exists; gaps remain |
| :x: | **Not Started** | No implementation yet |

**Delivery Tier**
| Tier | Label | Meaning |
|------|-------|---------|
| **T1** | Foundation | Core capabilities for a viable endpoint management platform |
| **T2** | Advanced | Enterprise-grade features for production deployments at scale |
| **T3** | Future | Aspirational capabilities for competitive parity with top-tier platforms |

---

## Progress at a Glance

```
Foundation   [================================]  33/33 done  (100%)
Advanced     [======================--------]   60/87 done   (69%)
Future       [===-----------------------------]   2/22 done   (9%)
─────────────────────────────────────────────────────────────────
Overall      [=======================-------]   96/142 done  (68%)
```

| Domain | Total | Done | Partial | Not Started |
|--------|:-----:|:----:|:-------:|:-----------:|
| 1. Agent Lifecycle | 9 | 8 | 0 | 1 |
| 2. Command Execution | 13 | 13 | 0 | 0 |
| 3. Device & Endpoint Info | 10 | 8 | 0 | 2 |
| 4. Network Info & Discovery | 11 | 6 | 0 | 5 |
| 5. Process & Service Mgmt | 5 | 4 | 0 | 1 |
| 6. User & Session Mgmt | 5 | 1 | 0 | 4 |
| 7. Software & App Mgmt | 6 | 5 | 0 | 1 |
| 8. Patch & Update Mgmt | 9 | 1 | 1 | 7 |
| 9. Security & Compliance | 10 | 5 | 0 | 5 |
| 10. File System Operations | 15 | 7 | 0 | 8 |
| 11. Script & Command Exec | 4 | 4 | 0 | 0 |
| 12. Registry & System Config | 7 | 7 | 0 | 0 |
| 13. Content Distribution | 5 | 4 | 0 | 1 |
| 14. User Interaction | 6 | 3 | 0 | 3 |
| 15. Inventory & Data Collection | 5 | 2 | 0 | 3 |
| 16. Policy & Compliance Engine | 8 | 8 | 0 | 0 |
| 17. Triggers & Automation | 7 | 7 | 0 | 0 |
| 18. Auth & Authorization | 9 | 6 | 0 | 3 |
| 19. Device & Group Mgmt | 7 | 3 | 0 | 4 |
| 20. Response Collection | 7 | 5 | 0 | 2 |
| 21. Notifications & Audit | 5 | 2 | 0 | 3 |
| 22. System & Infrastructure | 8 | 0 | 2 | 6 |
| 23. Agent Key-Value Storage | 3 | 3 | 0 | 0 |
| 24. Integration & Extensibility | 10 | 6 | 1 | 3 |
| **TOTAL** | **142** | **96** | **4** | **42** |

---

## 1. Agent Lifecycle Management

*Agent registration, health monitoring, self-diagnostics, and remote control.*

### 1.1 Agent Registration and Enrollment :white_check_mark: `T1`

3-tier enrollment model: manual approval (Tier 1), pre-shared tokens (Tier 2), and platform trust (Tier 3, reserved). gRPC `Register` RPC with enrollment token support.

> **Gap:** Tier 3 server-side certificate validation not implemented.

### 1.2 Heartbeat and Session Keepalive :white_check_mark: `T1`

`Heartbeat` RPC with pending command delivery and `status_tags` for lightweight state reporting.

> **Gap:** No configurable heartbeat interval from server side.

### 1.3 Agent Summary and Diagnostics :white_check_mark: `T1`

`diagnostics` and `status` plugins report agent health, uptime, and resource usage. `agent_actions` plugin for self-management.

> **Gap:** No unified diagnostics bundle download (key files, logs).

### 1.4 Agent Version and Update Management :white_check_mark: `T1`

`CheckForUpdate`/`DownloadUpdate` RPCs in agent.proto. Full updater implementation (`agents/core/src/updater.cpp`) with hash verification and platform-specific self-update.

### 1.5 Agent Extensibility Introspection :white_check_mark: `T1`

Plugins reported in `RegisterRequest.AgentInfo.plugins` with name, version, description, and capabilities list.

> **Gap:** No runtime plugin install/uninstall from server.

### 1.6 Agent Sleep and Stagger Control :white_check_mark: `T2`

Stagger control via `CommandRequest.stagger` field. Agents introduce random delay before executing, preventing thundering herd on broadcast.

### 1.7 Agent Logging and Log Retrieval :white_check_mark: `T2`

spdlog-based local logging on the agent. `agent_logging` plugin provides remote log retrieval (`get_log` action, configurable 1-500 lines) and key file listing (`get_key_files` action). Log file discovery from agent config with platform default fallbacks.

### 1.8 Connection and Session Info :white_check_mark: `T1`

Session ID returned on registration. `WatchEvents` tracks connect/disconnect events. `connection_info` action in diagnostics plugin reports server address, TLS status, session ID, gRPC channel state, reconnect count, latency, uptime.

### 1.9 Instruction Execution Statistics :x: `T2`

No per-agent metrics on commands executed, success rate, or average duration.

> **Need:** Full execution history and statistics for operational visibility.

---

## 2. Command Execution and Orchestration

*Dispatching instructions to agents, collecting results, and workflow coordination.*

### 2.1 Single-Agent Command Dispatch :white_check_mark: `T1`

`ExecuteCommand` RPC with streaming response. `SendCommand` in the management API.

### 2.2 Multi-Agent Broadcast :white_check_mark: `T1`

`SendCommandRequest.agent_ids` supports broadcast (empty = all agents).

> **Gap:** No scope/filter-based targeting (e.g., "all Windows agents").

### 2.3 Streaming Command Output :white_check_mark: `T1`

`CommandResponse` streams via gRPC and SSE to the dashboard.

### 2.4 Command Timeout and Expiry :white_check_mark: `T1`

`CommandRequest.expires_at` and `SendCommandRequest.timeout_seconds`.

> **Gap:** No server-side command cancellation mid-execution.

### 2.5 Bidirectional Command Channel :white_check_mark: `T1`

`Subscribe` bidi-streaming RPC as alternative to polling.

### 2.6 Instruction Templates / Definitions :white_check_mark: `T2`

`InstructionStore` with full CRUD. Named, versioned definitions with YAML source, parameter schema (JSON Schema), result schema (typed columns), approval mode, concurrency mode, platform constraints. JSON import/export. Stored in SQLite.

### 2.7 Instruction Sets (Grouping) :white_check_mark: `T2`

`InstructionSet` CRUD in `InstructionStore`. Named logical groupings with cascade delete. Definitions belong to at most one set. RBAC permissions scoped at set level.

### 2.8 Instruction Hierarchies (Workflows) :white_check_mark: `T2`

`ExecutionTracker` supports parent/child execution hierarchy via `parent_execution_id`. Query children by parent. Follow-up instructions use parent response data as scope input.

### 2.9 Instruction Scheduling :white_check_mark: `T2`

`ScheduleEngine` with frequency types (daily, weekly, monthly, sub-day), scope expressions evaluated dynamically at dispatch, enable/disable toggle, execution history tracking. REST CRUD via `/api/schedules`.

### 2.10 Instruction Approval Workflows :white_check_mark: `T2`

`ApprovalManager` with submit/approve/reject, ownership validation (reviewer != submitter), pending count, scope expression, and full audit trail. Per-definition approval mode (auto/role-gated/always).

### 2.11 Target Estimation :white_check_mark: `T2`

`ScopeEngine` with `/api/scope/estimate` endpoint. Evaluates scope expression against connected agents and returns matching count and agent list before execution.

### 2.12 Instruction Progress Tracking :white_check_mark: `T2`

`ExecutionTracker` with per-agent status tracking (dispatched, responded, success, failure), aggregate progress percentage, summary with agent state counts. Dashboard progress bars via REST API.

### 2.13 Instruction Rerun and Cancellation :white_check_mark: `T2`

`ExecutionTracker` supports rerun (clone with same parameters, optional failed-only targeting) and cancellation with user attribution. REST endpoints: `POST /api/executions/{id}/rerun`, `POST /api/executions/{id}/cancel`.

---

## 3. Device and Endpoint Information

*Hardware, OS, identity, and classification data from managed endpoints.*

### 3.1 OS Summary :white_check_mark: `T1`

`os_info` plugin (cross-platform). Platform reported in registration.

### 3.2 Hardware Inventory :white_check_mark: `T1`

`hardware` plugin (cross-platform) covers CPU, RAM, and disks.

### 3.3 Device Identity :white_check_mark: `T1`

`device_identity` plugin. `agent_id` (UUID) in protocol.

> **Gap:** No FQDN-based server-side lookup.

### 3.4 Disk Information :white_check_mark: `T1`

Covered by the `hardware` plugin.

### 3.5 Processor Details :white_check_mark: `T1`

Covered by the `hardware` plugin.

### 3.6 Device Criticality Classification :white_check_mark: `T2`

Implemented as a special-purpose tag via the device tagging system (`TagStore`). Set/get criticality per device using key-value tags.

### 3.7 Device Location Tracking :white_check_mark: `T2`

Implemented as a special-purpose tag via the device tagging system (`TagStore`). Set/get location per device using key-value tags.

### 3.8 Mapped Drive History :x: `T3`

Not implemented. Tracks inbound mapped drive connections for lateral movement analysis. Windows-specific.

### 3.9 Printer Inventory :x: `T3`

Not implemented. Enumerate connected printers for asset tracking.

### 3.10 Device Tagging (Key-Value Metadata) :white_check_mark: `T2`

`TagStore` with SQLite backend. Full CRUD: set, get, get_all, delete, check, clear, count. Agent-side `tags` plugin with server-side sync via heartbeat. Validation: key max 64 chars, value max 448 bytes. `agents_with_tag()` for scope queries.

---

## 4. Network Information and Discovery

*Network configuration, connection state, and active discovery.*

### 4.1 IP Address and Interface Enumeration :white_check_mark: `T1`

`network_config` plugin (cross-platform).

### 4.2 TCP Connection Listing :white_check_mark: `T1`

`netstat` plugin (cross-platform).

### 4.3 Listening Endpoint Enumeration :white_check_mark: `T1`

`netstat` and `sockwho` plugins.

### 4.4 ARP Table :white_check_mark: `T1`

`network_config` plugin.

### 4.5 DNS Cache Retrieval :white_check_mark: `T1`

`network_actions` plugin has flush DNS. `dns_cache` action in `network_config` plugin dumps DNS cache (Windows: `DnsGetCacheDataTable` via dnsapi.dll, Linux: systemd-resolved query).

### 4.6 WiFi Network Enumeration :x: `T2`

Not implemented. Need to enumerate available WiFi networks with signal strength and security type.

### 4.7 Wake-on-LAN :x: `T2`

Not implemented. Requires server-side or peer-originated magic packet.

### 4.8 Network Diagnostics :white_check_mark: `T1`

`network_diag` plugin (cross-platform). `network_actions` for ping.

### 4.9 NetBIOS / Name Lookup :x: `T3`

Not implemented. Legacy reverse lookup on IP addresses.

### 4.10 ARP Scanning (Subnet Discovery) :x: `T3`

Not implemented. Active scanning to retrieve physical addresses for network discovery.

### 4.11 Port Scanning :x: `T3`

Not implemented. Probe specified ports on target devices for service discovery.

---

## 5. Process and Service Management

*Enumerate, inspect, and control running processes and system services.*

### 5.1 Process Enumeration :white_check_mark: `T1`

`processes` plugin (cross-platform). `procfetch` for formatted view with executable hash.

### 5.2 Process Termination :white_check_mark: `T1`

`processes` plugin supports kill.

> **Gap:** No multi-process kill by pattern or batch.

### 5.3 Service Enumeration :white_check_mark: `T1`

`services` plugin (cross-platform).

### 5.4 Service Control :white_check_mark: `T1`

`services` plugin supports start/stop/restart.

### 5.5 Open Windows Enumeration :x: `T3`

Not implemented. Desktop interaction to enumerate visible application windows.

---

## 6. User and Session Management

*Enumerate users, sessions, and group membership on managed endpoints.*

### 6.1 Logged-On User Enumeration :white_check_mark: `T1`

`users` plugin (cross-platform).

### 6.2 Primary User Determination :x: `T2`

Not implemented. Requires heuristic (most frequent login, console owner).

### 6.3 Local Group Membership :x: `T2`

Not implemented. Enumerate members of local groups (Administrators, Remote Desktop Users, etc.).

### 6.4 User Connection History :x: `T2`

Not implemented. Login/logout audit trail including RDP/Terminal Services history.

### 6.5 Active Session Enumeration :x: `T2`

Not implemented. RDP, console, and SSH sessions with state.

---

## 7. Software and Application Management

*Inventory installed software, manage installations, and control applications.*

### 7.1 Installed Application Inventory :white_check_mark: `T1`

`installed_apps` plugin (cross-platform).

### 7.2 Windows Installer (MSI) Package Inventory :white_check_mark: `T1`

`msi_packages` plugin (Windows).

### 7.3 SCCM Integration :white_check_mark: `T2`

`sccm` plugin (Windows).

### 7.4 Software Uninstall :white_check_mark: `T2`

`software_actions` plugin.

### 7.5 Per-User Application Inventory :white_check_mark: `T2`

`installed_apps` plugin extended with per-user hive enumeration (HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall for each user profile). Distinguishes system-wide from user-specific installs in output.

### 7.6 Software Deployment (Install/Upgrade) :x: `T2`

Can execute scripts, but no managed software deployment workflow.

> **Need:** Package staging, silent install orchestration, and rollback. Ties into content distribution.

---

## 8. Patch and Update Management

*Detect, deploy, and track operating system and application patches.*

### 8.1 Installed Update Enumeration :white_check_mark: `T1`

`windows_updates` plugin.

> **Gap:** Windows only; no Linux/macOS package update tracking.

### 8.2 Pending Update Detection :large_orange_diamond: `T1`

`windows_updates` reports pending updates.

> **Gap:** No cross-platform equivalent. No tracking of updates pending reboot.

### 8.3 Patch Deployment :x: `T2`

Not implemented. Need server-orchestrated patch install (download + install) with reboot control.

### 8.4 Patch Status Tracking :x: `T2`

Not implemented. Per-device patch compliance state and deployment status tracking.

### 8.5 Patch Metadata Retrieval :x: `T2`

Not implemented. KB article details, severity, and supersedence chain.

### 8.6 Reboot Management (Post-Patch) :x: `T2`

Not implemented. Scheduled/forced reboot with user notification.

### 8.7 Update Summary and Compliance Reporting :x: `T2`

Not implemented. Fleet-wide patch compliance dashboard.

### 8.8 Patch Connectivity Testing :x: `T2`

Not implemented. Test connection to patch/update server.

### 8.9 Patch Inventory Event Generation :x: `T3`

Not implemented. Event emission for SIEM/compliance integration.

---

## 9. Security and Compliance

*Antivirus, firewall, encryption, vulnerability scanning, and device quarantine.*

### 9.1 Antivirus Status and Product Detection :white_check_mark: `T1`

`antivirus` plugin (cross-platform).

### 9.2 Firewall Status and Rule Enumeration :white_check_mark: `T1`

`firewall` plugin (cross-platform).

### 9.3 Disk Encryption Status :white_check_mark: `T1`

`bitlocker` plugin (Windows).

> **Gap:** No macOS FileVault or Linux LUKS coverage.

### 9.4 Vulnerability Scanning :white_check_mark: `T1`

`vuln_scan` plugin + NVD database sync on server.

### 9.5 Event Log Collection :white_check_mark: `T1`

`event_logs` plugin (cross-platform).

### 9.6 Device Quarantine (Network Isolation) :x: `T2`

Not implemented. Disable networking except management channel.

> **Need:** Quarantine/unquarantine with whitelist management for incident response.

### 9.7 Indicator of Compromise (IOC) Checking :x: `T2`

Not implemented. Hash/IP/domain IOC matching against local state.

### 9.8 Certificate Inventory (Get/Delete) :x: `T2`

Agent reads certs from Windows cert store for mTLS, but no general-purpose cert enumeration or management.

### 9.9 Quarantine Status Tracking :x: `T2`

Not implemented. Server-side quarantine state, history, and whitelist management.

### 9.10 Application Whitelisting :x: `T3`

Not implemented. Modify allow/block lists on endpoint security products.

---

## 10. File System Operations

*Browse, search, inspect, and manipulate files on managed endpoints.*

### 10.1 File and Directory Listing :white_check_mark: `T1`

`filesystem` plugin (cross-platform, admin-required).

### 10.2 File Search by Name :white_check_mark: `T1`

`filesystem` plugin.

### 10.3 File Content Read (by Line) :white_check_mark: `T1`

`filesystem` plugin `read` action with `offset` (1-based line number) and `limit` (max lines, configurable) parameters for line-range access.

### 10.4 File Hash Computation :white_check_mark: `T1`

`filesystem` plugin.

### 10.5 File Deletion :white_check_mark: `T1`

`filesystem` plugin.

### 10.6 Path Existence Check :white_check_mark: `T1`

`filesystem` plugin.

### 10.7 File Permissions Inspection :x: `T2`

Not implemented. ACL/permission enumeration.

### 10.8 Digital Signature Verification :x: `T2`

Not implemented. Authenticode/codesign verification.

### 10.9 File Version Info :x: `T2`

Not implemented. PE version resource extraction (Windows).

### 10.10 File Content Search and Replace :x: `T2`

Not implemented. Find/replace, append, write, and delete operations on text files.

### 10.11 Directory Hash (Recursive) :x: `T3`

Not implemented. Integrity verification of directory trees.

### 10.12 Temp File Creation :white_check_mark: `T1`

`yuzu_create_temp_file()` and `yuzu_create_temp_dir()` in SDK with secure permissions (POSIX mkstemps 0600, Windows owner-only DACL). Exposed via filesystem plugin `create_temp`/`create_temp_dir` actions.

### 10.13 File Retrieval (Upload to Server) :x: `T2`

Not implemented. Pull files from endpoint to server for analysis.

### 10.14 Find File by Size and Hash :x: `T2`

Not implemented. Locate files matching both size and hash criteria for malware hunting.

### 10.15 Directory Search by Name :x: `T2`

Not implemented. Find directory paths matching a name pattern.

---

## 11. Script and Command Execution

*Execute arbitrary scripts and commands on managed endpoints.*

### 11.1 Script Execution (File-Based) :white_check_mark: `T1`

`script_exec` plugin (cross-platform).

### 11.2 Inline Script Execution :white_check_mark: `T1`

`script_exec` plugin accepts inline text.

### 11.3 OS Command Execution :white_check_mark: `T1`

`script_exec` covers this.

### 11.4 Execution Output Streaming :white_check_mark: `T1`

gRPC streaming delivers output in real time.

---

## 12. Registry and System Configuration (Windows)

*Read and modify Windows registry, WMI, and system configuration.*

### 12.1 WMI Query Execution :white_check_mark: `T2`

`wmi` plugin with `query` action. Execute WQL SELECT statements against any WMI namespace with structured property/value output.

### 12.2 WMI Method Invocation :white_check_mark: `T2`

`wmi` plugin with `get_instance` action. Get all properties of a WMI class instance.

### 12.3 WMI Namespace Enumeration :white_check_mark: `T3`

`wmi` plugin supports configurable namespace parameter (default `root\cimv2`).

### 12.4 Registry Key/Value Read :white_check_mark: `T2`

`registry` plugin with `get_value` action. Read values from HKLM, HKCU, HKCR, HKU hives with structured type/value output.

### 12.5 Registry Key/Value Write/Delete :white_check_mark: `T2`

`registry` plugin with `set_value`, `delete_value`, and `delete_key` actions. Support REG_SZ and REG_DWORD types.

### 12.6 Registry Enumeration :white_check_mark: `T2`

`registry` plugin with `enumerate_keys` and `enumerate_values` actions. `key_exists` for existence checks.

### 12.7 Per-User Registry Operations :white_check_mark: `T2`

`registry` plugin with `get_user_value` action. Loads NTUSER.DAT hive via `RegLoadKey` for offline users. Requires SE_RESTORE_NAME and SE_BACKUP_NAME privileges.

---

## 13. Content Distribution

*Stage and distribute files, packages, and content to endpoints.*

### 13.1 Server-to-Agent Content Staging :white_check_mark: `T2`

`content_dist` plugin with `stage` action. Download files to agent staging directory with SHA256 hash verification. `list_staged` to inventory staged content. `cleanup` to remove staged files.

### 13.2 Stage and Execute (Deploy + Run) :white_check_mark: `T2`

`content_dist` plugin with `execute_staged` action. Execute previously staged files with optional arguments. Returns exit code and output.

### 13.3 HTTP File Download (Agent-Initiated) :white_check_mark: `T2`

`http_client` plugin with `download` action. Download files from arbitrary URLs with optional SHA256 hash verification. `get` and `head` actions for HTTP requests.

### 13.4 HTTP POST (Agent-Initiated) :white_check_mark: `T3`

`http_client` plugin supports HTTP operations. Agent can fetch content from external URLs.

### 13.5 Peer-to-Peer Content Distribution :x: `T3`

Not implemented. P2P caching to reduce WAN bandwidth. Requires agent mesh networking.

---

## 14. User Interaction

*Display notifications, surveys, and dialogs on endpoint desktops.*

### 14.1 Desktop Notification :white_check_mark: `T2`

`interaction` plugin with `notify` action. Toast/balloon notifications with info/warning/error severity. Cross-platform: ShellNotifyIcon (Windows), notify-send (Linux), osascript (macOS).

### 14.2 Announcement Dialog :white_check_mark: `T2`

`interaction` plugin with `message_box` action. Modal message box with configurable buttons (ok, okcancel, yesno). Returns user response.

### 14.3 Question / Confirmation Dialog :white_check_mark: `T2`

`interaction` plugin with `input` action. Text input dialog with configurable prompt and default value. Returns entered text or cancellation. MessageBoxW (Windows), zenity (Linux), osascript (macOS).

### 14.4 Survey Dialog :x: `T3`

Not implemented. Multi-question form with response aggregation.

### 14.5 Do-Not-Disturb Mode :x: `T3`

Not implemented. Suppress notifications during user-defined windows.

### 14.6 Active Response Tracking :x: `T3`

Not implemented. List all active survey/question responses waiting for user input.

---

## 15. Inventory and Data Collection

*Structured inventory collection, storage, querying, and replication.*

### 15.1 Plugin-Based Inventory Reporting :white_check_mark: `T1`

`ReportInventory` RPC with per-plugin data blobs.

### 15.2 Inventory Persistence and Query :white_check_mark: `T1`

`QueryInventory` RPC on management API. Server stores inventory.

> **Gap:** No advanced query language (filtering, joins).

### 15.3 Inventory Table Enumeration :x: `T2`

Not implemented. List available inventory tables and schemas.

### 15.4 Inventory Evaluation (Item Lookup) :x: `T2`

Not implemented. Evaluate specific inventory items against criteria.

### 15.5 Inventory Replication (Local Replica) :x: `T3`

Not implemented. Agent-side cache with delta sync.

---

## 16. Policy and Compliance Engine (Guaranteed State)

*Define desired-state policies, evaluate compliance, and auto-remediate.*

### 16.1 Policy Rules Definition :white_check_mark: `T2`

`PolicyStore` with `PolicyFragment` (check/fix/postCheck pattern) and `Policy` kinds. YAML-defined with CEL compliance expressions. CRUD via REST API.

### 16.2 Policy Evaluation and Enforcement :white_check_mark: `T2`

`PolicyStore` tracks per-agent compliance status (compliant, non_compliant, unknown, fixing, error). Trigger-based evaluation with configurable trigger types (interval, file_change, service_status, event_log, registry, startup).

### 16.3 Policy Assignment to Device Groups :white_check_mark: `T2`

Policies support management group bindings via `PolicyGroupBinding`. Scope expressions for device targeting.

### 16.4 Compliance Summary and Statistics :white_check_mark: `T2`

`FleetCompliance` aggregate with compliance percentage. Per-policy `ComplianceSummary`. Compliance dashboard with fleet-level and per-policy drill-down to agent-level detail.

### 16.5 Evaluation History and Audit Trail :white_check_mark: `T2`

`PolicyAgentStatus` tracks last_check_at, last_fix_at, and check_result per agent per policy. Queryable via REST API.

### 16.6 Policy Event Subscriptions :white_check_mark: `T3`

Policy status changes tracked in compliance store. REST API endpoints expose compliance data for external consumption.

### 16.7 Cache Invalidation and Force Re-Evaluation :white_check_mark: `T2`

`invalidate_policy()` resets all agent statuses to pending for a specific policy. `invalidate_all_policies()` for fleet-wide reset. REST endpoints: `POST /api/policies/{id}/invalidate` and `POST /api/policies/invalidate-all`.

### 16.8 Pending Policy Changes Review :white_check_mark: `T2`

Policies support enable/disable toggle for staged deployment. REST endpoints: `POST /api/policies/{id}/enable` and `POST /api/policies/{id}/disable`.

---

## 17. Triggers and Event-Driven Automation

*React to endpoint events in real time: file changes, service state, intervals.*

### 17.1 Interval-Based Trigger :white_check_mark: `T2`

Trigger engine with `interval` type. Timer-based execution with configurable seconds/minutes/hours.

### 17.2 File / Directory Change Trigger :white_check_mark: `T2`

Trigger engine with `file_change` and `directory_change` types. Filesystem watcher using inotify (Linux), FSEvents (macOS), ReadDirectoryChangesW (Windows).

### 17.3 Service Status Change Trigger :white_check_mark: `T2`

Trigger engine with `service_status_change` type. React to service start/stop/crash via Windows SCM or systemd on Linux.

### 17.4 Windows Event Log Trigger :white_check_mark: `T2`

Trigger engine with `event_log` type. React to Windows Event Log entries matching XPath filters.

### 17.5 Registry Change Trigger :white_check_mark: `T3`

Trigger engine with `registry` type. React to registry key modifications on Windows.

### 17.6 Agent Startup Trigger :white_check_mark: `T2`

Trigger engine with `agent_startup` type. Execute actions on agent boot.

### 17.7 Trigger Templates (Server-Side) :white_check_mark: `T2`

`TriggerTemplate` YAML kind (`yuzu.io/v1alpha1`) for server-defined trigger configurations. Pre-configured trigger variants managed server-side and pushed to agents.

---

## 18. Server: Authentication and Authorization

*User authentication, role-based access control, and session management.*

### 18.1 Session-Based Authentication :white_check_mark: `T1`

Session-cookie auth with PBKDF2-hashed passwords.

### 18.2 Role-Based Access Control (Two Roles) :white_check_mark: `T1`

`admin` (full access) and `user` (read-only).

### 18.3 Granular RBAC :white_check_mark: `T2`

`RBACStore` (777 LOC): principals, custom roles, 10 securable types (Infrastructure, UserManagement, InstructionDefinition, InstructionSet, Execution, Schedule, Approval, Tag, AuditLog, Response), 5 operations (Read, Write, Execute, Delete, Approve). Deny-override, system roles, group-based assignments. Global enable/disable toggle.

### 18.4 Management-Group-Scoped Roles :x: `T2`

Not implemented. Role applies to specific device groups only.

### 18.5 OIDC / SSO Integration :white_check_mark: `T2`

`OidcProvider` (575 LOC): PKCE authorization code flow, OpenID Connect discovery, JWT validation (iss, aud, nonce, exp), Entra ID group claim parsing, group-to-role mapping (`--oidc-admin-group`), token exchange via platform HTTP (WinHTTP/httplib). Login page SSO button active.

### 18.6 Active Directory / Entra Integration :x: `T2`

Settings page has greyed-out AD/Entra section. Import users/groups, inherit roles from domain groups.

### 18.7 Token-Based API Authentication :white_check_mark: `T2`

`ApiTokenStore` with SQLite backend. Tokens generated via `POST /api/v1/tokens` with optional expiry. Auth via `Authorization: Bearer` header or `X-Yuzu-Token` header. RBAC permissions: `ApiToken:Read`, `ApiToken:Write`, `ApiToken:Delete`. Tokens support optional `mcp_tier` field for MCP integration (readonly/operator/supervised). Settings UI token management with create/revoke.

### 18.8 Device Authorization Tokens :x: `T2`

Not implemented. Per-instruction or per-device auth tokens.

### 18.9 HTTPS for Web Dashboard :white_check_mark: `T1`

`httplib::SSLServer` with OpenSSL. CLI flags: `--https`, `--https-port`, `--https-cert`, `--https-key`, `--no-https-redirect`. HTTP-to-HTTPS 301 redirect. Secure cookie flag. Settings UI TLS configuration section.

---

## 19. Server: Device and Group Management

*Organize endpoints into groups, scope operations, and manage device metadata.*

### 19.1 Agent Listing and Detail View :white_check_mark: `T1`

`ListAgents`, `GetAgent` RPCs. Web dashboard shows agent list.

### 19.2 Agent Lifecycle Events :white_check_mark: `T1`

`WatchEvents` RPC streams connect/disconnect/plugin-load events.

### 19.3 Scope / Filter-Based Device Selection :white_check_mark: `T2`

750-line recursive-descent `ScopeEngine` parser. 10 binary operators (`==`, `!=`, `LIKE`, `MATCHES`, `<`, `>`, `<=`, `>=`, `IN`, `CONTAINS`) plus 3 extended operators/functions (`EXISTS`, `LEN()`, `STARTSWITH()`), AND/OR/NOT combinators. `MATCHES` uses ECMAScript regex with safe error handling. Attributes: ostype, osver, hostname, arch, fqdn, `tag:*`. Target estimation via `/api/scope/estimate`.

### 19.4 Hierarchical Management Groups :x: `T2`

Not implemented. Nested groups with membership, access scoping, and SLA sync.

### 19.5 Device Discovery (Unmanaged Endpoints) :x: `T2`

Not implemented. Discover endpoints not yet running the agent.

### 19.6 Custom Properties on Devices :x: `T2`

Not implemented. Extensible metadata (key-value or typed properties).

### 19.7 Agent Deployment Jobs :x: `T2`

Not implemented. Server-initiated agent installer push to discovered endpoints.

---

## 20. Server: Response Collection and Reporting

*Aggregate, filter, paginate, and export command results.*

### 20.1 Real-Time Response Streaming :white_check_mark: `T1`

SSE-based streaming to dashboard. gRPC streaming for programmatic access.

### 20.2 Response Filtering and Pagination :white_check_mark: `T2`

`ResponseStore` with SQLite backend. `ResponseQuery` struct: agent_id, status, time range (since/until), limit/offset pagination. Exposed via `GET /api/responses/{instruction_id}` with query parameters.

### 20.3 Response Aggregation :white_check_mark: `T2`

`ResponseStore` aggregation engine with COUNT, SUM, AVG, MIN, MAX. Multi-column GROUP BY, incremental computation as responses arrive. REST endpoint with drill-down from aggregate to raw rows.

### 20.4 Per-Device Error Tracking :white_check_mark: `T2`

`ResponseStore` persists per-response `error_detail` alongside status. Queryable by agent_id, status code, and time range for error history.

### 20.5 CSV / Data Export :white_check_mark: `T2`

CSV and JSON export endpoints for responses, audit, and inventory data. RFC 4180-compliant CSV with streaming via chunked transfer encoding. Generic JSON-to-CSV conversion.

### 20.6 Response Templates :x: `T3`

Not implemented. Pre-defined response formats and views.

### 20.7 Response Offloading :x: `T3`

Not implemented. Route instruction responses to external HTTP endpoints.

---

## 21. Server: Notifications and Audit

*System events, audit trails, and external notification delivery.*

### 21.1 Agent Lifecycle Event Streaming :white_check_mark: `T1`

`WatchEvents` RPC.

### 21.2 Audit Trail of User Actions :white_check_mark: `T2`

`AuditStore` with SQLite WAL backend. Structured events: timestamp, principal, principal_role, action, target_type, target_id, detail, source_ip, result. Query with filtering and pagination via `/api/audit`. Default 365-day retention.

### 21.3 System Notifications :x: `T2`

Not implemented. Alerts for system health, license, and capacity.

### 21.4 Event Subscriptions (Webhook / Email) :x: `T3`

Not implemented. Push events to external systems.

### 21.5 Event Source Management :x: `T3`

Not implemented. Configure which events generate notifications.

---

## 22. Server: System and Infrastructure

*Monitoring, licensing, configuration, and multi-node scaling.*

### 22.1 System Health Monitoring :x: `T2`

Not implemented. CPU, memory, connection counts, queue depths.

### 22.2 System Topology View :x: `T2`

Not implemented. Visual map of server nodes, gateways, agent counts.

### 22.3 License Management :x: `T2`

Not implemented. Seat count, expiry, feature entitlements.

### 22.4 Platform Configuration (TTLs, Limits) :large_orange_diamond: `T2`

Some config in `yuzu-server.cfg`.

> **Gap:** No runtime configuration API; requires restart.

### 22.5 Gateway / Scale-Out Architecture :large_orange_diamond: `T2`

`gateway.proto` defines `GatewayUpstream` service with batch heartbeat, proxy register, and stream status.

> **Gap:** Gateway node not yet implemented.

### 22.6 Statistics Dashboard :x: `T2`

Not implemented. High-level and detailed operational statistics.

### 22.7 Binary Resource Distribution :x: `T3`

Not implemented. Distribute versioned binary resources via server.

### 22.8 Product Packs (Bundled Definitions) :x: `T3`

Not implemented. Import/export bundles of instruction definitions, policies, and templates.

---

## 23. Agent-Side Key-Value Storage

*Persistent key-value store on the agent for cross-instruction state.*

### 23.1 Local Key-Value Storage :white_check_mark: `T2`

`storage` plugin with `set`, `get`, `delete`, `list`, `clear` actions. SQLite-backed persistent key-value store on the agent. Keys namespaced per plugin. Survives agent restarts and upgrades.

### 23.2 Remote Key-Value Access :white_check_mark: `T3`

`storage` plugin actions are dispatchable via server instructions. Server can remotely read/write agent storage via standard command dispatch.

### 23.3 Key Existence Check :white_check_mark: `T2`

`storage` plugin `list` action with optional prefix filter. `get` returns empty result for non-existent keys.

---

## 24. Integration and Extensibility

*External system integration, data exchange, and API surface.*

### 24.1 Plugin SDK (C ABI + C++ Wrapper) :white_check_mark: `T1`

Stable `plugin.h` C ABI with `plugin.hpp` CRTP wrapper. `YUZU_PLUGIN_EXPORT` macro.

### 24.2 gRPC Management API :white_check_mark: `T1`

`ManagementService` with list/get/send/watch/query.

### 24.3 REST / HTTP Management API :large_orange_diamond: `T2`

70+ JSON endpoints covering instructions, executions, schedules, approvals, responses, audit, tags, scope, and settings. Session cookie and OIDC auth.

> **Gap:** Not yet under a versioned `/api/v1/` prefix. Needs consistent URL patterns and CORS configuration.

### 24.4 Consumer (External System) Registration :x: `T3`

Not implemented. Register external systems to receive data feeds.

### 24.5 Data Export to External Formats :x: `T2`

Not implemented. CSV, JSON export of inventory and responses.

### 24.6 Utility Functions (JSON/Table Conversion) :white_check_mark: `T1`

`yuzu_table_to_json()`, `yuzu_json_to_table()`, `yuzu_split_lines()`, `yuzu_generate_sequence()`, `yuzu_free_string()` in `sdk/include/yuzu/plugin.h` C ABI.

### 24.7 SDK Libraries for External Integrations :x: `T3`

Not implemented. Client libraries wrapping the management API for third-party integration.

### 24.8 MCP Server (Model Context Protocol) :white_check_mark: `T2`

Embedded MCP server at `POST /mcp/v1/` using JSON-RPC 2.0 transport. Enables AI models (e.g., Claude Desktop) to query fleet status, check compliance, and investigate agents. Phase 1: 22 read-only tools (`list_agents`, `get_agent_details`, `query_audit_log`, `list_definitions`, `get_definition`, `query_responses`, `aggregate_responses`, `query_inventory`, `list_inventory_tables`, `get_agent_inventory`, `get_tags`, `search_agents_by_tag`, `list_policies`, `get_compliance_summary`, `get_fleet_compliance`, `list_management_groups`, `get_execution_status`, `list_executions`, `list_schedules`, `validate_scope`, `preview_scope_targets`, `list_pending_approvals`), 3 resources (`yuzu://server/health`, `yuzu://compliance/fleet`, `yuzu://audit/recent`), 4 prompts (`fleet_overview`, `investigate_agent`, `compliance_report`, `audit_investigation`).

### 24.9 MCP Authorization Tiers :white_check_mark: `T2`

Three-tier authorization model enforced before RBAC: `readonly` (read-only tools), `operator` (+ tag writes, auto-approved executions), `supervised` (all operations via approval workflow). MCP tokens use existing API token system with `mcp_tier` column. Mandatory expiration (max 90 days). Kill switch: `--mcp-disable` rejects all MCP requests, `--mcp-read-only` blocks non-read tools.

### 24.10 MCP Settings UI :white_check_mark: `T2`

Settings page section for MCP configuration: enable/disable toggle, read-only mode toggle. API token creation supports MCP tier dropdown for creating MCP-scoped tokens.

---

## Appendix A: Plugin Coverage Matrix

| Plugin | Win | Linux | macOS | Category |
|--------|:---:|:-----:|:-----:|----------|
| os_info | Y | Y | Y | System Info |
| hardware | Y | Y | Y | System Info |
| device_identity | Y | Y | Y | System Info |
| status | Y | Y | Y | System Info |
| processes | Y | Y | Y | Process/Service |
| procfetch | Y | Y | Y | Process/Service |
| services | Y | Y | Y | Process/Service |
| users | Y | Y | Y | User |
| network_config | Y | Y | Y | Network |
| netstat | Y | Y | Y | Network |
| sockwho | Y | Y | Y | Network |
| network_diag | Y | Y | Y | Network |
| network_actions | Y | Y | Y | Network |
| installed_apps | Y | Y | Y | Software |
| msi_packages | Y | - | - | Software |
| windows_updates | Y | - | - | Patch |
| software_actions | Y | Y | Y | Software |
| sccm | Y | - | - | Software |
| antivirus | Y | Y | Y | Security |
| firewall | Y | Y | Y | Security |
| bitlocker | Y | - | - | Security |
| event_logs | Y | Y | Y | Security |
| vuln_scan | Y | Y | Y | Security |
| filesystem | Y | Y | Y | File System |
| script_exec | Y | Y | Y | Execution |
| agent_actions | Y | Y | Y | Agent Mgmt |
| diagnostics | Y | Y | Y | Agent Mgmt |
| chargen | Y | Y | Y | Test/Debug |
| example | Y | Y | Y | Test/Debug |

**44 plugins** -- covering hardware, network, security, filesystem, registry, WMI, and more. Includes cross-platform, Windows-only, and test/debug plugins.

---

## Appendix B: Foundation Tier Status

**Foundation tier: 33/33 done (100%)**

All Foundation-tier gaps have been closed as of 2026-03-18:

- **1.4** Agent OTA updates -- `agents/core/src/updater.cpp`
- **1.8** Connection diagnostics -- `connection_info` action in diagnostics plugin
- **4.5** DNS cache dump -- `dns_cache` action in network_config plugin
- **10.3** File read by line range -- `offset`/`limit` params in filesystem plugin
- **10.12** Temp file creation -- `yuzu_create_temp_file()` in SDK
- **18.9** HTTPS for dashboard -- `httplib::SSLServer` with OpenSSL
- **24.6** SDK utility functions -- 4 conversion functions in plugin.h
