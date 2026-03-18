# Yuzu Capability Map

**Version:** 1.1 | **Date:** 2026-03-18 | **Status:** Draft

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
Foundation   [===============================_]  32/33 done  (97%)
Advanced     [====---------------------------]  12/84 done   (14%)
Future       [-------------------------------]   0/22 done   (0%)
─────────────────────────────────────────────────────────────────
Overall      [==========--------------------]   44/139 done  (32%)
```

| Domain | Total | Done | Partial | Not Started |
|--------|:-----:|:----:|:-------:|:-----------:|
| 1. Agent Lifecycle | 9 | 6 | 1 | 2 |
| 2. Command Execution | 13 | 5 | 1 | 7 |
| 3. Device & Endpoint Info | 10 | 8 | 0 | 2 |
| 4. Network Info & Discovery | 11 | 6 | 0 | 5 |
| 5. Process & Service Mgmt | 5 | 4 | 0 | 1 |
| 6. User & Session Mgmt | 5 | 1 | 0 | 4 |
| 7. Software & App Mgmt | 6 | 4 | 0 | 2 |
| 8. Patch & Update Mgmt | 9 | 1 | 1 | 7 |
| 9. Security & Compliance | 10 | 5 | 0 | 5 |
| 10. File System Operations | 15 | 7 | 0 | 8 |
| 11. Script & Command Exec | 4 | 4 | 0 | 0 |
| 12. Registry & System Config | 7 | 0 | 0 | 7 |
| 13. Content Distribution | 5 | 0 | 0 | 5 |
| 14. User Interaction | 6 | 0 | 0 | 6 |
| 15. Inventory & Data Collection | 5 | 2 | 0 | 3 |
| 16. Policy & Compliance Engine | 8 | 0 | 0 | 8 |
| 17. Triggers & Automation | 7 | 0 | 0 | 7 |
| 18. Auth & Authorization | 9 | 3 | 0 | 6 |
| 19. Device & Group Mgmt | 7 | 3 | 0 | 4 |
| 20. Response Collection | 7 | 3 | 0 | 4 |
| 21. Notifications & Audit | 5 | 2 | 0 | 3 |
| 22. System & Infrastructure | 8 | 0 | 2 | 6 |
| 23. Agent Key-Value Storage | 3 | 0 | 0 | 3 |
| 24. Integration & Extensibility | 7 | 3 | 0 | 4 |
| **TOTAL** | **139** | **44** | **5** | **90** |

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

### 1.6 Agent Sleep and Stagger Control :x: `T2`

No mechanism for the server to instruct agents to sleep or stagger execution.

> **Need:** Large-scale rollouts require stagger control to avoid thundering herd problems.

### 1.7 Agent Logging and Log Retrieval :large_orange_diamond: `T2`

spdlog-based local logging on the agent. No remote log retrieval.

> **Gaps:** Need server-initiated log fetch, log level control, and log streaming.

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

### 2.6 Instruction Templates / Definitions :x: `T2`

Commands are ad-hoc `plugin + action + params`. No saved or named instruction templates.

> **Need:** Reusable instruction definitions with parameter schemas, versioning, and digital signing.

### 2.7 Instruction Sets (Grouping) :x: `T2`

No concept of grouped or chained instructions.

> **Need:** Workflow chaining (instruction A output feeds instruction B). Sets provide organizational hierarchy and access control scoping.

### 2.8 Instruction Hierarchies (Workflows) :x: `T2`

No parent-child instruction relationships.

> **Need:** DAG-based workflow execution with branching, conditionals, and follow-up instruction tracking.

### 2.9 Instruction Scheduling :x: `T2`

All commands are immediate. No deferred or recurring execution.

> **Need:** Cron-style scheduling with recurrence patterns, target scope expressions, and execution history tracking.

### 2.10 Instruction Approval Workflows :x: `T2`

No approval gates before execution.

> **Need:** Approval submission, review, notification pipeline, and per-instruction approval.

### 2.11 Target Estimation :x: `T2`

No pre-execution estimate of how many agents match a scope filter.

> **Need:** Safety check before large-scale operations via an `ApproxTarget` endpoint.

### 2.12 Instruction Progress Tracking :large_orange_diamond: `T2`

`CommandResponse.Status` tracks RUNNING/SUCCESS/FAILURE per agent.

> **Gap:** No aggregate progress (e.g., "247/1000 agents complete"), no summary/detail statistics views.

### 2.13 Instruction Rerun and Cancellation :x: `T2`

No mechanism to rerun failed instructions or cancel in-flight ones.

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

### 7.5 Per-User Application Inventory :x: `T2`

`installed_apps` returns system-wide only.

> **Need:** Per-user-hive enumeration (HKCU\Software) to distinguish system-wide from user-specific installs.

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

### 12.1 WMI Query Execution :x: `T2`

Can be approximated via `script_exec` (PowerShell), but no native WMI integration with structured output.

### 12.2 WMI Method Invocation :x: `T2`

Not implemented. Instance and static method calls.

### 12.3 WMI Namespace Enumeration :x: `T3`

Not implemented. List WMI namespaces, classes, and columns.

### 12.4 Registry Key/Value Read :x: `T2`

Can be approximated via `script_exec`, but no native registry plugin with structured output.

### 12.5 Registry Key/Value Write/Delete :x: `T2`

Not implemented. Full CRUD operations.

### 12.6 Registry Enumeration :x: `T2`

Not implemented. Recursive key/value listing.

### 12.7 Per-User Registry Operations :x: `T2`

Not implemented. Enumerate and modify registry values across all user hives.

---

## 13. Content Distribution

*Stage and distribute files, packages, and content to endpoints.*

### 13.1 Server-to-Agent Content Staging :x: `T2`

Not implemented. Push files/packages from server to agents.

### 13.2 Stage and Execute (Deploy + Run) :x: `T2`

Not implemented. Atomic download-then-execute workflow.

### 13.3 HTTP File Download (Agent-Initiated) :x: `T2`

Not implemented. Agent fetches content from arbitrary URL.

### 13.4 HTTP POST (Agent-Initiated) :x: `T3`

Not implemented. Agent sends data to external endpoint.

### 13.5 Peer-to-Peer Content Distribution :x: `T3`

Not implemented. P2P caching to reduce WAN bandwidth. Requires agent mesh networking.

---

## 14. User Interaction

*Display notifications, surveys, and dialogs on endpoint desktops.*

### 14.1 Desktop Notification :x: `T2`

Not implemented. Toast/balloon notification to logged-on user.

### 14.2 Announcement Dialog :x: `T2`

Not implemented. Modal message requiring acknowledgment.

### 14.3 Question / Confirmation Dialog :x: `T2`

Not implemented. Yes/No or multi-choice with response collection.

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

### 16.1 Policy Rules Definition :x: `T2`

Not implemented. Declarative rules (e.g., "service X must be running") with check instructions, fix instructions, and compliance state tracking.

### 16.2 Policy Evaluation and Enforcement :x: `T2`

Not implemented. Periodic check + auto-remediation. Rules evaluate on trigger fire, agent startup, and initial receipt with de-bounce.

### 16.3 Policy Assignment to Device Groups :x: `T2`

Not implemented. Scope policies to management groups.

### 16.4 Compliance Summary and Statistics :x: `T2`

Not implemented. Dashboard showing fleet compliance posture.

### 16.5 Evaluation History and Audit Trail :x: `T2`

Not implemented. When compliance was last checked, what changed.

### 16.6 Policy Event Subscriptions :x: `T3`

Not implemented. Notify external systems on compliance changes.

### 16.7 Cache Invalidation and Force Re-Evaluation :x: `T2`

Not implemented. On-demand compliance recheck.

### 16.8 Pending Policy Changes Review :x: `T2`

Not implemented. Review and deploy staged policy changes before they take effect.

---

## 17. Triggers and Event-Driven Automation

*React to endpoint events in real time: file changes, service state, intervals.*

### 17.1 Interval-Based Trigger :x: `T2`

Not implemented. Execute action every N minutes for periodic compliance checks.

### 17.2 File / Directory Change Trigger :x: `T2`

Not implemented. React to filesystem modifications.

### 17.3 Service Status Change Trigger :x: `T2`

Not implemented. React to service start/stop/crash.

### 17.4 Windows Event Log Trigger :x: `T2`

Not implemented. React to specific event IDs or patterns.

### 17.5 Registry Change Trigger :x: `T3`

Not implemented. React to registry key modifications.

### 17.6 Agent Startup Trigger :x: `T2`

Not implemented. Execute actions on agent boot.

### 17.7 Trigger Templates (Server-Side) :x: `T2`

Not implemented. Pre-configured trigger variants managed server-side.

---

## 18. Server: Authentication and Authorization

*User authentication, role-based access control, and session management.*

### 18.1 Session-Based Authentication :white_check_mark: `T1`

Session-cookie auth with PBKDF2-hashed passwords.

### 18.2 Role-Based Access Control (Two Roles) :white_check_mark: `T1`

`admin` (full access) and `user` (read-only).

### 18.3 Granular RBAC :x: `T2`

Only two hardcoded roles.

> **Need:** Custom roles, per-operation permissions (Create/Read/Execute/Write/Delete), securable type mapping, and instance-level security.

### 18.4 Management-Group-Scoped Roles :x: `T2`

Not implemented. Role applies to specific device groups only.

### 18.5 OIDC / SSO Integration :x: `T2`

Login page has greyed-out SSO stub. Full OIDC flow needed.

### 18.6 Active Directory / Entra Integration :x: `T2`

Settings page has greyed-out AD/Entra section. Import users/groups, inherit roles from domain groups.

### 18.7 Token-Based API Authentication :x: `T2`

Web UI uses session cookies only.

> **Need:** API tokens for automation and external integration.

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

494-line recursive-descent `ScopeEngine` parser. 9 operators (`==`, `!=`, `LIKE`, `<`, `>`, `<=`, `>=`, `IN`, `CONTAINS`), AND/OR/NOT combinators. Attributes: ostype, osver, hostname, arch, fqdn, `tag:*`. Target estimation via `/api/target/estimate`.

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

### 20.3 Response Aggregation :x: `T2`

Not implemented. Summarize responses across agents (counts, averages, distributions).

### 20.4 Per-Device Error Tracking :white_check_mark: `T2`

`ResponseStore` persists per-response `error_detail` alongside status. Queryable by agent_id, status code, and time range for error history.

### 20.5 CSV / Data Export :x: `T2`

Not implemented. Export query results for external tools.

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

### 23.1 Local Key-Value Storage :x: `T2`

Not implemented. Plugin-local persistent store (set/get/delete/list).

### 23.2 Remote Key-Value Access :x: `T3`

Not implemented. Server or other agents read an agent's stored values.

### 23.3 Key Existence Check :x: `T2`

Not implemented. Check if a storage table exists before accessing.

---

## 24. Integration and Extensibility

*External system integration, data exchange, and API surface.*

### 24.1 Plugin SDK (C ABI + C++ Wrapper) :white_check_mark: `T1`

Stable `plugin.h` C ABI with `plugin.hpp` CRTP wrapper. `YUZU_PLUGIN_EXPORT` macro.

### 24.2 gRPC Management API :white_check_mark: `T1`

`ManagementService` with list/get/send/watch/query.

### 24.3 REST / HTTP Management API :x: `T2`

Dashboard endpoints exist but no formal REST API.

> **Need:** Versioned REST API for external integration. All UIs and external integrations should use the same endpoints.

### 24.4 Consumer (External System) Registration :x: `T3`

Not implemented. Register external systems to receive data feeds.

### 24.5 Data Export to External Formats :x: `T2`

Not implemented. CSV, JSON export of inventory and responses.

### 24.6 Utility Functions (JSON/Table Conversion) :white_check_mark: `T1`

`yuzu_table_to_json()`, `yuzu_json_to_table()`, `yuzu_split_lines()`, `yuzu_generate_sequence()`, `yuzu_free_string()` in `sdk/include/yuzu/plugin.h` C ABI.

### 24.7 SDK Libraries for External Integrations :x: `T3`

Not implemented. Client libraries wrapping the management API for third-party integration.

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

**29 plugins** -- 24 cross-platform, 3 Windows-only, 2 test/debug.

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
