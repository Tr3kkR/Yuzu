# Yuzu Capability Map

**Version:** 3.0 | **Date:** 2026-03-30 | **Status:** Draft

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
Advanced     [================================]  101/101 done (100%)
Future       [====================------------]  31/50 done  (62%)
New (Ph 8-16)[=---------------------------]     1/41 done   (2%) (3 partial — Guardian PRs 1-2 + Guardian pre-login activation done; 15.A + 28.4 + 28.6 in flight)
─────────────────────────────────────────────────────────────────
Overall      [======================---------]   166/225 done (74%)
```

| Domain | Total | Done | Partial | Not Started |
|--------|:-----:|:----:|:-------:|:-----------:|
| 1. Agent Lifecycle | 9 | 9 | 0 | 0 |
| 2. Command Execution | 13 | 13 | 0 | 0 |
| 3. Device & Endpoint Info | 10 | 8 | 0 | 2 |
| 4. Network Info & Discovery | 11 | 9 | 0 | 2 |
| 5. Process & Service Mgmt | 5 | 4 | 0 | 1 |
| 6. User & Session Mgmt | 5 | 5 | 0 | 0 |
| 7. Software & App Mgmt | 6 | 6 | 0 | 0 |
| 8. Patch & Update Mgmt | 9 | 8 | 0 | 1 |
| 9. Security & Compliance | 10 | 9 | 0 | 1 |
| 10. File System Operations | 15 | 14 | 0 | 1 |
| 11. Script & Command Exec | 4 | 4 | 0 | 0 |
| 12. Registry & System Config | 7 | 7 | 0 | 0 |
| 13. Content Distribution | 5 | 5 | 0 | 0 |
| 14. User Interaction | 6 | 3 | 0 | 3 |
| 15. Inventory & Data Collection | 5 | 4 | 0 | 1 |
| 16. Policy & Compliance Engine | 8 | 8 | 0 | 0 |
| 17. Triggers & Automation | 7 | 7 | 0 | 0 |
| 18. Auth & Authorization | 10 | 9 | 0 | 1 |
| 19. Device & Group Mgmt | 7 | 7 | 0 | 0 |
| 20. Response Collection | 7 | 5 | 0 | 2 |
| 21. Notifications & Audit | 5 | 4 | 0 | 1 |
| 22. System & Infrastructure | 10 | 7 | 0 | 3 |
| 23. Agent Key-Value Storage | 3 | 3 | 0 | 0 |
| 24. Integration & Extensibility | 10 | 8 | 0 | 2 |
| 25. Connector Framework | 5 | 0 | 0 | 5 |
| 26. Inventory Repositories | 4 | 0 | 0 | 4 |
| 27. Software Catalog & Licensing | 5 | 0 | 0 | 5 |
| 28. Response Visualization | 6 | 0 | 1 | 5 |
| 29. Consumer Applications | 4 | 0 | 0 | 4 |
| 30. Scope Walking & Result Sets | 4 | 0 | 0 | 4 |
| 31. System Guardian | 10 | 1 | 2 | 7 |
| **TOTAL** | **225** | **166** | **3** | **56** |

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

### 1.9 Instruction Execution Statistics :white_check_mark: `T2`

`ExecutionTracker` aggregation methods: per-agent stats, per-definition stats, fleet summary. REST endpoints: `GET /api/v1/execution-statistics`, `/agents`, `/definitions`. HTMX fragment for dashboard card.

---

## 2. Command Execution and Orchestration

*Dispatching instructions to agents, collecting results, and workflow coordination.*

### 2.1 Single-Agent Command Dispatch :white_check_mark: `T1`

`ExecuteCommand` RPC with streaming response. `SendCommand` in the management API.

### 2.2 Multi-Agent Broadcast :white_check_mark: `T1`

`SendCommandRequest.agent_ids` supports broadcast (empty = all agents).

> **Gap:** No scope/filter-based targeting (e.g., "all Windows agents").

> **Gap:** Contradicts the stated capability to filter scope based on asset tag values as stated in asset-tagging-guide.md.

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

### 4.6 WiFi Network Enumeration :white_check_mark: `T2`

`wifi` plugin (cross-platform). `list_networks` scans for visible WiFi networks with SSID, signal strength, security type, channel, and BSSID. `connected` reports the currently connected network. Windows: WlanAPI, Linux: nmcli, macOS: airport.

### 4.7 Wake-on-LAN :white_check_mark: `T2`

`wol` plugin (cross-platform). `wake` sends magic packet (UDP broadcast, 6×0xFF + 16×MAC) to a target MAC address. `check` pings the host to verify wake. Windows: Winsock2, Linux/macOS: POSIX sockets.

### 4.8 Network Diagnostics :white_check_mark: `T1`

`network_diag` plugin (cross-platform). `network_actions` for ping.

### 4.9 NetBIOS / Name Lookup :x: `T3`

Not implemented. Legacy reverse lookup on IP addresses.

### 4.10 ARP Scanning (Subnet Discovery) :white_check_mark: `T3`

`discovery` plugin with `scan_subnet` action. ARP scan + ping sweep of a CIDR subnet to find hosts. Returns IP, MAC address, hostname, and managed/unmanaged status. Cross-platform: arp table parsing + ping sweep via subprocess. Input validation prevents command injection on CIDR parameter.

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

### 6.2 Primary User Determination :white_check_mark: `T2`

`users` plugin `primary_user` action. Identifies primary user via most-frequent-login heuristic. Linux: parses `last` output. macOS: parses `last` output. Windows: queries Event Log 4624 logon events, falls back to registry ProfileList.

### 6.3 Local Group Membership :white_check_mark: `T2`

`users` plugin `local_admins` action lists Administrators group members. `group_members` action enumerates members of any specified local group. Linux: parses `/etc/group` + checks sudo/wheel. Windows: NetLocalGroupGetMembers API. macOS: dscl.

### 6.4 User Connection History :white_check_mark: `T2`

`users` plugin `session_history` action. Historical login/logout records with configurable count (default 50). Cross-platform: parses `last` (Linux/macOS), Windows Event Log logon/logoff events.

### 6.5 Active Session Enumeration :white_check_mark: `T2`

`users` plugin `sessions` action. Lists active interactive sessions (console, RDP, SSH) with user, session type, login time, and state. Cross-platform.

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

### 7.6 Software Deployment (Install/Upgrade) :white_check_mark: `T2`

`SoftwareDeploymentStore` (SQLite) with package registration, deployment lifecycle (staged/deploying/verifying/completed/rolled_back/failed), per-agent status tracking. REST endpoints: `GET/POST /api/v1/software-packages`, `GET/POST /api/v1/software-deployments`, `/start`, `/rollback`, `/cancel`.

---

## 8. Patch and Update Management

*Detect, deploy, and track operating system and application patches.*

### 8.1 Installed Update Enumeration :white_check_mark: `T1`

`windows_updates` plugin with `installed` action. Cross-platform: Windows (Get-HotFix), Linux (rpm/apt), macOS (system_profiler).

### 8.2 Pending Reboot Detection :white_check_mark: `T1`

`windows_updates` plugin `pending_reboot` action. Cross-platform reboot-pending detection:
Windows (3 registry keys: WindowsUpdate RebootRequired, CBS RebootPending, Session Manager PendingFileRenameOperations),
Linux (reboot-required file + kernel version comparison + needs-restarting fallback),
macOS (softwareupdate restart flag). Reports per-source status and aggregate boolean.

### 8.3 Patch Deployment :white_check_mark: `T2`

`PatchManager` (794 LOC) with `deploy_patch()` orchestration: scan → download → install → verify → optional reboot. Per-target status tracking (pending, scanning, downloading, installing, verifying, completed, failed, skipped). REST endpoints for deployment CRUD and cancellation.

### 8.4 Patch Status Tracking :white_check_mark: `T2`

`PatchManager` tracks per-device deployment status via `PatchDeploymentTarget`. Per-agent status, error messages, start/complete timestamps. `recalculate_deployment_progress()` maintains aggregate counts. Queryable via REST API.

### 8.5 Patch Metadata Retrieval :white_check_mark: `T2`

`PatchInfo` stores KB ID, title, severity (Critical/Important/Moderate/Low/Unspecified), release date, and scan timestamp. `get_fleet_patch_summary()` returns per-KB missing counts. `get_missing_patches()` and `get_installed_patches()` support severity and agent filtering.

### 8.6 Reboot Management (Post-Patch) :white_check_mark: `T2`

Full reboot orchestration in `PatchManager::execute_deployment()`. Configurable `reboot_delay_seconds` (default 300, clamped [60, 86400]) and optional `reboot_at` epoch timestamp for maintenance windows. Pre-reboot user notification via `device.interaction.notify` (best-effort). Cross-platform reboot commands: Windows `shutdown /r /t N /c`, Linux/macOS `shutdown -r +N`. Target status lifecycle includes `"rebooting"` state. REST API accepts `reboot_delay_seconds` and `reboot_at` in `POST /api/patches/deploy`.

### 8.7 Update Summary and Compliance Reporting :white_check_mark: `T2`

`PatchManager::get_fleet_patch_summary()` returns fleet-wide patch compliance (per-KB missing agent counts). `get_missing_patches()` with `PatchQuery` filters by agent, severity, status. Deployment tracking with aggregate progress.

### 8.8 Patch Connectivity Testing :white_check_mark: `T2`

`patch_connectivity` action in `windows_updates` plugin. Per-target DNS resolution (getaddrinfo), TCP connect (non-blocking socket), latency measurement. Platform-specific defaults: Windows Update/WSUS, apt/yum repos, Apple SWUpdate.

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

### 9.6 Device Quarantine (Network Isolation) :white_check_mark: `T2`

`quarantine` plugin (cross-platform). `quarantine` action isolates device from network, whitelisting management server and optional IPs via firewall rules (prefixed `YuzuQuarantine_`). `unquarantine` removes rules and restores access. `status` checks active quarantine state. `whitelist` adds/removes IPs from active quarantine.

### 9.7 Indicator of Compromise (IOC) Checking :white_check_mark: `T2`

`ioc` plugin with `check` action. Matches indicators against local endpoint state: `ip_addresses` checked against active TCP/UDP connections, `domains` against DNS cache, `file_hashes` (SHA-256) against files on disk, `file_paths` for existence, `ports` for listening services. Cross-platform: Windows (GetExtendedTcpTable, DnsGetCacheDataTable), Linux (/proc/net/tcp), macOS (lsof).

### 9.8 Certificate Inventory (Get/Delete) :white_check_mark: `T2`

`certificates` plugin with `list`, `details`, and `delete` actions. Enumerates certificates in system stores with thumbprint, subject, issuer, expiry, and key usage. Windows: CryptoAPI (CertOpenStore, CertEnumCertificatesInStore). Linux: PEM files in /etc/ssl/certs/. macOS: security find-certificate.

### 9.9 Quarantine Status Tracking :white_check_mark: `T2`

`QuarantineStore` (SQLite backend). Server-side quarantine records with agent_id, status (active/released), quarantined_by, timestamps, whitelist, and reason. `list_quarantined()` for active quarantines, `get_history()` for per-agent quarantine history. REST API endpoints for quarantine/release/status.

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

### 10.7 File Permissions Inspection :white_check_mark: `T2`

`filesystem` plugin `get_acl` action. Windows: full DACL enumeration via GetNamedSecurityInfo — returns each ACE with trustee, access mask, and ace type. Linux/macOS: POSIX `stat()` permissions (owner, group, other, special bits).

### 10.8 Digital Signature Verification :white_check_mark: `T2`

`filesystem` plugin `get_signature` action. Windows: Authenticode verification via WinVerifyTrust — reports signature status (valid, invalid, unsigned, untrusted), signer name, and timestamp. Linux/macOS: returns platform-unsupported status.

### 10.9 File Version Info :white_check_mark: `T2`

`get_version_info` action in `filesystem` plugin. Windows: GetFileVersionInfoW/VerQueryValueW for VS_FIXEDFILEINFO + string table. Returns file_version, product_version, company_name, file_description, etc. Returns platform-unsupported on Linux/macOS.

### 10.10 File Content Search and Replace :white_check_mark: `T2`

Five new actions in `filesystem` plugin: `search` (line-by-line pattern matching, literal or regex), `replace` (atomic temp+rename), `write_content`, `append`, `delete_lines`. All enforce base_dir restrictions. Pattern capped at 256 chars. Binary detection.

### 10.11 Directory Hash (Recursive) :x: `T3`

Not implemented. Integrity verification of directory trees.

### 10.12 Temp File Creation :white_check_mark: `T1`

`yuzu_create_temp_file()` and `yuzu_create_temp_dir()` in SDK with secure permissions (POSIX mkstemps 0600, Windows owner-only DACL). Exposed via filesystem plugin `create_temp`/`create_temp_dir` actions.

### 10.13 File Retrieval (Upload to Server) :white_check_mark: `T2`

`upload_file` action in `content_dist` plugin. Agent-side: SHA-256 hash, multipart POST to server. Server-side: `POST /api/v1/file-retrieval` endpoint. File stored in `{data_dir}/file-retrieval/`. `GET/DELETE` endpoints for management.

### 10.14 Find File by Size and Hash :white_check_mark: `T2`

`filesystem` plugin `find_by_hash` action. Searches directory trees for files matching a SHA-256 hash. Used for malware hunting and file integrity verification. Recursive search with configurable root path.

### 10.15 Directory Search by Name :white_check_mark: `T2`

`search_dir` action in `filesystem` plugin. `fs::recursive_directory_iterator` with glob or regex name matching. Parameters: root, pattern, match_type (directories/files/both), max_depth, max_results. Respects base_dir.

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

### 15.3 Inventory Table Enumeration :white_check_mark: `T2`

`InventoryStore::list_tables()` returns all distinct inventory "tables" (one per plugin) with agent count and last collection timestamp. REST API endpoint and MCP `list_inventory_tables` tool expose this data.

### 15.4 Inventory Evaluation (Item Lookup) :white_check_mark: `T2`

`inventory_eval.hpp/cpp` evaluation engine. JSON dot-path field extraction, 10 comparison operators including version_gte/version_lte (semver-aware). REST: `POST /api/v1/inventory/evaluate` with conditions array and AND/OR combine.

### 15.5 Inventory Replication (Local Replica) :x: `T3`

Not implemented. Agent-side cache with delta sync.

---

## 16. Policy and Compliance Engine (Server-Side Guaranteed State)

*Define desired-state policies, evaluate compliance on a poll-based schedule, and auto-remediate. This domain covers the **server-side** half of guaranteed state — definition, fleet-wide compliance evaluation, history, drill-down. Real-time **agent-side** enforcement (kernel-event-driven, millisecond-level, pre-login, offline-capable) lives in §31 (System Guardian) and is the operational primitive that makes "this setting must never be in a non-compliant state" actually true on disk. A complete guaranteed-state implementation requires both halves — §16 alone has a 5-minute poll cycle that is unacceptable for security-sensitive settings (firewall, registry, EDR process running, SSH config).*

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

### 18.4 Management-Group-Scoped Roles :white_check_mark: `T2`

`ManagementGroupStore` supports group-scoped role assignments. `assign_role()` / `unassign_role()` bind principals to roles within a specific group. `get_visible_agents()` resolves which agents a user can see based on their group-scoped roles. REST endpoints at `/api/v1/management-groups/{id}/roles` (GET/POST/DELETE). RBAC integration filters agent lists to respect group-scoped visibility.

### 18.5 OIDC / SSO Integration :white_check_mark: `T2`

`OidcProvider` (575 LOC): PKCE authorization code flow, OpenID Connect discovery, JWT validation (iss, aud, nonce, exp), Entra ID group claim parsing, group-to-role mapping (`--oidc-admin-group`), token exchange via platform HTTP (WinHTTP/httplib). Login page SSO button active. Runtime-configurable via Settings UI (`POST /api/settings/oidc`) — admin can enter issuer, client_id, client_secret, redirect_uri, and admin_group from the dashboard without server restart. "Test Connection" button validates OIDC discovery endpoint. TLS cert verification configurable (`--oidc-skip-tls-verify`).

### 18.6 Active Directory / Entra Integration :white_check_mark: `T2`

`DirectorySync` (1013 LOC). Entra ID sync via Microsoft Graph API (OAuth2 client credentials flow). Fetches `/users` and `/groups`, stores in SQLite. Group-to-role mapping (`configure_group_role_mapping`) maps directory groups to RBAC roles. LDAP sync stub for on-prem AD (full LDAP support planned). REST API endpoints for sync trigger, status, and mapping CRUD. Settings UI section active.

### 18.7 Token-Based API Authentication :white_check_mark: `T2`

`ApiTokenStore` with SQLite backend. Tokens generated via `POST /api/v1/tokens` with optional expiry. Auth via `Authorization: Bearer` header or `X-Yuzu-Token` header. RBAC permissions: `ApiToken:Read`, `ApiToken:Write`, `ApiToken:Delete`. Tokens support optional `mcp_tier` field for MCP integration (readonly/operator/supervised). Settings UI token management with create/revoke.

### 18.8 Device Authorization Tokens :white_check_mark: `T2`

`DeviceTokenStore` (SQLite) with SHA-256 hashed tokens, device_id and definition_id scoping. REST: `GET/POST/DELETE /api/v1/device-tokens`. Integrated into auth chain.

### 18.9 HTTPS for Web Dashboard :white_check_mark: `T1`

`httplib::SSLServer` with OpenSSL. CLI flags: `--https`, `--https-port`, `--https-cert`, `--https-key`, `--no-https-redirect`. HTTP-to-HTTPS 301 redirect. Secure cookie flag. Settings UI TLS configuration section.

### 18.10 Two-Factor Authentication for Approvals :x: `T2`

Not implemented. TOTP (RFC 6238) second factor for instruction approval workflows. Per-user TOTP enrollment with QR code, email-based OTP fallback.

---

## 19. Server: Device and Group Management

*Organize endpoints into groups, scope operations, and manage device metadata.*

### 19.1 Agent Listing and Detail View :white_check_mark: `T1`

`ListAgents`, `GetAgent` RPCs. Web dashboard shows agent list.

### 19.2 Agent Lifecycle Events :white_check_mark: `T1`

`WatchEvents` RPC streams connect/disconnect/plugin-load events.

### 19.3 Scope / Filter-Based Device Selection :white_check_mark: `T2`

750-line recursive-descent `ScopeEngine` parser. 10 binary operators (`==`, `!=`, `LIKE`, `MATCHES`, `<`, `>`, `<=`, `>=`, `IN`, `CONTAINS`) plus 3 extended operators/functions (`EXISTS`, `LEN()`, `STARTSWITH()`), AND/OR/NOT combinators. `MATCHES` uses ECMAScript regex with safe error handling. Attributes: ostype, osver, hostname, arch, fqdn, `tag:*`. Target estimation via `/api/scope/estimate`.

### 19.4 Hierarchical Management Groups :white_check_mark: `T2`

`ManagementGroupStore` with `parent_id` for nesting. `get_children()` returns direct children. `get_ancestor_ids()` / `get_descendant_ids()` traverse the hierarchy. Static membership (manual add/remove) and dynamic membership (scope expression evaluation via `refresh_dynamic_membership()`). Well-known root group. REST CRUD + hierarchy endpoints. Group-scoped role assignments for access control.

### 19.5 Device Discovery (Unmanaged Endpoints) :white_check_mark: `T2`

`discovery` agent plugin (`scan_subnet` action) performs ARP scan + ping sweep of CIDR subnets. Server-side `DiscoveryStore` persists discovered devices with IP, MAC, hostname, managed status, discovering agent, and subnet. `mark_managed()` links discovered IPs to enrolled agents. REST API for listing and clearing results.

### 19.6 Custom Properties on Devices :white_check_mark: `T2`

`CustomPropertiesStore` (462 LOC). Typed key-value properties per device: string, int, bool, datetime. Schema CRUD with validation regex. Usable in scope expressions via `props.<key>`. Property validation against schemas. REST API for property and schema CRUD. Key validation (1-64 chars, `[a-zA-Z0-9_.-:]`), value limit 1024 bytes.

### 19.7 Agent Deployment Jobs :white_check_mark: `T2`

`DeploymentStore` with job management. Create deployment jobs targeting discovered hosts by IP, OS, and method (ssh, group_policy, manual). Job lifecycle: pending → running → completed/failed/cancelled. REST API for job CRUD, status updates, and cancellation.

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

### 21.3 System Notifications :white_check_mark: `T2`

`NotificationStore` (SQLite backend). Create notifications with level (info/warn/error/success), title, and message. List unread/all, mark as read, dismiss (soft-delete), count unread. Server generates notifications for system events (agent registration, policy violations, deployment completions). REST API and dashboard bell icon integration.

### 21.4 Event Subscriptions (Webhook / Email) :white_check_mark: `T3`

`WebhookStore` (437 LOC). Register webhooks with URL, event type filter (comma-separated), and HMAC-SHA256 signing secret. Async delivery on detached threads with 10-concurrent-delivery semaphore. Delivery history with status codes and errors. `fire_event()` dispatches matching webhooks automatically. REST API for webhook CRUD and delivery log.

### 21.5 Event Source Management :x: `T3`

Not implemented. Configure which events generate notifications.

---

## 22. Server: System and Infrastructure

*Monitoring, licensing, configuration, and multi-node scaling.*

### 22.1 System Health Monitoring :white_check_mark: `T2`

Kubernetes-style health probes: `/livez` (always 200) and `/readyz` (checks store connectivity). Gateway health endpoint with circuit breaker status. Prometheus `/metrics` endpoint exposes server/agent/gateway metrics. `ProcessHealthSampler` provides cross-platform (Linux `/proc/self`, macOS `mach_task_info`/`getrusage`, Windows `GetProcessMemoryInfo`/`GetProcessTimes`) process telemetry sampled every 15s. New Prometheus metrics: `yuzu_server_cpu_usage_percent`, `yuzu_server_memory_bytes{type=rss|vss}`, `yuzu_server_open_connections`, `yuzu_server_command_queue_depth`, `yuzu_server_uptime_seconds`. `/health` endpoint includes `system` object with CPU, memory, connections, queue depth. Health dashboard strip shows CPU% and memory.

### 22.2 System Topology View :white_check_mark: `T2`

`topology_ui.cpp` dashboard page at `/topology`. HTMX fragment `/frag/topology-data` (30s poll). Shows server node, gateway badges, management group tree, OS breakdown. REST: `GET /api/v1/topology`.

### 22.3 License Management :white_check_mark: `T2`

`LicenseStore` (SQLite) with seat-based licensing, expiry, edition, feature flags. Soft enforcement with alerts at 90% seats / 30 days to expiry. REST: `GET/POST/DELETE /api/v1/license`, `GET /api/v1/license/alerts`.

### 22.4 Platform Configuration (TTLs, Limits) :white_check_mark: `T2`

`RuntimeConfigStore` (219 LOC). Persistent runtime configuration overrides in SQLite. Allow-listed safe keys only (no secrets). Set/get/remove with `updated_by` attribution. Changes take effect without restart. REST API for configuration CRUD. Startup defaults overridden by stored values.

### 22.5 Gateway / Scale-Out Architecture :white_check_mark: `T2`

Full Erlang/OTP gateway (`gateway/` rebar3 project). `yuzu_gw_agent` manages agent connections, `yuzu_gw_upstream` handles server-side gRPC (batch heartbeat, proxy register, command forwarding). `yuzu_gw_heartbeat_buffer` batches heartbeats for efficiency. Circuit breaker for upstream resilience. Health endpoint with metrics. Supervision tree with restart strategies. EUnit + Common Test suites including scale tests (10K+ agents).

### 22.6 Statistics Dashboard :white_check_mark: `T2`

`statistics_ui.cpp` dashboard page at `/statistics`. Six HTMX cards (fleet, executions, compliance, top instructions, license, system health) each with independent 60s polling. REST: `GET /api/v1/statistics`.

### 22.7 Binary Resource Distribution :x: `T3`

Not implemented. Distribute versioned binary resources via server.

### 22.8 Product Packs (Bundled Definitions) :white_check_mark: `T3`

`ProductPackStore` (680 LOC). Install multi-document YAML bundles containing InstructionDefinitions, PolicyFragments, Policies, TriggerTemplates. Ed25519 signature verification (OpenSSL on Unix, BCrypt on Windows). Install/uninstall with callback delegation to origin stores. Pack metadata, item tracking, and version management. REST API for pack CRUD.

### 22.9 Database Sharding (Response Partitioning) :x: `T3`

Not implemented. Time-partitioned response storage (monthly SQLite files) with automatic rotation, TTL cleanup, and transparent cross-partition query routing.

### 22.10 High Availability (Active-Passive) :x: `T3`

Not implemented. Active-passive failover with shared storage, inter-server heartbeat, automatic failover on primary health check failure, and gateway re-registration.

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

### 24.3 REST / HTTP Management API :white_check_mark: `T2`

70+ JSON endpoints under versioned `/api/v1/` prefix. Full CRUD for instructions, executions, schedules, approvals, responses, audit, tags, scope, management groups, policies, tokens, inventory, patches, webhooks, notifications, discovery, and custom properties. Session cookie, OIDC, and API token auth. CORS origin allowlist. OpenAPI spec at `/api/v1/openapi.json`. Consistent JSON error envelopes.

### 24.4 Consumer (External System) Registration :x: `T3`

Not implemented. Register external systems to receive data feeds.

### 24.5 Data Export to External Formats :white_check_mark: `T2`

CSV and JSON export endpoints. RFC 4180-compliant CSV with streaming via chunked transfer encoding. Generic `json_array_to_csv` converter at `/api/export/json-to-csv`. Response data export with Content-Disposition headers. Audit log and inventory data also exportable via REST API JSON endpoints.

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

## 25. Connector Framework

*Bidirectional data sync with external management systems.*

### 25.1 Connector Registry and Configuration :x: `T2`

Not implemented. Pluggable connector architecture for syncing inventory data from external systems. ConnectorStore with encrypted credentials, sync scheduling, and connection testing.

### 25.2 Connector Sync Engine :x: `T2`

Not implemented. Background sync execution with lifecycle management (NotStarted → Pending → InProgress → Completed/Failed/Cancelled).

### 25.3 SCCM / ConfigMgr Connector :x: `T2`

Not implemented. SQL query integration with ConfigMgr database for hardware, software, user, and patch inventory.

### 25.4 Intune Connector :x: `T2`

Not implemented. Microsoft Graph API integration for managed device inventory and compliance state.

### 25.5 ServiceNow Connector :x: `T2`

Not implemented. REST API integration with ServiceNow CMDB for CI records, incidents, and change requests.

---

## 26. Inventory Repositories

*Named, multi-source inventory partitions with consolidation and normalization.*

### 26.1 Repository Model :x: `T2`

Not implemented. Named repositories per type (inventory, compliance, entitlement) with connector bindings and default repository.

### 26.2 Inventory Consolidation :x: `T2`

Not implemented. Multi-source deduplication by device identity (hostname + MAC + serial). Consolidation reports showing matched vs. unmatched records.

### 26.3 Software Normalization :x: `T2`

Not implemented. Vendor/title/version canonicalization pipeline. Normalize raw inventory entries to canonical software identities.

### 26.4 WSUS / CSV / File Upload Connectors :x: `T2`

Not implemented. WSUS database connector for patch compliance. CSV/TSV file upload connector with configurable column mapping.

---

## 27. Software Catalog & Licensing

*Normalized software identification and license compliance management.*

### 27.1 Software Catalog Store :x: `T2`

Not implemented. Canonical software registry (vendor, title, version, edition, platform) with manual curation and automatic matching from raw inventory.

### 27.2 Software Usage Tracking :x: `T2`

Not implemented. Agent-side application usage metering (launch tracking, run time, last-used timestamp). Categorization: Used, Rarely Used, Unused, Unreported.

### 27.3 License Entitlements & Compliance :x: `T2`

Not implemented. Entitlement records (product, purchased_seats, license_type). Compliance calculation: installed vs. entitled with over/under-licensed reporting.

### 27.4 Software Tags :x: `T2`

Not implemented. Server-side tags on software catalog entries for categorization (approved, prohibited, eval). Usable in Management Group rules.

### 27.5 License Compliance Dashboard :x: `T2`

Not implemented. Per-product compliance summary with drill-down to device-level detail. Reclamation candidate identification from usage data.

---

## 28. Response Visualization

*Chart rendering, data processing, and template management for instruction responses.*

### 28.1 Response Visualization Engine :white_check_mark: `T2`

Implemented. Server-side data transformation with built-in processors (`single_series`, `multi_series`, `datetime_series`) and an optional row pre-filter (`whereField` / `whereEquals`). Chart types: pie, bar, column, line, area. Configured via `spec.visualization` (singular) or `spec.visualizations` (plural for multi-chart). REST: `GET /api/v1/executions/{id}/visualization?definition_id=<id>&index=<N>` gated on `Response:Read`. Renderer is Apache ECharts 5 (vendored at `/static/echarts.min.js`) wrapped by a thin adapter at `/static/yuzu-charts.js` that reads Cisco Momentum `--mds-color-chart-*` design tokens at render time. Six chart-bearing demo definitions (vuln_scan, antivirus, bitlocker, firewall, certificates, os_info) ship as `InstructionSet demo.visualization.fleet-posture`, auto-imported on server startup.

### 28.2 Response Templates :x: `T2`

Not implemented. Named response view configurations (column selection, sort order, filter presets) stored per InstructionDefinition.

### 28.3 Response Offloading :x: `T2`

Not implemented. Configure external HTTP endpoints to receive response data in real time. OffloadTarget model with auth, event filtering, and batch delivery.

### 28.4 TAR Dashboard Page :large_orange_diamond: `T2`

In progress (Phase 15.A and 15.D). A dedicated `/tar` page off the main dashboard nav. Surfaces, in one place, every operator-facing TAR affordance: ad-hoc SQL against agent warehouses with scope-walking-aware results (`save as result set` for downstream narrowing), retention awareness across the fleet, and the process tree viewer. The consolidation makes TAR — the headline forensics + inventory capability — a discoverable destination rather than a fragment scattered across other pages. Design: `docs/tar-dashboard.md`.

### 28.5 TAR Process Tree Viewer :x: `T2`

Not implemented (Phase 15.H). Reconstructs the per-device process tree from `process_live` — a seed snapshot taken at agent install / first start (walks `/proc` on Linux, `CreateToolhelp32Snapshot` + `Process32FirstW`/`NextW` on Windows, `proc_listallpids` + `proc_pidinfo` on macOS) plus subsequent `started` / `stopped` events from the regular `collect_fast` cycle. Renders as a collapsible tree with honest "as observed since `<seed_ts>`" framing — orphans whose parents died before the seed appear reparented to PID 1, exactly as in a live `ps`. Time-slicing via `?as_of=<ts>`. Cmdline redaction reuses the existing TAR redaction patterns. Data quality depends on agent uptime and tamper-resistance — that hardening pillar is the parallel Guardian PR ladder and does not block the viewer. Design: `docs/tar-dashboard.md` §5.

### 28.6 Retention Awareness Surface :large_orange_diamond: `T2`

In progress (Phase 15.A). Operator-facing aggregate view of every device × source pair where `<source>_enabled=false` — the operational consequence of issue #539's per-source retention pause. Surfaces "paused since" timestamp, live-row count, oldest timestamp; supports one-click re-enable (per-source, the #539 invariant) and a typed-confirmation purge for the "we have what we need, drop the rows but keep the collector paused" case. Without this surface, operators who disabled a collector for forensic preservation have no way to know which boxes are accumulating non-aging data. Design: `docs/tar-dashboard.md` §3.

---

## 29. Consumer Applications

*Formal registration and management of external systems consuming Yuzu data.*

### 29.1 Consumer Application Registration :x: `T2`

Not implemented. ConsumerStore for registering third-party applications with scoped API tokens, rate limits, and custom data fields.

### 29.2 Event Source Management :x: `T2`

Not implemented. Configure which system events generate notifications and webhook deliveries. Per-category enable/disable with severity thresholds.

### 29.3 PowerShell Module :x: `T3`

Not implemented. `Yuzu.Management` PowerShell module wrapping REST API v1 with cmdlets for fleet management, instruction execution, and compliance queries.

### 29.4 Python SDK :x: `T3`

Not implemented. `yuzu-sdk` Python package wrapping REST API v1 with async support and typed models.

---

## 30. Scope Walking & Result Sets

*The Yuzu product differentiator. Operator working memory is finite; the IT estate is a finite-state automaton with mutating state-table size and mutating per-row state. Real-time discovery via iterative scope narrowing — every query produces a device set that becomes the input scope for the next query or action — is the only realistic interaction model at fleet scale. Reference walkthrough: the Chrome incident-response scenario in `docs/scope-walking-design.md` §10.*

### 30.1 Result Set Persistence and Lineage :x: `T2`

Not implemented (Phase 15.B). A named, TTL-bounded set of device IDs produced by a query, action result, or operator-curated list — the unit of composable scope. Stable identity (`rs_<ulid>`), optional human-readable per-operator alias, immutable lineage edges that record the chain of `(parent_result_set, narrowing_query)` back to a ground set, source-payload JSON sufficient to live-re-evaluate the producing query without operator re-input. Persisted in `result_sets.db` with `ON DELETE CASCADE` member rows; pinning extends TTL beyond the default 1 hour for incident-response sessions; per-operator quotas (10K result sets, 50 pins) and a 5-minute background GC sweep prevent runaway scripts from filling the table. REST: `/api/v1/result-sets/...` covering create-from-inventory/tar/instruction, members, lineage, pin/unpin/re-eval, delete. Audit row per state transition for forensic reconstruction. Design: `docs/scope-walking-design.md` §3, §6, §9.

### 30.2 Composable Scope from Previous Query :x: `T2`

Not implemented (Phase 15.C). The Scope Engine grammar gains a third short-circuit kind, `from_result_set:<id-or-alias>`, alongside the existing `__all__` and `group:<name>`. Composes with attribute predicates via `AND`/`OR`/`NOT` so a result set can be the candidate set and the predicate is a real-time refinement against current device attributes. Stale members (offline > 24h, decommissioned, removed from management group) are silently dropped at resolve time with a dashboard-surfaced warning rather than failing the query — operators iterating an IR chain need progress, not a stop, and the audit row records the dropped IDs for forensic completeness. Dashboard surfacing: persistent left-rail sidebar of the operator's active result sets, chain breadcrumb above every query frame mirroring the lineage, scope chip in every query/instruction/policy frame for one-click rebinding. Design: `docs/scope-walking-design.md` §4, §8.

### 30.3 YAML DSL `fromResultSet:` Surface :x: `T2`

Not implemented (Phase 15.E). The `scope:` block in `InstructionDefinition`, `InstructionSet`, and `Policy` gains `fromResultSet:` as a mutually-exclusive (or composable-with-`selector:`) alternative form so YAML-defined automation can target the device set produced by a previous query. Validation rules: `fromResultSet + assignment.managementGroups` rejected at YAML load (a result set already has a fixed device set, layering management-group filtering on top is redundant); `fromResultSet` requires `assignment.mode = static` (the whole point of a result set is a fixed target — `dynamic` re-evaluation against management groups would defeat it). Resolution at instruction *invocation* time, not YAML load time, so a definition carrying `fromResultSet:` is valid YAML even if the referenced set has expired by invocation. Resolution failure surfaces as `INSTRUCTION_SCOPE_RESOLUTION_FAILED` with the result-set ID and reason in the audit row. Design: `docs/scope-walking-design.md` §7.

### 30.4 Result Set Operational Hardening :x: `T2`

Not implemented (Phase 15.G). Live re-evaluation produces a *new* result set ID rooted at the original's parent (sibling, not child) — operators can refresh a stale set against current estate state without breaking lineage. Background GC sweep every 5 minutes removes unpinned sets past TTL, cascading to member rows. Per-operator quotas enforced with `429 RESULT_SET_QUOTA` and `409 PIN_LIMIT`. Prometheus metrics — `yuzu_result_sets_total`, `yuzu_result_sets_alive`, `yuzu_result_set_resolve_seconds` histogram by cardinality bucket, GC counter, quota-rejection counter — surface health and runaway-script detection. Audit polish on every state transition. Design: `docs/scope-walking-design.md` §3.3, §9.

---

## 31. System Guardian — Real-Time Agent-Side Guaranteed State

*The agent-side primitive that makes guaranteed state **operationally true** rather than approximately true. PolicyStore (§16) evaluates desired-state rules on a poll-based schedule — typical 5-minute cadence. For security-sensitive settings ("this firewall port must never be open," "this registry value must never change," "this EDR process must always run") a 5-minute window is unacceptable. System Guardian uses **kernel-backed user-mode notification APIs** to detect drift within microseconds of it occurring, remediate it, and journal the event — even when the server is unreachable, even before any user has logged in. This is the headline parity feature against 1E Tachyon's Guaranteed State. Agent runs in user space as SYSTEM (Windows) / root (Linux) / privileged daemon (macOS); no kernel drivers required. Design: `docs/yuzu-guardian-design-v1.1.md`. Windows-first delivery: `docs/yuzu-guardian-windows-implementation-plan.md`.*

### 31.1 Guardian Engine and Wire Protocol :large_orange_diamond: `T2`

In progress (PRs 1-2 shipped). Agent-side `GuardianEngine` (`agents/core/src/guardian_engine.{hpp,cpp}`) with two-phase startup — `start_local()` pre-network so enforcement is active before the Register RPC, then `sync_with_server()` post-Register. KV namespace `__guardian__` for cached policy. Reserved plugin name `__guard__` intercepted in `agent.cpp` before the plugin match loop (load-time rejection in `plugin_loader.cpp` for defence in depth). Wire contract: `proto/yuzu/guardian/v1/guaranteed_state.proto` with `GuaranteedStateRule`, `GuaranteedStatePush`, `GuaranteedStateEvent`, `GuaranteedStateStatus`, `GuaranteedStateRuleStatus`. Server store `guaranteed-state.db` with immutable event log. Actions: `push_rules`, `get_status`. Every rule reports `errored` until guard implementations land in PR 3+.

### 31.2 Event Guards — Kernel-Event-Driven Enforcement (Windows) :x: `T2`

Not implemented (PRs 3, 5, 6, 7, 10). Real-time enforcement via four Windows kernel-backed user-mode APIs:
- **Registry Guard** — `RegNotifyChangeKeyValue` + `WaitForMultipleObjects` (~0 ms latency); the canonical "registry value must equal X" enforcer.
- **SCM Guard** — `NotifyServiceStatusChange` (~0 ms latency); enforces "service must remain running/stopped/disabled."
- **WFP Guard** — `FwpmFilterSubscribeChanges0` (~0 ms latency); defence-in-depth filter monitor for firewall posture.
- **ETW Guard** — `OpenTrace` / `ProcessTrace` (~1-5 ms latency); the multiplexed event provider with shared-session pooling per `docs/yuzu-guardian-design-v1.1.md` §8.3 (mandatory because Windows caps system-wide ETW sessions at 64, shared with Defender / EDR).

Each guard implements `self_test()` on start to prove kernel wiring (sentinel write → expected callback within 500 ms → pass / `errored` mark). Resilience strategies (`Fixed`, `Backoff`, `Escalation`) and `RaceDetector` (sliding-window drifts/second) surface at PR 4.

### 31.3 Condition Guards — Periodic Evaluation (All Platforms) :x: `T2`

Not implemented (PRs 8, 9). Time-based compliance — "process X must be running," "AV scan must have run within last 7 days," "software must have been updated within 30 days." Configurable interval per type. Hybrid Process Guard combines `Microsoft-Windows-Kernel-Process` ETW (events 1/2 for start/stop, near-real-time) with periodic `CreateToolhelp32Snapshot` poll (safety net). WMI Guard runs arbitrary WMI queries against an evaluator. Software Guard reads Registry Uninstall keys + WMI for installed-software freshness. Compliance Guard runs Event Log queries.

### 31.4 Event Guards — Linux :x: `T3`

Not implemented (PR 16). Linux equivalents of the Windows event-guard primitives:
- **Inotify Guard** — `inotify_add_watch` for file/directory state assertions (config files, certificate files, sshd config).
- **Netlink Guard** — `NETLINK_KOBJECT_UEVENT` for process-tree and device-event monitoring.
- **D-Bus Guard** — `org.freedesktop.systemd1` signal subscriptions for service state ("sshd.service must remain running").
- **Audit Guard** — Linux audit subsystem (`auditd`) consumer for syscall-level assertions.
- **Sysctl Guard** — periodic check + `/proc/sys/...` write remediation; monitors kernel parameters that drift would indicate compromise.

Phase 16 Linux delivery is gated on Windows track soaking in production.

### 31.5 Event Guards — macOS :x: `T3`

Not implemented (PR 17). macOS equivalents using Apple's Endpoint Security (ES) framework — *requires the ES entitlement*, which is a notarised-build / DDM-distributed entitlement that Apple grants per-bundle-ID. Without ES, the macOS guard surface is reduced to `fseventsd`, `launchd` plist polling, and `kqueue` file-watch. Phase 16 macOS delivery is gated on (a) Windows + Linux soak and (b) ES entitlement availability.

### 31.6 State Evaluator and Remediation Engine :x: `T2`

Not implemented (PRs 3, 5+). Assertion registry (`registry-value-equals`, `registry-value-absent`, `service-running`, `service-stopped`, `firewall-port-blocked`, `process-running`, `file-hash-equals`, `kernel-param-equals`, `plist-key-equals`, etc.) returns `compliant | drift | exempt` for a `StateSnapshot`. Remediation methods are **system calls only — no shell-out** (per design §14): `RegSetValueExW` / `RegDeleteValueW` (Win), `INetFwPolicy2` COM (Win firewall), service control via SCM (Win) / systemd D-Bus (Linux) / launchctl (macOS), `/proc/sys` writes (Linux), `defaults write` equivalent via plist serialisation (macOS). Re-entrancy guard per rule with 5 ms suppression window prevents the remediation from triggering its own watch callback.

### 31.7 Audit Journal and Server Store :large_orange_diamond: `T2`

Server store shipped (PR 1 — `server/core/src/guaranteed_state_store.{hpp,cpp}`, `guaranteed-state.db`, immutable event log, no FK cascade on rule delete so historical events persist for forensic review). Agent-side journal (`agents/core/src/guard_audit.{hpp,cpp}`) lands with PR 3: MPSC queue + dedicated writer thread, SQLite journal table inside `kv_store.db` keyed by monotonic `event_seq`, drained by `GuardianEngine::sync_with_server` into `CommandResponse { plugin: "__guard__", action: "event" }`. Every detection and remediation journaled locally first, synced to server when online.

### 31.8 Pre-Login Activation and Offline Capability :white_check_mark: `T2`

Pre-login activation works by construction today: the agent runs as a Windows service with `SERVICE_AUTO_START` + `FailureActions` configured at install time (`agents/core/src/main.cpp:136-200`); systemd unit on Linux with `Type=notify` + `Restart=always`; launchd `KeepAlive=true` + `RunAtLoad=true` on macOS. `GuardianEngine::start_local()` runs before the Register RPC, so once guard implementations land in PR 3+, enforcement begins as soon as the service starts — before any user can log in. Offline capability comes from caching policy in `kv_store.db` under `__guardian__` namespace; enforcement continues with last-known-good rules when the server is unreachable, and queued events flush when the server returns. Marked `:white_check_mark:` because the service-install side is operational; the *enforcement* half is gated on PR 3+ landing real guards.

### 31.9 Dashboard and Approval Workflow :x: `T2`

Not implemented (PRs 4, 11, 14). Dashboard page at `/guaranteed-state` listing rules (with kernel-wiring health indicator — `guard_healthy` + `last_notification` timestamp surface "deaf because subscription silently went nowhere" vs. "compliant because nothing's happening"), event timeline, summary cards, fragments per `docs/yuzu-guardian-design-v1.1.md` §10. Approval workflow reuses the existing `ApprovalManager` with `definition_id = "guaranteed_state_rule_*"` — no manager code changes (already generic). HTMX rule editor (CRUD + YAML validation + conflict detection) at PR 14.

### 31.10 Rule Signing and Quarantine Integration :x: `T2`

Not implemented (PRs 12, 15). HMAC rule signing (HKDF per design §11.2) with per-tenant key stored in `CredWrite`/`CredRead` (Windows), Linux Secret Service / kernel keyring (Linux), Keychain (macOS); agent-side signature validation before activating a rule prevents unauthenticated rule injection. Quarantine integration: WFP block-all filter at weight 65535 (Windows) or `iptables` / `nftables` rule (Linux) drops all traffic except Yuzu's own; instruction handlers `quarantine.add_exception | remove_exception | lift`; server-side DNS resolution; resilience reset on lift so a remediation storm doesn't carry over.

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
| wifi | Y | Y | Y | Network |
| wol | Y | Y | Y | Network |
| discovery | Y | Y | Y | Network |
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
| ioc | Y | Y | Y | Security |
| quarantine | Y | Y | Y | Security |
| certificates | Y | Y | Y | Security |
| filesystem | Y | Y | Y | File System |
| registry | Y | - | - | System Config |
| wmi | Y | - | - | System Config |
| script_exec | Y | Y | Y | Execution |
| content_dist | Y | Y | Y | Content Dist |
| http_client | Y | Y | Y | Content Dist |
| interaction | Y | Y | Y | User Interaction |
| storage | Y | Y | Y | Agent KV |
| asset_tags | Y | Y | Y | Device Mgmt |
| agent_logging | Y | Y | Y | Agent Mgmt |
| agent_actions | Y | Y | Y | Agent Mgmt |
| diagnostics | Y | Y | Y | Agent Mgmt |
| tar | Y | Y | Y | Monitoring |
| chargen | Y | Y | Y | Test/Debug |
| example | Y | Y | Y | Test/Debug |

| software_usage | Y | Y | Y | Software | *Planned (Phase 12)* |
| app_control | Y | Y | - | Security | *Planned (Phase 12)* |

**44 plugins** (+ 2 planned) — covering hardware, network, security, filesystem, registry, WMI, WiFi, WoL, IOC, quarantine, certificates, content distribution, user interaction, and more. Includes cross-platform, Windows-only, and test/debug plugins.

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
