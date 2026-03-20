# Agent Plugin Catalog

This document is the complete reference for all Yuzu agent plugins. Each plugin runs inside the agent process on managed endpoints and exposes one or more **actions** that the server can invoke via instructions.

Plugins are organized by functional category. The **Platforms** column uses: **W** = Windows, **L** = Linux, **M** = macOS.

---

## Table of Contents

1. [System & Identity](#system--identity)
2. [Process & Service](#process--service)
3. [User & Session](#user--session)
4. [Network](#network)
5. [Software & Patch](#software--patch)
6. [Security](#security)
7. [File System](#file-system)
8. [Execution](#execution)
9. [Test / Debug](#test--debug)
10. [HTTP & Content Distribution](#http--content-distribution)
11. [User Interaction](#user-interaction)
12. [Agent Infrastructure](#agent-infrastructure)
13. [Windows Depth](#windows-depth)
14. [Stub Plugins (Planned)](#stub-plugins-planned)
15. [Plugin Architecture](#plugin-architecture)

---

## System & Identity

Plugins for querying operating system details, hardware inventory, device identity, and agent health.

### os_info

| | |
|---|---|
| **Version** | v1.0.0 |
| **Platforms** | W L M |
| **Description** | Returns core operating system metadata. |

| Action | Description |
|---|---|
| `os_name` | Operating system name (e.g., "Windows 11 Pro", "Ubuntu 24.04"). |
| `os_version` | OS version string. |
| `os_build` | OS build number or kernel version. |
| `os_arch` | CPU architecture (x64, arm64, etc.). |
| `uptime` | System uptime in seconds since last boot. |

### hardware

| | |
|---|---|
| **Platforms** | W L M |
| **Description** | Collects hardware inventory. Uses WMI on Windows, DMI tables on Linux, and `sysctl` on macOS. |

| Action | Description |
|---|---|
| `manufacturer` | Device manufacturer (e.g., "Dell Inc."). |
| `model` | Device model name. |
| `bios` | BIOS/UEFI vendor, version, and date. |
| `processors` | CPU model, core count, clock speed, and socket information. |
| `memory` | Total physical memory, speed, and slot details. |
| `disks` | Physical disk model, size, interface type, and health status. |

### device_identity

| | |
|---|---|
| **Version** | v1.0.0 |
| **Platforms** | W L M |
| **Description** | Returns the device's identity within its network/domain. |

| Action | Description |
|---|---|
| `device_name` | Hostname of the device. |
| `domain` | Active Directory domain or workgroup. |
| `ou` | Organizational unit (if domain-joined). |

### status

| | |
|---|---|
| **Platforms** | W L M |
| **Description** | Agent self-reporting. Returns operational health and configuration state. |

| Action | Description |
|---|---|
| `version` | Agent binary version string. |
| `info` | Summary of agent build, OS, and runtime environment. |
| `health` | Agent health check (uptime, memory usage, error counts). |
| `plugins` | List of loaded plugins with their versions. |
| `connection` | Server connection state (connected, reconnecting, disconnected). |
| `config` | Current agent configuration values (sanitized, no secrets). |

### diagnostics

| | |
|---|---|
| **Version** | v0.2.0 |
| **Platforms** | W L M |
| **Description** | Troubleshooting data for diagnosing agent or connectivity issues. |

| Action | Description |
|---|---|
| `log_level` | Current log verbosity level. |
| `certificates` | mTLS certificate details (subject, issuer, expiry, thumbprint). |
| `connection_info` | Server endpoint, connection age, reconnect count, last error. |

### agent_actions

| | |
|---|---|
| **Version** | v0.1.0 |
| **Platforms** | W L M |
| **Description** | Administrative actions on the agent itself. |

| Action | Description |
|---|---|
| `set_log_level` | Change the agent's log verbosity at runtime (trace, debug, info, warn, error). |
| `info` | Return agent build and environment summary. |

---

## Process & Service

Plugins for enumerating running processes, fetching process metadata, and querying system services.

### processes

| | |
|---|---|
| **Platforms** | W L M |
| **Description** | Enumerate and query running processes. |

| Action | Description |
|---|---|
| `list` | List all running processes (PID, name, user, memory, CPU). |
| `query` | Filter processes by name pattern. Returns matching entries. |

### procfetch

| | |
|---|---|
| **Platforms** | W L M |
| **Description** | Fetch detailed metadata for processes, including file hashes for integrity verification. |

| Action | Description |
|---|---|
| `procfetch_fetch` | For each running process, returns PID, name, executable path, and SHA-1 hash of the binary on disk. |

### services

| | |
|---|---|
| **Platforms** | W L M |
| **Description** | Query and configure system services. Uses Service Control Manager on Windows, `systemctl` on Linux, and `launchd` on macOS. |

| Action | Description |
|---|---|
| `list` | List all registered services with their current state and start type. |
| `running` | List only services that are currently running. |
| `set_start_mode` | Change a service's startup type. Parameters: `name` (service identifier), `mode` (`automatic`, `manual`, or `disabled`). On Windows, calls `ChangeServiceConfig`. On Linux, maps to `systemctl enable`/`disable`/`mask`. On macOS, uses `launchctl enable`/`disable` on the system domain. Requires `endpoint-admin` role and role-gated approval. |

---

## User & Session

Plugins for querying user accounts and active sessions.

### users

| | |
|---|---|
| **Platforms** | W L M |
| **Description** | Enumerate local user accounts and active login sessions. |

| Action | Description |
|---|---|
| `logged_on` | Users currently logged on (interactive and remote sessions). |
| `sessions` | All active sessions (console, RDP, SSH) with session ID and state. |
| `local_users` | All local user accounts with enabled/disabled status. |
| `local_admins` | Members of the local administrators group. |

---

## Network

Plugins for network configuration, active connections, diagnostics, and administrative actions.

### network_config

| | |
|---|---|
| **Platforms** | W L M |
| **Description** | Network adapter configuration and addressing. |

| Action | Description |
|---|---|
| `adapters` | List network adapters with type, MAC address, and link status. |
| `ip_addresses` | IPv4 and IPv6 addresses per adapter, including subnet mask and gateway. |
| `dns_servers` | Configured DNS servers per adapter. |
| `proxy` | System proxy settings (HTTP, HTTPS, SOCKS, PAC URL). |

### netstat

| | |
|---|---|
| **Platforms** | W L M |
| **Description** | Active network connections (similar to the `netstat` command-line tool). |

| Action | Description |
|---|---|
| `netstat_list` | List all TCP and UDP connections with local/remote address, port, state, and owning PID. |

### sockwho

| | |
|---|---|
| **Platforms** | W L M |
| **Description** | Maps open sockets to the processes that own them. |

| Action | Description |
|---|---|
| `sockwho_list` | For each listening or established socket, returns the owning process name and PID alongside connection details. |

### network_diag

| | |
|---|---|
| **Platforms** | W L M |
| **Description** | Network diagnostic queries. |

| Action | Description |
|---|---|
| `listening` | List all listening ports with owning process. |
| `connections` | List established connections with owning process. |

### network_actions

| | |
|---|---|
| **Platforms** | W L M |
| **Description** | Administrative network operations. |

| Action | Description |
|---|---|
| `flush_dns` | Flush the local DNS resolver cache. |
| `ping` | ICMP ping a target host and return round-trip statistics. |

---

## Software & Patch

Plugins for software inventory, Windows-specific package management, update status, and SCCM integration.

### installed_apps

| | |
|---|---|
| **Platforms** | W L M |
| **Description** | Enumerate installed applications from OS-native registries. |

| Action | Description |
|---|---|
| `list` | All installed applications with name, version, publisher, and install date. |
| `query` | Search installed applications by name pattern. |

### msi_packages

| | |
|---|---|
| **Platforms** | W |
| **Description** | Windows Installer (MSI) package inventory. |

| Action | Description |
|---|---|
| `list` | All installed MSI packages with name, version, and vendor. |
| `product_codes` | MSI product codes (GUIDs) for each installed package. Useful for silent uninstall automation. |

### windows_updates

| | |
|---|---|
| **Platforms** | W (L M via package managers) |
| **Description** | Windows Update status. On Linux and macOS, queries the native package manager for available updates. |

| Action | Description |
|---|---|
| `installed` | List installed updates/hotfixes with KB number, date, and type. |
| `missing` | List updates that are available but not yet installed. |

### software_actions

| | |
|---|---|
| **Platforms** | W L M |
| **Description** | Software inventory actions. |

| Action | Description |
|---|---|
| `list_upgradable` | List packages with available upgrades (version comparison). |
| `installed_count` | Total count of installed applications. |

### sccm

| | |
|---|---|
| **Platforms** | W |
| **Description** | Microsoft SCCM/ConfigMgr client integration. |

| Action | Description |
|---|---|
| `client_version` | Installed SCCM client version. |
| `site` | SCCM site code and management point the client reports to. |

---

## Security

Plugins for antivirus, firewall, disk encryption, event logs, vulnerability scanning, certificate management, IOC checking, and device quarantine.

### antivirus

| | |
|---|---|
| **Version** | v0.1.0 |
| **Platforms** | W L M |
| **Description** | Antivirus product detection and status. |

| Action | Description |
|---|---|
| `products` | List registered antivirus products with name, vendor, and version. |
| `status` | Real-time protection state, signature date, and scan status per product. |

### firewall

| | |
|---|---|
| **Platforms** | W L M |
| **Description** | Host firewall state and rules. |

| Action | Description |
|---|---|
| `state` | Whether the firewall is enabled, per profile (domain, private, public on Windows). |
| `rules` | List firewall rules with direction, action, port, and protocol. |

### bitlocker

| | |
|---|---|
| **Version** | v0.1.0 |
| **Platforms** | W L M |
| **Description** | Disk encryption status. Reports BitLocker on Windows, LUKS on Linux, and FileVault on macOS. |

| Action | Description |
|---|---|
| `state` | Encryption status per volume (encrypted, decrypted, encrypting, protection on/off). |

### event_logs

| | |
|---|---|
| **Version** | v1.0.0 |
| **Platforms** | W L M |
| **Description** | Query OS event logs. Uses Windows Event Log API, `journalctl` on Linux, and macOS unified log. |

| Action | Description |
|---|---|
| `errors` | Recent error-level events from system and application logs. |
| `query` | Filter events by log name, level, source, time range, and keyword. |

### vuln_scan

| | |
|---|---|
| **Platforms** | W L M |
| **Description** | Lightweight vulnerability and configuration scanning. |

| Action | Description |
|---|---|
| `scan` | Run a full vulnerability scan (installed software against known CVE data). |
| `cve_scan` | Check for a specific CVE by ID. |
| `config_scan` | Audit system configuration against security baselines. |
| `summary` | Return counts of critical, high, medium, and low findings. |

### certificates

| | |
|---|---|
| **Version** | v1.0.0 |
| **Platforms** | W L M |
| **Description** | Manage certificates in the system store. Uses CryptoAPI on Windows, PEM files on Linux, and the `security` CLI on macOS. |

| Action | Description |
|---|---|
| `list` | List certificates with subject, issuer, thumbprint, and expiry date. |
| `details` | Full details for a specific certificate by thumbprint. |
| `delete` | Remove a certificate from the store by thumbprint. |

### ioc

| | |
|---|---|
| **Platforms** | W L M |
| **Description** | Indicator of Compromise (IOC) checking for threat hunting. |

| Action | Description |
|---|---|
| `check` | Check the endpoint against a set of IOCs. Supports multiple indicator types. |

Supported indicator types for the `check` action:

| Indicator | Description |
|---|---|
| `ip_addresses` | Check for connections to known-bad IP addresses. |
| `domains` | Check DNS cache and hosts file for known-bad domains. |
| `file_hashes` | Scan specified paths for files matching known-bad SHA-256 hashes. |
| `file_paths` | Check for the existence of specific file paths. |
| `ports` | Check for processes listening on suspicious ports. |

### quarantine

| | |
|---|---|
| **Platforms** | W L M |
| **Description** | Network quarantine for compromised or suspicious devices. Uses `netsh` on Windows, `iptables`/`nftables` on Linux, and `pfctl` on macOS. |

| Action | Description |
|---|---|
| `quarantine` | Isolate the device by blocking all network traffic except the Yuzu server connection. |
| `unquarantine` | Remove quarantine rules and restore normal network access. |
| `status` | Check whether quarantine is currently active. |
| `whitelist` | Add an IP or CIDR range to the quarantine exception list. |

---

## File System

Plugins for file and directory operations.

### filesystem

| | |
|---|---|
| **Platforms** | W L M |
| **Description** | File system queries and temporary file creation. All paths are canonicalized before use to prevent directory traversal attacks. |

| Action | Description |
|---|---|
| `exists` | Check whether a file or directory exists at the given path. |
| `list_dir` | List directory contents with name, size, type, and modification time. |
| `file_hash` | Compute SHA-256 hash of a file. |
| `create_temp` | Create a temporary file and return its path. |
| `create_temp_dir` | Create a temporary directory and return its path. |
| `read` | Read a text file with line-number offsets (max 100 MB, binary detection, paginated). |

---

## Execution

Plugins for running arbitrary commands, managing device tags, and structured asset tagging.

### script_exec

| | |
|---|---|
| **Platforms** | W L M |
| **Description** | Execute arbitrary commands on the endpoint. **Admin-only** -- requires an admin-level RBAC role. Supports configurable execution timeouts. |

| Action | Description |
|---|---|
| `exec` | Execute a raw shell command and return stdout, stderr, and exit code. |
| `powershell` | Execute a PowerShell script block (Windows only). |
| `bash` | Execute a bash script block (Linux and macOS). |

> **Security note:** The `script_exec` plugin is the most powerful plugin in the catalog. Access should be restricted to trusted administrators via RBAC roles. All executions are recorded in the audit log.

### tags

| | |
|---|---|
| **Platforms** | W L M |
| **Description** | Manage key-value tags on the device. Tags are persisted locally in `tags.json` and synced to the server for use in scope expressions. |

| Action | Description |
|---|---|
| `set` | Set a tag (key-value pair). Creates or overwrites. |
| `get` | Get the value of a specific tag by key. |
| `get_all` | Return all tags as key-value pairs. |
| `delete` | Remove a tag by key. |
| `check` | Check whether a tag with the given key exists. |
| `clear` | Remove all tags. |
| `count` | Return the total number of tags. |

### asset_tags

| | |
|---|---|
| **Version** | v0.1.0 |
| **Platforms** | W L M |
| **Description** | Structured asset tagging with server-side awareness. Supports tag sync and change tracking. |

| Action | Description |
|---|---|
| `sync` | Synchronize local tags with the server's authoritative tag set. |
| `status` | Report sync state (last sync time, pending changes, conflict count). |
| `get` | Retrieve a structured tag value by key. |
| `changes` | List tag changes since the last sync (additions, modifications, deletions). |

---

## Test / Debug

Plugins used for development, testing, and plugin authoring reference.

### chargen

| | |
|---|---|
| **Version** | v1.0.0 |
| **Platforms** | W L M |
| **Description** | RFC 864 character generator. Produces a continuous stream of output for testing transport throughput and backpressure handling. |

| Action | Description |
|---|---|
| `chargen_start` | Begin generating character output. |
| `chargen_stop` | Stop the character generator. |

### example

| | |
|---|---|
| **Version** | v0.1.0 |
| **Platforms** | W L M |
| **Description** | Minimal reference plugin. Use as a template when writing new plugins. |

| Action | Description |
|---|---|
| `ping` | Returns "pong". Verifies the plugin host is functioning. |
| `echo` | Returns the input string unchanged. Tests parameter passing. |

---

## HTTP & Content Distribution

Plugins for HTTP operations, file downloads, content staging, and package deployment.

### http_client

| | |
|---|---|
| **Version** | v1.0.0 |
| **Platforms** | W L M |
| **Description** | HTTP client for downloading files and making HTTP requests. Supports SHA256 hash verification on downloads. |

| Action | Description |
|---|---|
| `download` | Download a file from a URL to a local path. Parameters: `url` (required), `path` (required), `expected_hash` (optional SHA256 for verification). Returns status, path, size, and hash. |
| `get` | Perform an HTTP GET request and return the response status code and body. Parameters: `url` (required). |
| `head` | Perform an HTTP HEAD request and return the response status code and headers. Parameters: `url` (required). Useful for checking file availability or size before downloading. |

### content_dist

| | |
|---|---|
| **Version** | v1.0.0 |
| **Platforms** | W L M |
| **Description** | Content staging and execution. Downloads files to the agent's staging directory with hash verification, then executes them with optional arguments. |

| Action | Description |
|---|---|
| `stage` | Download a file to the agent's staging directory and verify its SHA256 hash. Parameters: `url` (required), `filename` (required), `sha256` (required). Returns status and staged file path. |
| `execute_staged` | Execute a previously staged file with optional arguments. Parameters: `filename` (required), `args` (optional). Returns status, exit code, and output. |
| `list_staged` | List all files in the agent's staging directory with size and SHA256 hash. |
| `cleanup` | Remove one or all files from the staging directory. Parameters: `filename` (optional; omit to clear all staged files). Returns status and count of files removed. |

---

## User Interaction

Plugins for displaying notifications, dialogs, and input prompts on endpoint desktops.

### interaction

| | |
|---|---|
| **Version** | v1.0.0 |
| **Platforms** | W L M |
| **Description** | Desktop user interaction. Shows toast notifications, message box dialogs, and text input dialogs. Uses native APIs per platform: `ShellNotifyIcon` on Windows, `notify-send`/`zenity` on Linux, `osascript` on macOS. |

| Action | Description |
|---|---|
| `notify` | Show a desktop notification/toast. Parameters: `title` (required), `message` (required), `type` (`info`, `warning`, or `error`; default `info`). |
| `message_box` | Show a modal message box dialog that blocks until the user responds. Parameters: `title` (required), `message` (required), `buttons` (`ok`, `okcancel`, or `yesno`; default `ok`). Returns which button was clicked. |
| `input` | Show a text input dialog. Parameters: `title` (required), `prompt` (required), `default_value` (optional). Returns the text entered by the user, or indicates cancellation. |

---

## Agent Infrastructure

Plugins for agent-side persistent storage, logging, and remote diagnostics.

### storage

| | |
|---|---|
| **Version** | v1.0.0 |
| **Platforms** | W L M |
| **Description** | Persistent key-value storage on the agent, backed by SQLite. Keys are namespaced per plugin. Survives agent restarts and upgrades. Used for cross-instruction state and plugin-local persistence. |

| Action | Description |
|---|---|
| `set` | Store a key-value pair. Parameters: `key` (required), `value` (required). |
| `get` | Retrieve a value by key. Parameters: `key` (required). |
| `delete` | Delete a key from storage. Parameters: `key` (required). |
| `list` | List all keys, optionally filtered by prefix. Parameters: `prefix` (optional). Returns count and key names. |
| `clear` | Delete all keys from the storage namespace. Returns status and count of cleared keys. |

### agent_logging

| | |
|---|---|
| **Version** | v1.0.0 |
| **Platforms** | W L M |
| **Description** | Remote access to agent log files and key agent files. Enables server-initiated log retrieval for diagnostics without requiring direct endpoint access. |

| Action | Description |
|---|---|
| `get_log` | Return the last N lines of the agent's log file. Parameters: `lines` (1-500, default 50). The log file path is discovered from agent config, falling back to platform defaults (`/var/log/yuzu` on Linux, `ProgramData/Yuzu` on Windows). |
| `get_key_files` | List important agent files (executable, log files, config files, data stores, plugins, TLS certificates) with their absolute paths, sizes in bytes, and last-modified timestamps. |

---

## Windows Depth

Plugins for Windows-specific system management: registry operations and WMI queries.

### registry

| | |
|---|---|
| **Version** | v1.0.0 |
| **Platforms** | W |
| **Description** | Windows registry CRUD operations. Read, write, delete, and enumerate registry keys and values. Supports per-user registry operations via NTUSER.DAT hive loading for offline users. |

| Action | Description |
|---|---|
| `get_value` | Read a value from the Windows registry. Parameters: `hive` (`HKLM`, `HKCU`, `HKCR`, `HKU`), `key` (path), `name` (value name). Returns value and type. |
| `set_value` | Write a value to the Windows registry. Creates the key if it does not exist. Parameters: `hive`, `key`, `name`, `value`, `type` (`REG_SZ` or `REG_DWORD`). |
| `delete_value` | Delete a specific value from a registry key. Parameters: `hive`, `key`, `name`. |
| `delete_key` | Delete a registry key and all its values. Parameters: `hive`, `key`. |
| `key_exists` | Check whether a registry key exists. Parameters: `hive`, `key`. Returns boolean. |
| `enumerate_keys` | List all subkeys under a registry key. Parameters: `hive`, `key`. |
| `enumerate_values` | List all value names and types under a registry key. Parameters: `hive`, `key`. |
| `get_user_value` | Read a registry value from a specific user's NTUSER.DAT hive. Loads the hive via `RegLoadKey` if the user is not logged in. Requires `SE_RESTORE_NAME` and `SE_BACKUP_NAME` privileges. Parameters: `username`, `key`, `name` (optional). |

### wmi

| | |
|---|---|
| **Version** | v1.0.0 |
| **Platforms** | W |
| **Description** | Windows Management Instrumentation (WMI) queries. Execute WQL SELECT statements against any WMI namespace with structured property/value output. |

| Action | Description |
|---|---|
| `query` | Execute a WQL SELECT query. Only SELECT statements are allowed. Parameters: `wql` (required, e.g., `"SELECT * FROM Win32_OperatingSystem"`), `namespace` (optional, default `root\cimv2`). Returns property/value pairs. |
| `get_instance` | Get all properties of the first instance of a WMI class. Parameters: `class` (required, e.g., `Win32_OperatingSystem`), `namespace` (optional). |

---

## Stub Plugins (Planned)

The following plugins are defined in the roadmap but not yet implemented. They are listed here for planning purposes.

| Plugin | Description | Target Phase |
|---|---|---|
| `wifi` | Wi-Fi scanning, profile management, and signal diagnostics. | Phase 7 (7.15) |
| `patch` | Patch deployment, scheduling, and compliance reporting. | Phase 7 (7.8) |
| `discovery` | Subnet scanning and network device discovery. | Phase 7 (7.18) |

---

## Plugin Architecture

### Overview

All agent plugins share a common architecture based on a **stable C ABI** defined in `sdk/include/yuzu/plugin.h`. This ABI is designed to remain binary-compatible across compiler versions and agent upgrades, so plugins can be updated independently of the agent binary.

A **C++23 CRTP wrapper** (`sdk/include/yuzu/plugin.hpp`) provides ergonomic C++ authoring on top of the C ABI. The `YUZU_PLUGIN_EXPORT` macro handles symbol visibility and the export table automatically.

### Plugin Lifecycle

1. The agent scans its plugin directory at startup.
2. Each shared library (`.dll` on Windows, `.so` on Linux, `.dylib` on macOS) is loaded dynamically.
3. The agent calls the plugin's `init` function, passing a context with configuration and callbacks.
4. When the server sends an instruction targeting a plugin action, the agent dispatches it to the correct plugin.
5. The plugin executes the action and returns results via the output callback.

### Output Format

Plugins emit results by calling `write_output()` with pipe-delimited (`|`) fields. Each call writes one row of output. The server parses these rows according to the result schema declared in the plugin's `InstructionDefinition` YAML.

Example:
```
write_output("hostname|Windows 11 Pro|10.0.26200|x64");
```

### Configuration Access

Plugins can read configuration values set by the server using `get_config(key)`. This allows the server to pass parameters (filter strings, thresholds, target paths) to plugin actions at execution time.

### Data Storage

Each plugin can persist state locally. Per-plugin data is stored at:

```
<agent_data_dir>/<plugin_name>.json
```

For example, the `tags` plugin stores its tag set in `tags.json` within the agent's data directory. This file survives agent restarts and upgrades.

### Writing a New Plugin

Use the `example` plugin as a starting template. The minimum steps are:

1. Create a new directory under `agents/plugins/<your_plugin>/`.
2. Implement the C ABI entry points (or use the C++ CRTP wrapper).
3. Add the plugin to `meson.build`.
4. Write an `InstructionDefinition` YAML file in `content/definitions/` following the `yuzu.io/v1alpha1` DSL spec.
5. Register plugin actions in the Substrate Primitive Reference table (`docs/yaml-dsl-spec.md`, section 14).

For the full DSL specification, see `docs/yaml-dsl-spec.md`. For a walkthrough, see `docs/getting-started.md`.
