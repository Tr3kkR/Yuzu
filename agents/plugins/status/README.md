# status

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Reports agent version, system info, health, modules, connection, switch, and config |
| **Version** | 0.13.1 |
| **Kind** | Collector · read-only · on-demand (no scheduled gather) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux ✅ |
| **Actions** | `version` (definition `device.status.version`) · `info` (definition `device.status.info`) · `health` (definition `device.status.health`) · `plugins` (definition `device.status.plugins`) · `modules` (definition `device.status.modules`) · `connection` (definition `device.status.connection`) · `switch` (definition `device.status.switch`) · `config` (definition `device.status.config`) |
| **Security** | securable `Inventory` (seven actions) / `PluginSecret` (`switch`) · operation Read · risk Low (Medium for `switch`) · dispatch ReadOnly · approval gate none |
| **Roles** | execute: endpoint-admin, endpoint-operator (`version`, `info`, `health`, `plugins`, `modules`, `connection`) · endpoint-admin only (`switch`, `config`) · author: content-author |
<!-- END GENERATED -->

## How it works

`version` and `info` are pure reads that never touch plugin state: `version` formats three compile-time constants (`yuzu::kFullVersionString`/`kBuildNumber`/`kGitCommitHash`), `info` calls `uname(2)`+`gethostname(3)` on Linux/macOS or `GetNativeSystemInfo`+`GetComputerNameA` on Windows. `health` reads process memory via the platform's own API (`/proc/self/status`, Mach `task_info`, or `K32GetProcessMemoryInfo`) and computes uptime from a `steady_clock` timestamp taken in `init()`.

The other five actions — `plugins`, `modules`, `connection`, `switch`, `config` — all read the agent's in-process config map through one helper, `cfg()`, which forwards to `yuzu_ctx_get_config()` against a raw context pointer captured in `init()`. That map is a snapshot: the agent copies its master config into every plugin's own context once, right after every plugin finishes loading, so these five actions only ever see the config as it stood at that moment (see Caveats).

The plugin deliberately does not call `yuzu_ctx_get_secret()` (always returns `nullptr` on this agent build) and does not shell out, open a socket, or mutate anything — `execute()` is a flat action-name dispatch with no side effects beyond the one `init_time_` timestamp.

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: Inventory.Read or<br/>PluginSecret.Read for switch]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[status.execute]
  EX --> WIN[Windows leg<br/>native API / in-process config]
  EX --> MAC[macOS leg<br/>native API / in-process config]
  EX --> LIN[Linux leg<br/>native API / in-process config]
  WIN & MAC & LIN --> ROWS[key|value rows,<br/>UNDECLARED status] --> RS[(ResponseStore)] --> API[REST /api/responses · MCP]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `version` | ✅ supported · rung 1 · in-process (compiled version constants) | ✅ supported · rung 1 · in-process (compiled version constants) | ✅ supported · rung 1 · in-process (compiled version constants) |
| `info` | ✅ supported · rung 1 · `GetNativeSystemInfo` + `GetComputerNameA` | ✅ supported · rung 1 · `uname(2)` + `gethostname(3)` | ✅ supported · rung 1 · `uname(2)` + `gethostname(3)` |
| `health` | ✅ supported · rung 1 · `K32GetProcessMemoryInfo` + `steady_clock` | ✅ supported · rung 1 · `task_info(MACH_TASK_BASIC_INFO)` + `steady_clock` | ✅ supported · rung 1 · `/proc/self/status` VmRSS + `steady_clock` |
| `plugins` | ✅ supported · rung 1 · in-process agent config (`agent.plugins.*`) | ✅ supported · rung 1 · in-process agent config (`agent.plugins.*`) | ✅ supported · rung 1 · in-process agent config (`agent.plugins.*`) |
| `modules` | ✅ supported · rung 1 · in-process agent config (`agent.modules.*`) | ✅ supported · rung 1 · in-process agent config (`agent.modules.*`) | ✅ supported · rung 1 · in-process agent config (`agent.modules.*`) |
| `connection` | ✅ supported · rung 1 · in-process agent config (`agent.server_address`/`tls_enabled`/*) | ✅ supported · rung 1 · in-process agent config (`agent.server_address`/`tls_enabled`/*) | ✅ supported · rung 1 · in-process agent config (`agent.server_address`/`tls_enabled`/*) |
| `switch` | ✅ supported · rung 1 · in-process agent config (`agent.server_address`/`session_id`/*) | ✅ supported · rung 1 · in-process agent config (`agent.server_address`/`session_id`/*) | ✅ supported · rung 1 · in-process agent config (`agent.server_address`/`session_id`/*) |
| `config` | ✅ supported · rung 1 · in-process agent config (`agent.*`) | ✅ supported · rung 1 · in-process agent config (`agent.*`) | ✅ supported · rung 1 · in-process agent config (`agent.*`) |

**Declared limits per leg** (the descriptor's fallback text, verbatim):

- None. Every action/OS leg in `kActionDescriptors` is `YUZU_SUPPORT_SUPPORTED` at rung 1 with a `nullptr` fallback — no action degrades on any platform.
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account (LocalSystem today, #1442) | None — every call (`GetNativeSystemInfo`, `GetComputerNameA`, `K32GetProcessMemoryInfo`) works for an unprivileged process on its own memory/host info. | 2026-09-07 on the-rig as `SYSTEM` | No typed denial path exists; a failed native call is simply not written (see `health` in Caveats) |
| macOS | agent daemon, unprivileged | None — `uname`, `gethostname`, and `task_info(MACH_TASK_BASIC_INFO)` on the calling process require no entitlement. | 2026-09-07 at euid 501 (alex) | Same — no typed denial path |
| Linux | agent daemon, root today | None — `uname`, `gethostname`, and reading the process's own `/proc/self/status` require no capability. | 2026-09-06 in a container at euid 0 | Same — no typed denial path |

No external binaries, no subprocesses, no network access. Every call in `status_plugin.cpp` is either an in-process constant, a config-map lookup, or a single native syscall.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
`version`, `info`, `health`, `plugins`, `modules`, `connection`, `switch`, and `config` all take no parameters (`spec.parameters.properties: {}` in every one of the eight definitions).
<!-- END GENERATED -->

### Outputs

Every field is written as its own pipe-delimited `key|value` row via `write_output()` — not one row per entity. `plugins` and `modules` are the two exceptions: after their own `<action>_count|<n>` row, each lists one `plugin|name|version|description` or `module|name|version|status` row per item, and `modules` additionally emits a separate `module_description|name|description` row only when a description is non-empty. The YAML declares `bool`/`int` types for several columns (`tls_enabled`, `encrypted`, `debug_mode`, `verbose_logging`, `reconnect_count`, …) purely for consumer convenience — every value actually travels as raw text from the agent's config map, and an unset or not-yet-synced key comes through as an empty string, never a typed `false`/`0`.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`version` — one `key|value` row per field: `version`, `build_number`, `git_commit`**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `version` | string | free text (semver + build suffix) | W, M, L | `0.13.1+5871` |
| `build_number` | string | free text (integer as string) | W, M, L | `5871` |
| `git_commit` | string | free text (hex hash or `unknown`) | W, M, L | `4c377398e` |

**`info` — one `key|value` row per field: `os`, `arch`, `hostname`**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `os` | string | `Darwin`, `Linux`, `Windows` | W, M, L | `Darwin` |
| `arch` | string | free text on Linux/macOS; on Windows one of `x86_64`, `aarch64`, `x86`, `arm`, `unknown` | W, M, L | `arm64` |
| `hostname` | string | free text (row omitted if the call fails) | W, M, L | `braga.local` |

**`health` — one `key|value` row per field: `uptime_seconds`, `timestamp_epoch_ms`, `memory_rss_kb`**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `uptime_seconds` | int64 | non-negative integer (seconds since `init()`) | W, M, L | `49012` |
| `timestamp_epoch_ms` | int64 | integer (Unix epoch milliseconds) | W, M, L | `1788774965076` |
| `memory_rss_kb` | int64 | non-negative integer (kilobytes), row absent on a failed read | W, M, L | `31056` |

**`plugins` — `plugins_count\|<n>` then one `plugin\|name\|version\|description` row per plugin**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `plugins_count` | int32 | non-negative integer | W, M, L | `0` |
| `plugin_name` | string | free text | W, M, L | `-` |
| `plugin_version` | string | free text | W, M, L | `-` |
| `plugin_description` | string | free text | W, M, L | `-` |

**`modules` — `modules_count\|<n>` then one `module\|name\|version\|status` row per module, plus an optional `module_description\|name\|description` row**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `modules_count` | int32 | non-negative integer | W, M, L | `0` |
| `module_name` | string | free text | W, M, L | `-` |
| `module_version` | string | free text or empty | W, M, L | `-` |
| `module_status` | string | `loaded`, `init_failed`, `load_failed` | W, M, L | `-` |
| `module_description` | string | free text, or the row is absent | W, M, L | `-` |

**`connection` — one `key|value` row per field: `server_address`, `tls_enabled`, `encrypted`, `debug_mode`, `verbose_logging`, `log_level`**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `server_address` | string | free text (host:port), or empty if unset | W, M, L | `-` (empty in every capture) |
| `tls_enabled` | bool | `true`, `false`, or empty if unset | W, M, L | `-` (empty in every capture) |
| `encrypted` | bool | `true`, `false` — `false` only when `tls_enabled` is literally `"false"` | W, M, L | `true` |
| `debug_mode` | bool | `true`, `false`, or empty if unset | W, M, L | `-` (empty in every capture) |
| `verbose_logging` | bool | `true`, `false`, or empty if unset | W, M, L | `-` (empty in every capture) |
| `log_level` | string | free text, or empty if unset | W, M, L | `-` (empty in every capture) |

**`switch` — one `key|value` row per field: `switch_address`, `session_id`, `connected_since`, `reconnect_count`**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `switch_address` | string | free text (host:port), or empty if unset | W, M, L | `-` (empty in every capture) |
| `session_id` | string | free text (opaque token), or empty | W, M, L | `-` (empty in every capture) |
| `connected_since` | string | integer-as-string (Unix ms), or empty | W, M, L | `-` (empty in every capture) |
| `reconnect_count` | int32 | non-negative integer, or empty string when unset | W, M, L | `-` (empty in every capture) |

**`config` — one `key|value` row per field: `agent_id`, `agent_version`, `build_number`, `git_commit`, `server_address`, `tls_enabled`, `heartbeat_interval`, `plugin_dir`, `data_dir`, `log_level`, `debug_mode`, `verbose_logging`**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `agent_id` | string | free text | W, M, L | `-` (empty in every capture) |
| `agent_version` | string | free text | W, M, L | `-` (empty in every capture) |
| `build_number` | string | free text (integer as string) | W, M, L | `-` (empty in every capture) |
| `git_commit` | string | free text | W, M, L | `-` (empty in every capture) |
| `server_address` | string | free text (host:port), or empty if unset | W, M, L | `-` (empty in every capture) |
| `tls_enabled` | bool | `true`, `false`, or empty if unset | W, M, L | `-` (empty in every capture) |
| `heartbeat_interval` | string | free text (integer seconds as string) | W, M, L | `-` (empty in every capture) |
| `plugin_dir` | string | free text (filesystem path) | W, M, L | `-` (empty in every capture) |
| `data_dir` | string | free text (filesystem path) | W, M, L | `-` (empty in every capture) |
| `log_level` | string | free text | W, M, L | `-` (empty in every capture) |
| `debug_mode` | bool | `true`, `false`, or empty if unset | W, M, L | `-` (empty in every capture) |
| `verbose_logging` | bool | `true`, `false`, or empty if unset | W, M, L | `-` (empty in every capture) |
<!-- END GENERATED -->

### Result status

This plugin does not set a typed result status; the agent records `UNDECLARED` and every sample shows `UNDECLARED / UNKNOWN /` for every action.

### Where the data goes

- **Instruction result only.** Rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore, queryable at `/api/responses/{id}`; none of the eight definitions override `spec.response.retentionDays`, so the store's default retention applies.
- **Not consumed by** daily-sync inventory, the TAR warehouse, or DEX — `status_plugin.cpp` has no `sync_source_*`, TAR cursor, or Guardian/DEX integration. Nothing runs on a schedule; every action executes only when an operator or workflow dispatches its definition.
- **Siblings:** `os_info` (a separate, broader platform-inventory plugin) and `agent_actions.info` (a separate plugin action that also reads "agent runtime info from config context" — overlaps in spirit with `status.info`/`status.config` but is a distinct code path).
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("device.status.version")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash pending

```
== action=version
version|0.13.1+7854
build_number|7854
git_commit|4c377398e
[result_status] UNDECLARED / UNKNOWN / 

== action=info
os|Windows
arch|x86_64
hostname|DESKTOP-04DNSIG
[result_status] UNDECLARED / UNKNOWN / 

== action=health
uptime_seconds|69196
timestamp_epoch_ms|1788775738117
memory_rss_kb|9772
[result_status] UNDECLARED / UNKNOWN / 

== action=plugins
plugins_count|0
[result_status] UNDECLARED / UNKNOWN / 

== action=modules
modules_count|0
[result_status] UNDECLARED / UNKNOWN / 

== action=connection
server_address|
tls_enabled|
encrypted|true
debug_mode|
verbose_logging|
log_level|
[result_status] UNDECLARED / UNKNOWN / 

== action=switch
switch_address|
session_id|
connected_since|
reconnect_count|
[result_status] UNDECLARED / UNKNOWN / 

== action=config
agent_id|
agent_version|
build_number|
git_commit|
server_address|
tls_enabled|
heartbeat_interval|
plugin_dir|
data_dir|
log_level|
debug_mode|
verbose_logging|
[result_status] UNDECLARED / UNKNOWN / 
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (alex) · leg-hash pending

```
== action=version
version|0.13.1+5871
build_number|5871
git_commit|4c377398e
[result_status] UNDECLARED / UNKNOWN / 

== action=info
os|Darwin
arch|arm64
hostname|braga.local
[result_status] UNDECLARED / UNKNOWN / 

== action=health
uptime_seconds|49012
timestamp_epoch_ms|1788774965076
memory_rss_kb|31056
[result_status] UNDECLARED / UNKNOWN / 

== action=plugins
plugins_count|0
[result_status] UNDECLARED / UNKNOWN / 

== action=modules
modules_count|0
[result_status] UNDECLARED / UNKNOWN / 

== action=connection
server_address|
tls_enabled|
encrypted|true
debug_mode|
verbose_logging|
log_level|
[result_status] UNDECLARED / UNKNOWN / 

== action=switch
switch_address|
session_id|
connected_since|
reconnect_count|
[result_status] UNDECLARED / UNKNOWN / 

== action=config
agent_id|
agent_version|
build_number|
git_commit|
server_address|
tls_enabled|
heartbeat_interval|
plugin_dir|
data_dir|
log_level|
debug_mode|
verbose_logging|
[result_status] UNDECLARED / UNKNOWN / 
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-06 · euid 0 · leg-hash pending

```
== action=version
version|0.13.1+0
build_number|0
git_commit|unknown
[result_status] UNDECLARED / UNKNOWN / 

== action=info
os|Linux
arch|aarch64
hostname|988e0b888baf
[result_status] UNDECLARED / UNKNOWN / 

== action=health
uptime_seconds|184122
timestamp_epoch_ms|1788722304837
memory_rss_kb|15020
[result_status] UNDECLARED / UNKNOWN / 

== action=plugins
plugins_count|0
[result_status] UNDECLARED / UNKNOWN / 

== action=modules
modules_count|0
[result_status] UNDECLARED / UNKNOWN / 

== action=connection
server_address|
tls_enabled|
encrypted|true
debug_mode|
verbose_logging|
log_level|
[result_status] UNDECLARED / UNKNOWN / 

== action=switch
switch_address|
session_id|
connected_since|
reconnect_count|
[result_status] UNDECLARED / UNKNOWN / 

== action=config
agent_id|
agent_version|
build_number|
git_commit|
server_address|
tls_enabled|
heartbeat_interval|
plugin_dir|
data_dir|
log_level|
debug_mode|
verbose_logging|
[result_status] UNDECLARED / UNKNOWN / 
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **The capture driver never calls `init()`, so five of eight actions read an empty config.** `plugins`, `modules`, `connection`, `switch`, and `config` all read through `cfg()` (`status_plugin.cpp:305-310`), which returns empty unconditionally until `init()` sets `raw_plugin_ctx_` (`status_plugin.cpp:264-273`) — every sample above shows this: `plugins_count|0`, `modules_count|0`, and every `connection`/`switch`/`config` field blank. On a running agent `init()` runs at plugin load, before any action executes.
2. **`switch`'s `session_id`, `connected_since`, and `reconnect_count` never populate on a live agent either.** The post-load config sync (`agents/core/src/agent.cpp:1017`, mechanism documented in `plugin_config_sync.hpp:24-29`) is one-shot and runs before `Register` sets `agent.session_id`/`agent.connected_since` (`agent.cpp:1896-1897`) or the reconnect loop updates `agent.reconnect_count` past its startup value of `"0"` (`agent.cpp:787`, updated at `agent.cpp:1630`) — so this action reports the live session id and reconnect count as empty/`0` for the whole life of the agent process, independent of this capture. `switch_address` (from `agent.server_address`, set at `agent.cpp:770`, before the sync) is the one field here that does reflect reality.
3. **`switch`'s `session_id` is classified as a live session credential, not plain inventory.** `server/core/src/capability_decls/plugin_action_catalogue_b.hpp:296-303` deliberately gates it under `PluginSecret`/Medium risk because Heartbeat/ReportInventory resolve the agent's identity from that same session id — do not reclassify it to `Inventory`/Low to match the other seven actions.
4. **`health.memory_rss_kb` is silently omitted, not placeholdered, on a failed read.** `get_memory_rss_kb()` returns `-1` on failure and `do_health` only calls `write_output` when the result is `>= 0` (`status_plugin.cpp:418-421`) — unlike the empty-string convention used by the config-backed actions, a failed read here drops the row entirely.
5. **`connection.encrypted` defaults to `"true"` whenever `tls_enabled` isn't the literal string `"false"`** (`status_plugin.cpp:343`) — including when the config value is unset, as in every capture above. A misconfigured or not-yet-synced agent reports itself encrypted by default on this field, never unencrypted.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/status/src/status_plugin.cpp` (single-file plugin — descriptor, action legs, and all eight actions)
- Definitions: `content/definitions/status.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_b.hpp` (lines 233-325)
- Tests: `tests/unit/test_runner_status.cpp` (tests `classify_runner_failure`, the agent's subprocess-runner status mapping — not specific to this plugin) · `tests/unit/test_tar_capture_status.cpp` (tests the TAR subprocess-capture classifier — also not specific to this plugin); no test dispatches the `status` plugin's own actions directly (no `DESCRIPTOR_TEST("status", ...)` entry in `tests/unit/test_new_plugins.cpp`, no `test_status_local_dispatcher.cpp`)
- Privilege row: no row in `docs/agent-privilege-model.md`
- Changelog: `changelog.d/2204-declarations-group-b.added.md` (added the ABI4 per-action/per-OS declarations for `status`) · `changelog.d/plugin-abi4-descriptor.added.md` (introduced the ABI4 mechanism these declarations use)
<!-- END GENERATED -->
