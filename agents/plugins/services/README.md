# services

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | System services — enumerate, query, and configure service startup types |
| **Version** | 0.2.0 |
| **Kind** | Collector + Action · read-only (`list`, `running`) / mutating (`set_start_mode`) · on-demand (no scheduled gather) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux ✅ |
| **Actions** | `list` (definition `crossplatform.service.list`) · `running` (definition `crossplatform.service.running`) · `set_start_mode` (definition `crossplatform.service.set_start_mode`) |
| **Security** | securable `Infrastructure` · operation Read (`list`, `running`) / Write (`set_start_mode`) · risk Low (`list`, `running`) / High (`set_start_mode`) · dispatch ReadOnly (`list`, `running`) / Mutating (`set_start_mode`) · approval gate none (`list`, `running`) / AdminOrApproval (`set_start_mode`) |
| **Roles** | execute: endpoint-admin, endpoint-operator (`list`, `running`) / endpoint-admin only (`set_start_mode`) · author: content-author |
<!-- END GENERATED -->

## How it works

`list` and `running` are reads: each enumerates the OS's service registry — the Service Control Manager on Windows, the systemd unit list on Linux, the launchd job list on macOS — and returns one row per service. `running` is the same enumeration filtered to services currently active (`SERVICE_ACTIVE` on Windows, `--state=running` on Linux, a non-`-` PID on macOS — `launchctl` has no running filter of its own, so the plugin filters after parsing). `set_start_mode` is the plugin's one mutation: it changes a single named service's startup type to automatic, manual, or disabled, translating that three-state input onto whatever the target OS actually supports (Windows' native `ChangeServiceConfig` start type; `systemctl enable`/`disable`/`mask`; or `launchctl enable`/`disable` — macOS has no manual state and refuses the request outright rather than aliasing it to disabled). On macOS, `list`/`running` additionally join a single bulk `launchctl print-disabled system` call against every enumerated label to report an honest startup type — one extra subprocess call total, never one per service (C-1.12). Every Linux/macOS subprocess call runs through the bounded, shell-free argv runner (no `/bin/sh -c` hop); `set_start_mode`'s mutating calls on both platforms are additionally wrapped in `sudo -n --` to match the installer's sudoers grant. The plugin is deliberately not a change-history/diff of service state — that is the separately-implemented TAR service collector (see *Where the data goes*).

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: Infrastructure.Read list/running<br/>Infrastructure.Write + AdminOrApproval set_start_mode]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[services.execute]
  EX --> WIN[Windows leg<br/>EnumServicesStatusExW / QueryServiceConfigW / ChangeServiceConfigW]
  EX --> LIN[Linux leg<br/>runner argv systemctl list-units / sudo -n -- systemctl enable|disable|mask|unmask]
  EX --> MAC[macOS leg<br/>runner argv launchctl list + print-disabled / sudo -n -- launchctl enable|disable]
  WIN & LIN & MAC --> ROWS[pipe rows + typed result status] --> RS[(ResponseStore)] --> API[REST /api/responses · MCP]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `list` | ✅ supported · rung 1 · `win32_service_api` | ✅ supported · rung 2 · runner argv `launchctl list` | ✅ supported · rung 2 · runner argv `systemctl list-units` |
| `running` | ✅ supported · rung 1 · `win32_service_api` | ✅ supported · rung 2 · runner argv `launchctl list` | ✅ supported · rung 2 · runner argv `systemctl list-units` |
| `set_start_mode` | ✅ supported · rung 1 · `win32_service_api` | ✅ supported · rung 2 · runner argv `sudo -n -- launchctl enable\|disable` | ✅ supported · rung 2 · runner argv `sudo -n -- systemctl enable\|disable\|mask\|unmask` |

**Declared limits per leg** (the descriptor's fallback text, verbatim): none — every leg's fallback field is `nullptr` (`services_plugin.cpp:621-637`); the descriptor declares no fallback text for any action/OS pair.
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account — LocalSystem today (#1442) | `list`/`running`: none (default account). `set_start_mode`: `SeAssignPrimaryTokenPrivilege` (service control). | 2026-09-07, bare-metal, captured as `SYSTEM` | `list`/`running`: `OpenSCManagerW` failing returns an **empty** service list with no error and no result status set (`services_plugin.cpp:189-191`) — a permission failure reads identically to "this host has zero services". `set_start_mode`: `OpenServiceW`/`ChangeServiceConfigW` failure emits an explicit `error\|access denied changing service '<name>'` row (`services_plugin.cpp:426-429`). |
| macOS | agent daemon — root (shipped LaunchDaemon has no `UserName` key) | `list`/`running`: none. `set_start_mode`: sudoers grant `/bin/launchctl enable system/*`, `/bin/launchctl disable system/*` (the installed grant also covers `bootstrap`/`bootout`, which this plugin does not use). | 2026-09-07, bare-metal, captured **unprivileged** at `euid 501 (alex)` — not the root identity the daemon actually runs under | `list`/`running`: a failed `launchctl list` or `launchctl print-disabled` forwards `UNAVAILABLE`/`CONSTRAINED` via `forward_runner_failure` (`services_plugin.cpp:743-745`). `set_start_mode`: a `sudo -n` denial is captured (`merge_stderr=true`, `services_plugin.cpp:375-379`) and threaded into the `error\|...` message by `decide_set_start_mode_outcome`. |
| Linux | agent daemon — unprivileged `yuzu` account | `list`/`running`: none. `set_start_mode`: sudoers grant `/bin/systemctl enable\|disable\|mask\|unmask *` (also `/usr/bin/systemctl` on distros that mirror it). | 2026-09-06, container, captured at `euid 0` — root, not the deployed unprivileged identity | Same `forward_runner_failure` path as macOS; the captured Linux sample shows exactly this on both `list` and `running` (`UNAVAILABLE / PARTIAL / subprocess_runner:spawn_error`, `docs/samples/linux.txt:3,7`) — here caused by `systemctl` not being resolvable in the capture container, not by a privilege denial. `set_start_mode` mirrors macOS. |

Binaries/subprocesses/network: Linux runs `systemctl` (list-units for reads; enable/disable/mask/unmask under `sudo -n --` for the mutation). macOS runs `launchctl` (list, print-disabled for reads; enable/disable under `sudo -n --` for the mutation). Windows uses the native Win32 Service Control Manager API only — no subprocess. No network access on any OS.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
`list` takes no parameters.

`running` takes no parameters.

| Definition | Parameter | Type | Required | Default | Values | Description |
|---|---|---|---|---|---|---|
| `crossplatform.service.set_start_mode` | name | string | yes | - | pattern `^[a-zA-Z0-9._@-]+$`, 1–256 chars | The service identifier: a short Win32 service name, a systemd unit name, or a launchd label |
| `crossplatform.service.set_start_mode` | mode | string | yes | - | `automatic`, `manual`, `disabled` | Target startup type; macOS rejects `manual` (launchd has no manual/auto distinction — only enabled or disabled) |
<!-- END GENERATED -->

### Outputs

Rows are pipe-delimited, prefixed `svc|`, one row per service. The row **shape** differs by OS, not just the values: Windows and macOS emit exactly the four fields the `result.columns` schema names (`name|display_name|status|startup_type`), but Linux emits only **three** fields (`name|status|description`) — the systemctl leg never derives a startup type, so the fourth column doesn't exist on the Linux wire, and Linux's second/third fields carry different data than the schema's `display_name`/`status` names suggest (`services_plugin.cpp:730-733`; corroborated independently by the server's own parsing comment at `server/core/src/device_routes.cpp:197`). There is no placeholder-row convention: on Windows an enumeration failure silently returns zero rows with no error and no result status (`services_plugin.cpp:186-191`); on Linux/macOS it instead sets a typed `UNAVAILABLE`/`CONSTRAINED` status via `forward_runner_failure` before whatever rows were parsed (`services_plugin.cpp:121-130`). `set_start_mode` never writes the three schema columns as one pipe row: on success it writes three separate lines, `status|ok` / `service|<name>` / `mode|<mode>`; on any failure it writes a single `error|<message>` line and none of the three (`services_plugin.cpp:446-448`, file header comment lines 13-14).

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`list` — `name|display_name|status|startup_type`**

**`running` — `name|display_name|status|startup_type`**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `name` | string | free text — service/unit identifier | W, L, M | `ADPSvc` |
| `display_name` | string | free text (Windows) · integer PID or `-` (macOS) · field absent (Linux) | W, M | `Aggregated Data Platform Service` (W) · `1111` (M, PID) |
| `status` | string | `stopped`, `start_pending`, `stop_pending`, `running`, `continue_pending`, `pause_pending`, `paused`, `unknown` (Windows) · systemd SUB state, free text e.g. `running`, `dead`, `exited`, `failed` (Linux) · raw `launchctl` last-exit-status code, an integer as a string — NOT a running/stopped word (macOS) | W, L, M | `stopped` (W) · `0` (M) |
| `startup_type` | string | `automatic`, `boot`, `manual`, `disabled`, `system`, `unknown` (Windows) · `automatic`, `disabled`, `unknown` (macOS) · field absent (Linux) | W, M | `manual` (W) · `unknown` (M) |

**`set_start_mode` — `status|service|mode` (success) or `error|<message>` (failure)**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `status` | string | literal `ok` — the only value ever emitted, and only on success | W, L, M | `ok` |
| `service` | string | free text — echoes the `name` parameter unmodified | W, L, M | `-` (no successful mutation was captured live; see *Sample output*) |
| `mode` | string | `automatic`, `disabled` (all OS) · `manual` additionally on Windows/Linux (macOS rejects it) | W, L, M | `-` (no successful mutation was captured live; see *Sample output*) |
<!-- END GENERATED -->

### Result status

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `UNDECLARED` (default) | UNKNOWN | (empty) | Every successful `list`/`running` read on every OS, and every `set_start_mode` parameter-validation or platform-decision error (missing `name`/`mode`, invalid mode, unsafe name, macOS `manual` rejection) — the plugin never calls `ctx.set_result_status` on these paths (`services_plugin.cpp`, `do_set_start_mode`) |
| `UNAVAILABLE` or `CONSTRAINED` (via `forward_runner_failure`) | typically PARTIAL | e.g. `subprocess_runner:spawn_error` | Linux/macOS `list`/`running` when the `systemctl`/`launchctl` subprocess fails to spawn, times out, is cancelled, or is signaled (`services_plugin.cpp:121-123`); demonstrated live in `docs/samples/linux.txt:3,7` |
| `CONSTRAINED` | PARTIAL | `services:output_truncated` | Linux/macOS `list`/`running` when the captured subprocess output was cut short by the runner's byte cap but the tool itself exited cleanly (`services_plugin.cpp:124-128`) |

### Where the data goes

- **Instruction result only.** Rows travel the agent's mTLS gRPC channel as the command response into the ResponseStore (`response_retention_days`, default 90 — `server/core/include/yuzu/server/server.hpp:222`), queryable at `/api/responses/{id}`; the dashboard's generic result viewer renders `services` through its key/value fallback schema (`server/core/src/result_parsing.hpp:65`).
- **Device pages "Get live info".** The `services` live-snapshot kind (`device.live.services` audit verb) dispatches `list` directly and re-parses the same 3-vs-4-field row shape described above to render the device card (`server/core/src/device_routes.cpp:79-80,197`; `server/core/src/device_ui.cpp:410`).
- **Not consumed by** daily-sync inventory, TAR, or DEX/metrics — nothing here runs on a schedule; the plugin executes only when dispatched.
- **Siblings:** `agents/plugins/tar/src/tar_service_collector.cpp` performs its own, independently implemented service enumeration (the same three OS mechanisms) for TAR's diff-based change detection; it shares no code with this plugin.
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("crossplatform.service.list")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`; live snapshot via the device page's `services` kind (`device.live.services`).

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash pending

```
svc|ADPSvc|Aggregated Data Platform Service|stopped|manual
svc|ALG|Application Layer Gateway Service|stopped|manual
svc|AppIDSvc|Application Identity|stopped|manual
svc|Appinfo|Application Information|stopped|manual
svc|AppMgmt|Application Management|stopped|manual
svc|AppReadiness|App Readiness|stopped|manual
svc|AppVClient|Microsoft App-V Client|stopped|disabled
svc|AppXSvc|AppX Deployment Service (AppXSVC)|running|automatic
svc|ApxSvc|Windows Virtual Audio Device Proxy Service|stopped|manual
svc|AssignedAccessManagerSvc|AssignedAccessManager Service|stopped|manual
svc|AsusUpdateCheck|AsusUpdateCheck|stopped|automatic
svc|AudioEndpointBuilder|Windows Audio Endpoint Builder|running|automatic
svc|Audiosrv|Windows Audio|running|automatic
svc|autotimesvc|Cellular Time|stopped|manual
svc|AxInstSV|ActiveX Installer (AxInstSV)|stopped|manual
svc|battlenet_helpersvc|Battle.net Update Helper Svc|stopped|manual
svc|BDESVC|BitLocker Drive Encryption Service|stopped|manual
svc|BEService|BattlEye Service|stopped|manual
svc|BFE|Base Filtering Engine|running|automatic
svc|BITS|Background Intelligent Transfer Service|stopped|manual
svc|BrokerInfrastructure|Background Tasks Infrastructure Service|running|automatic
svc|BTAGService|Bluetooth Audio Gateway Service|running|manual
svc|BthAvctpSvc|AVCTP service|running|manual
svc|bthserv|Bluetooth Support Service|running|manual
svc|camsvc|Capability Access Manager Service|running|automatic
… 25 of 289 rows
[result_status] UNDECLARED / UNKNOWN /

svc|AppXSvc|AppX Deployment Service (AppXSVC)|running|automatic
svc|AudioEndpointBuilder|Windows Audio Endpoint Builder|running|automatic
svc|Audiosrv|Windows Audio|running|automatic
svc|BFE|Base Filtering Engine|running|automatic
svc|BrokerInfrastructure|Background Tasks Infrastructure Service|running|automatic
svc|BTAGService|Bluetooth Audio Gateway Service|running|manual
svc|BthAvctpSvc|AVCTP service|running|manual
svc|bthserv|Bluetooth Support Service|running|manual
svc|camsvc|Capability Access Manager Service|running|automatic
svc|CCleaner7|CCleaner 7|running|automatic
svc|CDPSvc|Connected Devices Platform Service|running|automatic
svc|CertPropSvc|Certificate Propagation|running|manual
svc|CoreMessagingRegistrar|CoreMessaging|running|automatic
svc|CryptSvc|Cryptographic Services|running|automatic
svc|DcomLaunch|DCOM Server Process Launcher|running|automatic
svc|DeviceAssociationService|Device Association Service|running|automatic
svc|DeviceInstall|Device Install Service|running|manual
svc|DevQueryBroker|DevQuery Background Discovery Broker|running|manual
svc|Dhcp|DHCP Client|running|automatic
svc|DiagTrack|Connected User Experiences and Telemetry|running|automatic
svc|DispBrokerDesktopSvc|Display Policy Service|running|automatic
svc|Dnscache|DNS Client|running|automatic
svc|DoSvc|Delivery Optimization|running|automatic
svc|DPS|Diagnostic Policy Service|running|automatic
svc|DsSvc|Data Sharing Service|running|manual
… 25 of 115 rows
[result_status] UNDECLARED / UNKNOWN /

error|missing required parameter: name
[result_status] UNDECLARED / UNKNOWN /
[rc] 1
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (alex) · leg-hash pending

```
svc|io.tailscale.ipn.macsys.login-item-helper|-|0|unknown
svc|com.apple.SafariHistoryServiceAgent|-|0|unknown
svc|com.apple.progressd|1111|0|unknown
svc|com.apple.enhancedloggingd|-|0|unknown
svc|com.apple.cloudphotod|1012|0|unknown
svc|com.apple.MENotificationService|1099|0|unknown
svc|com.apple.Finder|1186|0|unknown
svc|com.apple.homed|889|0|unknown
svc|com.apple.dataaccess.dataaccessd|1223|0|unknown
svc|com.apple.quicklook|-|0|unknown
svc|com.apple.parentalcontrols.check|-|0|unknown
svc|com.apple.mediaremoteagent|1057|0|unknown
svc|com.apple.FontWorker|1042|0|unknown
svc|com.apple.bird|941|0|unknown
svc|com.apple.amp.mediasharingd|-|0|unknown
svc|com.apple.knowledgeconstructiond|2105|0|unknown
svc|com.apple.inputanalyticsd|1559|0|unknown
svc|com.apple.familycontrols.useragent|-|0|unknown
svc|com.apple.AssetCache.agent|-|0|unknown
svc|com.apple.GameController.gamecontrolleragentd|974|0|unknown
svc|com.apple.universalaccessAuthWarn|1227|0|unknown
svc|com.apple.UserPictureSyncAgent|-|0|unknown
svc|com.apple.nsurlsessiond|871|0|unknown
svc|com.apple.devicecheckd|1477|0|unknown
svc|com.apple.syncservices.uihandler|-|0|unknown
… 25 of 513 rows
[result_status] UNDECLARED / UNKNOWN /

svc|com.apple.progressd|1111|0|unknown
svc|com.apple.cloudphotod|1012|0|unknown
svc|com.apple.MENotificationService|1099|0|unknown
svc|com.apple.Finder|1186|0|unknown
svc|com.apple.homed|889|0|unknown
svc|com.apple.dataaccess.dataaccessd|1223|0|unknown
svc|com.apple.mediaremoteagent|1057|0|unknown
svc|com.apple.FontWorker|1042|0|unknown
svc|com.apple.bird|941|0|unknown
svc|com.apple.knowledgeconstructiond|2105|0|unknown
svc|com.apple.inputanalyticsd|1559|0|unknown
svc|com.apple.GameController.gamecontrolleragentd|974|0|unknown
svc|com.apple.universalaccessAuthWarn|1227|0|unknown
svc|com.apple.nsurlsessiond|871|0|unknown
svc|com.apple.devicecheckd|1477|0|unknown
svc|com.apple.iconservices.iconservicesagent|1083|0|unknown
svc|com.apple.diagnosticextensionsd|916|0|unknown
svc|com.apple.intelligenceplatformd|2003|0|unknown
svc|com.apple.SafariBookmarksSyncAgent|1270|0|unknown
svc|com.apple.managedcorespotlightd.D4D2EF40-0450-FD20-B9EA-08B3E5E85211|1980|0|unknown
svc|com.apple.ndoagent|1003|0|unknown
svc|com.apple.wallpaper.agent|1190|0|unknown
svc|com.apple.localizationswitcherd|1080|0|unknown
svc|com.apple.commerce|1576|0|unknown
svc|com.apple.ManagedSettingsAgent|920|0|unknown
… 25 of 279 rows
[result_status] UNDECLARED / UNKNOWN /

error|missing required parameter: name
[result_status] UNDECLARED / UNKNOWN /
[rc] 1
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-06 · euid 0 · leg-hash pending

```
[result_status] UNAVAILABLE / PARTIAL / subprocess_runner:spawn_error
[rc] 1

[result_status] UNAVAILABLE / PARTIAL / subprocess_runner:spawn_error
[rc] 1

error|missing required parameter: name
[result_status] UNDECLARED / UNKNOWN /
[rc] 1
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **Linux drops the fourth output column entirely, not just leaves it blank.** The Linux leg emits `svc|name|status|description` (three fields); Windows and macOS emit four. A consumer that indexes the row by the schema's declared column names will misread Linux's `status`/`description` fields as `display_name`/`status`.
2. **A Windows enumeration failure is silently indistinguishable from zero services.** If `OpenSCManagerW` fails, `do_list`'s Windows branch returns an empty list with no error text and no result status set (`services_plugin.cpp:186-191`, `717-723`) — unlike the Linux/macOS legs, which forward a typed `UNAVAILABLE`/`CONSTRAINED` status on the same class of failure.
3. **macOS's `status` field is a raw exit-status code, not a running/stopped word.** Every sample row shows `status=0`, launchctl's last-exit-status column — to tell whether a macOS service is currently running, check the `display_name` (PID) field is not `-`, not this field (`services_plugin.cpp:747-749`; `LaunchdEntry::pid`, `services_parsers.hpp:126-128`).
4. **The macOS row cap already fired in this capture.** `total_seen=517` exceeded `kMaxServiceRows=512`, so the real `list` capture ends with a `svc|__truncated__|-|517|-` sentinel row (`docs/samples/macos.txt:515`) that falls outside this page's 25-row trim; the cap is documented behavior (`services_plugin.cpp:750-756`), not a capture artifact.
5. **No capture exercises `set_start_mode`'s actual mutation.** Every OS's `set_start_mode` sample stops at the parameter-validation rejection (`error|missing required parameter: name`) — the sudo-wrapped `enable`/`disable`/`mask`/`unmask` calls have never been captured live. The Linux `list`/`running` captures also failed outright (`subprocess_runner:spawn_error` — `systemctl` was not resolvable in the capture container), so the Linux 3-field row shape above is verified from source (`services_plugin.cpp:730-733`), not from a captured row.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/services/src/services_plugin.cpp` (descriptor, execute, per-OS legs) · `services_parsers.hpp` (Linux/macOS enumeration parsers, `is_safe_service_name`, `decide_set_start_mode_outcome`) · `services_macos_launchd.hpp` (macOS `print-disabled` parser, `startup_type_for`) · `meson.build`
- Definitions: `content/definitions/services.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_d.hpp`
- Tests: `tests/unit/test_services_parsers.cpp` · `tests/unit/agent/test_services_macos.cpp`
- Privilege row: `docs/agent-privilege-model.md` (`services.list`/`services.running`, `services.set_start_mode`)
- Changelog: `changelog.d/2204-declarations-group-d.added.md` · `changelog.d/2277-macos-plugin-parity.added.md` · `changelog.d/2277-macos-parity-contracts.changed.md` · `changelog.d/20260818-wave2-network-actions-wol-services-native-argv.changed.md` · `changelog.d/3404-hardware-wmi-bounded.fixed.md`
<!-- END GENERATED -->
