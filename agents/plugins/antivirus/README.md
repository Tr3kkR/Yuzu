# antivirus

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Antivirus product detection, status, and Defender exclusions |
| **Version** | 0.3.0 · plugin ABI 4 · shipped in PR #3369 (2026-08-23) |
| **Kind** | Collector · read-only · on-demand (no scheduled gather) |
| **Platforms** | Windows ✅ · macOS 🟡 constrained · Linux 🟡 constrained |
| **Actions** | `products` (definition `security.antivirus.products`) · `status` (definitions `security.antivirus.defender_status`, `security.antivirus.xprotect_status`) · `av_exclusions` (definition `security.antivirus.av_exclusions`) |
| **Security** | securable `Security` · operation Read · risk Low (`products`, `status`) / Medium (`av_exclusions`) · dispatch ReadOnly · approval gate none |
| **Roles** | execute: endpoint-admin, endpoint-operator, security-admin · author: content-author |
<!-- END GENERATED -->

## How it works

`products` enumerates installed/running AV products. Windows queries `root\SecurityCenter2` for `AntiVirusProduct` rows in-process via WMI and decodes each `productState` into enabled/snoozed/disabled plus a current/stale definitions field. Linux checks for `clamd`, `falcon-sensor`, and `sophos` via `pgrep`, falling back to an install-directory check for the latter two. macOS probes the XProtect definition bundle for identity, then enumerates endpoint-security system extensions for third-party EDR/AV, falling back to `pgrep` only for vendors the extension registry didn't already report.

`status` reports engine/definitions freshness. Windows queries `MSFT_MpComputerStatus` for real-time protection, signature version, and scan times. macOS reads the XProtect bundle's version and modification time plus the Remediator/MRT engine versions — no real-time-protection field, since macOS exposes no queryable equivalent. Linux checks ClamAV liveness plus its signature database's mtime, and reports CrowdStrike/Sophos presence only (no freshness data is reachable at this leg's rung).

`av_exclusions` is Windows-only: it reads Defender's Paths/Processes/Extensions exclusion keys from both the operator-editable local hive and the GPO/MDM policy hive, merges the two with per-entry provenance, and reports the worst of six subkey-read outcomes as the action's status. Linux and macOS have no equivalent exclusion store to read, so the action reports `unsupported` there rather than guessing.

The plugin deliberately stops at raw posture: a snoozed or disabled product is reported honestly, never normalized into a compliance verdict — that judgment belongs to a downstream policy engine.

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: Security.Read]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[antivirus.execute]
  EX --> WIN[Windows leg<br/>in-process WMI SecurityCenter2/Defender<br/>+ registry exclusion keys]
  EX --> MAC[macOS leg<br/>PlistBuddy + systemextensionsctl + pgrep<br/>bounded subprocess]
  EX --> LIN[Linux leg<br/>pgrep + stat<br/>bounded subprocess]
  WIN & MAC & LIN --> ROWS[rows + typed result status<br/>Windows only]
  ROWS --> RS[(ResponseStore)]
  RS --> API[REST /api/responses]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `products` | ✅ supported · rung 1 · `wmi_securitycenter2` | ✅ supported · rung 2 · `plistbuddy+systemextensionsctl+pgrep` | ✅ supported · rung 2 · `pgrep+filesystem_probe` |
| `status` | ✅ supported · rung 1 · `wmi_defender_status` | ✅ supported · rung 2 · `plistbuddy+stat` | ✅ supported · rung 2 · `pgrep+stat` |
| `av_exclusions` | ✅ supported · rung 1 · `win32_registry` | ⛔ unsupported | ⛔ unsupported |

**Declared limits per leg** (the descriptor's fallback text, verbatim):

- **`status` / Linux** — ClamAV liveness+definitions mtime; CrowdStrike/Sophos presence-only
- **`av_exclusions` / Windows** — permission_denied sentinel on ACL'd key, never a silent empty list
- **`av_exclusions` / macOS** — Windows-only concept
- **`av_exclusions` / Linux** — Windows-only concept
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account, captured as `SYSTEM` (LocalSystem today, #1442) | None observed. In-process WMI queries against SecurityCenter2/Defender and the Defender exclusion registry keys all succeeded under this identity. | 2026-09-07, bare-metal host, `SYSTEM` | `products`/`status`: `not_available\|<WMI error text>` row + `UNAVAILABLE`/`PARTIAL`. `av_exclusions`: a per-subkey `ERROR_ACCESS_DENIED` open renders `permission_denied\|exclusions <kind> access denied` and the action's status becomes `PERMISSION_DENIED`/`PARTIAL`. |
| macOS | agent daemon (docs describe default/unprivileged; sample was captured as an interactive user, euid 501, not the daemon identity) | None — `PlistBuddy`, `systemextensionsctl list`, and `pgrep` are all unprivileged reads. | 2026-09-07, bare-metal, euid 501 (alex) | An unreadable XProtect bundle renders `av\|XProtect\|unknown` (`products`) or `status\|unknown` (`status`) — never assumed active/healthy. |
| Linux | agent daemon (docs describe default/unprivileged; sample was captured as root in a container) | None — `pgrep` and the `/opt/*` existence checks need no capability. | 2026-09-06, container, euid 0 | A failed `pgrep` invocation is forwarded once via `forward_runner_failure`; the affected product renders as `not_running`/`not_detected` rather than crashing or fabricating a state. |

Binaries/subprocesses: macOS — `/usr/libexec/PlistBuddy`, `/usr/bin/systemextensionsctl`, `/usr/bin/pgrep` (bounded subprocess, 5s deadline). Linux — `/usr/bin/pgrep` or `/bin/pgrep` (bounded subprocess, 5s deadline). Windows — none; WMI and registry access are in-process. No network access on any OS.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
`products` takes no parameters.

`status` takes no parameters.

`av_exclusions` takes no parameters.
<!-- END GENERATED -->

### Outputs

Pipe-delimited rows, one per record, with the first field a literal row-type discriminator. `products` also emits ancillary single-purpose rows outside the `av|` shape: `av_count|0` when nothing was found, `xprotect_version|<n>` alongside `av|XProtect|active` on macOS, `edr|<bundle_id>|<version>` per detected macOS endpoint-security extension, and `not_available|<detail>` on Windows when the SecurityCenter2 query itself failed. `av_exclusions` likewise emits `exclusion_count|0` (clean empty read), or a typed `permission_denied|…` / `not_available|…` / `partial|…` row when a subkey read failed, or `unsupported|av_exclusions is Windows-only` on Linux/macOS. A missing WMI property is simply omitted from `status`'s Windows output, never fabricated.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`products` — `av|name|state|definitions`**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `name` | string | OS-supplied product/extension display name, sanitized | W, M, L | `Windows Defender` |
| `state` | string | Windows: `enabled` `snoozed` `disabled` `unknown`. macOS/Linux: `running` `installed` `active` `unknown` | W, M, L | `snoozed` |
| `definitions` | string | `current` `stale` `unknown` — Windows only; the row has 3 fields (no `definitions`) on Linux/macOS | W | `current` |

**`status` (definition `security.antivirus.defender_status`, Windows) — `realtime_protection|definition_version|last_update|last_quick_scan`**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `realtime_protection` | string | `enabled` `disabled`; row omitted entirely if the WMI property is absent | W | `enabled` |
| `definition_version` | string | free text, vendor signature version string | W | `1.459.88.0` |
| `last_update` | string | WMI CIM datetime string, not ISO-8601 | W | `20260906211522.000000+000` |
| `last_quick_scan` | string | WMI CIM datetime string, not ISO-8601 | W | `20260906150800.885000+000` |

**`status` (definition `security.antivirus.xprotect_status`, macOS) — `definition_version|last_update|remediator_version|mrt_version`**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `definition_version` | string | XProtect bundle version token | M | `5358` |
| `last_update` | string | ISO-8601 local time, bundle mtime | M | `2026-08-28T08:11:38` |
| `remediator_version` | string | XProtect.app version token | M | `157` |
| `mrt_version` | string | MRT.app version token | M | `1.93` |

**`av_exclusions` — `exclusion|kind|source|value`**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `kind` | enum | `path` `process` `extension` | W | `path` |
| `source` | enum | `local` `policy` `both` | W | `local` |
| `value` | string | free text — a registry value name (path/process/extension), vendor/operator-controlled | W | `D:\yuzu-dev` |
<!-- END GENERATED -->

### Result status

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `UNDECLARED` (agent-recorded default) | — | — | every macOS/Linux run (no leg calls `set_result_status`), and every Windows run that hits none of the paths below |
| `UNAVAILABLE` | partial | `antivirus:securitycenter2_unavailable` | Windows `products`: the SecurityCenter2 WMI query itself failed |
| `OK` | partial | `antivirus:securitycenter2_truncated` | Windows `products`: the WMI result set was truncated |
| `UNAVAILABLE` | partial | `antivirus:defender_namespace_unavailable` | Windows `status`: the Defender WMI namespace/query failed |
| `PERMISSION_DENIED` | partial | (subkey/kind named in the row) | Windows `av_exclusions`: any of the six subkey opens returned `ERROR_ACCESS_DENIED` (outranks the other two outcomes below) |
| `UNAVAILABLE` | partial | `antivirus:av_exclusions_open_failed` | Windows `av_exclusions`: a subkey open failed for a reason other than access-denied/not-found |
| `OK` | partial | `antivirus:av_exclusions_enumeration_incomplete` | Windows `av_exclusions`: a subkey opened but its value-name enumeration could not be confirmed complete |

### Where the data goes

- **Instruction result only.** Rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore, queryable at `/api/responses/{id}`. `defender_status`'s real-time-protection field also drives a fleet-wide pie-chart visualization defined directly in the YAML.
- **Not consumed by** daily-sync inventory, the TAR warehouse, DEX, or metrics — no source under those subsystems references `antivirus` or any `security.antivirus.*` id. The plugin executes only when an operator or workflow dispatches one of its definitions.
- **Siblings:** none — no other shipped plugin covers AV product/status/exclusion detection.
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("security.antivirus.products")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash pending

```
== action=products
av|Windows Defender|snoozed|current
[result_status] UNDECLARED / UNKNOWN / 

== action=status
realtime_protection|enabled
definition_version|1.459.88.0
last_update|20260906211522.000000+000
last_quick_scan|20260906150800.885000+000
[result_status] UNDECLARED / UNKNOWN / 

== action=av_exclusions
exclusion|path|local|D:\yuzu-dev
[result_status] UNDECLARED / UNKNOWN / 
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (alex) · leg-hash pending

```
== action=products
av|XProtect|active
xprotect_version|5358
[result_status] UNDECLARED / UNKNOWN / 

== action=status
definition_version|5358
last_update|2026-08-28T08:11:38
remediator_version|157
mrt_version|1.93
[result_status] UNDECLARED / UNKNOWN / 

== action=av_exclusions
unsupported|av_exclusions is Windows-only
[result_status] UNDECLARED / UNKNOWN / 
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-06 · euid 0 · leg-hash pending

```
== action=products
av_count|0
[result_status] UNDECLARED / UNKNOWN / 

== action=status
av|ClamAV|not_running
av|CrowdStrike Falcon|not_detected
av|Sophos|not_detected
[result_status] UNDECLARED / UNKNOWN / 

== action=av_exclusions
unsupported|av_exclusions is Windows-only
[result_status] UNDECLARED / UNKNOWN / 
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **The Windows `productState` decode is a reverse-engineered convention, not a documented API.** `decode_wsc_product_state` (`antivirus_parsers.hpp:217`) formats a widely-corroborated community convention going back to Vista — Microsoft has never published this layout, so the decode is MEDIUM confidence, not the HIGH confidence a header-published struct would carry.
2. **No content definition targets the Linux `status` leg.** `list_status_linux` is real, and the descriptor declares `status` supported on Linux at rung 2 (`antivirus_plugin.cpp:490-492`), but `security.antivirus.defender_status` is `platforms: [windows]` and `security.antivirus.xprotect_status` is `platforms: [darwin]` (`content/definitions/antivirus.yaml:104`, `:178`) — no definition in this file targets Linux for the `status` action.
3. **A single ACL'd exclusion subkey degrades the whole `av_exclusions` run.** The worst-of-six aggregation (`antivirus_plugin.cpp:211-247`) means one policy-hive key denied to the reading account reports `PERMISSION_DENIED` for the entire action, even if the other five subkey reads succeeded and returned real exclusions.
4. **`docs/agent-privilege-model.md`'s Windows cell is stale.** It still describes "PowerShell SecurityCenter2 / `Get-MpComputerStatus` CIM queries" (`docs/agent-privilege-model.md:97`); the plugin has read both namespaces in-process via WMI, with no PowerShell spawn, since PR #3369 (2026-08-23).
5. **CrowdStrike and Sophos are presence-only outside Windows.** Linux and macOS report `detected`/`not_detected` or `installed`/`running` for these vendors with no definitions-freshness data — this plugin has no rung-1 or rung-2 mechanism to read their own signature state on those platforms (`antivirus_plugin.cpp:327-329`).

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/antivirus/src/antivirus_plugin.cpp` (descriptor, execute, OS legs) · `agents/plugins/antivirus/src/antivirus_parsers.hpp` (pure parse/render helpers, OS-free)
- Definitions: `content/definitions/antivirus.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_d.hpp` (antivirus rows at lines 458, 468, 482)
- Tests: `tests/unit/test_antivirus_parsers.cpp` (29 cases) · `tests/unit/test_antivirus_local_dispatcher.cpp` (1 case, Windows-only, real WMI/registry via `LocalDispatcher`)
- Privilege row: `docs/agent-privilege-model.md` (line 97)
- Changelog: `changelog.d/20260716-macos-antivirus-xprotect.fixed.md` · `changelog.d/20260818-wave3-antivirus-av-exclusions.added.md` · `changelog.d/20260818-wave3-antivirus-native-wmi-registry.changed.md` · `changelog.d/2204-declarations-group-d.added.md`
<!-- END GENERATED -->
