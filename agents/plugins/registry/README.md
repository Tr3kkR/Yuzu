# registry

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Windows Registry — get, set, delete, enumerate keys and values |
| **Version** | 1.0.0 |
| **Kind** | Action · read-only (6 actions) + mutating/destructive (3 actions) · on-demand (no scheduled gather) |
| **Platforms** | Windows ✅ · macOS ⛔ · Linux ⛔ |
| **Actions** | `get_value` (definition `windows.registry.get_value`) · `set_value` (`windows.registry.set_value`) · `delete_value` (`windows.registry.delete_value`) · `delete_key` (`windows.registry.delete_key`) · `key_exists` (`windows.registry.key_exists`) · `enumerate_keys` (`windows.registry.enumerate_keys`) · `enumerate_values` (`windows.registry.enumerate_values`) · `get_user_value` (`windows.registry.get_user_value`) · `list_profiles` (`windows.registry.list_profiles`) |
| **Security** | securable `Infrastructure` (all 9 actions) · operation Read (`get_value`, `key_exists`, `enumerate_keys`, `enumerate_values`, `get_user_value`, `list_profiles`) / Write (`set_value`) / Delete (`delete_value`, `delete_key`) · risk Low (5 read actions) / Medium (`set_value`, `get_user_value`) / High (`delete_value`) / Critical (`delete_key`) · dispatch ReadOnly (6) / Mutating (`set_value`) / Destructive (`delete_value`, `delete_key`) · approval gate None (5 read actions) / AdminOrApproval (`set_value`, `delete_value`, `delete_key`, `get_user_value`) |
| **Roles** | execute: endpoint-admin, endpoint-operator (`get_value`, `key_exists`, `enumerate_keys`, `enumerate_values`, `list_profiles`) · endpoint-admin only (`set_value`, `delete_value`, `delete_key`, `get_user_value`) · author: content-author (all actions) |
<!-- END GENERATED -->

## How it works

All nine actions are direct, synchronous Win32 registry calls — there is no scheduled gather. `get_value`/`key_exists`/`enumerate_keys`/`enumerate_values` open a key read-only and read or list it; `set_value` opens the key with `KEY_WRITE` (creating it if absent); `delete_value`/`delete_key` open with `KEY_SET_VALUE` or call `RegDeleteKeyW` directly. Every one of these six validates `hive`+`key` through one shared `parse_params` helper, which also logs (never blocks) access to a small set of sensitive `HKLM` subtrees (`...CurrentVersion\Run*`, `...Services`) via `spdlog::info` — an audit trail, not a policy gate.

`get_user_value` is the odd one out: it resolves the target profile through the same `ProfileList` walk `list_profiles` exposes as its own action, reads the live `HKEY_USERS\<SID>` hive if the user is logged in, and only falls back to an offline `RegLoadKeyW` mount of that profile's `NTUSER.DAT` — under `SeBackup`/`SeRestore` privilege and a process-wide mutex serialising the whole offline arm — when the user is logged out. `list_profiles` is the discovery step the other per-user action needs: SID, resolved name, path, and live hive-load state, with the three well-known system SIDs filtered out.

The plugin deliberately does **not** decode `REG_MULTI_SZ`/`REG_LINK` *values* on `get_value`/`enumerate_values` — both are left hex-encoded there, unlike `get_user_value`, which decodes both; closing that gap would change `get_value`'s output shape for existing callers and is out of scope for this plugin as it stands. On macOS/Linux every action honestly reports `registry|unsupported|...` — reads return rc 0 (an honest "unsupported" read is itself a successful read) and the three mutators return rc 1 (a state-changing action that touched nothing must never report SUCCESS).

```mermaid
flowchart LR
  OP[Operator / workflow<br/>dispatches definition] --> SRV[Server<br/>authz: Infrastructure.Read/Write/Delete<br/>ExecuteGate: None or AdminOrApproval]
  SRV -- gRPC mTLS --> HOST[Agent plugin host]
  HOST --> EX[registry.execute]
  EX --> WIN[Windows leg<br/>Reg*W Open/Query/Set/Delete/Enum<br/>+ RegLoadKeyW hive mount for get_user_value]
  EX --> MAC[macOS leg<br/>honest 'unsupported' sentinel]
  EX --> LIN[Linux leg<br/>honest 'unsupported' sentinel]
  WIN & MAC & LIN --> ROWS[rows / lines +<br/>result status]
  ROWS -- CommandResponse --> RS[(ResponseStore)]
  RS --> API[REST /api/responses]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `get_value` | ✅ supported · rung 1 · `win32_registry` | ⛔ unsupported · no mechanism bound | ⛔ unsupported · no mechanism bound |
| `set_value` | ✅ supported · rung 1 · `win32_registry` | ⛔ unsupported · no mechanism bound | ⛔ unsupported · no mechanism bound |
| `delete_value` | ✅ supported · rung 1 · `win32_registry` | ⛔ unsupported · no mechanism bound | ⛔ unsupported · no mechanism bound |
| `delete_key` | ✅ supported · rung 1 · `win32_registry` | ⛔ unsupported · no mechanism bound | ⛔ unsupported · no mechanism bound |
| `key_exists` | ✅ supported · rung 1 · `win32_registry` | ⛔ unsupported · no mechanism bound | ⛔ unsupported · no mechanism bound |
| `enumerate_keys` | ✅ supported · rung 1 · `win32_registry` | ⛔ unsupported · no mechanism bound | ⛔ unsupported · no mechanism bound |
| `enumerate_values` | ✅ supported · rung 1 · `win32_registry` | ⛔ unsupported · no mechanism bound | ⛔ unsupported · no mechanism bound |
| `get_user_value` | ✅ supported · rung 1 · `win32_registry+hive_mount` | ⛔ unsupported · no mechanism bound | ⛔ unsupported · no mechanism bound |
| `list_profiles` | ✅ supported · rung 1 · `win32_registry` | ⛔ unsupported · no mechanism bound | ⛔ unsupported · no mechanism bound |

**Declared limits per leg** (the descriptor's fallback text, verbatim):

None declared — every leg's fallback field is `nullptr` in the descriptor (`registry_plugin.cpp:104-158`); the plugin's per-OS caveats live only in the macOS/Linux honest-sentinel strings emitted by `execute()` (`registry_plugin.cpp:216`, `registry_plugin.cpp:220`), reproduced in Privileges and prerequisites and Sample output below.
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account (LocalSystem today, #1442) | `set_value`/`delete_value`/`delete_key` against `HKLM\*` need the service account in `Administrators`; `HKCU\*` needs no elevation. `get_user_value`'s offline-hive fallback needs `SeBackupPrivilege`+`SeRestorePrivilege`, already granted to the service account — no new grant; its live-hive path and `list_profiles` need no elevated privilege at all. | 2026-09-07, bare-metal, as `SYSTEM` | `error\|key not found` / `error\|value not found` (reads); `error\|failed to open/create key` / `error\|failed to delete key` (writes/deletes) — Win32 does not distinguish "access denied" from "does not exist" in these two messages |
| macOS | n/a — plugin loads but every action is the honest `unsupported` leg | n/a | 2026-09-07, bare-metal, euid 501 (alex) | always `registry\|unsupported\|Windows registry has no macOS equivalent; use defaults/plists`, rc 0 (reads) / rc 1 (mutators) |
| Linux | n/a — plugin loads but every action is the honest `unsupported` leg | n/a | 2026-09-07, container, euid 0 | always `registry\|unsupported\|Windows registry is not available on this platform`, rc 0 (reads) / rc 1 (mutators) |

No external binaries, no subprocesses, no network access — every call is an in-process Win32 `Reg*W`/`AdjustTokenPrivileges` call (`registry_plugin.cpp`, `agents/shared/win_profiles.hpp`, `agents/shared/win_reg_handle.hpp`).

**`HKCU` is a per-process alias, not a real hive.** `parse_hive` maps `"HKCU"` straight to the predefined handle `HKEY_CURRENT_USER` (`registry_plugin.cpp:78`), which Win32 resolves against the calling process's own token rather than any hive path the plugin names. The agent runs as `SYSTEM`/LocalSystem with no interactively logged-on user context, so every `hive=HKCU` call in this plugin resolves to `HKEY_USERS\.DEFAULT` — the Windows sample's `Software\YuzuCaptureTmp` scratch key (`set_value`/`delete_value`/`delete_key`, above) lived under `.DEFAULT`, not any real user's profile. An operator who needs a specific user's hive must use `get_user_value` (or `list_profiles` + an explicit `sid`), never `hive=HKCU`.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
| Action | Parameter | Type | Required | Default | Values | Description |
|---|---|---|---|---|---|---|
| `get_value` | `hive` | string | yes | - | `HKLM`, `HKCU`, `HKCR`, `HKU` | Registry hive to read from |
| `get_value` | `key` | string | yes | - | - | Key path relative to the hive root |
| `get_value` | `name` | string | yes | - | - | The value name to read |
| `set_value` | `hive` | string | yes | - | `HKLM`, `HKCU`, `HKCR`, `HKU` | Registry hive to write to |
| `set_value` | `key` | string | yes | - | - | Key path relative to the hive root; created if absent |
| `set_value` | `name` | string | yes | - | - | The value name to write |
| `set_value` | `value` | string | yes | - | - | The value data, interpreted per `type` |
| `set_value` | `type` | string | no | - | `REG_SZ`, `REG_DWORD` | Value type to write; the plugin itself defaults to `REG_SZ` when omitted |
| `delete_value` | `hive` | string | yes | - | `HKLM`, `HKCU`, `HKCR`, `HKU` | Registry Hive |
| `delete_value` | `key` | string | yes | - | - | Key Path |
| `delete_value` | `name` | string | yes | - | - | Value Name |
| `delete_key` | `hive` | string | yes | - | `HKLM`, `HKCU`, `HKCR`, `HKU` | Registry Hive |
| `delete_key` | `key` | string | yes | - | - | Key Path |
| `key_exists` | `hive` | string | yes | - | `HKLM`, `HKCU`, `HKCR`, `HKU` | Registry Hive |
| `key_exists` | `key` | string | yes | - | - | Key Path |
| `enumerate_keys` | `hive` | string | yes | - | `HKLM`, `HKCU`, `HKCR`, `HKU` | Registry hive to enumerate |
| `enumerate_keys` | `key` | string | yes | - | - | Key path relative to the hive root |
| `enumerate_values` | `hive` | string | yes | - | `HKLM`, `HKCU`, `HKCR`, `HKU` | Registry Hive |
| `enumerate_values` | `key` | string | yes | - | - | Key Path |
| `get_user_value` | `username` | string | no* | - | maxLength 256 | Profile folder name resolved via ProfileList, matched case-insensitively; not always the account name |
| `get_user_value` | `sid` | string | no* | - | maxLength 256 | Windows SID as an alternative to `username`; must be one `list_profiles` would report |
| `get_user_value` | `key` | string | yes | - | maxLength 1024 | Key path relative to the resolved user's hive root |
| `get_user_value` | `name` | string | no | - | maxLength 256 | The value name to read; empty reads the key's unnamed "(Default)" value |
| `list_profiles` | — | — | — | — | — | takes no parameters |

\* `username` or `sid` — one is required; `sid` takes precedence if both are given.
<!-- END GENERATED -->

### Outputs

This plugin does not emit a uniform pipe-joined "row"; each action has its own shape. `get_value`, `get_user_value`, `key_exists`, `set_value`, `delete_value` and `delete_key` each write one self-describing `field_name|value` line per field, on success only — a failure instead writes an `error|...` line and returns rc 1, so `-` is never used as an absence placeholder anywhere in this plugin. `enumerate_keys` writes one `subkey|<name>` line per subkey; a genuinely empty key emits zero lines with rc 0 (a key that cannot be opened at all instead reports `error|key not found`, rc 1). `enumerate_values` writes one line per value shaped `value|<name>|<type>` — the leading `value` is a fixed literal tag, not one of the two documented columns (`name`, `type`); see Caveats. `list_profiles` writes one true pipe-joined row per profile (`<sid>|<name>|<path>|<state>`, no discriminator prefix) and zero rows is a structural success, not an error, when the host has no non-system profiles.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`get_value` — `value|<data>` then `type|<type-name>` (two separate output lines)**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `value` | string | free text | W | `Windows 10 Pro` |
| `type` | string | `REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_MULTI_SZ, REG_NONE, REG_LINK, REG_DWORD_BIG_ENDIAN, REG_UNKNOWN` | W | `REG_SZ` |

**`set_value` / `delete_value` / `delete_key` — `status|ok` (single line, success only)**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `status` | string | `ok` | W | `ok` |

**`key_exists` — `exists|<true or false>`**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `exists` | bool | `true, false` | W | `true` |

**`enumerate_keys` — `subkey|<name>` (one line per subkey)**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `subkey` | string | free text | W | `ProfileList` |

**`enumerate_values` — `value|<name>|<type-name>` (one line per value; leading `value` is a literal tag, not a column)**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `name` | string | free text | W | `ProductName` |
| `type` | string | `REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_MULTI_SZ, REG_NONE, REG_LINK, REG_DWORD_BIG_ENDIAN, REG_UNKNOWN` | W | `REG_SZ` |

**`get_user_value` — `username|<name>` then `value|<data>` then `type|<type-name>` (three separate output lines, success only)**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `username` | string | free text, never fabricated/empty (ADR-0024 D11) | W | `alex` |
| `value` | string | free text; decodes `REG_MULTI_SZ`/`REG_LINK` where `get_value` does not | W | `1` |
| `type` | string | `REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_MULTI_SZ, REG_NONE, REG_LINK, REG_DWORD_BIG_ENDIAN, REG_UNKNOWN` | W | `REG_DWORD` |

**`list_profiles` — `<sid>|<profile_name>|<profile_path>|<hive_state>` (one row per profile, no discriminator prefix)**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `sid` | string | free text (a Windows SID string) | W | `S-1-5-21-571721511-16201247-3531262703-1001` |
| `profile_name` | string | free text or `-` | W | `Alex` |
| `profile_path` | string | free text or `-` | W | `C:\Users\Alex` |
| `hive_state` | string | `loaded, loaded_classes_only, not_loaded` | W | `loaded` |
<!-- END GENERATED -->

### Result status

This plugin does not set a typed result status; the agent records `UNDECLARED` and every sample shows `UNDECLARED / UNKNOWN /`.

### Where the data goes

- **Instruction result only.** Rows/lines travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore, queryable at `/api/responses/{id}`.
- **Not consumed by** daily-sync inventory, the TAR warehouse, DEX, or metrics — nothing here runs on a schedule; the plugin executes only when an operator or workflow dispatches one of its nine definitions.
- **Siblings:** none. Guardian's own real-time registry-key watch (`guard_type: "registry"`, `spark_fleet_tags.hpp:112`) is an unrelated detection mechanism, not this plugin — this plugin is on-demand CRUD only, with no watch/trigger surface.
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("windows.registry.get_value")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash pending

```
== action=get_value hive=HKLM key="SOFTWARE\Microsoft\Windows NT\CurrentVersion" name=ProductName
value|Windows 10 Pro
type|REG_SZ
[result_status] UNDECLARED / UNKNOWN / 

== action=set_value hive=HKCU key=Software\YuzuCaptureTmp name=probe value=1
status|ok
[result_status] UNDECLARED / UNKNOWN / 

== action=delete_value hive=HKCU key=Software\YuzuCaptureTmp name=probe
status|ok
[result_status] UNDECLARED / UNKNOWN / 

== action=delete_key hive=HKCU key=Software\YuzuCaptureTmp
status|ok
[result_status] UNDECLARED / UNKNOWN / 

== action=key_exists hive=HKLM key="SOFTWARE\Microsoft\Windows NT\CurrentVersion"
exists|true
[result_status] UNDECLARED / UNKNOWN / 

== action=enumerate_keys hive=HKLM key="SOFTWARE\Microsoft\Windows NT\CurrentVersion"
subkey|Accessibility
subkey|AdaptiveDisplayBrightness
subkey|AeDebug
subkey|AppCompatFlags
subkey|ASR
subkey|Audit
subkey|BackgroundModel
subkey|ClipSVC
subkey|Compatibility32
subkey|Console
subkey|Containers
subkey|CorruptedFileRecovery
subkey|DefaultProductKey
subkey|DefaultProductKey2
subkey|DeviceDisplayObjects
subkey|DiskDiagnostics
subkey|drivers.desc
subkey|Drivers32
subkey|EFS
subkey|Event Viewer
subkey|Font Drivers
subkey|Font Management
subkey|FontDPI
subkey|FontIntensityCorrection
subkey|FontLink
… 25 of 99 rows
[result_status] UNDECLARED / UNKNOWN / 

== action=enumerate_values hive=HKLM key="SOFTWARE\Microsoft\Windows NT\CurrentVersion"
value|SystemRoot|REG_SZ
value|BaseBuildRevisionNumber|REG_DWORD
value|BuildBranch|REG_SZ
value|BuildGUID|REG_SZ
value|BuildLab|REG_SZ
value|BuildLabEx|REG_SZ
value|CompositionEditionID|REG_SZ
value|CurrentBuild|REG_SZ
value|CurrentBuildNumber|REG_SZ
value|CurrentMajorVersionNumber|REG_DWORD
value|CurrentMinorVersionNumber|REG_DWORD
value|CurrentType|REG_SZ
value|CurrentVersion|REG_SZ
value|DisplayVersion|REG_SZ
value|EditionID|REG_SZ
value|EditionSubManufacturer|REG_SZ
value|EditionSubstring|REG_SZ
value|EditionSubVersion|REG_SZ
value|InstallationType|REG_SZ
value|InstallDate|REG_DWORD
value|LCUVer|REG_SZ
value|ProductName|REG_SZ
value|ReleaseId|REG_SZ
value|SoftwareType|REG_SZ
value|UBR|REG_DWORD
value|PathName|REG_SZ
value|PendingInstall|REG_DWORD
value|ProductId|REG_SZ
value|DigitalProductId|REG_BINARY
value|DigitalProductId4|REG_BINARY
value|RegisteredOwner|REG_SZ
value|InstallTime|REG_QWORD
[result_status] UNDECLARED / UNKNOWN / 

== action=get_user_value username=alex key=Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced name=Hidden
username|alex
value|1
type|REG_DWORD
[result_status] UNDECLARED / UNKNOWN / 

== action=list_profiles
S-1-5-21-571721511-16201247-3531262703-1001|Alex|C:\Users\Alex|loaded
[result_status] UNDECLARED / UNKNOWN / 
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (alex) · leg-hash pending

```
== action=get_value hive=HKLM key="SOFTWARE\Microsoft\Windows NT\CurrentVersion" name=ProductName
registry|unsupported|Windows registry has no macOS equivalent; use defaults/plists
[result_status] UNDECLARED / UNKNOWN / 

== action=set_value hive=HKCU key=Software\YuzuCaptureTmp name=probe value=1
registry|unsupported|Windows registry has no macOS equivalent; use defaults/plists
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1

== action=delete_value hive=HKCU key=Software\YuzuCaptureTmp name=probe
registry|unsupported|Windows registry has no macOS equivalent; use defaults/plists
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1

== action=delete_key hive=HKCU key=Software\YuzuCaptureTmp
registry|unsupported|Windows registry has no macOS equivalent; use defaults/plists
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1

== action=key_exists hive=HKLM key="SOFTWARE\Microsoft\Windows NT\CurrentVersion"
registry|unsupported|Windows registry has no macOS equivalent; use defaults/plists
[result_status] UNDECLARED / UNKNOWN / 

== action=enumerate_keys hive=HKLM key="SOFTWARE\Microsoft\Windows NT\CurrentVersion"
registry|unsupported|Windows registry has no macOS equivalent; use defaults/plists
[result_status] UNDECLARED / UNKNOWN / 

== action=enumerate_values hive=HKLM key="SOFTWARE\Microsoft\Windows NT\CurrentVersion"
registry|unsupported|Windows registry has no macOS equivalent; use defaults/plists
[result_status] UNDECLARED / UNKNOWN / 

== action=get_user_value username=alex key=Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced name=Hidden
registry|unsupported|Windows registry has no macOS equivalent; use defaults/plists
[result_status] UNDECLARED / UNKNOWN / 

== action=list_profiles
registry|unsupported|Windows registry has no macOS equivalent; use defaults/plists
[result_status] UNDECLARED / UNKNOWN / 
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-07 · euid 0 · leg-hash pending

```
== action=get_value hive=HKLM key="SOFTWARE\Microsoft\Windows NT\CurrentVersion" name=ProductName
registry|unsupported|Windows registry is not available on this platform
[result_status] UNDECLARED / UNKNOWN / 

== action=set_value hive=HKCU key=Software\YuzuCaptureTmp name=probe value=1
registry|unsupported|Windows registry is not available on this platform
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1

== action=delete_value hive=HKCU key=Software\YuzuCaptureTmp name=probe
registry|unsupported|Windows registry is not available on this platform
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1

== action=delete_key hive=HKCU key=Software\YuzuCaptureTmp
registry|unsupported|Windows registry is not available on this platform
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1

== action=key_exists hive=HKLM key="SOFTWARE\Microsoft\Windows NT\CurrentVersion"
registry|unsupported|Windows registry is not available on this platform
[result_status] UNDECLARED / UNKNOWN / 

== action=enumerate_keys hive=HKLM key="SOFTWARE\Microsoft\Windows NT\CurrentVersion"
registry|unsupported|Windows registry is not available on this platform
[result_status] UNDECLARED / UNKNOWN / 

== action=enumerate_values hive=HKLM key="SOFTWARE\Microsoft\Windows NT\CurrentVersion"
registry|unsupported|Windows registry is not available on this platform
[result_status] UNDECLARED / UNKNOWN / 

== action=get_user_value username=alex key=Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced name=Hidden
registry|unsupported|Windows registry is not available on this platform
[result_status] UNDECLARED / UNKNOWN / 

== action=list_profiles
registry|unsupported|Windows registry is not available on this platform
[result_status] UNDECLARED / UNKNOWN / 
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **`enumerate_values`'s wire format carries an undocumented literal tag.** Each line is `value|<name>|<type>` (`registry_plugin.cpp:383`), but the definition's `result.columns` lists only `name` and `type` — the leading `value` segment is a fixed literal, not a third data column, and a naive "split on the declared column count" parser will misread every row by one field.
2. **`get_value`/`enumerate_values` do not decode `REG_MULTI_SZ`/`REG_LINK` values; `get_user_value` does.** Both fall to the hex-dump default branch on the first two actions (`registry_plugin.cpp:277-280`) but are decoded (semicolon-joined records / sanitised target string) on the third via the shared `read_reg_value` (`agents/shared/win_profiles.hpp:660-742`). This is a declared, deliberate inconsistency (`catalog.md`'s value-type notes) — closing it changes `get_value`'s output for existing callers and is out of scope here.
3. **`set_value`/`delete_value`/`delete_key` cannot distinguish "access denied" from "does not exist" in their error text.** `do_set_value`'s `RegCreateKeyExW` failure always reports `error|failed to open/create key` (`registry_plugin.cpp:296-299`) and `do_delete_value`'s `RegOpenKeyExW` failure always reports `error|key not found` (`registry_plugin.cpp:324-326`) regardless of the underlying `LSTATUS` — unlike `get_user_value`'s ladder, which does separate `key_access_denied` from `key_not_found` (`agents/shared/user_profile_model.hpp:266-278`).
4. **`PrivilegeScope`'s `AdjustTokenPrivileges` call must keep its `ReturnLength` argument.** A prior version omitted it and the call failed with `ERROR_NOACCESS` on every invocation, so the offline per-user hive fallback silently never enabled `SeBackup`/`SeRestore` from the plugin's initial ship until #2771 (`agents/shared/win_profiles.hpp:358-371`, `changelog.d/2771-privilegescope-token-adjust-bug.fixed.md`) — do not "simplify" that call signature.
5. **The `get_user_value` capture exercised the live-hive path, not the offline mount.** `list_profiles` in the same Windows capture reports the target SID's `hive_state` as `loaded`, so `with_user_hive`'s first `RegOpenKeyExW(HKEY_USERS, <sid>, ...)` succeeded and the offline `RegLoadKeyW`/`SeBackup`+`SeRestore` fallback (`win_profiles.hpp:495-534`) was never reached — this sample does not exercise that branch, the unload-warning line, or the `mount_failed`/`privilege_missing` error text.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/registry/src/registry_plugin.cpp` · shared shell: `agents/shared/win_profiles.hpp` · `agents/shared/win_reg_handle.hpp` · `agents/shared/user_profile_model.hpp` · `agents/shared/win_str.hpp`
- Definitions: `content/definitions/registry.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_a.hpp` (lines 427, 438, 449, 460, 474, 485, 496, 507, 520)
- Tests: `tests/unit/test_registry_local_dispatcher.cpp` (loads the real built plugin via `PluginHandle::load` + `LocalDispatcher`)
- Privilege row: `docs/agent-privilege-model.md` (`registry.get_user_value` / `registry.list_profiles` / `registry.set_value,delete_value,delete_key` rows)
- Changelog: `changelog.d/20260803-registry-list-profiles.added.md` · `changelog.d/20260803-registry-user-hive-fix.fixed.md` · `changelog.d/2771-per-user-hive-honest-reporting.fixed.md` · `changelog.d/2771-per-user-hive-ladder-consolidation.changed.md` · `changelog.d/2771-privilegescope-token-adjust-bug.fixed.md` · `changelog.d/2204-declarations-group-a.added.md`
<!-- END GENERATED -->
