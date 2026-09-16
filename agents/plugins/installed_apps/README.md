# installed_apps

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Inventories installed applications and queries by name |
| **Version** | 1.1.0 |
| **Kind** | Collector · read-only · gathered (crossplatform.software.inventory, crossplatform.software.query, crossplatform.software.per_user_inventory) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux ✅ |
| **Actions** | `list` (definition `crossplatform.software.inventory`) · `list_inventory` · `list_per_user` (definition `crossplatform.software.per_user_inventory`) · `query` (definition `crossplatform.software.query`) |
| **Security** | `list`: securable `Inventory` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `query`: securable `Inventory` · operation Read · risk Low · dispatch ReadOnly · approval gate None; `list_per_user`: securable `Inventory` · operation Read · risk Low · dispatch ReadOnly · approval gate AdminOrApproval; `list_inventory`: securable `Inventory` · operation Read · risk Low · dispatch ReadOnly · approval gate None |
| **Roles** | execute: `list`: endpoint-admin, endpoint-operator; `query`: endpoint-admin, endpoint-operator; `list_per_user`: endpoint-admin · author: content-author |
<!-- END GENERATED -->

## How it works

`list`/`query` read the OS's native application registry: Windows enumerates the Uninstall keys (64-bit HKLM, WoW64 HKLM, and the agent's own HKCU) natively via `Reg*W`; Linux auto-detects dpkg/rpm/pacman; macOS shells out to `system_profiler SPApplicationsDataType`. `query` never re-acquires — it filters the same collection with a case-insensitive substring match and emits a `found|true`/`found|false` discriminator. `list_per_user` is the real per-user surface: on Windows it walks every local profile's registry hive via the shared `win_profiles.hpp` ladder, mounting `NTUSER.DAT` offline when a profile isn't already loaded; Linux/macOS instead report the same system-wide set tagged `username=system`, and macOS additionally runs `brew list --versions` under the calling account. `list_inventory` is a separate acquisition — the ADR-0016 daily-sync collector — emitting an extended 12-field row where a field an ecosystem doesn't store stays honestly empty (never a `-` placeholder), and on macOS it additionally performs a native, budget-capped CFBundle/SecStaticCode enrichment per app for publisher and signature *presence*. The plugin is read-only throughout: it never installs, removes, or verifies a package's cryptographic validity.

```mermaid
flowchart LR
  OP[Operator / workflow<br/>dispatches definition] --> SRV[Server<br/>authz: Inventory.Read]
  SRV -- gRPC mTLS --> HOST[Agent plugin host]
  HOST --> EX[installed_apps.execute]
  EX --> WIN[Windows leg<br/>Reg*W Uninstall key enumeration]
  EX --> MAC[macOS leg<br/>system_profiler + pkgutil + native CFBundle/SecStaticCode]
  EX --> LIN[Linux leg<br/>dpkg-query / rpm / pacman / apk]
  WIN & MAC & LIN --> ROWS[rows + typed result status] --> RS[(ResponseStore)] --> API[REST /api/responses]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `list` | ✅ supported · rung 1 · Reg*W enumeration of the Uninstall key(s) | ✅ supported · rung 2 · system_profiler via bounded argv runner | ✅ supported · rung 2 · dpkg-query/rpm/pacman via bounded argv runner |
| `list_inventory` | ✅ supported · rung 1 · Reg*W enumeration of the Uninstall key(s) | ✅ supported · rung 2 · system_profiler + pkgutil via bounded argv runner + native SecCode/CFBundle enrichment | ✅ supported · rung 2 · dpkg-query/rpm/pacman/apk via bounded argv runner |
| `list_per_user` | ✅ supported · rung 1 · Reg*W enumeration of HKU\\<SID>'s Uninstall key, mounting NTUSER.DAT via RegLoadKeyW when not already loaded | ✅ supported · rung 2 · system_profiler + brew via bounded argv runner | ✅ supported · rung 2 · dpkg-query/rpm/pacman via bounded argv runner |
| `query` | ✅ supported · rung 1 · Reg*W enumeration of the Uninstall key(s) | ✅ supported · rung 2 · system_profiler via bounded argv runner | ✅ supported · rung 2 · dpkg-query/rpm/pacman via bounded argv runner |
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account — LocalSystem today, not the intended virtual service account (`docs/agent-privilege-model.md` Correction, #1442) | **None** for `list`/`query`/`list_inventory` — `Reg*W` reads only. `list_per_user`'s offline `NTUSER.DAT` mount fallback rides `SeBackupPrivilege` + `SeRestorePrivilege`, already held by the agent account (`docs/agent-privilege-model.md:87`) — no new privilege is introduced. | 2026-09-07, bare-metal, as `SYSTEM` (`windows.txt:1`) | `warning\|privilege_missing: SeBackupPrivilege/SeRestorePrivilege could not be enabled for N logged-out profile(s); their per-user apps are not listed` (`installed_apps_plugin.cpp:1123-1128`); machine-scope actions still report |
| macOS | agent daemon — root today (LaunchDaemon carries no `UserName` key; not yet narrowed to the unprivileged `_yuzu` account, #1455) | **None** — `docs/agent-privilege-model.md:86` lists `list`/`query`/`list_inventory` as `default`; no keychain/TCC/Location Services grant is touched | 2026-09-07, bare-metal, euid 501 (`alex`) (`macos.txt:1`) — captured unprivileged, not the daemon's real root identity | n/a — no privilege is required; a Security framework absent at build time silently no-ops the `#2273` enrichment (empty `publisher`/`signature_status`) rather than refusing (`meson.build:15-23`) |
| Linux | agent daemon, intended dedicated unprivileged account (`_yuzu`/`yuzu`) | **None** — `docs/agent-privilege-model.md:86` lists all four actions as `default`; the dpkg/rpm/pacman/apk databases are world-readable | 2026-09-06, container, euid 0 (`linux.txt:1`) — captured as root, not the intended unprivileged account | n/a — no privilege is required; a missing package-manager binary falls through the ladder and `probe_tool_path` returns empty, yielding an empty (not degraded) collection (`installed_apps_plugin.cpp:400-446`) |

Binaries/subprocesses: Linux — `dpkg-query`, `rpm`, `pacman`, `apk` (`list_inventory` only), probed by fixed absolute path (`installed_apps_plugin.cpp:404-441`, `:532-574`) and exec'd directly via `yuzu::agent::run_bounded_subprocess` (no shell, ADR-3002 rung 2). macOS — `system_profiler`, `pkgutil`, `brew` (`list_per_user` only), same bounded runner. Windows — no subprocess; native `Reg*W` calls only. No network access on any OS.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
| Definition | Parameter | Type | Required | Default | Constraints | Description |
|---|---|---|---|---|---|---|
| `crossplatform.software.query` | `name` | string | yes | - | minLength 1 · maxLength 256 | Case-insensitive substring to match against installed application names. All apps whose name contains this string are returned. |
<!-- END GENERATED -->

### Outputs

Pipe-delimited rows, one per application, written via `write_output()`. `list`/`query`/`list_per_user` emit the stable `app`/`app`/`user_app`-tagged wire format `content/definitions/installed_apps.yaml` documents; `-` marks a field the OS reported empty. `list_inventory` emits a separate, extended `inv`-tagged 12-field row (blob contract v2, ADR-0016) where a field an ecosystem does not store stays *honestly empty* — never a `-` placeholder (`installed_apps_inventory.hpp:6-11`).

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`crossplatform.software.inventory` — `name|version|publisher|install_date`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `name` | string | - | Windows, Linux, macOS | `7-Zip 26.02 (x64)` | The application's display name as read from the OS-native registry or package database. Values: free text. |
| `version` | string | - | Windows, Linux, macOS | `26.02` | The installed version string, or "-" when the source reports none. Values: free text or "-". |
| `publisher` | string | - | Windows, Linux | `Igor Pavlov` | The vendor or maintainer name; always "-" on macOS, since system_profiler's mini detail carries no publisher field. Values: free text or "-". |
| `install_date` | string | - | Windows, macOS | `20260617` | Install date in the OS's native format (Windows registry InstallDate, rpm's formatted install time); "-" when the source reports none, which dpkg-based Linux hosts always do. Values: free text or "-". |

**`crossplatform.software.per_user_inventory` — `username|name|version|publisher|install_date`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `username` | string | - | Windows, Linux, macOS | `Alex` | The resolved local profile name on Windows (never the SID), the literal "system" for the machine-scope Linux/macOS leg, or "brew" for macOS per-user Homebrew formulae. Values: profile name, "system", "brew", or "-". |
| `name` | string | - | Windows, Linux, macOS | `Signal 8.18.0` | The application's display name. Values: free text. |
| `version` | string | - | Windows, Linux, macOS | `8.18.0` | The installed version string, or "-" when the source reports none. Values: free text or "-". |
| `publisher` | string | - | Windows, Linux | `Signal Messenger, LLC` | The vendor or maintainer name; always "-" on macOS and for Homebrew rows. Values: free text or "-". |
| `install_date` | string | - | Windows, macOS | `20260714` | Install date in the OS's native format; "-" when the source reports none, which dpkg-based Linux hosts and Homebrew rows always do. Values: free text or "-". |

**`crossplatform.software.query` — `found|name|version|publisher`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `found` | bool | - | Windows, Linux, macOS | `true` | Whether at least one installed application matched the search string. Values: true, false. |
| `name` | string | - | Windows, Linux, macOS | `Microsoft Edge` | The matching application's display name. Values: free text. |
| `version` | string | - | Windows, Linux, macOS | `152.0.4191.66` | The matching application's installed version string, or "-" when the source reports none. Values: free text or "-". |
| `publisher` | string | - | Windows, Linux | `Microsoft Corporation` | The vendor or maintainer name; always "-" on macOS, since system_profiler's mini detail carries no publisher field. Values: free text or "-". |
<!-- END GENERATED -->

**Empty-result convention.** `list_inventory` drops a row outright if `name` is empty (`installed_apps_plugin.cpp:845-847`); there is no sentinel row, so an empty collection is empty output at rc 0. A *degraded* collection instead returns rc 1 (`installed_apps_plugin.cpp:834-841`) and the daily sync skips the whole cycle rather than committing a partial inventory as authoritative.

### Result status

This plugin does not set a typed result status; the agent records `UNDECLARED` and the sample shows `UNDECLARED / UNKNOWN /` for every action (verified: no `set_result_status`/`yuzu_ctx_set_result_status` call exists anywhere in `installed_apps_plugin.cpp`).

### Where the data goes

- **Instruction result.** `list`/`query`/`list_per_user` rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore (operator-configurable retention, 90-day default — `server.hpp:222`), queryable at `/api/responses/{id}`.
- **Daily-sync typed store.** `list_inventory` is never dispatched through `execute_instruction` — it has no definition. The agent's own `SyncSource` (`make_installed_software_source`, `sync_source_installed_software.cpp:181-199`) runs it every 24 hours, canonicalizes the parsed rows into a hash-skip blob, and pushes it to the server's typed `SoftwareInventoryStore` (ADR-0016), served fleet-wide at `GET /api/v1/inventory/software` (`rest_api_v1.cpp:6800`), gated on `Inventory:Read`.
- **Not consumed by** TAR, DEX, or metrics — no reference to `installed_apps`/`crossplatform.software.*` was found in the TAR or DEX collector sources.
- **Sensitivity.** `list_per_user`/`list_inventory` rows carry per-account software names/versions/publishers, and `list_per_user`'s `username` field is a resolved local account name (not a raw SID) — a per-person installed-software inventory; `list`/`query`/`list_inventory` alone already name specific installed software (`name`/`version`/`publisher`) even at machine scope.
- **Siblings:** `msi_packages.*` (Windows-only MSI package detail) and `license_scan.list` (software-licence/entitlement detection) — grouped alongside `installed_apps` in the privilege matrix's read-only row (`docs/agent-privilege-model.md:86`).
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("crossplatform.software.inventory")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}` for `list`/`query`/`list_per_user`; `list_inventory`'s daily-sync output instead lands at `GET /api/v1/inventory/software`, since it carries no definition and is never dispatched through `execute_instruction`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash 47e1dd9008d0

```
== action=list
app|7-Zip 26.02 (x64)|26.02|Igor Pavlov|-
app|Age of Empires II: Definitive Edition|-|Forgotten Empires|-
app|Application Verifier x64 External Package (DesktopEditions)|10.1.26100.7705|Microsoft|20260617
app|Application Verifier x64 External Package (OnecoreUAP)|10.1.26100.7705|Microsoft|20260617
app|Baldur's Gate 3|-|Larian Studios|-
app|Battle.net|-|Blizzard Entertainment|-
app|CCleaner 7|7.10.1464.1889|Piriform|-
app|CMake|4.3.3|Kitware|20260617
app|Cities: Skylines II|-|Colossal Order Ltd.|-
app|Crusader Kings III|-|Paradox Development Studio|-
app|DayZ|-|Bohemia Interactive|-
app|Defraggler|2.22|Piriform|-
… 12 of 226 rows shown
[result_status] UNDECLARED / UNKNOWN

== action=query name=Microsoft
found|true
app|Microsoft .NET Host - 6.0.11 (x64)|48.47.50420|Microsoft Corporation
app|Microsoft .NET Host - 6.0.20 (x86)|48.83.63169|Microsoft Corporation
app|Microsoft .NET Host - 8.0.28 (x64)|64.112.53549|Microsoft Corporation
app|Microsoft .NET Host - 8.0.28 (x86)|64.112.53549|Microsoft Corporation
app|Microsoft .NET Host FX Resolver - 6.0.11 (x64)|48.47.50420|Microsoft Corporation
app|Microsoft .NET Host FX Resolver - 6.0.20 (x86)|48.83.63169|Microsoft Corporation
app|Microsoft .NET Host FX Resolver - 8.0.28 (x64)|64.112.53549|Microsoft Corporation
app|Microsoft .NET Host FX Resolver - 8.0.28 (x86)|64.112.53549|Microsoft Corporation
app|Microsoft .NET Runtime - 6.0.11 (x64)|48.47.50420|Microsoft Corporation
app|Microsoft .NET Runtime - 6.0.20 (x86)|48.83.63169|Microsoft Corporation
app|Microsoft .NET Runtime - 8.0.28 (x64)|64.112.53549|Microsoft Corporation
… 12 of 57 rows shown
[result_status] UNDECLARED / UNKNOWN

== action=list_per_user
user_app|Alex|Signal 8.18.0|8.18.0|Signal Messenger, LLC|-
user_app|Alex|Discord|1.0.9255|Discord Inc.|20212118
user_app|Alex|NordPass|7.9.5|NordPass Team|-
user_app|Alex|Inno Setup version 6.7.3|6.7.3|jrsoftware.org|20260714
user_app|Alex|ninja|1.13.2|ninja-build|20260617
user_app|Alex|Node.js (LTS)|24.16.0|Node.js Foundation|20260617
user_app|Alex|Microsoft Visual Studio Code (User)|1.128.1|Microsoft Corporation|20260715
user_app|Alex|Python 3.12.10 (64-bit)|3.12.10150.0|Python Software Foundation|-
user_app|Alex|MSYS2|20260611|The MSYS2 Developers|Wed Jun 17 17:28:18 2026
user_app|Alex|Paradox Launcher v2|1.0.0.0|Paradox Interactive|-
[result_status] UNDECLARED / UNKNOWN

== action=list_inventory
inv|7-Zip 26.02 (x64)|26.02|Igor Pavlov||app|windows||||||
inv|Age of Empires II: Definitive Edition||Forgotten Empires||app|windows||||||
inv|Application Verifier x64 External Package (DesktopEditions)|10.1.26100.7705|Microsoft|20260617|app|windows||||||
inv|Application Verifier x64 External Package (OnecoreUAP)|10.1.26100.7705|Microsoft|20260617|app|windows||||||
inv|Baldur's Gate 3||Larian Studios||app|windows||||||
inv|Battle.net||Blizzard Entertainment||app|windows||||||
inv|CCleaner 7|7.10.1464.1889|Piriform||app|windows||||||
inv|CMake|4.3.3|Kitware|20260617|app|windows||||||
inv|Cities: Skylines II||Colossal Order Ltd.||app|windows||||||
inv|Crusader Kings III||Paradox Development Studio||app|windows||||||
inv|DayZ||Bohemia Interactive||app|windows||||||
inv|Defraggler|2.22|Piriform||app|windows||||||
… 12 of 226 rows shown
[result_status] UNDECLARED / UNKNOWN
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (jsmith) · leg-hash 47e1dd9008d0

```
== action=list
app|50onPaletteServer|1.1.0|-|13/08/2026, 03:51
app|ABAssistantService|14.0|-|13/08/2026, 03:51
app|AMSEngagementViewService|1.0|-|13/08/2026, 03:51
app|AOSAlertManager|1.07|-|13/08/2026, 03:51
app|AOSHeartbeat|1.07|-|13/08/2026, 03:51
app|AOSPushRelay|1.07|-|13/08/2026, 03:51
app|AOSUIPrefPaneLauncher|1.0|-|13/08/2026, 03:51
app|ARDAgent|3.9.8|-|13/08/2026, 03:51
app|AVB Configuration|1440.7|-|13/08/2026, 03:51
app|AXVisualSupportAgent|1.0|-|13/08/2026, 03:51
app|About This Mac|1.0|-|13/08/2026, 03:51
app|Accessibility Reader|1.0|-|13/08/2026, 03:51
… 12 of 322 rows shown
[result_status] UNDECLARED / UNKNOWN

== action=query name=bash
found|false
[result_status] UNDECLARED / UNKNOWN

== action=list_per_user
user_app|system|50onPaletteServer|1.1.0|-|13/08/2026, 03:51
user_app|system|ABAssistantService|14.0|-|13/08/2026, 03:51
user_app|system|AMSEngagementViewService|1.0|-|13/08/2026, 03:51
user_app|system|AOSAlertManager|1.07|-|13/08/2026, 03:51
user_app|system|AOSHeartbeat|1.07|-|13/08/2026, 03:51
user_app|system|AOSPushRelay|1.07|-|13/08/2026, 03:51
user_app|system|AOSUIPrefPaneLauncher|1.0|-|13/08/2026, 03:51
user_app|system|ARDAgent|3.9.8|-|13/08/2026, 03:51
user_app|system|AVB Configuration|1440.7|-|13/08/2026, 03:51
user_app|system|AXVisualSupportAgent|1.0|-|13/08/2026, 03:51
user_app|system|About This Mac|1.0|-|13/08/2026, 03:51
user_app|system|Accessibility Reader|1.0|-|13/08/2026, 03:51
… 12 of 323 rows shown
[result_status] UNDECLARED / UNKNOWN
[rc] 1

== action=list_inventory
inv|App Store|3.0|macOS Software Signing|13/08/2026, 03:51|app|macos||||signed||
inv|Apps|1.0|macOS Software Signing|13/08/2026, 03:51|app|macos||||signed||
inv|Automator|2.10|macOS Software Signing|13/08/2026, 03:51|app|macos||||signed||
inv|Books|8.5|macOS Software Signing|13/08/2026, 03:51|app|macos||||signed||
inv|Calculator|12.0|macOS Software Signing|13/08/2026, 03:51|app|macos||||signed||
inv|Calendar|16.0|macOS Software Signing|13/08/2026, 03:51|app|macos||||signed||
inv|Chess|3.18|macOS Software Signing|13/08/2026, 03:51|app|macos||||signed||
inv|Clock|1.1|macOS Software Signing|13/08/2026, 03:51|app|macos||||signed||
inv|Contacts|14.0|macOS Software Signing|13/08/2026, 03:51|app|macos||||signed||
inv|Dictionary|2.3.0|macOS Software Signing|13/08/2026, 03:51|app|macos||||signed||
inv|FaceTime|36|macOS Software Signing|13/08/2026, 03:51|app|macos||||signed||
inv|Find My|4.0|macOS Software Signing|13/08/2026, 03:51|app|macos||||signed||
… 12 of 390 rows shown
[result_status] UNDECLARED / UNKNOWN
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-06 · euid 0 · leg-hash 47e1dd9008d0

```
== action=list
app|apt|3.0.3|APT Development Team <deity@lists.debian.org>|-
app|autoconf|2.72-3.1|Alex Myczko <tar@debian.org>|-
app|automake|1:1.17-4|Eric Dorland <eric@debian.org>|-
app|autotools-dev|20240727.1|Henrique de Moraes Holschuh <hmh@debian.org>|-
app|base-files|13.8+deb13u6|Santiago Vila <sanvila@debian.org>|-
app|base-passwd|3.6.7|Shadow package maintainers <pkg-shadow-devel@lists.alioth.debian.org>|-
app|bash|5.2.37-2+b9|Matthias Klose <doko@debian.org>|-
app|binutils|2.44-3|Matthias Klose <doko@debian.org>|-
app|binutils-aarch64-linux-gnu|2.44-3|Matthias Klose <doko@debian.org>|-
app|binutils-common|2.44-3|Matthias Klose <doko@debian.org>|-
app|bison|2:3.8.2+dfsg-1+b2|Chuan-kai Lin <cklin@debian.org>|-
app|bsdutils|1:2.41.5-0+deb13u1|Chris Hofstaedtler <zeha@debian.org>|-
… 12 of 206 rows shown
[result_status] UNDECLARED / UNKNOWN

== action=query name=bash
found|true
app|bash|5.2.37-2+b9|Matthias Klose <doko@debian.org>
[result_status] UNDECLARED / UNKNOWN

== action=list_per_user
user_app|system|apt|3.0.3|APT Development Team <deity@lists.debian.org>|-
user_app|system|autoconf|2.72-3.1|Alex Myczko <tar@debian.org>|-
user_app|system|automake|1:1.17-4|Eric Dorland <eric@debian.org>|-
user_app|system|autotools-dev|20240727.1|Henrique de Moraes Holschuh <hmh@debian.org>|-
user_app|system|base-files|13.8+deb13u6|Santiago Vila <sanvila@debian.org>|-
user_app|system|base-passwd|3.6.7|Shadow package maintainers <pkg-shadow-devel@lists.alioth.debian.org>|-
user_app|system|bash|5.2.37-2+b9|Matthias Klose <doko@debian.org>|-
user_app|system|binutils|2.44-3|Matthias Klose <doko@debian.org>|-
user_app|system|binutils-aarch64-linux-gnu|2.44-3|Matthias Klose <doko@debian.org>|-
user_app|system|binutils-common|2.44-3|Matthias Klose <doko@debian.org>|-
user_app|system|bison|2:3.8.2+dfsg-1+b2|Chuan-kai Lin <cklin@debian.org>|-
user_app|system|bsdutils|1:2.41.5-0+deb13u1|Chris Hofstaedtler <zeha@debian.org>|-
… 12 of 206 rows shown
[result_status] UNDECLARED / UNKNOWN

== action=list_inventory
inv|apt|3.0.3|APT Development Team <deity@lists.debian.org>||package|deb|||arm64||debian|13
inv|autoconf|2.72|Alex Myczko <tar@debian.org>||package|deb||3.1|all||debian|13
inv|automake|1.17|Eric Dorland <eric@debian.org>||package|deb|1|4|all||debian|13
inv|autotools-dev|20240727.1|Henrique de Moraes Holschuh <hmh@debian.org>||package|deb|||all||debian|13
inv|base-files|13.8+deb13u6|Santiago Vila <sanvila@debian.org>||package|deb|||arm64||debian|13
inv|base-passwd|3.6.7|Shadow package maintainers <pkg-shadow-devel@lists.alioth.debian.org>||package|deb|||arm64||debian|13
inv|bash|5.2.37|Matthias Klose <doko@debian.org>||package|deb||2+b9|arm64||debian|13
inv|binutils|2.44|Matthias Klose <doko@debian.org>||package|deb||3|arm64||debian|13
inv|binutils-aarch64-linux-gnu|2.44|Matthias Klose <doko@debian.org>||package|deb||3|arm64||debian|13
inv|binutils-common|2.44|Matthias Klose <doko@debian.org>||package|deb||3|arm64||debian|13
inv|bison|3.8.2+dfsg|Chuan-kai Lin <cklin@debian.org>||package|deb|2|1+b2|arm64||debian|13
inv|bsdutils|2.41.5|Chris Hofstaedtler <zeha@debian.org>||package|deb|1|0+deb13u1|arm64||debian|13
… 12 of 206 rows shown
[result_status] UNDECLARED / UNKNOWN
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **Windows `list`/`query` machine scope is invisible to a partial failure.** `enumerate_uninstall_key` returns silently if `RegOpenKeyExW` fails and stops at the first non-`ERROR_SUCCESS` from `RegEnumKeyExW` (`installed_apps_plugin.cpp:312-330`); a partial registry walk still reports success today. `do_list_inventory`'s own comment (`installed_apps_plugin.cpp:817-824`) flags this as pre-existing and needing its own change to close, not something this plugin currently detects.
2. **macOS `signature_status` is presence, not validity.** The `#2273` enrichment calls `SecCodeCopySigningInformation` only, never `SecStaticCodeCheckValidity` — a bundle with `Contents/_CodeSignature` deleted, or with bytes appended to its Mach-O, both still read `signed` (`installed_apps_macos_enrich.hpp:13-30`). Deep verification was deliberately left an open decision, not shipped.
3. **`list`/`query`/`list_per_user` degrade loudly only on Linux/macOS.** A subprocess that is killed, times out, is truncated, or exits nonzero (outside the tolerated per-ID `pkgutil` lookup) makes these three emit `error|installed_apps: acquisition degraded (...)` and return rc 1 rather than a false-empty/partial list (`installed_apps_plugin.cpp:857-870`). The Windows registry path has no equivalent signal — see caveat 1.
4. **`query`'s row omits `install_date`.** `do_query` emits `app|name|version|publisher` (`installed_apps_plugin.cpp:938-940`), one field short of `list`'s `app|name|version|publisher|install_date` (`installed_apps_plugin.cpp:899-902`) — intentional per the YAML contract (`installed_apps.yaml:119-128`), not a truncation bug.
5. **The `list_inventory`/`list_per_user` samples were captured under the wrong identity on two of three OSes, and the macOS `list_per_user` `[rc] 1` traces to that.** macOS ran unprivileged (`euid 501`) and Linux ran as root inside a container (`euid 0`); neither matches the agent's actual production identity (root today on macOS, the intended `_yuzu` account on Linux) — see *Privileges and prerequisites*. On macOS, `do_list_per_user` first lists system apps via `system_profiler` (succeeds), then probes for Homebrew and, if found, runs `brew list --versions` (`installed_apps_plugin.cpp:1162-1165`); under the euid-501 capture identity that `brew` invocation exits nonzero, `run_tool` marks it `degraded` on any nonzero exit (`installed_apps_plugin.cpp:186-188`), and `report_if_degraded` then emits the `error|...` row and returns rc 1 (`installed_apps_plugin.cpp:857-870`, called at `:1166-1167`) — the traced cause of the sample's `[rc] 1`, not an unrelated fault.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/installed_apps/src/installed_apps_inventory.hpp` · `agents/plugins/installed_apps/src/installed_apps_macos_enrich.hpp` · `agents/plugins/installed_apps/src/installed_apps_parsers.hpp` · `agents/plugins/installed_apps/src/installed_apps_plugin.cpp` · `agents/plugins/installed_apps/src/installed_apps_registry_utf8.hpp`
- Definitions: `content/definitions/installed_apps.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_b.hpp`
- Tests: `tests/unit/test_installed_apps_actions.cpp` · `tests/unit/test_installed_apps_inventory.cpp` · `tests/unit/test_installed_apps_macos_enrich.cpp` · `tests/unit/test_installed_apps_parsers.cpp` · `tests/unit/test_installed_apps_registry_utf8.cpp`
- Privilege row: `docs/agent-privilege-model.md`
<!-- END GENERATED -->
