# msi_packages

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Enumerates installed packages and product codes (Windows MSI / macOS pkgutil) |
| **Version** | 1.0.0 |
| **Kind** | Collector · read-only · on-demand (no scheduled gather) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux ⛔ |
| **Actions** | `list` (definition `windows.software.msi.list`) · `product_codes` (definition `windows.software.msi.product_codes`) |
| **Security** | securable `Inventory` · operation Read · risk Low · dispatch ReadOnly · approval gate none |
| **Roles** | execute: endpoint-admin, endpoint-operator · author: content-author |
<!-- END GENERATED -->

## How it works

`list` enumerates installed packages and reports name, version, and install location per package. On Windows it walks `MsiEnumProductsA` and pulls `InstalledProductName`/`VersionString`/`InstallLocation` per product code via `MsiGetProductInfoA`. On macOS it runs `pkgutil --pkgs` to get the receipt ID list, then issues one `pkgutil --pkg-info <id>` call per receipt (bounded at 500 receipts) and derives a display name from the identifier's last dot-segment, since a receipt carries no separate name field. `product_codes` is the lighter sibling: it returns only the identifier and name, so on macOS it skips the per-id `--pkg-info` round trip entirely (the name is derived from the identifier alone).

The macOS legs buffer every row locally and commit only after the whole acquisition completes, because `write_output` only appends — a mid-walk pkgutil failure can never leave a partial mix of real rows and an error line. A degraded run (pkgutil timeout, kill, spawn failure, truncation, or nonzero exit) emits a single `error|...` row and returns rc=1 instead of a partial or empty list read as complete.

This plugin is deliberately narrow: it is the honest MSI/pkgutil view only, never coercing a macOS reverse-domain identifier into a fabricated Windows-shaped GUID, and it does not attempt the broader dpkg/rpm/pacman/Homebrew/registry inventory that `installed_apps` already covers.

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: Inventory.Read]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[msi_packages.execute]
  EX --> WIN[Windows leg<br/>MsiEnumProductsA / MsiGetProductInfoA]
  EX --> MAC[macOS leg<br/>pkgutil via bounded argv runner]
  EX --> LIN[Linux leg<br/>error|platform not supported, rc=1]
  WIN & MAC & LIN --> ROWS[rows + no typed result status] --> RS[(ResponseStore)] --> API[REST /api/responses]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `list` | ✅ supported · rung 1 · `msi_api` | ✅ supported · rung 2 · `pkgutil via bounded argv runner` | ⛔ unsupported · no mechanism bound |
| `product_codes` | ✅ supported · rung 1 · `msi_api` | ✅ supported · rung 2 · `pkgutil via bounded argv runner` | ⛔ unsupported · no mechanism bound |

**Declared limits per leg** (the descriptor's fallback text, verbatim):

No declared per-leg fallback text — every action/OS fallback field is `-` in both the capability matrix and the descriptor (`nullptr`).
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account (LocalSystem today, #1442) | None — `MsiEnumProductsA`/`MsiGetProductInfoA` read the per-machine product registration table; the source requests no elevation. | 2026-09-07 on bare metal as `SYSTEM` | No explicit permission-denied handling in the leg; an empty enumeration falls through to the honest "no packages" sentinel row (`msi\|No MSI packages found\|-\|-\|-` / `product_code\|none\|-`) rather than a typed error. |
| macOS | agent daemon, root by default today (`docs/agent-privilege-model.md` TL;DR; narrowing tracked in #1455) | None — `pkgutil` reads local receipt databases that do not require root. The captured sample below was taken unprivileged. | 2026-09-07 on bare metal, unprivileged (euid 501, alex) | A degraded pkgutil run (timeout, kill, spawn failure, truncation, or nonzero exit) emits one `error\|msi_packages: acquisition degraded (...)` row and rc=1 rather than a partial or empty list read as complete. |
| Linux | n/a | n/a — leg not implemented | 2026-09-06 in a container, euid 0 | Both actions unconditionally return `error\|platform not supported` and rc=1. |

Binaries/subprocesses: the macOS leg execs `/usr/sbin/pkgutil` directly through the bounded argv runner (`probe_tool_path`-resolved, no shell) — one `--pkgs` call plus up to `min(receipt count, 500)` `--pkg-info` calls per `list`, one `--pkgs` call per `product_codes`, each under a 15-second per-call deadline. Windows and Linux legs spawn nothing. No network access on any OS.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
`list` takes no parameters.

`product_codes` takes no parameters.
<!-- END GENERATED -->

### Outputs

Pipe-delimited rows. `list` rows use the literal discriminator `msi`; `product_codes` rows use the literal discriminator `product_code`. Every dynamic macOS field is pipe/newline-escaped before being written, so an identifier, version, or path containing `|` or a newline can never shift columns or inject a row. `-` means the underlying property was empty or absent — it never means the plugin failed to read it (a failed acquisition is instead reported as a single `error|...` row and a nonzero return code, never as a placeholder data row).

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`list` — `msi|product_code|name|version|install_location`**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `product_code` | string | Windows: `{GUID}`; macOS: reverse-domain string | W, M | `{90160000-008C-0000-1000-0000000FF1CE}` · `com.apple.pkg.CLTools_SDK_macOS13` |
| `name` | string | free text, or `-` | W, M | `Office 16 Click-to-Run Extensibility Component` · `CLTools_SDK_macOS13` |
| `version` | string | free text version string, or `-` | W, M | `16.0.19822.20104` · `26.6.0.0.1781586384` |
| `install_location` | string | filesystem path, or `-` | W, M | `C:\Program Files (x86)\NordVPN network TAP\` · `/` |

**`product_codes` — `product_code|product_code|name`**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `product_code` | string | Windows: `{GUID}`; macOS: reverse-domain string | W, M | `{90160000-008C-0000-1000-0000000FF1CE}` · `com.tailscale.ipn.macsys` |
| `name` | string | free text, or `-` | W, M | `Office 16 Click-to-Run Extensibility Component` · `macsys` |
<!-- END GENERATED -->

Two additional macOS-only sentinel rows exist outside the schema above: `msi|__truncated__|<total_seen>|-|-` when a `list` receipt walk exceeds the 500-receipt cap (the tail is dropped, and this row states how many receipts were actually seen), and `msi|No packages found|-|-|-` / `product_code|none|-` when a clean walk finds zero receipts.

### Result status

This plugin does not set a typed result status; the agent records `UNDECLARED` and the sample shows `UNDECLARED / UNKNOWN /`.

### Where the data goes

- **Instruction result only.** Rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore (default 90-day retention), queryable at `/api/responses/{id}`. `list` is additionally aggregatable by `name` with a `count` operation; `product_codes` carries no aggregation.
- **Not consumed by** daily-sync inventory, the TAR warehouse, DEX, or metrics — nothing runs on a schedule, and the only other production references to `msi_packages` are the server's dashboard key-value column-rendering fallback and its MCP workflow-catalog blurb, both cosmetic.
- **Siblings:** `installed_apps.list` / `.query` (the broader dpkg/rpm/pacman/apk/Homebrew/registry software inventory this plugin deliberately does not duplicate).
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("windows.software.msi.list")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash pending

```
== action=list
msi|{90160000-008C-0000-1000-0000000FF1CE}|Office 16 Click-to-Run Extensibility Component|16.0.19822.20104|-
msi|{49727420-70BA-4495-9405-31F8D711CB5A}|Microsoft Visual Studio Setup WMI Provider|3.12.2140.44225|-
msi|{14EDF950-06B9-415F-862C-1D5DEC321AE6}|Microsoft GameInput|3.3.221.0|-
msi|{B8D93870-98D1-4980-AFCA-E26563CDFB79}|Update for x64-based Windows Systems (KB5001716)|8.94.0.0|-
msi|{FED10190-CF54-E72D-7A92-E3F9CA9B7950}|Windows Desktop Extension SDK|10.1.26100.7705|-
msi|{AA11F890-8A6F-D292-8A1D-D70710A87852}|Windows IoT Extension SDK Contracts|10.1.26100.7705|-
msi|{0A1B70B0-DD98-1BCC-6958-D5AD8BBAF2B2}|Windows SDK Desktop Headers arm64|10.1.26100.7705|-
msi|{B7BC83B0-1A94-0290-4309-820859276E72}|Windows App Certification Kit x64|10.1.26100.7705|-
msi|{931A2CF0-2404-45EA-82F5-345735AE6A90}|Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.51.36247|14.51.36247|-
msi|{80F76A51-EAF7-DA8E-C732-B26C591BCC23}|Windows SDK OnecoreUap Headers x64|10.1.26100.7705|-
msi|{1D8E6291-B0D5-35EC-8441-6616F567A0F7}|Microsoft Visual C++ 2010  x64 Redistributable - 10.0.40219|10.0.40219|-
msi|{20C01991-CCD1-2C06-7A9A-B10A9B4AF807}|Windows App Certification Kit Native Components|10.1.26100.7705|-
msi|{ad8a2fa1-06e7-4b0d-927d-6e54b3d31028}|Microsoft Visual C++ 2005 Redistributable (x64)|8.0.61000|-
msi|{8122DAB1-ED4D-3676-BB0A-CA368196543E}|Microsoft Visual C++ 2013 x86 Minimum Runtime - 12.0.40664|12.0.40664|-
msi|{AA86DFC1-17A2-6133-1D55-92818B9D3082}|SDK ARM64 Redistributables|10.1.26100.7705|-
msi|{F0C3E5D1-1ADE-321E-8167-68EF0DE699A5}|Microsoft Visual C++ 2010  x86 Redistributable - 10.0.40219|10.0.40219|-
msi|{B817BAD1-CC9F-940C-FFD8-7543D89B8EB7}|Windows App Certification Kit x64 (OnecoreUAP)|10.1.26100.7705|-
msi|{F9DDDEF1-BCF0-275F-DE29-9332F1149B79}|Windows SDK Signing Tools|10.1.26100.7705|-
msi|{9EE92E02-FA29-DF43-7E45-A256139DEBE4}|Windows SDK Desktop Libs x86|10.1.26100.7705|-
msi|{6C7D0172-7367-4F0C-95DB-6021765B58EA}|vs_filehandler_x86|17.14.36024|-
msi|{E43BDB72-464A-290B-A51D-537CBBE1CAC8}|Windows App Certification Kit SupportedApiList x86|10.1.26100.7705|-
msi|{BC104582-4691-4D4C-8922-C215D941A2EB}|Microsoft Visual C++ 2022 X86 Debug Runtime - 14.44.35211|14.44.35211|-
msi|{13D2A7A2-1B42-4C03-8F0F-697991259AEE}|Windows SDK AddOn|10.1.0.0|-
msi|{CCEEC7A2-2179-C5D0-60E2-2651993A8AD5}|Windows SDK Desktop Headers x64|10.1.26100.7705|-
msi|{368E4D03-5983-1C2C-B42E-1C0C51A935A5}|Universal CRT Redistributable|10.1.26100.7705|-
… 25 of 137 rows
[result_status] UNDECLARED / UNKNOWN / 

== action=product_codes
product_code|{90160000-008C-0000-1000-0000000FF1CE}|Office 16 Click-to-Run Extensibility Component
product_code|{49727420-70BA-4495-9405-31F8D711CB5A}|Microsoft Visual Studio Setup WMI Provider
product_code|{14EDF950-06B9-415F-862C-1D5DEC321AE6}|Microsoft GameInput
product_code|{B8D93870-98D1-4980-AFCA-E26563CDFB79}|Update for x64-based Windows Systems (KB5001716)
product_code|{FED10190-CF54-E72D-7A92-E3F9CA9B7950}|Windows Desktop Extension SDK
product_code|{AA11F890-8A6F-D292-8A1D-D70710A87852}|Windows IoT Extension SDK Contracts
product_code|{0A1B70B0-DD98-1BCC-6958-D5AD8BBAF2B2}|Windows SDK Desktop Headers arm64
product_code|{B7BC83B0-1A94-0290-4309-820859276E72}|Windows App Certification Kit x64
product_code|{931A2CF0-2404-45EA-82F5-345735AE6A90}|Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.51.36247
product_code|{80F76A51-EAF7-DA8E-C732-B26C591BCC23}|Windows SDK OnecoreUap Headers x64
product_code|{1D8E6291-B0D5-35EC-8441-6616F567A0F7}|Microsoft Visual C++ 2010  x64 Redistributable - 10.0.40219
product_code|{20C01991-CCD1-2C06-7A9A-B10A9B4AF807}|Windows App Certification Kit Native Components
product_code|{ad8a2fa1-06e7-4b0d-927d-6e54b3d31028}|Microsoft Visual C++ 2005 Redistributable (x64)
product_code|{8122DAB1-ED4D-3676-BB0A-CA368196543E}|Microsoft Visual C++ 2013 x86 Minimum Runtime - 12.0.40664
product_code|{AA86DFC1-17A2-6133-1D55-92818B9D3082}|SDK ARM64 Redistributables
product_code|{F0C3E5D1-1ADE-321E-8167-68EF0DE699A5}|Microsoft Visual C++ 2010  x86 Redistributable - 10.0.40219
product_code|{B817BAD1-CC9F-940C-FFD8-7543D89B8EB7}|Windows App Certification Kit x64 (OnecoreUAP)
product_code|{F9DDDEF1-BCF0-275F-DE29-9332F1149B79}|Windows SDK Signing Tools
product_code|{9EE92E02-FA29-DF43-7E45-A256139DEBE4}|Windows SDK Desktop Libs x86
product_code|{6C7D0172-7367-4F0C-95DB-6021765B58EA}|vs_filehandler_x86
product_code|{E43BDB72-464A-290B-A51D-537CBBE1CAC8}|Windows App Certification Kit SupportedApiList x86
product_code|{BC104582-4691-4D4C-8922-C215D941A2EB}|Microsoft Visual C++ 2022 X86 Debug Runtime - 14.44.35211
product_code|{13D2A7A2-1B42-4C03-8F0F-697991259AEE}|Windows SDK AddOn
product_code|{CCEEC7A2-2179-C5D0-60E2-2651993A8AD5}|Windows SDK Desktop Headers x64
product_code|{368E4D03-5983-1C2C-B42E-1C0C51A935A5}|Universal CRT Redistributable
… 25 of 137 rows
[result_status] UNDECLARED / UNKNOWN / 
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (alex) · leg-hash pending

```
== action=list
msi|com.apple.pkg.CLTools_SDK_macOS13|CLTools_SDK_macOS13|26.6.0.0.1781586384|/
msi|com.apple.pkg.CLTools_SDK_macOS12|CLTools_SDK_macOS12|26.6.0.0.1781586378|/
msi|com.apple.pkg.MAContent10_AssetPack_0637_AppleLoopsDrummerKyle|MAContent10_AssetPack_0637_AppleLoopsDrummerKyle|3.1.0.0.1.1601920555|/
msi|com.apple.pkg.MAContent10_AssetPack_0593_DrummerSoCalGBLogic|MAContent10_AssetPack_0593_DrummerSoCalGBLogic|2.0.0.0.1.1602002531|/
msi|com.apple.pkg.CLTools_Executables|CLTools_Executables|26.6.0.0.1781586589|/
msi|com.apple.files.data-template|data-template|26.6.2|/
msi|com.apple.pkg.CLTools_SDK_macOS_LMOS|CLTools_SDK_macOS_LMOS|26.6.0.0.1781586411|/
msi|com.apple.pkg.GatekeeperCompatibilityData.16U1906|16U1906|8.0.1.1570042755|/
msi|com.apple.pkg.MobileAssets|MobileAssets|1.0.0.0.1645860813|/
msi|com.apple.pkg.MAContent10_AssetPack_0317_AppleLoopsModernRnB1|MAContent10_AssetPack_0317_AppleLoopsModernRnB1|2.0.0.0.1.1601920555|/
msi|com.apple.pkg.MAContent10_AssetPack_0537_DrummerShaker|MAContent10_AssetPack_0537_DrummerShaker|2.0.0.0.1.1602002531|/
msi|com.apple.pkg.MAContent10_AssetPack_0482_EXS_OrchWoodwindAltoSax|MAContent10_AssetPack_0482_EXS_OrchWoodwindAltoSax|2.0.0.0.1.1602004766|/
msi|com.apple.pkg.CLTools_SDK_macOS14|CLTools_SDK_macOS14|26.6.0.0.1781586377|/
msi|com.apple.pkg.CLTools_SDK_macOS_NMOS|CLTools_SDK_macOS_NMOS|26.6.0.0.1781586415|/
msi|com.apple.pkg.CLTools_SDK_macOS110|CLTools_SDK_macOS110|26.6.0.0.1781586368|/
msi|com.apple.pkg.XProtectPayloads_10_15.16U4413|16U4413|157.1.1770928711|/
msi|com.apple.pkg.MAContent10_AssetPack_0048_AlchemyPadsDigitalHolyGhost|MAContent10_AssetPack_0048_AlchemyPadsDigitalHolyGhost|2.0.0.0.1.1601679620|/
msi|com.apple.pkg.MAContent10_AssetPack_0539_DrummerTambourine|MAContent10_AssetPack_0539_DrummerTambourine|2.0.0.0.1.1602002531|/
msi|com.apple.pkg.MAContent10_AssetPack_0323_AppleLoopsVintageBreaks|MAContent10_AssetPack_0323_AppleLoopsVintageBreaks|2.1.0.0.1.1601920555|/
msi|com.apple.pkg.MAContent10_AssetPack_0487_EXS_OrchWoodwindFluteSolo|MAContent10_AssetPack_0487_EXS_OrchWoodwindFluteSolo|3.0.0.0.1.1602004766|/
msi|com.apple.pkg.MAContent10_AssetPack_0557_IRsSharedAUX|MAContent10_AssetPack_0557_IRsSharedAUX|2.0.0.0.1.1602781381|/
msi|com.apple.pkg.MAContent10_AssetPack_0484_EXS_OrchWoodwindClarinetSolo|MAContent10_AssetPack_0484_EXS_OrchWoodwindClarinetSolo|3.0.0.0.1.1602004766|/
msi|com.apple.pkg.MRTConfigData_10_15.16U4211|16U4211|1.93.1.1657754914|/
msi|com.apple.pkg.MAContent10_AssetPack_0310_UB_DrumMachineDesignerGB|MAContent10_AssetPack_0310_UB_DrumMachineDesignerGB|2.0.0.0.1.1602002531|/
msi|com.apple.pkg.MAContent10_AssetPack_0316_AppleLoopsDubstep1|MAContent10_AssetPack_0316_AppleLoopsDubstep1|2.0.0.0.1.1601920555|/
… 25 of 68 rows
[result_status] UNDECLARED / UNKNOWN / 

== action=product_codes
product_code|com.apple.pkg.CLTools_SDK_macOS13|CLTools_SDK_macOS13
product_code|com.apple.pkg.CLTools_SDK_macOS12|CLTools_SDK_macOS12
product_code|com.apple.pkg.MAContent10_AssetPack_0637_AppleLoopsDrummerKyle|MAContent10_AssetPack_0637_AppleLoopsDrummerKyle
product_code|com.apple.pkg.MAContent10_AssetPack_0593_DrummerSoCalGBLogic|MAContent10_AssetPack_0593_DrummerSoCalGBLogic
product_code|com.apple.pkg.CLTools_Executables|CLTools_Executables
product_code|com.apple.files.data-template|data-template
product_code|com.apple.pkg.CLTools_SDK_macOS_LMOS|CLTools_SDK_macOS_LMOS
product_code|com.apple.pkg.GatekeeperCompatibilityData.16U1906|16U1906
product_code|com.apple.pkg.MobileAssets|MobileAssets
product_code|com.apple.pkg.MAContent10_AssetPack_0317_AppleLoopsModernRnB1|MAContent10_AssetPack_0317_AppleLoopsModernRnB1
product_code|com.apple.pkg.MAContent10_AssetPack_0537_DrummerShaker|MAContent10_AssetPack_0537_DrummerShaker
product_code|com.apple.pkg.MAContent10_AssetPack_0482_EXS_OrchWoodwindAltoSax|MAContent10_AssetPack_0482_EXS_OrchWoodwindAltoSax
product_code|com.apple.pkg.CLTools_SDK_macOS14|CLTools_SDK_macOS14
product_code|com.apple.pkg.CLTools_SDK_macOS_NMOS|CLTools_SDK_macOS_NMOS
product_code|com.apple.pkg.CLTools_SDK_macOS110|CLTools_SDK_macOS110
product_code|com.apple.pkg.XProtectPayloads_10_15.16U4413|16U4413
product_code|com.apple.pkg.MAContent10_AssetPack_0048_AlchemyPadsDigitalHolyGhost|MAContent10_AssetPack_0048_AlchemyPadsDigitalHolyGhost
product_code|com.apple.pkg.MAContent10_AssetPack_0539_DrummerTambourine|MAContent10_AssetPack_0539_DrummerTambourine
product_code|com.apple.pkg.MAContent10_AssetPack_0323_AppleLoopsVintageBreaks|MAContent10_AssetPack_0323_AppleLoopsVintageBreaks
product_code|com.apple.pkg.MAContent10_AssetPack_0487_EXS_OrchWoodwindFluteSolo|MAContent10_AssetPack_0487_EXS_OrchWoodwindFluteSolo
product_code|com.apple.pkg.MAContent10_AssetPack_0557_IRsSharedAUX|MAContent10_AssetPack_0557_IRsSharedAUX
product_code|com.apple.pkg.MAContent10_AssetPack_0484_EXS_OrchWoodwindClarinetSolo|MAContent10_AssetPack_0484_EXS_OrchWoodwindClarinetSolo
product_code|com.apple.pkg.MRTConfigData_10_15.16U4211|16U4211
product_code|com.apple.pkg.MAContent10_AssetPack_0310_UB_DrumMachineDesignerGB|MAContent10_AssetPack_0310_UB_DrumMachineDesignerGB
product_code|com.apple.pkg.MAContent10_AssetPack_0316_AppleLoopsDubstep1|MAContent10_AssetPack_0316_AppleLoopsDubstep1
… 25 of 68 rows
[result_status] UNDECLARED / UNKNOWN / 
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-06 · euid 0 · leg-hash pending

```
== action=list
error|platform not supported
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1

== action=product_codes
error|platform not supported
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **Windows has no typed permission-denied path.** A failed `MsiEnumProductsA` loop looks identical to a genuinely empty product table — both fall through to the "no packages" sentinel row. Only the macOS leg distinguishes a degraded acquisition from a truly empty result.
2. **macOS never reports a partial or empty list as complete.** A killed, timed-out, truncated, or nonzero-exit pkgutil run — checked across the whole walk, including every per-receipt `--pkg-info` call — emits a single `error|msi_packages: acquisition degraded (...)` row and rc=1 instead. Do not reintroduce a per-row emit-as-you-go loop; rows are buffered and committed only after the health verdict is known, because `write_output` cannot retract an already-appended row.
3. **macOS `list` caps at 500 receipts.** A receipt DB with more entries than `kMaxPackages` gets an honest `msi|__truncated__|<total_seen>|-|-` sentinel row rather than a silently incomplete list.
4. **Linux is unimplemented, not merely leg-unsupported.** Both actions unconditionally return `error|platform not supported` and rc=1; no mechanism was bound.
5. **Windows `install_location` is usually empty.** In the captured sample only 4 of 137 packages carry a real path (NordVPN network TAP, NordVPN network TUN, PlayStation Accessories, CMake); MSI's `InstallLocation` property is frequently left unset by the installer — a `-` here reflects the source data, not a plugin gap.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/msi_packages/src/msi_packages_plugin.cpp` (descriptor + both actions) · `msi_packages_macos.hpp` (pure pkgutil parsers)
- Definitions: `content/definitions/msi_packages.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_d.hpp`
- Tests: `tests/unit/test_msi_packages_actions.cpp` (2 cases, real pkgutil via `LocalDispatcher`, macOS-only) · `tests/unit/agent/test_msi_macos.cpp` (12 cases, pure parser fixtures)
- Privilege row: `docs/agent-privilege-model.md`
- Changelog: `changelog.d/2204-declarations-group-d.added.md` · `changelog.d/2243-os-capability-matrix-sections.changed.md` · `changelog.d/2277-macos-parity-contracts.changed.md` · `changelog.d/2277-macos-plugin-parity.added.md` · `changelog.d/wave4-pr43a-installed-apps-msi-argv.changed.md`
<!-- END GENERATED -->
