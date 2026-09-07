# wifi

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Scans visible WiFi networks and reports current connection status |
| **Version** | 1.1.0 |
| **Kind** | Collector · read-only · on-demand (no scheduled gather) |
| **Platforms** | Windows ✅ · macOS 🟡 constrained · Linux 🟡 constrained |
| **Actions** | `list_networks` (definition `device.wifi.list_networks`) · `connected` (definition `device.wifi.connected`) |
| **Security** | securable `Infrastructure` · operation Read · risk Low · dispatch ReadOnly · approval gate none |
| **Roles** | execute: endpoint-admin, endpoint-operator · author: content-author |
<!-- END GENERATED -->

## How it works

`list_networks` scans for visible access points, one row per AP (SSID, signal, security, channel, BSSID/type). Windows walks every WLAN interface via `WlanEnumInterfaces` + `WlanGetAvailableNetworkList` (wifi_plugin.cpp:666-715). Linux first reads NetworkManager's cached `AccessPoints` over D-Bus — a read only, not a scan trigger; it requires a device to report a finished `LastScan` before trusting the cache — then falls to `nmcli device wifi list` (which does scan), then a per-interface `iwlist <iface> scan` bounded by a 45s aggregate ladder budget across the whole action (wifi_plugin.cpp:87-105, 716-869). macOS runs the legacy `airport -s` (removed in macOS 14+) and then `system_profiler SPAirPortDataType`, both via the bounded argv runner and both needing a Location Services grant a background daemon typically lacks (wifi_plugin.cpp:870-937).

`connected` reports the single currently-associated network. Windows walks every connected-state interface via `WlanQueryInterface`; Linux checks NetworkManager's `ActiveAccessPoint` over D-Bus, then nmcli's `ACTIVE` row, then an `iwconfig` ESSID/Signal text blob; macOS reads CoreWLAN directly — native, no shell-out (wifi_corewlan.mm:69-118).

Every subprocess leg is gated on `wifi_tool_answered()`: a tool only counts as having answered the question if it exited zero, so a spawn failure or nonzero exit is never reported as a fabricated "Not connected" or an empty scan (wifi_parsers.hpp:695-721). No leg anywhere invokes a shell or interpreter — every subprocess call is direct argv (wifi_plugin.cpp:16-24, wifi_parsers.hpp:630-637). It deliberately does not distinguish WEP from Open on the Linux D-Bus leg (the AP's PRIVACY bit is never read, wifi_parsers.hpp:592-595), and it does not itself trigger a NetworkManager scan on the D-Bus rung — it consumes whatever cache already exists.

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: Infrastructure.Read]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[wifi.execute]
  EX --> WIN[Windows leg<br/>WlanGetAvailableNetworkList / WlanQueryInterface]
  EX --> MAC[macOS leg<br/>airport / system_profiler (list_networks)<br/>CoreWLAN (connected)]
  EX --> LIN[Linux leg<br/>NetworkManager D-Bus → nmcli → iw/iwlist/iwconfig]
  WIN & MAC & LIN --> ROWS[rows + typed result status]
  ROWS --> RS[(ResponseStore)] --> API[REST /api/responses · MCP]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `list_networks` | ✅ supported · rung 1 · `WlanGetAvailableNetworkList` | 🟡 constrained · rung 2 · `airport -s` / `system_profiler` via argv runner | 🟡 constrained · rung 1 · NetworkManager D-Bus (sd-bus) |
| `connected` | ✅ supported · rung 1 · `WlanQueryInterface` | 🟡 constrained · rung 1 · CoreWLAN | 🟡 constrained · rung 1 · NetworkManager D-Bus (sd-bus) |

**Declared limits per leg** (the descriptor's fallback text, verbatim):

- **`list_networks` / Linux** — reads NetworkManager's cached AccessPoints and does not itself initiate a scan (falls through to nmcli, which rescans, when NM reports no finished scan); then falls back to nmcli via the argv runner (rung 2), then an iw/iwlist text dump. Not yet exercised against a real Wi-Fi radio
- **`list_networks` / macOS** — airport was removed in macOS 14 (Sonoma); the system_profiler SPAirPortDataType fallback needs Location Services authorisation a background daemon may lack, so an unauthorised modern host yields no networks and an honest wifi|info sentinel
- **`connected` / Linux** — reports the device interface (e.g. wlan0) in the connection column rather than the NetworkManager profile name; falls back to nmcli via the argv runner (rung 2), then an iwconfig ESSID/Signal blob. Not yet exercised against a real Wi-Fi radio
- **`connected` / macOS** — Location Services (macOS 14+) may withhold SSID/BSSID from a background daemon
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account (LocalSystem today, #1442) | None — `WlanGetAvailableNetworkList`/`WlanQueryInterface` need no elevation (docs/agent-privilege-model.md row 96) | 2026-09-07 on bare-metal as SYSTEM (windows.txt capture stamp) | A WLAN API failure (not privilege-specific) reports `UNAVAILABLE`/`PARTIAL` with a named provenance rather than a false "Not connected" (wifi_plugin.cpp:956-971, 1023-1027) |
| macOS | agent LaunchDaemon, root by default (no `UserName` key — docs/agent-privilege-model.md "macOS is the current exception"); this plugin itself needs no elevation | None for `connected` (CoreWLAN reads are unprivileged); `list_networks`' `system_profiler` fallback needs a Location Services grant a background daemon cannot obtain (docs/agent-privilege-model.md row 96) | 2026-09-07 on bare-metal at **euid 501 (alex)** — unprivileged, not the production root LaunchDaemon identity (macos.txt capture stamp) | `list_networks`: `CONSTRAINED`/`PARTIAL`/`wifi:macos_scan_requires_location_services`, sentinel `wifi\|info\|...` (wifi_plugin.cpp:931-936). `connected`: SSID/BSSID silently become `<ssid-withheld>` on an otherwise-live connection, never a false "Not connected" (wifi_corewlan.hpp:14-22) |
| Linux | agent unprivileged account (`yuzu`, docs/agent-privilege-model.md "TL;DR") | None for the D-Bus read or the `nmcli` argv fallback; the tertiary `iwlist <iface> scan` needs root for an active scan, which the agent does not hold and does not request (docs/agent-privilege-model.md row 96) | 2026-09-06 in a container as **euid 0 (root)** (linux.txt capture stamp) | Under the least-privilege agent, `iwlist` returns nothing and the plugin reports the scan as failed (`wifi\|error\|Wi-Fi scan failed on every discovered interface...`, `UNAVAILABLE`/`PARTIAL`/`wifi:iwlist_scan_failed`, wifi_plugin.cpp:833-839) rather than an empty airspace |

Binaries/subprocesses/network: Linux spawns `nmcli`, `iw`, `iwlist`, `iwconfig` via the bounded argv runner (20s per call, 45s aggregate ladder budget, wifi_plugin.cpp:84-97) and opens a D-Bus session-bus connection to NetworkManager (IPC, not a subprocess). macOS spawns `airport` (legacy, absent on macOS 14+) and `system_profiler` via the same bounded runner. Windows spawns nothing — it links `wlanapi.dll` directly (meson.build:8). No leg on any OS makes a network call of its own; the D-Bus and WLAN API calls are all local IPC to the host's own network stack.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
`list_networks` takes no parameters.

`connected` takes no parameters.
<!-- END GENERATED -->

### Outputs

Pipe-delimited rows. `list_networks` emits zero or more `wifi|...` rows per scan, or a single `wifi|info|...` / `wifi|error|...` / `wifi|scan_output|...` sentinel row when the scan could not enumerate real access points; `connected` emits exactly one `connected|...` row. Every free-text field (SSID, security, BSSID, raw scan blobs) is escaped through `safe_output_field` at the single emission site in `wifi_plugin.cpp`, because `wifi` is not a key|value plugin server-side and an unescaped `|`/`\n` in an attacker-controlled SSID would shift columns or fabricate a row (wifi_plugin.cpp:75-79, wifi_corewlan.hpp:58-65). The fourth and fifth columns of `list_networks` are OVERLOADED across platforms (see the table below), and its `wifi|scan_output|<blob>` fallback — the raw `iwlist` text after ESSID/Quality/Encryption filtering — does not populate the declared columns at all; it is one opaque field (wifi_plugin.cpp:824-828).

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`list_networks` — `wifi|ssid|signal|security|channel_or_type|bssid_or_connected`**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `ssid` | string | network name; `<hidden>` (empty SSID); `<hex:...>` (Linux D-Bus non-UTF-8 SSID, wifi_parsers.hpp:544-563); `info`/`error`/`scan_output` sentinel discriminator | W, M, L | `info` |
| `signal` | string | 0-100 quality/percent (Windows/Linux); RSSI in dBm (macOS); free-text message on a sentinel row | W, M, L | `wi-fi scan unavailable; airport removed in macOS 14+ and system_profiler requires Location Services` |
| `security` | string | free text, e.g. `Open` `WEP` `WPA2-Personal` `WPA3` `802.1X` `OWE` (wifi_parsers.hpp:596-622); `0` on a sentinel row | W, M, L | `0` |
| `channel_or_type` | string | Linux/macOS: 802.11 channel, `0` unknown; Windows: BSS type `Infrastructure`/`Ad-hoc`/`Unknown` — NOT a channel (wifi_plugin.cpp:702-704) | W, M, L | `0` |
| `bssid_or_connected` | string | Linux/macOS: AP MAC address, `-` unknown; Windows: literal `true`/`false` for "is this the connected network" — NOT a BSSID (wifi_plugin.cpp:705,708) | W, M, L | `none` |

**`connected` — `connected|ssid|signal|security|bssid|interface_or_channel`**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `ssid` | string | connected SSID; `none`/`unknown` sentinel when disconnected/undetermined; `<ssid-withheld>` on macOS when Location Services blocks the read on an otherwise-live association (wifi_corewlan.hpp:60-66); `<hex:...>` on the Linux D-Bus leg | W, M, L | `none` |
| `signal` | string | same per-OS units as `list_networks`' signal; free-text sentinel message (e.g. `Not connected`) on a disconnected/undetermined row | W, M, L | `Not connected` |
| `security` | string | free text; `unknown` on the Linux iwconfig blob fallback (wifi_plugin.cpp:1092); `0` on the disconnected/undetermined sentinel | W, M, L | `0` |
| `bssid` | string | AP MAC address; `-`/`none` when not associated or unknown | W, M, L | `none` |
| `interface_or_channel` | string | Linux/Windows: interface name (e.g. `wlan0`, an adapter description); macOS: 802.11 channel number; `none` sentinel | W, M, L | `none` |
<!-- END GENERATED -->

### Result status

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `OK` | FULL | `wifi:nm_dbus_fallthrough` | Linux, both actions: NetworkManager D-Bus failed/unreachable and the action fell through to nmcli — provenance, not a failure, because the next rung answers fully (wifi_plugin.cpp:754-755, 1055-1056) |
| `CONSTRAINED` | PARTIAL | `wifi:action_budget_exhausted` | Linux `list_networks`: the 45s aggregate ladder budget ran out mid `iwlist` scan with interfaces still unscanned (wifi_plugin.cpp:806-808) |
| `CONSTRAINED` | PARTIAL | `wifi:macos_scan_requires_location_services` | macOS `list_networks`: neither `airport` nor `system_profiler` produced rows (wifi_plugin.cpp:931-933) |
| `UNAVAILABLE` | PARTIAL | `wifi:iwlist_scan_failed` | Linux `list_networks`: interfaces were discovered but no `iwlist scan` answered (wifi_plugin.cpp:835-837) |
| `UNAVAILABLE` | PARTIAL | `wifi:no_wireless_tools` | Linux `list_networks`: neither nmcli nor `iw` answered and no runner-level failure was already forwarded (wifi_plugin.cpp:857-859) |
| `UNAVAILABLE` | PARTIAL | `wifi:wlan_open_handle_failed` / `wifi:wlan_enum_interfaces_failed` / `wifi:wlan_query_interface_failed` | Windows `connected`: the WLAN API call itself failed (wifi_plugin.cpp:956-957, 967-968, 1023-1025) |
| `UNAVAILABLE` | PARTIAL | `wifi:nmcli_and_iwconfig_failed` | Linux `connected`: neither nmcli nor iwconfig answered and no runner-level failure was already forwarded (wifi_plugin.cpp:1111-1113) |
| (runner-derived) | (runner-derived) | `subprocess_runner:*` (e.g. `spawn_error`) | Any `run_tool()` call whose subprocess itself failed to spawn, hit its deadline, or hit the line cap forwards `yuzu::agent::forward_runner_failure`'s own status instead (wifi_plugin.cpp:768-769, 822-823, 854-855, 1074-1075, 1090-1091, 1109-1110) — this is what the linux.txt sample shows for both actions |

macOS `connected` and Windows `list_networks` never call `set_result_status` on any path (wifi_plugin.cpp:666-715, 1117-1134); Windows `connected`'s "not found, no error" branch (wifi_plugin.cpp:1028-1030) is the same. All three record `UNDECLARED`/`UNKNOWN` with empty provenance, exactly as the macos.txt and windows.txt samples show.

### Where the data goes

- **Instruction result only.** Rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore at the DSL default 90-day retention (`spec.response.retentionDays` is unset in `wifi.yaml`, docs/yaml-dsl-spec.md:190-194), queryable at `/api/responses/{id}`.
- **Not consumed by** daily-sync inventory, the TAR warehouse, DEX, or metrics. Nothing runs on a schedule — `gather.ttlSeconds: 30` bounds the agent's response deadline, not a recurring interval (docs/yaml-dsl-spec.md:184-188) — the plugin executes only when an operator or workflow dispatches one of its two definitions.
- **Siblings:** none of this plugin's own definitions feed TAR. TAR ships its own, independent `netconn` capture source (`agents/plugins/tar/src/tar_netconn.hpp`, Windows-only, opt-in, default-disabled) that records Wi-Fi connect/fail/disconnect transitions from the OS event log with a stricter allow-list than this plugin — it never extracts SSID, BSSID, or profile names (tar_schema_registry.cpp:838-844).
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("device.wifi.connected")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash pending

```
== action=list_networks
[result_status] UNDECLARED / UNKNOWN / 

== action=connected
connected|none|Not connected|0|none|none
[result_status] UNDECLARED / UNKNOWN /
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (alex) · leg-hash pending

```
== action=list_networks
wifi|info|wi-fi scan unavailable; airport removed in macOS 14+ and system_profiler requires Location Services|0|0|none
[result_status] CONSTRAINED / PARTIAL / wifi:macos_scan_requires_location_services

== action=connected
connected|none|Not connected|0|none|none
[result_status] UNDECLARED / UNKNOWN / 
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-06 · euid 0 · leg-hash pending

```
== action=list_networks
wifi|error|No wireless tools available (nmcli/iw)|0|0|none
[result_status] UNAVAILABLE / PARTIAL / subprocess_runner:spawn_error

== action=connected
connected|unknown|Wi-Fi connection state could not be determined (NetworkManager unreachable; nmcli and iwconfig both failed)|0|none|none
[result_status] UNAVAILABLE / PARTIAL / subprocess_runner:spawn_error
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **Windows `list_networks` can emit zero rows with no sentinel.** A failed WLAN handle or zero enumerated interfaces IS reported (`wifi|error|Cannot open WLAN handle|...`, `wifi|error|No wireless interfaces found|...`, wifi_plugin.cpp:670-673, 677-682). The silent gap is one level deeper: once at least one interface exists, `WlanGetAvailableNetworkList` returning `ERROR_SUCCESS` with zero networks (wifi_plugin.cpp:689-691) leaves the per-network loop with nothing to iterate (wifi_plugin.cpp:693,710) — no sentinel is written, unlike the Linux/macOS legs, which always emit an explicit `wifi|info|...`/`wifi|error|...` line for an empty result. This is what the windows.txt capture shows: the-rig's SYSTEM capture had a wireless interface (the WLAN API needs no interactive session) but no visible networks.
2. **The Linux D-Bus rung has never met a real access point.** Every AP-property signature is spec/introspection-verified, not runtime-verified: the verification host was a container with no wireless device (wifi_plugin.cpp:159-166, 1184-1202). Promoting either leg to `SUPPORTED` needs one real-radio run that returns an AP through D-Bus and a second that forces the nmcli fallback (wifi_plugin.cpp:1199-1202).
3. **WEP is indistinguishable from Open on the Linux D-Bus leg.** `nm_security_flags_to_string` reads only `WpaFlags`/`RsnFlags`, never the AP's PRIVACY bit, so a WEP-only AP reports `Open` the same as a genuinely unsecured one (wifi_parsers.hpp:592-595).
4. **The nmcli `connected` fallback was dead on every host before this migration.** The previous `nmcli device show` argv requested `WIFI.SSID`/`WIFI.SIGNAL`-family fields that command rejects outright (`invalid field 'WIFI.SSID'`, exit 2); `device wifi list`'s `ACTIVE` row replaces it (wifi_parsers.hpp:140-155).
5. **Neither non-Windows sample exercises the least-privilege path.** The Linux capture ran as root (euid 0) in a container with no `nmcli`/`iw` installed at all, so both actions hit the "no wireless tools" branch rather than the documented root-only-`iwlist` degrade; the macOS capture ran unprivileged (euid 501), not as the production root LaunchDaemon (docs/agent-privilege-model.md "macOS is the current exception").

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/wifi/src/wifi_plugin.cpp` (descriptor + actions) · `wifi_corewlan.hpp` / `wifi_corewlan.mm` (macOS CoreWLAN `connected` leg) · `wifi_parsers.hpp` (pure parse/format helpers)
- Definitions: `content/definitions/wifi.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_c.hpp`
- Tests: `tests/unit/test_wifi_corewlan.cpp` · `tests/unit/test_wifi_local_dispatcher.cpp` · `tests/unit/test_wifi_parsers.cpp`
- Privilege row: `docs/agent-privilege-model.md`
- Changelog: `changelog.d/2204-declarations-group-c.added.md` · `changelog.d/2215-wifi-connected-corewlan.added.md` · `changelog.d/native-raii-objcpp.added.md` · `changelog.d/wave4-pr41b-wifi-native-dbus.changed.md`
<!-- END GENERATED -->
