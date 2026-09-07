# rdp_control

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Remote Desktop control — enable/disable RDP (registry + firewall + TermService) |
| **Version** | 0.1.0 |
| **Kind** | Action · `status` read-only · `set_state` mutating · on-demand (no scheduled gather) |
| **Platforms** | Windows ✅ · macOS ⛔ · Linux ⛔ |
| **Actions** | `set_state` (definition `windows.rdp.set_state`) · `status` (definition `windows.rdp.status`) |
| **Security** | securable `Security` · `set_state`: operation Write · risk High · dispatch Mutating · approval gate AdminOrApproval · `status`: operation Read · risk Low · dispatch ReadOnly · approval gate None |
| **Roles** | execute: `set_state` endpoint-admin · `status` endpoint-admin, endpoint-operator · author: content-author (both) |
<!-- END GENERATED -->

## How it works

`set_state` runs three sequential steps under a per-process mutex (registry `fDenyTSConnections`, the built-in Remote Desktop firewall rule group via `INetFwPolicy2`, then TermService) and reports each step's outcome independently; `overall|ok` only when every attempted step succeeded, and there is no rollback on partial failure. Disable deliberately leaves TermService running — only the registry and firewall gates are closed. `status` independently re-reads all three gates and derives a `rdp` verdict that is `unknown` (never a false `off`) whenever any gate could not be read. On macOS and Linux neither action touches the OS: both return the honest `rdp_control|unsupported|...` sentinel; `set_state` still reports rc=1 there (a state-changing action that touched nothing must not read as success), while `status` keeps rc=0 (an unsupported read is not itself a failure). The plugin is deliberately not a rollback/undo mechanism, and it never stops a running TermService — that is the Guardian service-guard's job.

```mermaid
flowchart LR
  OP[Operator / ITSM change window] --> SRV[Server<br/>authz: Security.Write set_state<br/>authz: Security.Read status]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[rdp_control.execute]
  EX --> WIN[Windows leg<br/>registry + INetFwPolicy2 COM + SCM]
  EX --> MAC[macOS leg<br/>honest UNSUPPORTED sentinel<br/>no mechanism]
  EX --> LIN[Linux leg<br/>honest UNSUPPORTED sentinel<br/>no mechanism]
  WIN & MAC & LIN --> ROWS[key|value rows +<br/>result status] --> RS[(ResponseStore)] --> API[REST /api/responses]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `set_state` | ✅ supported · rung 1 · Win32 registry + INetFwPolicy2 COM + SCM | ⛔ unsupported · no mechanism bound | ⛔ unsupported · no mechanism bound |
| `status` | ✅ supported · rung 1 · Win32 registry + INetFwPolicy2 COM + SCM | ⛔ unsupported · no mechanism bound | ⛔ unsupported · no mechanism bound |

**Declared limits per leg** (the descriptor's fallback text, verbatim):

- None declared — every leg's Fallback column is `-`.
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account with an elevated token (LocalSystem today, #1442) | **Administrators** group membership (LocalSystem already has it). The intended least-privilege `NT SERVICE\YuzuAgent` account is **not** granted this by `scripts/install-agent-user.ps1`; must be added out of band (GPO Restricted Groups / Intune / `Add-LocalGroupMember`). | 2026-09-07, bare metal, as `SYSTEM` | `set_state`: per-step `error:<code>` rows and `overall\|error`; `status`: per-gate `error:<code>` rows and `rdp\|unknown` |
| macOS | n/a — leg not implemented; the honest-sentinel path needs no privilege | n/a | 2026-09-07, bare metal, at euid 501 (alex) | always `rdp_control\|unsupported\|...`, rc=1 (`set_state`) / rc=0 (`status`) |
| Linux | n/a — leg not implemented; the honest-sentinel path needs no privilege | n/a | 2026-09-06, container, at euid 0 | always `rdp_control\|unsupported\|...`, rc=1 (`set_state`) / rc=0 (`status`) |

None. The Windows leg calls Win32 registry, COM, and Service Control Manager APIs in-process (`RegSetValueExW`/`RegGetValueW`, `INetFwPolicy2` COM, `StartServiceW`/`QueryServiceStatusEx`) — no subprocess, no network.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
| Definition | Parameter | Type | Required | Default | Values | Description |
|---|---|---|---|---|---|---|
| `windows.rdp.set_state` | `state` | string | yes | — | `enable`, `disable` | enable allows Remote Desktop connections; disable blocks them (e.g. `state: enable`). |

`windows.rdp.status` takes no parameters.
<!-- END GENERATED -->

### Outputs

Each action's result is a set of independent `key|value` lines — one per gate or step, in emission order — not a single delimited row; the bold lines below list the field order. There is no `-` placeholder convention here: a step or gate that could not be read reports its own `error:<code>` (or `error:com_init` / `error:group_not_found` for the firewall step) instead.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`set_state` — `reg_status|firewall_status|service_status|overall`**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `reg_status` | string | `ok`, `error:<win32 code>` | W | `ok` (not observed in any capture — only the rejection path was run) |
| `firewall_status` | string | `ok`, `error:com_init`, `error:group_not_found`, `error:0x<hresult>` | W | `ok` (not observed in any capture) |
| `service_status` | string | `running` (enable, confirmed), `untouched` (disable), `error:<win32 code>` | W | `running` (not observed in any capture) |
| `overall` | string | `ok`, `error` | W | `ok` (not observed in any capture) |

**`status` — `deny_ts_connections|firewall_group|term_service|rdp`**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `deny_ts_connections` | string | `0` or `1` (raw registry DWORD), or `error:<win32 code>` | W | `0` |
| `firewall_group` | string | `enabled`, `disabled`, `group_not_found`, `error:com_init`, `error:0x<hresult>` | W | `enabled` |
| `term_service` | string | `running` `start_pending` `stopped` `stop_pending` `paused` `pause_pending` `continue_pending` `unknown`, or `error:<win32 code>` | W | `running` (not observed in any capture) |
| `rdp` | string | `on`, `off`, `unknown` | W | `on` |
<!-- END GENERATED -->

### Result status

This plugin does not set a typed result status; the agent records `UNDECLARED` and the sample shows `UNDECLARED / UNKNOWN /`.

### Where the data goes

- **Instruction result only.** Rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore (default 90-day retention), queryable at `/api/responses/{id}`.
- **Not consumed by** daily-sync inventory, the TAR warehouse, DEX, or metrics. The plugin is registered only in the agent's instruction catalogue and the capability catalogue — nothing else in `server/` references `rdp_control` or the `windows.rdp.*` ids.
- **Siblings:** none report combined RDP posture. `registry.get_value`/`registry.set_value` can reach the same `fDenyTSConnections` value in isolation, and `firewall.state`/`firewall.rules` read Windows Firewall generally, but neither combines the registry + firewall-group + service triad this plugin reports together.
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("windows.rdp.status")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash pending

```
== action=set_state
error|invalid state (use enable or disable)
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1

== action=status
deny_ts_connections|0
firewall_group|enabled
term_service|running
rdp|on
[result_status] UNDECLARED / UNKNOWN / 
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (alex) · leg-hash pending

```
== action=set_state
rdp_control|unsupported|Windows Remote Desktop has no macOS equivalent; use Screen Sharing / com.apple.screensharing
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1

== action=status
rdp_control|unsupported|Windows Remote Desktop has no macOS equivalent; use Screen Sharing / com.apple.screensharing
[result_status] UNDECLARED / UNKNOWN / 
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-06 · euid 0 · leg-hash pending

```
== action=set_state
rdp_control|unsupported|Windows Remote Desktop is not available on this platform
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1

== action=status
rdp_control|unsupported|Windows Remote Desktop is not available on this platform
[result_status] UNDECLARED / UNKNOWN /
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **No rollback on partial failure.** `set_state`'s three steps each report their own status; `overall|ok` only when all succeeded, and a partial failure leaves whichever gates were flipped in place with no automatic revert.
2. **Disable does not stop TermService.** Only the registry and firewall gates close on disable; the service is deliberately left running, which is why the capability catalogue classifies `set_state` as `Irreversible` rather than claiming a complete undo.
3. **`S_FALSE` from the firewall API is not success.** `INetFwPolicy2::EnableRuleGroup`/`IsRuleGroupEnabled` return `S_FALSE` (which passes `SUCCEEDED()`) when the built-in Remote Desktop rule group is absent (e.g. a hardened image); the plugin explicitly classifies that as `group_not_found`/an unreadable gate, never a confirmed enable, disable, or "off".
4. **`status` never reports "off" from an unreadable gate.** If any of the three gates cannot be read, the derived verdict is `unknown`, distinguishing "confirmed closed" from "couldn't tell" — the fail-safe direction for a remote-access posture check.
5. **No typed result status.** The plugin never calls a result-status setter; every sample on every OS shows `UNDECLARED / UNKNOWN`, so a caller must key off `overall`/`rdp` and the process exit code, not a typed status field.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/rdp_control/src/rdp_control_plugin.cpp`
- Definitions: `content/definitions/rdp_control.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_c.hpp`
- Tests: `tests/unit/test_new_plugins.cpp` (descriptor shape + validation-mirror cases) · `tests/test_capability_gate_consistency.py` · `tests/fixtures/1398_pair_gate_table.json`
- Privilege row: `docs/agent-privilege-model.md`
- Changelog: `changelog.d/2204-declarations-group-c.added.md` · `changelog.d/2243-os-capability-matrix-sections.changed.md` · `changelog.d/2277-macos-plugin-parity.added.md`
<!-- END GENERATED -->
