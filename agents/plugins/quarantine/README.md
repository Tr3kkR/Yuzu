# quarantine

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Device network isolation (quarantine) with per-IP whitelisting |
| **Version** | 1.0.0 |
| **Kind** | Action · mixed: read-only (`status`) + mutating (`quarantine`/`unquarantine`/`whitelist`) · on-demand (no scheduled gather; `gather.ttlSeconds` only bounds cached-result staleness, 60–120s per definition) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux ✅ |
| **Actions** | `quarantine` (definition `security.quarantine.isolate`) · `unquarantine` (definition `security.quarantine.release`) · `status` (definition `security.quarantine.status`) · `whitelist` (definition `security.quarantine.whitelist`) |
| **Security** | securable `Security` · `quarantine`: operation Execute · risk Critical · dispatch Destructive · mutability Irreversible · gate AdminOrApproval · `unquarantine`: Execute · High · Mutating · Reversible · AdminOrApproval · `whitelist`: Execute · High · Mutating · Reversible · AdminOrApproval · `status`: Read · Low · ReadOnly · mutability None · gate none |
| **Roles** | execute: endpoint-admin, security-admin (`status` also: endpoint-operator) · author: content-author |
<!-- END GENERATED -->

## How it works

`quarantine` builds a whitelist (the operator-supplied `server_ip` and `whitelist_ips`, merged with the agent's own pre-resolved server address) and blocks everything else: on Windows by setting the all-profiles firewall policy to block/block (`#3284` branch A) and adding explicit per-IP and loopback Allow rules for both IPv4 and IPv6; on Linux by building a `yuzu-quarantine` iptables chain, mirrored to ip6tables only when the host has a real IPv6 stack; on macOS by generating and atomically loading (`pfctl -f`) a full pf main ruleset ending in `block all`, never a named anchor. `unquarantine` reverses it: Windows deletes its named Allow rules and replays the firewall policy captured at quarantine time (or Microsoft's default if nothing was captured); Linux flushes and deletes the chain (and its ip6tables mirror, if one was applied); macOS reloads `/etc/pf.conf`, falling back to disabling pf if that reload itself fails. `status` never mutates and never waits behind the mutation gate below — it re-reads the live firewall state and reports `active`/`partial`/`degraded`/`uncertain`/`inactive`, plus the current whitelist unless the device is `inactive`. `whitelist` adds/removes IPs from an already-quarantined device by editing rules directly on Windows/Linux; macOS has no per-rule granularity, so it rebuilds and reloads the *entire* main ruleset from the current whitelist plus the change — which means running `whitelist` against a device that is not yet quarantined isolates it (`quarantine_plugin.cpp:2409-2460`). Every mutating action first acquires one process-wide `MutationGate` (`quarantine_serialization.hpp`) so quarantine/unquarantine/whitelist never race each other on the same OS firewall state; a caller that cannot get in within 2s gets `status|busy` instead of hanging. This plugin is deliberately not a state-preserving undo on macOS: `macos_unquarantine` restores the OS default `/etc/pf.conf`, not whatever pf rules the endpoint had before quarantine, so any runtime rules the host had are permanently lost — the reason the catalogue classifies `quarantine` Irreversible on every platform even though Linux and Windows do restore their own prior state.

```mermaid
flowchart LR
  OP[Operator / MCP quarantine_device] --> SRV[Server<br/>authz: Security.Execute or .Read<br/>writes QuarantineStore]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[quarantine.execute]
  EX --> WIN[Windows leg<br/>netsh.exe: all-profiles policy + named Allow rules]
  EX --> MAC[macOS leg<br/>sudo pfctl -f: atomic main-ruleset reload]
  EX --> LIN[Linux leg<br/>sudo iptables/ip6tables: yuzu-quarantine chain]
  WIN & MAC & LIN --> ROWS[key|value rows +<br/>typed result status]
  ROWS --> RS[(ResponseStore)]
  SRV --> QS[(QuarantineStore<br/>Postgres, authoritative)]
  RS --> API[REST /api/responses · MCP]
  QS --> API2[REST /api/v1/quarantine]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `quarantine` | ✅ supported · rung 2 · netsh via bounded runner argv (service-account privilege, no sudo) | ✅ supported · rung 2 · sudo-governed pfctl via bounded runner argv | ✅ supported · rung 2 · sudo-governed iptables via bounded runner argv |
| `unquarantine` | ✅ supported · rung 2 · netsh via bounded runner argv (service-account privilege, no sudo) | ✅ supported · rung 2 · sudo-governed pfctl via bounded runner argv | ✅ supported · rung 2 · sudo-governed iptables via bounded runner argv |
| `status` | ✅ supported · rung 2 · netsh via bounded runner argv (service-account privilege, no sudo) | ✅ supported · rung 2 · sudo-governed pfctl via bounded runner argv | ✅ supported · rung 2 · sudo-governed iptables via bounded runner argv |
| `whitelist` | ✅ supported · rung 2 · netsh via bounded runner argv (service-account privilege, no sudo) | ✅ supported · rung 2 · sudo-governed pfctl via bounded runner argv | ✅ supported · rung 2 · sudo-governed iptables via bounded runner argv |

**Declared limits per leg** (the descriptor's fallback text, verbatim):

- None declared. Every leg's fourth `YuzuActionDescriptor` field is `nullptr` for all four actions on all three platforms (`quarantine_plugin.cpp:1786-1811`), matching the capability-matrix "-" fallback for every row.
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | Agent service account — LocalSystem today (#1442). Shells directly to `netsh.exe`, resolved via `GetSystemDirectoryW` (`quarantine_plugin.cpp:271-288`) — never a PowerShell cmdlet. | **None today** (LocalSystem already holds firewall-policy privilege). Under the intended least-privilege model (`NT SERVICE\YuzuAgent`, not in `Administrators`) this needs Administrators-group membership or equivalent firewall-policy privilege (`docs/agent-privilege-model.md` row for `quarantine.*`) — see Caveat 4 for where that doc's own description of the mechanism is stale. | 2026-09-07, bare-metal, as `SYSTEM` | `state|uncertain`, note "firewall query failed — containment state could not be determined", ABI4 `UNAVAILABLE`/`PARTIAL` (`quarantine_plugin.cpp:802-805`) |
| macOS | Agent daemon; production runs under a narrow sudoers NOPASSWD grant for `/sbin/pfctl` (`quarantine_plugin.cpp:139,1540-1543`). | Sudoers entry for `/sbin/pfctl` at `/etc/sudoers.d/yuzu-agent`, verified with `scripts/install-agent-user.sh --check` (`quarantine_plugin.cpp:1541-1543`). | 2026-09-07, bare-metal, **unprivileged, euid 501 (alex)** — deliberately below the production grant. | Reproduced by this capture's own `status` run: `state|uncertain`, note "pf state could not be read -- containment can be neither confirmed nor ruled out", `[result_status] UNAVAILABLE / PARTIAL / quarantine:macos_is_quarantined pf status unreadable`, `[rc] 1` (`quarantine_plugin.cpp:1728-1746`; `docs/samples/macos.txt`). |
| Linux | Agent daemon; every `iptables`/`ip6tables` call is prefixed `sudo -n --` via `yuzu::shared::sudo_wrap` regardless of the caller's own privilege. | Sudoers NOPASSWD entries for `/usr/sbin/iptables` and `/usr/sbin/ip6tables` (`quarantine_plugin.cpp:130-145`). | 2026-09-06, container, **as root (euid 0)** — the sudo layer is a pass-through here, not exercised as a real escalation. | A failed listing reads `state|uncertain`, ABI4 status forwarded from the runner (`quarantine_plugin.cpp:1279,1362-1363`). This capture instead hit a **missing-binary** refusal (`ip6tables` not installed): `state|uncertain`, note "ipv6_unavailable — IPv6 stack is up but ip6tables is not installed", `[result_status] UNAVAILABLE / PARTIAL / subprocess_runner:spawn_error`, `[rc] 1` (`docs/samples/linux.txt`). |

Binaries: `netsh.exe` (Windows), `/usr/sbin/iptables` + `/usr/sbin/ip6tables` (Linux), `/sbin/pfctl` (macOS) — every call runs through `yuzu::agent::run_bounded_subprocess` with a 15s deadline for mutating calls and 10s for reads (`quarantine_plugin.cpp:97-98`), never a shell. No network access beyond the agent's existing gRPC channel.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
| Definition | Parameter | Type | Required | Default | Values | Description |
|---|---|---|---|---|---|---|
| `security.quarantine.isolate` | `server_ip` | string | no | — | — | IP address of the Yuzu management server; always whitelisted so the agent connection survives containment. |
| `security.quarantine.isolate` | `whitelist_ips` | string | no | — | — | Comma-separated list of additional IPs to allow through the quarantine firewall (e.g. DNS server, SIEM collector). |
| `security.quarantine.whitelist` | `action` | string | yes | — | add, remove | Whether to add or remove the specified IPs from the quarantine whitelist. |
| `security.quarantine.whitelist` | `ips` | string | yes | — | — | Comma-separated list of IP addresses to add to or remove from the quarantine whitelist. |

`unquarantine` (`security.quarantine.release`) takes no parameters. `status` (`security.quarantine.status`) takes no parameters.
<!-- END GENERATED -->

### Outputs

Every action writes pipe-delimited `key|value` pairs via `ctx.write_output` — not a fixed-position row like the collector plugins' `field0|field1|…` schema, so a caller reads by key name, never by column offset. A hard failure before any mutation is attempted (a missing/invalid parameter, a failed macOS whitelist-read prerequisite) emits `error|<message>` instead of the action's normal `status`/`state` row. Several outcomes also carry extra keys the declared schema below does not enumerate — `prior_policy`, `rules_attempted` and `note` on `quarantine`; `note` on `unquarantine`, `status`, and `whitelist` — see Caveats 5.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`quarantine` — `status|<value>[|rules_applied|<n>][|rules_attempted|<n>][|prior_policy|<text>][|note|<text>]`** (or `error|<message>` on an aborted run)

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `status` | string | `quarantined`, `quarantined_partial`, `failed`, `busy` | windows, linux, darwin | `quarantined` (not observed — `quarantine` was never executed for these samples) |
| `rules_applied` | int32 | integer ≥ 0 | windows, linux, darwin | `4` |

**`unquarantine` — `status|<value>[|note|<text>]`** (or `error|<message>` on macOS, if both restore paths fail)

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `status` | string | `released`, `release_uncertain` | windows, linux, darwin | `released` (not observed — `unquarantine` was never executed for these samples) |

**`status` — `state|<value>[|note|<text>]`, then (only when `state` != `inactive`) `whitelist|<comma-list>[|note|<text>]`**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `state` | string | `active`, `partial`, `degraded` (macOS only), `uncertain`, `inactive` | windows, linux, darwin | `uncertain` |
| `whitelist` | string | free text — comma-separated IP list, or empty | windows, linux, darwin | `` (empty) |

**`whitelist` — `status|<value>|whitelist|<comma-list>`** (or `error|<message>` on invalid/missing parameters)

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `status` | string | `updated`, `update_uncertain` | windows, linux, darwin | `updated` |
| `whitelist` | string | free text — comma-separated IP list, or empty | windows, linux, darwin | `` (empty) |
<!-- END GENERATED -->

### Result status

Surfaced as `plugin_result_status` on the command response, set via `ctx.set_result_status` or forwarded from a runner failure via `yuzu::agent::forward_runner_failure`.

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `UNDECLARED` (agent default) | — | — | No `set_result_status` call fires on this path: a clean `active`/`inactive` `status` read, or a `whitelist`/`quarantine`/`unquarantine` rejected before any mutation for a missing/invalid parameter. Matches every sample's `[result_status] UNDECLARED / UNKNOWN /` line (`quarantine_plugin.cpp:2263-2289,2327-2334`). |
| `UNAVAILABLE` | `PARTIAL` | e.g. `subprocess_runner:spawn_error` | A genuine runner failure (spawn/timeout/signal) on any read or mutation, forwarded via `forward_runner_failure` before the action's own status call runs — matches the Linux sample's `ip6tables`-missing capture. |
| `UNAVAILABLE` | `PARTIAL` | `quarantine:win_quarantine …firewall policy not applied` | `quarantine` on Windows, when the all-profiles policy set itself fails (`quarantine_plugin.cpp:568-577`). |
| `OK` | `PARTIAL` | `quarantine:win_quarantine contained, but …exceptions failed to apply` | `quarantine` on Windows, containment holds but a loopback/whitelist exception failed (`quarantine_plugin.cpp:584-593`). |
| `OK` | `PARTIAL` | `quarantine:win_unquarantine restored the Windows default policy — no captured pre-quarantine policy…` | `unquarantine` on Windows, release succeeded but no prior policy was available to replay (`quarantine_plugin.cpp:731-737`). |
| `UNAVAILABLE` | `PARTIAL` | `quarantine:linux_quarantine containment incomplete` | `quarantine` on Linux, any non-full-success token (`quarantine_plugin.cpp:1145-1148`). |
| `UNAVAILABLE` | `PARTIAL` | `quarantine:macos_load_ruleset pfctl exited non-zero` / `…pf is not actually enabled` | `quarantine`/`whitelist` on macOS, the ruleset load or the post-enable verification fails (`quarantine_plugin.cpp:1531-1534,1584-1593`). |
| `UNAVAILABLE` | `PARTIAL` | `quarantine:macos_unquarantine restore and disable both failed` | `unquarantine` on macOS, both `/etc/pf.conf` reload and `pfctl -d` fail (`quarantine_plugin.cpp:1670-1674`). |
| `UNAVAILABLE` | `PARTIAL` | `quarantine:macos_is_quarantined pf ruleset loaded but pf is disabled` (`state=degraded`) | `status` on macOS, pf holds the blocking ruleset but is itself disabled (`quarantine_plugin.cpp:1720-1726`). |
| `UNAVAILABLE` | `PARTIAL` | `quarantine:macos_is_quarantined pf status unreadable` (`state=uncertain`) | `status` on macOS, the pf status read fails or is unparseable — matches this build's macOS sample exactly (`quarantine_plugin.cpp:1742-1744`; `docs/samples/macos.txt`). |
| `UNAVAILABLE` | `PARTIAL` | `quarantine: another mutating quarantine action is in progress` | Any mutating action refused `status|busy` by the `MutationGate` (`quarantine_plugin.cpp:2028,2168,2318`). |
| `OK` | `PARTIAL` | `quarantine:win_quarantine contained, but the pre-quarantine firewall policy could not be captured/stored…` | `quarantine` on Windows, containment succeeded but the restore image failed to persist (`quarantine_plugin.cpp:2123-2133`). |
| `OK` | `PARTIAL` | `quarantine:linux_quarantine contained, but the ip6tables-applied marker could not be stored…` | `quarantine` on Linux, containment succeeded but the v6-applied marker failed to persist (`quarantine_plugin.cpp:2145-2151`). |
| `OK` / `UNAVAILABLE` | `PARTIAL` | `quarantine:do_status containment is incomplete` / `…containment state could not be determined` | `status`, `state=partial` (OK/PARTIAL) or `state=uncertain`/`degraded` (UNAVAILABLE/PARTIAL) (`quarantine_plugin.cpp:2263-2289`). |

### Where the data goes

- **Instruction result.** Every action's output rows and result status travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore, queryable at `/api/responses/{id}`, like any other plugin dispatch.
- **QuarantineStore (Postgres, authoritative).** MCP `quarantine_device` writes the containment intent — `quarantine_store->quarantine_device(agent_id, session->username, reason, whitelist)` (`server/core/src/mcp_server.cpp:10049`) — before dispatching this plugin's `quarantine` action; the store holds "at most one active record per agent" and is explicitly **not** expendable telemetry — it persists until an administrator lifts it, no clock-guarded retention (`server/core/src/quarantine_store.hpp:8-15`). `QuarantineContainmentReconciler` re-drives containment from that stored record alone (never a fresh/caller-supplied value) on agent reconnect, via the shared `redispatch_stored_containment` chokepoint (`server/core/src/quarantine_reapply.hpp:2-38`).
- **Not consumed by** daily-sync inventory, the TAR warehouse, DEX, or metrics. Nothing runs on a schedule; the plugin executes only when an operator, MCP `quarantine_device`, or the reconciler dispatches one of its four definitions.
- **Siblings:** `rdp_control.set_state` shares the same `Administrators`-group-or-equivalent grant shape as `quarantine.*` on Windows and cites it directly rather than declaring a new right (`docs/agent-privilege-model.md` row for `rdp_control.set_state`).
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("security.quarantine.isolate")`. Run: `execute_instruction {definition_id, parameters}` (or MCP `quarantine_device` for the record + live-isolate path). Read: `/api/responses/{id}` for the instruction result; `/api/v1/quarantine` for the QuarantineStore-backed active-containment state.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash pending

```
== action=quarantine
[not captured] Destructive/Irreversible: not executed on a live host

== action=unquarantine
[not captured] Mutating/Reversible: not executed on a live host

== action=status
state|inactive
[result_status] UNDECLARED / UNKNOWN / 

== action=whitelist
error|missing required parameter: action (add/remove)
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (alex) · leg-hash pending

```
== action=quarantine
[not captured] Destructive/Irreversible: not executed on a live host

== action=unquarantine
[not captured] Mutating/Reversible: not executed on a live host

== action=status
state|uncertain|note|pf state could not be read -- containment can be neither confirmed nor ruled out
[result_status] UNAVAILABLE / PARTIAL / quarantine:macos_is_quarantined pf status unreadable
[rc] 1

== action=whitelist
error|missing required parameter: action (add/remove)
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-06 · euid 0 · leg-hash pending

```
== action=quarantine
[not captured] Destructive/Irreversible: not executed on a live host

== action=unquarantine
[not captured] Mutating/Reversible: not executed on a live host

== action=status
state|uncertain|note|ipv6_unavailable — IPv6 stack is up but ip6tables is not installed
[result_status] UNAVAILABLE / PARTIAL / subprocess_runner:spawn_error
[rc] 1

== action=whitelist
error|missing required parameter: action (add/remove)
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **macOS release is not a genuine undo.** `macos_unquarantine` restores `/etc/pf.conf`, never the endpoint's actual prior ruleset — any runtime pf rules present before quarantine are permanently lost. This is why the capability catalogue classifies `quarantine` Irreversible on every platform (`capdecls.md`; `quarantine_plugin.cpp:28-45,1776-1785`).
2. **`whitelist` can quarantine a clean macOS device.** `add`/`remove` on macOS always calls `macos_load_ruleset`, which writes `block all` and enables pf regardless of the device's current state — running `whitelist` against a device that is not yet quarantined isolates it (`quarantine_plugin.cpp:2409-2460`).
3. **No nftables path, despite the privilege doc.** `docs/agent-privilege-model.md`'s row for `quarantine.*` lists `/usr/sbin/nft` as a Linux grant, but the plugin only ever shells to `/usr/sbin/iptables` and `/usr/sbin/ip6tables` (`quarantine_plugin.cpp:142-145`) — the doc row is stale in the same way the old user-manual catalogue text was before it was corrected.
4. **The Windows privilege doc overstates the mechanism.** `docs/agent-privilege-model.md` describes the Windows grant as using the `Set-NetFirewallRule` cmdlet; the code shells directly to `netsh.exe` (`quarantine_plugin.cpp:271-288,357`) — no PowerShell cmdlet is invoked anywhere in this plugin.
5. **Two undeclared storage keys make release retry-safe, once.** The captured pre-quarantine Windows firewall policy (`win.prior_firewall_policy`) and the Linux "ip6tables applied" marker (`linux.v6_applied`) are write-once until a clean release clears them (`quarantine_plugin.cpp:1873-2017`) — a re-quarantine of an already-contained host deliberately never overwrites a good restore image, so only the very first capture is ever trusted.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/quarantine/meson.build` · `agents/plugins/quarantine/src/quarantine_plugin.cpp` (descriptor legs, execute dispatch) · `quarantine_parsers.hpp` (pure status parsing + argv construction) · `quarantine_serialization.hpp` (`MutationGate`)
- Definitions: `content/definitions/quarantine.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_c.hpp`
- Tests: `tests/unit/test_quarantine_argv.cpp` · `tests/unit/test_quarantine_parsers.cpp` · `tests/unit/test_quarantine_serialization.cpp` · `tests/unit/server/test_quarantine_containment_reconciler.cpp` · `tests/unit/server/test_quarantine_dispatch_decision.cpp` · `tests/unit/server/test_quarantine_dispatch_gate.cpp` · `tests/unit/server/test_quarantine_reapply.cpp` · `tests/unit/server/test_quarantine_store.cpp` · `tests/unit/server/test_rest_quarantine_routes.cpp`
- Privilege row: `docs/agent-privilege-model.md`
- Changelog: `changelog.d/1788-quarantine-rest-scoped-gate.security.md` · `changelog.d/20260814-quarantine-store-postgres.changed.md` · `changelog.d/20260818-wave2-quarantine-native-argv.changed.md` · `changelog.d/2204-declarations-group-c.added.md` · `changelog.d/2298-guardian-journal-fleet-rollup.added.md` · `changelog.d/2376-authz-topology-floor.security.md` · `changelog.d/2452-guardian-journal-progress-stamp.fixed.md` · `changelog.d/3127-mcp-quarantine-phantom-isolation.fixed.md` · `changelog.d/3282-linux-ipv6-quarantine.security.md` · `changelog.d/3283-macos-pf-enabled-status.security.md` · `changelog.d/3284-windows-precedence-probe.added.md` · `changelog.d/3284-windows-quarantine-precedence.security.md` · `changelog.d/3286-quarantine-mutation-serialization.fixed.md` · `changelog.d/3424-3511-dispatch-plugin-presence.security.md` · `changelog.d/3425-quarantine-reapply-on-reconnect.security.md` · `changelog.d/3495-shutdown-join-ordering.fixed.md` · `changelog.d/3687-mcp-dispatch-denial-reasons.security.md` · `changelog.d/881-quarantine-dispatch-enforcement.security.md`
<!-- END GENERATED -->
