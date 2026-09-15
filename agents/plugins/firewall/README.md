# firewall

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Firewall status and rule listing |
| **Version** | 0.4.1 |
| **Kind** | Collector · read-only · gathered (security.firewall.state, security.firewall.rules) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux ✅ |
| **Actions** | `rules` (definition `security.firewall.rules`) · `state` (definition `security.firewall.state`) |
| **Security** | securable `Security` · operation Read · risk Low · dispatch ReadOnly · approval gate None |
| **Roles** | execute: endpoint-admin, endpoint-operator, security-admin · author: content-author |
<!-- END GENERATED -->

## How it works

Both actions are reads; the plugin has no rule-mutation surface despite its name. `state` reports whether the host firewall is on, per profile or per backend. `rules` lists the rule set the same backend exposes. On Windows both go through the `INetFwPolicy2` COM interface: `state` asks each of the Domain, Private and Public profiles for `FirewallEnabled`; `rules` enumerates `INetFwRules` and stops after 100 rules with a `truncated|true` marker row. On macOS `state` reads the Application Firewall global state through `socketfilterfw --getglobalstate` (the firewall a Mac administrator means), adds a `mode|block_all` row when block-all is set, then reads the pf packet-filter status through `pfctl -s info` as a secondary row; `rules` lists pf rules through `pfctl -s rules`. On Linux the plugin probes backends in a fixed order and stops at the first that answers: firewalld over sd-bus, then nftables over `NETLINK_NETFILTER` dumps, then `ufw status numbered`, then `iptables -S`, else `backend|none`.

Every subprocess runs through the bounded runner with a fixed deadline; every parse is a pure function in `firewall_parsers.hpp`. On Linux, firewalld, nftables, ufw and iptables are each bounded to their own ~5s acquisition deadline and probed in that fixed order, so a run that must walk every leg takes up to ~20s worst case (4 legs × 5s). The nftables leg further verifies each dump reply's sender (`nl_pid == 0`, genuinely from the kernel rather than a foreign process sharing the netlink family) before trusting it, and splits that ~5s deadline across three sequential per-dump budget slices (table, then chain, then rule) rather than one shared timeout for all three. The honest-status invariant holds on every leg: empty, truncated or unrecognised output parses to `unknown` (state) or no rows (rules), never to a false-safe "disabled" or a fabricated rule. Once nftables' table dump succeeds but a later chain or rule dump fails, the leg writes a `fallthrough|nftables:<dump>:<reason>` provenance row and falls through to `ufw` then `iptables` (clamped so a downstream "disabled" can't contradict tables already seen) rather than stopping there; only when neither backend answers either does the run report `backend|nftables` + `state|unknown` (or `rules|unknown`) plus an `error|nftables:<dump>:<reason>` row naming why.

```mermaid
flowchart LR
  OP[Operator / workflow<br/>dispatches definition] --> SRV[Server<br/>authz: Security.Read<br/>concurrency: per-device]
  SRV -- gRPC mTLS --> HOST[Agent plugin host]
  HOST --> EX[firewall.execute]
  EX --> WIN[Windows leg<br/>INetFwPolicy2 COM<br/>profiles · INetFwRules]
  EX --> MAC[macOS leg<br/>socketfilterfw · pfctl<br/>bounded subprocess]
  EX --> LIN[Linux leg<br/>firewalld sd-bus → nftables netlink<br/>→ ufw → iptables → none]
  WIN & MAC & LIN --> ROWS[pipe rows<br/>state · rule · backend]
  ROWS -- CommandResponse --> RS[(ResponseStore<br/>90-day default retention)]
  RS --> API[REST /api/responses<br/>fleet pie by state]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `rules` | ✅ supported · rung 1 · INetFwPolicy2 COM (INetFwRules enumeration) | ✅ supported · rung 2 · pfctl via run_bounded_subprocess | ✅ supported · rung 1 · firewalld sd-bus, else nftables NETLINK_NETFILTER (both rung 1), else ufw/iptables via run_bounded_subprocess (rung 2) |
| `state` | ✅ supported · rung 1 · INetFwPolicy2 COM (per-profile FirewallEnabled) | ✅ supported · rung 2 · socketfilterfw/pfctl via run_bounded_subprocess | ✅ supported · rung 1 · firewalld sd-bus, else nftables NETLINK_NETFILTER (both rung 1), else ufw/iptables via run_bounded_subprocess (rung 2) |
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account (LocalSystem today, #1442) | None. `INetFwPolicy2` profile and rule reads need no elevation. | 2026-09-06 on the-rig (Windows 11 Pro 10.0.26200), elevated SSH session: three profiles read `enabled`, 100 rule rows plus the `truncated\|true` marker | `error\|com_init` or `error\|policy2_create:<hresult>` row; profile rows read `error:<hresult>` |
| macOS | LaunchDaemon (root today) | None for the primary Application Firewall read (`socketfilterfw --getglobalstate` is unprivileged). The secondary pf read opens `/dev/pf` and needs root; the plugin deliberately does not ride the quarantine plugin's `pfctl` sudoers grant. | 2026-09-06 at euid 501 on this host: `state\|disabled`, `pf\|unknown`, no pf rule rows | `pf\|unknown` (state), no rows (rules), never a false-safe value |
| Linux | agent service account | `firewall-cmd --state` is an unprivileged D-Bus query. The nftables netlink dump conventionally needs `CAP_NET_ADMIN` (verified 2026-08-23 with the capability present); `ufw status` and `iptables -S` need root. No sudoers entry is granted for any of them. | nftables verified 2026-08-23 in an Ubuntu 26.04 container with `CAP_NET_ADMIN`. The no-cap (unprivileged) signature is measured from the dispatch code itself — sender-verified (`nl_pid == 0`) reads, `classify_open_errno`/`nft_dump_reason` EPERM/EMFILE decoding, and the fixed C4 fall-through ladder — not a live no-cap host capture, and it is **qualified by which rung-2 backend binaries are installed**: on a host where `ufw` or `iptables` exists, a refused nftables read falls through and the ladder terminates at `backend\|iptables` (or `backend\|ufw`) + `state\|unknown`, never `backend\|none`; `backend\|none` appears only when neither rung-2 binary is present at all | a refused nftables table dump (EPERM or other kernel error, or `EMFILE`/`ENFILE` reporting `error\|fd_exhausted`) falls through to `ufw` then `iptables`, each clamped so neither reports a false "disabled" contradicting tables already seen; a refused chain or rule dump after a successful table dump behaves the same way, first writing `fallthrough\|nftables:<dump>:<reason>`; if neither `ufw` nor `iptables` answers either, the run reports `backend\|nftables` + `state\|unknown` / `rules\|unknown` plus `error\|nftables:<dump>:<reason>`; a refused `iptables -S` alone (the last backend, nothing further to fall through to) reports `backend\|iptables` + `state\|unknown` / `rules\|unknown`; `backend\|none` appears only when no backend ran at all — neither `/usr/sbin/ufw` nor `/usr/sbin/iptables` exists, or `ufw` was refused and `iptables` is absent |

Subprocesses: `socketfilterfw`, `pfctl` (macOS), `ufw`, `iptables` (Linux), each as an argv vector through the bounded runner (rung 2), never a shell. Windows and the firewalld and nftables legs are native (rung 1). No network access.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
Neither action takes parameters.
<!-- END GENERATED -->

### Outputs

Pipe-delimited key rows; the first field is the row kind. `state` emits `profile|<Domain|Private|Public>|<enabled|disabled|unknown|error:0x…>` on Windows, and `backend|<name>`, `state|<value>`, optional `mode|block_all` and `pf|<value>` rows on macOS and Linux. `rules` emits `rule|<name>|<enabled|disabled>|<in|out|unknown>|<allow|block|unknown>|<profile mask>` on Windows (plus `truncated|true` after 100 rules), `rule|<raw pf line>` on macOS, and per backend on Linux: `rule|firewalld|<zone>|service|<service>`, `rule|nftables|<family>|<table>|<chain>|<hook>|<policy>` and `rule|nftables|<family>|<table>|<chain>|handle|<n>`, `rule|<index>|<to>|<action>|<from>` for ufw, and `rule|<policy|new_chain|append>|<chain>|<spec>` for iptables — so on Linux the field after `rule` is the backend name for firewalld and nftables, a numeric index for ufw and the entry kind for iptables. A backend that answers `backend|<name>` but whose rule dump is refused emits `rules|unknown`. On Linux, a refused or fd-exhausted nftables read additionally emits an `error|nftables:<dump>:<reason>` or `error|fd_exhausted` row naming the failure, a handed-off-to-the-next-backend dump emits `fallthrough|nftables:<dump>:<reason>`, and the `state` action's rule count emits `ruleset|<n>` when the backend's read genuinely completed or `ruleset|unknown` whenever that read was incomplete or refused — never a fabricated `ruleset|0`. The server parses this plugin as key/value rows (`profile_or_backend`, `state`), so the value column carries the remainder of each row verbatim. Windows rules sharing a display name (one per profile, protocol or direction, e.g. six `ChatGPT` rows) are each real rules, not a capture defect. A run that reads nothing emits no `rule` rows and, for state, `unknown` values; it never fabricates a row.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`security.firewall.rules` — `rule_name|enabled|direction|action|profiles`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `rule_name` | string | - | all | `Core Networking - DNS (UDP-Out)` | The field after "rule". Windows: the rule's display name. Linux: the backend literal "firewalld" (then zone, "service", service name) or "nftables" (then family, table, chain, hook and policy — or "handle" and the handle number); the numbered index for ufw; the entry kind for iptables (policy, new_chain, append; then chain and rule spec). macOS: the raw pf rule line. The server clamps the row to two fields, so the remainder lands in the value column. |
| `enabled` | string | `enabled` `disabled` | Windows | `enabled` | Windows only; enabled or disabled. |
| `direction` | string | `in` `out` `unknown` | Windows | `out` | Windows only; in, out or unknown. |
| `action` | string | `allow` `block` `unknown` | Windows | `allow` | Windows only; allow, block or unknown. |
| `profiles` | string | - | Windows | `2147483647` | Windows only; the NET_FW_PROFILE_TYPE2 bitmask as an integer (1 domain, 2 private, 4 public, 2147483647 all). |

**`security.firewall.state` — `profile_or_backend|state`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `profile_or_backend` | string | `profile` `backend` `state` `mode` `pf` `error` `fallthrough` `ruleset` | all | `profile` | Row key. Windows: "profile" rows carry the profile name in the next field (Domain, Private, Public). Linux and macOS: "backend", "state", "mode" and "pf" rows, one key each. Linux additionally emits "error" rows (a refused or fd-exhausted backend read), "fallthrough" rows (the nftables leg handing off to the next backend after a dump failure), and "ruleset" rows (the rule count, or unknown when that count could not be trusted). |
| `state` | string | - | all | `enabled` | The remainder of the row after the key (the server clamps this plugin to two fields). Windows "profile" rows: the profile name (Domain, Private, Public), then its state (enabled, disabled, unknown or error:<hresult>). Linux "state" rows: running (firewalld), active, inactive or unknown. macOS "state" rows: enabled, disabled or unknown; "pf" rows the same; "mode" row is block_all. "backend" rows name the backend (appfirewall, firewalld, nftables, ufw, iptables, none). Linux "error" rows: nftables:<table\|chain\|rule>:<eperm\|timeout\|foreign_flood\|...> for a refused/failed dump, or fd_exhausted for EMFILE/ENFILE on the nftables socket. Linux "fallthrough" rows: nftables:<table\|chain\|rule>:<reason>, written when a dump fails and the leg hands off to the next backend. Linux "ruleset" rows: the rule count as an integer, or unknown whenever the backend's read was incomplete or refused rather than a fabricated 0. |
<!-- END GENERATED -->

### Result status

The plugin does not call `set_result_status`; every run reports `UNDECLARED`, from which the agent derives `OK` when `execute` returns 0. Degradation is carried in the rows themselves (`unknown`, `error|…`, `backend|none`, `truncated|true`), not in the typed status.

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `OK` (derived from `UNDECLARED`) | — | — | every run that returns 0, including degraded reads |

### Where the data goes

- **Instruction result only.** Rows land in the ResponseStore (90-day default retention), queryable at `/api/responses/{id}`; `security.firewall.state` aggregates by `state` and drives the fleet pie "Firewall profile state across the fleet" (profile rows, labelled by value).
- **Not consumed by** daily-sync inventory, the TAR warehouse, DEX, or metrics. Both definitions carry a gather TTL (120 s and 300 s) but no schedule; they run when dispatched.
- **Sensitivity.** `rules` rows name installed applications on the host (Windows rule display names are application names — an installed-software inventory by another route) and, on Linux, the host's network policy; `state` rows carry nothing beyond the device id.
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("security.firewall.state")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`.
- **Siblings:** `quarantine` (mutates firewall state through its own sudoers-granted `pfctl` anchor and Windows firewall rules), `rdp_control` (toggles the Remote Desktop rule group through `INetFwPolicy2`), `network_config`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Windows 11 Pro 10.0.26200 · bare-metal · 2026-09-07 · interactive user (elevated) · leg-hash 8ef7b004fc8a

```
== action=state
profile|Domain|enabled
profile|Private|enabled
profile|Public|enabled
[result_status] UNDECLARED / UNKNOWN

== action=rules
rule|ChatGPT|enabled|in|allow|2147483647
rule|ChatGPT|enabled|in|allow|2147483647
rule|ChatGPT|enabled|in|allow|2147483647
rule|ChatGPT|enabled|in|allow|2147483647
rule|ChatGPT|enabled|in|allow|2147483647
rule|ChatGPT|enabled|in|allow|2147483647
rule|Microsoft Edge (mDNS-In)|enabled|in|allow|2147483647
rule|Microsoft Edge (mDNS-In)|enabled|in|allow|2147483647
rule|Tailscale-In|enabled|in|allow|3
rule|Tailscale-In|enabled|in|allow|3
rule|Tailscale-Process|enabled|in|allow|2147483647
rule|Microsoft Edge (mDNS-In)|enabled|in|allow|2147483647
… 12 of 101 rows shown
[result_status] UNDECLARED / UNKNOWN
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 · leg-hash 8ef7b004fc8a

```
== action=state
backend|appfirewall
state|disabled
pf|unknown
[result_status] UNDECLARED / UNKNOWN

== action=rules
[result_status] UNDECLARED / UNKNOWN
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-06 · euid 0 with CAP_NET_ADMIN in the host network namespace · leg-hash 8ef7b004fc8a

```
== action=state
backend|nftables
state|active
[result_status] UNDECLARED / UNKNOWN

== action=rules
backend|nftables
rule|nftables|ip|filter|OUTPUT|output|accept
rule|nftables|ip|filter|FORWARD|forward|accept
rule|nftables|ip6|filter|OUTPUT|output|accept
rule|nftables|ip6|filter|FORWARD|forward|accept
rule|nftables|ip|nat|PREROUTING|prerouting|accept
rule|nftables|ip|nat|OUTPUT|output|accept
rule|nftables|ip|nat|POSTROUTING|postrouting|accept
rule|nftables|ip6|nat|PREROUTING|prerouting|accept
rule|nftables|ip6|nat|OUTPUT|output|accept
rule|nftables|ip|raw|PREROUTING|prerouting|accept
rule|nftables|ip|filter|DOCKER-USER|handle|2
… 12 of 55 rows shown
[result_status] UNDECLARED / UNKNOWN
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **Row shape is a key/value contract, not the YAML column list.** `result_parsing.hpp` clamps this plugin to two fields, so a `profile|Domain|enabled` row reaches the dashboard as key `profile`, value `Domain|enabled`. Splitting the value into its own axes is tracked under #626.
2. **macOS rules are the raw pf lines** and the pf reads need root; under the least-privilege model both `pf|` state and the rules list degrade to unknown or empty on purpose.
3. **The Linux unprivileged denial path is measured from the dispatch code, not a live no-cap host capture.** The nftables leg was verified with `CAP_NET_ADMIN` present; on a non-firewalld host without that capability the probe falls through to `ufw`, then `iptables -S`, and a root-only iptables reports `backend|iptables` + `state|unknown`; `backend|none` only when no backend ran at all (neither binary exists, or `ufw` was refused and `iptables` is absent). Tracked for the Linux parity sweep. Linux troubleshooting tokens: `error|nftables:table:eperm` (or `:chain:`/`:rule:`) means the netlink read was refused — grant `CAP_NET_ADMIN` or run `firewalld` instead; `error|nftables:<dump>:timeout` means a dump did not finish inside its per-dump budget, typically a long-running nft transaction holding the table lock; `error|nftables:<dump>:foreign_flood` means another local process is writing to the same netlink family, drowning out the agent's own dump replies.
4. **Windows rules stop at 100.** The `truncated|true` row is emitted only when a genuine 101st rule exists, so a host with exactly 100 rules is not marked truncated.
5. **A mixed fleet shows two macOS shapes.** Agents older than the Application Firewall change report pf as the sole state source (`backend|pf`); current agents report `backend|appfirewall` plus a `pf|` row.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/firewall/src/firewall_parsers.hpp` · `agents/plugins/firewall/src/firewall_plugin.cpp`
- Definitions: `content/definitions/firewall.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_c.hpp`
- Tests: `tests/unit/test_firewall_local_dispatcher.cpp` · `tests/unit/test_firewall_parsers.cpp`
- Privilege row: `docs/agent-privilege-model.md`
- Changelog: `changelog.d/20260716-macos-firewall-alf-primary.fixed.md` · `changelog.d/20260818-wave3-firewall-native-acquisition.changed.md` · `changelog.d/20260818-wave3-firewall-ufw-inactive-misreport.fixed.md` · `changelog.d/20260823-firewall-nftables-netlink.added.md` · `changelog.d/2237-guardian-reconcile-exception-firewall.fixed.md` · `changelog.d/2298-guardian-convergence-lane-firewall.fixed.md` · `changelog.d/3461-firewall-nftables-sender-verify.security.md` · `changelog.d/3462-firewall-nftables-dump-hardening.changed.md`
<!-- END GENERATED -->
