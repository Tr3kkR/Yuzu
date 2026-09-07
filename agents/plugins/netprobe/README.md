# netprobe

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Active network measurement: ICMP/TCP round-trip time, jitter, loss, and DNS resolution timing to operator-chosen targets |
| **Version** | 1.0.0 |
| **Kind** | Collector · read-only · on-demand (no scheduled gather) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux 🟡 constrained (`icmp`) |
| **Actions** | `icmp` (definition `network.probe.icmp`) · `tcp` (definition `network.probe.tcp`) · `dns` (definition `network.probe.dns`) |
| **Security** | securable `Infrastructure` · operation Read · risk Low · dispatch ReadOnly · approval gate none |
| **Roles** | execute: endpoint-admin · author: content-author |
<!-- END GENERATED -->

## How it works

All three actions are native in-process socket work — no shell-out, no subprocess (`netprobe_plugin.cpp:1-65`). `icmp` opens one ICMP session for the whole run, resolves each target to its first IPv4 address only (`netprobe_plugin.cpp:340`), and sends `count` echo requests spaced 200 ms apart (`netprobe_plugin.cpp:79`, `:346-348`); on Windows via `IcmpSendEcho`, on macOS/Linux via an unprivileged `SOCK_DGRAM` ICMP ping socket, which Linux additionally gates on `net.ipv4.ping_group_range` (`netprobe_plugin.cpp:6-11`, `matrix.md`). `tcp` resolves each target to any address family (`AF_UNSPEC`, `netprobe_plugin.cpp:381`) and times a non-blocking `connect()` per sample on the chosen port (default 443). `dns` times one `getaddrinfo` call per name and reports the resolved address count and status. Every action validates and caps the `targets` CSV first (max 4 — `netprobe_plugin.cpp:75`, `netprobe_stats.hpp:118-136`) and rejects each invalid entry individually rather than failing the whole call (`netprobe_plugin.cpp:308-313`).

The plugin deliberately does not schedule its own recurrence or keep history — that is the server scheduler's job against the response store (`content/definitions/netprobe.yaml:1-4`); nor does it shell out to the OS `ping` binary the way the sibling `device.network_actions.ping` does (`content/definitions/network_actions.yaml:74-82`).

```mermaid
flowchart LR
  OP[Operator / workflow<br/>dispatches definition] --> SRV[Server<br/>authz: Infrastructure.Read]
  SRV -- gRPC mTLS --> HOST[Agent plugin host]
  HOST --> EX[netprobe.execute]
  EX --> WIN[Windows leg<br/>IcmpSendEcho icmp<br/>non-blocking connect tcp<br/>getaddrinfo dns]
  EX --> MAC[macOS leg<br/>SOCK_DGRAM ICMP ping socket icmp<br/>non-blocking connect tcp<br/>getaddrinfo dns]
  EX --> LIN[Linux leg<br/>SOCK_DGRAM ICMP ping socket icmp — constrained<br/>non-blocking connect tcp<br/>getaddrinfo dns]
  WIN & MAC & LIN --> ROWS[rtt / dns rows<br/>UNDECLARED result status] --> RS[(ResponseStore)] --> API[REST /api/responses]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `icmp` | ✅ supported · rung 1 · `IcmpSendEcho` | ✅ supported · rung 1 · `SOCK_DGRAM` ICMP ping socket | 🟡 constrained · rung 1 · `SOCK_DGRAM` ICMP ping socket |
| `tcp` | ✅ supported · rung 1 · non-blocking `connect()` timing | ✅ supported · rung 1 · non-blocking `connect()` timing | ✅ supported · rung 1 · non-blocking `connect()` timing |
| `dns` | ✅ supported · rung 1 · `getaddrinfo` | ✅ supported · rung 1 · `getaddrinfo` | ✅ supported · rung 1 · `getaddrinfo` |

**Declared limits per leg** (the descriptor's fallback text, verbatim):

- **`icmp` / Linux** — requires net.ipv4.ping_group_range to admit the process group; reports not-permitted otherwise
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account (LocalSystem today, `docs/agent-privilege-model.md:70`, #1442) | None — `IcmpSendEcho`, `connect()`, and `getaddrinfo` need no elevation | 2026-09-07 as `SYSTEM` (`docs/samples/windows.txt:1`) | n/a — no netprobe action is privilege-gated on Windows |
| macOS | agent daemon, intended unprivileged `_yuzu` account (`docs/agent-privilege-model.md:12`) | None — the ICMP ping socket, `connect()`, and `getaddrinfo` all work unprivileged | 2026-09-07 at euid 501, `alex` (`docs/samples/macos.txt:1`) | n/a — no netprobe action is privilege-gated on macOS |
| Linux | agent daemon, intended unprivileged `yuzu` account (`docs/agent-privilege-model.md:12`) | `icmp` only: the kernel sysctl `net.ipv4.ping_group_range` must admit the agent's process group, or the ping-socket open fails (`matrix.md`, `netprobe_plugin.cpp:229-230`) | 2026-09-07 at euid 0, root, container (`docs/samples/linux.txt:1`) — privileged, so this gate was not exercised | `icmp` row reports `status: not-permitted`, `sent: 0`, `ok: 0`, `loss_pct: 100.0` — never a fabricated loss figure (`netprobe_plugin.cpp:9-11`, `:332-337`); `tcp`/`dns` are unaffected |

No netprobe-specific row exists in `docs/agent-privilege-model.md` (per `privilege.md`); the identities above are the agent's general per-OS account model, cited at the lines shown.

No external binaries or subprocesses (the whole plugin is native socket calls — `::socket`/`::connect`/`::sendto`/`::recv` at `netprobe_plugin.cpp:126,157,228,256,271`; `IcmpSendEcho`/`IcmpCreateFile` on Windows). Network access: outbound ICMP echo, outbound TCP connect, and DNS resolution to the operator-supplied targets only.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
| Action | Parameter | Type | Required | Default | Description |
|---|---|---|---|---|---|
| `icmp` | `targets` | string | yes | - | Comma-separated hostnames or IPv4 literals (max 4), e.g. `10.0.0.1,gateway.corp.example.com`. |
| `icmp` | `count` | int32 | no | 5 | Echo samples per target (1-10, default 5). |
| `icmp` | `timeout_ms` | int32 | no | 1000 | Per-sample timeout in milliseconds (100-3000, default 1000). |
| `tcp` | `targets` | string | yes | - | Comma-separated hostnames or IP literals (max 4), e.g. `10.0.0.1,vpn-gw.corp.example.com`. |
| `tcp` | `port` | int32 | no | 443 | TCP port to connect to (default 443; clamped 1-65535). |
| `tcp` | `count` | int32 | no | 5 | Connect samples per target (1-10, default 5). |
| `tcp` | `timeout_ms` | int32 | no | 1000 | Per-sample timeout in milliseconds (100-3000, default 1000). |
| `dns` | `targets` | string | yes | - | Comma-separated DNS names to resolve (max 4), e.g. `example.com,internal.corp.local`. |
<!-- END GENERATED -->

### Outputs

Pipe-delimited rows. `icmp` and `tcp` share one row shape with a literal `rtt` discriminator (the `proto` field, not the row prefix, tells them apart); `dns` uses its own `dns`-prefixed row. An invalid target still emits one row (never dropped silently) with the sanitized target string, zeroed timing fields, and a `status` naming why (`netprobe_plugin.cpp:294-306`).

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`icmp` — `rtt|target|proto|sent|ok|min_ms|avg_ms|max_ms|jitter_ms|loss_pct|status`**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `target` | string | free text (hostname or IPv4 literal, or the sanitized value on an invalid target) | W, M, L | `127.0.0.1` |
| `proto` | string | literal `icmp` | W, M, L | `icmp` |
| `sent` | int32 | integer 0-10 (the clamped `count`, or 0 if no session/invalid target) | W, M, L | `5` |
| `ok` | int32 | integer 0-sent | W, M, L | `5` |
| `min_ms` | string | 1-decimal milliseconds | W, M, L | `0.1` |
| `avg_ms` | string | 1-decimal milliseconds | W, M, L | `0.1` |
| `max_ms` | string | 1-decimal milliseconds | W, M, L | `0.2` |
| `jitter_ms` | string | 1-decimal milliseconds, population stddev of successful samples (`netprobe_stats.hpp:36-61`) | W, M, L | `0.0` |
| `loss_pct` | string | 1-decimal percentage, 0.0-100.0 | W, M, L | `0.0` |
| `status` | string | `ok`, `invalid-target`, `resolve-failed`, `error`, `not-permitted` (Linux only, ping-socket refused) | W, M, L | `ok` |

**`tcp` — `rtt|target|proto|sent|ok|min_ms|avg_ms|max_ms|jitter_ms|loss_pct|status`**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `target` | string | free text (hostname or IP literal, or the sanitized value on an invalid target) | W, M, L | `127.0.0.1` |
| `proto` | string | `tcp:<port>` | W, M, L | `tcp:22` |
| `sent` | int32 | integer 0-10 (the clamped `count`, or 0 if resolve failed/invalid target) | W, M, L | `5` |
| `ok` | int32 | integer 0-sent | W, M, L | `5` |
| `min_ms` | string | 1-decimal milliseconds | W, M, L | `0.3` |
| `avg_ms` | string | 1-decimal milliseconds | W, M, L | `0.3` |
| `max_ms` | string | 1-decimal milliseconds | W, M, L | `0.4` |
| `jitter_ms` | string | 1-decimal milliseconds, population stddev of successful samples (`netprobe_stats.hpp:36-61`) | W, M, L | `0.0` |
| `loss_pct` | string | 1-decimal percentage, 0.0-100.0 | W, M, L | `0.0` |
| `status` | string | `ok`, `invalid-target`, `resolve-failed` — `ok` means the probe ran to completion, not that every sample connected (see Caveats #1) | W, M, L | `ok` |

**`dns` — `dns|name|resolve_ms|status|addresses`**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `name` | string | free text DNS name (or the sanitized value on an invalid target) | W, M, L | `localhost` |
| `resolve_ms` | string | 1-decimal milliseconds | W, M, L | `2.9` |
| `status` | string | `ok`, `invalid-target`, `error:<getaddrinfo return code>` | W, M, L | `ok` |
| `addresses` | int32 | count of addresses `getaddrinfo` returned; 0 on failure or invalid target | W, M, L | `2` |
<!-- END GENERATED -->

### Result status

This plugin does not set a typed result status; the agent records `UNDECLARED` and every sample shows `UNDECLARED / UNKNOWN /` for every action on every OS (see Sample output).

### Where the data goes

- **Instruction result only.** Rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore, queryable at `/api/responses/{id}`.
- **Not consumed by** daily-sync inventory, the TAR warehouse, DEX, or metrics (no reference to `netprobe` or `network.probe.*` anywhere under `server/` outside the plugin catalogue and descriptor summary map, `server/core/src/agent_registry.cpp:830-833`). Recurrence/trending is the server scheduler's job, not this plugin's (`content/definitions/netprobe.yaml:1-4`).
- **Siblings:** `device.network_actions.ping` — a one-shot ICMP reachability check that shells out to the OS `ping` binary and streams its raw text output (`content/definitions/network_actions.yaml:74-82`), unlike netprobe's native, structured, no-shell-out RTT/jitter/loss rows. Both ship in the same #2204 network/security plugin declaration group alongside `netstat`, `discovery`, `wifi`, `wol`, `http_client`, `certificates`, `firewall`, and `quarantine` (`changelog.d/2204-declarations-group-c.added.md`).
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("network.probe.icmp")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash pending

```
== action=icmp targets=127.0.0.1
rtt|127.0.0.1|icmp|5|5|0.0|0.0|0.0|0.0|0.0|ok
[result_status] UNDECLARED / UNKNOWN / 

== action=tcp targets=127.0.0.1 port=22
rtt|127.0.0.1|tcp:22|5|5|0.3|0.3|0.4|0.0|0.0|ok
[result_status] UNDECLARED / UNKNOWN / 

== action=dns targets=localhost
dns|localhost|2.8|ok|2
[result_status] UNDECLARED / UNKNOWN / 
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (alex) · leg-hash pending

```
== action=icmp targets=127.0.0.1
rtt|127.0.0.1|icmp|5|5|0.0|0.1|0.1|0.0|0.0|ok
[result_status] UNDECLARED / UNKNOWN / 

== action=tcp targets=127.0.0.1 port=22
rtt|127.0.0.1|tcp:22|5|5|0.0|0.1|0.1|0.0|0.0|ok
[result_status] UNDECLARED / UNKNOWN / 

== action=dns targets=localhost
dns|localhost|0.9|ok|2
[result_status] UNDECLARED / UNKNOWN / 
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-07 · euid 0 · leg-hash pending

```
== action=icmp targets=127.0.0.1
rtt|127.0.0.1|icmp|5|5|0.0|0.1|0.2|0.0|0.0|ok
[result_status] UNDECLARED / UNKNOWN / 

== action=tcp targets=127.0.0.1 port=22
rtt|127.0.0.1|tcp:22|5|0|0.0|0.0|0.0|0.0|100.0|ok
[result_status] UNDECLARED / UNKNOWN / 

== action=dns targets=localhost
dns|localhost|0.4|ok|2
[result_status] UNDECLARED / UNKNOWN /
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **`status: ok` means the probe ran to completion, not that every sample connected — read it together with `loss_pct`.** `tcp` (and `icmp`) write `status: ok` unconditionally once a session opened and the target resolved (`netprobe_plugin.cpp:359`, `:394`), regardless of how many samples actually succeeded. The Linux `tcp` capture against `127.0.0.1 port=22` (no sshd in the capture container) shows this directly: `rtt|127.0.0.1|tcp:22|5|0|0.0|0.0|0.0|0.0|100.0|ok` — all 5 connect attempts failed fast (`ok: 0`, `loss_pct: 100.0`), yet `status` still reads `ok`. Windows and macOS, which do have something listening on 22, show `ok: 5`/`loss_pct: 0.0` for the same capture (`rtt|127.0.0.1|tcp:22|5|5|0.3|0.3|0.4|0.0|0.0|ok` and `…|0.0|0.1|0.1|0.0|0.0|ok`). The `targets` grammar itself is comma-separated hostnames/IPv4 literals only — no embedded port (`valid_probe_target`, `netprobe_stats.hpp:83-93`, rejects `:`); the port is the separate `port` parameter (default 443), as all three samples now correctly demonstrate.
2. **The Linux `icmp` leg is honestly gated, never fakes loss.** When the kernel refuses the unprivileged `SOCK_DGRAM` ICMP socket (`net.ipv4.ping_group_range` doesn't admit the process group), the row reports `status: not-permitted` with `sent: 0`/`loss_pct: 100.0` rather than a fabricated 100% loss figure (`netprobe_plugin.cpp:9-11`, `:229-230`, `:332-337`). The Linux sample was captured as root (euid 0) and so did not exercise this path.
3. **`icmp` is IPv4-only; `tcp`/`dns` resolve any family.** `icmp` forces `AF_INET` (`netprobe_plugin.cpp:340`, comment "IPv4 only this slice"); `tcp` resolves `AF_UNSPEC` (`netprobe_plugin.cpp:381`). A target with only an IPv6 address succeeds on `tcp`/`dns` but fails `icmp` with `resolve-failed`. IPv6 for `icmp` is a tracked follow-up (`netprobe_plugin.cpp:11`).
4. **Windows ICMP RTT is whole-millisecond only.** `IcmpSendEcho`'s `RoundTripTime` is a whole-ms value by API design (`netprobe_plugin.cpp:184-186`) — a sub-millisecond LAN hop reads `0.0`; use `tcp` for sub-ms fidelity on Windows.
5. **No action-level deadline, only per-sample.** Each sample is bounded by `timeout_ms` (100-3000 ms) plus a fixed 200 ms inter-sample gap, run strictly sequentially (`netprobe_plugin.cpp:79`, `:346-348`, `:388-390`); worst case is about 2 minutes at maximum targets/samples/timeout (`netprobe_plugin.cpp:16-18`), but nothing bounds the sum beyond that arithmetic.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/netprobe/src/netprobe_plugin.cpp` (descriptor, actions, execute) · `netprobe_stats.hpp` (pure stats/validation helpers) · `meson.build`
- Definitions: `content/definitions/netprobe.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_c.hpp`
- Tests: `tests/unit/test_netprobe_stats.cpp` (9 cases, pure-function only — the socket shell is not unit-tested)
- Privilege row: no row in `docs/agent-privilege-model.md`
- Changelog: `changelog.d/2204-declarations-group-c.added.md`
<!-- END GENERATED -->
