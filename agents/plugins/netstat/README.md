# netstat

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Enumerates active network connections and listening sockets |
| **Version** | 1.0.0 |
| **Kind** | Collector · read-only · on-demand (no scheduled gather) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux ✅ |
| **Actions** | `netstat_list` (definition `device.network.netstat_list`) · `attribution` (definition `device.network.netstat_attribution`) |
| **Security** | securable `Infrastructure` · operation Read · risk Low · dispatch ReadOnly · approval gate none |
| **Roles** | execute: endpoint-admin, endpoint-operator · author: content-author |
<!-- END GENERATED -->

## How it works

`netstat_list` enumerates active TCP/UDP connections and listening sockets, returning protocol, local/remote address and port, connection state, and owning PID. `attribution` runs the same enumeration and additionally resolves the owning process's name and executable path — this is the retired `sockwho` plugin's functionality, folded in as netstat's second action (#3403). `attribution` emits `netstat_list`'s 7 fields as a prefix with `process_name`/`process_path` appended (9 total); `pid` stays in its `netstat_list` position (6th field), not sockwho's old 1st-column layout.

On macOS both actions walk the same shared `agents/shared/macos_socket_walk.hpp` libproc enumeration with `dedup=true`, so a socket shared across a fork (multiple PIDs holding the same fd) collapses to one row — a deliberate match to `netstat_list`'s semantics, and a deliberate *difference* from the retired `sockwho`, which emitted one row per (pid, fd). On Linux, `attribution` builds its inode→PID and PID→process maps in one `/proc` scan rather than reusing `netstat_list`'s separate scan. On Windows, `attribution` resolves each owning PID via `QueryFullProcessImageNameW`, cached per PID for the duration of one call. `escape_pipes()` (`netstat_parsers.hpp`) escapes `|` and strips CR/LF from `process_name`/`process_path` so an attacker-controlled process name can't split one row into extra server-visible lines.

Neither action takes parameters, sets a typed result status, filters by protocol/state, or schedules itself — both are one-shot, unfiltered reads dispatched on demand.

```mermaid
flowchart LR
  OP[Operator / workflow<br/>dispatches definition] --> SRV[Server<br/>authz: Infrastructure.Read]
  SRV -- gRPC mTLS --> HOST[Agent plugin host]
  HOST --> EX[netstat.execute]
  EX --> WIN[Windows leg<br/>GetExtendedTcpTable/UdpTable<br/>+ QueryFullProcessImageNameW]
  EX --> MAC[macOS leg<br/>libproc via macos_socket_walk.hpp]
  EX --> LIN[Linux leg<br/>/proc/net/tcp,udp[6] + /proc/pid/fd]
  WIN & MAC & LIN --> ROWS[pipe rows,<br/>UNDECLARED result status]
  ROWS -- CommandResponse --> RS[(ResponseStore<br/>90-day retention)]
  RS --> API[REST /api/responses · dashboard table]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `netstat_list` | ✅ supported · rung 1 · `GetExtendedTcpTable`/`GetExtendedUdpTable` | ✅ supported · rung 1 · libproc | ✅ supported · rung 1 · `/proc/net/{tcp,udp}[6]` |
| `attribution` | ✅ supported · rung 1 · IP Helper API + `QueryFullProcessImageNameW` | ✅ supported · rung 1 · libproc | ✅ supported · rung 1 · `/proc/net/*` + `/proc/[pid]/{comm,exe,fd}` |

**Declared limits per leg** (the descriptor's fallback text, verbatim):

None — every leg above is declared supported at rung 1 with no fallback text (`kActionDescriptors`, `netstat_plugin.cpp:806-822`; `matrix.md`).
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | LocalSystem today (#1442); intended target is `NT SERVICE\YuzuAgent` | None — `GetExtendedTcpTable`/`GetExtendedUdpTable` and `QueryFullProcessImageNameW(PROCESS_QUERY_LIMITED_INFORMATION)` need no elevation | 2026-09-07, bare metal, as SYSTEM | No typed error path: a table-query failure (return code other than `NO_ERROR`/`ERROR_INSUFFICIENT_BUFFER`) or a failed `QueryFullProcessImageNameW` is swallowed — the call returns with whatever rows it already emitted, or an attribution row with empty `process_name`/`process_path` (see `tcp|192.168.0.131|139|0.0.0.0|0|LISTEN|4||` in the Windows sample below, PID 4) |
| macOS | root — the LaunchDaemon has no `UserName` key (#1455 tracks narrowing this) | None beyond the agent's actual (root) identity; libproc reads need no separate entitlement | 2026-09-07, bare metal, at euid 501 (alex) — captured unprivileged, not as the production root daemon | `walk_sockets`/`resolve_proc_name_path` silently skip a PID libproc can't inspect (`proc_pidinfo`/`proc_name`/`proc_pidpath` returning ≤0); the socket, or its process fields, is simply omitted — never a typed status |
| Linux | dedicated unprivileged `_yuzu`/`yuzu` account (`docs/agent-privilege-model.md:95`, `netstat.*` row: default/default/default) | None declared — but see Caveats: `/proc/[pid]/fd` on another user's process needs a matching uid or `CAP_SYS_PTRACE`, which the "default" grant does not include | 2026-09-06, container, at euid 0 (root) — captured privileged, not as the least-privilege agent | `opendir()`/`ifstream` failures return silently (`if (!fd_dir) continue;` / `if (!f) return;`, `netstat_plugin.cpp:164-165,197-198`); an unresolved socket's `pid` stays `-1` (netstat_list) or its `process_name`/`process_path` stay empty (attribution) — never a typed status |

No external binaries, no subprocesses, no sockets of its own — every leg reads OS-supplied tables/files or calls native Win32/libproc APIs directly (`netstat_plugin.cpp` has no `popen`/`CreateProcess`/`system(`/`exec*` call).

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
`netstat_list` takes no parameters.

`attribution` takes no parameters.
<!-- END GENERATED -->

### Outputs

Pipe-delimited rows, one per socket, written via `ctx.write_output()`. `netstat_list` emits 7 fields; `attribution` emits the same 7 as a prefix with `process_name`/`process_path` appended (9 total). A leg that finds no connections emits zero rows and sets no status — there is no one-row placeholder convention here (contrast `disk_actions`); an empty action block in the sample output below means the host genuinely had nothing to report at capture time.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`netstat_list` — `proto|local_addr|local_port|remote_addr|remote_port|state|pid`**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `proto` | string | `tcp` `tcp6` `udp` `udp6` | W, M, L | `tcp` |
| `local_addr` | string | IPv4 or IPv6 address | W, M, L | `100.109.177.77` |
| `local_port` | int32 | 0–65535 | W, M, L | `52882` |
| `remote_addr` | string | IPv4/IPv6 address, or the literal `*` for a UDP row on macOS/Windows; Linux instead reports the real (usually `0.0.0.0`) value parsed from `/proc/net/udp*` | W, M, L | `100.123.53.121` |
| `remote_port` | int32 | 0–65535; always `0` for UDP | W, M, L | `22` |
| `state` | string | TCP state name, or empty for UDP (never a fabricated `LISTEN`); the exact name set differs slightly per OS — `CLOSE` is Linux-only, `DELETE_TCB` is Windows-only, plain `CLOSED` does not occur on Linux | W, M, L | `ESTABLISHED` |
| `pid` | int32 | owning PID, or `-1` (Linux only) when no `/proc/[pid]/fd` inode matched the socket | W, M, L | `9653` |

**`attribution` — `proto|local_addr|local_port|remote_addr|remote_port|state|pid|process_name|process_path`**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `proto` | string | `tcp` `tcp6` `udp` `udp6` | W, M, L | `tcp` |
| `local_addr` | string | IPv4 or IPv6 address | W, M, L | `100.109.177.77` |
| `local_port` | int32 | 0–65535 | W, M, L | `52882` |
| `remote_addr` | string | IPv4/IPv6 address, or the literal `*` for a UDP row on macOS/Windows; Linux instead reports the real (usually `0.0.0.0`) value parsed from `/proc/net/udp*` | W, M, L | `100.123.53.121` |
| `remote_port` | int32 | 0–65535; always `0` for UDP | W, M, L | `22` |
| `state` | string | TCP state name, or empty for UDP | W, M, L | `ESTABLISHED` |
| `pid` | int32 | owning PID, or `-1` (Linux only) when unresolved | W, M, L | `9653` |
| `process_name` | string | free text, escaped for `\|`/CR/LF, or empty when unresolved | W, M, L | `ssh` |
| `process_path` | string | absolute path, escaped for `\|`/CR/LF, or empty when unresolved | W, M, L | `/usr/bin/ssh` |
<!-- END GENERATED -->

### Result status

This plugin does not set a typed result status; the agent records `UNDECLARED` and the sample shows `UNDECLARED / UNKNOWN /` (no `set_result_status`/`yuzu_ctx_set_result_status` call anywhere in `netstat_plugin.cpp`).

### Where the data goes

- **Instruction result only.** Rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore (90-day default retention — `docs/yaml-dsl-spec.md:194`, `response_store.hpp:167`), queryable at `/api/responses/{id}` and dashboard-rendered: `netstat_list` uses a static 8-column schema (`result_parsing.hpp:56`), while `attribution`'s 9-column schema is resolved from the content-definition `result` schema instead of a static entry (`result_parsing.hpp:50-55`).
- **Not consumed by** daily-sync inventory, the TAR warehouse, DEX, or metrics — grepping `server/` and `agents/plugins/tar/` for `netstat` finds only the dashboard-schema and command-catalogue sites above; nothing runs on a schedule.
- **Siblings:** `network_diag` (connection/socket diagnostics), `netprobe` (active reachability probes), the retired `sockwho` (folded into `attribution`, #3403).
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("device.network.netstat_attribution")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash pending

```
== action=netstat_list
tcp|0.0.0.0|22|0.0.0.0|0|LISTEN|5148
tcp|100.123.53.121|22|100.109.177.77|53137|ESTABLISHED|5148
tcp|0.0.0.0|135|0.0.0.0|0|LISTEN|1008
tcp|192.168.0.131|139|0.0.0.0|0|LISTEN|4
tcp|0.0.0.0|3389|0.0.0.0|0|LISTEN|9048
tcp|0.0.0.0|5040|0.0.0.0|0|LISTEN|14216
tcp|127.0.0.1|5432|0.0.0.0|0|LISTEN|6436
tcp|127.0.0.1|5432|127.0.0.1|49748|ESTABLISHED|6436
tcp|127.0.0.1|5432|127.0.0.1|49749|ESTABLISHED|6436
tcp|127.0.0.1|5432|127.0.0.1|50169|ESTABLISHED|6436
tcp|0.0.0.0|8080|0.0.0.0|0|LISTEN|13676
tcp|127.0.0.1|8080|127.0.0.1|49754|ESTABLISHED|13676
tcp|0.0.0.0|8099|0.0.0.0|0|LISTEN|13800
tcp|0.0.0.0|49664|0.0.0.0|0|LISTEN|1740
tcp|0.0.0.0|49665|0.0.0.0|0|LISTEN|1596
tcp|0.0.0.0|49666|0.0.0.0|0|LISTEN|2448
tcp|0.0.0.0|49667|0.0.0.0|0|LISTEN|3352
tcp|0.0.0.0|49668|0.0.0.0|0|LISTEN|4512
tcp|192.168.0.131|49673|34.141.96.57|7500|ESTABLISHED|5036
tcp|0.0.0.0|49676|0.0.0.0|0|LISTEN|10096
tcp|0.0.0.0|49706|0.0.0.0|0|LISTEN|1676
tcp|192.168.0.131|49708|199.165.136.100|443|ESTABLISHED|5808
tcp|127.0.0.1|49748|127.0.0.1|5432|ESTABLISHED|13676
tcp|127.0.0.1|49749|127.0.0.1|5432|ESTABLISHED|13676
tcp|127.0.0.1|49750|127.0.0.1|49751|ESTABLISHED|13800
… 25 of 97 rows
[result_status] UNDECLARED / UNKNOWN / 

== action=attribution
tcp|0.0.0.0|22|0.0.0.0|0|LISTEN|5148|sshd.exe|C:\Windows\System32\OpenSSH\sshd.exe
tcp|100.123.53.121|22|100.109.177.77|53137|ESTABLISHED|5148|sshd.exe|C:\Windows\System32\OpenSSH\sshd.exe
tcp|0.0.0.0|135|0.0.0.0|0|LISTEN|1008|svchost.exe|C:\Windows\System32\svchost.exe
tcp|192.168.0.131|139|0.0.0.0|0|LISTEN|4||
tcp|0.0.0.0|3389|0.0.0.0|0|LISTEN|9048|svchost.exe|C:\Windows\System32\svchost.exe
tcp|0.0.0.0|5040|0.0.0.0|0|LISTEN|14216|svchost.exe|C:\Windows\System32\svchost.exe
tcp|127.0.0.1|5432|0.0.0.0|0|LISTEN|6436|postgres.exe|C:\Program Files\PostgreSQL\18\bin\postgres.exe
tcp|127.0.0.1|5432|127.0.0.1|50169|ESTABLISHED|6436|postgres.exe|C:\Program Files\PostgreSQL\18\bin\postgres.exe
tcp|127.0.0.1|5432|127.0.0.1|49749|ESTABLISHED|6436|postgres.exe|C:\Program Files\PostgreSQL\18\bin\postgres.exe
tcp|127.0.0.1|5432|127.0.0.1|49748|ESTABLISHED|6436|postgres.exe|C:\Program Files\PostgreSQL\18\bin\postgres.exe
tcp|0.0.0.0|8080|0.0.0.0|0|LISTEN|13676|yuzu-server.exe|C:\yuzu-rig\yuzu-0.13.0-windows-x64\bin\yuzu-server.exe
tcp|127.0.0.1|8080|127.0.0.1|49754|ESTABLISHED|13676|yuzu-server.exe|C:\yuzu-rig\yuzu-0.13.0-windows-x64\bin\yuzu-server.exe
tcp|0.0.0.0|8099|0.0.0.0|0|LISTEN|13800|python.exe|C:\Users\Alex\AppData\Local\Programs\Python\Python312\python.exe
tcp|0.0.0.0|49664|0.0.0.0|0|LISTEN|1740|lsass.exe|C:\Windows\System32\lsass.exe
tcp|0.0.0.0|49665|0.0.0.0|0|LISTEN|1596|wininit.exe|C:\Windows\System32\wininit.exe
tcp|0.0.0.0|49666|0.0.0.0|0|LISTEN|2448|svchost.exe|C:\Windows\System32\svchost.exe
tcp|0.0.0.0|49667|0.0.0.0|0|LISTEN|3352|svchost.exe|C:\Windows\System32\svchost.exe
tcp|0.0.0.0|49668|0.0.0.0|0|LISTEN|4512|spoolsv.exe|C:\Windows\System32\spoolsv.exe
tcp|192.168.0.131|49673|34.141.96.57|7500|ESTABLISHED|5036|CCleaner_service.exe|C:\Program Files\Piriform\CCleaner 7\CCleaner_service.exe
tcp|0.0.0.0|49676|0.0.0.0|0|LISTEN|10096|svchost.exe|C:\Windows\System32\svchost.exe
tcp|0.0.0.0|49706|0.0.0.0|0|LISTEN|1676|services.exe|C:\Windows\System32\services.exe
tcp|192.168.0.131|49708|199.165.136.100|443|ESTABLISHED|5808|tailscaled.exe|C:\Program Files\Tailscale\tailscaled.exe
tcp|127.0.0.1|49748|127.0.0.1|5432|ESTABLISHED|13676|yuzu-server.exe|C:\yuzu-rig\yuzu-0.13.0-windows-x64\bin\yuzu-server.exe
tcp|127.0.0.1|49749|127.0.0.1|5432|ESTABLISHED|13676|yuzu-server.exe|C:\yuzu-rig\yuzu-0.13.0-windows-x64\bin\yuzu-server.exe
tcp|127.0.0.1|49750|127.0.0.1|49751|ESTABLISHED|13800|python.exe|C:\Users\Alex\AppData\Local\Programs\Python\Python312\python.exe
… 25 of 97 rows
[result_status] UNDECLARED / UNKNOWN / 
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (alex) · leg-hash pending

```
== action=netstat_list
tcp|100.109.177.77|52882|100.123.53.121|22|ESTABLISHED|9653
tcp|192.168.0.66|52771|160.79.104.10|443|ESTABLISHED|9039
tcp|192.168.0.66|52775|160.79.104.10|443|ESTABLISHED|9039
tcp|192.168.0.66|52773|160.79.104.10|443|ESTABLISHED|9039
tcp|192.168.0.66|52789|160.79.104.10|443|ESTABLISHED|9039
tcp|192.168.0.66|52801|34.149.66.165|443|ESTABLISHED|9039
tcp|192.168.0.66|52777|160.79.104.10|443|ESTABLISHED|9039
tcp|192.168.0.66|52779|160.79.104.10|443|ESTABLISHED|9039
tcp|192.168.0.66|52781|160.79.104.10|443|ESTABLISHED|9039
tcp|192.168.0.66|52856|160.79.104.10|443|ESTABLISHED|9039
tcp|192.168.0.66|52783|160.79.104.10|443|ESTABLISHED|9039
tcp|192.168.0.66|52785|160.79.104.10|443|ESTABLISHED|9039
tcp|192.168.0.66|52744|160.79.104.10|443|ESTABLISHED|9001
tcp|192.168.0.66|52748|160.79.104.10|443|ESTABLISHED|9001
tcp|192.168.0.66|52746|160.79.104.10|443|ESTABLISHED|9001
tcp|192.168.0.66|52760|160.79.104.10|443|ESTABLISHED|9001
tcp|192.168.0.66|52791|160.79.104.10|443|ESTABLISHED|9001
tcp|192.168.0.66|52887|160.79.104.10|443|ESTABLISHED|9001
tcp|192.168.0.66|52750|160.79.104.10|443|ESTABLISHED|9001
tcp|192.168.0.66|52890|160.79.104.10|443|ESTABLISHED|9001
tcp|192.168.0.66|52754|160.79.104.10|443|ESTABLISHED|9001
tcp|192.168.0.66|52892|160.79.104.10|443|ESTABLISHED|9001
tcp|192.168.0.66|52756|160.79.104.10|443|ESTABLISHED|9001
tcp|192.168.0.66|52758|160.79.104.10|443|ESTABLISHED|9001
tcp|192.168.0.66|52721|160.79.104.10|443|ESTABLISHED|8979
… 25 of 105 rows
[result_status] UNDECLARED / UNKNOWN / 

== action=attribution
tcp|100.109.177.77|52882|100.123.53.121|22|ESTABLISHED|9653|ssh|/usr/bin/ssh
tcp|192.168.0.66|52771|160.79.104.10|443|ESTABLISHED|9039|claude|/Users/alex/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|192.168.0.66|52775|160.79.104.10|443|ESTABLISHED|9039|claude|/Users/alex/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|192.168.0.66|52773|160.79.104.10|443|ESTABLISHED|9039|claude|/Users/alex/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|192.168.0.66|52789|160.79.104.10|443|ESTABLISHED|9039|claude|/Users/alex/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|192.168.0.66|52801|34.149.66.165|443|ESTABLISHED|9039|claude|/Users/alex/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|192.168.0.66|52777|160.79.104.10|443|ESTABLISHED|9039|claude|/Users/alex/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|192.168.0.66|52779|160.79.104.10|443|ESTABLISHED|9039|claude|/Users/alex/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|192.168.0.66|52781|160.79.104.10|443|ESTABLISHED|9039|claude|/Users/alex/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|192.168.0.66|52856|160.79.104.10|443|ESTABLISHED|9039|claude|/Users/alex/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|192.168.0.66|52783|160.79.104.10|443|ESTABLISHED|9039|claude|/Users/alex/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|192.168.0.66|52785|160.79.104.10|443|ESTABLISHED|9039|claude|/Users/alex/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|192.168.0.66|52744|160.79.104.10|443|ESTABLISHED|9001|claude|/Users/alex/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|192.168.0.66|52748|160.79.104.10|443|ESTABLISHED|9001|claude|/Users/alex/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|192.168.0.66|52746|160.79.104.10|443|ESTABLISHED|9001|claude|/Users/alex/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|192.168.0.66|52760|160.79.104.10|443|ESTABLISHED|9001|claude|/Users/alex/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|192.168.0.66|52791|160.79.104.10|443|ESTABLISHED|9001|claude|/Users/alex/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|192.168.0.66|52887|160.79.104.10|443|ESTABLISHED|9001|claude|/Users/alex/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|192.168.0.66|52750|160.79.104.10|443|ESTABLISHED|9001|claude|/Users/alex/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|192.168.0.66|52890|160.79.104.10|443|ESTABLISHED|9001|claude|/Users/alex/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|192.168.0.66|52754|160.79.104.10|443|ESTABLISHED|9001|claude|/Users/alex/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|192.168.0.66|52892|160.79.104.10|443|ESTABLISHED|9001|claude|/Users/alex/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|192.168.0.66|52756|160.79.104.10|443|ESTABLISHED|9001|claude|/Users/alex/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|192.168.0.66|52758|160.79.104.10|443|ESTABLISHED|9001|claude|/Users/alex/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
tcp|192.168.0.66|52721|160.79.104.10|443|ESTABLISHED|8979|claude|/Users/alex/.vscode/extensions/anthropic.claude-code-2.1.263-darwin-arm64/resources/native-binary/claude
… 25 of 105 rows
[result_status] UNDECLARED / UNKNOWN / 
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-06 · euid 0 · leg-hash pending

```
== action=netstat_list
[result_status] UNDECLARED / UNKNOWN / 

== action=attribution
[result_status] UNDECLARED / UNKNOWN / 
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **UDP's remote address is not the same sentinel on every OS.** macOS and Windows report the literal `*` with `remote_port=0` for a UDP row (`macos_socket_walk.hpp:181,185`; `netstat_plugin.cpp:579,606`). Linux instead runs UDP rows through the same parser as TCP (`netstat_plugin.cpp:203-249`), so it reports the real value parsed from `/proc/net/udp*` — normally `0.0.0.0`, not `*`. The Linux sample below has no UDP rows to demonstrate this; it follows from the shared code path.
2. **The Linux capture returned zero rows for both actions.** `docs/samples/linux.txt` was taken in a container with no active TCP/UDP connections at capture time (`euid 0`, i.e. privileged) — this is an empty result, not a failure; the plugin has no placeholder-row convention (see Outputs) so an idle host legitimately shows nothing.
3. **`/proc/[pid]/fd` access on Linux is per-owner, not blanket-readable.** `build_inode_to_pid_map`/`build_socket_and_proc_maps` silently skip a PID whose `fd` directory they can't open (`netstat_plugin.cpp:163-165,311-313`); under the agent's default (non-root) Linux identity, sockets owned by other users resolve `pid=-1` in `netstat_list` and empty `process_name`/`process_path` in `attribution`, with no status flagging the gap. The captured sample ran as root in a container and can't show this.
4. **TCP state name sets differ slightly per OS.** Linux's `tcp_state_str` has no `CLOSED`; Windows's `tcp_state_str_win` alone has `DELETE_TCB`; only Linux has a plain `CLOSE` (`netstat_plugin.cpp:76-103,453-482`; `macos_socket_walk.hpp:54-82`). A consumer matching on exact state strings across a mixed fleet should treat the set as a per-OS union, not one fixed enum.
5. **`attribution`'s macOS dedup is deliberate, not inherited by accident.** `enumerate_and_stream_attribution` explicitly passes `dedup=true` to match `netstat_list`'s semantics; the retired `sockwho` used the opposite (one row per fd-holder). Do not revert this to `dedup=false` to restore sockwho's old shape (`netstat_plugin.cpp:429-435`).

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/netstat/src/netstat_plugin.cpp` (descriptor, all three OS legs) · `netstat_parsers.hpp` (`escape_pipes`, pure/unit-tested)
- Definitions: `content/definitions/netstat.yaml` (`netstat_list`) · `content/definitions/netstat_attribution.yaml` (`attribution`)
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_c.hpp:147-165`
- Tests: `tests/unit/test_netstat_parsers.cpp` (`escape_pipes`, portable) · `tests/unit/agent/test_netstat_attribution.cpp` (macOS-only, loads the built plugin via `PluginHandle::load` + `LocalDispatcher`)
- Privilege row: `docs/agent-privilege-model.md:95` (`netstat.*`)
- Changelog: `changelog.d/3403-netstat-attribution-action.added.md` · `changelog.d/3403-sockwho-plugin-retired.removed.md` · `changelog.d/2204-declarations-group-c.added.md` · `changelog.d/20260819-wave3-pr31-syscall-promotion.changed.md`
<!-- END GENERATED -->
