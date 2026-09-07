# agent_actions

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Agent runtime actions — set log level, query agent info |
| **Version** | 0.1.0 |
| **Kind** | Action · mixed: `set_log_level` mutating (Reversible) / `info` read-only · on-demand (`info` gather TTL 300 s, `set_log_level` TTL 0) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux ✅ |
| **Actions** | `set_log_level` (definition `device.agent_actions.set_log_level`) · `info` (definition `device.agent_actions.info`) |
| **Security** | securable `Infrastructure` · `set_log_level`: operation Write · risk Medium · dispatch Mutating · approval gate None · `info`: operation Read · risk Low · dispatch ReadOnly · approval gate None |
| **Roles** | execute: `set_log_level` → endpoint-admin · `info` → endpoint-admin, endpoint-operator · author (both): content-author |
<!-- END GENERATED -->

## How it works

`set_log_level` reads the required `level` parameter, lowercases it, and validates it through spdlog's own `from_str` before calling `spdlog::set_level()` in-process — no OS call, no subprocess. On success it writes two `key|value` lines, `status|ok` then `level|<normalized>`; on a missing or unrecognized level it instead writes a single `error|<message>` line and returns 1, never touching the `status`/`level` shape. `info` reads five `agent.*` keys from the agent's config context and echoes each as `key|value`, substituting the literal `(not set)` for anything unpopulated. Both actions run identically on Windows, macOS, and Linux — the descriptor declares the same `spdlog_runtime`/`agent_config_read` mechanism at rung 1 on all three legs, because neither reaches the OS. The plugin deliberately is not a log reader or shipper: it only changes the live logger's verbosity and reads config already held in memory — no file writes, no subprocesses, no network.

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: Infrastructure.Write or .Read]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[agent_actions.execute]
  EX --> WIN[Windows leg<br/>spdlog_runtime / agent_config_read]
  EX --> MAC[macOS leg<br/>spdlog_runtime / agent_config_read]
  EX --> LIN[Linux leg<br/>spdlog_runtime / agent_config_read]
  WIN & MAC & LIN --> ROWS[key|value rows] --> RS[(ResponseStore)] --> API[REST /api/responses]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `set_log_level` | ✅ supported · rung 1 · `spdlog_runtime` | ✅ supported · rung 1 · `spdlog_runtime` | ✅ supported · rung 1 · `spdlog_runtime` |
| `info` | ✅ supported · rung 1 · `agent_config_read` | ✅ supported · rung 1 · `agent_config_read` | ✅ supported · rung 1 · `agent_config_read` |

**Declared limits per leg** (the descriptor's fallback text, verbatim):

- None declared — every `(action, OS)` fallback column is `-`.
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | not documented for this plugin (no row in `docs/agent-privilege-model.md`); captured as `SYSTEM` | None — both actions are in-process calls, no subprocess on either leg | 2026-09-07, bare-metal, `SYSTEM` (`docs/samples/windows.txt:1`) | N/A — no OS permission check exists |
| macOS | not documented; captured unprivileged, `euid 501 (alex)` | None | 2026-09-07, bare-metal, euid 501 (`docs/samples/macos.txt:1`) | N/A — same as above |
| Linux | not documented; captured as root, `euid 0`, container | None | 2026-09-06, container, euid 0 (`docs/samples/linux.txt:1`) | N/A — same as above |

None. Both actions execute in-process — no subprocess and no network call on any OS (agent_actions_plugin.cpp:27-29 states "no subprocess on any OS -- rung 1 on all three legs").

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
| Action | Parameter | Type | Required | Default | Description |
|---|---|---|---|---|---|
| `set_log_level` | `level` | string | yes | — | Desired spdlog log level, case-insensitive: `trace`, `debug`, `info`, `warn`, `error`, `critical`, `off` (e.g. `info`). |

`info` takes no parameters.
<!-- END GENERATED -->

### Outputs

Both actions emit `write_output()` lines of the form `key|value` rather than disk-plugin-style single pipe-delimited rows. `set_log_level` writes exactly two lines on success (`status`, then `level`); a validation failure instead writes one `error|<message>` line that matches neither declared column. `info` writes exactly five lines, one per config key, in a fixed order; an unpopulated key renders the literal `(not set)` rather than being omitted.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`set_log_level` — one `status|<value>` line, then one `level|<value>` line**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `status` | string | `ok` (only value on success; a validation failure emits `error|<message>` instead of this row) | W, M, L | `ok` |
| `level` | string | `trace` `debug` `info` `warn` `error` `critical` `off` (lowercased echo of the `level` parameter) | W, M, L | `info` |

**`info` — five `key|value` lines, one per config key (`agent.id`, `agent.version`, `agent.server_address`, `agent.heartbeat_interval`, `agent.plugins.count`)**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `agent_id` | string | free text, or literal `(not set)` | W, M, L | `(not set)` |
| `agent_version` | string | free text, or literal `(not set)` | W, M, L | `(not set)` |
| `server_address` | string | free text, or literal `(not set)` | W, M, L | `(not set)` |
| `heartbeat_interval` | string | free text, or literal `(not set)` | W, M, L | `(not set)` |
| `plugins_count` | int32 (declared) | plugin always emits this as text — the raw `agent.plugins.count` string or literal `(not set)`, never a JSON number | W, M, L | `(not set)` |
<!-- END GENERATED -->

### Result status

This plugin does not set a typed result status; the agent records `UNDECLARED` and every sample shows `UNDECLARED / UNKNOWN /` for both actions on all three OSes (`docs/samples/windows.txt`, `docs/samples/macos.txt`, `docs/samples/linux.txt`).

### Where the data goes

- **Instruction result only.** Rows travel over the agent's mTLS gRPC channel as the command response into the ResponseStore. The dashboard renders `agent_actions` output as a generic `Agent | Key | Value` table — it is in the `kKeyValuePlugins` set, not a custom schema (`server/core/src/result_parsing.hpp:53-67`).
- **Not consumed by** daily-sync inventory, the TAR warehouse, DEX, or metrics — no reference to `agent_actions` or `device.agent_actions.*` exists outside the capability catalogue, `result_parsing.hpp`, and `agent_registry.cpp`'s action-description registry.
- **Siblings:** none — both actions are this plugin's whole surface; no other definition shares its config-read or log-level mechanism.
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("device.agent_actions.info")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`, rendered as an `Agent | Key | Value` table (`server/core/src/result_parsing.hpp:53-67`).

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash pending

```
== action=set_log_level level=info
status|ok
level|info
[result_status] UNDECLARED / UNKNOWN /

== action=info
agent.id|(not set)
agent.version|(not set)
agent.server_address|(not set)
agent.heartbeat_interval|(not set)
agent.plugins.count|(not set)
[result_status] UNDECLARED / UNKNOWN /
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (alex) · leg-hash pending

```
== action=set_log_level level=info
status|ok
level|info
[result_status] UNDECLARED / UNKNOWN /

== action=info
agent.id|(not set)
agent.version|(not set)
agent.server_address|(not set)
agent.heartbeat_interval|(not set)
agent.plugins.count|(not set)
[result_status] UNDECLARED / UNKNOWN /
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-06 · euid 0 · leg-hash pending

```
== action=set_log_level level=info
status|ok
level|info
[result_status] UNDECLARED / UNKNOWN /

== action=info
agent.id|(not set)
agent.version|(not set)
agent.server_address|(not set)
agent.heartbeat_interval|(not set)
agent.plugins.count|(not set)
[result_status] UNDECLARED / UNKNOWN /
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **No typed result status.** The plugin never calls a result-status setter; every capture on every OS shows `UNDECLARED / UNKNOWN /` for both actions (`docs/samples/{windows,macos,linux}.txt`).
2. **The `info` capture artifact is real production behavior with the config sync skipped, not a broken leg.** `do_info` reads config through the module-global `g_ctx`, populated by `init()` and then kept current by `agent.cpp`'s `sync_master_config_to_plugins`; `tests/unit/test_plugin_loader.cpp:411-417` states this sync is "the only thing that makes `agent_actions::info` return a populated `agent.plugins.count` instead of `(not set)`." The capture driver loads the plugin without going through that agent-boot sync path, so every sample legitimately shows all five keys as `(not set)`.
3. **Validation failures don't match the declared schema.** A missing or unrecognized `level` emits one `error|<message>` line (agent_actions_plugin.cpp:83-86, 94-97) instead of the declared `status`/`level` columns — the YAML `result.columns` describe only the success path.
4. **`plugins_count` is declared `int32` but always emitted as text.** Every `info` line, `plugins_count` included, is a `key|value` string (agent_actions_plugin.cpp:121-124); the code never emits a numeric type.
5. **No privilege-model row.** `docs/agent-privilege-model.md` carries no entry for this plugin; the identities above are only what each sample capture measured, not a documented production guarantee.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/agent_actions/src/agent_actions_plugin.cpp` (single TU — `meson.build` lists exactly one source file, no per-OS split)
- Definitions: `content/definitions/agent_actions.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_d.hpp` (lines ~524, ~534)
- Tests: no dedicated test file for this plugin; `tests/unit/test_plugin_loader.cpp:411-475` covers the config-sync invariant `info` depends on, and `tests/unit/server/test_instruction_yaml.cpp` parses its YAML definitions generically
- Privilege row: no row in `docs/agent-privilege-model.md`
- Changelog: `changelog.d/2204-declarations-group-d.added.md`
<!-- END GENERATED -->
