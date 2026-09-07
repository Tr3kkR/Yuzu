# content_dist

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Content staging — download, verify, execute, and manage staged files (no shell-out) |
| **Version** | 1.1.0 |
| **Kind** | Action · read-only (`list_staged`) / mutating (`stage`, `execute_staged`, `cleanup`, `upload_file`) · on-demand |
| **Platforms** | Windows 🟡 constrained · macOS ✅ · Linux 🟡 constrained |
| **Actions** | `stage` (definition `agent.content_dist.stage`) · `execute_staged` (definition `agent.content_dist.execute_staged`) · `list_staged` (definition `agent.content_dist.list_staged`) · `cleanup` (definition `agent.content_dist.cleanup`) · `upload_file` (definition `agent.content_dist.upload_file`) |
| **Security** | `stage`: securable `SoftwareDeployment` · op Write · risk High · dispatch Destructive · gate AdminOrApproval — `execute_staged`: securable `Execution` · op Execute · risk High · dispatch Destructive · gate AdminOrApproval — `list_staged`: securable `SoftwareDeployment` · op Read · risk Low · dispatch ReadOnly · gate none — `cleanup`: securable `SoftwareDeployment` · op Delete · risk High · dispatch Destructive · gate AdminOrApproval — `upload_file`: securable `FileRetrieval` · op Write · risk High · dispatch Destructive · gate AdminOrApproval |
| **Roles** | execute: endpoint-admin (all actions), endpoint-operator (`list_staged` only) · author: content-author (all actions) |
<!-- END GENERATED -->

## How it works

`stage` downloads over a raw httplib socket it opens itself (no shell), verifies the SHA-256 against the caller-supplied `sha256`, and — only once verified — persists that hash into agent KV under `staged_hash:<filename>` so a later `execute_staged` has a source of truth the staging-dir attacker can't also rewrite (`content_dist_plugin.cpp:529-540`, #808). `execute_staged` re-verifies the hash from KV (never trusts a caller-supplied hash), rejects a shebang-interpreted script on Linux before it ever reaches the runner (B6 fd-exec has no resolvable path for `binfmt_script`), chmods the file `0700` on POSIX, then execs it directly — no shell — via `yuzu::agent::run_bounded_subprocess` with a fixed 30-minute deadline. `list_staged` and `cleanup` are plain `std::filesystem` walks of the same staging directory; `cleanup` removes files older than an age cutoff and evicts their KV hash entry alongside them. `upload_file` is an unrelated protocol: it drives a session-open/chunk/commit/cancel exchange against the agent's own configured server URL (never an operator-supplied one) using a one-time `grant_id`/`grant_secret`, hashing the exact bytes each chunk transmitted as it is acknowledged.

Deliberately not: a shell. No action here ever invokes `/bin/sh`, `cmd.exe`, or any interpreter — downloads and uploads are direct socket clients, execution is a direct argv exec. Deliberately not: a general file manager — every filesystem action is scoped to the plugin's own `staging_dir()`.

```mermaid
flowchart LR
  OP[Operator / workflow<br/>or the /auto Deploy engine] --> SRV[Server<br/>authz: SoftwareDeployment/Execution/FileRetrieval per action]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[content_dist.execute]
  EX --> WIN[Windows leg<br/>httplib_tls · subprocess_runner:staged_payload · std_filesystem]
  EX --> MAC[macOS leg<br/>httplib_tls · subprocess_runner:staged_payload · std_filesystem]
  EX --> LIN[Linux leg<br/>httplib_tls · subprocess_runner:staged_payload (native only) · std_filesystem]
  WIN & MAC & LIN --> ROWS[pipe rows +<br/>typed result status on execute_staged only]
  ROWS -- CommandResponse --> RS[(ResponseStore)]
  RS --> API[REST /api/responses · /auto Deploy engine]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `stage` | 🟡 constrained · rung 1 · `httplib_tls` | ✅ supported · rung 1 · `httplib_tls` | ✅ supported · rung 1 · `httplib_tls` |
| `execute_staged` | ✅ supported · rung 2 · `subprocess_runner:staged_payload` | ✅ supported · rung 2 · `subprocess_runner:staged_payload` | 🟡 constrained · rung 2 · `subprocess_runner:staged_payload` |
| `list_staged` | ✅ supported · rung 1 · `std_filesystem` | ✅ supported · rung 1 · `std_filesystem` | ✅ supported · rung 1 · `std_filesystem` |
| `cleanup` | ✅ supported · rung 1 · `std_filesystem` | ✅ supported · rung 1 · `std_filesystem` | ✅ supported · rung 1 · `std_filesystem` |
| `upload_file` | 🟡 constrained · rung 1 · `httplib_tls` | ✅ supported · rung 1 · `httplib_tls` | ✅ supported · rung 1 · `httplib_tls` |

**Declared limits per leg** (the descriptor's fallback text, verbatim):

- **`stage` / Windows** — requires OpenSSL to be found at build time; HTTPS unavailable if absent
- **`execute_staged` / Linux** — shebang-interpreted (#!) staged payloads are rejected -- B6 fd-exec (execveat O_CLOEXEC) is incompatible with the kernel's binfmt_script re-open; native executables only
- **`upload_file` / Windows** — requires OpenSSL to be found at build time; HTTPS unavailable if absent
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account (LocalSystem today, #1442); `execute_staged` runs as `YuzuAgent` (`docs/agent-privilege-model.md:121`) | **None.** Every action stays inside the agent-owned staging directory or a socket the agent opens itself. | 2026-09-07, bare-metal, as `SYSTEM` (`windows.txt`) | no typed status — a filesystem/network failure surfaces as an `error\|<message>` line, not a `PERMISSION_DENIED` result status |
| macOS | agent daemon, unprivileged (`_yuzu`) | **None.** `staging_dir()` creates the directory owner-only (`fs::perms::owner_all`, `content_dist_plugin.cpp:72-75`). | 2026-09-07, bare-metal, euid 501 (`macos.txt`) | same — an `error\|` line, no typed status |
| Linux | agent daemon, unprivileged (`yuzu`) | **None.** Same owner-only staging directory. | 2026-09-06, container, euid 0 (`linux.txt`) — captured as root, not the unprivileged `yuzu` identity `execute_staged` actually runs as in production | same — an `error\|` line, no typed status |

Binaries/subprocesses/network: `stage`/`upload_file` open raw TCP/TLS sockets via cpp-httplib (no subprocess). `execute_staged` spawns exactly one process — the staged file itself — via `yuzu::agent::run_bounded_subprocess` (no shell, no other binary). `list_staged`/`cleanup` touch no network and spawn nothing.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
| Action | Parameter | Type | Required | Default | Description |
|---|---|---|---|---|---|
| `stage` | `url` | string | yes | — | Source URL; must start with `http://` or `https://`, downloaded directly over a socket the agent opens itself. |
| `stage` | `filename` | string | yes | — | Destination filename inside the staging directory; alphanumeric, dots, hyphens, underscores only. |
| `stage` | `sha256` | string | yes | — | Lowercase hex SHA-256 the download must hash to; a mismatch deletes the file and fails the action. |
| `execute_staged` | `filename` | string | yes | — | Name of a previously staged file with a verified hash on record in agent KV. |
| `execute_staged` | `args` | string | no | — | Optional whitespace-separated argv tail; rejected if it contains a shell metacharacter. |
| `list_staged` takes no parameters. | | | | | |
| `cleanup` | `filename` | string | no | — | Declared but not read by `do_cleanup` today — has no effect (see Caveats). |
| `upload_file` | `path` | string | yes | — | Local file path on the endpoint to upload (max 4096 chars). |
| `upload_file` | `grant_id` | string | yes | — | One-time upload grant id minted via `POST /api/v1/upload-grants` (max 64 chars). |
| `upload_file` | `grant_secret` | string | yes | — | One-time upload grant secret paired with `grant_id` (max 128 chars). |
| `upload_file` | `base_dir` | string | no | — | If set, `path` must resolve inside this directory after symlink canonicalisation (max 4096 chars). |
| `upload_file` | `max_size_mb` | int32 | no | `100` | Maximum allowed file size in MB, checked locally before the session opens (1–1000). |
<!-- END GENERATED -->

### Outputs

Every action writes independent `key|value` lines via `ctx.write_output` — not a fixed-width pipe row like a collector's table. A validation or transport failure typically replaces the whole declared line set with a single unstructured `error|<message>` line rather than filling the declared columns with a placeholder value; there is no `-`-for-unknown convention in this plugin.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`stage` — `status`, `staged_path` (two independent lines, not a single pipe row)**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `status` | string | `ok` (the only value ever written; a failure emits `error\|` instead, never `status\|error`) | W, M, L | `ok` |
| `staged_path` | string | absolute path under the staging directory | W, M, L | `-` (no captured sample shows a success) |

**`execute_staged` — `status`, `exit_code`, `output` (three independent lines; `output` is omitted when empty)**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `status` | string | `ok` / `error` | W, M, L | `-` |
| `exit_code` | int32 | process exit code, or `-1` on spawn failure / deadline / cancel | W, M, L | `-` |
| `output` | string | combined stdout+stderr (16 MiB cap) with truncation/termination annotations, or the line is omitted | W, M, L | `-` |

**`list_staged` — one `file` line per staged file plus a trailing `count` summary (not a declared column)**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `file` | string | filename (relative, no path) | W, M, L | `-` |
| `size` | int64 | bytes | W, M, L | `-` |
| `sha256` | string | 64 lowercase hex chars, recomputed on every call | W, M, L | `-` |

**`cleanup` — `removed` (wire field; the declared `status`/`files_removed` columns are never emitted / name-mismatched — see Caveats)**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `status` (declared) | string | never emitted — `do_cleanup` writes no `status\|` line | — | `-` |
| `files_removed` (declared) | int32 | actual wire field is `removed\|<n>`, not `files_removed\|<n>` | W, M, L | `-` |

**`upload_file` — `status`, `sha256`, `size`, `upload_id` (four independent lines on success)**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `status` | string | `ok` (the only value on success; failures use `error\|`) | W, M, L | `ok` |
| `sha256` | string | server-confirmed SHA-256 of the committed upload | W, M, L | `-` |
| `size` | int64 | server-reported `actual_size`, matches the local file size | W, M, L | `-` |
| `upload_id` | string | 32-char lowercase hex session id assigned at session-open | W, M, L | `-` |
<!-- END GENERATED -->

### Result status

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `UNAVAILABLE` | PARTIAL | `subprocess_runner:spawn_error` | `execute_staged` only: the runner never confirmed exec (missing/non-executable staged file, or a Linux B6 exec_verify rejection) |
| `CONSTRAINED` | PARTIAL | `subprocess_runner:deadline` | `execute_staged` only: the fixed 30-minute deadline fired and the process was killed |
| `CONSTRAINED` | PARTIAL | `subprocess_runner:cancelled` | `execute_staged` only: a cancellation reached the runner mid-run |
| `CONSTRAINED` | PARTIAL | `subprocess_runner:signaled` | `execute_staged` only: the staged process died of a signal it received itself |
| `OK` | PARTIAL | `subprocess_runner:line_limit` | never reached for this plugin — `content_dist` never sets `max_lines`/`stop_after_max_lines` (`content_dist_exec_parsers.hpp:288-291`) |

`execute_staged`'s ordinary exit (rc 0 or nonzero) sets no typed status at all — `classify_runner_failure` returns `nullopt` for `exited` by design, leaving the `status`/`exit_code` lines to carry the outcome (`runner_status.hpp`). `stage`, `list_staged`, `cleanup`, and `upload_file` never call `set_result_status` anywhere in `content_dist_plugin.cpp`; every sample capture for all five actions shows `UNDECLARED / UNKNOWN /` because each capture failed at parameter validation, before any runner call could occur.

### Where the data goes

- **Instruction result, and the `/auto` Deploy engine.** Rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore. `content_dist.stage`/`execute_staged` are additionally dispatched by the `/auto` Deploy engine (`server/core/src/deployment_engine.cpp:306,331`), which parses this exact wire contract via `server/core/src/deployment_parse.hpp:17-25` to drive its own per-device state machine — `content_dist` needed no new agent code for that surface.
- **`upload_file`'s `grant_id`/`grant_secret` are redacted before any persisted audit/history copy** (`server/core/src/sensitive_instruction_params.hpp:6`) — never logged or stored beyond the upload store's own hashed record.
- **Not consumed by** daily-sync inventory, the TAR warehouse, DEX, or metrics.
- **Siblings:** none in this catalogue — `execute_staged` is the only "run an arbitrary binary" action here; compare `script_exec.exec` for ad hoc admin commands/scripts.
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("agent.content_dist.execute_staged")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`; `content_dist.stage`/`execute_staged` results are also polled by the `/auto` Deploy engine's `deployment_run_store`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash pending

```
== action=stage
error|missing required parameters: url, filename, sha256
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1

== action=execute_staged
error|missing required parameter: filename
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1

== action=list_staged
count|0
[result_status] UNDECLARED / UNKNOWN / 

== action=cleanup
[not captured] Destructive/Irreversible: not executed on a live host

== action=upload_file
error|missing required parameters: path, grant_id, grant_secret
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (alex) · leg-hash pending

```
== action=stage
error|missing required parameters: url, filename, sha256
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1

== action=execute_staged
error|missing required parameter: filename
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1

== action=list_staged
count|0
[result_status] UNDECLARED / UNKNOWN / 

== action=cleanup
[not captured] Destructive/Irreversible: not executed on a live host

== action=upload_file
error|missing required parameters: path, grant_id, grant_secret
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-06 · euid 0 · leg-hash pending

```
== action=stage
error|missing required parameters: url, filename, sha256
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1

== action=execute_staged
error|missing required parameter: filename
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1

== action=list_staged
count|0
[result_status] UNDECLARED / UNKNOWN / 

== action=cleanup
[not captured] Destructive/Irreversible: not executed on a live host

== action=upload_file
error|missing required parameters: path, grant_id, grant_secret
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **`cleanup`'s `filename` parameter is dead code.** The definition declares `filename` for targeted removal, but `do_cleanup` (`content_dist_plugin.cpp:1179-1209`) only ever reads an undeclared `hours` parameter and sweeps the whole staging directory by age (default 24h) — a single-file removal is not implemented today. The definition's description and the `filename` parameter now disclose this.
2. **`cleanup`'s declared result columns don't match its wire output.** `status` is never emitted — there is no `status|` line anywhere in `do_cleanup`, including on an hours-parse failure (silently ignored, not reported) — and the declared `files_removed` column is actually wired as `removed|<n>`.
3. **`execute_staged` rejects Linux shebang scripts by design — do not "fix" this.** B6 fd-exec (`execveat` with `AT_EMPTY_PATH`) gives the kernel no resolvable path for `binfmt_script` to build the interpreter's argv from; a `#!`-interpreted staged file is refused up front (`content_dist_exec_seam.hpp:81-105`) rather than spawn-failing opaquely. Stage a native executable instead.
4. **A residual hash-time-to-exec-time swap window is accepted, not closed (CDX-001).** The #808 KV hash re-verification and the seam's independent B6 open both target the same path but not the same fd; full closure needs the runner itself to accept a caller-supplied digest, deferred to a follow-up runner package (`content_dist_plugin.cpp:628-652`).
5. **Windows soft-terminate grace is configured but undeliverable.** `no_window=true` (restoring the deleted launcher's `CREATE_NO_WINDOW`) means a console-less child can never receive `GenerateConsoleCtrlEvent`/`CTRL_BREAK`, so the 30s grace is zeroed on the Windows path rather than claiming a grace the platform cannot deliver (`content_dist_exec_parsers.hpp:242-268`).

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/content_dist/src/content_dist_plugin.cpp` (descriptor, actions) · `content_dist_exec_parsers.hpp` (pure `execute_staged` decision layer) · `content_dist_exec_seam.hpp` (`execute_staged` OS shell) · `content_dist_upload_parsers.hpp` (pure `upload_file` decision layer)
- Definitions: `content/definitions/content_dist.yaml` (`stage`, `execute_staged`, `list_staged`, `cleanup`) · `content/definitions/t2_capabilities.yaml` (`upload_file`)
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_content_dist.hpp`
- Tests: `tests/unit/test_content_dist_actions.cpp` · `tests/unit/test_content_dist_exec_parsers.cpp` · `tests/unit/test_content_dist_exec_seam.cpp` · `tests/unit/test_content_dist_exec_seam_win.cpp` · `tests/unit/test_content_dist_upload_parsers.cpp`
- Privilege row: `docs/agent-privilege-model.md` (`content_dist.execute_staged` identity row; staging-directory cache-path row)
- Changelog: `changelog.d/1.6-content-dist-authenticated-upload.changed.md` · `changelog.d/20260814-deployment-dispatch-caller-security.security.md` · `changelog.d/2204-declarations-group-d.added.md` · `changelog.d/5.1-content-dist-runner-convergence.changed.md` · `changelog.d/runner-adr3002-contract.added.md` · `changelog.d/wave5-pr51-script-exec-appdir-codepage.fixed.md` · `changelog.d/wave5-pr51-windows-inherit-env-filter.security.md`
<!-- END GENERATED -->
