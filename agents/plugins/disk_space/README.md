# disk_space

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Reports free / total disk space for a single volume |
| **Version** | 1.0.0 · plugin ABI 4 · shipped in PR #2204 (2026-08-16) |
| **Kind** | Collector · read-only · on-demand (no scheduled gather; `gather.ttlSeconds` 60 for the /auto pre-flight cache) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux ✅ |
| **Actions** | `free` (definition `crossplatform.storage.free`) |
| **Security** | securable `Inventory` · operation Read · risk Low · dispatch ReadOnly · approval gate none |
| **Roles** | execute: endpoint-admin, endpoint-operator · author: content-author |
<!-- END GENERATED -->

## How it works

`free` is the plugin's only action: it stats one volume and reports total bytes, caller-usable free bytes, and percent used. The volume is selected by the optional `path` parameter (default `C:\` on Windows, `/` on POSIX); the plugin never enumerates volumes itself, so a caller wanting every volume on a host must call it once per path. `free_bytes` is deliberately the quota-aware, caller-visible figure — `FreeBytesAvailableToCaller` on Windows, `f_bavail` on POSIX — not the raw free-block count, because the plugin exists to answer "does this installer have headroom," which is a per-caller question. Thresholds (how much free space is enough) are not the plugin's concern; they live with the caller, matching `os_info`'s convention. The whole action is one synchronous stat call — no subprocess, no retry, no caching inside the plugin.

```mermaid
flowchart LR
  OP[Operator / workflow<br/>or /auto pre-flight] --> SRV[Server<br/>authz: Inventory.Read]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[disk_space.execute]
  EX --> WIN[Windows leg<br/>GetDiskFreeSpaceExW]
  EX --> MAC[macOS leg<br/>statfs 2]
  EX --> LIN[Linux leg<br/>statvfs 2]
  WIN & MAC & LIN --> ROWS[disk row, no typed status] --> RS[(ResponseStore)] --> API[REST /api/responses · /auto pre-flight · device-live disk card]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `free` | ✅ supported · rung 1 · `GetDiskFreeSpaceExW` | ✅ supported · rung 1 · `statfs(2)` | ✅ supported · rung 1 · `statvfs(2)` |

**Declared limits per leg** (the descriptor's fallback text, verbatim):

None declared — all three legs report `nullptr` fallback text.
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account (LocalSystem today, #1442) | None. `GetDiskFreeSpaceExW` needs no elevated access. | 2026-09-07, bare-metal, SYSTEM | `error|failed to query disk space for path: <path>`, non-zero return |
| macOS | agent daemon (root today per `docs/agent-privilege-model.md`) | None. `statfs(2)` on an accessible path needs no privilege. | 2026-09-07, bare-metal, euid 501 (unprivileged — the capture ran outside the real daemon identity) | `error|failed to stat path: <path>`, non-zero return |
| Linux | agent daemon (`yuzu` user, unprivileged, per `docs/agent-privilege-model.md`) | None. `statvfs(2)` needs no privilege. | 2026-09-06, container, euid 0 | `error|failed to stat path: <path>`, non-zero return |

No external binaries, no subprocesses, no network access — one in-process OS call per platform (`agents/plugins/disk_space/src/disk_space_plugin.cpp:97-134`).

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
| Definition | Parameter | Type | Required | Default | Values | Description |
|---|---|---|---|---|---|---|
| `crossplatform.storage.free` | `path` | string | no | `C:\` (Windows) / `/` (Linux, macOS) | - | Directory or volume root to measure (e.g. "C:\", "/", "/var"). Defaults to the platform root if omitted. |
<!-- END GENERATED -->

### Outputs

One pipe-delimited row per call. Field 0 is the literal discriminator `disk`; the four columns below map to fields 1–4. On failure the plugin emits `error|<message>` instead and returns non-zero — there is no partial-success row.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`free` — `disk|path|total_bytes|free_bytes|percent_used`**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `path` | string | the resolved input path, echoed back verbatim | windows, linux, darwin | `/` |
| `total_bytes` | int64 | raw volume capacity in bytes (`f_blocks`/`total.QuadPart` times block size) | windows, linux, darwin | `494384795648` |
| `free_bytes` | int64 | caller-usable free bytes — `FreeBytesAvailableToCaller` (Windows) / `f_bavail` (POSIX), quota-aware, not the raw free-block count | windows, linux, darwin | `313557938176` |
| `percent_used` | int32 | `(total-free)*100/total`, truncated integer 0-100; `0` if `total_bytes` is 0 | windows, linux, darwin | `36` |
<!-- END GENERATED -->

### Result status

This plugin does not set a typed result status; the agent records `UNDECLARED` and the sample shows `UNDECLARED / UNKNOWN /`.

### Where the data goes

- **Instruction result.** Rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore (default 90-day retention, `server/core/src/response_store.hpp:8`), readable at `/api/responses/{id}`.
- **`/auto` Pre-flight page.** `crossplatform.storage.free`'s raw `disk|<path>|<total>|<free>|<percent_used>` row is one of the five Slice-1 pre-flight checks (`server/core/src/preflight_parse.hpp:53`); the parser reads `free` at field[3] and applies the operator's `min_free_gib` threshold to produce a Pass/Fail/Warn/Unknown verdict per device (`server/core/src/preflight_parse.hpp:18-20`, `:60-67`).
- **Device-live "disk" card.** The `/device/live?kind=disk` route dispatches `disk_space.free` directly and renders the result as `LiveDiskVolume{path, total, free, percent_used}` (`server/core/src/device_routes.cpp:97`, `server/core/src/device_routes.hpp:164-165`), audited as `device.live.disk`.
- **Not consumed by** daily-sync inventory, the TAR warehouse, or the DEX performance store.
- **Siblings:** `disk_actions` (`crossplatform.storage.smart`, `crossplatform.storage.volumes` — physical-drive health and the volume-to-drive join; `total_bytes` there is raw media capacity, not comparable field-for-field with this plugin's), `filesystem_posture` (`crossplatform.storage.mounts` — full mount inventory).
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("crossplatform.storage.free")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`; also drives `/auto` pre-flight verdicts and the device-live disk card.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash pending

```
== action=free
disk|C:\|248158089216|20788936704|91
[result_status] UNDECLARED / UNKNOWN /
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (alex) · leg-hash pending

```
== action=free
disk|/|494384795648|313557938176|36
[result_status] UNDECLARED / UNKNOWN / 
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-06 · euid 0 · leg-hash pending

```
== action=free
disk|/|485473984512|407729123328|16
[result_status] UNDECLARED / UNKNOWN / 
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **No typed result status.** The plugin never calls `set_result_status`; every capture reads `UNDECLARED / UNKNOWN /` regardless of platform or outcome. A caller distinguishing success from failure must check for the leading `error|` row and the non-zero return, not the status field.
2. **`percent_used` is not directly comparable across OSes.** Linux's `f_bavail` excludes the root-reserved slack that Windows' `FreeBytesAvailableToCaller` does not withhold in the same way, so the same physical fill level reads a few points higher on Linux (`agents/plugins/disk_space/src/disk_space_plugin.cpp:130-131`).
3. **`total_bytes` is raw media capacity, not compared with `disk_actions`.** The two plugins measure independently; do not assume `disk_space.free`'s `total_bytes` and `disk_actions.volumes`' `total_bytes` for the same path are byte-identical without checking both mechanisms.
4. **Windows suppresses the session-0 hard-error dialog per call.** `ThreadErrorModeGuard` sets `SEM_FAILCRITICALERRORS` only for the duration of the `GetDiskFreeSpaceExW` call, thread-scoped rather than process-wide, specifically so a not-ready removable or BitLocker-locked volume degrades to an `error|` row instead of blocking a dispatch-pool worker on a hidden dialog (`agents/plugins/disk_space/src/disk_space_plugin.cpp:56-72`, `:96-97`).
5. **macOS uses `statfs`, not `statvfs`, on purpose.** `statvfs`'s block-count type is 32-bit on Darwin and would truncate a volume above roughly 16 TiB; `statfs`'s counters are 64-bit (`agents/plugins/disk_space/src/disk_space_plugin.cpp:29-32`, `:108-111`). Do not "simplify" this to `statvfs` for cross-platform symmetry with the Linux leg.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/disk_space/src/disk_space_plugin.cpp` · `agents/plugins/disk_space/meson.build`
- Definitions: `content/definitions/disk_space.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_b.hpp:565`
- Tests: `tests/unit/test_new_plugins.cpp:338` (descriptor shape)
- Privilege row: no row in `docs/agent-privilege-model.md` (general per-platform account rows apply)
- Changelog: `changelog.d/2204-declarations-group-b.added.md`
<!-- END GENERATED -->
