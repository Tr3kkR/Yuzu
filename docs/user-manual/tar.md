# Timeline Activity Record (TAR)

The TAR plugin continuously captures system state snapshots and records changes as timestamped events in a local SQLite database on each endpoint. It enables retrospective investigation of "what happened on this machine" without requiring pre-configured logging or SIEM integration.

> Engineers maintaining or extending TAR should also read [`docs/tar-implementer.md`](../tar-implementer.md) — it covers the on-disk format, persistence semantics across upgrade/uninstall/reinstall, the post-restart double-capture caveat, and device-impact expectations.

## What TAR captures

TAR monitors five categories of system activity:

| Category | Collection interval | Events detected |
|----------|-------------------|-----------------|
| **Processes** | **event-driven on Windows** (ETW) **and macOS** (Endpoint Security), gap-free; 60 s poll on Linux | Process started, process stopped |
| **Network connections** | 60 seconds (fast) | Connection opened, connection closed |
| **Services** | 300 seconds (slow) | Service started, stopped, state changed |
| **User sessions** | 300 seconds (slow) | User login, user logout |
| **Performance** | 30 seconds (perf) | Device CPU/memory/disk/network sample (a scalar reading, not a diff) |

The first four categories take a snapshot of the current state each cycle, compare it to the previous snapshot, and record only the differences as events. This keeps the database compact while providing full visibility into system changes.

The **Performance** source is different: it is a fixed-cadence *scalar sample*, not an event diff. Each 30-second tick records one row of derived device metrics — CPU busy %, memory used % and commit-charge %, per-IO disk service time (µs) and read/write throughput, and non-loopback network rx/tx throughput. It is collected from raw kernel counters (no PDH, no WMI, no shell-out) and, like all TAR data, **stays on the device** — only aggregates leave the edge. On Windows it is fully supported; Linux and macOS collectors are planned. The first sample after the agent starts is a baseline (it establishes the counter reference and records no row); every subsequent tick records one sample.

## Querying TAR data

### From the Yuzu dashboard

Use the **TAR Query** instruction to search events by time range and type.

### From the REST API

```
POST /api/v1/instructions/execute
{
  "plugin": "tar",
  "action": "query",
  "parameters": {
    "from": "1711000000",
    "to": "1711100000",
    "type": "process",
    "limit": "500"
  }
}
```

### Query parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `from` | No | 0 | Start of time range (Unix epoch seconds) |
| `to` | No | now | End of time range (Unix epoch seconds) |
| `type` | No | all | Filter: `process`, `network`, `service`, or `user` |
| `limit` | No | 1000 | Maximum results (max 10000) |

### Output format

Each event is output as a pipe-delimited line:

```
timestamp|event_type|event_action|snapshot_id|detail_json
```

Example:

```
1711050123|process|started|1711050123001|{"pid":1234,"ppid":1,"name":"nginx","cmdline":"nginx -g daemon off;","user":"www-data"}
1711050123|network|connected|1711050123001|{"proto":"tcp","local_addr":"0.0.0.0","local_port":80,"remote_addr":"10.0.0.5","remote_port":54321,"state":"ESTABLISHED","pid":1234}
1711050423|service|state_changed|1711050423002|{"name":"sshd","display_name":"OpenSSH","status":"stopped","prev_status":"running","startup_type":"automatic","prev_startup_type":"automatic"}
1711050423|user|login|1711050423002|{"user":"admin","domain":"CORP","logon_type":"remote","session_id":"pts/0"}
```

> The `cmdline` field above is shown populated for a **Linux** example. **On Windows (ETW) and macOS, the process feeder is names-only, so `cmdline` is empty** — see the OS compatibility matrix below. On macOS this holds on **both paths**: when the Endpoint Security stream is unavailable the agent falls back to the `KERN_PROC_ALL` sysctl poll, which also blanks `cmdline` (only Linux populates it).

### JSON export

Use the `export` action for JSON output suitable for integration with Splunk, ClickHouse, or ELK:

```
POST /api/v1/instructions/execute
{
  "plugin": "tar",
  "action": "export",
  "parameters": { "type": "process", "limit": "100" }
}
```

## Configuration

Use the `configure` action to adjust TAR behavior.

| Setting | Valid range | Default | Description |
|---------|-----------|---------|-------------|
| `retention_days` | 1-365 | 7 | Days to keep events before automatic purge |
| `fast_interval` | 10-3600 | 60 | Seconds between process/network collections |
| `slow_interval` | 30-7200 | 300 | Seconds between service/user collections |
| `redaction_patterns` | JSON array | See below | Patterns for command-line redaction (case-insensitive) |
| `process_enabled` | `true` / `false` | `true` | Toggle the process collector on this host |
| `tcp_enabled` | `true` / `false` | `true` | Toggle the network collector on this host |
| `service_enabled` | `true` / `false` | `true` | Toggle the service collector on this host |
| `user_enabled` | `true` / `false` | `true` | Toggle the user-session collector on this host |
| `perf_enabled` | `true` / `false` | `true` | Toggle the device performance sampler on this host |
| `procperf_enabled` | `true` / `false` | **`false`** | Toggle the per-application top-N sampler on this host. **Off by default** — per-application CPU/working-set reveals which applications run on a device, which is usage-class telemetry under the works-council posture (device-level `perf` carries no per-app identity and stays on by default). Set to `true` to opt in; independent of `perf_enabled`. |
| `netqual_enabled` | `true` / `false` | **`false`** | Toggle the per-connection TCP-quality sampler (`netqual` source → `$NetQual_Live`) on this host. **Off by default** — per-connection quality is usage-class telemetry under the works-council posture. Only a coarse destination *class* (`loopback`/`private`/`public`) is stored; raw remote addresses are dropped at the edge and never persisted, and the owning process is recorded as its image name only. Linux only. Set to `true` to opt in; independent of `tcp_enabled`. |
| `perf_interval_seconds` | ≥ 1 | 30 | Seconds between performance samples (device **and** per-app, when each is enabled — they share the tick). Set to `0` to disable the perf trigger entirely. |
| `network_capture_method` | `polling` plus the values returned by `accepted_capture_methods("tcp")` (`iphlpapi`, `procfs`, `proc_pidfdinfo`, plus any `kPlanned` rows once added) | `polling` | Network capture mechanism. `polling` is the platform default — the only mechanism actually wired today. Other values are accepted for pre-staging when the corresponding kernel-event collector lands; the agent emits a `warn` line and continues polling. |
| `process_stabilization_exclusions` | JSON array | `[]` | Process-name glob patterns to drop before diffing. Useful for noisy short-lived helpers (CI runners, IDE indexers) that dwarf real activity. **Trade-off: forensic completeness is reduced — anything matching these patterns is invisible to TAR.** |

**Validation rules:**

- When both `fast_interval` and `slow_interval` are provided, `fast_interval` must be less than `slow_interval`.
- `redaction_patterns` and `process_stabilization_exclusions` must each be a JSON array of non-empty strings.
- `process_stabilization_exclusions` matching is **case-insensitive substring**, not real glob. Leading and trailing `*` are stripped; `?` and `[abc]` are treated as literals. A pattern like `"a"` will match every process whose name contains the letter `a` (most of them) — use length-3+ patterns or anchor with explicit substrings (`"-helper"`, `"chrome-helper"`).
- `network_capture_method` is accepted unconditionally for the literal value `polling` (the platform default). Any other value must appear in the accept-list returned by `accepted_capture_methods("tcp")` (currently `iphlpapi`, `procfs`, `proc_pidfdinfo`); else the configure call is rejected.
- Disabling a collector (`<source>_enabled=false`) short-circuits new captures but leaves existing rows queryable. Re-enabling later starts from a clean baseline rather than diffing against a stale snapshot.

Example:

```
POST /api/v1/instructions/execute
{
  "plugin": "tar",
  "action": "configure",
  "parameters": {
    "retention_days": "14",
    "fast_interval": "30",
    "user_enabled": "false",
    "process_stabilization_exclusions": "[\"*-helper*\",\"*ide-language-server*\"]"
  }
}
```

## OS compatibility matrix

TAR runs on Windows, Linux, and macOS, but each capture source has platform-specific constraints. Run the `compatibility` action to print the live matrix from the agent itself; the table below is a snapshot for documentation purposes.

| Source | Windows | Linux | macOS |
|--------|---------|-------|-------|
| **process** | supported (`etw`) — `Microsoft-Windows-Kernel-Process` real-time session: **gap-free** start/stop (catches short-lived processes the poll misses), exact timestamps + exit code. **Names only — no command line** (the start event carries none; aligns with the privacy posture). Owning user resolved from the SID at start (empty for processes that exit faster than ETW's ~1s buffer flush — the same limit the poll has). Falls back to the `toolhelp32` poll if the ETW session cannot start. **Boot gap:** processes that start *and* exit before the agent's live session opens are backfilled from a boot **AutoLogger** (a circular, FlushTimer-enabled Kernel-Process `.etl` configured by the InnoSetup installer and `install-agent-user.ps1`, started by the kernel early each boot); the agent reads it directly at startup for events before the live session began (no session stop / no elevation — read access only), de-duplicated per boot. Takes effect from the next boot after install. Boot-window events are **names-only with no user** (the start event carries no user SID — precise attribution would need the Security-Auditing 4688 provider); if the AutoLogger isn't configured, that narrow window is simply not captured. | supported (`procfs`) — `/proc/<pid>/status` and `/proc/<pid>/cmdline`. | constrained (`endpoint_security`) — Endpoint Security `NOTIFY_EXEC`/`NOTIFY_EXIT` stream: **gap-free** start/stop, full image path, accurate ppid, owning user from the audit token. **Names only — no command line** (parity with the Windows ETW posture). Requires a build against the **full Xcode SDK** (the Command Line Tools SDK omits the framework), the `com.apple.developer.endpoint-security.client` entitlement, and root. Falls back to the `KERN_PROC_ALL` sysctl poll when the stream is unavailable (CLT-SDK build, missing entitlement, or non-root) — **the poll is also names-only** (it blanks the `proc_pidpath` image it would otherwise place in `cmdline`), so macOS process rows carry no command line on either path. **Boot gap** (as on Windows): processes alive before the agent's session opens get no `started` row — macOS has no AutoLogger-equivalent backfill. **Not active in current shipped builds** — the Apple entitlement + notarized release pipeline are pending (#1455), so macOS agents poll until then; check `process_capture_method` in `tar.status` to see the live path. |
| **tcp** | supported (`iphlpapi`) — `GetExtendedTcpTable` polled at `fast_interval`. ETW (`Microsoft-Windows-Kernel-Network`) is **planned** for sub-second fidelity; not yet wired. | supported (`procfs`) — `/proc/net/{tcp,tcp6,udp,udp6}`. Connection lifetime below `fast_interval` may be missed. | constrained (`proc_pidfdinfo`) — `proc_listallpids` + `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)` via `libproc`. Inherent TOCTOU between pid enumeration and per-fd query — short-lived sockets that close before the per-fd query may produce empty rows. Endpoint Security framework is the planned replacement. |
| **service** | supported (`scm`) — `EnumServicesStatusEx` / `QueryServiceConfig`; full status + startup_type. | constrained (`systemctl`) — `systemctl list-units`; `startup_type` reported as `unknown`. Hosts without systemd (Alpine sysvinit, OpenRC) are unsupported. | constrained (`launchctl`) — `launchctl list`; no startup_type, status binary running/stopped only. |
| **user** | supported (`wts`) — `WTSEnumerateSessionsW` + `WTSQuerySessionInformationW`; interactive, RDP, console. Server Core 2008 R2 minimal installs lack Terminal Services. | constrained (`utmp`) — `getutent`. Containers without `/var/run/utmp` produce no events. `logon_type` inferred from tty (`pts/*` → remote). | constrained (`utmpx`) — `getutxent`. GUI logins are not always reflected. |
| **perf** | supported (`ntcounters`) — `GetSystemTimes`, `GlobalMemoryStatusEx`/`GetPerformanceInfo`, `IOCTL_DISK_PERFORMANCE`, `GetIfTable2`. No PDH, no WMI, no shell-out. Some virtual disks do not answer `IOCTL_DISK_PERFORMANCE` — disk columns read 0 there. | planned (`procfs`) — `/proc/stat`, `/proc/meminfo`, `/proc/diskstats`, `/proc/net/dev`. Records nothing until wired. | planned (`host_statistics`) — `host_processor_info` / `host_statistics64` + IOKit. Records nothing until wired. |
| **procperf** | supported (`ntsysinfo`), **opt-in (off by default)** — one `NtQuerySystemInformation(SystemProcessInformation)` snapshot per tick: image name, CPU times, working set for every process. No PDH, no WMI, no per-process handles. Records image **names only — never command lines**; redaction patterns apply to the name (as bare case-insensitive substrings — a pattern meant for a command-line argument can match an image name, so over-matching drops a process from the warehouse entirely). | planned (`procfs`) — `/proc/<pid>/stat` utime+stime + VmRSS. Records nothing until wired. | planned (`libproc`) — `proc_pid_rusage`/`proc_taskinfo`. Records nothing until wired. |

Status values:

- **supported** — fully wired and exercised in CI.
- **constrained** — works but with a documented limitation.
- **planned** — not yet implemented; `network_capture_method` accepts the value so you can pre-stage configuration.
- **unsupported** — platform cannot supply the data at all (e.g., `service` on a kernel without a service manager).

To get the matrix at runtime (returns one `row|...` line per source/OS pair):

```
POST /api/v1/instructions/execute
{
  "plugin": "tar",
  "action": "compatibility"
}
```

## Security: command-line redaction

TAR automatically redacts sensitive command-line arguments before storing process events. Any command line matching a redaction pattern has its `cmdline` field replaced with `[REDACTED by TAR]`.

> **Windows + macOS (stream) scope.** On Windows the process source is the ETW Kernel-Process feeder; on macOS with the Endpoint Security stream active it is likewise names-only — both capture **image names only, never a command line**. The `cmdline` column is therefore empty for those process rows, and these redaction patterns have **no effect on them** (there is nothing to redact). They still apply to **per-app perf** rows (`procperf`, matched against the image *name*) on all platforms and to **Linux** process command lines (always poll-captured). **macOS is names-only on both paths** (ES stream and sysctl poll), so these patterns have nothing to redact there either. If your threat model depends on never storing command-line secrets on Windows/macOS, both the streaming feeder and the macOS poll guarantee that structurally.

Default redaction patterns:

```json
["*password*", "*secret*", "*token*", "*api_key*", "*credential*"]
```

Patterns use case-insensitive substring matching. The `*` characters at the start and end indicate substring semantics (e.g., `*password*` matches any command line containing "password" in any case).

To customize:

```
POST /api/v1/instructions/execute
{
  "plugin": "tar",
  "action": "configure",
  "parameters": {
    "redaction_patterns": "[\"*password*\",\"*secret*\",\"*token*\",\"*private_key*\"]"
  }
}
```

## Checking TAR status

The `status` action returns database health information:

```
record_count|15234
oldest_timestamp|1710950000
newest_timestamp|1711050423
db_size_bytes|2097152
retention_days|7
config|process_enabled|true
config|process_paused_at|0
config|process_live_rows|18402
config|process_oldest_ts|1710950000
config|tcp_enabled|true
config|tcp_paused_at|0
config|tcp_live_rows|4193
config|tcp_oldest_ts|1710955000
config|service_enabled|true
config|service_paused_at|0
config|service_live_rows|812
config|service_oldest_ts|1710901000
config|user_enabled|true
config|user_paused_at|0
config|user_live_rows|97
config|user_oldest_ts|1710900100
config|network_capture_method|polling
```

The four `<source>_*` blocks are emitted per capture source. `<source>_paused_at` is `0` when the source has never been disabled and the wall-clock UTC seconds when it was last transitioned `enabled → disabled`. The reverse transition resets it to `0`. `<source>_live_rows` and `<source>_oldest_ts` are the count and minimum timestamp of the per-source `*_live` table at the moment of the status call. Agents older than v0.12.0 do not emit the per-source `paused_at` / `live_rows` / `oldest_ts` lines; the dashboard renders `—` in their absence.

## TAR dashboard page

The Yuzu dashboard includes a dedicated TAR page at `/tar`, reachable from the **TAR** entry in the main navigation bar (visible after authentication). The page is the central operator surface for TAR across the fleet. Phase 15.A delivers the retention-paused source list as the first frame; the scope-walking-aware SQL frame and the process tree viewer drop into placeholder slots in subsequent phases.

### Retention-paused source list

The first frame surfaces every device × source pair where the collector has been disabled (`<source>_enabled=false`). Rows are sorted paused-longest-first so devices accumulating non-aging data the longest float to the top of the list.

**Columns:** device hostname, source pill, paused since (UTC), paused for (coarse age), live rows count, oldest data age.

**Workflow:**

1. Click **Scan fleet** to dispatch a `tar.status` command to the agents in your management-group scope. The scan-provenance header above the table reports how many agents were dispatched to, how many have responded so far, and how many have all sources collecting normally.
2. Review the table. A row with a high `live_rows` count or a long pause duration may indicate forensic data accumulating without being queried.
3. Click **Re-enable** on a row to dispatch `tar.configure` with `<source>_enabled=true` to that single device. The row drops optimistically; click **Refresh** to reconcile against a fresh scan.

**Permissions:**

- Viewing the page and the retention-paused list requires `Infrastructure:Read`.
- **Scan fleet** requires `Execution:Execute` (it dispatches a fleet-wide command).
- **Re-enable** requires `Execution:Execute` (it dispatches a configure command to a single device).
- Both Scan dispatch and the rendered list are scoped to your management-group visibility — agents outside your scope are neither queried nor rendered, and the Re-enable endpoint rejects out-of-scope `device_id` values with the same 404 response as a not-connected agent (no enumeration oracle).

**State persistence:** Scan results are held in the server's memory keyed by your username. Restarting the server clears the last-scan reference; click **Scan fleet** again after a restart. Persistence across restarts and multi-server coordination are planned for Phase 15.G operational hardening.

**Audit trail:** Every Scan emits a `tar.status.scan` audit event. Every Re-enable emits `tar.source.reenable` (with `result=success` and `detail` carrying `device_id` and `source` on success, or `result=failure` with `detail` carrying the real reason — `scope_violation` or `agent_not_connected` — on rejected attempts). See `docs/user-manual/audit-log.md` for the full schema.

## Forcing an immediate snapshot

The `snapshot` action triggers an immediate full collection of all four categories, useful before a maintenance window or at the start of an investigation:

```
POST /api/v1/instructions/execute
{
  "plugin": "tar",
  "action": "snapshot"
}
```

## Performance impact

TAR is designed for minimal performance overhead:

- **Fast collection** (processes + network): typically completes in under 100ms
- **Slow collection** (services + users): typically completes in under 200ms
- **Performance sampling**: a handful of kernel-counter reads every 30s; one row written per sample. The `$Perf_Live` 7-day window holds ~20,000 rows (~1-2 MB) per endpoint at the default cadence.
- **Database size**: varies by system activity; a typical endpoint generates 1-5 MB per day (plus the ~1-2 MB perf window)
- **CPU**: negligible between collection cycles; brief spike during snapshot + diff
- **Automatic purge**: old events are removed hourly based on the retention setting

> **Upgrade note (device perf sampling; per-app sampling is opt-in).** On
> upgrade to this release, every Windows agent continues **device** performance
> sampling (`perf_enabled` defaults to `true`, 30-second cadence — unchanged
> from the prior release). **Per-application** sampling (`procperf_enabled`) is
> a new, distinct telemetry category — per-app CPU/working-set by image name —
> and ships **off by default**: it is not collected until an operator opts in,
> because it is usage-class data subject to works-council/DPA review (see
> `docs/enterprise-readiness-soc2-first-customer.md`). To enable it, set
> `procperf_enabled=true` via the `configure` action (fleet-wide or per-device).
> Warehouse tables added by a new release are now created on every database open
> (previously a pre-existing `tar.db` missed tables introduced after it was
> first created), so no manual table-creation step is needed on upgrade.

> **Upgrade note (Windows process capture → ETW). BREAKING for `cmdline`
> consumers.** On upgrade, the Windows process source switches from the
> 60-second snapshot-diff poll to an event-driven ETW Kernel-Process feeder.
> Three operator-visible changes:
> - **`cmdline` is now empty for Windows process rows** (the feeder is
>   names-only). Any dashboard, SIEM export, or Guardian rule that relied on the
>   Windows process command line will see an empty field after upgrade. **Linux is
>   unchanged** (the poll still captures command lines there). **macOS is now
>   names-only on both paths** — the Endpoint Security stream and the sysctl poll —
>   so `cmdline` is empty there too (the poll blanks the `proc_pidpath` image it
>   would otherwise store). This is intentional (works-council / data-minimization
>   posture) and not reversible by configuration — see the redaction section.
> - **Live capture is active from the next agent start** — gap-free during the
>   live session, so short-lived processes the poll missed now appear, and
>   `$Process_Live` holds more rows (cap raised to 100000). (One narrow seam: at
>   the boot→live handoff, events in the window between the agent sampling its
>   boot/live boundary and the live provider becoming active can fall in neither
>   the backfill nor the live stream — tracked as a follow-up.) If the ETW session
>   cannot start, the agent
>   logs the reason and falls back to the `toolhelp32` poll automatically; if the
>   session later dies it self-heals to the poll. On Windows the death signal is
>   immediate (the ETW `ProcessTrace` returns). On **macOS** the Endpoint Security
>   client exposes no liveness API, so the agent treats a prolonged TOTAL silence
>   (no exec/exit for ~1h) as presumed-dead and re-arms the poll then — the
>   threshold is deliberately long because a NOTIFY-only client cannot distinguish a
>   dead stream from a legitimately quiet host, and a false trip drops a healthy
>   stream to the inferior poll. The active path is reported by the `status` action
>   as `process_capture_method` (`etw` or `polling` on Windows; `endpoint_security`
>   or `polling` on macOS). Once it has fallen back to the poll, stream capture is
>   **not** re-established until the agent restarts (so `process_capture_method=polling`
>   on a host that should be streaming indicates a prior session failure — restart
>   the agent to retry). Two drop counters: `process_stream_dropped` is the
>   **userspace ring-overflow** count (the drain tick fell behind; renamed from
>   `process_etw_dropped` this release, now cross-platform), and
>   `process_stream_kernel_dropped` is the **kernel/provider-side** drop count
>   (Endpoint Security `seq_num` gaps on macOS; 0 on Windows ETW, which exposes no
>   per-message sequence here).
> - **macOS parity gap (fork-without-exec).** The Endpoint Security stream
>   subscribes `NOTIFY_EXEC`/`NOTIFY_EXIT` only, so a child that forks but never
>   execs is invisible until it exits (Windows ETW fires on every process create).
>   Capturing it via `NOTIFY_FORK` is deferred (#1455) — adding it naively would
>   double-count the overwhelmingly common fork→exec case.
> - **Boot-window backfill requires the boot AutoLogger**, configured by the
>   production InnoSetup installer (scoped to the `advanced` component that ships
>   `tar.dll`) and by the developer install path (`install-agent-user.ps1`). A
>   **reboot is required** for the AutoLogger to take effect: on a fresh install,
>   or when upgrading from a release that did not configure it, boot-window
>   backfill (the narrow window of processes that start *and* exit before the
>   agent's session opens) is absent until after the next reboot. A minimal
>   install that omits the `advanced` component does not configure the
>   AutoLogger. Boot-window events are names-only with **no user**.
>
> To disable Windows process capture entirely (ETW and poll), set
> `process_enabled=false` via `configure`; there is no separate "disable ETW but
> keep polling" switch today. While disabled, the live ETW session keeps running
> but its buffered events are drained-and-discarded each cycle, so no process
> activity from the paused window is persisted when you re-enable.
- **WAL mode**: SQLite Write-Ahead Logging ensures reads never block writes

## Warehouse Query System

TAR includes a typed data warehouse that replaces the legacy flat `tar_events` table with structured, tiered tables optimized for different query time horizons.

### Warehouse tables

Table names use `$`-prefixed identifiers (e.g., `$Process_Live`) which the agent translates to real SQLite table names at execution time. There are six capture sources, each with multiple granularity tiers:

| Source | Live | Hourly | Daily | Monthly |
|--------|:----:|:------:|:-----:|:-------:|
| **Process** | `$Process_Live` (100000 rows) | `$Process_Hourly` (24h) | `$Process_Daily` (31d) | `$Process_Monthly` (12mo) |
| **TCP** | `$TCP_Live` (5000 rows) | `$TCP_Hourly` (24h) | `$TCP_Daily` (31d) | `$TCP_Monthly` (12mo) |
| **Service** | `$Service_Live` (5000 rows) | `$Service_Hourly` (24h) | -- | -- |
| **User** | `$User_Live` (5000 rows) | -- | `$User_Daily` (31d) | -- |
| **Perf** | `$Perf_Live` (7d, time-based) | `$Perf_Hourly` (31d) | -- | -- |
| **ProcPerf** | `$ProcPerf_Live` (7d, time-based) | `$ProcPerf_Hourly` (31d, per app) | -- | -- |

- **Live** tables hold the most recent raw events with a row cap (oldest rows are evicted): **5000 rows** for TCP / Service / User, and **100000 rows for `$Process_Live`** — raised because the Windows ETW feeder is event-driven (every start/stop, including short-lived processes) and fills a 5000-row window far faster than the old 60-second poll did, so a larger raw window keeps a meaningful history before rows roll up into the hourly/daily/monthly count tiers. **Exception: `$Perf_Live` and `$ProcPerf_Live` are time-based (7 days), not row-capped** — a fixed-cadence sampler keeps a *time window*, so raising `perf_interval_seconds` must not shrink the history it covers.
- **Hourly** tables aggregate counts and summaries per hour, retained for 24 hours (perf/procperf hourly: 31 days).
- **Daily** tables aggregate per day, retained for 31 days.
- **Monthly** tables aggregate per month, retained for 12 months.
- Service only has live and hourly tiers. User only has live and daily tiers. Perf and ProcPerf have live and hourly tiers.

### Key columns by table type

**Process tables:** `ts`, `name`, `pid`, `ppid`, `cmdline`, `user`, `action` (started/stopped). Aggregated tiers add `start_count`, `stop_count`. **`cmdline` is empty on Windows (ETW) and on macOS** (names-only feeders — see the OS compatibility matrix and the command-line redaction section); it is populated on **Linux only**. macOS is names-only on **both** paths (the Endpoint Security stream and the sysctl-poll fallback).

**TCP tables:** `ts`, `process_name`, `pid`, `remote_addr`, `remote_port`, `local_port`, `proto`, `state`. Aggregated tiers add `connect_count`.

**Service tables:** `ts`, `name`, `status`, `prev_status`, `action` (started/stopped/state_changed). Hourly tier adds `change_count`.

**User tables:** `ts`, `user`, `domain`, `logon_type`, `action` (login/logout). Daily tier adds `login_count`.

**Perf tables:** `ts`, `cpu_pct`, `mem_used_pct`, `commit_pct`, `disk_read_bps`, `disk_write_bps`, `disk_read_lat_us`, `disk_write_lat_us`, `net_rx_bps`, `net_tx_bps` (all numeric; rates are bytes/sec, latencies are µs per I/O). `$Perf_Hourly` carries per-hour `samples`, `cpu_avg`/`cpu_max`, `mem_avg`/`mem_max`, `commit_avg`, and avg/max throughput and latency columns. Collection is trigger-driven (`tar.collect_perf`, every `perf_interval_seconds`), so the audit trail for perf is the `configure` action that enables/paces it, not a per-sample dispatch record.

**ProcPerf tables:** `ts`, `name` (image name only — **never a command line**), `instances`, `cpu_pct`, `ws_bytes`. Each tick records the **top 10 applications by CPU plus the top 10 by working set** (union, ≤ 20 rows), aggregated across same-name processes (`instances` = how many). `cpu_pct` is the app's share of *total machine capacity* — one saturated core on an 8-core box reads 12.5, matching `$Perf_Live` and Task Manager. `$ProcPerf_Hourly` aggregates per `(hour, name)`: `samples`, `instances_max`, `cpu_avg`/`cpu_max`, `ws_avg_bytes`/`ws_max_bytes`. Apps matching a redaction pattern are never recorded. Example — yesterday's CPU-hungriest apps on a device:

```sql
SELECT name, MAX(cpu_max) AS peak, AVG(cpu_avg) AS typical
FROM $ProcPerf_Hourly GROUP BY name ORDER BY peak DESC LIMIT 10
```

### Querying with SQL

Use the `tar.sql` action to execute SELECT queries against warehouse tables:

```
POST /api/v1/instructions/execute
{
  "plugin": "tar",
  "action": "sql",
  "parameters": {
    "sql": "SELECT name, pid, cmdline FROM $Process_Live ORDER BY ts DESC LIMIT 50"
  }
}
```

Pre-built queries are available in `content/definitions/tar_warehouse.yaml`, covering common use cases like recent processes, TCP connections by process, listening ports, hourly summaries, service state changes, user sessions, and process trees.

### Rollup aggregation

The warehouse automatically runs a rollup aggregation cycle every 15 minutes. Each cycle:

1. Aggregates live-tier data into hourly summaries
2. Aggregates hourly data into daily summaries
3. Aggregates daily data into monthly summaries
4. Enforces retention limits on each tier

To force an immediate rollup, use the `tar.rollup` action.

### Safety controls

SQL queries are validated at multiple levels:

- **Server-side:** Only SELECT statements are permitted. A keyword blocklist rejects INSERT, UPDATE, DELETE, DROP, ALTER, CREATE, ATTACH, DETACH, PRAGMA, VACUUM, and REINDEX.
- **Agent-side:** Queries run on a dedicated **read-only** SQLite connection guarded by a `sqlite3` authorizer. Only `SELECT` against registry-known warehouse tables is permitted (reference them by the `$`-prefixed names: `$Process_Live`, `$TCP_Hourly`, etc.); `PRAGMA`, `ATTACH`, schema-table reads (`sqlite_master`), writes, and recursive CTEs are denied at prepare time. `$`-prefixed names are translated to physical names only outside string literals and comments. Only a single statement is allowed, and queries exceeding 4KB are rejected. A blocked query returns `query rejected: operation or table not permitted` — for schema discovery use the `$`-prefixed warehouse table names rather than `PRAGMA`/`sqlite_master`.

## Data storage

TAR events are stored in `{data_dir}/tar.db` (SQLite), where `data_dir` is the agent's configured data directory. The database uses:

- WAL journal mode for concurrent performance
- `busy_timeout=5000` for thread safety
- `secure_delete=ON` to zero deleted data
- Indexes on `timestamp`, `(event_type, timestamp)`, and `snapshot_id`
