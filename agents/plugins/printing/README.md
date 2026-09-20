# printing

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Printer and print-job inventory |
| **Version** | 1.0.0 |
| **Kind** | Collector · read-only · gathered (crossplatform.printing.printers, crossplatform.printing.jobs) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux ✅ |
| **Actions** | `jobs` (definition `crossplatform.printing.jobs`) · `printers` (definition `crossplatform.printing.printers`) |
| **Security** | securable `Inventory` · operation Read · risk Low · dispatch ReadOnly · approval gate None |
| **Roles** | execute: endpoint-admin, endpoint-operator · author: content-author |
<!-- END GENERATED -->

## How it works

`printers` and `jobs` are plain IPP reads: encode a request (RFC 8010, no libcups — `printing_ipp.hpp` is a from-scratch minimal codec), send it over the CUPS Unix domain socket (falling back to `localhost:631` over TCP when no socket is found), decode the response, and format the rows. On Windows the same two actions go through winspool (`EnumPrintersW`/`EnumJobsW`) instead of IPP; there is no libcups dependency on any platform. The plugin keeps no history: `jobs` only ever reports not-completed jobs, and nothing here retains a record of a job once it leaves the queue. A focused follow-up PR on top of this one adds `clear_queue`, the plugin's only mutation.

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: Inventory.Read]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[printing.execute]
  EX --> WIN[Windows leg<br/>winspool EnumPrintersW/EnumJobsW]
  EX --> POSIX[macOS + Linux leg<br/>IPP over the CUPS Unix socket]
  WIN & POSIX --> ROWS[rows + typed result status] --> RS[(ResponseStore)] --> API[REST /api/responses]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `jobs` | ✅ supported · rung 1 · winspool EnumJobsW level 2 | ✅ supported · rung 1 · IPP Get-Jobs (which-jobs=not-completed) over the CUPS Unix socket | ✅ supported · rung 1 · IPP Get-Jobs (which-jobs=not-completed) over the CUPS Unix socket |
| `printers` | ✅ supported · rung 1 · winspool EnumPrintersW level 2 | ✅ supported · rung 1 · IPP CUPS-Get-Printers over the CUPS Unix socket (cpp-httplib) | ✅ supported · rung 1 · IPP CUPS-Get-Printers over the CUPS Unix socket (cpp-httplib) |

**Declared limits per leg** (descriptor fallback text, verbatim):

- **`jobs` / macOS** — localhost:631 fallback for reads when no socket is found
- **`jobs` / Linux** — localhost:631 fallback for reads when no socket is found
- **`printers` / macOS** — localhost:631 fallback for reads when no socket is found
- **`printers` / Linux** — localhost:631 fallback for reads when no socket is found
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account | None — `EnumPrintersW`/`EnumJobsW`/`OpenPrinterW` need no elevated right. `EnumPrintersW` (the only call at risk of blocking against an unreachable network print server — `PRINTER_ENUM_CONNECTIONS`) is bounded (`yuzu::shared::bounded_call`, 5s); the per-printer `OpenPrinterW`/`EnumJobsW` pair is deliberately NOT — bounding a call holding a live `HANDLE` the caller closes on return would race a timed-out detached thread against that close (see `enum_jobs_raw`'s own comment) — `EnumJobsW` instead caps at 5000 rows, not wall-clock time; a genuinely unreachable per-printer RPC can still hang (tracked as a follow-up, not closed here) | the-rig, `SYSTEM`, 2026-09-08 (`docs/samples/windows.txt`) | n/a — reads do not fail closed; a win32 failure or bounded-call timeout on `EnumPrintersW` reports `CONSTRAINED`, never a permission error |
| macOS | agent daemon — **root** by documented exception (`docs/agent-privilege-model.md:14`: launchd's LaunchDaemon has no `UserName` key; the `_yuzu` unprivileged-account model is not yet applied on macOS), not the dedicated-unprivileged-account design line 12 describes for the other two platforms | None to read | this Mac, euid 501, 2026-09-14 (`docs/samples/macos.txt`) | n/a — reads do not fail closed |
| Linux | agent daemon, dedicated unprivileged account (`yuzu`), never root by design (`docs/agent-privilege-model.md:12`) | None to read | container, euid 0, 2026-09-14 (`docs/samples/linux.txt`) | n/a — reads do not fail closed |

No external binaries, no subprocesses, no shell-out — the IPP codec talks to cupsd's Unix socket (or `localhost:631` TCP, reads only) through `cpp-httplib` directly; Windows uses in-process winspool calls only. No network use beyond that local loopback/socket traffic — the CUPS socket carries no TLS by design (a local IPC channel, same trust boundary as any other local Unix socket).

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
| Definition | Parameter | Type | Required | Default | Constraints | Description |
|---|---|---|---|---|---|---|
| `crossplatform.printing.jobs` | `printer` | string | no | - | maxLength 256 | Optional printer name to filter to. When omitted, jobs across every printer are listed. |
<!-- END GENERATED -->

### Outputs

Every row is pipe-delimited, one row per printer/job. `printers`/`jobs` report `<kind>|none` when the read succeeded but nothing was found (an honest empty result, never conflated with a read failure). A field the platform mechanism did not report is `-` for a string field or `-1` for a count/size the mechanism could not determine.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`crossplatform.printing.jobs` — `printer|job_id|owner|document|status|submitted_at|size_bytes`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `printer` | string | - | Windows, Linux, macOS | `ipp://localhost/printers/Office-LaserJet` | The printer this job is queued on (URI on the IPP leg, printer name on Windows), or "-" when unavailable. |
| `job_id` | int64 | - | Windows, Linux, macOS | `42` | Job identifier. Values: 1 or greater. |
| `owner` | string | - | Windows, Linux, macOS | `alex` | The submitting user, or "-" when unavailable. |
| `document` | string | - | Windows, Linux, macOS | `hosts` | The job's document name/title, or "-" when unavailable. User content — see this definition's retention note above. |
| `status` | string | - | Windows, Linux, macOS | `processing` | Job status. Values: pending, held, processing, stopped, canceled, aborted, completed, unknown. |
| `submitted_at` | string | - | Windows, Linux, macOS | `2026-09-08T12:00:00Z` | ISO-8601 UTC submission timestamp, or "-" when unavailable. |
| `size_bytes` | int64 | - | Windows, Linux, macOS | `1024` | Job size in bytes, or -1 (unknown). |

**`crossplatform.printing.printers` — `name|state|state_reasons|is_default|make_model|uri|queued_jobs`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `name` | string | - | Windows, Linux, macOS | `Office-LaserJet` | Printer name/identifier as reported by the platform mechanism. |
| `state` | string | - | Windows, Linux, macOS | `idle` | Reported printer state. Values: idle, processing, stopped, unknown. |
| `state_reasons` | string | - | Windows, Linux, macOS | `-` | Comma-joined printer-state-reasons keywords, or "-" when none reported. winspool has no equivalent vocabulary and always reports "-". |
| `is_default` | boolean | - | Windows, Linux, macOS | `1` | Whether this is the system default printer. Values: 1, 0 — a digit, never true/false. |
| `make_model` | string | - | Windows, Linux, macOS | `Local Raw Printer` | Make/model string (IPP printer-make-and-model, or the winspool driver name), or "-" when unavailable. |
| `uri` | string | - | Windows, Linux, macOS | `ipp://localhost/printers/Office-LaserJet` | Printer URI (IPP printer-uri-supported, or the winspool port name), or "-" when unavailable. |
| `queued_jobs` | int64 | - | Windows, Linux, macOS | `0` | Number of jobs currently queued on this printer. Values: 0 or greater, or -1 (unknown — the mechanism did not report a count). |
<!-- END GENERATED -->

### Result status

`printers`/`jobs` set `OK`/`FULL` on every successful read, including a genuinely empty result (`printer|none`/`job|none`) — a read is never left `UNDECLARED`. Windows reports success or failure directly from the Win32 calls themselves (`EnumPrintersW`/`EnumJobsW`/`OpenPrinterW` — see Privileges and prerequisites for which of the three is actually bounded against a hang, and which is not); macOS/Linux additionally check the IPP response's own status code before trusting a zero-row result as "genuinely empty" — a request CUPS itself refuses (e.g. an unrecognised printer-uri) is `CONSTRAINED`, never reported as an empty queue.

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `OK` | full | (empty) | every platform: a successful read, populated or genuinely empty |
| `CONSTRAINED` | partial | `windows:winspool:enum_printers_failed` / `windows:winspool:open_printer_failed` / `windows:winspool:enum_jobs_failed` — `"CUPS-Get-Printers: transport failed"` / `linux:cups:connect_failed` / `macos:cups:connect_failed` — `"CUPS-Get-Printers: response did not decode"` / `linux:cups:decode_failed` / `macos:cups:decode_failed` — `"Get-Jobs: transport failed"` / `"Get-Jobs: response did not decode"` — `"CUPS-Get-Printers: unexpected status 0x⟨hex⟩"` / `"Get-Jobs: unexpected status 0x⟨hex⟩"` / `linux:cups:unexpected_status` / `macos:cups:unexpected_status` | Windows `printers`: `EnumPrintersW` failed or timed out (a bounded call — see Privileges and prerequisites). Windows `jobs`: the same `EnumPrintersW` failure, OR a specific printer's queue could not be opened (`OpenPrinterW` denied — NOT a bounded call), or its `EnumJobsW` read failed or was truncated at the row cap (also NOT a bounded call — see Privileges and prerequisites for why) — each is a per-printer skip, surfaced as `CONSTRAINED`/`PARTIAL` alongside whatever rows did succeed, never silently. macOS/Linux `printers`/`jobs`: the IPP round trip failed at the transport/decode step, or cupsd returned a status outside the successful range (RFC 8010 `0x0000`–`0x00FF`) — e.g. an unrecognised printer-uri, never silently read as zero rows |

### Where the data goes

- **Instruction result.** Every row is server instruction-result data — the standard retention policy, served over REST `/api/responses`. Nothing here is a durable server-side table of its own.
- **Not consumed by** daily-sync, TAR, DEX, or metrics — the plugin never runs on a schedule outside an explicit instruction dispatch, and there is no agent daily-sync source for print queues.
- **Sensitivity.** `jobs.document` is the job's user-supplied document title/filename — it is treated as user content: instruction-result retention only, never forwarded to daily-sync, TAR, or DEX. `jobs.owner` is a local account name on the target device.
- **Siblings:** `crossplatform.printing.printers`, `crossplatform.printing.jobs`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Windows 10.0.26200 x86_64 · bare-metal · 2026-09-08 · LocalSystem (elevated) · leg-hash 8aea1a515344

```
== action=printers
printer|OneNote (Desktop)|idle|-|0|Send to Microsoft OneNote 16 Driver|nul:|0
printer|Microsoft XPS Document Writer|idle|-|0|Microsoft XPS Document Writer v4|PORTPROMPT:|0
printer|Microsoft Print to PDF|idle|-|1|Microsoft Print To PDF|PORTPROMPT:|0
printer|Fax|idle|-|0|Microsoft Shared Fax Driver|SHRFAX:|0
[result_status] UNDECLARED / UNKNOWN

== action=jobs
job|none
[result_status] UNDECLARED / UNKNOWN
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-14 · euid 501 · leg-hash 8aea1a515344

```
== action=printers
printer|none
[result_status] OK / FULL

== action=jobs
job|none
[result_status] OK / FULL
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-14 · euid 0 · leg-hash 8aea1a515344

```
== action=printers
printer|yuzu_test|stopped|paused|0|Local Raw Printer|ipp://localhost:631/printers/yuzu_test|1
[result_status] OK / FULL

== action=jobs
job|ipp://localhost:631/printers/yuzu_test|1|-|-|pending|2026-09-14T17:27:40Z|1024
[result_status] OK / FULL
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **`jobs` reports only not-completed jobs; there is no completed-job history.** A job that has finished, failed, or was already cancelled by a previous call simply stops appearing — there is no lookup for it.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/printing/src/printing_ipp.hpp` · `agents/plugins/printing/src/printing_parsers.hpp` · `agents/plugins/printing/src/printing_plugin.cpp`
- Definitions: `content/definitions/printing.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_printing.hpp`
- Tests: `tests/unit/test_printing_local_dispatcher.cpp` · `tests/unit/test_printing_parsers.cpp`
- Privilege row: `docs/agent-privilege-model.md`
- Changelog: `changelog.d/wave9-pr91b-printing.added.md`
<!-- END GENERATED -->
