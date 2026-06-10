# DEX Signal Catalogue

The Guardian DEX observer collects **20 reliability / employee-experience
signals** from Windows endpoints as ruleless observations (`rule_id =
"__observation__"`, `event_type` = the obs_type below). One catalogue-driven
engine (`agents/core/src/dex_observer.cpp`) arms one kernel-filtered
`EvtSubscribe` per channel; the signal set, field extraction, privacy
minimisations, and per-type rate caps all live in
`agents/core/src/dex_signal_catalog.cpp`. **Adding signal #21 is one catalogue
entry + one extractor + fixtures — zero server change** (the projection reads
the uniform `detail_json` keys generically, the `/dex` signal-summary panel
GROUP-BYs whatever types exist, and unknown types render with a raw-label
fallback).

## Uniform observation shape

Every signal maps onto the same shape — on the wire (`detail_json`), in the
projection (`guardian_observations`), and in the dashboard:

| Field | Meaning | Examples |
|---|---|---|
| `subject` | The failing entity | `chrome.exe`, `Spooler`, `HQ-Laser-3`, `KB5055555`, `CorpNet` |
| `reason` | Machine-ish failure code | `0xC0000005`, `0x80070643`, `7031`, `timeout` |
| `symbolic` | Human name for reason | `ACCESS_VIOLATION`, `WIFI_DISCONNECT` |
| `component` | Secondary entity | `ntdll.dll` (faulting module), NIC description, MAC |
| `metric` | Numeric payload where the signal IS a number | boot duration ms |

`process.crashed` additionally dual-emits the legacy slice-1 keys
(`process`/`exception_code`/`faulting_module`) for the PR #1311 transition;
remove once that window closes.

## The 20 signals

| # | obs_type | Channel / Provider / Event IDs | DEX meaning | Cap (events/h) | Privacy minimisation | Verified |
|---|---|---|---|---|---|---|
| 1 | `process.crashed` | Application / Application Error / 1000 | App crash | 120 | `AppPath` never extracted | **live** (canary + real Win11 record) |
| 2 | `process.hung` | Application / Application Hang / 1002 | App not responding | 120 | — | fixture |
| 3 | `service.crashed` | System / Service Control Manager / 7031, 7034 | Service died unexpectedly | 60 | — | fixture + UAT canary |
| 4 | `service.start_failed` | System / Service Control Manager / 7000 | Service failed to start | 60 | — | fixture + UAT canary |
| 5 | `os.bugcheck` | System / WER-SystemErrorReporting **and** BugCheck / 1001 | BSOD | 30 | — | fixture |
| 6 | `os.power_loss` | System / Kernel-Power / 41 | Unexpected reboot (6008 deliberately excluded — co-fires with 41, would double-count) | 30 | — | fixture |
| 7 | `display.driver_reset` | System / Display / 4101 | GPU TDR (screen freeze/flash) | 60 | — | fixture |
| 8 | `hw.error` | System / WHEA-Logger / any id, Level ≤ 3 | Hardware (CPU/PCIe/memory) error | 30 | — | fixture |
| 9 | `disk.error` | System / disk / 7, 11, 51, 153 | Failing disk I/O (bad block / controller / paging / retried) | 30 | — | **real record** (event 11 added after a live box showed its disk failures land there) |
| 10 | `fs.corruption` | System / Ntfs **and** Microsoft-Windows-Ntfs / 55 | Filesystem corruption | 30 | — | fixture |
| 11 | `memory.exhausted` | System / Resource-Exhaustion-Detector / 2004 | Commit-charge exhaustion | 12 | — | fixture |
| 12 | `os.boot` | Diagnostics-Performance/Operational / 100 | Boot duration (ms, every boot — trendable) | 30 | — | fixture |
| 13 | `update.failed` | System / WindowsUpdateClient / 20 | Patch install failure | 30 | KB title kept (corp patch info) | fixture |
| 14 | `app_install.failed` | Application / MsiInstaller / 11708 | MSI install failure | 60 | — | fixture |
| 15 | `logon.temp_profile` | Application / User Profiles Service / 1511, 1508 | Temp profile / profile load failure | 12 | **username never extracted** | fixture |
| 16 | `gpo.failed` | System / GroupPolicy / 1125, 1129 | Group Policy processing failure | 12 | — | fixture |
| 17 | `network.wifi_drop` | WLAN-AutoConfig/Operational / 8003 | Wi-Fi disconnect (reason text kept) | 60 | SSID kept (network infra) | fixture |
| 18 | `network.dns_timeout` | System / DNS Client Events / 1014 | Name resolution failing | 30 | **queried hostname never extracted** (browsing behavior) | fixture |
| 19 | `network.ip_conflict` | System / Tcpip / 4199 | IP address conflict | 12 | — | fixture |
| 20 | `print.failed` | PrintService/Admin / 372 | Print failure (top helpdesk driver) | 60 | **document name + owner never extracted**; printer kept | fixture |

"fixture" = the extractor is pinned by a unit fixture encoding the provider's
manifest field layout; field-name drift on a real box degrades gracefully
(empty `subject`, occurrence still counted).

**Real-record verification (2026-06-10):** full-chain fixtures captured from a
live Win11 26100 box now pin `process.crashed` (slice 1), `service.crashed`
(7031), `service.start_failed` (7000 incl. the `%%1053` message-resource form),
`os.power_loss` (41), `os.boot` (100, 64.9 s boot), `update.failed` (20),
`app_install.failed` (11708), `network.wifi_drop` (8003 — **Level 4**, which is
why that spec carries no level filter), and `disk.error` (11). `process.hung`
is canary-verified through the live pipeline (synthetic 1002). Still
manifest-pinned (no local specimen exists — they require a BSOD, hardware
fault, FS corruption, DNS outage, etc.): `os.bugcheck`, `display.driver_reset`,
`hw.error`, `fs.corruption`, `memory.exhausted`, `logon.temp_profile`,
`gpo.failed`, `network.dns_timeout`, `network.ip_conflict`, `print.failed` —
each degrades to a counted occurrence if its field layout drifts.

**Dashboard visibility contract:** the `/dex` All-signals panel lists every
catalogued type, fired or not (quiet types as muted real-zero rows), so
operators see what the fleet monitors — `kDexCatalogueOrder` in
`dex_routes.cpp` is the server-side mirror of this table; keep both in sync
when adding a signal.

## Privacy / works-council contract

Extractors drop user content **at the edge, before anything leaves the
device**: DNS queried names, print document names/owners, profile usernames,
image paths. What is never extracted can never be exfiltrated or mis-scoped.
This is the data-minimisation half of the co-determination posture (see memory
`project-telemetry-privacy-works-council`); the per-device drill-down is
additionally permission-gated and audit-logged server-side. Remaining product
gaps (per-category collection toggles, individual-view kill switch,
pseudonymization, operator-set retention) are tracked as roadmap items, not
solved here.

## Rate caps

Each obs_type carries `max_per_hour`; the engine counts per fixed hour-bucket
and drops the overflow with ONE warn per (type, bucket). Storm-prone providers
(WHEA corrected-error loops, failing disks issuing retry storms, Wi-Fi flaps)
cannot flood the wire or the Guardian event store. Caps are deliberately
generous for genuine incident rates.

## macOS mapping (future collectors)

The shape is OS-neutral; the planned macOS sources are:

| obs_type | macOS source |
|---|---|
| `process.crashed` | DiagnosticReports `.ips` crash reports |
| `process.hung` | spindump / `.hang` reports |
| `os.power_loss` | shutdown-cause codes (`previous shutdown cause`) |
| `os.boot` | `kern.boottime` + login-window timing |
| `disk.error` / `fs.corruption` | `fsck` / IOKit error logs |
| `update.failed` | `softwareupdate` history |

Linux: journald-based collectors (coredumpctl, systemd unit failures, OOM
killer) follow the same catalogue pattern.

## Wire + read-model invariants

- **No proto change** for new signals: `detail_json` is keyed by `event_type`
  (route a′); the gateway forwards `GuaranteedStateEvent` opaquely.
- The projection (`guardian_observations`, migration {7}) is written **inside
  the event transaction** — duplicate `event_id` rolls back both (at-least-once
  dedup), and the reaper deletes projection rows in lockstep with events.
- Observations are facts, not alerts: severity is uniformly `info`; DEX applies
  its own framing and ignores Guardian severity.
- The headline dashboard rate stays **crash-free devices** (crash-scoped);
  other signals get their own panels. Rates always pair with coverage
  (reporting Windows agents) and show "—" when the denominator is missing.
