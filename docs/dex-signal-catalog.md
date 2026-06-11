# DEX Signal Catalogue

The Guardian DEX observer collects **103 reliability / employee-experience
signals** (wave 1: 20, wave 2: +50, wave 3: +33) from Windows endpoints as
ruleless observations (`rule_id = "__observation__"`, `event_type` = the
obs_type below). One catalogue-driven engine (`agents/core/src/dex_observer.cpp`)
arms one kernel-filtered `EvtSubscribe` per channel (22 channels); the signal
set, field extraction, privacy minimisations, and per-type rate caps all live
in `agents/core/src/dex_signal_catalog.cpp`. **Adding a signal is one catalogue
entry + one extractor + fixtures — zero server change** (the projection reads
the uniform `detail_json` keys generically, the `/dex` signal panel GROUP-BYs
whatever types exist, and unknown types render with a raw-label fallback under
"Other"). The dashboard groups the catalogue into 12 display groups; the
server-side mirror is `dex_signal_groups()` in `dex_routes.cpp` — keep it in
sync (the paired drift-net tests fail loudly if not).

Channels that do not exist on a given SKU fail to arm individually and are
logged + skipped (per-channel isolation; e.g. PushNotifications-Platform is
absent on some builds) — the catalogue row then honestly reads zero for that
device while other devices still report.

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

## Wave 1 — the first 20 signals

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

## Wave 2 — +50 signals (2026-06-10), by display group

Sources marked **real** are pinned by full-chain fixtures captured from a live
Win11 26100 box; the rest are manifest-best-effort and covered by the
whole-catalogue graceful-degradation test (empty/reordered fields → counted
occurrence, never a crash).

| Group | obs_type | Source | Notes / privacy |
|---|---|---|---|
| Boot, start-up & shutdown | `boot.degraded_app` | Diag-Perf/Op 101 **real** | subject=Name, metric=DegradationTime ms; **Path dropped** |
| | `boot.degraded_driver` | Diag-Perf 102 | same shape |
| | `boot.degraded_service` | Diag-Perf 103 **real** | same shape |
| | `boot.degraded_device` | Diag-Perf 109 | same shape |
| | `os.shutdown` | Diag-Perf 200 **real** | metric=ShutdownTime ms |
| | `shutdown.degraded` | Diag-Perf 203 **real** | app delaying shutdown |
| | `os.standby` | Diag-Perf 300 | occurrence + best-effort metric |
| | `os.standby_degraded` | Diag-Perf 301, 302 | resume slowed |
| | `logon.slow_subscriber` | Winlogon 6005, 6006 (Application) | e.g. GPClient — classic slow logon |
| | `os.uptime_report` | EventLog 6013 **real** | metric=uptime s (first numeric positional) |
| System stability | `os.dirty_shutdown` | EventLog 6008 **real** | co-fires with Kernel-Power 41 — never sum both |
| | `os.time_unsynced` | Time-Service 36, 47 **real** | metric=UnsynchronizedTimeSeconds |
| | `os.activation_failed` | Security-SPP 8198 (Application) | license activation |
| | `os.vss_error` | VSS 8193 (Application) | shadow-copy errors |
| | `fs.hive_recovered` | Kernel-General 5 | **hive path dropped** (ntuser.dat ⇒ username) |
| | `fs.autochk_ran` | Wininit 1001 (Application) | chkdsk output blob dropped |
| App reliability | `process.crashed_managed` | .NET Runtime 1026 **real** | app + exception TYPE only; **stack frames never shipped**; pairs with 1000 — crash counts use `process.crashed` alone |
| | `app.sxs_error` | SideBySide 33, 35, 59 | missing VC-runtime class; paths → basename |
| | `app.activation_failed` | Immersive-Shell / TWinUI 5973 | store-app activation |
| | `app.com_failed` | DistributedCOM 10005, 10010 | **10016 noise excluded** |
| | `app.error_popup` | Application Popup 26 **real** | the dialog the user actually saw (Caption+Message clipped) |
| | `app.shutdown_blocked` | RestartManager 10006 | **FullPath dropped** |
| Service health | `service.hung` | SCM 7022 | |
| | `service.start_timeout` | SCM 7009 **real** | params REVERSED vs 7000 (param2=service) |
| | `service.logon_failed` | SCM 7038 | **logon account dropped** |
| | `service.recovery_failed` | SCM 7032 | |
| Hardware & storage | `disk.smart_failure` | disk 52 | SMART predictive failure |
| | `disk.port_reset` | storahci + stornvme 129 | reset storms = dying disk/cable |
| | `fs.write_lost` | Ntfs 50 | delayed-write data loss |
| | `fs.database_corrupt` | ESENT 447, 454, 467 | **db paths dropped**, owner process kept |
| | `hw.device_start_failed` | Kernel-PnP/Configuration 411 **real** | DeviceInstanceId/DriverName/Status |
| | `hw.cpu_throttled` | Kernel-Processor-Power 37 | firmware thermal/power cap |
| Network | `network.wifi_connect_failed` | WLAN-AutoConfig 8002 **real** | SSID + FailureReason |
| | `network.dhcp_failed` | Dhcp-Client/Admin 1001, 1002 | |
| | `network.vpn_failed` | RasClient 20227 (Application) | **dialing user (insert %1) never read** |
| | `network.smb_failed` | SmbClient/Connectivity 30803 | server name kept (corp infra) |
| | `network.name_conflict` | NetBT 4319 | |
| Identity & logon | `logon.no_dc` | NETLOGON 5719 | domain kept |
| | `security.kerberos_error` | Security-Kerberos 4 | SPN/clock problems |
| | `logon.profile_locked` | User Profiles Service 1530 | **profile (≈person) not extracted** |
| | `logon.folder_redirect_failed` | Folder Redirection 502 | **folder paths dropped** |
| Security & protection | `security.rtp_disabled` | Defender 5001 | |
| | `security.threat_detected` | Defender 1116 | threat name kept; **file path + user dropped** |
| | `security.av_update_failed` | Defender 2001 **real** | Data names contain SPACES ('Error Code') |
| | `security.tamper_blocked` | Defender 5013 | |
| Updates & installs | `app_uninstall.failed` | MsiInstaller 11725 | same "Product: X --" parse as 11708 |
| | `app_install.appx_failed` | AppXDeployment-Server 404 **real** | PackageFullName + ErrorCode |
| | `update.transfer_failed` | Bits-Client 61 **real** | job name kept; **url dropped**; decimal `hr` → HRESULT hex |
| Printing | `print.driver_install_failed` | PrintService/Admin 215 | |
| | `print.plugin_failed` | PrintService/Admin 808 | dll → basename |

## Wave 3 — +33 signals (2026-06-10), the identity / remote-work / management lens

Real-record pins from the live box: Power-Troubleshooter 1 (**WakeDuration ms
metric** → resume-speed trend), User32 1074 (**param7 = initiating user,
dropped**; process basename + reason kept), TPM-WMI 1801 / Biometrics 1014 /
MDM 844 (validating the any-id + level≤2 pattern for providers whose error ids
vary), AAD 1097 (decimal `Error` → HRESULT hex; **ErrorMessage never shipped —
can embed UPNs**).

| Group | New types |
|---|---|
| Boot, start-up & shutdown | `boot.fast_startup_failed` (Kernel-Boot 29), `os.resume_report` (Power-Troubleshooter 1, metric), `os.restart_initiated` (User32 1074, user dropped) |
| System stability | `os.shadow_copies_lost` (volsnap 25), `os.crashdump_disabled` (volmgr 46), `display.dwm_exited` (DWM 9009) |
| App reliability | `process.file_access_failure` (1005, file path dropped), `app.push_notification_error` (WPN any-err), `app.file_association_reset` (Shell-Core 62), `app.staterepo_error` (StateRepository any-err) |
| Service health | `service.dependency_failed` (SCM 7001) |
| File system | `fs.flush_failed` (Ntfs 57) |
| Hardware & storage | `hw.user_driver_error` (UMDF 10110/10111), `hw.tpm_error` (TPM-WMI any-err) |
| Network | `network.port_exhaustion` (Tcpip 4227/4231), `network.smb_write_lost` (mrxsmb 50), `network.dns_register_failed` (DNS-Client 8015/8016), `session.rdp_disconnected` (TS-LSM 24/39/40 — **user + client address dropped**) |
| Identity & logon | `logon.winlogon_terminated` (4005), `logon.machine_trust_failed` (NETLOGON 3210), `logon.biometric_error` (any-err), `logon.hello_error` (any-err), `logon.aad_token_error` (AAD 1097/1098), `security.auth_error` (LsaSrv 40960/40961) |
| Security & protection | `security.tls_alert` (Schannel 36874/36887), `security.threat_action_failed` (Defender 1119), `security.rtp_error` (3002), `security.bitlocker_error` (any-err), `security.cert_enroll_failed` (AutoEnrollment 6/13) |
| Updates & installs | `update.check_failed` (WUC 16/25), `update.download_failed` (WUC 31) |
| Policy & management | `gpo.cse_failed` (GroupPolicy 1085), `mgmt.mdm_error` (DeviceManagement any-err) — `gpo.failed` moved into this group |

Deliberately still excluded: Security-channel logon events (privilege-gated),
Task Scheduler (channel disabled by default), DCOM 10016 + WMI-Activity 5858
(noise), app start-times / audio glitches / NCSI (need ETW collectors, not
event IDs — collector-gated future work).

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

## Testing methodology & evidence hygiene

Extractors are verified two ways: pure unit fixtures (the field layouts encoded
from provider manifests / real captured records) and a live **injection sweep**
that writes synthetic events through the real `EvtSubscribe` path to confirm the
end-to-end agent→server→`/dex` flow. Only **classic registered event sources**
can be written this way (`Write-EventLog`); manifest providers
(`Microsoft-Windows-*`) cannot be spoofed — which is also the security property
that makes forged DEX signals hard.

**Evidence-integrity rule (do this only on isolated rigs):** an injection sweep
writes events from sources like `Service Control Manager`, `Tcpip`, `NETLOGON`,
`disk`, and Defender into the host's *real* System/Application logs. On a managed
production endpoint that would contaminate SIEM pipelines, trip EDR/IDS rules (a
synthetic `machine-trust-failed` or threat detection reads as a real attack
indicator), and corrupt forensic evidence. **Run injection sweeps only on
isolated lab/test machines that are not managed endpoints, not ingested by a
customer SIEM, and not a potential forensic-evidence source.** To exercise the
collector on a real endpoint, trigger or wait for *genuine* events (restart a
test service, run a disk check) rather than injecting security-provider events.
