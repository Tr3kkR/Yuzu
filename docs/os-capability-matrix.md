# OS capability matrix

**What this is:** a per-capability × per-OS snapshot of what the Yuzu **agent**
actually collects/enforces on Windows, Linux, and macOS — the thing that was
missing when the `/network` tab showed no data on a Windows-only fleet (the
collector was Linux-only and nothing surfaced that gap). It now covers the
whole agent surface, grouped into sections: **agent core**, **Guardian guards**,
**Spark detection mechanisms**, **DEX**, **TAR warehouse capture sources**,
**inventory / daily-sync sources**, **live device snapshot**, **network
quality**, and every **agent plugin** (49).

**Read this first — accuracy & drift.** This is a *curated snapshot*, and a
hand-maintained matrix drifts from code exactly the way the gap above happened.
Each row therefore cites its **source of truth in code**; trust the code over this
table, and when you change per-OS support, update both. The durable fix is to
**generate** this matrix from the machine-readable per-OS metadata that already
exists (see [Make this self-maintaining](#make-this-self-maintaining)) — treat
this doc as the interim, not the destination.

Legend: ✅ Full · 🟡 Partial / constrained · 🔜 Planned/spike · ⛔ None

For **TAR capture sources** the cells map directly to the registry enum
`OsSupportStatus` (`tar_schema_registry.hpp:56`): `kSupported` → ✅,
`kSupportedConstrained` → 🟡, `kPlanned` → 🔜, `kUnsupported` → ⛔ (no source
currently uses `kUnsupported` — every macOS/Linux gap is `kPlanned`,
pre-staged/queryable-empty, not hard-unsupported).

_Last re-verified against code: 2026-07-20 (all rows re-checked against the cited
sources; see [Verification](#verification))._
_Last hand-updated: 2026-07-20 (folded in the macOS-parity batch — see Verification)._

## Matrix

One table, split into sections by the bold divider rows. Some capability rows are
powered by a plugin that also has its own row in the **Agent plugins** section at
the foot — the capability row states the *feature's* per-OS depth, the plugin row
states the plugin's overall per-OS build/availability; they are consistent, not
duplicates.

| Capability / component | Windows | Linux | macOS | Source of truth |
|---|:---:|:---:|:---:|---|
| **━━ Agent core ━━** | | | | |
| **Agent core** (enroll, heartbeat, plugin host, triggers, KV, mTLS) | ✅ | ✅ | ✅ | `agents/core/` builds + enrolls on all three |
| **━━ Guardian guards — agent-side enforcement (Guaranteed State) ━━** | | | | The engine dispatches exactly **three** guard families in `guardian_engine.cpp` (`start_guard_for_rule_locked`, by `rule.spark().type()`). No process/firewall/launchd guard exists. `IGuard` interface: `agents/core/include/yuzu/agent/guard.hpp` |
| **Guardian — registry guard** (`registry-change` / `registry-value-equals`) | ✅ enforce | ⛔ | ⛔ | `guard_registry.cpp` / `RegistryGuard`: full impl under `#ifdef _WIN32` (advapi32 watch; enforce recreates key chain + rewrites value). Non-Windows `start()`→`false` no-op (covers Linux **and** macOS). Support array `registry_support::kHives = {HKLM,HKCU,HKCR,HKU}` (`guard_registry.hpp:43`), H2-cross-checked vs published schema enum |
| **Guardian — file guard** (`file-change` / `file-exists`, `file-hash-equals`) | 🟡 observe-only | ⛔ | ⛔ | `guard_file.cpp` / `FileGuard`: Windows impl (`ReadDirectoryChangesW` + bounded SHA-256) is **detection-only by design — it never writes on any platform** (content remediation is deferred to Content Distribution). Non-Windows `start()`→`false` no-op (Linux + macOS) |
| **Guardian — service run-state guard** (`service-status-change` / `service-running`, `service-stopped`) | ✅ enforce | 🟡 observe-only | ⛔ | Factory `make_service_guard()` (`guard_systemd.cpp:157`): Linux → `SystemdServiceGuard` (sd-bus watch; **enforce explicitly DEFERRED**, governance-gated — an enforce rule logs a downgrade), else → `ServiceGuard`. Windows `ServiceGuard` (`guard_service.cpp`, SCM `NotifyServiceStatusChangeW` + `StartServiceW`/`ControlService`) enforces; macOS falls to the `ServiceGuard` no-op stub. Support array `service_support::kStates = {running,stopped}` (`guard_service.hpp:56`) |
| **━━ Spark detection mechanisms (ADR-0021) ━━** | | | | The ADR-0021 reflex layer that will *replace* the legacy `IGuard` path above. `make_{file,registry,service}_mechanism()` in `spark_mechanism.hpp` returns `nullptr` off-platform (type left unregistered). **Not yet live:** rung 7 wired Guardian as the first consumer (`GuardianEngine::reconcile_rule_locked()`), but `prefer_spark_` defaults `false` and `agent.cpp` has **zero** `wire_spark_engine()` call sites, so legacy `IGuard` remains the sole live path |
| **SparkEngine mechanisms** (file / registry / service; observe-only) | ✅ file + registry + service | 🟡 service only — **and NONE in a container** (see note) | ⛔ none | File/Registry are Windows-only; Service is Win-SCM + Linux-sd-bus; macOS none. **Registered ≠ functional:** a mechanism that starts but cannot bind its OS facility is marked INERT and EXCLUDED from the capability CSV (`sd_bus_open_system()` failing in `spark_service.cpp`; `OpenSCManager` denied; threadpool/IOCP failing). **The container case is common:** `Dockerfile.agent` installs `libsystemd0` but a container has **no system bus**, so a containerised Linux agent registers Service INERT and ends up with **zero** spark capability (`spark_running=1`, empty `spark_mechs` CSV, no `{os=linux,mechanism=*}` series). Fleet view `yuzu_fleet_spark_mechanisms{os,mechanism}`; an inert agent shows as a GAP (`yuzu_fleet_spark_reporting{os}` exceeding the sum of mechanisms) |
| **━━ DEX — Digital Employee Experience ━━** | | | | Server-side coverage map `dex_obs_platforms()` (`dex_routes.cpp:132-174`) is the hand-maintained mirror, drift-net-tested vs the agent collectors. Catalogue: `docs/dex-signal-catalog.md`; defs `dex_signal_catalog.cpp` |
| **DEX — reliability signals** (crashes, hangs, service/boot, storage, kernel faults, perf/thermal, …) | ✅ (~110 event types + state-poll) | 🟡 (17 obs_types) | 🟡 (17 obs_types) | Win: `dex_observer.cpp`/`dex_win_poll.cpp` — the catalogue IS the `EvtSubscribe` set (22 channels, waves 1–4). Linux: `dex_linux_collector.cpp` + `dex_linux_{proc,storage,journal,kmsg,sysfs}.cpp` (perf trio + storage/uptime + journald crash/hung + kernel panic/OOM/disk/fs/MCE/hung-task + thermal). macOS **real & shipped**: `dex_macos_collector.cpp` + `dex_macos_{signals,oslog,iokit}.cpp` (DiagnosticReports `.ips` crashes/hangs/panics/jetsam, OSLog service-crash/wifi-drop/daemon-errors at **Error and Fault** level — `oslog_predicate()` requests both, reaching Fault-level `com.apple.apfs` `fs.corruption` — IOKit SMART/battery/storage/thermal/mem-pressure); covers ~10/11 headings unprivileged |
| **DEX — performance telemetry** (sustained-breach CPU/mem/disk levels — the `perf.*` trio) | ✅ | ✅ | ⛔ | Win `dex_win_poll.cpp` + Linux `/proc` both drive `dex_perf_breach.cpp` for all three. macOS emits **no** `perf.cpu_sustained`/`perf.memory_pressure`/`perf.disk_latency_high` (only adjacent state signals: thermal-throttle, mem-pressure warning, storage-low). Separately, the TAR `perf` source samples levels on Win+Linux (see TAR section) — macOS there is `kPlanned` too |
| **DEX — per-app file version** (the `(name, version)` identity) | ✅ real on-disk version | ⛔ (emits `""`) | 🟡 crash/hang via `.ips` | Win: `GetFileVersionInfoW` + `VS_FIXEDFILEINFO` (`tar_proc_perf.cpp:415-456`). Linux (`:630`) has no handle-free version source → `""` unknown bucket. macOS `process.crashed`/`process.hung` now read `CFBundleShortVersionString` from the `.ips` (header `app_version`, else body `bundleInfo`) via `ips_app_version()` (`dex_macos_signals.cpp`); macOS procperf (`:650`) still emits `""`. All normalized by `canon_version` |
| **DEX — per-app performance over time** (B1 per-device daily + B2 fleet aggregate, by `(app, version, day)`) | ✅ | 🟡 (samples; version `""`) | ⛔ (no data) | Fed by the TAR proc-perf sampler → `app_perf` daily-sync source (`sync_source_app_perf.cpp`) → server `AppPerfDailyStore` (B1) → `AppPerfRollup`/`AppPerfFleetStore` (B2). macOS `read_proc_counters()` returns `valid=false` (`tar_proc_perf.cpp:643`) — records nothing; server plumbing is platform-agnostic and lights up when the macOS collector lands |
| **━━ TAR warehouse capture sources ━━** | | | | **Authoritative & machine-readable:** `tar_schema_registry.cpp` `build_sources()` — 13 sources, per-OS `OsSupportStatus` + notes + `capture_method`. Enable flag is uniformly `<name>_enabled` in `tar_config`; 5 sources on by default, 8 opt-in (off). Implementer guide: `docs/tar-implementer.md` |
| **TAR — process** (`$Process`) · *on* | ✅ etw | ✅ procfs | 🟡 endpoint_security | Win ETW Kernel-Process (Toolhelp fallback), names-only, no cmdline; Linux `/proc/<pid>/{status,cmdline}`; macOS ES NOTIFY_EXEC/EXIT where entitled else `KERN_PROC_ALL` poll. Collectors `tar_proc_stream.cpp`/`tar_proc_etw.cpp`/`tar_proc_es.cpp` |
| **TAR — tcp** (`$TCP`) · *on* | ✅ iphlpapi | ✅ procfs | 🟡 nstat + proc poll | Win `GetExtendedTcpTable`/UDP poll; Linux `/proc/net/{tcp,udp}*` (short lifetimes may be missed); macOS sub-second TCP connect/close is event-driven via `nstat` (`com.apple.network.statistics` kctl `SRC_ADDED`/`SRC_REMOVED`), with `proc_pidfdinfo` demoted to fallback/seed + UDP (ES has no inet-socket events). `tar_network_collector.cpp`/`tar_netqual_nstat.cpp` |
| **TAR — service** (`$Service`) · *on* | ✅ scm | 🟡 systemctl | 🟡 launchctl | Win SCM (display_name/status/startup_type); Linux `systemctl list-units` (startup_type unknown; non-systemd hosts unsupported); macOS `launchctl list` (running/stopped only). `tar_service_collector.cpp` |
| **TAR — user** (`$User`) · *on* | ✅ wts | 🟡 utmp | 🟡 utmpx | Win WTS sessions (interactive/RDP/console); Linux `/var/run/utmp` (empty without utmp; type inferred from tty); macOS `getutxent` (GUI logins not always reflected). `tar_user_collector.cpp` |
| **TAR — perf** (`$Perf`) · *on* | ✅ ntcounters | ✅ procfs | 🔜 host_statistics | Win `GetSystemTimes`/`GlobalMemoryStatusEx`/disk IOCTL/`GetIfTable2` (no PDH/WMI); Linux `/proc/{stat,meminfo,diskstats,net/dev}`; macOS `host_statistics64`+IOKit **planned** (queryable-empty). `tar_perf.cpp` |
| **TAR — procperf** (`$ProcPerf`) · *opt-in* | ✅ ntsysinfo | ✅ procfs | 🔜 libproc | Win `NtQuerySystemInformation` + least-privilege version read; Linux `/proc/[pid]/stat` (version always `""`); macOS `proc_pid_rusage` **planned**. `procperf_enabled`. `tar_proc_perf.cpp` |
| **TAR — netqual** (`$NetQual`) · *opt-in* | 🟡 estats | ✅ inetdiag | 🟡 nstat | Linux netlink SOCK_DIAG TCP_INFO (non-root, `ss -ti`-equivalent); Win TCP ESTATS (ADR-0020) **admin-only** — non-elevated records nothing (`netqual_capture_method=none`); macOS `nstat` per-flow `SRC_DESC`/`SRC_COUNTS` via the `com.apple.network.statistics` kctl (`kSupportedConstrained`) — **root required** for system-wide visibility else `netqual_capture_method=none` (no silent partial), private struct guarded by a runtime wire-layout self-check. `netqual_enabled`. `tar_netqual.hpp`/`tar_netqual_boot.cpp`/`tar_netqual_nstat.cpp` |
| **TAR — module** (`$Module`) · *opt-in* | ✅ etw | 🔜 auditd | 🔜 endpoint_security | Win ETW image-load + WinVerifyTrust signing; Linux kmod via auditd (`.so` needs eBPF, deferred; M6); macOS ES KEXT/dylib (M4/M5) — both **planned**. `module_enabled`. `tar_module_etw.cpp`/`tar_module_stream.cpp` |
| **TAR — software** (install/uninstall events) (`$Software`) · *opt-in* | ✅ registry | 🔜 dpkg_rpm | 🔜 pkgutil | Win registry Uninstall keys diffed (HKLM 64/32-bit; machine scope only; #1620); Linux dpkg/rpm/pacman and macOS `system_profiler`/pkgutil **planned** (fast-follow). `software_enabled`. Distinct from the daily *inventory* sync row (events vs point-in-time). `tar_software_collector.cpp` |
| **TAR — arp** (`$ARP`) · *opt-in* | ✅ iphlpapi | 🔜 procfs | 🔜 route_sysctl | Win `GetIpNetTable2` (full mac/entry_type); Linux `/proc/net/arp` and macOS route sysctl (mac present, entry_type `unknown`) **planned**. `arp_enabled` (ADR-0015). `tar_arp_collector.cpp` |
| **TAR — dns** (cache) (`$DNS`) · *opt-in* | ✅ dnsapi | 🔜 systemd-resolved | 🔜 dscacheutil | Win `DnsGetCacheDataTable` (name/type/data/TTL); Linux resolve1 D-Bus (hosts-file fallback) and macOS `dscacheutil` (no TTL) **planned**. Device-level usage-class PII, names-only. `dns_enabled` (ADR-0015). `tar_dns_collector.cpp` |
| **TAR — netconn** (connectivity-transition timeline) (`$NetConn`) · *opt-in* | ✅ wevtapi | 🔜 journald | 🔜 oslog | Win EvtQuery over NetworkProfile/NCSI/WLAN-AutoConfig channels (allow-listed fields); Linux NetworkManager/networkd journal and macOS configd/Wi-Fi OSLog **planned**. `netconn_enabled`. `tar_netconn_win.cpp` |
| **TAR — mapdrive** (network-share mappings) (`$MapDrive`) · *opt-in* | ✅ wnet | 🟡 procfs | 🔜 getfsstat | Win WNet outbound + NetSessionEnum inbound (+ history); Linux `/proc/mounts` cifs/nfs (username unavailable) + `smbstatus`; macOS `getfsstat`/smbutil **planned** (empty today). `mapdrive_enabled`. `tar_mapdrive_collector.cpp` |
| **━━ Inventory & daily-sync sources (→ central Postgres) ━━** | | | | Agent daily-sync framework `sync_scheduler.cpp` pushes per-source state over `ReportInventory` (hash-skip), reusing plugins via `LocalDispatcher`. ADR-0016 |
| **Installed-software inventory** | ✅ | ✅ | ✅ | `sync_source_installed_software.cpp` reuses `installed_apps` `list_inventory` (Win registry; Linux dpkg/rpm/pacman/**apk**; macOS `system_profiler`). Blob contract v2 (kind/ecosystem/EVR/arch/packager + rpm signature_status + distro; honest-empty; Win/macOS rows = kind=app, name/version/publisher). Machine-scope only. Server `SoftwareInventoryStore` |
| **Software-licence detection (SLE)** | ✅ (WMI `SoftwareLicensingProduct` + Office C2R + `ProbeSpec` + per-user hives/files) | 🟡 (rpm/dpkg declared-licence classification — no lapse detection; RHEL entitlement + FlexLM `.lic` expiry authoritative) | 🟡 (`_MASReceipt` + machine-scope vendor plists — `probable` confidence only) | Per-OS TUs `license_scan/src/licensing_{win,wmi,linux,macos}.cpp`; `sync_source_software_licensing.cpp` → `SoftwareLicensingStore` (ADR-0024). Detail: `docs/user-manual/software-licensing.md`. Java + SWID tags are the fast-follow (#2112) |
| **Device-identity inventory** (serial, UUID, BIOS, CPU/RAM/disk, MAC, OS) | ✅ | ✅ | ✅ | `sync_source_device_ci.cpp` reuses `hardware`/`device_identity`/`os_info`/`network_config`. `hardware` `system`: Win WMI `Win32_BIOS`/`Win32_ComputerSystemProduct`; Linux `/sys/class/dmi/id/product_{serial,uuid}` (0400 → needs `cap_dac_read_search`; `unknown` without it); macOS `ioreg IOPlatformExpertDevice` (`IOPlatformUUID` ≠ SMBIOS UUID). Machine-scope only. Server `DeviceInventoryStore` |
| **━━ Live device snapshot ("Get live info") ━━** | | | | Device page dispatch-and-poll snapshot; each kind has its own `device.live.<kind>` audit verb. `docs/user-manual/device-management.md` |
| **Live — process tree + per-process connections** | ✅ tree + conn join | 🟡 tree; conn join absent | 🟡 tree | `processes/list_tree` (`proc\|pid\|ppid\|name\|sha256\|path`, all OSes) joined by PID to `network_diag/connections` (owning PID via `GetExtendedTcpTable`, Windows). Linux `/proc/net/tcp` exposes inode not pid → no join |
| **Live — ARP / neighbour table** | ✅ | 🔜 (`/proc/net/arp`) | 🔜 (route sysctl) | `network_config/arp` (`GetIpNetTable2`); no-op note elsewhere |
| **Live — DNS resolver cache** | ✅ | ⛔ (no portable resolver cache) | ⛔ | `network_config/dns_cache` (`DnsGetCacheDataTable` on Windows; macOS returns an honest `dns_cache\|unsupported` sentinel — `dscacheutil -cachedump` is defunct on modern macOS) |
| **Live — disk space** | ✅ | ✅ | ✅ | `disk_space` plugin `free` action; `GetDiskFreeSpaceExW` on Windows, `statvfs` on POSIX |
| **Live — Wi-Fi current connection** | ✅ | ✅ | 🟡 | `wifi/connected` — Win `WlanQueryInterface`, Linux `nmcli`/`iwconfig`, macOS `wifi_corewlan.mm` `corewlan_current_connection` (CoreWLAN `CWWiFiClient`/`CWInterface`, first `.mm` TU; pure `format_connected_record` in `wifi_corewlan.hpp`). macOS 🟡: association/RSSI/channel/security read, but SSID/BSSID are withheld from a background daemon by Location Services on 14+ (`<ssid-withheld>`) — replaces the dead `airport -I` path |
| **━━ Network quality (`/network`) ━━** | | | | Measurement-first device/local-link health lens. `net_quality_sampler.cpp`; `docs/user-manual/network.md` "Platform coverage" |
| **Network quality** (throughput / retransmit / RTT) | 🟡 throughput + retransmit (no RTT) | ✅ all three | 🟡 throughput only | Win `GetIfTable2` throughput + `GetTcpStatisticsEx` system-wide interval retransmit (**measurement-first, not loss-validated** — withheld from the fleet retransmit aggregate); RTT needs ESTATS (admin+overhead) → 🔜. Linux has all three. macOS `NET_RT_IFLIST2` throughput only (`read_net_counters()` sums non-loopback `if_data64` rx/tx, differenced per heartbeat); retransmit + RTT deferred — global `net.inet.tcp.stats` reads all-zero on modern macOS → 🔜 |
| **━━ Agent plugins (49) — per-plugin build/availability ━━** | | | | Per-OS via platform macros / per-OS TUs (`agents/plugins/*/src/*`). 43 fully cross-platform, 4 Windows-only, 2 uneven (`tar`, `msi_packages` — Win+macOS). "Full" = the plugin builds and its core actions work on that OS; a plugin can be cross-platform yet expose a few OS-specific actions (noted) |
| agent_actions | ✅ | ✅ | ✅ | portable — no platform macros |
| agent_logging | ✅ | ✅ | ✅ | `_WIN32`/`__APPLE__`/Linux branches all implemented |
| antivirus | ✅ | ✅ | ✅ | Defender/WMI · ClamAV+Falcon+Sophos · macOS real probes — XProtect bundle version + endpoint-security system-extension enumeration (`antivirus_plugin.cpp`, parsers `antivirus_parsers.hpp`), no longer a hardcoded assertion (posture depth: the **Antivirus posture** row) |
| asset_tags | ✅ | ✅ | ✅ | portable — `std::filesystem` only |
| bitlocker | ✅ | ✅ | ✅ | BitLocker `manage-bde` · LUKS `cryptsetup` · FileVault `fdesetup` + per-APFS-volume `diskutil apfs list` (encrypted/not_encrypted/unknown, parser `bitlocker_macos_apfs.hpp`) |
| certificates | ✅ | ✅ | ✅ | full per-OS blocks (`_WIN32`/`__linux__`/`__APPLE__`) |
| chargen | ✅ | ✅ | ✅ | portable — RFC 864 generator |
| content_dist | ✅ | ✅ | ✅ | `_WIN32` vs POSIX; HTTPS gated on OpenSSL build option, not OS |
| device_identity | ✅ | ✅ | ✅ | all three branches implemented |
| diagnostics | ✅ | ✅ | ✅ | portable — `std::filesystem` checks |
| discovery | ✅ | ✅ | ✅ | all three branches implemented |
| disk_space | ✅ | ✅ | ✅ | linux/apple/win branches; `#else` unsupported only |
| event_logs | ✅ | ✅ | ✅ | win/linux/apple branches |
| example | ✅ | ✅ | ✅ | portable — sample plugin |
| filesystem | ✅ | ✅ | ✅ | `_WIN32` vs POSIX. Caveat: Authenticode signature-verify action is Windows-only |
| firewall | ✅ | ✅ | ✅ | win/linux/apple all implemented |
| hardware | ✅ | ✅ | ✅ | linux/apple/win branches throughout |
| http_client | ✅ | ✅ | ✅ | `_WIN32` vs POSIX; HTTPS gated on OpenSSL build option |
| installed_apps | ✅ | ✅ | ✅ | linux/apple/win branches (feeds inventory sync) |
| interaction | ✅ | ✅ | 🟡 | win/apple/linux branches. macOS caveat: as a GUI-less root LaunchDaemon `message_box` can't reach a WindowServer session — the `osascript` leg reports an honest `status\|not_reachable` (never a fabricated `response\|ok`), decoded via pure `interaction_parsers.hpp` in `interaction_plugin.cpp`; delivering the dialog to the logged-in user is a deferred per-session helper |
| ioc | ✅ | ✅ | ✅ | win/linux/apple all implemented |
| license_scan | ✅ | ✅ | ✅ | per-OS TUs `licensing_{win,linux,macos}.cpp` (feeds SLE sync) |
| msi_packages | ✅ | ⛔ | ✅ | Win MSI (`MsiEnumProductsA`); macOS `pkgutil --pkgs`/`--pkg-info` receipts (reverse-domain id / derived name / version / install location) — pure parser `msi_packages_macos.hpp` + `__APPLE__` branch in `msi_packages_plugin.cpp` (500-pkg cap, `__truncated__` sentinel); Linux `#else` → "platform not supported" |
| netprobe | ✅ | ✅ | ✅ | `_WIN32` vs POSIX portable sockets |
| netstat | ✅ | ✅ | ✅ | linux/apple/win branches |
| network_actions | ✅ | ✅ | ✅ | win/linux/apple branches. macOS `flush_dns` runs both `dscacheutil -flushcache` **and** `killall -HUP mDNSResponder` (the load-bearing reset), honest status from real exit codes (`network_actions_plugin.cpp`) |
| network_config | ✅ | ✅ | ✅ | win/linux/apple throughout. macOS: real adapter link speed via `SIOCGIFMEDIA` (was hardcoded 0); `arp`/`dns_cache` return honest `not_available`/`unsupported` sentinels (`network_config_plugin.cpp`) |
| network_diag | ✅ | ✅ | ✅ | win/linux/apple all implemented |
| os_info | ✅ | ✅ | ✅ | linux/apple/win branches |
| processes | ✅ | ✅ | ✅ | win/linux/apple branches (point-in-time enum; streaming capture is under TAR `process`) |
| procfetch | ✅ | ✅ | ✅ | linux/apple/win branches |
| quarantine | ✅ | ✅ | ✅ | full per-OS blocks |
| rdp_control | ✅ | ⛔ | ⛔ | Windows-only. Off-Windows returns an honest `rdp_control\|unsupported` sentinel (macOS names Screen Sharing); state-changing `set_state` reports terminal FAILURE, read-only `status` rc=0 — `rdp_control_plugin.cpp` `#ifndef _WIN32` branch |
| registry | ✅ | ⛔ | ⛔ | Windows-only (advapi32). Off-Windows returns an honest `registry\|unsupported` sentinel (reads rc=0; mutating `set_value`/`delete_*` report terminal FAILURE — no false success) — `registry_plugin.cpp` `#ifndef _WIN32` branch |
| sccm | ✅ | ⛔ | ⛔ | Windows-only. macOS returns an honest `sccm\|unsupported` (points at Jamf/MDM); Linux `installed\|false` + "platform not supported" — `sccm_plugin.cpp` `__APPLE__` branch |
| script_exec | ✅ | ✅ | ✅ | win/apple/linux. Different action sets per OS (`bash` POSIX-only; powershell/cmd on Windows) |
| services | ✅ | ✅ | ✅ | win/linux/apple branches. macOS `list`/`running` now emit `startup_type` (automatic/disabled/unknown) from a bulk `launchctl print-disabled` join (parser `services_macos_launchd.hpp`); `set_start_mode` rejects `manual` (launchd is binary enable/disable) |
| sockwho | ✅ | ✅ | ✅ | linux/apple/win branches |
| software_actions | ✅ | ✅ | ✅ | win/linux/apple branches |
| status | ✅ | ✅ | ✅ | linux/apple/win branches |
| storage | ✅ | ✅ | ✅ | portable — persistent KV store |
| tags | ✅ | ✅ | ✅ | portable — `std::filesystem` |
| **tar** | ✅ | 🟡 | 🟡 | Uneven by design — richest on Windows (ETW/dnsapi/registry), `/proc`-based on Linux, ES + scattered branches on macOS. Per-source depth is the **TAR warehouse capture sources** section above (`tar_schema_registry.cpp`) |
| users | ✅ | ✅ | ✅ | linux/apple/win branches. macOS `local_users` now adds real `last_logon` (`last -y`) and a tri-state `console_state` GUI-login flag (`SCDynamicStoreCopyConsoleUser`, shared `macos_console_user.hpp`) |
| vuln_scan | ✅ | ✅ | ✅ | linux/apple/win branches |
| wifi | ✅ | ✅ | ✅ | win/linux/apple all implemented; macOS `connected` via CoreWLAN (`wifi_corewlan.mm`), `list_networks` legacy `airport -s`/`system_profiler` (connection depth: the **Live — Wi-Fi current connection** row) |
| windows_updates | ✅ | ✅ | ✅ | update history / rpm+apt / `system_profiler` install history (Linux/mac report installed-package history) |
| wmi | ✅ | ⛔ | ⛔ | Windows-only (`#ifndef _WIN32` → not available) |
| wol | ✅ | ✅ | ✅ | `wol_plugin.cpp` — `_WIN32` vs POSIX portable UDP broadcast (wake); macOS `check` reachability now uses `ping -t 2` (BSD whole-run deadline; the shared POSIX `-W 2` path meant 2 ms on Darwin → every live host falsely `unreachable`) |
| **Guardian — registry guard** | ✅ | ⛔ | ⛔ | `guard_registry.cpp` (no-op off-Windows); `registry_support::kHives` |
| **Guardian — file guard** | ✅ | ⛔ | ⛔ | `guard_file.cpp` (no-op off-Windows) |
| **Guardian — service run-state guard** | ✅ enforce | 🟡 observe-only | ⛔ | `make_service_guard()` in `guard_systemd.hpp`; Win `ServiceGuard` (SCM), Linux `SystemdServiceGuard` (sd-bus, enforce deferred) |
| **SparkEngine detection mechanisms** (ADR-0021 Stage-2; observe-only at rung 1) | ✅ file + registry + service | 🟡 service only — **and NONE in a container** (see note) | ⛔ none | `make_{file,registry,service}_mechanism()` in `spark_mechanism.hpp` (returns `nullptr` off-platform → type left unregistered): File/Registry Windows-only, Service Win-SCM + Linux-sd-bus, macOS none. **Registered ≠ functional:** a mechanism that starts but cannot bind its OS facility is marked INERT and EXCLUDED from the capability CSV — `sd_bus_open_system()` failing (`spark_service.cpp`, the inert branch in `start()`), `OpenSCManager` denied, `CreateThreadpool`/`CreateIoCompletionPort` failing. **The container case is the common one:** `deploy/docker/Dockerfile.agent` installs `libsystemd0`, but a container has **no system bus**, so a containerised Linux agent registers the Service mechanism INERT and ends up with **zero** spark capability — it reports `spark_running=1` with an EMPTY `spark_mechs` CSV and no `{os=linux,mechanism=*}` series. Surfaced fleet-wide via `yuzu_fleet_spark_mechanisms{os,mechanism}`; an inert agent shows up as a capability GAP (`yuzu_fleet_spark_reporting{os}` exceeding the sum of `yuzu_fleet_spark_mechanisms{os,mechanism}`). Not yet wired to drive detection/enforcement (that is rung 2/3) |
| **DEX — reliability signals** (crashes, hangs, service/boot, storage, kernel faults, perf/thermal, …) | ✅ | 🟡 growing (17 signals: perf cpu/mem/disk + storage/uptime + journald unit-crash/hung + coredump-crash + OOM + time-unsynced + kernel panic/disk/fs/dirty-shutdown/MCE/hung-task + thermal-throttle) | 🟡 | Win: `dex_observer.cpp`/`dex_win_poll.cpp`; Linux: `dex_linux_collector.cpp`/`dex_linux_proc.cpp`/`dex_linux_storage.cpp`/`dex_linux_journal.cpp`/`dex_linux_kmsg.cpp`/`dex_linux_sysfs.cpp`; macOS: `dex_macos_collector.cpp` (DiagnosticReports/OSLog/IOKit; OSLog now pre-filters Error+Fault via `dex_macos_oslog.cpp` `oslog_predicate()`, reaching Fault-level `com.apple.apfs` `fs.corruption`). Catalogue: `docs/dex-signal-catalog.md` |
| **DEX — performance telemetry** (CPU/mem/disk levels) | ✅ | ✅ | ⛔ | Two paths, both live on Win+Linux: DEX breach sampling (`dex_win_poll.cpp` / `dex_linux_proc.cpp`) and the TAR `$Perf_*` sampler (`tar_perf.cpp` — Win kernel counters; Linux `/proc` via `parse_linux_perf_counters`). macOS absent from the rollup |
| **DEX — per-app file version** (on procperf + on crash/hang signals; the `(name, version)` identity) | ✅ | ⛔ (emits `""`) | 🟡 crash/hang via `.ips` | Win: procperf reads `VS_FIXEDFILEINFO` via `GetFileVersionInfo` (`tar_proc_perf.cpp`, schema v4); crash/hang read WER `AppVersion` (`dex_signal_catalog.cpp`, migration {8}); both canonicalized by `yuzu::util::canon_version`. macOS crash/hang now read `CFBundleShortVersionString` from the `.ips` (`dex_macos_signals.cpp` `ips_app_version`); macOS procperf stays `kPlanned` and Linux emits `""` — that capture is a follow-up (`COREDUMP_PACKAGE_VERSION` / ELF `.note.package`) |
| **DEX — per-app performance over time** (B1 per-device daily + B2 fleet aggregate/histogram, by `(app, version, day)`) | ✅ | 🟡 (opt-in; version `""`) | ⛔ (no data) | Fed by procperf (Windows + Linux — see "DEX — performance telemetry" / per-app rows), shipped via the `app_perf` daily-sync source (`sync_source_app_perf.cpp`) → server `AppPerfDailyStore` (B1) → `AppPerfRollup`/`AppPerfFleetStore` (B2). Linux rows land in the `version=""` unknown bucket (per-app file version row above) once `procperf_enabled=true` is set. macOS procperf is `kPlanned`, so its rollup is empty and nothing is sent; server plumbing is platform-agnostic — macOS lights up when its per-app collector lands |
| **Network quality** (`/network`: throughput / retransmit / RTT) | 🟡 throughput + retransmit (no RTT) | ✅ all three | 🟡 throughput only | `net_quality_sampler.cpp` (macOS `NET_RT_IFLIST2` throughput; retransmit + RTT deferred); per-OS detail in `docs/user-manual/network.md` "Platform coverage" |
| **TAR warehouse capture sources** (per source) | varies | varies | varies | **Authoritative & machine-readable:** `tar_schema_registry.cpp` `OsSupportStatus::{kSupported,kPlanned}` per source, with a notes string |
| **TAR — ARP table** (capture source) | ✅ | 🔜 | 🔜 | `tar_schema_registry.cpp` `arp` def (Win `kSupported` via `iphlpapi`; Linux `kPlanned` `/proc/net/arp`; macOS `kPlanned` route sysctl, constrained — `entry_type 'unknown'`); collector `tar_arp_collector.cpp` (ADR-0015, opt-in) |
| **TAR — DNS cache** (capture source) | ✅ | 🔜 | 🔜 | `tar_schema_registry.cpp` `dns` def (Win `kSupported` via `dnsapi`; Linux `kPlanned` systemd-resolved, hosts-file fallback where absent; macOS `kPlanned` `dscacheutil`, constrained — no TTL); collector `tar_dns_collector.cpp` (ADR-0015, opt-in; device-level usage-class PII, names-only) |
| **TAR — software install/uninstall events** (capture source) | ✅ | 🔜 | 🔜 | `tar_schema_registry.cpp` `software` def (Win `kSupported` via registry Uninstall keys; Linux `kPlanned` dpkg/rpm/pacman; macOS `kPlanned` pkgutil); collector `tar_software_collector.cpp`. **Machine scope only** (HKLM Uninstall — no per-user / profile-name data); **opt-in (off by default)**, enable per host via `software_enabled` (#1620). Distinct from the daily *inventory* sync row below (events vs point-in-time) |
| **Process enumeration / live capture** | ✅ (ETW / Win32) | ✅ (`/proc`) | 🟡 | `process_enum.cpp`; ETW workstream is Windows-specific |
| **Installed-software inventory** (daily sync → central Postgres) | ✅ | ✅ | ✅ | Agent sync framework `sync_scheduler.cpp` + `sync_source_installed_software.cpp` reuse the `installed_apps` plugin `list_inventory` (Win registry; Linux dpkg/rpm/pacman/**apk**; macOS `system_profiler`) via `LocalDispatcher`. Blob contract v2: kind/ecosystem/EVR/arch/packager + rpm stored-tag signature_status + distro_id/version (honest-empty where an ecosystem lacks a field; Windows/macOS rows are kind=app with name/version/publisher only). Machine-scope only. Server: `SoftwareInventoryStore` (ADR-0016) |
| **Software-licence detection (SLE)** (daily sync → central Postgres; product/vendor/type/channel/status/expiry per detected licence) | ✅ (WMI `SoftwareLicensingProduct` authoritative + Office C2R + extensible `ProbeSpec` + per-user hives/files — the only OS with per-user surfaces) | 🟡 (rpm/dpkg declared-licence *classification* — no lapse detection, stated gap; RHEL entitlement certs + FlexLM `.lic` expiry are authoritative) | 🟡 (`_MASReceipt` + machine-scope vendor plists — `probable` confidence only) | Per-OS TUs `agents/plugins/license_scan/src/licensing_{win,wmi,linux,macos}.cpp`; synced by `sync_source_software_licensing.cpp` → server `SoftwareLicensingStore` (ADR-0024). Per-surface detail + privacy limits: `docs/user-manual/software-licensing.md` ("What is collected"). Java + ISO-19770-2 SWID tag surfaces are the named fast-follow (#2112) |
| **Device-identity inventory** (daily sync → central Postgres; serial, UUID, BIOS, CPU/RAM/disk, MAC, OS) | ✅ | ✅ | ✅ | `sync_source_device_ci.cpp` reuses `hardware`/`device_identity`/`os_info`/`network_config` via `LocalDispatcher`. New `hardware` `system` action: Win WMI `Win32_BIOS`/`Win32_ComputerSystemProduct`; Linux `/sys/class/dmi/id/product_serial`+`product_uuid` (0400 → needs `cap_dac_read_search`, granted by `install-agent-user.sh`; `unknown` without it); macOS `ioreg IOPlatformExpertDevice` (NB: `IOPlatformUUID` ≠ SMBIOS UUID — cross-OS UUID correlation is a PR2 concern). Machine-scope only. Server: `DeviceInventoryStore` (ADR-0016 source #3). Read surface deferred to PR2 |
| **Live device snapshot — process tree + per-process connections** | ✅ tree + conn join | 🟡 tree; conn join absent (`/proc/net/tcp` exposes inode, not pid) | 🟡 tree | `processes/list_tree` (`proc\|pid\|ppid\|name\|sha256\|path`, all OSes) joined by PID to `network_diag/connections` (owning PID via `GetExtendedTcpTable`, Windows). Device page "Get live info" Processes card |
| **Live device snapshot — ARP / neighbour table** | ✅ | 🔜 (`/proc/net/arp`) | 🔜 (route sysctl) | `network_config/arp` (`GetIpNetTable2`); no-op note elsewhere |
| **Live device snapshot — DNS resolver cache** | ✅ | ⛔ (no portable resolver cache) | ⛔ | `network_config/dns_cache` (`DnsGetCacheDataTable` on Windows; macOS returns an honest `dns_cache\|unsupported` sentinel — `dscacheutil -cachedump` is defunct on modern macOS) |
| **Live device snapshot — disk space** | ✅ | ✅ | ✅ | `disk_space` plugin `free` action; `GetDiskFreeSpaceExW` on Windows, `statvfs` on POSIX. Device page "Get live info" Disk space card. |
| **Antivirus posture** (`antivirus` plugin: `products` + `status`) | ✅ SecurityCenter2 products + Defender status | 🟡 process/dir detection only (ClamAV/CrowdStrike/Sophos; no `status` leg) | 🟡 `products`: XProtect bundle version + endpoint-security system-extension enumeration (`systemextensionsctl`, unprivileged) + process fallback; `status`: XProtect definition version + bundle mtime + Remediator/MRT — **no real-time-protection state** (macOS exposes no queryable equivalent), `av\|XProtect\|active` is a definitions-readable proxy, not a running-protection read | `agents/plugins/antivirus/src/antivirus_plugin.cpp` (`list_av_products_macos`/`xprotect_status_macos`); pure parsers `antivirus_parsers.hpp` (`parse_plist_version`/`parse_sysext_list`/`sysext_av_state`) tested every host |
| **Firewall posture** (`firewall` plugin: `state` + `rules`) | ✅ per-profile via `netsh advfirewall` | ✅ backend autodetect (firewalld / ufw / iptables) | 🟡 `state`: Application Firewall primary (`socketfilterfw --getglobalstate`, unprivileged; `mode\|block_all` when State = 2) + pf secondary (`pfctl -s info`, root — `unknown` without it); `rules`: pf only (`pfctl -s rules`, root; no Application Firewall per-app list yet) | `agents/plugins/firewall/src/firewall_plugin.cpp` `state`/`rules` legs; pure parsers `firewall_parsers.hpp` (tested every host) |

> The **network row's Windows cell is 🟡 as of 2026-06-15**: the agent now emits
> device throughput (`GetIfTable2`) and a system-wide interval retransmit rate
> (`GetTcpStatisticsEx`). RTT stays 🔜 — per-connection smoothed RTT needs ESTATS
> (`GetPerTcpConnectionEStats`: enable + admin + overhead). The Windows retransmit
> rate is system-wide (includes loopback) and is **measurement-first, not yet
> loss-validated on Windows** — see `docs/user-manual/network.md`.
>
> The **network row's macOS cell became 🟡 on 2026-07-18**: the agent now emits
> device throughput via `NET_RT_IFLIST2` (rx+tx summed across non-loopback
> interfaces, differenced per heartbeat — a coarse device aggregate, same caveat as
> Linux `/proc/net/dev` and Windows `GetIfTable2`). Retransmit and RTT stay
> deferred: the global `net.inet.tcp.stats` OID reads all-zero on modern macOS
> (Apple's own `netstat -s` agrees), so retransmit awaits a per-flow
> NetworkStatistics/nstat source, and heartbeat RTT is deferred as on Windows.

## Why gaps happen (and how to not get surprised again)

Per-OS support is **implicit and scattered**: a `#if defined(_WIN32)` here, a
no-op stub there, a `kPlanned` enum in one registry. Nothing forced it to the
surface, so a Windows-only fleet can hit a feature that was quietly Linux-only.
When adding or changing a collector/guard/plugin, assume the **other** platforms
are a deliberate decision you must record — in code (a stub + comment), in the
relevant user-manual "Platform coverage" section, and in this matrix.

## Make this self-maintaining

The truth already exists machine-readable; the durable fix is to render the matrix
from it rather than hand-curate:

- **TAR sources** — `tar_schema_registry.cpp` already declares
  `OsSupportStatus::{kSupported,kSupportedConstrained,kPlanned,kUnsupported}` *per
  source per OS* with a notes string. This is the model the rest should follow.
- **Guards** — the per-type support arrays (`registry_support::kHives`,
  `service_support::kStates`) + the `make_service_guard()` platform switch + the
  three-family dispatch in `guardian_engine.cpp`.
- **Spark mechanisms** — `make_{file,registry,service}_mechanism()` returning
  `nullptr` off-platform + the runtime INERT marking; already surfaced fleet-wide
  as `yuzu_fleet_spark_mechanisms{os,mechanism}`.
- **DEX signals** — the server-side coverage map `dex_obs_platforms()`
  (`dex_routes.cpp:132-174`, drift-net-tested) + the signal catalogue
  (`docs/dex-signal-catalog.md`, `dex_signal_catalog.*`).
- **Plugins** — per-OS is a mechanical scan of platform macros / per-OS TUs under
  `agents/plugins/*/src/`; a Windows-only plugin has a `#ifndef _WIN32` "not
  available" no-op.

**Proposed follow-up (file as an issue):** a small build-time generator that walks
those sources and emits this table (and optionally an in-product *Settings →
Coverage* page), so per-OS support can never silently diverge from the doc again.
Until that lands, this page is the single place to look — keep it honest.

## Verification

_2026-07-17 re-verification._ Every section above was re-checked against its cited
source of truth (not carried forward from the prior snapshot):

- **TAR** — all **13** registered sources read from `tar_schema_registry.cpp`
  `build_sources()`; the enum is four-valued (`kSupportedConstrained` added to the
  legend). The prior snapshot listed only arp/dns/software.
- **Guards** — confirmed exactly **three** families; corrected the **file guard**
  to observe-only (it never enforces on any platform, including Windows).
- **Spark** — corrected the "rung 2/3" note: rung 7 wired Guardian as consumer,
  but `prefer_spark_` defaults `false` with no `wire_spark_engine()` call sites, so
  legacy `IGuard` is still the only live path.
- **DEX** — macOS collector confirmed **real & shipped** (17 signals via
  `dex_macos_{signals,oslog,iokit}.cpp`); source-of-truth updated to the
  `dex_obs_platforms()` coverage map.
- **Plugins** — all **49** enumerated (CLAUDE.md's "47/49" reconciled to 49): 43
  fully cross-platform, **4** Windows-only (`rdp_control`, `registry`, `sccm`,
  `wmi`), **2** uneven (`tar`; and `msi_packages` — now Win+macOS via `pkgutil`
  receipts, Linux still unimplemented).

_2026-07-20 macOS-parity consolidation._ This pass folds the in-flight macOS
parity batch into the matrix (the individual feature PRs are being closed as their
capabilities land here as the single doc of record). Cell moves and honesty
corrections, each verified against the cited code:

- **`msi_packages`** ⛔→✅ on macOS (`pkgutil` receipts; `msi_packages_macos.hpp`)
  — the one plugin that leaves the Windows-only set.
- **Network quality** ⛔→🟡 (throughput only) on macOS via `NET_RT_IFLIST2`
  (`net_quality_sampler.cpp`); retransmit + RTT deferred.
- **TAR — netqual** 🔜→🟡 on macOS — registry `netqual` now
  `kSupportedConstrained` via the `nstat` kctl client (`tar_netqual_nstat.cpp`,
  root-gated); **TAR — tcp** stays 🟡 but is now `nstat` event-driven (the stale
  "ES is the planned replacement" note corrected — ES has no inet-socket events).
- **DEX — per-app file version** ⛔→🟡 on macOS — `process.crashed`/`.hung` read a
  real `CFBundleShortVersionString` from the `.ips` (`dex_macos_signals.cpp`);
  procperf stays version-less. **DEX reliability signals** unchanged (17 obs_types)
  but OSLog now pre-filters Error+Fault, reaching apfs `fs.corruption`.
- **`interaction`** ✅→🟡 on macOS — honest `not_reachable` from a GUI-less root
  daemon, no longer a fabricated `response|ok`.
- **New rows:** **Antivirus posture** (macOS 🟡 — real XProtect/EDR probes, no
  real-time-protection state) and **Live — Wi-Fi current connection** (macOS 🟡 —
  CoreWLAN, SSID/BSSID withheld from a daemon).
- **Honesty-only** (cell unchanged): `wol` `check` (`ping -t 2`, was a false
  `unreachable`), `wifi connected` (CoreWLAN vs dead `airport -I`), `flush_dns`
  (dual-step + real exit codes), `registry`/`sccm`/`rdp_control` off-Windows
  sentinels (no false success on writes), `bitlocker`/`services`/`users`/
  `network_config` macOS enrichments, DNS-cache `unsupported` sentinel.

Not folded in: #2254 (per-OS DEX catalogue **health score**) is a server-side
scoring change and moves no agent capability cell.
