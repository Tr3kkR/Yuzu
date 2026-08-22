# OS capability matrix

**What this is:** a per-capability × per-OS snapshot of what the Yuzu **agent**
actually collects/enforces on Windows, Linux, and macOS — the thing that was
missing when the `/network` tab showed no data on a Windows-only fleet (the
collector was Linux-only and nothing surfaced that gap). It now covers the
whole agent surface, grouped into sections: **agent core**, **Guardian guards**,
**Spark detection mechanisms**, **DEX**, **TAR warehouse capture sources**,
**inventory / daily-sync sources**, **live device snapshot**, **security posture
& file/certificate surfaces**, **network quality**, and every **agent plugin**
(49).

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

_Last re-verified against code: 2026-07-21 (all rows re-checked against the cited
sources on the consolidated macOS-parity branch; see [Verification](#verification))._
_Last hand-updated: 2026-07-21 (macOS-parity consolidation — see Verification)._

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
| **━━ Spark detection mechanisms (ADR-0021) ━━** | | | | The ADR-0021 reflex layer that will *replace* the legacy `IGuard` path above. `make_{file,registry,service}_mechanism()` in `spark_mechanism.hpp` returns `nullptr` off-platform (type left unregistered). **Not yet live as a detection path:** rung 7 wired Guardian as the first consumer (`GuardianEngine::reconcile_rule_locked()`), and rung 7.7a wires `wire_spark_engine()` at agent boot (`agent.cpp` — lifecycle-only), but `prefer_spark_` defaults `false`, so legacy `IGuard` remains the sole live detection path |
| **SparkEngine mechanisms** (file / registry / service; observe-only) | ✅ file + registry + service | 🟡 service only — **and NONE in a container** (see note) | ⛔ none | File/Registry are Windows-only; Service is Win-SCM + Linux-sd-bus; macOS none. **Registered ≠ functional:** a mechanism that starts but cannot bind its OS facility is marked INERT and EXCLUDED from the capability CSV (`sd_bus_open_system()` failing in `spark_service.cpp`; `OpenSCManager` denied; threadpool/IOCP failing). **The container case is common:** `Dockerfile.agent` installs `libsystemd0` but a container has **no system bus**, so a containerised Linux agent registers Service INERT and ends up with **zero** spark capability (`spark_running=1`, empty `spark_mechs` CSV, no `{os=linux,mechanism=*}` series). Fleet view `yuzu_fleet_spark_mechanisms{os,mechanism}`; an inert agent shows as a GAP (`yuzu_fleet_spark_reporting{os}` exceeding the sum of mechanisms) |
| **━━ DEX — Digital Employee Experience ━━** | | | | Server-side coverage map `dex_obs_platforms()` (`dex_routes.cpp:132-174`) is the hand-maintained mirror, drift-net-tested vs the agent collectors. Catalogue: `docs/dex-signal-catalog.md`; defs `dex_signal_catalog.cpp` |
| **DEX — reliability signals** (crashes, hangs, service/boot, storage, kernel faults, perf/thermal, …) | ✅ (~110 event types + state-poll) | 🟡 (17 obs_types) | 🟡 (16 obs_types) | Win: `dex_observer.cpp`/`dex_win_poll.cpp` — the catalogue IS the `EvtSubscribe` set (22 channels, waves 1–4). Linux: `dex_linux_collector.cpp` + `dex_linux_{proc,storage,journal,kmsg,sysfs}.cpp` (perf trio + storage/uptime + journald crash/hung + kernel panic/OOM/disk/fs/MCE/hung-task + thermal). macOS **real & shipped** (`kMacEmitted` = 16 catalogued obs_types, pinned by the `dex_obs_platforms()` drift-net in `test_dex_routes.cpp`; `process.resource_limit` is deliberately excluded from the taxonomy): `dex_macos_collector.cpp` + `dex_macos_{signals,oslog,iokit}.cpp` (DiagnosticReports `.ips` crashes/hangs/panics/jetsam, OSLog service-crash/wifi-drop/daemon-errors at **Error and Fault** level — `oslog_predicate()` requests both, reaching Fault-level `com.apple.apfs` `fs.corruption` — IOKit SMART/battery/storage/thermal/mem-pressure); covers ~10/11 headings unprivileged |
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
| **Software-licence detection (SLE)** | ✅ (WMI `SoftwareLicensingProduct` + Office C2R + `ProbeSpec` + per-user hives/files) | 🟡 (rpm/dpkg declared-licence classification — no lapse detection; RHEL entitlement + FlexLM `.lic` expiry authoritative) | 🟡 (`_MASReceipt` + machine-scope vendor plists — `probable` confidence only) | Per-OS TUs `license_scan/src/licensing_{win,linux,macos}.cpp` (Windows WMI probe via the shared `agents/shared/wmi_bounded.hpp`); `sync_source_software_licensing.cpp` → `SoftwareLicensingStore` (ADR-0024). Detail: `docs/user-manual/software-licensing.md`. Java + SWID tags are the fast-follow (#2112) |
| **Device-identity inventory** (serial, UUID, BIOS, CPU/RAM/disk, MAC, OS) | ✅ | ✅ | ✅ | `sync_source_device_ci.cpp` reuses `hardware`/`device_identity`/`os_info`/`network_config`. `hardware` `system`: Win WMI `Win32_BIOS`/`Win32_ComputerSystemProduct`; Linux `/sys/class/dmi/id/product_{serial,uuid}` (0400 → needs `cap_dac_read_search`; `unknown` without it); macOS native IOKit `IOPlatformExpertDevice` (`IOServiceGetMatchingService`/`IORegistryEntryCreateCFProperty`; `IOPlatformUUID` ≠ SMBIOS UUID). Machine-scope only. Server `DeviceInventoryStore` |
| **━━ Live device snapshot ("Get live info") ━━** | | | | Device page dispatch-and-poll snapshot; each kind has its own `device.live.<kind>` audit verb. `docs/user-manual/device-management.md` |
| **Live — process tree + per-process connections** | ✅ tree + conn join | 🟡 tree; conn join absent | 🟡 tree | `processes/list_tree` (`proc\|pid\|ppid\|name\|sha256\|path`, all OSes) joined by PID to `network_diag/connections` (owning PID via `GetExtendedTcpTable`, Windows). Linux `/proc/net/tcp` exposes inode not pid → no join |
| **Live — ARP / neighbour table** | ✅ | 🔜 (`/proc/net/arp`) | 🔜 (route sysctl) | `network_config/arp` (`GetIpNetTable2`, Windows); macOS emits an honest `arp\|not_available` sentinel (real route-sysctl collector still 🔜); Linux `/proc/net/arp` 🔜 |
| **Live — DNS resolver cache** | ✅ | ⛔ (no portable resolver cache) | ⛔ (OS exposes no resolver-cache contents; `dscacheutil -cachedump` defunct on macOS 26) | `network_config/dns_cache` (`DnsGetCacheDataTable` on Windows; macOS returns an honest `dns_cache\|unsupported` sentinel, no shell-out — see `darwin-compat.md`) |
| **Live — disk space** | ✅ | ✅ | ✅ | `disk_space` plugin `free` action; `GetDiskFreeSpaceExW` on Windows, `statvfs` on POSIX |
| **Live — Wi-Fi current connection** | ✅ | ✅ | 🟡 | `wifi/connected` — Win `WlanQueryInterface`, Linux `nmcli`/`iwconfig`, macOS `wifi_corewlan.mm` `corewlan_current_connection` (CoreWLAN `CWWiFiClient`/`CWInterface`, first `.mm` TU; pure `format_connected_record` in `wifi_corewlan.hpp`). macOS 🟡: association/RSSI/channel/security read, but SSID/BSSID are withheld from a background daemon by Location Services on 14+ (`<ssid-withheld>`) — replaces the dead `airport -I` path |
| **━━ Security posture & file/certificate surfaces ━━** | | | | Posture reads + signed-artifact/certificate actions; each row cites its per-OS legs |
| **Antivirus posture** (`antivirus` plugin: `products` + `status`) | ✅ SecurityCenter2 products + Defender status | 🟡 process/dir detection only (ClamAV/CrowdStrike/Sophos; no `status` leg) | 🟡 `products`: XProtect bundle version + endpoint-security system-extension enumeration (`systemextensionsctl`, unprivileged) + process fallback; `status`: XProtect definition version + bundle mtime + Remediator/MRT — **no real-time-protection state** (macOS exposes no queryable equivalent), `av\|XProtect\|active` is a definitions-readable proxy, not a running-protection read | `agents/plugins/antivirus/src/antivirus_plugin.cpp` (`list_av_products_macos`/`xprotect_status_macos`); pure parsers `antivirus_parsers.hpp` (`parse_plist_version`/`parse_sysext_list`/`sysext_av_state`) tested every host |
| **Firewall posture** (`firewall` plugin: `state` + `rules`) | ✅ per-profile via `INetFwPolicy2` COM (rung 1, native — no `netsh` shell-out) | ✅ backend autodetect, firewalld (rung 1, bounded sd-bus) → nftables (not yet implemented — falls through) → ufw → iptables (rung 2, `run_bounded_subprocess` argv, structured per-backend rows) | 🟡 `state`: Application Firewall primary (`socketfilterfw --getglobalstate`, unprivileged; `mode\|block_all` when State = 2) + pf secondary (`pfctl -s info`, root — `unknown` without it); `rules`: pf only (`pfctl -s rules`, root; no Application Firewall per-app list yet) — both via `run_bounded_subprocess` (rung 2, no shell) | `agents/plugins/firewall/src/firewall_plugin.cpp` `state`/`rules` legs; pure parsers `firewall_parsers.hpp` (tested every host) |
| **Digital-signature verification** (`filesystem.get_signature`) | ✅ | ⛔ | ✅ | Win: WinVerifyTrust (Authenticode: valid/invalid/unsigned/untrusted) in `filesystem_plugin.cpp`. macOS: `codesign --verify --deep --strict` mapped to valid/unsigned/invalid/unknown by `classify_codesign_result` in `agents/plugins/filesystem/src/filesystem_macos_sig.hpp` (macOS `valid` = seal integrity, not Gatekeeper/notarization trust). Linux emits platform-unsupported |
| **File version info** (`filesystem.get_version_info`) | ✅ | ⛔ | ✅ | Win: `GetFileVersionInfoW`/`VerQueryValueW` (VS_FIXEDFILEINFO + string table) in `filesystem_plugin.cpp`. macOS: CFBundleShortVersionString/CFBundleVersion from the bundle Info.plist via `plutil -extract`, mapped by `classify_plutil_extract` in `filesystem_macos_sig.hpp` (binary + XML plists; `version_status\|not_available` when absent). Linux emits platform-unsupported |
| **Certificate store — login-keychain read** (`certificates.list`/`details` `store=login`/`all`) | ⛔ | ⛔ | ✅ | macOS-specific: reads the console user's login keychain via `launchctl asuser <uid> sudo -n -u <user> security find-certificate` (root-only; see `docs/agent-privilege-model.md`), built by `build_login_keychain_read_command` in `agents/shared/macos_console_user.hpp`, invoked from `agents/plugins/certificates/src/certificates_plugin.cpp`. Windows machine stores (CryptoAPI) and Linux `/etc/ssl/certs` have no per-user login-keychain equivalent for this hop |
| **Certificate delete — verified / SIP-aware** (`certificates.delete`) | ✅ | ✅ | ✅ | Win: CryptoAPI store delete; Linux: remove matching PEM under `/etc/ssl/certs`. macOS: `security delete-certificate` on `System.keychain` then a re-enumeration that reports `deleted` only on a positively-proven absence (`classify_delete_verdict` in `agents/shared/macos_console_user.hpp`); `store=root` rejected (SystemRootCertificates.keychain is SIP-sealed) in `certificates_plugin.cpp` |
| **━━ Network quality (`/network`) ━━** | | | | Measurement-first device/local-link health lens. `net_quality_sampler.cpp`; `docs/user-manual/network.md` "Platform coverage" |
| **Network quality** (throughput / retransmit / RTT) | 🟡 throughput + retransmit (no RTT) | ✅ all three | 🟡 throughput only | Win `GetIfTable2` throughput + `GetTcpStatisticsEx` system-wide interval retransmit (**measurement-first, not loss-validated** — withheld from the fleet retransmit aggregate); RTT needs ESTATS (admin+overhead) → 🔜. Linux has all three. macOS `NET_RT_IFLIST2` throughput only (`read_net_counters()` sums non-loopback `if_data64` rx/tx, differenced per heartbeat); retransmit + RTT deferred — global `net.inet.tcp.stats` reads all-zero on modern macOS → 🔜 |
| **━━ Agent plugins (49) — per-plugin build/availability ━━** | | | | Per-OS via platform macros / per-OS TUs (`agents/plugins/*/src/*`). 42 fully cross-platform, 4 Windows-only (`rdp_control`, `registry`, `sccm`, `wmi`), 2 uneven (`tar` — richest on Windows; `msi_packages` — Win+macOS, no Linux), 1 macOS-constrained (`interaction` — GUI-less daemon). "Full" = the plugin builds and its core actions work on that OS; a plugin can be cross-platform yet expose a few OS-specific actions (noted) |
| agent_actions | ✅ | ✅ | ✅ | portable — no platform macros |
| agent_logging | ✅ | ✅ | ✅ | `_WIN32`/`__APPLE__`/Linux branches all implemented |
| antivirus | ✅ | ✅ | ✅ | Defender/WMI · ClamAV+Falcon+Sophos · macOS real probes — XProtect bundle version + endpoint-security system-extension enumeration (`antivirus_plugin.cpp`, parsers `antivirus_parsers.hpp`), no longer a hardcoded assertion (posture depth: the **Antivirus posture** row) |
| asset_tags | ✅ | ✅ | ✅ | portable — `std::filesystem` only |
| bitlocker | ✅ | ✅ | ✅ | BitLocker `manage-bde` · LUKS `cryptsetup` · FileVault `fdesetup` + per-APFS-volume `diskutil apfs list` (encrypted/not_encrypted/unknown, parser `bitlocker_macos_apfs.hpp`) |
| certificates | ✅ | ✅ | ✅ | full per-OS blocks (`_WIN32`/`__linux__`/`__APPLE__`); Linux now parses in-process via libcrypto (rung 1); macOS System/SystemRoot keychains read natively via SecItem (rung 1), login keychain stays on its registered Decision-7 governed-shell path; macOS depth — login-keychain read + verified SIP-aware delete — in the **Security posture** section rows |
| chargen | ✅ | ✅ | ✅ | portable — RFC 864 generator |
| content_dist | ✅ | ✅ | ✅ | `_WIN32` vs POSIX; HTTPS gated on OpenSSL build option, not OS |
| device_identity | ✅ | ✅ | ✅ | all three branches implemented |
| diagnostics | ✅ | ✅ | ✅ | portable — `std::filesystem` checks |
| discovery | ✅ | ✅ | ✅ | all three legs are native (`GetIpNetTable2` / `/proc/net/arp` / sysctl routing table), and the sweep uses a shared unprivileged ICMP socket, constrained on Linux by `net.ipv4.ping_group_range` |
| disk_space | ✅ | ✅ | ✅ | linux/apple/win branches; `#else` unsupported only |
| event_logs | ✅ | ✅ | ✅ | win/linux/apple branches. macOS `log show` now runs under the bounded `SubprocessRunner` with a hard wall-clock deadline (no built-in timeout in the tool), classified by pure `event_logs_macos.hpp` (`decide_log_show_output`) — a timed-out/degraded run surfaces a sentinel row + non-zero rc, never a silent empty result |
| example | ✅ | ✅ | ✅ | portable — sample plugin |
| filesystem | ✅ | ✅ | ✅ | `_WIN32` vs POSIX. `get_signature`/`get_version_info` now Win + macOS (Linux platform-unsupported) — depth in the **Security posture** section rows |
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
| quarantine | ✅ | ✅ | ✅ | full per-OS blocks; Linux covers IPv4 and IPv6 (honest `note\|ipv6_unavailable` on hosts with no IPv6 stack), macOS verifies pf is actually ENABLED and not merely loaded, and status on all three platforms reports partial/degraded containment rather than a clean `active` (#3282, #3283, #3285). Windows containment now blocks via profile-default policy rather than named Block rules, so the loopback/whitelist Allow rules actually take effect once quarantined (#3284) — see docs/quarantine-windows-firewall-precedence.md |
| rdp_control | ✅ | ⛔ | ⛔ | Windows-only. Off-Windows returns an honest `rdp_control\|unsupported` sentinel (macOS names Screen Sharing); state-changing `set_state` reports terminal FAILURE, read-only `status` rc=0 — `rdp_control_plugin.cpp` `#ifndef _WIN32` branch |
| registry | ✅ | ⛔ | ⛔ | Windows-only (advapi32). Off-Windows returns an honest `registry\|unsupported` sentinel (reads rc=0; mutating `set_value`/`delete_*` report terminal FAILURE — no false success) — `registry_plugin.cpp` `#ifndef _WIN32` branch. `list_profiles` (PR1.7) enumerates local profiles via ProfileList/HKEY_USERS. `get_user_value` resolves the target profile via ProfileList and reads the live `HKEY_USERS\<SID>` hive when the user is logged in, falling back to an offline `RegLoadKey` mount (SeBackup/SeRestore privileges, required only for that fallback) when not. The ladder lives in `agents/shared/win_profiles.hpp` and is shared with `installed_apps.list_per_user`, `license_scan`'s per-user surfaces and `tar`'s mapdrive history (#2771) |
| sccm | ✅ | ⛔ | ⛔ | Windows-only. macOS returns an honest `sccm\|unsupported` (points at Jamf/MDM); Linux `installed\|false` + "platform not supported" — `sccm_plugin.cpp` `__APPLE__` branch |
| script_exec | ✅ | ✅ | ✅ | win/apple/linux. Different action sets per OS (`bash` POSIX-only; powershell/cmd on Windows) |
| services | ✅ | ✅ | ✅ | win/linux/apple branches. macOS `list`/`running` now emit `startup_type` (automatic/disabled/unknown) from a bulk `launchctl print-disabled` join (parser `services_macos_launchd.hpp`); `set_start_mode` rejects `manual` (launchd is binary enable/disable) |
| sockwho | ✅ | ✅ | ✅ | linux/apple/win branches |
| software_actions | ✅ | ✅ | ✅ | win/linux/apple branches |
| status | ✅ | ✅ | ✅ | linux/apple/win branches |
| storage | ✅ | ✅ | ✅ | portable — persistent KV store |
| tags | ✅ | ✅ | ✅ | portable — `std::filesystem` |
| **tar** | ✅ | 🟡 | 🟡 | Uneven by design — richest on Windows (ETW/dnsapi/registry), `/proc`-based on Linux, ES + scattered branches on macOS. Per-source depth is the **TAR warehouse capture sources** section above (`tar_schema_registry.cpp`) |
| users | ✅ | ✅ | ✅ | linux/apple/win branches. macOS `local_users` now adds real `last_logon` (`last -y`) and a tri-state `console_state` GUI-login flag (`SCDynamicStoreCopyConsoleUser`, shared `macos_console_user.hpp`); Windows `primary_user`/`session_history` now read the Security channel natively via wevtapi, and the POSIX account tools run as bounded argv invocations instead of a shell |
| vuln_scan | ✅ | ✅ | ✅ | linux/apple/win branches |
| wifi | ✅ | ✅ | ✅ | win/linux/apple all implemented; macOS `connected` via CoreWLAN (`wifi_corewlan.mm`), `list_networks` legacy `airport -s`/`system_profiler` (connection depth: the **Live — Wi-Fi current connection** row) |
| windows_updates | ✅ | ✅ | ✅ | update history / rpm+apt / `system_profiler` install history (Linux/mac report installed-package history) |
| wmi | ✅ | ⛔ | ⛔ | Windows-only (`#ifndef _WIN32` → not available) |
| wol | ✅ | ✅ | ✅ | `wol_plugin.cpp` — `_WIN32` vs POSIX portable UDP broadcast (wake); `check` reachability is native on every platform (unprivileged ICMP echo with a TCP-connect fallback on port 443, ADR-3002 rung 1) — no subprocess spawn, no `ping` shell-out |

## Why gaps happen (and how to not get surprised again)

Per-OS support is **implicit and scattered**: a `#if defined(_WIN32)` here, a
no-op stub there, a `kPlanned` enum in one registry. Nothing forced it to the
surface, so a Windows-only fleet can hit a feature that was quietly Linux-only.
When adding or changing a collector/guard/plugin, assume the **other** platforms
are a deliberate decision you must record — in code (a stub + comment), in the
relevant user-manual "Platform coverage" section, and in this matrix.

## Generated: ABI4 per-action capability declarations (#2204)

PR1.1 builds the generator this doc's "Make this self-maintaining" section
below used to propose only as a follow-up issue: `tools/capmatrix-gen`
dlopens each built plugin's `YuzuPluginDescriptor` (ABI4,
`sdk/include/yuzu/plugin.h`) and emits the block below from its
`action_descriptors` array. `scripts/ci/check-capability-matrix.sh` regenerates
and byte-diffs this block on every Linux CI leg, in **RATCHET mode**: the
"Undeclared plugins" count must never grow, and it is not enough for a PR to
merely shrink it — the script exits 1 on a *lower* count too until
`RATCHET_BASELINE_UNDECLARED` is lowered to match in the same change, so the
adoption gain is sticky rather than leaving room for a later regression back
up to the old baseline.

Adoption is now **complete**: all 49 plugins the CI gate tracks populate
`action_descriptors`, so the undeclared count and `RATCHET_BASELINE_UNDECLARED`
are both **0** and the "Undeclared plugins" section below is empty. From here
the ratchet is equivalent to a hard fail — a new plugin directory landing
without descriptors grows the count above 0 and fails the Linux leg.

The generator is also the completeness check: `capmatrix-gen` hard-errors on
any mismatch between a plugin's `actions()` list and its `action_descriptors`
array *before* it writes anything, so a declaration that silently omits an
action cannot reach this table.

**Rung legend** (the table's Rung column below): 1 = native OS interface
(zero processes, best) · 2 = argv runner · 3 = governed shell (two-plus
processes, worst) — rung states *how* a leg acquires its capability per
docs/adr/3002-acquisition-ladder.md, never how mature or hardened the
implementation is.

<!-- BEGIN GENERATED: capmatrix-gen (#2204) — do not hand-edit; regenerate with
     tools/capmatrix-gen, verified by scripts/ci/check-capability-matrix.sh -->
| Plugin | Action | OS | Support | Rung | Mechanism | Fallback |
|---|---|---|---|---|---|---|
| agent_actions | set_log_level | linux | supported | 1 | spdlog_runtime | - |
| agent_actions | set_log_level | macos | supported | 1 | spdlog_runtime | - |
| agent_actions | set_log_level | windows | supported | 1 | spdlog_runtime | - |
| agent_actions | info | linux | supported | 1 | agent_config_read | - |
| agent_actions | info | macos | supported | 1 | agent_config_read | - |
| agent_actions | info | windows | supported | 1 | agent_config_read | - |
| agent_logging | get_log | linux | supported | 1 | agent config lookup + std::ifstream tail read | - |
| agent_logging | get_log | macos | supported | 1 | agent config lookup + std::ifstream tail read | - |
| agent_logging | get_log | windows | supported | 1 | agent config lookup + std::ifstream tail read | - |
| agent_logging | get_key_files | linux | supported | 1 | /proc/self/exe symlink + std::filesystem metadata | - |
| agent_logging | get_key_files | macos | supported | 1 | _NSGetExecutablePath + realpath(3) + std::filesystem metadata | - |
| agent_logging | get_key_files | windows | supported | 1 | GetModuleFileNameA + std::filesystem metadata | - |
| antivirus | products | linux | supported | 3 | pgrep+filesystem_probe | - |
| antivirus | products | macos | supported | 3 | plistbuddy+systemextensionsctl | - |
| antivirus | products | windows | supported | 3 | powershell_cim_securitycenter2 | - |
| antivirus | status | linux | unsupported | - | - | - |
| antivirus | status | macos | supported | 3 | plistbuddy+stat | - |
| antivirus | status | windows | supported | 3 | powershell_defender_status | - |
| asset_tags | sync | linux | supported | 1 | local_json_store | - |
| asset_tags | sync | macos | supported | 1 | local_json_store | - |
| asset_tags | sync | windows | supported | 1 | local_json_store | - |
| asset_tags | status | linux | supported | 1 | local_json_store | - |
| asset_tags | status | macos | supported | 1 | local_json_store | - |
| asset_tags | status | windows | supported | 1 | local_json_store | - |
| asset_tags | get | linux | supported | 1 | local_json_store | - |
| asset_tags | get | macos | supported | 1 | local_json_store | - |
| asset_tags | get | windows | supported | 1 | local_json_store | - |
| asset_tags | changes | linux | supported | 1 | local_json_store | - |
| asset_tags | changes | macos | supported | 1 | local_json_store | - |
| asset_tags | changes | windows | supported | 1 | local_json_store | - |
| bitlocker | state | linux | supported | 3 | lsblk+cryptsetup | - |
| bitlocker | state | macos | supported | 3 | fdesetup+diskutil | - |
| bitlocker | state | windows | supported | 3 | manage_bde | - |
| certificates | list | linux | supported | 1 | libcrypto X509 (in-process PEM parse) | - |
| certificates | list | macos | supported | 3 | SecItem (System/root, in-process) + security find-certificate via governed shell (login) | System.keychain and SystemRootCertificates.keychain are read natively via SecItemCopyMatching (rung 1); the login keychain still requires the launchctl/sudo ~user hop (Decision-7 governed-shell exception) |
| certificates | list | windows | supported | 1 | CryptoAPI (CertEnumCertificatesInStore) | - |
| certificates | details | linux | supported | 1 | libcrypto X509 (in-process PEM parse) | - |
| certificates | details | macos | supported | 3 | SecItem (System/root, in-process) + security find-certificate via governed shell (login) | System.keychain and SystemRootCertificates.keychain are read natively via SecItemCopyMatching (rung 1); the login keychain still requires the launchctl/sudo ~user hop (Decision-7 governed-shell exception) |
| certificates | details | windows | supported | 1 | CryptoAPI (CertEnumCertificatesInStore) | - |
| certificates | delete | linux | supported | 1 | libcrypto X509 lookup + filesystem remove | - |
| certificates | delete | macos | constrained | 2 | security delete-certificate via subprocess runner | SystemRootCertificates.keychain is sealed under SIP and rejected outright; only System/MY store deletes are supported |
| certificates | delete | windows | supported | 1 | CryptoAPI (CertDeleteCertificateFromStore) | - |
| chargen | chargen_start | linux | supported | 1 | in-process | - |
| chargen | chargen_start | macos | supported | 1 | in-process | - |
| chargen | chargen_start | windows | supported | 1 | in-process | - |
| chargen | chargen_stop | linux | supported | 1 | in-process | - |
| chargen | chargen_stop | macos | supported | 1 | in-process | - |
| chargen | chargen_stop | windows | supported | 1 | in-process | - |
| content_dist | stage | linux | supported | 1 | httplib_tls | - |
| content_dist | stage | macos | supported | 1 | httplib_tls | - |
| content_dist | stage | windows | constrained | 1 | httplib_tls | requires OpenSSL to be found at build time; HTTPS unavailable if absent |
| content_dist | execute_staged | linux | supported | 2 | fork_execvp | - |
| content_dist | execute_staged | macos | supported | 2 | fork_execvp | - |
| content_dist | execute_staged | windows | supported | 2 | createprocessw | - |
| content_dist | list_staged | linux | supported | 1 | std_filesystem | - |
| content_dist | list_staged | macos | supported | 1 | std_filesystem | - |
| content_dist | list_staged | windows | supported | 1 | std_filesystem | - |
| content_dist | cleanup | linux | supported | 1 | std_filesystem | - |
| content_dist | cleanup | macos | supported | 1 | std_filesystem | - |
| content_dist | cleanup | windows | supported | 1 | std_filesystem | - |
| content_dist | upload_file | linux | supported | 1 | httplib_tls | - |
| content_dist | upload_file | macos | supported | 1 | httplib_tls | - |
| content_dist | upload_file | windows | constrained | 1 | httplib_tls | requires OpenSSL to be found at build time; HTTPS unavailable if absent |
| device_identity | device_name | linux | supported | 1 | gethostname(3) | - |
| device_identity | device_name | macos | supported | 1 | gethostname(3) | - |
| device_identity | device_name | windows | supported | 1 | GetComputerNameExA | - |
| device_identity | domain | linux | supported | 1 | /etc/resolv.conf read + sd-bus org.freedesktop.sssd.infopipe ListDomains [fallback: run_bounded_subprocess(realm list); further fallback: /etc/sssd/sssd.conf read] | - |
| device_identity | domain | macos | supported | 2 | run_bounded_subprocess(dsconfigad -show) + native parser (device_identity_macos.hpp) [fallback: gethostname(3) + getaddrinfo(AI_CANONNAME)] | - |
| device_identity | domain | windows | supported | 1 | NetGetJoinInformation | - |
| device_identity | ou | linux | supported | 2 | run_bounded_subprocess(realm list) [fallback: /etc/sssd/sssd.conf read] | - |
| device_identity | ou | macos | supported | 2 | run_bounded_subprocess(dsconfigad -show) + native parser (device_identity_macos.hpp) | - |
| device_identity | ou | windows | supported | 1 | GetComputerObjectNameA | - |
| diagnostics | log_level | linux | supported | 1 | in-process agent config (agent.log_level) | - |
| diagnostics | log_level | macos | supported | 1 | in-process agent config (agent.log_level) | - |
| diagnostics | log_level | windows | supported | 1 | in-process agent config (agent.log_level) | - |
| diagnostics | certificates | linux | supported | 1 | in-process agent config (tls.*_cert/tls.client_key) + std::filesystem::exists | - |
| diagnostics | certificates | macos | supported | 1 | in-process agent config (tls.*_cert/tls.client_key) + std::filesystem::exists | - |
| diagnostics | certificates | windows | supported | 1 | in-process agent config (tls.*_cert/tls.client_key) + std::filesystem::exists | - |
| diagnostics | connection_info | linux | supported | 1 | in-process agent config (agent.server_address/tls.enabled/*) | - |
| diagnostics | connection_info | macos | supported | 1 | in-process agent config (agent.server_address/tls.enabled/*) | - |
| diagnostics | connection_info | windows | supported | 1 | in-process agent config (agent.server_address/tls.enabled/*) | - |
| discovery | scan_subnet | linux | constrained | 1 | /proc/net/arp + unprivileged SOCK_DGRAM ICMP | the ICMP sweep needs net.ipv4.ping_group_range to admit the agent's gid; ARP-only results with a CONSTRAINED/PARTIAL status otherwise, or UNAVAILABLE/PARTIAL when the ICMP socket cannot be created at all. netlink RTM_GETNEIGH is a recorded future promotion over /proc/net/arp |
| discovery | scan_subnet | macos | supported | 1 | sysctl NET_RT_FLAGS/RTF_LLINFO + SOCK_DGRAM ICMP | - |
| discovery | scan_subnet | windows | supported | 1 | GetIpNetTable2 + IcmpSendEcho | - |
| disk_space | free | linux | supported | 1 | statvfs(2) | - |
| disk_space | free | macos | supported | 1 | statfs(2) | - |
| disk_space | free | windows | supported | 1 | GetDiskFreeSpaceExW | - |
| event_logs | errors | linux | supported | 3 | journalctl | - |
| event_logs | errors | macos | supported | 2 | log_show | - |
| event_logs | errors | windows | supported | 3 | powershell_getwinevent | - |
| event_logs | query | linux | supported | 3 | journalctl | - |
| event_logs | query | macos | supported | 2 | log_show | - |
| event_logs | query | windows | supported | 3 | powershell_getwinevent | - |
| example | ping | linux | supported | 1 | in-process | - |
| example | ping | macos | supported | 1 | in-process | - |
| example | ping | windows | supported | 1 | in-process | - |
| example | echo | linux | supported | 1 | in-process | - |
| example | echo | macos | supported | 1 | in-process | - |
| example | echo | windows | supported | 1 | in-process | - |
| filesystem | exists | linux | supported | 1 | std::filesystem | - |
| filesystem | exists | macos | supported | 1 | std::filesystem | - |
| filesystem | exists | windows | supported | 1 | std::filesystem | - |
| filesystem | list_dir | linux | supported | 1 | std::filesystem | - |
| filesystem | list_dir | macos | supported | 1 | std::filesystem | - |
| filesystem | list_dir | windows | supported | 1 | std::filesystem | - |
| filesystem | file_hash | linux | supported | 2 | subprocess_runner:sha256sum/sha1sum | - |
| filesystem | file_hash | macos | supported | 2 | subprocess_runner:shasum | - |
| filesystem | file_hash | windows | supported | 1 | bcrypt | - |
| filesystem | create_temp | linux | supported | 1 | yuzu_create_temp_file | - |
| filesystem | create_temp | macos | supported | 1 | yuzu_create_temp_file | - |
| filesystem | create_temp | windows | supported | 1 | yuzu_create_temp_file | - |
| filesystem | create_temp_dir | linux | supported | 1 | yuzu_create_temp_dir | - |
| filesystem | create_temp_dir | macos | supported | 1 | yuzu_create_temp_dir | - |
| filesystem | create_temp_dir | windows | supported | 1 | yuzu_create_temp_dir | - |
| filesystem | read | linux | supported | 1 | std::ifstream | - |
| filesystem | read | macos | supported | 1 | std::ifstream | - |
| filesystem | read | windows | supported | 1 | std::ifstream | - |
| filesystem | get_acl | linux | constrained | 1 | posix_stat | stat()-only basic owner/group/permission bits; no ACL/ACE enumeration |
| filesystem | get_acl | macos | constrained | 1 | posix_stat | stat()-only basic owner/group/permission bits; no ACL/ACE enumeration |
| filesystem | get_acl | windows | supported | 1 | win32_acl | - |
| filesystem | get_signature | linux | unsupported | - | - | - |
| filesystem | get_signature | macos | supported | 2 | subprocess_runner:codesign | - |
| filesystem | get_signature | windows | supported | 1 | wintrust | - |
| filesystem | find_by_hash | linux | supported | 2 | std::filesystem+subprocess_runner:sha256sum | - |
| filesystem | find_by_hash | macos | supported | 2 | std::filesystem+subprocess_runner:shasum | - |
| filesystem | find_by_hash | windows | supported | 1 | std::filesystem+bcrypt | - |
| filesystem | search_dir | linux | supported | 1 | std::filesystem+std::regex | - |
| filesystem | search_dir | macos | supported | 1 | std::filesystem+std::regex | - |
| filesystem | search_dir | windows | supported | 1 | std::filesystem+std::regex | - |
| filesystem | get_version_info | linux | unsupported | - | - | - |
| filesystem | get_version_info | macos | supported | 2 | subprocess_runner:plutil | - |
| filesystem | get_version_info | windows | supported | 1 | win32_version_info | - |
| filesystem | search | linux | supported | 1 | std::ifstream+std::regex | - |
| filesystem | search | macos | supported | 1 | std::ifstream+std::regex | - |
| filesystem | search | windows | supported | 1 | std::ifstream+std::regex | - |
| filesystem | replace | linux | supported | 1 | atomic_write_file | - |
| filesystem | replace | macos | supported | 1 | atomic_write_file | - |
| filesystem | replace | windows | supported | 1 | atomic_write_file | - |
| filesystem | write_content | linux | supported | 1 | atomic_write_file | - |
| filesystem | write_content | macos | supported | 1 | atomic_write_file | - |
| filesystem | write_content | windows | supported | 1 | atomic_write_file | - |
| filesystem | append | linux | supported | 1 | std::ofstream | - |
| filesystem | append | macos | supported | 1 | std::ofstream | - |
| filesystem | append | windows | supported | 1 | std::ofstream | - |
| filesystem | delete_lines | linux | supported | 1 | atomic_write_file | - |
| filesystem | delete_lines | macos | supported | 1 | atomic_write_file | - |
| filesystem | delete_lines | windows | supported | 1 | atomic_write_file | - |
| firewall | state | linux | supported | 1 | firewalld sd-bus (rung 1), else ufw/iptables via run_bounded_subprocess (rung 2) | nftables backend not yet implemented -- falls through to ufw/iptables |
| firewall | state | macos | supported | 2 | socketfilterfw/pfctl via run_bounded_subprocess | - |
| firewall | state | windows | supported | 1 | INetFwPolicy2 COM (per-profile FirewallEnabled) | - |
| firewall | rules | linux | supported | 1 | firewalld sd-bus (rung 1), else ufw/iptables via run_bounded_subprocess (rung 2) | nftables backend not yet implemented -- falls through to ufw/iptables |
| firewall | rules | macos | supported | 2 | pfctl via run_bounded_subprocess | - |
| firewall | rules | windows | supported | 1 | INetFwPolicy2 COM (INetFwRules enumeration) | - |
| hardware | manufacturer | linux | supported | 1 | /sys/class/dmi/id/sys_vendor | - |
| hardware | manufacturer | macos | supported | 1 | sysctlbyname(hw.manufacturer) | - |
| hardware | manufacturer | windows | supported | 1 | WMI Win32_ComputerSystem.Manufacturer | - |
| hardware | model | linux | supported | 1 | /sys/class/dmi/id/product_name | - |
| hardware | model | macos | supported | 1 | sysctlbyname(hw.model) | - |
| hardware | model | windows | supported | 1 | WMI Win32_ComputerSystem.Model | - |
| hardware | bios | linux | supported | 1 | /sys/class/dmi/id/bios_vendor + bios_version + bios_date | - |
| hardware | bios | macos | supported | 2 | run_bounded_subprocess(system_profiler SPHardwareDataType) + native parser (hardware_macos_bios.hpp) | - |
| hardware | bios | windows | supported | 1 | WMI Win32_BIOS | - |
| hardware | processors | linux | supported | 1 | /proc/cpuinfo | - |
| hardware | processors | macos | supported | 1 | sysctlbyname(machdep.cpu.*, hw.*cpu*) | - |
| hardware | processors | windows | supported | 1 | WMI Win32_Processor | - |
| hardware | memory | linux | constrained | 2 | run_bounded_subprocess(dmidecode -t memory) | falls back to the aggregate MemTotal from /proc/meminfo (no per-DIMM detail) when dmidecode is unavailable or unprivileged |
| hardware | memory | macos | constrained | 1 | sysctlbyname(hw.memsize) | aggregate total only, no per-DIMM breakdown (macOS has no public per-DIMM API) |
| hardware | memory | windows | supported | 1 | WMI Win32_PhysicalMemory | - |
| hardware | disks | linux | supported | 1 | /sys/block/*/{size,device/model} native walk | - |
| hardware | disks | macos | supported | 2 | run_bounded_subprocess(system_profiler SPStorageDataType SPNVMeDataType SPSerialATADataType -json) + native parser (hardware_disks_macos.hpp) | - |
| hardware | disks | windows | supported | 1 | WMI Win32_DiskDrive | - |
| hardware | drivers | linux | supported | 1 | /proc/modules | - |
| hardware | drivers | macos | unsupported | - | - | - |
| hardware | drivers | windows | supported | 1 | WMI Win32_PnPSignedDriver | - |
| hardware | system | linux | supported | 1 | /sys/class/dmi/id/product_serial + product_uuid | - |
| hardware | system | macos | supported | 1 | IOServiceGetMatchingService(IOPlatformExpertDevice) + IORegistryEntryCreateCFProperty(kIOPlatformSerialNumberKey/kIOPlatformUUIDKey) | - |
| hardware | system | windows | supported | 1 | WMI Win32_BIOS.SerialNumber + Win32_ComputerSystemProduct.UUID | - |
| http_client | download | linux | supported | 1 | cpp-httplib (native sockets) | - |
| http_client | download | macos | supported | 1 | cpp-httplib (native sockets) | - |
| http_client | download | windows | supported | 1 | cpp-httplib (native sockets) | - |
| http_client | get | linux | supported | 1 | cpp-httplib (native sockets) | - |
| http_client | get | macos | supported | 1 | cpp-httplib (native sockets) | - |
| http_client | get | windows | supported | 1 | cpp-httplib (native sockets) | - |
| http_client | head | linux | supported | 1 | cpp-httplib (native sockets) | - |
| http_client | head | macos | supported | 1 | cpp-httplib (native sockets) | - |
| http_client | head | windows | supported | 1 | cpp-httplib (native sockets) | - |
| installed_apps | list | linux | supported | 3 | popen(dpkg-query / rpm / pacman) | - |
| installed_apps | list | macos | supported | 3 | popen(system_profiler SPApplicationsDataType) | - |
| installed_apps | list | windows | supported | 1 | Reg*W enumeration of the Uninstall key(s) | - |
| installed_apps | query | linux | supported | 3 | popen(dpkg-query / rpm / pacman) | - |
| installed_apps | query | macos | supported | 3 | popen(system_profiler SPApplicationsDataType) | - |
| installed_apps | query | windows | supported | 1 | Reg*W enumeration of the Uninstall key(s) | - |
| installed_apps | list_per_user | linux | supported | 3 | popen(dpkg-query / rpm / pacman) | - |
| installed_apps | list_per_user | macos | supported | 3 | popen(system_profiler SPApplicationsDataType) + popen(brew list --versions) | - |
| installed_apps | list_per_user | windows | supported | 1 | Reg*W enumeration of HKU\\<SID>'s Uninstall key, mounting NTUSER.DAT via RegLoadKeyW when not already loaded | - |
| installed_apps | list_inventory | linux | supported | 3 | popen(dpkg-query / rpm / pacman / apk) | - |
| installed_apps | list_inventory | macos | supported | 3 | popen(system_profiler SPApplicationsDataType) | - |
| installed_apps | list_inventory | windows | supported | 1 | Reg*W enumeration of the Uninstall key(s) | - |
| interaction | notify | linux | supported | 2 | notify_send | - |
| interaction | notify | macos | constrained | 3 | osascript | no reachable GUI session under a headless/root LaunchDaemon |
| interaction | notify | windows | supported | 1 | shell_notifyicon | - |
| interaction | message_box | linux | supported | 2 | zenity | - |
| interaction | message_box | macos | constrained | 3 | osascript | no reachable GUI session under a headless/root LaunchDaemon |
| interaction | message_box | windows | supported | 1 | messageboxw | - |
| interaction | input | linux | supported | 2 | zenity | - |
| interaction | input | macos | constrained | 3 | osascript | no reachable GUI session under a headless/root LaunchDaemon |
| interaction | input | windows | supported | 3 | powershell_inputbox | - |
| interaction | survey | linux | supported | 2 | zenity | - |
| interaction | survey | macos | constrained | 3 | osascript | no reachable GUI session under a headless/root LaunchDaemon |
| interaction | survey | windows | supported | 3 | powershell_winforms | - |
| interaction | set_dnd | linux | supported | 1 | local_kv_store | - |
| interaction | set_dnd | macos | supported | 1 | local_kv_store | - |
| interaction | set_dnd | windows | supported | 1 | local_kv_store | - |
| ioc | check | linux | supported | 1 | procfs | - |
| ioc | check | macos | supported | 1 | libproc | UDP rows carry an empty state (no fabricated "LISTEN") — a real UDP listener still matches a port check, but its detail text differs from a TCP match; a port shared by more than one process (SO_REUSEPORT, prefork) reports the pid of one arbitrarily-chosen owner in its match detail, not every owner |
| ioc | check | windows | supported | 1 | iphlpapi_dnsapi | - |
| license_scan | list | linux | supported | 3 | popen(rpm/dpkg-query/openssl) | - |
| license_scan | list | macos | constrained | 1 | filesystem_probe(glob+plist) | binary (bplist00) Info.plist files are not parsed; falls back to the bundle name with an empty version |
| license_scan | list | windows | supported | 1 | wmi+win32_registry | - |
| license_scan | surfaces | linux | supported | 3 | popen(rpm/dpkg-query/openssl) | - |
| license_scan | surfaces | macos | constrained | 1 | filesystem_probe(glob+plist) | binary (bplist00) Info.plist files are not parsed; falls back to the bundle name with an empty version |
| license_scan | surfaces | windows | supported | 1 | wmi+win32_registry | - |
| msi_packages | list | linux | unsupported | - | - | - |
| msi_packages | list | macos | supported | 3 | pkgutil | - |
| msi_packages | list | windows | supported | 1 | msi_api | - |
| msi_packages | product_codes | linux | unsupported | - | - | - |
| msi_packages | product_codes | macos | supported | 3 | pkgutil | - |
| msi_packages | product_codes | windows | supported | 1 | msi_api | - |
| netprobe | icmp | linux | constrained | 1 | SOCK_DGRAM ICMP ping socket | requires net.ipv4.ping_group_range to admit the process group; reports not-permitted otherwise |
| netprobe | icmp | macos | supported | 1 | SOCK_DGRAM ICMP ping socket | - |
| netprobe | icmp | windows | supported | 1 | IcmpSendEcho | - |
| netprobe | tcp | linux | supported | 1 | non-blocking connect() timing | - |
| netprobe | tcp | macos | supported | 1 | non-blocking connect() timing | - |
| netprobe | tcp | windows | supported | 1 | non-blocking connect() timing | - |
| netprobe | dns | linux | supported | 1 | getaddrinfo | - |
| netprobe | dns | macos | supported | 1 | getaddrinfo | - |
| netprobe | dns | windows | supported | 1 | getaddrinfo | - |
| netstat | netstat_list | linux | supported | 1 | /proc/net/{tcp,udp}[6] | - |
| netstat | netstat_list | macos | supported | 1 | libproc | - |
| netstat | netstat_list | windows | supported | 1 | GetExtendedTcpTable/GetExtendedUdpTable | - |
| network_actions | flush_dns | linux | constrained | 2 | resolvectl/systemd-resolve via bounded argv runner (sudo -n) | requires resolvectl (systemd-resolved) or the legacy systemd-resolve CLI; an honest failure is reported if neither is present |
| network_actions | flush_dns | macos | supported | 2 | dscacheutil + killall via bounded argv runner (sudo -n) | - |
| network_actions | flush_dns | windows | supported | 2 | ipconfig via bounded argv runner | - |
| network_actions | ping | linux | supported | 2 | system ping via bounded argv runner | - |
| network_actions | ping | macos | supported | 2 | system ping via bounded argv runner | - |
| network_actions | ping | windows | supported | 2 | system ping.exe via bounded argv runner | - |
| network_config | adapters | linux | supported | 3 | ip(8) via governed shell runner | - |
| network_config | adapters | macos | supported | 3 | ifconfig via governed shell runner | - |
| network_config | adapters | windows | supported | 1 | GetAdaptersAddresses | - |
| network_config | ip_addresses | linux | supported | 3 | ip(8) via governed shell runner | - |
| network_config | ip_addresses | macos | supported | 3 | ifconfig/route via governed shell runner | - |
| network_config | ip_addresses | windows | supported | 1 | GetAdaptersAddresses | - |
| network_config | dns_servers | linux | supported | 1 | /etc/resolv.conf read | - |
| network_config | dns_servers | macos | supported | 3 | scutil via governed shell runner | - |
| network_config | dns_servers | windows | supported | 1 | GetAdaptersAddresses | - |
| network_config | proxy | linux | supported | 1 | environment variables | - |
| network_config | proxy | macos | constrained | 3 | networksetup via governed shell runner | only the Wi-Fi network service is queried; other interfaces are not checked |
| network_config | proxy | windows | supported | 1 | WinHttpGetIEProxyConfigForCurrentUser | - |
| network_config | dns_cache | linux | constrained | 3 | resolvectl via governed shell runner | falls back to systemd-resolve statistics, or reports unavailable, when resolvectl is absent |
| network_config | dns_cache | macos | unsupported | - | - | - |
| network_config | dns_cache | windows | supported | 1 | DnsGetCacheDataTable (dnsapi.dll) | - |
| network_config | arp | linux | unsupported | - | - | - |
| network_config | arp | macos | unsupported | - | - | - |
| network_config | arp | windows | supported | 1 | GetIpNetTable2 | - |
| network_diag | listening | linux | supported | 1 | /proc/net/tcp[6] | - |
| network_diag | listening | macos | supported | 1 | libproc | a socket shared by more than one process (SO_REUSEPORT, prefork) surfaces under one arbitrarily-chosen owning PID, not one row per owner |
| network_diag | listening | windows | supported | 1 | GetExtendedTcpTable | - |
| network_diag | connections | linux | supported | 1 | /proc/net/tcp[6] | - |
| network_diag | connections | macos | supported | 1 | libproc | a socket shared by more than one process (SO_REUSEPORT, prefork) surfaces under one arbitrarily-chosen owning PID, not one row per owner |
| network_diag | connections | windows | supported | 1 | GetExtendedTcpTable | - |
| os_info | os_name | linux | supported | 1 | /etc/os-release | - |
| os_info | os_name | macos | supported | 1 | SystemVersion.plist + sysctlbyname | - |
| os_info | os_name | windows | supported | 1 | Reg*W CurrentVersion\\ProductName + build-number correction | - |
| os_info | os_version | linux | supported | 1 | uname(2) | - |
| os_info | os_version | macos | supported | 1 | uname(2) + SystemVersion.plist + sysctlbyname | - |
| os_info | os_version | windows | supported | 1 | RtlGetVersion (ntdll) | - |
| os_info | os_build | linux | supported | 1 | /proc/version | - |
| os_info | os_build | macos | supported | 1 | SystemVersion.plist + sysctlbyname | - |
| os_info | os_build | windows | supported | 1 | Reg*W CurrentBuildNumber + UBR | - |
| os_info | os_arch | linux | supported | 1 | uname(2) | - |
| os_info | os_arch | macos | supported | 1 | uname(2) | - |
| os_info | os_arch | windows | supported | 1 | GetNativeSystemInfo | - |
| os_info | uptime | linux | supported | 1 | /proc/uptime | - |
| os_info | uptime | macos | supported | 1 | sysctl(2) KERN_BOOTTIME | - |
| os_info | uptime | windows | supported | 1 | GetTickCount64 | - |
| processes | list | linux | supported | 1 | /proc enumeration | - |
| processes | list | macos | supported | 1 | sysctl(KERN_PROC_ALL) | - |
| processes | list | windows | supported | 1 | CreateToolhelp32Snapshot | - |
| processes | list_hashed | linux | supported | 1 | /proc enumeration + readlink(/proc/<pid>/exe) + SHA-256 | - |
| processes | list_hashed | macos | supported | 1 | sysctl(KERN_PROC_ALL) + proc_pidpath + SHA-256 | - |
| processes | list_hashed | windows | supported | 1 | CreateToolhelp32Snapshot + QueryFullProcessImageNameW + SHA-256 | - |
| processes | list_tree | linux | supported | 1 | /proc enumeration + readlink(/proc/<pid>/exe) + SHA-256 | - |
| processes | list_tree | macos | supported | 1 | sysctl(KERN_PROC_ALL) + proc_pidpath + SHA-256 | - |
| processes | list_tree | windows | supported | 1 | CreateToolhelp32Snapshot + QueryFullProcessImageNameW + SHA-256 | - |
| processes | query | linux | supported | 1 | /proc enumeration | - |
| processes | query | macos | supported | 1 | sysctl(KERN_PROC_ALL) | - |
| processes | query | windows | supported | 1 | CreateToolhelp32Snapshot | - |
| procfetch | procfetch_fetch | linux | supported | 1 | /proc enumeration + OpenSSL EVP SHA-1 | - |
| procfetch | procfetch_fetch | macos | supported | 1 | libproc (proc_listpids/proc_pidpath) + OpenSSL EVP SHA-1 | - |
| procfetch | procfetch_fetch | windows | supported | 1 | CreateToolhelp32Snapshot + BCrypt SHA-1 | - |
| quarantine | quarantine | linux | supported | 2 | sudo-governed iptables via bounded runner argv | - |
| quarantine | quarantine | macos | supported | 2 | sudo-governed pfctl via bounded runner argv | - |
| quarantine | quarantine | windows | supported | 2 | netsh via bounded runner argv (service-account privilege, no sudo) | - |
| quarantine | unquarantine | linux | supported | 2 | sudo-governed iptables via bounded runner argv | - |
| quarantine | unquarantine | macos | supported | 2 | sudo-governed pfctl via bounded runner argv | - |
| quarantine | unquarantine | windows | supported | 2 | netsh via bounded runner argv (service-account privilege, no sudo) | - |
| quarantine | status | linux | supported | 2 | sudo-governed iptables via bounded runner argv | - |
| quarantine | status | macos | supported | 2 | sudo-governed pfctl via bounded runner argv | - |
| quarantine | status | windows | supported | 2 | netsh via bounded runner argv (service-account privilege, no sudo) | - |
| quarantine | whitelist | linux | supported | 2 | sudo-governed iptables via bounded runner argv | - |
| quarantine | whitelist | macos | supported | 2 | sudo-governed pfctl via bounded runner argv | - |
| quarantine | whitelist | windows | supported | 2 | netsh via bounded runner argv (service-account privilege, no sudo) | - |
| rdp_control | set_state | linux | unsupported | - | - | - |
| rdp_control | set_state | macos | unsupported | - | - | - |
| rdp_control | set_state | windows | supported | 1 | Win32 registry + INetFwPolicy2 COM + SCM | - |
| rdp_control | status | linux | unsupported | - | - | - |
| rdp_control | status | macos | unsupported | - | - | - |
| rdp_control | status | windows | supported | 1 | Win32 registry + INetFwPolicy2 COM + SCM | - |
| registry | get_value | linux | unsupported | - | - | - |
| registry | get_value | macos | unsupported | - | - | - |
| registry | get_value | windows | supported | 1 | win32_registry | - |
| registry | set_value | linux | unsupported | - | - | - |
| registry | set_value | macos | unsupported | - | - | - |
| registry | set_value | windows | supported | 1 | win32_registry | - |
| registry | delete_value | linux | unsupported | - | - | - |
| registry | delete_value | macos | unsupported | - | - | - |
| registry | delete_value | windows | supported | 1 | win32_registry | - |
| registry | delete_key | linux | unsupported | - | - | - |
| registry | delete_key | macos | unsupported | - | - | - |
| registry | delete_key | windows | supported | 1 | win32_registry | - |
| registry | key_exists | linux | unsupported | - | - | - |
| registry | key_exists | macos | unsupported | - | - | - |
| registry | key_exists | windows | supported | 1 | win32_registry | - |
| registry | enumerate_keys | linux | unsupported | - | - | - |
| registry | enumerate_keys | macos | unsupported | - | - | - |
| registry | enumerate_keys | windows | supported | 1 | win32_registry | - |
| registry | enumerate_values | linux | unsupported | - | - | - |
| registry | enumerate_values | macos | unsupported | - | - | - |
| registry | enumerate_values | windows | supported | 1 | win32_registry | - |
| registry | get_user_value | linux | unsupported | - | - | - |
| registry | get_user_value | macos | unsupported | - | - | - |
| registry | get_user_value | windows | supported | 1 | win32_registry+hive_mount | - |
| registry | list_profiles | linux | unsupported | - | - | - |
| registry | list_profiles | macos | unsupported | - | - | - |
| registry | list_profiles | windows | supported | 1 | win32_registry | - |
| sccm | client_version | linux | unsupported | - | - | - |
| sccm | client_version | macos | unsupported | - | - | - |
| sccm | client_version | windows | supported | 3 | registry+sc_query | - |
| sccm | site | linux | unsupported | - | - | - |
| sccm | site | macos | unsupported | - | - | - |
| sccm | site | windows | supported | 3 | registry+powershell_com | - |
| script_exec | exec | linux | supported | 2 | fork_execvp | - |
| script_exec | exec | macos | supported | 2 | fork_execvp | - |
| script_exec | exec | windows | supported | 2 | create_process | - |
| script_exec | powershell | linux | unsupported | - | - | - |
| script_exec | powershell | macos | unsupported | - | - | - |
| script_exec | powershell | windows | supported | 3 | powershell_encodedcommand | - |
| script_exec | bash | linux | supported | 3 | bash_c | - |
| script_exec | bash | macos | supported | 3 | bash_c | - |
| script_exec | bash | windows | unsupported | - | - | - |
| services | list | linux | supported | 2 | runner argv 'systemctl list-units' | - |
| services | list | macos | supported | 2 | runner argv 'launchctl list' | - |
| services | list | windows | supported | 1 | win32_service_api | - |
| services | running | linux | supported | 2 | runner argv 'systemctl list-units' | - |
| services | running | macos | supported | 2 | runner argv 'launchctl list' | - |
| services | running | windows | supported | 1 | win32_service_api | - |
| services | set_start_mode | linux | supported | 2 | runner argv 'sudo -n -- systemctl enable\|disable\|mask\|unmask' | - |
| services | set_start_mode | macos | supported | 2 | runner argv 'sudo -n -- launchctl enable\|disable' | - |
| services | set_start_mode | windows | supported | 1 | win32_service_api | - |
| sockwho | sockwho_list | linux | supported | 1 | /proc/net/* + /proc/[pid]/{comm,exe,fd} | - |
| sockwho | sockwho_list | macos | supported | 1 | libproc | - |
| sockwho | sockwho_list | windows | supported | 1 | IP Helper API + QueryFullProcessImageNameW | - |
| software_actions | list_upgradable | linux | supported | 3 | apt+yum | - |
| software_actions | list_upgradable | macos | supported | 3 | softwareupdate | - |
| software_actions | list_upgradable | windows | supported | 3 | winget | - |
| software_actions | installed_count | linux | supported | 3 | dpkg+rpm | - |
| software_actions | installed_count | macos | supported | 3 | pkgutil | - |
| software_actions | installed_count | windows | supported | 3 | powershell_registry_count | - |
| status | version | linux | supported | 1 | in-process (compiled version constants) | - |
| status | version | macos | supported | 1 | in-process (compiled version constants) | - |
| status | version | windows | supported | 1 | in-process (compiled version constants) | - |
| status | info | linux | supported | 1 | uname(2) + gethostname(3) | - |
| status | info | macos | supported | 1 | uname(2) + gethostname(3) | - |
| status | info | windows | supported | 1 | GetNativeSystemInfo + GetComputerNameA | - |
| status | health | linux | supported | 1 | /proc/self/status VmRSS + steady_clock | - |
| status | health | macos | supported | 1 | task_info(MACH_TASK_BASIC_INFO) + steady_clock | - |
| status | health | windows | supported | 1 | K32GetProcessMemoryInfo + steady_clock | - |
| status | plugins | linux | supported | 1 | in-process agent config (agent.plugins.*) | - |
| status | plugins | macos | supported | 1 | in-process agent config (agent.plugins.*) | - |
| status | plugins | windows | supported | 1 | in-process agent config (agent.plugins.*) | - |
| status | modules | linux | supported | 1 | in-process agent config (agent.modules.*) | - |
| status | modules | macos | supported | 1 | in-process agent config (agent.modules.*) | - |
| status | modules | windows | supported | 1 | in-process agent config (agent.modules.*) | - |
| status | connection | linux | supported | 1 | in-process agent config (agent.server_address/tls_enabled/*) | - |
| status | connection | macos | supported | 1 | in-process agent config (agent.server_address/tls_enabled/*) | - |
| status | connection | windows | supported | 1 | in-process agent config (agent.server_address/tls_enabled/*) | - |
| status | switch | linux | supported | 1 | in-process agent config (agent.server_address/session_id/*) | - |
| status | switch | macos | supported | 1 | in-process agent config (agent.server_address/session_id/*) | - |
| status | switch | windows | supported | 1 | in-process agent config (agent.server_address/session_id/*) | - |
| status | config | linux | supported | 1 | in-process agent config (agent.*) | - |
| status | config | macos | supported | 1 | in-process agent config (agent.*) | - |
| status | config | windows | supported | 1 | in-process agent config (agent.*) | - |
| storage | set | linux | supported | 1 | in-process agent KV store (yuzu_ctx_storage_set) | - |
| storage | set | macos | supported | 1 | in-process agent KV store (yuzu_ctx_storage_set) | - |
| storage | set | windows | supported | 1 | in-process agent KV store (yuzu_ctx_storage_set) | - |
| storage | get | linux | supported | 1 | in-process agent KV store (yuzu_ctx_storage_get) | - |
| storage | get | macos | supported | 1 | in-process agent KV store (yuzu_ctx_storage_get) | - |
| storage | get | windows | supported | 1 | in-process agent KV store (yuzu_ctx_storage_get) | - |
| storage | delete | linux | supported | 1 | in-process agent KV store (yuzu_ctx_storage_delete) | - |
| storage | delete | macos | supported | 1 | in-process agent KV store (yuzu_ctx_storage_delete) | - |
| storage | delete | windows | supported | 1 | in-process agent KV store (yuzu_ctx_storage_delete) | - |
| storage | list | linux | supported | 1 | in-process agent KV store (yuzu_ctx_storage_list) | - |
| storage | list | macos | supported | 1 | in-process agent KV store (yuzu_ctx_storage_list) | - |
| storage | list | windows | supported | 1 | in-process agent KV store (yuzu_ctx_storage_list) | - |
| storage | clear | linux | supported | 1 | in-process agent KV store (yuzu_ctx_storage_list + storage_delete per key) | - |
| storage | clear | macos | supported | 1 | in-process agent KV store (yuzu_ctx_storage_list + storage_delete per key) | - |
| storage | clear | windows | supported | 1 | in-process agent KV store (yuzu_ctx_storage_list + storage_delete per key) | - |
| tags | set | linux | supported | 1 | local_json_store | - |
| tags | set | macos | supported | 1 | local_json_store | - |
| tags | set | windows | supported | 1 | local_json_store | - |
| tags | get | linux | supported | 1 | local_json_store | - |
| tags | get | macos | supported | 1 | local_json_store | - |
| tags | get | windows | supported | 1 | local_json_store | - |
| tags | get_all | linux | supported | 1 | local_json_store | - |
| tags | get_all | macos | supported | 1 | local_json_store | - |
| tags | get_all | windows | supported | 1 | local_json_store | - |
| tags | delete | linux | supported | 1 | local_json_store | - |
| tags | delete | macos | supported | 1 | local_json_store | - |
| tags | delete | windows | supported | 1 | local_json_store | - |
| tags | check | linux | supported | 1 | local_json_store | - |
| tags | check | macos | supported | 1 | local_json_store | - |
| tags | check | windows | supported | 1 | local_json_store | - |
| tags | clear | linux | supported | 1 | local_json_store | - |
| tags | clear | macos | supported | 1 | local_json_store | - |
| tags | clear | windows | supported | 1 | local_json_store | - |
| tags | count | linux | supported | 1 | local_json_store | - |
| tags | count | macos | supported | 1 | local_json_store | - |
| tags | count | windows | supported | 1 | local_json_store | - |
| tar | status | linux | supported | 1 | sqlite | - |
| tar | status | macos | supported | 1 | sqlite | - |
| tar | status | windows | supported | 1 | sqlite | - |
| tar | query | linux | supported | 1 | sqlite | - |
| tar | query | macos | supported | 1 | sqlite | - |
| tar | query | windows | supported | 1 | sqlite | - |
| tar | snapshot | linux | constrained | 3 | procfs+systemctl+dpkg_rpm(planned) | software inventory collection is PLANNED (dpkg/rpm not yet wired) on Linux; service enumeration shells out via popen(systemctl) |
| tar | snapshot | macos | constrained | 3 | endpoint_security+nstat+launchctl+pkgutil(planned) | software and mapdrive collection are PLANNED on macOS; service enumeration shells out via popen(launchctl); process/tcp fall back to a poll without the Endpoint Security entitlement or nstat root privilege |
| tar | snapshot | windows | supported | 1 | etw+iphlpapi+scm+wts+wnet+wevtapi+registry | - |
| tar | export | linux | supported | 1 | sqlite | - |
| tar | export | macos | supported | 1 | sqlite | - |
| tar | export | windows | supported | 1 | sqlite | - |
| tar | configure | linux | supported | 1 | sqlite | - |
| tar | configure | macos | supported | 1 | sqlite | - |
| tar | configure | windows | supported | 1 | sqlite | - |
| tar | collect_fast | linux | constrained | 1 | procfs | arp/dns opt-in sub-sources are PLANNED (no-op) on Linux; core process/network/netqual collection is native |
| tar | collect_fast | macos | constrained | 1 | endpoint_security+nstat | process/tcp fall back to a KERN_PROC_ALL/proc_pidfdinfo poll without the Endpoint Security entitlement or nstat root privilege; arp/dns opt-in sub-sources are PLANNED (no-op) on macOS |
| tar | collect_fast | windows | supported | 1 | etw+iphlpapi | - |
| tar | collect_slow | linux | constrained | 3 | systemctl+utmp | service enumeration shells out via popen(systemctl); startup_type reads 'unknown'; netconn opt-in source is PLANNED (no-op) on Linux |
| tar | collect_slow | macos | constrained | 3 | launchctl+utmpx | service enumeration shells out via popen(launchctl); no startup_type; mapdrive and netconn opt-in sources are PLANNED (no-op) on macOS |
| tar | collect_slow | windows | supported | 1 | scm+wts+wnet+wevtapi | - |
| tar | collect_perf | linux | supported | 1 | procfs | - |
| tar | collect_perf | macos | planned | 1 | host_statistics | - |
| tar | collect_perf | windows | supported | 1 | ntcounters | - |
| tar | collect_software | linux | planned | 2 | dpkg_rpm | - |
| tar | collect_software | macos | planned | 2 | pkgutil | - |
| tar | collect_software | windows | supported | 1 | registry | - |
| tar | rollup | linux | supported | 1 | sqlite | - |
| tar | rollup | macos | supported | 1 | sqlite | - |
| tar | rollup | windows | supported | 1 | sqlite | - |
| tar | sql | linux | supported | 1 | sqlite | - |
| tar | sql | macos | supported | 1 | sqlite | - |
| tar | sql | windows | supported | 1 | sqlite | - |
| tar | compatibility | linux | supported | 1 | sqlite | - |
| tar | compatibility | macos | supported | 1 | sqlite | - |
| tar | compatibility | windows | supported | 1 | sqlite | - |
| tar | fleet_snapshot | linux | supported | 1 | procfs | - |
| tar | fleet_snapshot | macos | constrained | 1 | libproc(proc_pidfdinfo) | inherent TOCTOU between pid enumeration and per-fd query; short-lived sockets may be missed |
| tar | fleet_snapshot | windows | supported | 1 | iphlpapi+win32_process_enum | - |
| tar | purge_source | linux | supported | 1 | sqlite | - |
| tar | purge_source | macos | supported | 1 | sqlite | - |
| tar | purge_source | windows | supported | 1 | sqlite | - |
| users | logged_on | linux | supported | 1 | utmp (setutent/getutent) | - |
| users | logged_on | macos | supported | 2 | runner argv 'who' | - |
| users | logged_on | windows | supported | 1 | WTSEnumerateSessionsW + WTSQuerySessionInformationW | - |
| users | sessions | linux | supported | 2 | runner argv 'w -h' | - |
| users | sessions | macos | supported | 2 | runner argv 'w -h' | - |
| users | sessions | windows | supported | 1 | WTSEnumerateSessionsW + WTSQuerySessionInformationW | - |
| users | local_users | linux | supported | 2 | /etc/passwd read + runner argv 'lastlog -u <user>' per account | - |
| users | local_users | macos | supported | 2 | runner argv 'dscl . -list/-read UserShell/RealName' + 'last -y -1 <user>' per account | - |
| users | local_users | windows | supported | 1 | NetUserEnum | - |
| users | local_admins | linux | supported | 1 | getgrnam(sudo/wheel) + getpwuid(0) | - |
| users | local_admins | macos | supported | 2 | runner argv 'dscl . -read /Groups/admin GroupMembership' | - |
| users | local_admins | windows | supported | 1 | NetLocalGroupGetMembers | - |
| users | group_members | linux | supported | 1 | getgrnam + /etc/passwd primary-group scan | - |
| users | group_members | macos | supported | 2 | runner argv 'dscl . -read /Groups/<name> GroupMembership' | - |
| users | group_members | windows | supported | 1 | NetLocalGroupGetMembers | - |
| users | primary_user | linux | supported | 2 | runner argv 'last -F' (max_lines=200 cap) | - |
| users | primary_user | macos | supported | 2 | runner argv 'last' (max_lines=200 cap) | - |
| users | primary_user | windows | supported | 1 | wevtapi (EvtQuery/EvtRender, Security 4624) | falls back to a native ProfileList registry enumeration (no login count) when the Security channel is inaccessible |
| users | session_history | linux | supported | 2 | runner argv 'last -F -n <count>' | - |
| users | session_history | macos | supported | 2 | runner argv 'last -n <count>' | - |
| users | session_history | windows | constrained | 1 | wevtapi (EvtQuery/EvtRender, Security 4624/4634) | requires an elevated token to read the Security channel; reports an error otherwise |
| vuln_scan | scan | linux | supported | 3 | popen(pkg-manager+iptables/nft/ufw) | - |
| vuln_scan | scan | macos | supported | 3 | popen(system_profiler/brew+security-checks) | - |
| vuln_scan | scan | windows | supported | 1 | win32_registry | - |
| vuln_scan | cve_scan | linux | supported | 3 | popen(dpkg-query/rpm/pacman/apk) | - |
| vuln_scan | cve_scan | macos | supported | 3 | popen(system_profiler/brew) | - |
| vuln_scan | cve_scan | windows | supported | 1 | win32_registry | - |
| vuln_scan | config_scan | linux | supported | 3 | popen(iptables/nft/ufw)+procfs | - |
| vuln_scan | config_scan | macos | supported | 3 | popen(spctl/fdesetup/csrutil/socketfilterfw) | - |
| vuln_scan | config_scan | windows | supported | 1 | win32_registry | - |
| vuln_scan | summary | linux | supported | 3 | popen(pkg-manager+iptables/nft/ufw) | - |
| vuln_scan | summary | macos | supported | 3 | popen(system_profiler/brew+security-checks) | - |
| vuln_scan | summary | windows | supported | 1 | win32_registry | - |
| vuln_scan | inventory | linux | supported | 3 | popen(dpkg-query/rpm/pacman/apk) | - |
| vuln_scan | inventory | macos | supported | 3 | popen(system_profiler/brew) | - |
| vuln_scan | inventory | windows | supported | 1 | win32_registry | - |
| wifi | list_networks | linux | constrained | 3 | nmcli via governed shell runner | falls back to a raw, unstructured iw/iwlist text dump when nmcli is unavailable |
| wifi | list_networks | macos | constrained | 3 | airport -s via governed shell runner | airport was removed in macOS 14 (Sonoma); the system_profiler SPAirPortDataType fallback needs Location Services authorisation a background daemon may lack, so an unauthorised modern host yields no networks and an honest wifi\|info sentinel |
| wifi | list_networks | windows | supported | 1 | WlanGetAvailableNetworkList | - |
| wifi | connected | linux | constrained | 3 | nmcli via governed shell runner | falls back to a raw iwconfig text blob (ESSID/Signal only) when nmcli reports no SSID |
| wifi | connected | macos | constrained | 1 | CoreWLAN | Location Services (macOS 14+) may withhold SSID/BSSID from a background daemon |
| wifi | connected | windows | supported | 1 | WlanQueryInterface | - |
| windows_updates | installed | linux | supported | 3 | rpm+apt | - |
| windows_updates | installed | macos | supported | 3 | system_profiler | - |
| windows_updates | installed | windows | supported | 3 | powershell_gethotfix | - |
| windows_updates | missing | linux | supported | 3 | apt+yum | - |
| windows_updates | missing | macos | supported | 3 | softwareupdate | - |
| windows_updates | missing | windows | supported | 3 | powershell_update_session | - |
| windows_updates | pending_reboot | linux | supported | 3 | filesystem+uname+needs_restarting | - |
| windows_updates | pending_reboot | macos | constrained | 3 | softwareupdate | unbounded network call -- may take 30-120s or hang on an offline/headless Mac |
| windows_updates | pending_reboot | windows | supported | 1 | registry | - |
| windows_updates | patch_connectivity | linux | supported | 1 | raw_sockets | - |
| windows_updates | patch_connectivity | macos | supported | 1 | raw_sockets | - |
| windows_updates | patch_connectivity | windows | supported | 1 | raw_sockets | - |
| wmi | query | linux | unsupported | - | - | - |
| wmi | query | macos | unsupported | - | - | - |
| wmi | query | windows | supported | 1 | wmi | - |
| wmi | get_instance | linux | unsupported | - | - | - |
| wmi | get_instance | macos | unsupported | - | - | - |
| wmi | get_instance | windows | supported | 1 | wmi | - |
| wol | wake | linux | supported | 1 | raw UDP broadcast socket | - |
| wol | wake | macos | supported | 1 | raw UDP broadcast socket | - |
| wol | wake | windows | supported | 1 | raw UDP broadcast socket | - |
| wol | check | linux | constrained | 1 | SOCK_DGRAM ICMP ping socket + TCP-connect fallback | requires net.ipv4.ping_group_range to admit the process group for ICMP; falls back to a TCP connect on port 443, and reports CONSTRAINED if neither mechanism is usable |
| wol | check | macos | supported | 1 | SOCK_DGRAM ICMP ping socket + TCP-connect fallback | - |
| wol | check | windows | supported | 1 | IcmpSendEcho + TCP-connect fallback | - |

**Undeclared plugins** (ABI<4, or ABI4 with no capability declarations yet — RATCHET: this count must never grow):

_none — every built plugin has adopted the ABI4 capability descriptor._
<!-- END GENERATED -->

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

**Status:** the generator machinery landed (PR1.1, [above](#generated-abi4-per-action-capability-declarations-2204))
as `tools/capmatrix-gen` + the `check-capability-matrix.sh` CI drift gate, reading
the ABI4 `YuzuPluginDescriptor.action_descriptors` array rather than any of the
four sources above directly. What's left is per-source/per-plugin **adoption** —
TAR, Guards, Spark, and DEX each still expose their per-OS truth through their
own hand-maintained structure (`OsSupportStatus`, the per-type support arrays,
`dex_obs_platforms()`); wiring each into `action_descriptors` so the *rest of
this page* (not just the generated block) renders from code is the remaining
follow-up. An in-product *Settings → Coverage* page reading the same array
remains a further possible step. Until every source is wired through, this page
is still the single place to look for the hand-curated sections above — keep it
honest.

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
- **DEX** — macOS collector confirmed **real & shipped** (16 catalogued
  obs_types via `dex_macos_{signals,oslog,iokit}.cpp` — 17 raw, with
  `process.resource_limit` excluded from the taxonomy, per the
  `dex_obs_platforms()` drift-net; the reliability-signals cell says 16);
  source-of-truth updated to the `dex_obs_platforms()` coverage map.
- **Plugins** — all **49** enumerated (CLAUDE.md's "47/49" reconciled to 49): 43
  fully cross-platform, **4** Windows-only (`rdp_control`, `registry`, `sccm`,
  `wmi`), **2** uneven (`tar`; and `msi_packages` — now Win+macOS via `pkgutil`
  receipts, Linux still unimplemented). (The 43 became **42** in the 2026-07-21
  pass below once `interaction` moved to macOS-constrained; both tallies still
  sum to 49.)

_2026-07-21 macOS-parity consolidation._ This pass documents the macOS parity
batch **landing in the same PR as this restructure** — every cited capability
ships in the consolidated branch this doc describes, so each row is verifiable
against the code in the same diff. Cell moves and honesty corrections, each
verified against the cited code:

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
  procperf stays version-less. **DEX reliability signals** unchanged (16 catalogued
  obs_types on macOS, per the `dex_obs_platforms()` drift-net) but OSLog now
  pre-filters Error+Fault, reaching apfs `fs.corruption`.
- **`interaction`** ✅→🟡 on macOS — honest `not_reachable` from a GUI-less root
  daemon, no longer a fabricated `response|ok`.
- **New rows:** **Antivirus posture** (macOS 🟡 — real XProtect/EDR probes, no
  real-time-protection state) and **Live — Wi-Fi current connection** (macOS 🟡 —
  CoreWLAN, SSID/BSSID withheld from a daemon).
- **Honesty-only** (cell unchanged): `wol` `check` (native ICMP + TCP-connect
  fallback, no subprocess; was a false `unreachable`), `wifi connected`
  (CoreWLAN vs dead `airport -I`), `flush_dns`
  (dual-step + real exit codes), `registry`/`sccm`/`rdp_control` off-Windows
  sentinels (no false success on writes), `bitlocker`/`services`/`users`/
  `network_config` macOS enrichments, DNS-cache `unsupported` sentinel.

Not folded in: #2254 (per-OS DEX catalogue **health score**) is a server-side
scoring change and moves no agent capability cell.

_2026-07-21 review-round corrections_ (the #2243 review findings, resolved on the
consolidated branch):

- **Duplicate legacy table removed.** The pre-restructure table (and its trailing
  network-row blockquote) had been left in wholesale after the sectioned matrix,
  and the two disagreed on several cells; the sectioned table is now the only one.
  The blockquote's per-cell caveats live inline in the **Network quality** row.
- **New section grafted:** *Security posture & file/certificate surfaces* —
  Antivirus posture, Firewall posture, digital-signature verification and file
  version info (`filesystem`, Win + macOS), and the two macOS certificate rows
  (login-keychain read, verified SIP-aware delete).
- **Antivirus macOS cell reconciled to 🟡** (the honest reading: real
  XProtect/system-extension probes, but no queryable real-time-protection state)
  — the legacy table's ✅ was the drifted claim.
- **Plugin tally re-derived from the table:** 42 fully cross-platform,
  4 Windows-only, 2 uneven (`tar`, `msi_packages`), 1 macOS-constrained
  (`interaction`) = 49.
- **Spark note un-staled:** rung 7.7a *does* wire `wire_spark_engine()` at boot
  (lifecycle-only); the sole-live-path claim now hangs on `prefer_spark_=false`,
  not on a nonexistent call site.
- **TAR `tcp` macOS `capture_method` verified:** the registry now lists `nstat`
  (primary) + `proc_pidfdinfo` (fallback/seed) — the schema matches the shipped
  mechanism.
