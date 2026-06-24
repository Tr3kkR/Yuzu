# OS capability matrix

**What this is:** a per-capability × per-OS snapshot of what the Yuzu **agent**
actually collects/enforces on each platform — the thing that was missing when the
`/network` tab showed no data on a Windows-only fleet (the collector was
Linux-only and nothing surfaced that gap).

**Read this first — accuracy & drift.** This is a *curated snapshot*, and a
hand-maintained matrix drifts from code exactly the way the gap above happened.
Each row therefore cites its **source of truth in code**; trust the code over this
table, and when you change per-OS support, update both. The durable fix is to
**generate** this matrix from the machine-readable per-OS metadata that already
exists (see [Make this self-maintaining](#make-this-self-maintaining)) — treat
this doc as the interim, not the destination.

Legend: ✅ Full · 🟡 Partial · 🔜 Planned/spike · ⛔ None

_Last hand-updated: 2026-06-24._

## Matrix

| Capability | Windows | Linux | macOS | Source of truth |
|---|:---:|:---:|:---:|---|
| **Agent core** (enroll, heartbeat, plugin host, triggers, KV, mTLS) | ✅ | ✅ | ✅ | `agents/core/` builds + enrolls on all three |
| **Guardian — registry guard** | ✅ | ⛔ | ⛔ | `guard_registry.cpp` (no-op off-Windows); `registry_support::kHives` |
| **Guardian — file guard** | ✅ | ⛔ | ⛔ | `guard_file.cpp` (no-op off-Windows) |
| **Guardian — service run-state guard** | ✅ enforce | 🟡 observe-only | ⛔ | `make_service_guard()` in `guard_systemd.hpp`; Win `ServiceGuard` (SCM), Linux `SystemdServiceGuard` (sd-bus, enforce deferred) |
| **DEX — reliability signals** (crashes, hangs, service/boot, storage, kernel faults, perf/thermal, …) | ✅ | 🟡 growing (17 signals: perf cpu/mem/disk + storage/uptime + journald unit-crash/hung + coredump-crash + OOM + time-unsynced + kernel panic/disk/fs/dirty-shutdown/MCE/hung-task + thermal-throttle) | 🟡 | Win: `dex_observer.cpp`/`dex_win_poll.cpp`; Linux: `dex_linux_collector.cpp`/`dex_linux_proc.cpp`/`dex_linux_storage.cpp`/`dex_linux_journal.cpp`/`dex_linux_kmsg.cpp`/`dex_linux_sysfs.cpp`; macOS: `dex_macos_collector.cpp` (DiagnosticReports/OSLog/IOKit). Catalogue: `docs/dex-signal-catalog.md` |
| **DEX — performance telemetry** (CPU/mem/disk levels) | ✅ | ✅ | ⛔ | `tar_perf.cpp` (Win: GetSystemTimes/IOCTL_DISK_PERFORMANCE/GetIfTable2; Linux: `/proc`). macOS absent from the rollup |
| **Network quality** (`/network`: throughput / retransmit / RTT) | 🟡 throughput + retransmit (no RTT) | ✅ all three | ⛔ | `net_quality_sampler.cpp`; per-OS detail in `docs/user-manual/network.md` "Platform coverage" |
| **TAR warehouse capture sources** (per source) | varies | varies | varies | **Authoritative & machine-readable:** `tar_schema_registry.cpp` `OsSupportStatus::{kSupported,kPlanned}` per source, with a notes string |
| **TAR — ARP table** (capture source) | ✅ | 🔜 | 🔜 | `tar_schema_registry.cpp` `arp` def (Win `kSupported` via `iphlpapi`; Linux `kPlanned` `/proc/net/arp`; macOS `kPlanned` route sysctl, constrained — `entry_type 'unknown'`); collector `tar_arp_collector.cpp` (ADR-0015, opt-in) |
| **TAR — DNS cache** (capture source) | ✅ | 🔜 | 🔜 | `tar_schema_registry.cpp` `dns` def (Win `kSupported` via `dnsapi`; Linux `kPlanned` systemd-resolved, hosts-file fallback where absent; macOS `kPlanned` `dscacheutil`, constrained — no TTL); collector `tar_dns_collector.cpp` (ADR-0015, opt-in; device-level usage-class PII, names-only) |
| **Process enumeration / live capture** | ✅ (ETW / Win32) | ✅ (`/proc`) | 🟡 | `process_enum.cpp`; ETW workstream is Windows-specific |
| **Installed-software inventory** (daily sync → central Postgres) | ✅ | ✅ | ✅ | Agent sync framework `sync_scheduler.cpp` + `sync_source_installed_software.cpp` reuse the `installed_apps` plugin `list` (Win registry; Linux dpkg/rpm/pacman; macOS `system_profiler`) via `LocalDispatcher`. Machine-scope only. Server: `SoftwareInventoryStore` (ADR-0016) |

> The **network row's Windows cell is 🟡 as of 2026-06-15**: the agent now emits
> device throughput (`GetIfTable2`) and a system-wide interval retransmit rate
> (`GetTcpStatisticsEx`). RTT stays 🔜 — per-connection smoothed RTT needs ESTATS
> (`GetPerTcpConnectionEStats`: enable + admin + overhead). The Windows retransmit
> rate is system-wide (includes loopback) and is **measurement-first, not yet
> loss-validated on Windows** — see `docs/user-manual/network.md`.

## Why gaps happen (and how to not get surprised again)

Per-OS support is **implicit and scattered**: a `#if defined(_WIN32)` here, a
no-op stub there, a `kPlanned` enum in one registry. Nothing forced it to the
surface, so a Windows-only fleet can hit a feature that was quietly Linux-only.
When adding or changing a collector/guard, assume the **other** platforms are a
deliberate decision you must record — in code (a stub + comment), in the relevant
user-manual "Platform coverage" section, and in this matrix.

## Make this self-maintaining

The truth already exists machine-readable; the durable fix is to render the matrix
from it rather than hand-curate:

- **TAR sources** — `tar_schema_registry.cpp` already declares
  `OsSupportStatus::{kSupported,kPlanned}` *per source per OS* with a notes
  string. This is the model the rest should follow.
- **Guards** — the per-type support arrays (`registry_support::kHives`,
  `service_support::kStates`) + the `make_service_guard()` platform switch.
- **DEX signals** — the signal catalogue's per-OS coverage (`docs/dex-signal-catalog.md`
  + the agent `dex_signal_catalog.*`).

**Proposed follow-up (file as an issue):** a small build-time generator that walks
those sources and emits this table (and optionally an in-product *Settings →
Coverage* page), so per-OS support can never silently diverge from the doc again.
Until that lands, this page is the single place to look — keep it honest.
