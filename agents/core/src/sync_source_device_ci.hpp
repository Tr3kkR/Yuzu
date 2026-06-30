#pragma once

/// @file sync_source_device_ci.hpp
/// The `device_ci` daily-sync source (ADR-0016) — a further source of the agent
/// sync framework (after `installed_software` and `app_perf`). Collects the
/// machine's stable hardware / OS identity — a ServiceNow-CMDB-style configuration
/// item (CI) record — by invoking the existing `hardware`, `device_identity`,
/// `os_info`, and `network_config` plugins in-process (`LocalDispatcher`) and
/// rendering them into the canonical wire blob the server (`device_ci_ingestion`)
/// reconstructs byte-for-byte.
///
/// **Machine scope only** — no per-user data (ADR-0016 §8). **Deliberately excludes
/// volatile telemetry** (disk free space, uptime, IP addresses): those flap between
/// cycles, which would flip the content hash every sync and defeat the hash-skip
/// protocol (the network-kindness the framework exists for). Only stable identity /
/// firmware / fixed-hardware / OS-version facts are in the CI record.

#include "sync_scheduler.hpp"

#include <yuzu/plugin.h> // YuzuPluginDescriptor (C ABI) — typedef, so include not fwd-decl

#include <string>

namespace yuzu::agent {

/// One device-CI record — the canonical, ordered field set. The canonical blob is
/// these fields in THIS exact order (positional), 0x1F-separated and 0x1E-terminated
/// (one record). Adding/reordering a field is a COORDINATED change: the server's
/// reconstruction (`device_ci_ingestion.cpp`) AND the cross-pin test must move in
/// lockstep, or the agent- and server-recomputed hashes diverge → permanent
/// `need_full`. Numbers are rendered as decimal strings (hashed as text; the server
/// parses them back to integers for typed columns).
struct CiRecord {
    std::string manufacturer;
    std::string model;
    std::string serial;
    std::string system_uuid;
    std::string hostname;
    std::string domain;
    std::string ou;
    std::string bios_vendor;
    std::string bios_version;
    std::string bios_date;
    std::string cpu_model;
    std::string cpu_cores;   ///< decimal string (summed physical cores)
    std::string cpu_threads; ///< decimal string (summed logical processors)
    std::string ram_bytes;   ///< decimal string (summed DIMM capacity, bytes)
    std::string disks_summary;
    std::string primary_mac;
    std::string macs_summary; ///< all non-zero MACs, sorted, comma-joined
    std::string nic_count;    ///< decimal string
    std::string os_name;
    std::string os_version;
    std::string os_build;
    std::string arch;
};

/// Canonical wire blob (see `CiRecord` for the field order). Each field is
/// UTF-8-scrubbed + length-clamped + separator-stripped identically to the server,
/// then positionally joined. MUST be byte-identical to the server's reconstruction
/// (`device_ci_ingestion.cpp`) so the server-recomputed hash equals this one.
YUZU_EXPORT std::string device_ci_canonical_blob(const CiRecord& rec);

/// True when the platform's core-identity subsystem was unavailable for this
/// collection — Windows WMI down (every WMI-gated action returns the `"unknown"`
/// sentinel at rc=0, so the per-action rc check does NOT catch it) or the Linux
/// DMI tables unreadable. The tell is `manufacturer` AND `model` both `"unknown"`:
/// both come from the SAME query behind ONE availability gate, so on a functioning
/// machine — physical OR virtual — both are always real (a VM reports e.g.
/// "VMware, Inc."/"VMware7,1"). Using AND (not OR) avoids skipping a healthy host
/// that reports a real manufacturer but an empty model forever. When true, the
/// collect skips the cycle rather than persist a degraded record whose
/// `serial`/`system_uuid` collapsed to `"unknown"` — which would overwrite the
/// last-good CI row and flap the content hash on every WMI blip (UP-1). A
/// genuinely serial-less host (a VM with real manufacturer/model) is NOT skipped;
/// its stable `"unknown"` serial persists. Pure/deterministic — unit-tested.
YUZU_EXPORT bool core_identity_unavailable(const CiRecord& rec);

/// Build the `device_ci` SyncSource. Each argument is a loaded plugin descriptor;
/// if ANY required plugin is null (not built/loaded — e.g. `build_examples=false`)
/// the source's collect returns `std::nullopt` and the scheduler no-ops it (a
/// partial CI record is never synced).
YUZU_EXPORT SyncSource make_device_ci_source(const YuzuPluginDescriptor* hardware,
                                             const YuzuPluginDescriptor* device_identity,
                                             const YuzuPluginDescriptor* os_info,
                                             const YuzuPluginDescriptor* network_config);

} // namespace yuzu::agent
