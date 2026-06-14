#pragma once

/**
 * dex_linux_proc.hpp — pure parsers for the Linux /proc DEX signals (Guardian DEX).
 *
 * The Linux DEX collector (dex_linux_collector.cpp) is all-poll: it reads
 * /proc/stat, /proc/meminfo and /proc/mounts on a slow cadence and feeds the
 * derived numbers into the SAME sustained-breach hysteresis + observation
 * builders the Windows poller uses (dex_perf_breach.hpp, dex_win_poll.hpp). A
 * Linux server therefore lights up the EXISTING perf.cpu_sustained /
 * perf.memory_pressure / storage.low buckets with ZERO server change — the
 * macOS-collector parity playbook (a server is observed the same as any other OS,
 * in the same dashboard rows).
 *
 * Everything here is a PURE text parse (no syscalls, no platform guards) so the
 * fiddly /proc field handling is unit-tested on every host against captured
 * fixtures, exactly like extract_named_data and the dex_perf_breach derivations.
 * Parsers NEVER throw (std::from_chars, not stoull): a malformed /proc line must
 * not unwind out of the poll thread (the dex_observer parse_int_field rule).
 *
 * Namespace `lnx`, not `linux`: `linux` is a predefined macro (== 1) under the
 * gnu++ dialects, so `namespace linux { … }` would not compile portably.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::agent::lnx {

/// CPU jiffies from the aggregate `cpu` line of /proc/stat. `total` sums the
/// first EIGHT fields (user, nice, system, idle, iowait, irq, softirq, steal);
/// guest / guest_nice are deliberately excluded — the kernel already folds them
/// into user / nice, so summing them would double-count. `idle` is idle + iowait
/// (time the CPU did no work — iowait is an I/O stall, not CPU busy). Both
/// cumulative since boot.
struct CpuJiffies {
    bool valid{false};
    std::uint64_t total{0};
    std::uint64_t idle{0};
};

/// Parse the aggregate `cpu ` line out of /proc/stat. valid=false when that line
/// is absent or carries fewer than the 4 fields (user, nice, system, idle) the
/// busy% derivation needs.
YUZU_EXPORT CpuJiffies parse_proc_stat(std::string_view proc_stat);

/// PURE: busy% over the interval between two readings. nullopt when either
/// reading is invalid, a counter regressed (reboot / reset — a rate off a
/// regressed baseline is garbage), or no time elapsed (total delta 0). Clamped to
/// [0,100]. Mirrors derive_breach_sample's CPU logic, for /proc jiffies.
YUZU_EXPORT std::optional<double> cpu_busy_pct(const CpuJiffies& prev, const CpuJiffies& cur);

/// PURE: commit charge as a percentage of the commit limit, from /proc/meminfo
/// (100 * Committed_AS / CommitLimit). This is the DIRECT analogue of Windows'
/// commit-total / commit-limit, so it feeds memory_pressure_observation with the
/// SAME meaning AND wording ("commit charge avg X% of limit") — genuine parity,
/// not a relabelled metric. nullopt when CommitLimit is missing or zero, or
/// Committed_AS is missing. Clamped to [0,100] (heuristic overcommit can push the
/// raw ratio above the limit).
YUZU_EXPORT std::optional<double> parse_commit_pct(std::string_view proc_meminfo);

/// One local filesystem worth a storage.low check, from /proc/mounts.
struct MountPoint {
    std::string device; ///< backing source (the dedup key)
    std::string path;   ///< mount point to statvfs
    std::string fstype;
};

/// PURE: the real, writable, LOCAL filesystems to check for storage.low, parsed
/// from /proc/mounts. Whitelists block-backed fstypes (ext*/xfs/btrfs/zfs/f2fs)
/// and skips read-only mounts — by construction this avoids the squashfs/snap
/// "100% full by design" storm and never statvfs()'s a pseudo or (potentially
/// hung) network mount. Deduped by backing device so a bind mount of the same
/// filesystem is not counted twice.
///
/// Deliberately EXCLUDED (parity with the Windows fixed-disk-only storage.low):
/// tmpfs (/run, /dev/shm, /tmp), other RAM-backed/pseudo fs (proc, sysfs, cgroup,
/// overlay), and network mounts (nfs/cifs). A full tmpfs is a MEMORY condition, not
/// disk-full — it is RAM-backed and sized by design — so it belongs to a future
/// memory/tmpfs obs_type, not storage.low; excluding network fs also keeps a hung
/// NFS server from blocking the poll thread in statvfs().
YUZU_EXPORT std::vector<MountPoint> parse_storage_mounts(std::string_view proc_mounts);

/// PURE: a stable, NON-PII storage.low subject derived from the backing DEVICE,
/// never the mount path. A mount path is *where users put files* and routinely
/// carries usernames / tenant / project names (`/home/alice/...`,
/// `/srv/acme-data`) — exactly the content the DEX edge-privacy contract forbids
/// leaving the device (`docs/dex-signal-catalog.md`). The backing-device
/// identifier is infrastructure config (the same class as the hostname), so it is
/// the Linux analogue of the Windows drive letter ("C:") and the macOS volume
/// label ("Macintosh HD") the other collectors emit. Returns the device basename
/// ("/dev/sda1" -> "sda1", "/dev/mapper/vg0-root" -> "vg0-root"), or "disk" when
/// the device is empty or has no basename (trailing slash).
YUZU_EXPORT std::string device_label(std::string_view device);

} // namespace yuzu::agent::lnx
