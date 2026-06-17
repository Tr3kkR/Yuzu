#pragma once

/**
 * dex_linux_kmsg.hpp — pure classification of kernel ring-buffer journal messages
 * for Linux DEX (Guardian DEX).
 *
 * Kernel messages (`_TRANSPORT=kernel`) carry NO stable `MESSAGE_ID` — they are
 * free text — so unlike the systemd-structured records in dex_linux_journal, they
 * are classified by anchored substring markers on the raw `MESSAGE`. The Linux DEX
 * collector's journald branch (dex_linux_journal.cpp `parse_journal_line`)
 * delegates every kernel-transport line here; this file owns the whole kernel-text
 * surface (the OOM-killer line included, moved from parse_journal_line so all the
 * free-text markers live together).
 *
 * Each marker maps onto an EXISTING obs_type so a Linux server lights up the same
 * `/dex` buckets as Windows/macOS with ZERO server change:
 *   - `Kernel panic - not syncing`              → os.bugcheck       (fatal only)
 *   - `… of memory: Killed process N (comm) …`  → memory.exhausted  (OOM-killer)
 *   - `[Hardware Error]` / `Machine check …`     → hw.error          (MCE)
 *   - `EXT4-fs error (device X)` / XFS / BTRFS    → fs.corruption
 *   - `EXT4-fs (X): recovery complete` / XFS rec. → os.dirty_shutdown (unclean reboot)
 *   - `… error, dev X, sector N …` / `Buffer I/O` → disk.error        (device subject)
 *   - `task <comm>:<pid> blocked for more than …` → process.hung      (hung_task)
 *
 * MARKER PROVENANCE (the make-or-break: a guessed marker is a dead signal that
 * still passes a guessed fixture — the cgroup-OOM trap). disk.error, fs.corruption
 * and os.dirty_shutdown markers are pinned to records LIVE-CAPTURED on a real
 * systemd-259 / kernel-7.0 box via safe error injection (scsi_debug medium error,
 * debugfs block-pointer corruption, a direct-IO loop snapshot mid-write). panic,
 * MCE and hung_task use the dead-stable documented kernel format strings and are
 * marked fixture-pinned-awaiting-live-fire (the box can't panic / inject MCE).
 *
 * PRIVACY (works-council / co-determination): only infra-safe fields leave the
 * device — the killed/blocked process comm, the backing-device identifier, a short
 * reason code. The raw `MESSAGE` (which carries inode/block numbers, the accessing
 * `comm`, kernel addresses, memory figures) is NEVER shipped. Pinned by
 * `[dex][linux][kmsg][privacy]` tests.
 *
 * Everything here is a PURE text parse (no syscalls, no platform guards), unit-
 * tested on every host incl. MSVC, and NEVER throws.
 */

#include <yuzu/plugin.h>                     // YUZU_EXPORT
#include <yuzu/agent/dex_signal_catalog.hpp> // SignalObservation

#include <optional>
#include <string>
#include <string_view>

namespace yuzu::agent::lnx {

/// PURE: classify one kernel-transport journal `MESSAGE` into a DEX observation.
/// nullopt = not a reliability signal we record (the common case — most kernel
/// lines are device-probe / audit noise; the cursor still advances past them).
/// Markers are checked most-severe-first and the first match wins, so the rare
/// overlap (an fs error that co-fires a disk error) is claimed by the more specific
/// marker. Stamps obs_type/subject/reason/kind/sentence only — the collector stamps
/// platform + timestamp. Never throws.
YUZU_EXPORT std::optional<SignalObservation> classify_kernel_message(std::string_view message);

/// PURE: the killed comm from a kernel OOM-killer line, or "" if `msg` is not one.
/// Exposed for tests / reuse; two real forms match (system-wide "Out of memory:"
/// and cgroup-v2 "Memory cgroup out of memory:") via the case-sensitive shared
/// marker "of memory: Killed process ". Only the comm is taken — never the memory
/// figures or the cgroup path.
YUZU_EXPORT std::string oom_victim_comm(std::string_view msg);

/// PURE: extract a backing-device / filesystem identifier from a kernel line, given
/// the marker that precedes it (e.g. "(device " for `EXT4-fs error (device sda1)`,
/// "on dev " for `Buffer I/O error on dev sdb`). Stops at the first of `) , space`.
/// "" when the marker is absent or the token is empty. The device id is infra
/// config (the storage.low subject class), never PII. Exposed for tests.
YUZU_EXPORT std::string kmsg_device_after(std::string_view msg, std::string_view marker);

} // namespace yuzu::agent::lnx
